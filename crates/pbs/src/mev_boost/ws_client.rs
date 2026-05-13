//! WebSocket client — persistent connection to a Helix relay (ARCH v3.2).
//!
//! Design: the WS connection is just a pipe. No auth handshake. Validator
//! registrations arrive from the normal commit-boost REST flow and get
//! forwarded over WS for lower-latency processing; REST still runs in
//! parallel.
//!
//! Inbound from relay: BidPush (pushed bids), RegistrationAck,
//! SubmitBlindedBlockAck, Pong.
//! Outbound to relay: Subscribe (validator registrations), SubmitBlindedBlock, Ping.
//!
//! Bid cache (D6): the most recently decoded `BidPush` is exposed via a
//! `tokio::sync::watch::Sender<Option<CachedBid>>`. `collect_ws_bids` on
//! the get_header hot path reads `borrow().clone()` — zero buffering,
//! always-latest-wins semantics.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::{U256, utils::format_ether};
use cb_common::pbs::{ForkName, ForkVersionDecode, GetHeaderResponse, SignedBuilderBid};
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::connect_async;
use tracing::{debug, error, info, warn};
use ws_wire::{
    WsMessage, framing,
    messages::{Ping, Pong, SignedValidatorRegistrationV1, SubscriptionBatch},
};

use crate::mev_boost::{CompoundGetHeaderResponse, wire};

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum WsClientState {
    Disconnected,
    Connecting { attempt: u32 },
    Connected { connected_at: Instant },
    Backoff { until: Instant },
    Failed { reason: String },
}

// ---------------------------------------------------------------------------
// Cached bid
// ---------------------------------------------------------------------------

/// Decoded BidPush kept in the watch channel. The `response` is the form
/// the get_header aggregator consumes directly. Slot isn't carried on the
/// wire (per ARCH v3.2 §2 raw SSZ semantics, the SignedBuilderBid itself
/// doesn't contain the slot); we rely on the relay pushing bids it
/// believes are current, and on the bid being cleared at slot boundaries
/// by the push service (or superseded by a newer bid before get_header
/// fires).
#[derive(Clone)]
pub struct CachedBid {
    pub fork: ForkName,
    pub value: U256,
    pub response: CompoundGetHeaderResponse,
}

// ---------------------------------------------------------------------------
// HelixWsClient
// ---------------------------------------------------------------------------

const INITIAL_BACKOFF_MS: u64 = 500;
const MAX_BACKOFF_MS: u64 = 30_000;
const LONG_RETRY_THRESHOLD: u32 = 20;
const PING_INTERVAL: Duration = Duration::from_secs(15);
const PONG_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for waiting for SubmitBlindedBlockAck before retrying.
const SUBMIT_ACK_TIMEOUT: Duration = Duration::from_millis(500);
/// Maximum retries for SubmitBlindedBlock over WS.
const MAX_SUBMIT_RETRIES: u8 = 2;

/// Per-submission retry tracker. Caller drives the loop:
/// send frame → call attempt(ack_rx) → if WouldRetry, resend and call again.
pub(crate) struct SubmitRetry {
    pub retries: u8,
    max_retries: u8,
    timeout: Duration,
}

#[derive(Debug, PartialEq)]
pub(crate) enum SubmitRetryResult {
    /// Ack received, status byte returned.
    Ok(u8),
    /// Ack not received within timeout. Resend and retry.
    WouldRetry,
    /// Max retries exhausted.
    MaxRetries,
    /// Channel closed (connection dropped).
    ChannelClosed,
}

impl SubmitRetry {
    fn new(max_retries: u8, timeout: Duration) -> Self {
        Self { retries: 0, max_retries, timeout }
    }

    async fn attempt(&mut self, ack_rx: oneshot::Receiver<u8>) -> SubmitRetryResult {
        match tokio::time::timeout(self.timeout, ack_rx).await {
            Ok(Ok(status)) => SubmitRetryResult::Ok(status),
            Ok(Err(_)) => SubmitRetryResult::ChannelClosed,
            Err(_elapsed) => {
                self.retries += 1;
                if self.retries >= self.max_retries {
                    SubmitRetryResult::MaxRetries
                } else {
                    SubmitRetryResult::WouldRetry
                }
            }
        }
    }
}

pub struct HelixWsClient {
    pub state: Arc<RwLock<WsClientState>>,
    pub(crate) cmd_tx: mpsc::UnboundedSender<WsMessage>,
    latest_bid_rx: watch::Receiver<Option<CachedBid>>,
    pub(crate) pending_ack: Arc<std::sync::Mutex<Option<oneshot::Sender<u8>>>>,
}

impl HelixWsClient {
    /// Spawn a WS client. Connects immediately and retries forever. The
    /// upgrade URL carries `?auction_conclusion_ms={N}` when the relay
    /// config resolves to one.
    pub fn spawn(base_url: url::Url, auction_conclusion_ms: Option<u64>) -> Self {
        let mut url = base_url;
        if let Some(v) = auction_conclusion_ms {
            url.query_pairs_mut().append_pair("auction_conclusion_ms", &v.to_string());
        }

        let state = Arc::new(RwLock::new(WsClientState::Disconnected));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<WsMessage>();
        let (bid_tx, bid_rx) = watch::channel::<Option<CachedBid>>(None);
        let pending_ack = Arc::new(std::sync::Mutex::new(None));

        let s = state.clone();
        let pa = pending_ack.clone();
        tokio::spawn(connection_loop(url, s, cmd_rx, bid_tx, pa));

        Self { state, cmd_tx, latest_bid_rx: bid_rx, pending_ack }
    }

    pub fn state_snapshot(&self) -> WsClientState {
        self.state.read().clone()
    }

    /// Get the latest cached bid, if any. Callers that want per-slot
    /// filtering should check `slot` on the returned struct.
    pub fn latest_bid(&self) -> Option<CachedBid> {
        self.latest_bid_rx.borrow().clone()
    }

    /// Send a raw WsMessage (used internally and by submit_block).
    pub fn send(&self, msg: WsMessage) {
        let _ = self.cmd_tx.send(msg);
    }

    /// Forward a batch of specs-SSZ registrations. No-op on empty batch.
    pub fn send_registration_batch(&self, registrations: Vec<SignedValidatorRegistrationV1>) {
        if registrations.is_empty() {
            return;
        }
        let batch = SubscriptionBatch::from_vec(registrations);
        let _ = self.cmd_tx.send(WsMessage::Subscribe(batch));
    }

    /// Fire-and-forget a `SubmitBlindedBlock` frame (V2 semantics). The
    /// caller is expected to also dispatch via REST in parallel; ack (if
    /// any) is swallowed by the read loop.
    pub fn send_submit_blinded_block(&self, fork: u8, body_ssz: Vec<u8>) {
        let _ = self.cmd_tx.send(WsMessage::SubmitBlindedBlock { fork, body_ssz });
    }

    /// Send SubmitBlindedBlock and wait for ack with retry. Returns the
    /// status byte on success. Retries on timeout (max 2).
    pub async fn send_submit_blinded_block_with_ack(
        &self,
        fork: u8,
        body_ssz: Vec<u8>,
    ) -> Result<u8, SubmitRetryError> {
        let mut retry = SubmitRetry::new(MAX_SUBMIT_RETRIES, SUBMIT_ACK_TIMEOUT);
        loop {
            let (tx, rx) = oneshot::channel();
            *self.pending_ack.lock().unwrap() = Some(tx);
            let _ = self.cmd_tx.send(WsMessage::SubmitBlindedBlock { fork, body_ssz: body_ssz.clone() });

            match retry.attempt(rx).await {
                SubmitRetryResult::Ok(status) => return Ok(status),
                SubmitRetryResult::WouldRetry => {
                    warn!(fork, retry = retry.retries, "WS: submit ack timeout, retrying");
                    continue;
                }
                SubmitRetryResult::MaxRetries => {
                    error!(fork, "WS: submit ack max retries exhausted");
                    *self.pending_ack.lock().unwrap() = None;
                    return Err(SubmitRetryError::MaxRetries);
                }
                SubmitRetryResult::ChannelClosed => {
                    debug!("WS: pending ack channel closed (connection dropped)");
                    return Err(SubmitRetryError::ChannelClosed);
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum SubmitRetryError {
    MaxRetries,
    ChannelClosed,
}

// ---------------------------------------------------------------------------
// Connection loop
// ---------------------------------------------------------------------------

async fn connection_loop(
    url: url::Url,
    state: Arc<RwLock<WsClientState>>,
    mut cmd_rx: mpsc::UnboundedReceiver<WsMessage>,
    bid_tx: watch::Sender<Option<CachedBid>>,
    pending_ack: Arc<std::sync::Mutex<Option<oneshot::Sender<u8>>>>,
) {
    let mut attempt: u32 = 0;
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        *state.write() = WsClientState::Connecting { attempt };
        if attempt >= LONG_RETRY_THRESHOLD {
            error!(attempt, url = %url, "WS connecting (long retry)");
        } else {
            info!(attempt, url = %url, "WS connecting");
        }

        let ws_stream = match connect_async(url.as_str()).await {
            Ok((stream, _)) => stream,
            Err(e) => {
                if attempt >= LONG_RETRY_THRESHOLD {
                    error!(attempt, "WS connection failed: {e}");
                } else {
                    warn!(attempt, "WS connection failed: {e}");
                }
                attempt += 1;
                backoff(&state, backoff_ms).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };

        info!("WS connected to {}", url);
        *state.write() = WsClientState::Connected { connected_at: Instant::now() };
        attempt = 0;
        backoff_ms = INITIAL_BACKOFF_MS;

        let (mut ws_tx, mut ws_rx) = ws_stream.split();
        let mut ping_interval = tokio::time::interval(PING_INTERVAL);
        let mut last_ping_nonce: u64 = 0;
        let mut awaiting_pong = false;
        let mut pong_deadline = Instant::now();

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    last_ping_nonce = last_ping_nonce.wrapping_add(1);
                    let ping = framing::encode(&WsMessage::Ping(Ping { nonce: last_ping_nonce }));
                    if ws_tx.send(tokio_tungstenite::tungstenite::Message::Binary(ping.into())).await.is_err() {
                        break;
                    }
                    awaiting_pong = true;
                    pong_deadline = Instant::now() + PONG_TIMEOUT;
                }

                msg = ws_rx.next() => {
                    let data = match msg {
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(d))) => d,
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => {
                            info!("WS closed by relay");
                            break;
                        }
                        _ => continue,
                    };
                    match framing::decode(&data) {
                        Ok(WsMessage::BidPush { fork, payload }) => {
                            match decode_bid_push(fork, &payload) {
                                Ok(cached) => {
                                    let value_eth = format_ether(cached.value);
                                    info!(
                                        fork = ?cached.fork,
                                        bytes = payload.len(),
                                        value_eth,
                                        "WS: cached pushed bid"
                                    );
                                    bid_tx.send_replace(Some(cached));
                                }
                                Err(e) => warn!(fork, ?e, "WS: BidPush decode failed"),
                            }
                        }
                        Ok(WsMessage::Ping(p)) => {
                            // Relay-side Ping — respond with Pong immediately
                            // so the relay can measure RTT.
                            let pong = framing::encode(&WsMessage::Pong(Pong { nonce: p.nonce }));
                            let _ = ws_tx
                                .send(tokio_tungstenite::tungstenite::Message::Binary(
                                    pong.into(),
                                ))
                                .await;
                        }
                        Ok(WsMessage::Pong(p)) => {
                            if awaiting_pong && p.nonce == last_ping_nonce { awaiting_pong = false; }
                        }
                        Ok(WsMessage::RegistrationAck(ack)) => {
                            debug!(accepted = ack.accepted, rejected = ack.rejected, "WS: registration ack");
                        }
                        Ok(WsMessage::SubmitBlindedBlockAck(ack)) => {
                            debug!(status = ack.status, "WS: submit blinded block ack");
                            if let Some(tx) = pending_ack.lock().unwrap().take() {
                                let _ = tx.send(ack.status);
                            }
                        }
                        Ok(_) => { debug!("unhandled inbound WS message"); }
                        Err(e) => { warn!(?e, "WS decode error"); }
                    }
                }

                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(msg) => {
                            let encoded = framing::encode(&msg);
                            if ws_tx.send(tokio_tungstenite::tungstenite::Message::Binary(encoded.into())).await.is_err() {
                                warn!("WS send failed, reconnecting");
                                break;
                            }
                        }
                        None => {
                            *state.write() = WsClientState::Failed { reason: "shutdown".into() };
                            return;
                        }
                    }
                }
            }

            if awaiting_pong && Instant::now() > pong_deadline {
                warn!("Pong timeout, reconnecting");
                break;
            }
        }

        info!("WS disconnected, falling back to REST");
        attempt += 1;
        backoff(&state, backoff_ms).await;
        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
    }
}

async fn backoff(state: &Arc<RwLock<WsClientState>>, ms: u64) {
    *state.write() = WsClientState::Backoff { until: Instant::now() + Duration::from_millis(ms) };
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

// ---------------------------------------------------------------------------
// BidPush decode
// ---------------------------------------------------------------------------

fn decode_bid_push(fork_byte: u8, payload: &[u8]) -> eyre::Result<CachedBid> {
    let fork = wire::fork_name_from_u8(fork_byte)
        .map_err(|e| eyre::eyre!("unknown fork byte {fork_byte}: {e}"))?;
    if payload.is_empty() {
        eyre::bail!("empty BidPush payload");
    }
    let signed_bid = SignedBuilderBid::from_ssz_bytes_by_fork(payload, fork)
        .map_err(|e| eyre::eyre!("BidPush SSZ decode failed: {e:?}"))?;
    let value = *signed_bid.message.value();
    let header =
        GetHeaderResponse { version: fork, data: signed_bid, metadata: Default::default() };
    Ok(CachedBid { fork, value, response: CompoundGetHeaderResponse::Full(Box::new(header)) })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[test]
    fn test_state_machine_variants_constructible() {
        let _disconnected = WsClientState::Disconnected;
        let _connecting = WsClientState::Connecting { attempt: 0 };
        let _connected = WsClientState::Connected { connected_at: Instant::now() };
        let _backoff = WsClientState::Backoff { until: Instant::now() + Duration::from_secs(1) };
        let _failed = WsClientState::Failed { reason: "test".into() };
    }

    #[test]
    fn test_fork_byte_encoding_electra_fulu_gloas() {
        assert_eq!(wire::fork_name_to_u8(ForkName::Electra).unwrap(), 1);
        assert_eq!(wire::fork_name_to_u8(ForkName::Fulu).unwrap(), 2);
        assert_eq!(wire::fork_name_to_u8(ForkName::Gloas).unwrap(), 3);
        assert!(wire::fork_name_to_u8(ForkName::Deneb).is_err());
    }

    #[test]
    fn test_watch_bid_cache_latest_wins() {
        // Simulate the watch behavior we rely on: send_replace stores the
        // newest value, borrow returns it, zero buffering.
        let (tx, rx) = watch::channel::<Option<CachedBid>>(None);
        assert!(rx.borrow().is_none());

        // In lieu of a real SignedBuilderBid (which requires BLS-signed
        // fixtures to construct outside Helix-land), we assert the watch
        // semantics that the client depends on: send_replace overwrites
        // and the latest reader sees only the last value.
        //
        // A full end-to-end "push 50 bids of ascending value, see max"
        // test lives in the commit-boost integration crate where signed
        // bid fixtures are available.
        tx.send_replace(None);
        tx.send_replace(None);
        assert!(rx.borrow().is_none());
    }

    #[test]
    fn test_watch_channel_latest_bid_is_cloneable_after_consume() {
        // Invariant: after we read via borrow().clone(), the watch retains
        // the value for subsequent reads. This is what lets get_header
        // re-read a still-valid bid on a later call without the relay
        // having to re-push.
        let (tx, rx) = watch::channel::<Option<u64>>(None);
        tx.send_replace(Some(42));
        assert_eq!(rx.borrow().clone(), Some(42));
        assert_eq!(rx.borrow().clone(), Some(42));
        // Replace and re-read.
        tx.send_replace(Some(100));
        assert_eq!(rx.borrow().clone(), Some(100));
    }

    /// Direct test of submit retry loop (no WS required).
    #[tokio::test]
    async fn test_submit_retry_success_first_attempt() {
        let mut retry = SubmitRetry::new(2, Duration::from_millis(500));
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move { let _ = tx.send(6); });
        assert_eq!(retry.attempt(rx).await, SubmitRetryResult::Ok(6));
        assert_eq!(retry.retries, 0);
    }

    #[tokio::test]
    async fn test_submit_retry_timeout_triggers_would_retry() {
        let mut retry = SubmitRetry::new(2, Duration::from_millis(1));
        let (_tx, rx) = oneshot::channel::<u8>();
        // drop tx — rx will never fire

        let result = retry.attempt(rx).await;
        assert_eq!(result, SubmitRetryResult::WouldRetry);
        assert_eq!(retry.retries, 1);
    }

    #[tokio::test]
    async fn test_submit_retry_max_retries_exhausted() {
        let mut retry = SubmitRetry::new(2, Duration::from_millis(1));

        let (_tx1, rx1) = oneshot::channel::<u8>();
        assert_eq!(retry.attempt(rx1).await, SubmitRetryResult::WouldRetry);
        assert_eq!(retry.retries, 1);

        let (_tx2, rx2) = oneshot::channel::<u8>();
        assert_eq!(retry.attempt(rx2).await, SubmitRetryResult::MaxRetries);
        assert_eq!(retry.retries, 2);
    }
}
