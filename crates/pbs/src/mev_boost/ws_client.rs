//! WebSocket client state machine for the Builder API WS extension.
//! See ARCH.md §10 for the full state machine specification.
//!
//! State transitions:
//!   Disconnected → Connecting → Authenticating → Connected
//!   Connected → Backoff → Connecting (on disconnect/ping timeout)
//!   Authenticating → Backoff (all acks rejected)
//!   Connecting → Failed (after max retries)

use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use ssz_types::VariableList;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use futures_util::{SinkExt, StreamExt};
use tracing::{info, warn, debug};

use crate::mev_boost::ws_messages::*;

// ---------------------------------------------------------------------------
// State types
// ---------------------------------------------------------------------------

/// The current state of the WebSocket client state machine.
#[derive(Clone, Debug)]
pub enum WsClientState {
    /// Initial state, or clean disconnect.
    Disconnected,

    /// Attempting to establish a WebSocket connection.
    Connecting { attempt: u32, started_at: Instant },

    /// TCP+TLS connected; sent validator registration; awaiting acks.
    Authenticating { sent_count: u32 },

    /// Fully connected and receiving bid pushes.
    Connected { connected_at: Instant },

    /// In exponential backoff before retrying connection.
    Backoff { until: Instant, reason: DisconnectReason },

    /// Permanently failed (max retries exceeded or unrecoverable error).
    Failed { reason: String },
}

/// Why the WebSocket disconnected.
#[derive(Clone, Debug, PartialEq)]
pub enum DisconnectReason {
    ConnectionRefused,
    AuthRejected(String),
    AuthAllStale,
    PingTimeout,
    ConnectionReset,
    ProtocolError(String),
}

// ---------------------------------------------------------------------------
// AuthTracker
// ---------------------------------------------------------------------------

/// Tracks validator registration acknowledgments during the Authenticating phase.
#[derive(Clone, Debug)]
pub struct AuthTracker {
    /// How many registrations were sent in the batch.
    pub sent_count: u32,
    /// How many acks have been received so far.
    pub received: u32,
    /// How many acks were `accepted: true`.
    pub accepted: u32,
}

impl AuthTracker {
    pub fn new(sent_count: u32) -> Self {
        Self { sent_count, received: 0, accepted: 0 }
    }

    /// Record one ack. Returns true if authentication is complete (all acks received).
    pub fn record_ack(&mut self, accepted: bool) -> bool {
        self.received += 1;
        if accepted { self.accepted += 1; }
        self.is_complete()
    }

    /// True when all sent registrations have been acknowledged.
    pub fn is_complete(&self) -> bool { self.received >= self.sent_count }

    /// Number of accepted registrations.
    pub fn accepted_count(&self) -> u32 { self.accepted }

    /// Should the client back off? True if all acks received but zero accepted.
    pub fn should_backoff(&self) -> bool {
        self.is_complete() && self.accepted == 0
    }
}

// ---------------------------------------------------------------------------
// HelixWsClient
// ---------------------------------------------------------------------------

/// A persistent WebSocket connection to a single Helix relay.
///
/// Holds the shared state and provides methods to query bids, disconnect, etc.
pub struct HelixWsClient {
    /// Shared state, readable by the BuilderApi aggregator.
    pub state: Arc<RwLock<WsClientState>>,

    /// Channel to send messages to the background connection task.
    ws_sender: mpsc::UnboundedSender<WsMessage>,

    /// Channel to receive bid pushes from the background task.
    bid_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<BidPush>>>>,
}

impl HelixWsClient {
    /// Spawn the WebSocket client, starting the state machine in the background.
    ///
    /// `url` must be a `ws://` or `wss://` URL pointing to the relay's WS endpoint.
    /// `registrations` is the initial batch of signed validator registrations.
    pub fn spawn(
        url: url::Url,
        registrations: Vec<WireSignedValidatorRegistration>,
    ) -> Self {
        let state = Arc::new(RwLock::new(WsClientState::Disconnected));
        let (tx, mut rx) = mpsc::unbounded_channel::<WsMessage>();
        let (bid_tx, bid_rx) = mpsc::unbounded_channel::<BidPush>();

        let s = state.clone();
        let batch = ValidatorRegistration {
            registrations: VariableList::from(registrations.clone()),
        };
        let sent_count = registrations.len() as u32;

        tokio::spawn(async move {
            connection_loop(url, s, &mut rx, bid_tx, batch, sent_count).await;
        });

        HelixWsClient {
            state,
            ws_sender: tx,
            bid_receiver: Arc::new(RwLock::new(Some(bid_rx))),
        }
    }

    /// Snapshot of current state.
    pub fn state_snapshot(&self) -> WsClientState { self.state.read().clone() }

    /// Get the cached bid for a slot/parent_hash pair (if any).
    /// Currently a placeholder — full cache logic added in Phase 3.x.
    pub fn best_bid(&self) -> Option<BidPush> {
        let mut rx_guard = self.bid_receiver.write();
        if let Some(rx) = rx_guard.as_mut() {
            // Drain the channel and return the latest bid
            let mut last = None;
            while let Ok(bid) = rx.try_recv() {
                last = Some(bid);
            }
            last
        } else {
            None
        }
    }

    /// Send a message over the WebSocket (non-blocking).
    pub fn send(&self, msg: WsMessage) {
        let _ = self.ws_sender.send(msg);
    }
}

// ---------------------------------------------------------------------------
// State machine loop
// ---------------------------------------------------------------------------

const MAX_RETRIES: u32 = 10;
const INITIAL_BACKOFF_MS: u64 = 500;
const MAX_BACKOFF_MS: u64 = 30_000;
const PING_INTERVAL: Duration = Duration::from_secs(15);
const PONG_TIMEOUT: Duration = Duration::from_secs(5);

async fn connection_loop(
    url: url::Url,
    state: Arc<RwLock<WsClientState>>,
    _cmd_rx: &mut mpsc::UnboundedReceiver<WsMessage>,
    bid_tx: mpsc::UnboundedSender<BidPush>,
    batch: ValidatorRegistration,
    sent_count: u32,
) {
    let mut attempt: u32 = 0;
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        // ----- Connecting -----
        *state.write() = WsClientState::Connecting { attempt, started_at: Instant::now() };
        debug!(attempt, "WebSocket connecting to {}", url);

        let ws_stream = match connect_async(url.as_str()).await {
            Ok((stream, _)) => stream,
            Err(e) => {
                warn!(attempt, "WebSocket connection failed: {e}");
                if attempt >= MAX_RETRIES {
                    *state.write() = WsClientState::Failed { reason: format!("max retries ({MAX_RETRIES}) exceeded") };
                    return;
                }
                attempt += 1;
                backoff_step(&state, backoff_ms, DisconnectReason::ConnectionRefused).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };

        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        // ----- Authenticating: send registration batch -----
        *state.write() = WsClientState::Authenticating { sent_count };
        debug!("WebSocket connected, sending {} registrations", sent_count);

        let reg_msg = framing::encode(&WsMessage::ValidatorRegistration(batch.clone()));
        if ws_tx.send(tokio_tungstenite::tungstenite::Message::Binary(reg_msg.into())).await.is_err() {
            warn!("Failed to send registration; reconnecting");
            attempt += 1;
            backoff_step(&state, backoff_ms, DisconnectReason::ConnectionReset).await;
            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            continue;
        }

        // Collect acks
        let mut auth_tracker = AuthTracker::new(sent_count);
        let mut connected = false;

        // ----- Main read loop -----
        let was_previously_connected = connected;  // track reconnect for logging
        let mut ping_interval = tokio::time::interval(PING_INTERVAL);
        let mut last_ping_nonce: u64 = 0;
        let mut awaiting_pong = false;
        let mut pong_deadline = Instant::now();

        loop {
            tokio::select! {
                // Periodic ping
                _ = ping_interval.tick() => {
                    if matches!(*state.read(), WsClientState::Connected { .. }) {
                        last_ping_nonce = last_ping_nonce.wrapping_add(1);
                        let ping = framing::encode(&WsMessage::Ping(Ping { nonce: last_ping_nonce }));
                        if ws_tx.send(tokio_tungstenite::tungstenite::Message::Binary(ping.into())).await.is_err() {
                            break;
                        }
                        awaiting_pong = true;
                        pong_deadline = Instant::now() + PONG_TIMEOUT;
                    }
                }

                // Inbound WS message
                msg = ws_rx.next() => {
                    let msg = match msg {
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => data,
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => {
                            warn!("WebSocket closed by relay");
                            break;
                        }
                        _ => continue,
                    };

                    let decoded = match framing::decode(&msg) {
                        Ok(d) => d,
                        Err(e) => { warn!("WS decode error: {e:?}"); continue; }
                    };

                    match decoded {
                        WsMessage::RegistrationAck(ack) => {
                            let done = auth_tracker.record_ack(ack.accepted);
                            debug!(accepted=ack.accepted, received=auth_tracker.received, total=auth_tracker.sent_count, "RegistrationAck");
                            if done {
                                if auth_tracker.should_backoff() {
                                    warn!("All registrations rejected; backing off");
                                    *state.write() = WsClientState::Backoff {
                                        until: Instant::now() + Duration::from_millis(backoff_ms),
                                        reason: DisconnectReason::AuthAllStale,
                                    };
                                    return; // exit loop, reconnect
                                }
                                if !connected {
                                    connected = true;
                                if was_previously_connected {
                                    info!("WebSocket reconnected ({} acks accepted)", auth_tracker.accepted_count());
                                } else {
                                    info!("WebSocket connected ({} acks accepted)", auth_tracker.accepted_count());
                                }
                                    *state.write() = WsClientState::Connected { connected_at: Instant::now() };
                                }
                            }
                        }
                        WsMessage::BidPush(bid) => {
                            let _ = bid_tx.send(bid);
                        }
                        WsMessage::Pong(pong) => {
                            if awaiting_pong && pong.nonce == last_ping_nonce {
                                awaiting_pong = false;
                            }
                        }
                        _ => { debug!("Unhandled WS message"); }
                    }
                }

                // Pong timeout check
                _ = tokio::time::sleep(Duration::from_millis(100)), if awaiting_pong && Instant::now() > pong_deadline => {
                    warn!("Pong timeout; disconnecting");
                    break;
                }
            }

            // Check pong timeout (non-async check after each iteration)
            if awaiting_pong && Instant::now() > pong_deadline {
                warn!("Pong timeout; disconnecting");
                break;
            }
        }

        let reason = DisconnectReason::ConnectionReset;
        warn!("ws disconnected, using REST");
        attempt += 1;
        if attempt >= MAX_RETRIES {
            *state.write() = WsClientState::Failed { reason: format!("max retries ({MAX_RETRIES}) exceeded") };
            return;
        }
        backoff_step(&state, backoff_ms, reason).await;
        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
    }
}

async fn backoff_step(state: &Arc<RwLock<WsClientState>>, ms: u64, reason: DisconnectReason) {
    let until = Instant::now() + Duration::from_millis(ms);
    warn!("ws disconnected, using REST");
    *state.write() = WsClientState::Backoff { until, reason };
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_tracker_accepts_all() {
        let mut t = AuthTracker::new(3);
        assert!(!t.is_complete());
        t.record_ack(true); assert!(!t.is_complete());
        t.record_ack(true); assert!(!t.is_complete());
        assert!(t.record_ack(true));
        assert!(t.is_complete());
        assert_eq!(t.accepted_count(), 3);
        assert!(!t.should_backoff());
    }

    #[test]
    fn auth_tracker_all_rejected_backoff() {
        let mut t = AuthTracker::new(2);
        t.record_ack(false);
        t.record_ack(false);
        assert!(t.is_complete());
        assert_eq!(t.accepted_count(), 0);
        assert!(t.should_backoff());
    }

    #[test]
    fn auth_tracker_partial_accepted() {
        let mut t = AuthTracker::new(3);
        t.record_ack(true);
        t.record_ack(false);
        t.record_ack(true);
        assert!(t.is_complete());
        assert_eq!(t.accepted_count(), 2);
        assert!(!t.should_backoff());
    }

    #[test]
    fn ws_client_state_transitions() {
        // Verify state enum variants can be constructed
        let _disconnected = WsClientState::Disconnected;
        let _connecting = WsClientState::Connecting { attempt: 0, started_at: Instant::now() };
        let _auth = WsClientState::Authenticating { sent_count: 5 };
        let _connected = WsClientState::Connected { connected_at: Instant::now() };
        let _backoff = WsClientState::Backoff {
            until: Instant::now() + Duration::from_secs(1),
            reason: DisconnectReason::ConnectionRefused,
        };
        let _failed = WsClientState::Failed { reason: "test".into() };
    }
}
