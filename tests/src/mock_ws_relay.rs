use std::{
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::primitives::{B256, U256};
use cb_common::{
    pbs::{HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, HEADER_VERSION_KEY},
    types::{BlsSecretKey, Chain},
};
use futures::SinkExt;
use ssz::Encode;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{Request, Response},
    },
};
use tracing::debug;

use crate::mock_relay::mock_signed_builder_bid;

const MSG_BID: u8 = 0x01;
const FORK_FULU: u8 = 6;

/// What PBS sent in the handshake, captured for assertions.
#[derive(Debug, Clone)]
pub struct StreamRequest {
    pub slot: u64,
    pub parent_hash: B256,
    pub validator_pubkey: String,
    pub timeout_ms: Option<u64>,
    pub start_time_ms: Option<u64>,
    pub user_agent: Option<String>,
    pub cb_version: Option<String>,
}

pub struct MockWsRelayState {
    pub chain: Chain,
    pub signer: BlsSecretKey,
    /// One frame pushed per value, in order. The last one is what PBS must
    /// return.
    bid_values: Vec<U256>,
    /// Pause between updates
    update_interval: Duration,
    /// Keep the connection open after the last update, so PBS returns on its
    /// own deadline instead of on close
    hold_open: bool,
    received_connections: AtomicU64,
    last_request: Mutex<Option<StreamRequest>>,
}

impl MockWsRelayState {
    pub fn new(chain: Chain, signer: BlsSecretKey) -> Self {
        Self {
            chain,
            signer,
            bid_values: vec![U256::from(10)],
            update_interval: Duration::ZERO,
            hold_open: false,
            received_connections: AtomicU64::new(0),
            last_request: Mutex::new(None),
        }
    }

    pub fn with_bid_values(self, bid_values: Vec<U256>) -> Self {
        Self { bid_values, ..self }
    }

    pub fn with_update_interval(self, update_interval: Duration) -> Self {
        Self { update_interval, ..self }
    }

    pub fn hold_open(self) -> Self {
        Self { hold_open: true, ..self }
    }

    pub fn received_connections(&self) -> u64 {
        self.received_connections.load(Ordering::Relaxed)
    }

    pub fn last_request(&self) -> Option<StreamRequest> {
        self.last_request.lock().unwrap().clone()
    }
}

pub async fn start_mock_ws_relay_service(
    state: Arc<MockWsRelayState>,
    listener: TcpListener,
) -> eyre::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_stream(state, stream).await {
                debug!(%addr, %err, "mock ws relay connection ended");
            }
        });
    }
}

// The handshake callback's Err type is fixed by tungstenite
#[allow(clippy::result_large_err)]
async fn serve_stream(state: Arc<MockWsRelayState>, stream: TcpStream) -> eyre::Result<()> {
    let mut request = None;
    let mut ws = accept_hdr_async(stream, |req: &Request, res: Response| {
        request = parse_request(req);
        Ok(res)
    })
    .await?;

    let request = request.ok_or_else(|| eyre::eyre!("malformed get_header stream request"))?;
    state.received_connections.fetch_add(1, Ordering::Relaxed);
    *state.last_request.lock().unwrap() = Some(request.clone());

    for value in &state.bid_values {
        let bid = mock_signed_builder_bid(
            state.chain,
            &state.signer,
            request.slot,
            request.parent_hash,
            *value,
        );

        let mut frame = vec![MSG_BID, FORK_FULU];
        frame.extend_from_slice(&bid.as_ssz_bytes());
        ws.send(Message::Binary(frame.into())).await?;

        if !state.update_interval.is_zero() {
            tokio::time::sleep(state.update_interval).await;
        }
    }

    if state.hold_open {
        // Never resolves: PBS has to cut the stream off at its own deadline
        std::future::pending::<()>().await;
    }

    ws.close(None).await?;

    Ok(())
}

/// The request is the handshake: `/{slot}/{parent_hash}/{pubkey}` plus the
/// same headers the HTTP path sends.
fn parse_request(req: &Request) -> Option<StreamRequest> {
    let mut segments = req.uri().path().trim_start_matches('/').split('/');
    let slot = segments.next()?.parse().ok()?;
    let parent_hash = B256::from_str(segments.next()?).ok()?;
    let validator_pubkey = segments.next()?.to_string();

    Some(StreamRequest {
        slot,
        parent_hash,
        validator_pubkey,
        timeout_ms: header(req, HEADER_TIMEOUT_MS).and_then(|v| v.parse().ok()),
        start_time_ms: header(req, HEADER_START_TIME_UNIX_MS).and_then(|v| v.parse().ok()),
        user_agent: header(req, "user-agent"),
        cb_version: header(req, HEADER_VERSION_KEY),
    })
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name)?.to_str().ok().map(ToOwned::to_owned)
}
