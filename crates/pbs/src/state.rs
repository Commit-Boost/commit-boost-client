use std::{
    collections::HashSet,
    str::FromStr,
    sync::{Arc, Mutex},
};

use alloy::{primitives::B256, rpc::types::beacon::BlsPublicKey};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use cb_common::{
    config::{PbsConfig, PbsModuleConfig},
    pbs::{RelayEntry, HEADER_VERSION_KEY, HEAVER_VERSION_VALUE},
    DEFAULT_REQUEST_TIMEOUT,
};
use dashmap::DashMap;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{types::GetHeaderReponse, BuilderEvent};

pub trait BuilderApiState: std::fmt::Debug + Default + Clone + Sync + Send + 'static {}
impl BuilderApiState for () {}

pub type BuilderEventReceiver = broadcast::Receiver<BuilderEvent>;

/// State for the Pbs module. It can be extended in two ways:
/// - By adding extra configs to be loaded at startup
/// - By adding extra data to the state
#[derive(Debug, Clone)]
pub struct PbsState<U, S: BuilderApiState = ()> {
    /// Config data for the Pbs service
    pub config: Arc<PbsModuleConfig<U>>,
    /// Opaque extra data for library use
    pub data: S,
    /// Relay client to reuse across requests
    relay_client: reqwest::Client,
    /// Pubsliher for builder events
    event_publisher: broadcast::Sender<BuilderEvent>,
    /// Info about the latest slot and its uuid
    current_slot_info: Arc<Mutex<(u64, Uuid)>>,
    /// Keeps track of which relays delivered which block for which slot
    bid_cache: Arc<DashMap<u64, Vec<GetHeaderReponse>>>,
}

impl<U, S> PbsState<U, S>
where
    S: BuilderApiState,
{
    pub fn new(config: PbsModuleConfig<U>) -> Self {
        let (tx, _) = broadcast::channel(10);

        let mut headers = HeaderMap::new();
        headers.insert(HEADER_VERSION_KEY, HeaderValue::from_static(HEAVER_VERSION_VALUE));

        if let Some(custom_headers) = &config.pbs_config.headers {
            for (key, value) in custom_headers.iter() {
                headers.insert(
                    HeaderName::from_str(key).expect("invalid header name"),
                    HeaderValue::from_str(&value).expect("invalid header value"),
                );
            }
        }

        let relay_client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .expect("failed to build relay client");

        Self {
            config: Arc::new(config),
            data: S::default(),
            relay_client,
            event_publisher: tx,
            current_slot_info: Arc::new(Mutex::new((0, Uuid::default()))),
            bid_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn with_data(self, data: S) -> Self {
        Self { data, ..self }
    }

    pub fn publish_event(&self, e: BuilderEvent) {
        // ignore client errors
        let _ = self.event_publisher.send(e);
    }

    pub fn subscribe_events(&self) -> BuilderEventReceiver {
        self.event_publisher.subscribe()
    }

    pub fn get_or_update_slot_uuid(&self, last_slot: u64) -> Uuid {
        let mut guard = self.current_slot_info.lock().expect("poisoned");
        if guard.0 < last_slot {
            // new slot
            guard.0 = last_slot;
            guard.1 = Uuid::new_v4();
            self.clear(last_slot);
        }
        guard.1
    }

    pub fn get_slot_and_uuid(&self) -> (u64, Uuid) {
        let guard = self.current_slot_info.lock().expect("poisoned");
        *guard
    }

    // Getters
    pub fn pbs_config(&self) -> &PbsConfig {
        &self.config.pbs_config
    }
    pub fn relays(&self) -> &[RelayEntry] {
        &self.pbs_config().relays
    }
    pub fn relay_client(&self) -> reqwest::Client {
        self.relay_client.clone()
    }

    /// Add some bids to the cache, the bids are all assumed to be for the
    /// provided slot Returns the bid with the max value
    /// TODO: this doesnt handle cancellations if we call multiple times
    /// get_header
    pub fn add_bids(&self, slot: u64, bids: Vec<GetHeaderReponse>) -> Option<GetHeaderReponse> {
        let mut slot_entry = self.bid_cache.entry(slot).or_default();
        slot_entry.extend(bids);
        slot_entry.iter().max_by_key(|bid| bid.value()).cloned()
    }

    /// Retrieves a list of relays pubkeys that delivered a given block hash
    /// Returns None if we dont have bids for the slot or for the block hash
    pub fn get_relays_by_block_hash(
        &self,
        slot: u64,
        block_hash: B256,
    ) -> Option<HashSet<BlsPublicKey>> {
        self.bid_cache.get(&slot).and_then(|bids| {
            let filtered: HashSet<_> = bids
                .iter()
                .filter(|&bid| (bid.block_hash() == block_hash))
                .map(|bid| bid.pubkey())
                .collect();

            (!filtered.is_empty()).then_some(filtered)
        })
    }

    /// Clear bids which are more than ~3 minutes old
    fn clear(&self, last_slot: u64) {
        self.bid_cache.retain(|slot, _| last_slot.saturating_sub(*slot) < 15)
    }
}
