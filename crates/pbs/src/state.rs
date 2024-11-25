use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use alloy::{primitives::B256, rpc::types::beacon::BlsPublicKey};
use cb_common::{
    config::{PbsConfig, PbsModuleConfig},
    pbs::{BuilderEvent, GetHeaderResponse, RelayClient},
};
use dashmap::DashMap;
use uuid::Uuid;

pub trait BuilderApiState: Clone + Sync + Send + 'static {}
impl BuilderApiState for () {}

/// State for the Pbs module. It can be extended by adding extra data to the
/// state
#[derive(Clone)]
pub struct PbsState<S: BuilderApiState = ()> {
    /// Config data for the Pbs service
    pub config: PbsModuleConfig,
    /// Opaque extra data for library use
    pub data: S,
    /// Info about the latest slot and its uuid
    current_slot_info: Arc<Mutex<(u64, Uuid)>>,
    /// Keeps track of which relays delivered which block for which slot
    bid_cache: Arc<DashMap<u64, Vec<GetHeaderResponse>>>,
}

impl PbsState<()> {
    pub fn new(config: PbsModuleConfig) -> Self {
        Self {
            config,
            data: (),
            current_slot_info: Arc::new(Mutex::new((0, Uuid::new_v4()))),
            bid_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn with_data<S: BuilderApiState>(self, data: S) -> PbsState<S> {
        PbsState {
            data,
            config: self.config,
            current_slot_info: self.current_slot_info,
            bid_cache: self.bid_cache,
        }
    }
}

impl<S> PbsState<S>
where
    S: BuilderApiState,
{
    pub fn publish_event(&self, e: BuilderEvent) {
        if let Some(publisher) = self.config.event_publisher.as_ref() {
            publisher.publish(e);
        }
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

    pub fn relays(&self) -> &[RelayClient] {
        &self.config.relays
    }
    /// Returns the PBS config and relay clients for the given validator pubkey.
    /// If the pubkey is not found in any mux, the default configs are
    /// returned
    pub fn mux_config_and_relays(
        &self,
        pubkey: &BlsPublicKey,
    ) -> (&PbsConfig, &[RelayClient], bool) {
        match self.config.muxes.as_ref().and_then(|muxes| muxes.get(pubkey)) {
            Some(mux) => (&mux.config, mux.relays.as_slice(), true),
            None => (self.pbs_config(), self.relays(), false),
        }
    }

    pub fn has_monitors(&self) -> bool {
        !self.config.pbs_config.relay_monitors.is_empty()
    }

    pub fn extra_validation_enabled(&self) -> bool {
        self.config.pbs_config.extra_validation_enabled
    }

    /// Add some bids to the cache, the bids are all assumed to be for the
    /// provided slot Returns the bid with the max value
    pub fn add_bids(&self, slot: u64, bids: Vec<GetHeaderResponse>) -> Option<GetHeaderResponse> {
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
