//! Accessors for the projection-only MuxConfig fields. The overlay's per-mux
//! map stays the fallback source for the non-p2p fields below them.

use alloy_primitives::U256;
use cb_common::config::MuxConfig;

pub trait MuxProjectionFields {
    /// Per-mux builder boost factor for entries and the key level.
    fn projected_boost_factor(&self) -> Option<u64>;
    /// Per-mux minimum bid in wei for entries and the key level.
    fn projected_min_bid_wei(&self) -> Option<U256>;
    /// Per-mux KEY-LEVEL builder boost factor governing p2p bids.
    fn projected_boost_factor_p2p(&self) -> Option<u64>;
    /// Per-mux KEY-LEVEL minimum bid in wei governing p2p bids.
    fn projected_min_bid_p2p_wei(&self) -> Option<U256>;
}

impl MuxProjectionFields for MuxConfig {
    fn projected_boost_factor(&self) -> Option<u64> {
        self.builder_boost_factor
    }

    fn projected_min_bid_wei(&self) -> Option<U256> {
        self.min_bid_wei
    }

    fn projected_boost_factor_p2p(&self) -> Option<u64> {
        self.builder_boost_factor_p2p
    }

    fn projected_min_bid_p2p_wei(&self) -> Option<U256> {
        self.min_bid_p2p_wei
    }
}
