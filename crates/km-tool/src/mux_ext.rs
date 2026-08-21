//! Seam for MuxConfig fields the projection reads but this cb-common revision
//! does not carry yet (`builder_boost_factor`, `min_bid`). Once cb-common
//! gains them, implement these accessors to read the config fields; the
//! overlay's per-mux map stays as the fallback source below them.

use alloy_primitives::U256;
use cb_common::config::MuxConfig;

pub trait MuxProjectionFields {
    /// Per-mux builder boost factor, when the config schema carries it.
    fn projected_boost_factor(&self) -> Option<u64>;
    /// Per-mux minimum bid in wei, when the config schema carries it.
    fn projected_min_bid_wei(&self) -> Option<U256>;
}

impl MuxProjectionFields for MuxConfig {
    fn projected_boost_factor(&self) -> Option<u64> {
        self.builder_boost_factor
    }

    fn projected_min_bid_wei(&self) -> Option<U256> {
        self.min_bid_wei
    }
}
