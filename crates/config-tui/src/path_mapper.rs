//! Maps serde error paths to user-visible paths.
//!
//! Handles:
//! - `#[serde(flatten)]` on `StaticPbsConfig.pbs_config` — strips `pbs_config`
//!   segment
//! - `#[serde(rename = "url")]` on `RelayConfig.entry` — maps `entry` → `url`
//!   in relay paths

/// Strip the `pbs_config` flatten artifact from paths like `pbs.pbs_config.X` →
/// `pbs.X`. Map `entry` to `url` in relay array paths like `relays[0].entry` →
/// `relays[0].url`.
pub fn map_path(serde_path: &str) -> String {
    // Strip the pbs_config flatten artifact
    let result = serde_path.replace("pbs.pbs_config.", "pbs.");
    // Replace `.entry` with `.url` only when preceded by `]` (array index),
    // since only RelayConfig uses `#[serde(rename = "url")]` on its `entry` field.
    result.replace("].entry", "].url")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strips_pbs_config_flatten() {
        let input = "pbs.pbs_config.timeout_get_header_ms";
        assert_eq!(map_path(input), "pbs.timeout_get_header_ms");
    }

    #[test]
    fn test_noop_for_non_flattened_path() {
        assert_eq!(map_path("pbs.timeout_get_header_ms"), "pbs.timeout_get_header_ms");
    }

    #[test]
    fn test_maps_entry_to_url_after_array_index() {
        assert_eq!(map_path("relays[0].entry"), "relays[0].url");
        assert_eq!(map_path("relays[1].entry"), "relays[1].url");
    }

    #[test]
    fn test_does_not_map_entry_without_array_index() {
        // Only .entry after ] should be mapped
        assert_eq!(map_path("pbs.entry"), "pbs.entry");
    }

    #[test]
    fn test_noop_for_unrelated_path() {
        assert_eq!(map_path("chain"), "chain");
    }

    #[test]
    fn test_handles_nested_array_mux_relays() {
        assert_eq!(map_path("muxes.muxes[0].relays[1].entry"), "muxes.muxes[0].relays[1].url");
    }
}
