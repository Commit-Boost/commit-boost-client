//! Serde ignores unknown `[pbs]` and `[[mux]]` keys, so a typo such as
//! `min_bid_p2p_eht` would project the default; builder-config refuses the
//! config instead. Relay entries already reject unknown keys.

/// `StaticPbsConfig` and its flattened `PbsConfig`, as serde names them
const PBS_KEYS: &[&str] = &[
    "docker_image",
    "with_signer",
    "host",
    "port",
    "relay_check",
    "wait_all_registrations",
    "timeout_get_header_ms",
    "timeout_get_payload_ms",
    "timeout_register_validator_ms",
    "skip_sigverify",
    "min_bid_eth",
    "late_in_slot_time_ms",
    "proposer_deadline_buffer_ms",
    "extra_validation_enabled",
    "rpc_url",
    "ssv_node_api_url",
    "ssv_public_api_url",
    "http_timeout_seconds",
    "register_validator_retry_limit",
    "validator_registration_batch_size",
    "mux_registry_refresh_interval_seconds",
    "max_execution_payment_gwei",
    "min_bid_p2p_eth",
    "builder_boost_factor_p2p",
];

/// `MuxConfig`, as serde names it
const MUX_KEYS: &[&str] = &[
    "id",
    "relays",
    "validator_pubkeys",
    "loader",
    "timeout_get_header_ms",
    "late_in_slot_time_ms",
    "builder_boost_factor",
    "min_bid_eth",
];

/// Every `[pbs]` and `[[mux]]` key Commit-Boost does not read, naming its table
pub fn unknown_keys(raw: &toml::Value) -> Vec<String> {
    let mut unknown = Vec::new();
    if let Some(pbs) = raw.get("pbs").and_then(toml::Value::as_table) {
        for key in pbs.keys().filter(|key| !PBS_KEYS.contains(&key.as_str())) {
            unknown.push(format!("`{key}` in [pbs]"));
        }
    }
    let muxes = raw.get("mux").and_then(toml::Value::as_array).into_iter().flatten();
    for table in muxes.filter_map(toml::Value::as_table) {
        let id = table.get("id").and_then(toml::Value::as_str).unwrap_or_default();
        for key in table.keys().filter(|key| !MUX_KEYS.contains(&key.as_str())) {
            unknown.push(format!("`{key}` in [[mux]] {id}"));
        }
    }
    unknown
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::Ipv4Addr};

    use alloy::primitives::U256;
    use cb_common::config::{
        ExecutionPaymentCap, MuxConfig, MuxKeysLoader, PbsConfig, StaticPbsConfig,
    };
    use url::Url;

    use super::*;

    fn keys(value: &toml::Value) -> BTreeSet<String> {
        value.as_table().unwrap().keys().cloned().collect()
    }

    fn set(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|key| key.to_string()).collect()
    }

    // Every Option is set, since toml drops a None, and a new field does not
    // compile until it is set here
    #[test]
    fn lists_match_the_keys_commit_boost_reads() {
        let url = |s: &str| Url::parse(s).unwrap();
        let pbs = StaticPbsConfig {
            docker_image: "ghcr.io/commit-boost/pbs:latest".into(),
            pbs_config: PbsConfig {
                host: Ipv4Addr::LOCALHOST,
                port: 18550,
                relay_check: true,
                wait_all_registrations: true,
                timeout_get_header_ms: 950,
                timeout_get_payload_ms: 4000,
                timeout_register_validator_ms: 3000,
                skip_sigverify: false,
                min_bid_wei: U256::from(1),
                late_in_slot_time_ms: 2000,
                proposer_deadline_buffer_ms: 50,
                extra_validation_enabled: false,
                rpc_url: Some(url("https://rpc.example.com")),
                ssv_node_api_url: url("https://ssv.example.com"),
                ssv_public_api_url: url("https://ssv-public.example.com"),
                http_timeout_seconds: 30,
                register_validator_retry_limit: 3,
                validator_registration_batch_size: Some(10),
                mux_registry_refresh_interval_seconds: 384,
                max_execution_payment_gwei: Some(ExecutionPaymentCap::Unclamped),
                min_bid_p2p_wei: Some(U256::from(2)),
                builder_boost_factor_p2p: Some(90),
            },
            with_signer: false,
        };
        let mux = MuxConfig {
            id: "m".into(),
            relays: vec![],
            validator_pubkeys: vec![],
            loader: Some(MuxKeysLoader::File("./keys.json".into())),
            timeout_get_header_ms: Some(900),
            late_in_slot_time_ms: Some(1500),
            builder_boost_factor: Some(100),
            min_bid_wei: Some(U256::from(3)),
        };

        let pbs = toml::Value::try_from(&pbs).unwrap();
        assert_eq!(keys(&pbs), set(PBS_KEYS));
        pbs.try_into::<StaticPbsConfig>().unwrap();
        let mux = toml::Value::try_from(&mux).unwrap();
        assert_eq!(keys(&mux), set(MUX_KEYS));
        mux.try_into::<MuxConfig>().unwrap();
    }
}
