//! Projects a Commit-Boost config into each validator key's builder config,
//! routing a key as Commit-Boost does: a mux key to its mux's relays, any other
//! key to `[[relays]]`.
//!
//! Each relay hostname gets one entry, at Commit-Boost's URL, with the hostname
//! as its auth data, so relays on one host share an entry. `builder_pubkeys` is
//! empty, accepting any builder: the pubkey in a relay URL is the relay's, not
//! the builder's bid-signing key.

use std::collections::{BTreeMap, BTreeSet};

use alloy::primitives::{U256, hex, utils::Unit};
use cb_common::{
    config::{
        CommitBoostConfig, ExecutionPaymentCap, MuxKeysLoader, PbsConfig, RelayConfig,
        check_mux_tables,
    },
    types::BlsPublicKey,
};
use eyre::{Context, Result, ensure};

use crate::{
    doc::{BuilderConfig, BuilderEntry, MAX_BUILDER_ENTRIES},
    unknown_keys::unknown_keys,
};

/// Unset, a bid counts at its value against the local block's
const BUILDER_BOOST_FACTOR: u64 = 100;

pub fn parse_config(text: &str) -> Result<CommitBoostConfig> {
    let raw: toml::Value = toml::from_str(text).wrap_err("could not parse Commit-Boost config")?;
    check_mux_tables(&raw)?;
    let unknown = unknown_keys(&raw);
    ensure!(unknown.is_empty(), "unknown keys in the Commit-Boost config: {}", unknown.join(", "));
    toml::from_str(text).wrap_err("could not parse Commit-Boost config")
}

/// Each mux's keys, resolved as Commit-Boost resolves them at startup, file,
/// URL and registry loaders included
pub async fn mux_keys(cfg: &CommitBoostConfig) -> Result<BTreeMap<String, Vec<BlsPublicKey>>> {
    let Some(mut muxes) = cfg.muxes.clone() else { return Ok(BTreeMap::new()) };
    let mut ids = BTreeSet::new();
    for mux in &mut muxes.muxes {
        // Keys are grouped by mux id below, so two muxes with one id would merge
        ensure!(ids.insert(mux.id.clone()), "mux id {} names more than one [[mux]]", mux.id);
        // builder-config never contacts a relay, so it needs none of their header
        // secrets
        for relay in &mut mux.relays {
            relay.headers = None;
        }
    }
    // builder-config reads no bids, so it needs rpc_url only for a registry loader
    let mut pbs = cfg.pbs.pbs_config.clone();
    if !muxes.muxes.iter().any(|mux| matches!(mux.loader, Some(MuxKeysLoader::Registry { .. }))) {
        pbs.rpc_url = None;
        pbs.extra_validation_enabled = false;
    }
    let (lookup, _) = muxes
        .validate_and_fill(cfg.chain, &pbs)
        .await
        .wrap_err("could not resolve the mux keys as Commit-Boost does at startup")?;
    let mut keys: BTreeMap<String, Vec<BlsPublicKey>> = BTreeMap::new();
    for (key, mux) in lookup {
        keys.entry(mux.id).or_default().push(key);
    }
    Ok(keys)
}

#[derive(Debug)]
pub struct Projection {
    /// Builder config by mux key, in 0x-hex
    pub mux_docs: BTreeMap<String, BuilderConfig>,
    /// Mux keys only a URL or registry loader lists, which the config does not
    /// name
    pub fetched_keys: BTreeSet<String>,
    /// The builder config of any other key, from `[[relays]]`; none when it is
    /// empty
    pub relays_doc: Option<BuilderConfig>,
    /// Mux key -> its mux's id
    pub mux_ids: BTreeMap<String, String>,
}

impl Projection {
    /// The builder config apply writes for `key`
    pub fn doc_for(&self, key: &str) -> Option<&BuilderConfig> {
        self.mux_docs.get(key).or(self.relays_doc.as_ref())
    }

    /// Whether any entry has a cap above 0, which Lodestar refuses without a
    /// flag
    pub fn has_nonzero_cap(&self) -> bool {
        self.mux_docs.values().chain(&self.relays_doc).any(BuilderConfig::has_nonzero_cap)
    }
}

pub fn project(
    cfg: &CommitBoostConfig,
    mux_keys: &BTreeMap<String, Vec<BlsPublicKey>>,
    advertised_url: &str,
) -> Result<Projection> {
    let pbs = &cfg.pbs.pbs_config;
    let mut mux_docs = BTreeMap::new();
    let mut fetched_keys = BTreeSet::new();
    let mut mux_ids = BTreeMap::new();
    for mux in cfg.muxes.iter().flat_map(|muxes| &muxes.muxes) {
        let doc = project_relays(
            pbs,
            &mux.relays,
            mux.min_bid_wei,
            mux.builder_boost_factor,
            advertised_url,
        )
        .wrap_err_with(|| format!("mux {}", mux.id))?;
        let fetches =
            matches!(mux.loader, Some(MuxKeysLoader::HTTP { .. } | MuxKeysLoader::Registry { .. }));
        for key in mux_keys.get(&mux.id).into_iter().flatten() {
            let hex = key.as_hex_string();
            if fetches && !mux.validator_pubkeys.contains(key) {
                fetched_keys.insert(hex.clone());
            }
            mux_docs.insert(hex.clone(), doc.clone());
            mux_ids.insert(hex, mux.id.clone());
        }
    }
    let relays_doc = match cfg.relays.as_slice() {
        [] => None,
        relays => {
            Some(project_relays(pbs, relays, None, None, advertised_url).wrap_err("[[relays]]")?)
        }
    };
    Ok(Projection { mux_docs, fetched_keys, relays_doc, mux_ids })
}

/// One key's builder config for `relays`, with a mux's `min_bid_wei` and
/// `builder_boost_factor` where it sets them
fn project_relays(
    pbs: &PbsConfig,
    relays: &[RelayConfig],
    min_bid_wei: Option<U256>,
    builder_boost_factor: Option<u64>,
    advertised_url: &str,
) -> Result<BuilderConfig> {
    // hostname -> (its first relay, that relay's cap)
    let mut hosts: BTreeMap<&str, (&str, u64)> = BTreeMap::new();
    for relay in relays {
        let host = relay.entry.url.host_str().unwrap_or_default();
        let cap = relay.max_execution_payment_gwei.or(pbs.max_execution_payment_gwei);
        let cap = cap.unwrap_or(ExecutionPaymentCap::Unclamped).gwei();
        let (first, first_cap) = *hosts.entry(host).or_insert((relay.id(), cap));
        ensure!(
            first_cap == cap,
            "relays {first} and {} share a hostname, so they share one entry and need the same \
             max_execution_payment_gwei",
            relay.id()
        );
    }
    ensure!(
        hosts.len() <= MAX_BUILDER_ENTRIES,
        "relays on {} hostnames, over the {MAX_BUILDER_ENTRIES} entries a builder config holds",
        hosts.len()
    );

    let min_bid = to_gwei(min_bid_wei.unwrap_or(pbs.min_bid_wei)).wrap_err("min_bid_eth")?;
    let key_min_bid = pbs.min_bid_p2p_wei.map(to_gwei).transpose().wrap_err("min_bid_p2p_eth")?;
    let boost = builder_boost_factor.unwrap_or(BUILDER_BOOST_FACTOR);
    let key_boost = pbs.builder_boost_factor_p2p.unwrap_or(boost);

    let builders = hosts
        .into_iter()
        .map(|(host, (_, cap))| BuilderEntry {
            url: advertised_url.to_string(),
            auth_data: Some(hex::encode_prefixed(host)),
            builder_pubkeys: Some(vec![]),
            max_execution_payment: Some(cap.to_string()),
            min_bid: Some(min_bid.clone()),
            builder_boost_factor: Some(boost.to_string()),
        })
        .collect();

    Ok(BuilderConfig {
        min_bid: Some(key_min_bid.unwrap_or(min_bid)),
        builder_boost_factor: Some(key_boost.to_string()),
        builders: Some(builders),
    })
}

/// Whole Gwei, rounded down
fn to_gwei(wei: U256) -> Result<String> {
    let gwei = u64::try_from(wei / Unit::GWEI.wei()).wrap_err("over the largest Uint64 in Gwei")?;
    Ok(gwei.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // relay pubkeys from config.example.toml (valid BLS points)
    const RELAY_PK_A: &str = "0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2";
    const RELAY_PK_B: &str = "0xa119589bb33ef52acbb8116832bec2b58fca590fe5c85eac5d3230b44d5bc09fe73ccd21f88eab31d6de16194d17782e";
    const ADVERTISED_URL: &str = "https://cb.example.com";
    const UNCLAMPED: &str = "18446744073709551615";

    fn random_key_hex() -> String {
        cb_common::types::BlsSecretKey::random().public_key().as_hex_string()
    }

    /// One mux holding a fresh key, with extra `[pbs]` and `[[mux]]` lines and
    /// relays given as (URL host, extra relay lines)
    fn one_mux(pbs: &str, mux: &str, relays: &[(&str, &str)]) -> Result<CommitBoostConfig> {
        let relays: String = relays
            .iter()
            .enumerate()
            .map(|(i, (host, extra))| {
                let pk = [RELAY_PK_A, RELAY_PK_B][i % 2];
                format!("[[mux.relays]]\nid = \"r{i}\"\nurl = \"https://{pk}@{host}\"\n{extra}\n")
            })
            .collect();
        parse_config(&format!(
            "chain = \"Holesky\"\n[pbs]\n{pbs}\n[[mux]]\nid = \"m\"\nvalidator_pubkeys = [\"{}\"]\n{mux}\n{relays}",
            random_key_hex()
        ))
    }

    async fn projected(cfg: &CommitBoostConfig) -> Result<Projection> {
        project(cfg, &mux_keys(cfg).await?, ADVERTISED_URL)
    }

    /// The one mux key's builder config
    fn doc(projection: &Projection) -> &BuilderConfig {
        projection.mux_docs.values().next().unwrap()
    }

    // A mux key gets its mux's relays; `[[relays]]` is the config of any other key
    #[tokio::test]
    async fn projects_literal_json_doc() {
        let key = random_key_hex();
        let cfg = parse_config(&format!(
            r#"
chain = "Holesky"

[pbs]
min_bid_eth = 0.5

[[relays]]
url = "https://{RELAY_PK_B}@default-relay.example.com"

[[mux]]
id = "mux1"
validator_pubkeys = ["{key}"]

[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"

[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
"#
        ))
        .unwrap();
        let projection = projected(&cfg).await.unwrap();

        assert_eq!(projection.mux_docs.keys().collect::<Vec<_>>(), [&key]);
        let entry = |host_hex: &str| {
            format!(
                r#"{{"url":"https://cb.example.com","auth_data":"{host_hex}","builder_pubkeys":[],"max_execution_payment":"18446744073709551615","min_bid":"500000000","builder_boost_factor":"100"}}"#
            )
        };
        let config = |entries: &[String]| {
            format!(
                r#"{{"min_bid":"500000000","builder_boost_factor":"100","builders":[{}]}}"#,
                entries.join(",")
            )
        };
        let mux_entries = [
            entry("0x72656c61792d612e6578616d706c652e636f6d"),
            entry("0x72656c61792d622e6578616d706c652e636f6d"),
        ];
        assert_eq!(serde_json::to_string(doc(&projection)).unwrap(), config(&mux_entries));
        // "default-relay.example.com"
        let relays_entries = [entry("0x64656661756c742d72656c61792e6578616d706c652e636f6d")];
        let relays_doc = projection.relays_doc.as_ref().unwrap();
        assert_eq!(serde_json::to_string(relays_doc).unwrap(), config(&relays_entries));
    }

    #[tokio::test]
    async fn entry_cap_is_the_relays_else_the_global_one_else_unclamped() {
        let cases = [
            ("", "max_execution_payment_gwei = 250000000", "", [
                Some("250000000"),
                Some(UNCLAMPED),
            ]),
            (
                "max_execution_payment_gwei = 500000000",
                "max_execution_payment_gwei = 250000000",
                "",
                [Some("250000000"), Some("500000000")],
            ),
            (
                r#"max_execution_payment_gwei = "unclamped""#,
                "",
                "max_execution_payment_gwei = 0",
                [Some(UNCLAMPED), Some("0")],
            ),
            (
                "max_execution_payment_gwei = 5",
                r#"max_execution_payment_gwei = "unclamped""#,
                "",
                [Some(UNCLAMPED), Some("5")],
            ),
        ];
        for (pbs, cap_a, cap_b, expected) in cases {
            let relays = [("relay-a.example.com", cap_a), ("relay-b.example.com", cap_b)];
            let projection = projected(&one_mux(pbs, "", &relays).unwrap()).await.unwrap();
            let caps: Vec<_> = doc(&projection)
                .builders
                .as_ref()
                .unwrap()
                .iter()
                .map(|entry| entry.max_execution_payment.as_deref())
                .collect();
            assert_eq!(caps, expected, "{pbs} / {cap_a} / {cap_b}");
        }
    }

    #[tokio::test]
    async fn one_host_is_one_entry_with_one_cap() {
        let unclamped = r#"max_execution_payment_gwei = "unclamped""#;
        let cases = [
            ("", "max_execution_payment_gwei = 100", "max_execution_payment_gwei = 200", None),
            ("", "max_execution_payment_gwei = 100", "", None),
            (
                "max_execution_payment_gwei = 500",
                "max_execution_payment_gwei = 500",
                "",
                Some("500"),
            ),
            (unclamped, "", unclamped, Some(UNCLAMPED)),
        ];
        for (pbs, cap_a, cap_b, expected) in cases {
            let relays = [("relay-a.example.com", cap_a), ("relay-a.example.com:8443/b", cap_b)];
            match (projected(&one_mux(pbs, "", &relays).unwrap()).await, expected) {
                (Ok(projection), Some(cap)) => {
                    let entries = doc(&projection).builders.clone().unwrap();
                    assert_eq!(entries.len(), 1);
                    assert_eq!(entries[0].max_execution_payment.as_deref(), Some(cap));
                }
                (Err(err), None) => {
                    assert!(format!("{err:#}").contains("share a hostname"), "{err:#}")
                }
                (result, _) => panic!("{pbs} / {cap_a} / {cap_b}: {result:?}"),
            }
        }
    }

    // builder-config stops on a key Commit-Boost would ignore, naming it and its
    // table, so a typo cannot project a default
    #[test]
    fn refuses_unknown_keys_and_bad_caps() {
        let cases: [(&str, &str, &str, &[&str]); 3] = [
            ("min_bid_p2p_eht = \"0.2\"", "bulder_boost_factor = 100", "", &[
                "`min_bid_p2p_eht` in [pbs]",
                "`bulder_boost_factor` in [[mux]] m",
            ]),
            ("", "", "max_execution_payment = 1", &[
                "could not parse [[mux]] m",
                "unknown field `max_execution_payment`",
            ]),
            (r#"max_execution_payment_gwei = "unlimited""#, "", "", &[
                r#"expected a Gwei amount or "unclamped", got "unlimited""#,
            ]),
        ];
        for (pbs, mux, relay, expected) in cases {
            let Err(err) = one_mux(pbs, mux, &[("relay-a.example.com", relay)]) else {
                panic!("accepted: {pbs} / {mux} / {relay}");
            };
            for part in expected {
                assert!(format!("{err:#}").contains(part), "{err:#}");
            }
        }
    }

    #[tokio::test]
    async fn key_level_takes_the_p2p_values() {
        // (extra [pbs], extra [[mux]], key level, entry level); an unset boost is 100
        let cases = [
            ("", "", ("0", Some("100")), ("0", Some("100"))),
            ("builder_boost_factor_p2p = 50", "", ("0", Some("50")), ("0", Some("100"))),
            (
                "min_bid_p2p_eth = \"0.2\"\nbuilder_boost_factor_p2p = 0",
                "min_bid_eth = \"0.0000010015\"\nbuilder_boost_factor = 100",
                ("200000000", Some("0")),
                ("1001", Some("100")),
            ),
            (
                "min_bid_p2p_eth = \"0.2\"",
                "builder_boost_factor = 120",
                ("200000000", Some("120")),
                ("0", Some("120")),
            ),
            (
                "builder_boost_factor_p2p = 50\nmin_bid_eth = 0.5",
                "min_bid_eth = \"0.7\"\nbuilder_boost_factor = 100",
                ("700000000", Some("50")),
                ("700000000", Some("100")),
            ),
        ];
        for (pbs, mux, key_level, entry_level) in cases {
            let cfg = one_mux(pbs, mux, &[("relay-a.example.com", "")]).unwrap();
            let projection = projected(&cfg).await.unwrap();
            let doc = doc(&projection);
            let entry = &doc.builders.as_ref().unwrap()[0];
            assert_eq!(
                (doc.min_bid.as_deref().unwrap(), doc.builder_boost_factor.as_deref()),
                key_level,
                "{pbs} / {mux}"
            );
            assert_eq!(
                (entry.min_bid.as_deref().unwrap(), entry.builder_boost_factor.as_deref()),
                entry_level,
                "{pbs} / {mux}"
            );
        }
    }

    // Commit-Boost refuses to start with either
    #[tokio::test]
    async fn duplicate_key_errors() {
        let key = random_key_hex();
        let relay =
            |pk: &str, host: &str| format!("[[mux.relays]]\nurl = \"https://{pk}@{host}\"\n");
        let (relay_a, relay_b) =
            (relay(RELAY_PK_A, "relay-a.example.com"), relay(RELAY_PK_B, "relay-b.example.com"));
        let across = format!(
            "[[mux]]\nid = \"m1\"\nvalidator_pubkeys = [\"{key}\"]\n{relay_a}\
             [[mux]]\nid = \"m2\"\nvalidator_pubkeys = [\"{key}\"]\n{relay_b}"
        );
        let within =
            format!("[[mux]]\nid = \"m1\"\nvalidator_pubkeys = [\"{key}\", \"{key}\"]\n{relay_a}");
        for muxes in [across, within] {
            let cfg = parse_config(&format!("chain = \"Holesky\"\n[pbs]\n{muxes}")).unwrap();
            let err = format!("{:#}", projected(&cfg).await.unwrap_err());
            assert!(err.contains("duplicate validator pubkey"), "{muxes}: {err}");
        }
    }

    // (extra [pbs] lines, extra [[mux]] lines, relay hostnames, the error or None)
    #[tokio::test]
    async fn projection_errors() {
        let cases = [
            ("", "relays = []", 0, Some("must have at least one relay")),
            ("", "min_bid_eth = 1e20", 1, Some("min_bid_eth: over the largest Uint64")),
            ("min_bid_p2p_eth = 1e20", "", 1, Some("min_bid_p2p_eth: over the largest Uint64")),
            ("", "", 64, None),
            ("", "", 65, Some("relays on 65 hostnames, over the 64 entries")),
        ];
        let hosts: Vec<String> = (0..65).map(|i| format!("relay-{i}.example.com")).collect();
        for (pbs, mux, n_hosts, expected) in cases {
            let relays: Vec<_> = hosts[..n_hosts].iter().map(|host| (host.as_str(), "")).collect();
            let cfg = one_mux(pbs, mux, &relays).unwrap();
            match (projected(&cfg).await, expected) {
                (Ok(projection), None) => {
                    assert_eq!(doc(&projection).builders.as_ref().map(Vec::len), Some(n_hosts))
                }
                (Err(err), Some(expected)) => {
                    assert!(format!("{err:#}").contains(expected), "{pbs} / {mux}: {err:#}")
                }
                (result, _) => panic!("{pbs} / {mux} / {n_hosts}: {result:?}"),
            }
        }
    }

    #[test]
    fn a_config_error_names_its_line() {
        let text = format!(
            "chain = \"Holesky\"\n[pbs]\n[[relays]]\nurl = \"https://{RELAY_PK_A}@relay.example.com\"\nfoo = 1\n"
        );
        let err = parse_config(&text).unwrap_err();
        assert!(format!("{err:#}").contains("line 5"), "{err:#}");
    }

    // A `[[relays]]` entry's own cap applies to the keys outside every mux, and
    // with no `[[relays]]` those keys get nothing
    #[tokio::test]
    async fn relays_config_is_for_keys_outside_muxes() {
        let relays = format!(
            "[[relays]]\nurl = \"https://{RELAY_PK_A}@relay-a.example.com\"\nmax_execution_payment_gwei = 7\n"
        );
        let cfg = parse_config(&format!("chain = \"Holesky\"\n[pbs]\n{relays}")).unwrap();
        let projection = projected(&cfg).await.unwrap();
        assert!(projection.mux_docs.is_empty());
        let key = random_key_hex();
        let entries = projection.doc_for(&key).unwrap().builders.as_ref().unwrap();
        assert_eq!(entries[0].max_execution_payment.as_deref(), Some("7"));

        let cfg = parse_config("chain = \"Holesky\"\n[pbs]\n").unwrap();
        assert!(projected(&cfg).await.unwrap().doc_for(&key).is_none());
    }

    // Lodestar refuses a cap above 0 without a flag, so builder-config warns when
    // it writes one
    #[tokio::test]
    async fn nonzero_cap_is_detected() {
        let relays = format!(
            "[[relays]]\nurl = \"https://{RELAY_PK_A}@relay-a.example.com\"\n\
             max_execution_payment_gwei = \"unclamped\"\n"
        );
        let zero_with_relays = format!("max_execution_payment_gwei = 0\n{relays}");
        for (pbs, expected) in [
            ("", true),
            ("max_execution_payment_gwei = 5", true),
            ("max_execution_payment_gwei = 0", false),
            (zero_with_relays.as_str(), true),
        ] {
            let cfg = one_mux(pbs, "", &[("relay-a.example.com", "")]).unwrap();
            assert_eq!(projected(&cfg).await.unwrap().has_nonzero_cap(), expected, "{pbs}");
        }
    }

    // A URL loader's keys are fetched, as Commit-Boost fetches them at startup
    #[tokio::test]
    async fn url_loader_resolves_keys() {
        let key = random_key_hex();
        let body = format!(r#"["{key}"]"#);
        let app =
            axum::Router::new().route("/keys", axum::routing::get(move || async move { body }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let mux = format!(r#"loader = {{ url = "http://{addr}/keys" }}"#);
        let cfg = one_mux("", &mux, &[("relay-a.example.com", "")]).unwrap();
        let projection = projected(&cfg).await.unwrap();
        assert!(projection.mux_docs.contains_key(&key), "{:?}", projection.mux_docs.keys());
        // The mux's own validator_pubkeys key is named, the fetched one is not
        assert_eq!(projection.fetched_keys.into_iter().collect::<Vec<_>>(), [key]);
    }

    // Commit-Boost routes each of two muxes with one id to its own relays, which
    // builder-config cannot tell apart by id
    #[tokio::test]
    async fn two_muxes_with_one_id_are_refused() {
        let mux = |host: &str| {
            format!(
                "[[mux]]\nid = \"m\"\nvalidator_pubkeys = [\"{}\"]\n\
                 [[mux.relays]]\nurl = \"https://{RELAY_PK_A}@{host}\"\n",
                random_key_hex()
            )
        };
        let cfg = parse_config(&format!(
            "chain = \"Holesky\"\n[pbs]\n{}{}",
            mux("relay-a.example.com"),
            mux("relay-b.example.com")
        ))
        .unwrap();
        let err = projected(&cfg).await.unwrap_err();
        assert!(format!("{err:#}").contains("mux id m names more than one [[mux]]"), "{err:#}");
    }

    // builder-config reads no relay header secrets, and checks rpc_url only for a
    // registry loader, which reads its keys through it
    #[tokio::test]
    async fn resolves_keys_without_commit_boosts_runtime_secrets() {
        let pbs = r#"rpc_url = "http://127.0.0.1:1""#;
        let header = r#"headers = { X-Api-Key = { env = "CB_KM_TEST_UNSET_HEADER" } }"#;
        let cfg = one_mux(pbs, "", &[("relay-a.example.com", header)]).unwrap();
        assert_eq!(projected(&cfg).await.unwrap().mux_docs.len(), 1);

        let lido = r#"loader = { registry = "lido", node_operator_id = 1 }"#;
        let cfg = one_mux(pbs, lido, &[("relay-a.example.com", "")]).unwrap();
        let err = projected(&cfg).await.unwrap_err();
        assert!(!format!("{err:#}").contains("requires RPC URL"), "{err:#}");
    }

    #[tokio::test]
    async fn file_loader_resolves_keys() {
        let key_a = random_key_hex();
        let key_b = random_key_hex();
        let dir = tempfile::tempdir().unwrap();
        let keys_path = dir.path().join("keys.json");
        // A file listing a key twice is deduped, as Commit-Boost does
        std::fs::write(&keys_path, format!(r#"["{key_b}", "{key_b}"]"#)).unwrap();
        let cfg = parse_config(&format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "filemux"
validator_pubkeys = ["{key_a}"]
loader = "{}"
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#,
            keys_path.display()
        ))
        .unwrap();
        let projection = projected(&cfg).await.unwrap();
        let mut expected = vec![key_a, key_b];
        expected.sort();
        assert_eq!(projection.mux_docs.into_keys().collect::<Vec<_>>(), expected);
    }
}
