//! Pure projection: CB mux config + overlay -> per-key KM builder_config docs.
//!
//! One KM entry per auth_data EQUIVALENCE CLASS: relays whose candidate
//! auth_data byte-strings are identical share one entry. Its `builder_pubkeys`
//! is emitted EMPTY (accept any builder for the key): the only pubkey cb-km can
//! see is the relay URL's userinfo pubkey, which is the relay's identity, not
//! the builder's bid-signing key, and binding the wrong key rejects every bid
//! (see `project_mux`). The candidate is `expected_auth_data` when set, else
//! the UTF-8 bytes of the relay URL as configured with the userinfo stripped
//! (userinfo, and thus any pubkey credential, is intentionally NOT part of the
//! emitted url or auth_data). Grouping-by-identical-bytes is a
//! reimplementation of the demux contract of cb-pbs's
//! `match_relays_by_auth_data` (pub(crate) there); the CB-side contract tests
//! pin those semantics. CAVEAT (also in the plan): CB's own matching is LAXER
//! (`url_matches` ignores userinfo/path/case), so a projected auth_data can
//! round-trip against CB and still mismatch a builder's exact-byte check;
//! prefer `expected_auth_data` when the relay URL is not byte-identical to
//! the builder's advertised URL.

use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
};

use alloy_primitives::U256;
use cb_common::{
    config::{CommitBoostConfig, MUX_PATH_ENV, MuxConfig, RelayConfig, load_optional_env_var},
    types::BlsPublicKey,
};
use eyre::{Context, Result, bail, ensure};
use tracing::warn;

use crate::{
    doc::{BuilderConfigDoc, BuilderEntryDoc, encode_auth_data},
    overlay::Overlay,
};

/// KM spec limits (builder_entry.yaml)
pub const MAX_BUILDER_ENTRIES: usize = 64;
pub const MAX_BUILDER_PUBKEYS: usize = 64;
pub const MAX_BUILDER_AUTH_DATA_SIZE: usize = 4096;

const WEI_PER_GWEI: u64 = 1_000_000_000;

/// A BLS pubkey ordered by its compressed bytes, so projections are
/// deterministic maps (lighthouse's `PublicKey` has no `Ord`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedPubkey(pub BlsPublicKey);

impl Ord for OrderedPubkey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.serialize().cmp(&other.0.serialize())
    }
}

impl PartialOrd for OrderedPubkey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for OrderedPubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_hex_string())
    }
}

/// The parsed CB config plus the RAW relay URL strings from the same TOML
/// text. The auth_data convention wants the URL bytes exactly as configured,
/// but `RelayEntry` holds a parsed `Url` whose serialization normalizes them
/// (see `Overlay::advertised_url`), so the raw strings are kept alongside.
pub struct ProjectionInput {
    pub cfg: CommitBoostConfig,
    mux_relay_urls: Vec<Vec<String>>,
    default_relay_urls: Vec<String>,
}

impl ProjectionInput {
    pub fn parse_str(text: &str) -> Result<Self> {
        let cfg: CommitBoostConfig =
            toml::from_str(text).wrap_err("could not parse Commit-Boost config")?;
        let raw: toml::Value = toml::from_str(text)?;

        let mux_relay_urls = raw_urls_per_mux(&raw)?;
        let mux_count = cfg.muxes.as_ref().map(|m| m.muxes.len()).unwrap_or(0);
        ensure!(
            mux_relay_urls.len() == mux_count,
            "raw TOML mux count {} does not match parsed config {}",
            mux_relay_urls.len(),
            mux_count
        );
        if let Some(muxes) = &cfg.muxes {
            for (mux, urls) in muxes.muxes.iter().zip(&mux_relay_urls) {
                ensure!(
                    mux.relays.len() == urls.len(),
                    "raw TOML relay count does not match parsed config in mux {}",
                    mux.id
                );
            }
        }

        let default_relay_urls = raw_url_array(raw.get("relays"))?;
        ensure!(
            default_relay_urls.len() == cfg.relays.len(),
            "raw TOML default-relay count does not match parsed config"
        );

        Ok(Self { cfg, mux_relay_urls, default_relay_urls })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("unable to read config file: {path:?}"))?;
        Self::parse_str(&text)
    }
}

fn raw_urls_per_mux(raw: &toml::Value) -> Result<Vec<Vec<String>>> {
    let Some(muxes) = raw.get("mux") else {
        return Ok(vec![]);
    };
    let muxes = muxes.as_array().ok_or_else(|| eyre::eyre!("mux is not an array"))?;
    muxes.iter().map(|mux| raw_url_array(mux.get("relays"))).collect()
}

fn raw_url_array(relays: Option<&toml::Value>) -> Result<Vec<String>> {
    let Some(relays) = relays else {
        return Ok(vec![]);
    };
    let relays = relays.as_array().ok_or_else(|| eyre::eyre!("relays is not an array"))?;
    relays
        .iter()
        .map(|relay| {
            relay
                .get("url")
                .and_then(|u| u.as_str())
                .map(String::from)
                .ok_or_else(|| eyre::eyre!("relay entry has no url string"))
        })
        .collect()
}

/// Strips the userinfo from a URL by string surgery, leaving everything else
/// exactly as written (no trailing-slash or port normalization).
pub fn strip_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let after = &url[scheme_end + 3..];
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    match after[..authority_end].rfind('@') {
        Some(at) => format!("{}{}", &url[..scheme_end + 3], &after[at + 1..]),
        None => url.to_string(),
    }
}

/// One relay's candidate auth_data bytes: `expected_auth_data` when set, else
/// the UTF-8 bytes of the configured URL with userinfo stripped.
fn candidate_auth_data(relay: &RelayConfig, raw_url: &str) -> Vec<u8> {
    match &relay.expected_auth_data {
        Some(expected) => expected.to_vec(),
        None => strip_userinfo(raw_url).into_bytes(),
    }
}

/// Where a relay's candidate auth_data came from, for check-side routing and
/// reference findings.
#[derive(Debug, Clone)]
pub struct RelayAuthCandidate {
    /// Mux id, or "[[relays]]" for the default relay list
    pub source: String,
    pub relay_id: String,
    pub bytes: Vec<u8>,
    /// Whether this relay is part of a projected mux (default relays are not)
    pub projected: bool,
}

#[derive(Debug)]
pub struct Projection {
    pub docs: BTreeMap<OrderedPubkey, BuilderConfigDoc>,
    pub warnings: Vec<String>,
    /// Candidate auth_data of every configured relay (muxes and defaults)
    pub relay_candidates: Vec<RelayAuthCandidate>,
}

/// Projects per-key KM docs with the overlay's global advertised URL.
pub fn project(input: &ProjectionInput, overlay: &Overlay) -> Result<Projection> {
    project_with_url(input, &overlay.advertised_url)
}

/// Projects with an explicit advertised URL (per-VC overrides).
pub fn project_with_url(input: &ProjectionInput, advertised_url: &str) -> Result<Projection> {
    let mut warnings = Vec::new();
    let mut docs = BTreeMap::new();
    let mut relay_candidates = Vec::new();
    let mut seen_keys: HashSet<Vec<u8>> = HashSet::new();

    if let Some(muxes) = &input.cfg.muxes {
        for (mux, raw_urls) in muxes.muxes.iter().zip(&input.mux_relay_urls) {
            let keys = resolve_mux_keys(mux, &mut warnings)?;
            let doc = project_mux(input, mux, raw_urls, advertised_url, &mut warnings)?;

            for (relay, raw_url) in mux.relays.iter().zip(raw_urls) {
                relay_candidates.push(RelayAuthCandidate {
                    source: mux.id.clone(),
                    relay_id: relay.id().to_string(),
                    bytes: candidate_auth_data(relay, raw_url),
                    projected: !keys.is_empty(),
                });
            }

            for key in keys {
                let bytes = key.serialize().to_vec();
                if !seen_keys.insert(bytes) {
                    bail!("duplicate validator pubkey in muxes: {}", key.as_hex_string());
                }
                docs.insert(OrderedPubkey(key), doc.clone());
            }
        }
    }

    for (relay, raw_url) in input.cfg.relays.iter().zip(&input.default_relay_urls) {
        relay_candidates.push(RelayAuthCandidate {
            source: "[[relays]]".to_string(),
            relay_id: relay.id().to_string(),
            bytes: candidate_auth_data(relay, raw_url),
            projected: false,
        });
    }

    Ok(Projection { docs, warnings, relay_candidates })
}

fn push_warn(warnings: &mut Vec<String>, msg: String) {
    warn!("{msg}");
    warnings.push(msg);
}

/// Resolves a mux's key set. Explicit `validator_pubkeys` always project. Of
/// the loaders only the File variant resolves offline; HTTP and Registry
/// loaders need the network and are skipped with a warning in v1 (schedule
/// km-apply/km-check when using them, per the plan's drift bounds).
fn resolve_mux_keys(mux: &MuxConfig, warnings: &mut Vec<String>) -> Result<Vec<BlsPublicKey>> {
    let mut keys = mux.validator_pubkeys.clone();

    if let Some(loader) = &mux.loader {
        match loader {
            cb_common::config::MuxKeysLoader::File(path) => {
                // same semantics as MuxKeysLoader::load: env var overrides path
                let path = load_optional_env_var(&format!("{MUX_PATH_ENV}_{}", mux.id))
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| path.clone());
                let file = std::fs::read_to_string(&path)
                    .wrap_err_with(|| format!("unable to read mux keys file: {path:?}"))?;
                let extra: Vec<BlsPublicKey> =
                    serde_json::from_str(&file).wrap_err("failed to parse mux keys file")?;
                keys.extend(extra);
            }
            other => {
                push_warn(
                    warnings,
                    format!(
                        "mux {}: loader {:?} needs the network and is not resolved by this tool; \
                         its keys are NOT projected (best-effort only)",
                        mux.id, other
                    ),
                );
            }
        }
    }

    let keys = cb_common::config::remove_duplicate_keys(keys);
    if keys.is_empty() {
        push_warn(warnings, format!("mux {}: no projectable keys, skipping", mux.id));
    }
    Ok(keys)
}

struct AuthClass {
    relay_ids: Vec<String>,
    max_execution_payment_gwei: Option<u64>,
}

/// Groups a mux's relays into auth_data equivalence classes keyed by identical
/// candidate bytes, unioning each class's builder pubkeys, requiring one shared
/// execution-payment cap per class, and enforcing the KM entry-count limit.
fn build_auth_classes(
    mux: &MuxConfig,
    raw_urls: &[String],
) -> Result<BTreeMap<Vec<u8>, AuthClass>> {
    let mut classes: BTreeMap<Vec<u8>, AuthClass> = BTreeMap::new();
    for (relay, raw_url) in mux.relays.iter().zip(raw_urls) {
        let bytes = candidate_auth_data(relay, raw_url);
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_BUILDER_AUTH_DATA_SIZE,
            "mux {} relay {}: auth_data must be 1..={MAX_BUILDER_AUTH_DATA_SIZE} bytes, got {}",
            mux.id,
            relay.id(),
            bytes.len()
        );
        let class = classes.entry(bytes).or_insert_with(|| AuthClass {
            relay_ids: vec![],
            max_execution_payment_gwei: relay.max_execution_payment_gwei,
        });
        ensure!(
            class.max_execution_payment_gwei == relay.max_execution_payment_gwei,
            "mux {}: relays {} and {} share an auth_data class but disagree on \
             max_execution_payment_gwei ({:?} vs {:?}); a KM entry carries one cap",
            mux.id,
            class.relay_ids.first().cloned().unwrap_or_default(),
            relay.id(),
            class.max_execution_payment_gwei,
            relay.max_execution_payment_gwei
        );
        class.relay_ids.push(relay.id().to_string());
    }

    ensure!(
        classes.len() <= MAX_BUILDER_ENTRIES,
        "mux {}: {} builder entries exceed the KM maximum of {MAX_BUILDER_ENTRIES}",
        mux.id,
        classes.len()
    );

    Ok(classes)
}

fn project_mux(
    input: &ProjectionInput,
    mux: &MuxConfig,
    raw_urls: &[String],
    advertised_url: &str,
    warnings: &mut Vec<String>,
) -> Result<BuilderConfigDoc> {
    ensure!(!mux.relays.is_empty(), "mux {} has no relays", mux.id);

    let classes = build_auth_classes(mux, raw_urls)?;

    // Entry values are mux/global-sourced; the KEY-LEVEL values come from the
    // projection-only p2p fields when set, resolving MUX p2p > global [pbs]
    // p2p. Rationale: projected entries always carry explicit per-entry
    // values, so the key level only governs p2p bids and entries that omit
    // their own. Unset p2p fields fall back to the entry values (uniform doc,
    // today's behavior).
    let min_bid_wei = mux.min_bid_wei.unwrap_or(input.cfg.pbs.pbs_config.min_bid_wei);
    let min_bid = wei_to_gwei_floor(&mux.id, min_bid_wei, warnings)?.to_string();
    let key_min_bid = match mux.min_bid_p2p_wei.or(input.cfg.pbs.pbs_config.min_bid_p2p_wei) {
        Some(wei) => wei_to_gwei_floor(&mux.id, wei, warnings)?.to_string(),
        None => min_bid.clone(),
    };
    let boost = mux.builder_boost_factor.map(|b| b.to_string());
    let key_boost = mux
        .builder_boost_factor_p2p
        .or(input.cfg.pbs.pbs_config.builder_boost_factor_p2p)
        .map(|b| b.to_string())
        .or_else(|| boost.clone());

    // `(url, auth_data-bytes)` uniqueness: classes are keyed by bytes and all
    // entries share the advertised URL, so uniqueness holds by construction;
    // asserted anyway to keep the invariant loud.
    let mut seen: HashSet<(&str, &[u8])> = HashSet::new();
    let mut entries = Vec::with_capacity(classes.len());
    // BTreeMap iterates classes in byte order = the KM (url, bytes) sort
    for (bytes, class) in &classes {
        ensure!(
            seen.insert((advertised_url, bytes)),
            "mux {}: duplicate (url, auth_data) pair",
            mux.id
        );
        // Emit an EMPTY builder_pubkeys. The only builder pubkey cb-km can see
        // is the relay URL's userinfo pubkey, which is the relay's IDENTITY, not
        // the builder's bid-SIGNING key. Lodestar rejects any builder-API bid
        // whose signing pubkey is not in builder_pubkeys (the check is skipped
        // when the array is empty), so populating it with the relay identity
        // would silently bind the VC to the wrong key and reject every bid. An
        // empty array = accept any builder for this key. Populate this in future
        // once cb-km can supply the builder's actual bid-signing pubkey.
        entries.push(BuilderEntryDoc {
            url: advertised_url.to_string(),
            auth_data: Some(encode_auth_data(bytes)),
            builder_pubkeys: Some(Vec::new()),
            max_execution_payment: class.max_execution_payment_gwei.map(|g| g.to_string()),
            min_bid: Some(min_bid.clone()),
            builder_boost_factor: boost.clone(),
        });
    }

    Ok(BuilderConfigDoc {
        min_bid: Some(key_min_bid),
        builder_boost_factor: key_boost,
        builders: Some(entries),
    })
}

fn wei_to_gwei_floor(mux_id: &str, wei: U256, warnings: &mut Vec<String>) -> Result<u64> {
    let divisor = U256::from(WEI_PER_GWEI);
    let gwei = wei / divisor;
    if wei % divisor != U256::ZERO {
        push_warn(
            warnings,
            format!(
                "mux {mux_id}: min_bid {wei} wei has a sub-Gwei remainder, flooring to {gwei} Gwei"
            ),
        );
    }
    gwei.try_into().map_err(|_| eyre::eyre!("mux {mux_id}: min_bid {wei} wei exceeds u64 Gwei"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // relay pubkeys from config.example.toml (valid BLS points)
    const RELAY_PK_A: &str = "0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2";
    const RELAY_PK_B: &str = "0xa119589bb33ef52acbb8116832bec2b58fca590fe5c85eac5d3230b44d5bc09fe73ccd21f88eab31d6de16194d17782e";

    fn random_key_hex() -> String {
        cb_common::types::BlsSecretKey::random().public_key().as_hex_string()
    }

    fn overlay() -> Overlay {
        Overlay::parse_str(r#"advertised_url = "https://cb.example.com""#).unwrap()
    }

    #[test]
    fn strip_userinfo_surgery() {
        assert_eq!(strip_userinfo("https://0xabc@relay.example.com"), "https://relay.example.com");
        assert_eq!(
            strip_userinfo("https://0xabc@relay.example.com:8443/path"),
            "https://relay.example.com:8443/path"
        );
        // no trailing slash is ADDED (Url::as_str would add one)
        assert_eq!(strip_userinfo("http://pk@host"), "http://host");
        // no userinfo: unchanged
        assert_eq!(strip_userinfo("https://host/x?q=1"), "https://host/x?q=1");
        // '@' after the authority is not userinfo
        assert_eq!(strip_userinfo("https://host/a@b"), "https://host/a@b");
    }

    fn config_toml(keys: &[String]) -> String {
        let keys = keys.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ");
        format!(
            r#"
chain = "Holesky"

[pbs]
port = 18550
min_bid_eth = 0.5

[[mux]]
id = "mux1"
validator_pubkeys = [{keys}]

[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"

[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
expected_auth_data = "0x736563726574"
"#
        )
    }

    #[test]
    fn projects_literal_json_doc() {
        let key = random_key_hex();
        let input = ProjectionInput::parse_str(&config_toml(std::slice::from_ref(&key))).unwrap();
        let projection = project(&input, &overlay()).unwrap();

        assert_eq!(projection.docs.len(), 1);
        let (pk, doc) = projection.docs.iter().next().unwrap();
        assert_eq!(pk.to_string(), key);

        // entries sorted by auth_data bytes: 0x736563726574 ("secret") sorts
        // after the https URL bytes (0x68...). builder_pubkeys is emitted EMPTY
        // for every entry (relay identity is not the builder's bid-signing key).
        let json = serde_json::to_string(doc).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"{"min_bid":"500000000","builders":["#,
                r#"{"url":"https://cb.example.com","#,
                r#""auth_data":"0x68747470733a2f2f72656c61792d612e6578616d706c652e636f6d","#,
                r#""builder_pubkeys":[],"min_bid":"500000000"},"#,
                r#"{"url":"https://cb.example.com","#,
                r#""auth_data":"0x736563726574","#,
                r#""builder_pubkeys":[],"min_bid":"500000000"}]}"#
            )
        );
    }

    #[test]
    fn stripped_userinfo_no_trailing_slash_in_auth_data() {
        let key = random_key_hex();
        let input = ProjectionInput::parse_str(&config_toml(&[key])).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        let auth = doc.builders.as_ref().unwrap()[0].auth_data.clone().unwrap();
        // "https://relay-a.example.com" exactly: no pubkey, no trailing slash
        assert_eq!(
            crate::doc::decode_auth_data(&auth).unwrap(),
            b"https://relay-a.example.com".to_vec()
        );
    }

    // Two relays sharing an auth_data class collapse to ONE entry. The entry's
    // builder_pubkeys is emitted empty (no relay-identity pubkeys unioned in).
    #[test]
    fn equivalence_class_groups_into_one_entry_with_empty_pubkeys() {
        let key = random_key_hex();
        // both relays carry the same expected_auth_data -> one entry
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
expected_auth_data = "0xaabb"
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
expected_auth_data = "0xaabb"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        let entries = doc.builders.as_ref().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].builder_pubkeys.as_ref().unwrap(), &Vec::<String>::new());
    }

    #[test]
    fn class_cap_disagreement_errors() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
expected_auth_data = "0xaabb"
max_execution_payment_gwei = 100
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
expected_auth_data = "0xaabb"
max_execution_payment_gwei = 200
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let err = project(&input, &overlay()).unwrap_err();
        assert!(err.to_string().contains("max_execution_payment_gwei"), "{err}");
    }

    #[test]
    fn relay_cap_projects_or_omits() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
max_execution_payment_gwei = 250000000
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        let entries = doc.builders.as_ref().unwrap();
        assert_eq!(entries.len(), 2);
        let by_cap: Vec<_> = entries.iter().map(|e| e.max_execution_payment.clone()).collect();
        assert!(by_cap.contains(&Some("250000000".to_string())));
        // the un-capped relay's entry OMITS the field (resolves to VC config)
        assert!(by_cap.contains(&None));
    }

    #[test]
    fn min_bid_falls_back_global_with_floor_warning() {
        let key = random_key_hex();
        // 1.5 gwei in eth: 0.0000000015 eth = 1500000000 wei... use
        // min_bid_eth for a sub-gwei remainder: 0.0000000000015 ETH = 1500 wei
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
min_bid_eth = 0.0000000000015
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        assert_eq!(doc.min_bid, Some("0".to_string()));
        assert!(
            projection.warnings.iter().any(|w| w.contains("sub-Gwei")),
            "{:?}",
            projection.warnings
        );
    }

    // The p2p fields split the doc: KEY-LEVEL min_bid/boost come from the
    // global projection-only p2p fields (they govern p2p bids and entries
    // omitting their own), while ENTRIES keep the mux/global-sourced values.
    #[test]
    fn p2p_fields_differentiate_key_level_from_entries() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
min_bid_p2p_eth = "0.2"
builder_boost_factor_p2p = 0
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
min_bid_eth = "0.000001"
builder_boost_factor = 100
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();

        // key level: 0.2 ETH = 200000000 Gwei floor, boost 0
        assert_eq!(doc.min_bid, Some("200000000".to_string()));
        assert_eq!(doc.builder_boost_factor, Some("0".to_string()));

        // entry level: mux min_bid 0.000001 ETH = 1000 Gwei, mux boost 100
        let entry = &doc.builders.as_ref().unwrap()[0];
        assert_eq!(entry.min_bid, Some("1000".to_string()));
        assert_eq!(entry.builder_boost_factor, Some("100".to_string()));
    }

    // A mux p2p field wins over a different global p2p field at the key level.
    #[test]
    fn mux_p2p_override_wins_over_global() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
min_bid_p2p_eth = "0.2"
builder_boost_factor_p2p = 50
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
min_bid_p2p_eth = "0.7"
builder_boost_factor_p2p = 130
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        // key level uses the MUX p2p values, not the global ones
        assert_eq!(doc.min_bid, Some("700000000".to_string()));
        assert_eq!(doc.builder_boost_factor, Some("130".to_string()));
    }

    // Only the global p2p fields are set: every mux uses them at the key level.
    #[test]
    fn global_p2p_applies_to_all_muxes() {
        let key_a = random_key_hex();
        let key_b = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
min_bid_p2p_eth = "0.2"
builder_boost_factor_p2p = 50
[[mux]]
id = "ma"
validator_pubkeys = ["{key_a}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
[[mux]]
id = "mb"
validator_pubkeys = ["{key_b}"]
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        assert_eq!(projection.docs.len(), 2);
        for doc in projection.docs.values() {
            assert_eq!(doc.min_bid, Some("200000000".to_string()));
            assert_eq!(doc.builder_boost_factor, Some("50".to_string()));
        }
    }

    // Mix: mux A overrides the global p2p, mux B inherits it.
    #[test]
    fn mux_p2p_override_and_inherit_mix() {
        let key_a = random_key_hex();
        let key_b = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
min_bid_p2p_eth = "0.2"
builder_boost_factor_p2p = 50
[[mux]]
id = "ma"
validator_pubkeys = ["{key_a}"]
min_bid_p2p_eth = "0.7"
builder_boost_factor_p2p = 130
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
[[mux]]
id = "mb"
validator_pubkeys = ["{key_b}"]
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let by_key = |k: &str| {
            projection.docs.iter().find(|(pk, _)| pk.to_string() == k).map(|(_, doc)| doc).unwrap()
        };
        // mux A: its own p2p values
        let doc_a = by_key(&key_a);
        assert_eq!(doc_a.min_bid, Some("700000000".to_string()));
        assert_eq!(doc_a.builder_boost_factor, Some("130".to_string()));
        // mux B: the global p2p values
        let doc_b = by_key(&key_b);
        assert_eq!(doc_b.min_bid, Some("200000000".to_string()));
        assert_eq!(doc_b.builder_boost_factor, Some("50".to_string()));
    }

    // Asymmetric: a mux sets ONLY min_bid_p2p (not builder_boost_factor_p2p).
    // The key-level min_bid must take the mux p2p value, while the key-level
    // boost must NOT be dragged along with it: boost independently follows the
    // global/uniform p2p fallback, never the mux. Guards the two p2p fields
    // against a coupling regression.
    #[test]
    fn mux_min_bid_p2p_does_not_drag_boost_p2p() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
builder_boost_factor_p2p = 50
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
min_bid_p2p_eth = "0.7"
builder_boost_factor = 100
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();

        // key-level min_bid: the MUX p2p value (0.7 ETH = 700000000 Gwei floor)
        assert_eq!(doc.min_bid, Some("700000000".to_string()));
        // key-level boost: the GLOBAL p2p value, NOT the mux's own boost (100)
        assert_eq!(doc.builder_boost_factor, Some("50".to_string()));

        // entry-level boost is still the mux's own value, confirming the split
        let entry = &doc.builders.as_ref().unwrap()[0];
        assert_eq!(entry.builder_boost_factor, Some("100".to_string()));
    }

    // Unset p2p fields keep today's uniform projection (key = entry values).
    #[test]
    fn p2p_fields_unset_keep_uniform_projection() {
        let key = random_key_hex();
        let input = ProjectionInput::parse_str(&config_toml(&[key])).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        let entry = &doc.builders.as_ref().unwrap()[0];
        assert_eq!(doc.min_bid, entry.min_bid);
        assert_eq!(doc.builder_boost_factor, None);
        assert_eq!(entry.builder_boost_factor, None);
    }

    #[test]
    fn boost_omitted_without_source() {
        let key = random_key_hex();
        let input = ProjectionInput::parse_str(&config_toml(&[key])).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        assert_eq!(doc.builder_boost_factor, None);
        assert_eq!(doc.builders.as_ref().unwrap()[0].builder_boost_factor, None);
    }

    #[test]
    fn determinism_under_toml_permutation() {
        let key_a = random_key_hex();
        let key_b = random_key_hex();
        let base = config_toml(&[key_a.clone(), key_b.clone()]);
        // permute validator key order AND relay order
        let permuted = format!(
            r#"
chain = "Holesky"

[pbs]
port = 18550
min_bid_eth = 0.5

[[mux]]
id = "mux1"
validator_pubkeys = ["{key_b}", "{key_a}"]

[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
expected_auth_data = "0x736563726574"

[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#
        );
        let overlay = overlay();
        let a = project(&ProjectionInput::parse_str(&base).unwrap(), &overlay).unwrap();
        let b = project(&ProjectionInput::parse_str(&permuted).unwrap(), &overlay).unwrap();
        let ser = |p: &Projection| {
            p.docs
                .iter()
                .map(|(k, d)| (k.to_string(), serde_json::to_string(d).unwrap()))
                .collect::<Vec<_>>()
        };
        assert_eq!(ser(&a), ser(&b));
    }

    #[test]
    fn duplicate_key_across_muxes_errors() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m1"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
[[mux]]
id = "m2"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        assert!(project(&input, &overlay()).unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn network_loader_mux_warns_and_projects_explicit_keys() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
loader = {{ url = "http://localhost:8000/keys" }}
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        assert_eq!(projection.docs.len(), 1);
        assert!(projection.warnings.iter().any(|w| w.contains("NOT projected")));
    }

    #[test]
    fn file_loader_resolves_keys() {
        let key_a = random_key_hex();
        let key_b = random_key_hex();
        let dir = tempfile::tempdir().unwrap();
        let keys_path = dir.path().join("keys.json");
        std::fs::write(&keys_path, format!(r#"["{key_b}"]"#)).unwrap();
        let toml_text = format!(
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
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let keys: Vec<String> = projection.docs.keys().map(|k| k.to_string()).collect();
        assert_eq!(projection.docs.len(), 2);
        assert!(keys.contains(&key_a) && keys.contains(&key_b));
    }

    #[test]
    fn default_relays_are_candidates_but_not_projected() {
        let key = random_key_hex();
        let toml_text = format!(
            r#"
chain = "Holesky"
[[relays]]
url = "https://{RELAY_PK_B}@default-relay.example.com"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let default_candidate =
            projection.relay_candidates.iter().find(|c| c.source == "[[relays]]").unwrap();
        assert!(!default_candidate.projected);
        assert_eq!(default_candidate.bytes, b"https://default-relay.example.com".to_vec());
        // the projected doc references only the mux relay
        let doc = projection.docs.values().next().unwrap();
        assert_eq!(doc.builders.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn lax_equivalent_urls_project_as_separate_entries() {
        let key = random_key_hex();
        // byte-distinct candidates that CB's url_matches would see as one relay
        // (https://h vs https://h:443) project as two byte-distinct entries.
        // builder_pubkeys is empty, so both accept any builder and there is
        // nothing to split.
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay.example.com"
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay.example.com:443"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        assert_eq!(doc.builders.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn lax_collision_via_expected_auth_data_url_projects_two_entries() {
        let key = random_key_hex();
        // expected_auth_data holds URL bytes lax-equivalent to the other
        // relay's URL-derived candidate: hex of "HTTPS://RELAY.EXAMPLE.COM"
        // is byte-distinct but host-case-insensitively the same relay. Both
        // project as separate entries with empty builder_pubkeys.
        let upper_hex = crate::doc::encode_auth_data(b"https://RELAY.EXAMPLE.COM");
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay.example.com"
[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
expected_auth_data = "{upper_hex}"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        assert_eq!(doc.builders.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn distinct_hosts_do_not_lax_collide() {
        let key = random_key_hex();
        let input = ProjectionInput::parse_str(&config_toml(&[key])).unwrap();
        // relay-a and relay-b: different hosts, projection succeeds
        assert_eq!(project(&input, &overlay()).unwrap().docs.len(), 1);
    }

    #[test]
    fn same_byte_urls_still_group_into_one_class() {
        let key = random_key_hex();
        // identical URL bytes after userinfo strip: one class, no ambiguity
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
id = "r1"
url = "https://{RELAY_PK_A}@relay.example.com"
[[mux.relays]]
id = "r2"
url = "https://{RELAY_PK_B}@relay.example.com"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        let projection = project(&input, &overlay()).unwrap();
        let doc = projection.docs.values().next().unwrap();
        let entries = doc.builders.as_ref().unwrap();
        assert_eq!(entries.len(), 1);
        // grouped into one class; builder_pubkeys is emitted empty
        assert_eq!(entries[0].builder_pubkeys.as_ref().unwrap().len(), 0);
    }

    #[test]
    fn auth_data_size_limit_enforced() {
        let key = random_key_hex();
        let big = "ab".repeat(4097);
        let toml_text = format!(
            r#"
chain = "Holesky"
[pbs]
[[mux]]
id = "m"
validator_pubkeys = ["{key}"]
[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"
expected_auth_data = "0x{big}"
"#
        );
        let input = ProjectionInput::parse_str(&toml_text).unwrap();
        assert!(project(&input, &overlay()).unwrap_err().to_string().contains("4096"));
    }
}
