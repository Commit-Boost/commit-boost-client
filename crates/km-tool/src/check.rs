//! `cb-km check`: read-only comparison of stored VC docs against the
//! projection. Comparison is canonical (see `doc::CanonicalDoc`), never a
//! byte-diff: a GET returns the doc fully RESOLVED, so fields the projection
//! intentionally omits (they resolve to the VC's own config) are skipped
//! rather than reported as drift.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use eyre::Result;
use url::Url;

use crate::{
    client::{GetConfigOutcome, KmClient, read_token},
    doc::{CanonicalDoc, CanonicalEntry},
    overlay::Overlay,
    project::{ProjectionInput, project, project_with_url},
};

/// Mirror of cb-pbs `url_matches`: scheme + canonical host (a trailing dot is
/// stripped) + effective port. Kept local to avoid a cb-pbs dependency from the
/// projection tool; the unit test pins the same cases so the two cannot drift.
fn advertised_url_matches(a: &Url, b: &Url) -> bool {
    fn host_canonical(url: &Url) -> Option<&str> {
        url.host_str().map(|host| host.strip_suffix('.').unwrap_or(host))
    }
    a.scheme() == b.scheme() &&
        host_canonical(a) == host_canonical(b) &&
        a.port_or_known_default() == b.port_or_known_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Info => write!(f, "INFO"),
            Tier::Warn => write!(f, "WARN"),
            Tier::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug)]
pub struct Finding {
    pub tier: Tier,
    pub code: &'static str,
    pub msg: String,
}

#[derive(Debug, Default)]
pub struct CheckReport {
    pub findings: Vec<Finding>,
}

impl CheckReport {
    fn push(&mut self, tier: Tier, code: &'static str, msg: String) {
        self.findings.push(Finding { tier, code, msg });
    }

    /// Whether any finding is at or above the given tier.
    pub fn fails(&self, fail_on: Tier) -> bool {
        self.findings.iter().any(|f| f.tier >= fail_on)
    }
}

pub async fn run_check(input: &ProjectionInput, overlay: &Overlay) -> Result<CheckReport> {
    let mut report = CheckReport::default();
    let global = project(input, overlay)?;
    let projected_keys: BTreeSet<String> = global.docs.keys().map(|k| k.to_string()).collect();

    // every auth_data byte-string a projected entry carries
    let projected_auth: BTreeSet<Vec<u8>> = global
        .docs
        .values()
        .flat_map(|doc| doc.builders.iter().flatten())
        .filter_map(|entry| entry.auth_data.as_ref())
        .filter_map(|hex| crate::doc::decode_auth_data(hex).ok())
        .collect();

    for candidate in &global.relay_candidates {
        if !projected_auth.contains(&candidate.bytes) {
            report.push(
                Tier::Info,
                "relay-unreferenced",
                format!(
                    "relay {} ({}) is referenced by no projected key",
                    candidate.relay_id, candidate.source
                ),
            );
        }
    }

    // Self-dial consistency (the transient pipe): every advertised_url km-tool
    // projects is echoed by a VC in its auth data, decoded by CB, and must be
    // recognized as CB's own via [pbs] advertised_urls. If advertised_urls is set
    // but does not cover a projected URL, a bid addressed to that URL decodes to
    // CB's own URL and self-dials recursively. The operator runs `cb-km check` as
    // the gate before apply, so this is an error, not a warning.
    let advertised = &input.cfg.pbs.pbs_config.advertised_urls;
    if !advertised.is_empty() {
        let mut projected_urls: BTreeSet<&str> = BTreeSet::new();
        projected_urls.insert(overlay.advertised_url.as_str());
        for vc in &overlay.vcs {
            if let Some(url) = &vc.advertised_url {
                projected_urls.insert(url.as_str());
            }
        }
        for raw in projected_urls {
            // overlay.validate() already rejected an unparseable advertised_url
            let Ok(projected) = Url::parse(raw) else { continue };
            if !advertised.iter().any(|own| advertised_url_matches(own, &projected)) {
                report.push(
                    Tier::Error,
                    "advertised-url-uncovered",
                    format!(
                        "projected advertised_url {raw} is not covered by any [pbs] advertised_urls entry; a bid addressed to it decodes to CB's own URL and self-dials recursively"
                    ),
                );
            }
        }
    }

    let mut key_holders: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for vc in &overlay.vcs {
        let vc_name = vc.url.to_string();
        let token = read_token(Path::new(&vc.token_path))?;
        let client = KmClient::new(vc.url.clone(), token)?;
        let enumerated = client.list_keystores().await?;
        for key in &enumerated {
            key_holders.entry(key.clone()).or_default().push(vc_name.clone());
        }

        let vc_projection = project_with_url(input, overlay.advertised_url_for(vc))?;
        let vc_docs: BTreeMap<String, _> =
            vc_projection.docs.iter().map(|(k, d)| (k.to_string(), d)).collect();

        for key in &enumerated {
            let stored = match client.get_builder_config(key).await? {
                GetConfigOutcome::Ok(doc) => doc,
                GetConfigOutcome::NotFound => {
                    // 404 on a key the VC itself enumerated: the ROUTE is
                    // missing, not the key
                    report.push(
                        Tier::Error,
                        "no-builder-config-route",
                        format!(
                            "{vc_name}: {key} enumerated but has no builder_config route \
                             (keymanager-APIs #88 unsupported?)"
                        ),
                    );
                    continue;
                }
            };
            let stored = CanonicalDoc::from_doc(&stored)?;

            // unroutable stored auth_data: no configured relay's candidate
            // bytes equal it
            for entry in stored.builders.iter().flatten() {
                if let Some(bytes) = &entry.auth_data &&
                    !global.relay_candidates.iter().any(|c| &c.bytes == bytes)
                {
                    // WARN, not ERROR: v1 CB is a pure pipe, an out-of-band
                    // builder URL routes fine
                    report.push(
                        Tier::Warn,
                        "unroutable-auth-data",
                        format!(
                            "{vc_name}: {key} stores auth_data {} not matched by any configured \
                             relay; will be served via the pipe",
                            display_auth_data(bytes)
                        ),
                    );
                }
            }

            match vc_docs.get(key) {
                Some(projected) => {
                    let projected = CanonicalDoc::from_doc(projected)?;
                    for drift in drift_lines(&projected, &stored) {
                        report.push(
                            Tier::Warn,
                            "drift",
                            format!("{vc_name}: {key} drifted: {drift}"),
                        );
                    }
                }
                None => {
                    if stored.builders.as_ref().is_some_and(|b| !b.is_empty()) {
                        report.push(
                            Tier::Warn,
                            "stored-unprojected",
                            format!("{vc_name}: {key} has a stored doc but is not projected"),
                        );
                    }
                }
            }
        }
    }

    for (key, holders) in &key_holders {
        if holders.len() > 1 {
            report.push(
                Tier::Error,
                "duplicate-key",
                format!("{key} is held by {} VCs ({holders:?}): slashing risk", holders.len()),
            );
        }
        if !projected_keys.contains(key) {
            report.push(
                Tier::Warn,
                "unprojected",
                format!("{key} enumerated but unprojected: best-effort only"),
            );
        }
    }

    Ok(report)
}

/// Compares a projected doc against a stored (resolved) one. A field the
/// projection left unset resolves to the VC's own config on GET, so only
/// projected values are compared. The entry sets are diffed both ways: a
/// projected entry with no stored match is missing, and a stored entry with no
/// projected match is surplus; each is itemized individually.
fn drift_lines(projected: &CanonicalDoc, stored: &CanonicalDoc) -> Vec<String> {
    let mut lines = Vec::new();
    compare_field(&mut lines, "min_bid", &projected.min_bid, &stored.min_bid);
    compare_field(
        &mut lines,
        "builder_boost_factor",
        &projected.builder_boost_factor,
        &stored.builder_boost_factor,
    );

    let Some(projected_entries) = &projected.builders else {
        return lines;
    };
    let stored_entries = stored.builders.as_deref().unwrap_or_default();
    let stored_by_key: BTreeMap<(String, Option<Vec<u8>>), &CanonicalEntry> = stored_entries
        .iter()
        .map(|entry| ((entry.url.clone(), entry.auth_data.clone()), entry))
        .collect();

    for entry in projected_entries {
        let key = (entry.url.clone(), entry.auth_data.clone());
        let Some(stored_entry) = stored_by_key.get(&key) else {
            lines.push(format!(
                "entry ({}, {}) is missing",
                entry.url,
                entry.auth_data.as_deref().map(display_auth_data).unwrap_or_default()
            ));
            continue;
        };
        if entry.builder_pubkeys != stored_entry.builder_pubkeys {
            lines.push(format!("entry {}: builder_pubkeys differ", entry.url));
        }
        compare_field(&mut lines, "entry min_bid", &entry.min_bid, &stored_entry.min_bid);
        compare_field(
            &mut lines,
            "entry max_execution_payment",
            &entry.max_execution_payment,
            &stored_entry.max_execution_payment,
        );
        compare_field(
            &mut lines,
            "entry builder_boost_factor",
            &entry.builder_boost_factor,
            &stored_entry.builder_boost_factor,
        );
    }

    let projected_by_key: BTreeSet<(String, Option<Vec<u8>>)> = projected_entries
        .iter()
        .map(|entry| (entry.url.clone(), entry.auth_data.clone()))
        .collect();
    for entry in stored_entries {
        let key = (entry.url.clone(), entry.auth_data.clone());
        if !projected_by_key.contains(&key) {
            lines.push(format!(
                "entry ({}, {}) is stored but not projected",
                entry.url,
                entry.auth_data.as_deref().map(display_auth_data).unwrap_or_default()
            ));
        }
    }
    lines
}

/// Renders decoded auth_data for a finding: a public builder URL is shown
/// as-is, but a bilateral secret (non-URL bytes) is reduced to a length-only
/// placeholder so a check report never prints the secret. Mirrors apply.rs
/// `redact_secrets_for_display`.
fn display_auth_data(bytes: &[u8]) -> String {
    let is_url = std::str::from_utf8(bytes).ok().and_then(|s| url::Url::parse(s).ok()).is_some();
    if is_url {
        crate::doc::encode_auth_data(bytes)
    } else {
        format!("{} bytes (secret)", bytes.len())
    }
}

fn compare_field(
    lines: &mut Vec<String>,
    name: &str,
    projected: &Option<u64>,
    stored: &Option<u64>,
) {
    if let Some(expected) = projected &&
        stored != &Some(*expected)
    {
        lines.push(format!("{name}: projected {expected}, stored {stored:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_url_matches_mirrors_cb_pbs() {
        let u = |s: &str| Url::parse(s).unwrap();
        // userinfo (relay pubkey) and the default port are ignored
        assert!(advertised_url_matches(
            &u("https://0xdead@cb.example.com"),
            &u("https://cb.example.com")
        ));
        assert!(advertised_url_matches(
            &u("https://cb.example.com:443"),
            &u("https://cb.example.com")
        ));
        // a trailing-dot FQDN canonicalizes to its dotless form
        assert!(advertised_url_matches(&u("http://cb.example.com."), &u("http://cb.example.com")));
        // scheme and host mismatches do not match
        assert!(!advertised_url_matches(&u("http://cb.example.com"), &u("https://cb.example.com")));
        assert!(!advertised_url_matches(&u("https://a.example.com"), &u("https://b.example.com")));
    }
}
