//! `cb-km check`: read-only comparison of stored VC docs against the
//! projection. Comparison is CANONICAL, never a byte-diff: the spec promises
//! neither entry order nor hex case, and a GET returns the doc fully
//! RESOLVED, so fields the projection intentionally omits (they resolve to
//! the VC's own config) are skipped rather than reported as drift.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use eyre::Result;

use crate::{
    client::{GetConfigOutcome, KmClient, read_token},
    doc::{CanonicalDoc, CanonicalEntry},
    overlay::Overlay,
    project::{ProjectionInput, project, project_with_url},
};

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
                            crate::doc::encode_auth_data(bytes)
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
/// projected values are compared; extra or missing entries are always drift.
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
    let stored_entries = stored.builders.clone().unwrap_or_default();
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
                entry.auth_data.as_deref().map(crate::doc::encode_auth_data).unwrap_or_default()
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

    if stored_entries.len() > projected_entries.len() {
        lines.push(format!(
            "stored doc has {} entries, projection has {}",
            stored_entries.len(),
            projected_entries.len()
        ));
    }
    lines
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
