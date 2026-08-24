//! `cb-km apply`: push projected docs to every VC and verify each projected
//! key was accepted by exactly one of them.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::{Path, PathBuf},
};

use eyre::{Context, Result, ensure};
use tracing::{error, info, warn};

use crate::{
    client::{GetConfigOutcome, KmClient, PostOutcome, read_token},
    doc::{BuilderConfigDoc, BuilderEntryDoc},
    overlay::{Overlay, VcConfig},
    project::{
        MAX_BUILDER_ENTRIES, MAX_BUILDER_PUBKEYS, Projection, ProjectionInput, project,
        project_with_url,
    },
};

#[derive(Debug, Default, Clone)]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub emit_dir: Option<PathBuf>,
    pub prune: bool,
    /// Preserve third-party builder entries a VC already stores (see --help).
    pub preserve_entries: bool,
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
    /// projected key -> VCs that accepted it (202)
    pub accepted: BTreeMap<String, Vec<String>>,
    /// (vc, key) pairs pruned with `POST {}`
    pub pruned: Vec<(String, String)>,
}

impl ApplyReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }

    fn error(&mut self, msg: String) {
        error!("{msg}");
        self.errors.push(msg);
    }

    fn warn(&mut self, msg: String) {
        warn!("{msg}");
        self.warnings.push(msg);
    }

    fn note(&mut self, msg: String) {
        info!("{msg}");
        self.info.push(msg);
    }
}

enum Preflight {
    Supported,
    Unsupported,
    /// No enumerated key to probe: proceed and let the POST responses tell
    Unknown,
}

/// Probes #88 builder_config support with a key the VC itself enumerated: a
/// 404 then means the ROUTE is missing, never "key elsewhere". Transport
/// errors and non-404 failures propagate; they are not evidence about
/// support.
async fn preflight_builder_config(client: &KmClient, enumerated: &[String]) -> Result<Preflight> {
    let Some(probe_key) = enumerated.first() else {
        return Ok(Preflight::Unknown);
    };
    match client.get_builder_config(probe_key).await? {
        GetConfigOutcome::Ok(_) => Ok(Preflight::Supported),
        GetConfigOutcome::NotFound => Ok(Preflight::Unsupported),
    }
}

pub async fn run_apply(
    input: &ProjectionInput,
    overlay: &Overlay,
    opts: &ApplyOptions,
) -> Result<ApplyReport> {
    let mut report = ApplyReport::default();
    let global = project(input, overlay)?;
    report.warnings.extend(global.warnings.iter().cloned());
    let projected_keys: BTreeSet<String> = global.docs.keys().map(|k| k.to_string()).collect();

    if opts.dry_run {
        for (key, doc) in &global.docs {
            let doc = redact_secrets_for_display(doc);
            report.note(format!("would apply {key}: {}", serde_json::to_string(&doc)?));
        }
        report.note(format!("dry-run: {} keys projected, nothing sent", global.docs.len()));
        return Ok(report);
    }

    if let Some(dir) = &opts.emit_dir {
        emit(dir, &global)?;
        report.note(format!("emitted {} per-key docs to {dir:?}", global.docs.len()));
        return Ok(report);
    }

    ensure!(!overlay.vcs.is_empty(), "no [[vcs]] configured in the overlay");

    let mut all_enumerated: BTreeSet<String> = BTreeSet::new();

    for vc in &overlay.vcs {
        apply_to_vc(vc, input, overlay, opts, &projected_keys, &mut all_enumerated, &mut report)
            .await?;
    }

    // coverage warning (default on): enumerated keys outside the projection
    // route to CB's own URL under the pipe default and are best-effort only
    for key in all_enumerated.difference(&projected_keys) {
        report.warn(format!("{key} enumerated but unprojected: best-effort only"));
    }

    // exit rule: every projected key accepted by exactly one VC
    for key in &projected_keys {
        match report.accepted.get(key).map(Vec::len).unwrap_or(0) {
            0 => report.error(format!("{key} was accepted by NO vc")),
            1 => {}
            n => report.error(format!(
                "{key} was accepted by {n} VCs: DUPLICATE KEY across VCs, slashing risk; \
                 partition your keys"
            )),
        }
    }

    Ok(report)
}

/// Applies the projection to one VC: enumerate its keys, confirm #88 support,
/// POST each projected doc (folding in preserved entries when asked), and prune
/// unprojected keys. A per-VC failure is recorded on the report and returns
/// early rather than aborting the whole run; only a transport/setup error
/// propagates.
async fn apply_to_vc(
    vc: &VcConfig,
    input: &ProjectionInput,
    overlay: &Overlay,
    opts: &ApplyOptions,
    projected_keys: &BTreeSet<String>,
    all_enumerated: &mut BTreeSet<String>,
    report: &mut ApplyReport,
) -> Result<()> {
    let vc_name = vc.url.to_string();
    let token = read_token(Path::new(&vc.token_path))?;
    let client = KmClient::new(vc.url.clone(), token)?;

    let enumerated = match client.list_keystores().await {
        Ok(keys) => keys,
        Err(err) => {
            report.error(format!("{vc_name}: keystores preflight failed: {err}"));
            return Ok(());
        }
    };
    all_enumerated.extend(enumerated.iter().cloned());

    match preflight_builder_config(&client, &enumerated).await {
        Ok(Preflight::Supported) => {}
        Ok(Preflight::Unsupported) => {
            report.error(format!(
                "{vc_name}: no builder_config support (keymanager-APIs #88); skipping"
            ));
            return Ok(());
        }
        Ok(Preflight::Unknown) => {
            report.warn(format!(
                "{vc_name}: no keys to probe for builder_config support; POSTing anyway"
            ));
        }
        Err(err) => {
            report.error(format!("{vc_name}: builder_config probe failed: {err}"));
            return Ok(());
        }
    }

    let vc_projection = project_with_url(input, overlay.advertised_url_for(vc))?;
    for (key, doc) in &vc_projection.docs {
        let key = key.to_string();

        // --preserve-entries: fold any third-party builder entries the VC
        // already stores back into our doc so the full-replace POST does
        // not erase them.
        let merged;
        let doc = if opts.preserve_entries {
            match client.get_builder_config(&key).await {
                Ok(GetConfigOutcome::Ok(stored)) => {
                    match merge_preserved_entries(&key, doc, &stored) {
                        Ok(m) => {
                            merged = m;
                            &merged
                        }
                        Err(err) => {
                            report.error(format!(
                                "{vc_name}: preserve-entries merge for {key} failed: {err}"
                            ));
                            continue;
                        }
                    }
                }
                // nothing stored (or route absent for this key): POST ours
                Ok(GetConfigOutcome::NotFound) => doc,
                Err(err) => {
                    report.error(format!(
                        "{vc_name}: preserve-entries GET for {key} failed: {err}"
                    ));
                    continue;
                }
            }
        } else {
            doc
        };

        match client.post_builder_config(&key, doc).await {
            Ok(PostOutcome::Accepted) => {
                report.accepted.entry(key).or_default().push(vc_name.clone());
            }
            Ok(PostOutcome::KeyNotFound) => {}
            Ok(PostOutcome::ConfigFileManaged) => {
                report.warn(format!("{vc_name}: {key} is config-file-managed, cannot override"));
            }
            Err(err) => report.error(format!("{vc_name}: POST {key} failed: {err}")),
        }
    }

    if opts.prune {
        for key in &enumerated {
            if !projected_keys.contains(key) {
                // POST {} is spec-equal to DELETE and a no-op when nothing
                // is stored
                match client.post_builder_config(key, &BuilderConfigDoc::default()).await {
                    Ok(PostOutcome::Accepted) => {
                        report.pruned.push((vc_name.clone(), key.clone()));
                    }
                    Ok(other) => {
                        report.warn(format!("{vc_name}: prune of {key} not accepted: {other:?}"))
                    }
                    Err(err) => report.error(format!("{vc_name}: prune of {key} failed: {err}")),
                }
            }
        }
    }

    Ok(())
}

/// An entry's identity for the preserve merge: its URL and DECODED auth_data
/// bytes (hex case is not identity). Two entries collide iff both agree.
fn entry_identity(entry: &BuilderEntryDoc) -> Result<(String, Option<Vec<u8>>)> {
    let auth = match &entry.auth_data {
        Some(hex) => Some(crate::doc::decode_auth_data(hex)?),
        // Dead in practice: a resolved KM GET always populates auth_data and our
        // projection always sets Some, so identities collide correctly.
        None => None,
    };
    Ok((entry.url.clone(), auth))
}

/// Folds third-party builder entries from a VC's stored (resolved) doc into our
/// projected doc. Identity is `(url, decoded auth_data)`. Every stored entry
/// whose identity our projection ALSO produces is OURS: a GET returns the doc
/// fully resolved, so field values on our own entries are VC defaults, not
/// third-party data, and ours win on collision. Every other stored entry was
/// pinned by someone else and is preserved, appended after ours. Key-level
/// fields (min_bid / boost) are p2p policy we own and stay ours. The KM entry
/// caps are re-checked on the MERGED set: a merge that would break the spec
/// (e.g. >64 combined entries) fails loudly rather than silently dropping.
fn merge_preserved_entries(
    key: &str,
    projected: &BuilderConfigDoc,
    stored: &BuilderConfigDoc,
) -> Result<BuilderConfigDoc> {
    let our_entries = projected.builders.clone().unwrap_or_default();
    let stored_entries = stored.builders.as_deref().unwrap_or_default();

    let mut seen: HashSet<(String, Option<Vec<u8>>)> = HashSet::new();
    for entry in &our_entries {
        seen.insert(entry_identity(entry)?);
    }

    let mut merged = our_entries.clone();
    for entry in stored_entries {
        let id = entry_identity(entry)?;
        // ours win on identity collision; dedup a stored doc's own repeats
        if seen.insert(id) {
            merged.push(entry.clone());
        }
    }

    ensure!(
        merged.len() <= MAX_BUILDER_ENTRIES,
        "{key}: --preserve-entries would keep {} builder entries, exceeding the KM maximum of \
         {MAX_BUILDER_ENTRIES}; refusing to POST rather than silently drop a pinned entry",
        merged.len()
    );
    for entry in &merged {
        if let Some(pubkeys) = &entry.builder_pubkeys {
            ensure!(
                pubkeys.len() <= MAX_BUILDER_PUBKEYS,
                "{key}: --preserve-entries merged entry {} has {} builder_pubkeys, exceeding the \
                 KM maximum of {MAX_BUILDER_PUBKEYS}",
                entry.url,
                pubkeys.len()
            );
        }
    }

    Ok(BuilderConfigDoc {
        min_bid: projected.min_bid.clone(),
        builder_boost_factor: projected.builder_boost_factor.clone(),
        builders: Some(merged),
    })
}

/// Writes per-key JSON docs plus a manifest instead of POSTing (GitOps /
/// orchestrator-consumable). Emitted files can carry bilateral-secret
/// auth_data, so the dir and every file are restricted to the owner.
fn emit(dir: &Path, projection: &Projection) -> Result<()> {
    std::fs::create_dir_all(dir).wrap_err_with(|| format!("cannot create emit dir {dir:?}"))?;
    restrict_to_owner(dir, 0o700)?;
    let mut manifest = Vec::new();
    for (key, doc) in &projection.docs {
        let file = format!("{key}.json");
        let path = dir.join(&file);
        std::fs::write(&path, serde_json::to_string_pretty(doc)?)?;
        restrict_to_owner(&path, 0o600)?;
        manifest.push(serde_json::json!({ "pubkey": key.to_string(), "file": file }));
    }
    let manifest_path = dir.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&serde_json::json!({ "keys": manifest }))?,
    )?;
    restrict_to_owner(&manifest_path, 0o600)?;
    Ok(())
}

/// Restricts a path to the owner. `mode` is 0o600 for files, 0o700 for the dir
/// (a directory needs its execute bit to stay traversable). No-op off Unix.
#[cfg(unix)]
fn restrict_to_owner(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .wrap_err_with(|| format!("cannot restrict permissions on {path:?}"))
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// For dry-run display: replace any bilateral-secret auth_data (bytes that are
/// not a valid UTF-8 URL) with a length-only placeholder. URL-form auth_data is
/// public and printed as-is.
fn redact_secrets_for_display(doc: &BuilderConfigDoc) -> BuilderConfigDoc {
    let mut doc = doc.clone();
    if let Some(builders) = &mut doc.builders {
        for entry in builders {
            let Some(hex) = &entry.auth_data else { continue };
            if auth_data_is_url(hex) {
                continue;
            }
            let len = crate::doc::decode_auth_data(hex).map(|b| b.len()).unwrap_or(0);
            entry.auth_data = Some(format!("{len} bytes (secret)"));
        }
    }
    doc
}

/// Whether hex-encoded auth_data decodes to a valid UTF-8 URL (the public form).
fn auth_data_is_url(hex: &str) -> bool {
    crate::doc::decode_auth_data(hex)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| url::Url::parse(&s).ok())
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::encode_auth_data;

    fn entry(url: &str, auth: &[u8], pubkeys: &[&str]) -> BuilderEntryDoc {
        BuilderEntryDoc {
            url: url.to_string(),
            auth_data: Some(encode_auth_data(auth)),
            builder_pubkeys: Some(pubkeys.iter().map(|s| s.to_string()).collect()),
            max_execution_payment: None,
            min_bid: None,
            builder_boost_factor: None,
        }
    }

    fn ours() -> BuilderConfigDoc {
        BuilderConfigDoc {
            min_bid: Some("500000000".into()),
            builder_boost_factor: None,
            builders: Some(vec![entry("https://cb.example.com", b"https://relay-a", &["0xaa"])]),
        }
    }

    #[test]
    fn third_party_entry_is_preserved_after_ours() {
        let stored = BuilderConfigDoc {
            builders: Some(vec![entry("https://other.example.com", b"https://relay-x", &["0xff"])]),
            ..Default::default()
        };
        let merged = merge_preserved_entries("k", &ours(), &stored).unwrap();
        let entries = merged.builders.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].url, "https://cb.example.com");
        assert_eq!(entries[1].url, "https://other.example.com");
        // key-level fields stay ours
        assert_eq!(merged.min_bid, Some("500000000".into()));
    }

    #[test]
    fn our_identity_wins_over_stored_resolved_version() {
        // stored holds OUR identity (same url + auth_data) but with VC-resolved
        // fields and a different pubkey set: ours must win, no duplicate
        let stored = BuilderConfigDoc {
            builders: Some(vec![BuilderEntryDoc {
                min_bid: Some("999".into()),
                ..entry("https://cb.example.com", b"https://relay-a", &["0xbb"])
            }]),
            ..Default::default()
        };
        let merged = merge_preserved_entries("k", &ours(), &stored).unwrap();
        let entries = merged.builders.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].builder_pubkeys, Some(vec!["0xaa".to_string()]));
        assert_eq!(entries[0].min_bid, None);
    }

    #[test]
    fn identity_ignores_hex_case() {
        let mut theirs = entry("https://cb.example.com", b"https://relay-a", &["0xcc"]);
        theirs.auth_data = Some(theirs.auth_data.unwrap().to_uppercase().replacen("0X", "0x", 1));
        let stored = BuilderConfigDoc { builders: Some(vec![theirs]), ..Default::default() };
        // same identity as ours despite uppercase hex -> collapses to ours
        let merged = merge_preserved_entries("k", &ours(), &stored).unwrap();
        assert_eq!(merged.builders.unwrap().len(), 1);
    }

    #[test]
    fn merge_exceeding_max_entries_fails() {
        let extras: Vec<_> = (0..MAX_BUILDER_ENTRIES)
            .map(|i| entry("https://other.example.com", format!("relay-{i}").as_bytes(), &["0xff"]))
            .collect();
        let stored = BuilderConfigDoc { builders: Some(extras), ..Default::default() };
        let err = merge_preserved_entries("k", &ours(), &stored).unwrap_err();
        assert!(err.to_string().contains("exceeding the KM maximum"), "{err}");
    }
}
