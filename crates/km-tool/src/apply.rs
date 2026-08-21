//! `cb-km apply`: push projected docs to every VC and verify each projected
//! key was accepted by exactly one of them.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use eyre::{Context, Result, ensure};
use tracing::{info, warn};

use crate::{
    client::{GetConfigOutcome, KmClient, PostOutcome, read_token},
    doc::BuilderConfigDoc,
    overlay::Overlay,
    project::{Projection, ProjectionInput, project, project_with_url},
};

#[derive(Debug, Default, Clone)]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub emit_dir: Option<PathBuf>,
    pub prune: bool,
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
        warn!("{msg}");
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

/// Whether a VC preflight proved #88 builder_config support.
async fn preflight_supports_builder_config(
    client: &KmClient,
    enumerated: &[String],
    fallback_probe_key: Option<&str>,
) -> Result<bool> {
    // Probe a key the VC itself enumerated: a 404 then means the ROUTE is
    // missing (no #88 support), never "key elsewhere". Without any enumerated
    // key fall back to a projected key, where 404 stays ambiguous and is
    // treated as unsupported to fail loud.
    let probe_key = enumerated.first().map(String::as_str).or(fallback_probe_key);
    let Some(probe_key) = probe_key else {
        return Ok(false);
    };
    match client.get_builder_config(probe_key).await? {
        GetConfigOutcome::Ok(_) => Ok(true),
        GetConfigOutcome::NotFound => Ok(false),
    }
}

pub async fn run_apply(
    input: &ProjectionInput,
    overlay: &Overlay,
    opts: &ApplyOptions,
) -> Result<ApplyReport> {
    let mut report = ApplyReport::default();
    let global = project(input, overlay)?;
    for w in &global.warnings {
        report.warnings.push(w.clone());
    }
    let projected_keys: BTreeSet<String> = global.docs.keys().map(|k| k.to_string()).collect();

    if opts.dry_run {
        for (key, doc) in &global.docs {
            report.note(format!("would apply {key}: {}", serde_json::to_string(doc)?));
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
        let vc_name = vc.url.to_string();
        let token = read_token(Path::new(&vc.token_path))?;
        let client = KmClient::new(vc.url.clone(), token)?;

        let enumerated = match client.list_keystores().await {
            Ok(keys) => keys,
            Err(err) => {
                report.error(format!("{vc_name}: keystores preflight failed: {err}"));
                continue;
            }
        };
        all_enumerated.extend(enumerated.iter().cloned());

        let supports = preflight_supports_builder_config(
            &client,
            &enumerated,
            projected_keys.iter().next().map(String::as_str),
        )
        .await
        .unwrap_or(false);
        if !supports {
            report.error(format!(
                "{vc_name}: no builder_config support (keymanager-APIs #88); skipping"
            ));
            continue;
        }

        let vc_projection = project_with_url(input, overlay, overlay.advertised_url_for(vc))?;
        for (key, doc) in &vc_projection.docs {
            let key = key.to_string();
            match client.post_builder_config(&key, doc).await {
                Ok(PostOutcome::Accepted) => {
                    report.accepted.entry(key).or_default().push(vc_name.clone());
                }
                Ok(PostOutcome::KeyNotFound) => {}
                Ok(PostOutcome::ConfigFileManaged) => {
                    report
                        .warn(format!("{vc_name}: {key} is config-file-managed, cannot override"));
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
                        Ok(other) => report
                            .warn(format!("{vc_name}: prune of {key} not accepted: {other:?}")),
                        Err(err) => {
                            report.error(format!("{vc_name}: prune of {key} failed: {err}"))
                        }
                    }
                }
            }
        }
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

/// Writes per-key JSON docs plus a manifest instead of POSTing (GitOps /
/// orchestrator-consumable).
fn emit(dir: &Path, projection: &Projection) -> Result<()> {
    std::fs::create_dir_all(dir).wrap_err_with(|| format!("cannot create emit dir {dir:?}"))?;
    let mut manifest = Vec::new();
    for (key, doc) in &projection.docs {
        let file = format!("{key}.json");
        std::fs::write(dir.join(&file), serde_json::to_string_pretty(doc)?)?;
        manifest.push(serde_json::json!({ "pubkey": key.to_string(), "file": file }));
    }
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "keys": manifest }))?,
    )?;
    Ok(())
}
