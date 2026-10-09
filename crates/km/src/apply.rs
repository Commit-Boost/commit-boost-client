//! `builder-config apply`: writes the builder config of every key a validator
//! client holds, a mux key's from its mux and any other key's from
//! `[[relays]]`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use eyre::{Result, ensure};
use url::Url;

use crate::{
    client::{KmClient, SetOutcome},
    doc::{BuilderConfig, MAX_BUILDER_ENTRIES},
    output,
    project::Projection,
    targets::{Targets, VcConfig, is_loopback},
};

/// Lodestar's refusal of a nonzero `max_execution_payment` names this flag
pub const LODESTAR_CAP_FLAG: &str = "--allowDangerousTrustedPayments";

/// Writes in a row a client may leave unanswered before apply stops writing to
/// it, since each waits for the request timeout. A `--preserve-entries` read
/// that gets no answer counts as its key's write
const MAX_UNANSWERED: usize = 3;

#[derive(Default)]
pub struct ApplyOptions {
    pub preserve_entries: bool,
    /// The clients given are not all that hold the muxes' keys, so a key none
    /// of them holds is counted rather than an error
    pub partial: bool,
    /// Print each error, warning and write as it is recorded, and each client's
    /// line
    pub print: bool,
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    /// Key -> the clients that accepted it
    pub accepted: BTreeMap<String, Vec<String>>,
    /// Writes a listed client was due but did not get
    pub unwritten: usize,
    print: bool,
}

impl ApplyReport {
    fn error(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.print {
            output::err(format_args!("ERROR: {msg}"));
        }
        self.errors.push(msg);
    }

    fn warn(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.print {
            output::out(format_args!("WARN: {msg}"));
        }
        self.warnings.push(msg);
    }

    fn accept(&mut self, key: &str, vc: &str, mux: Option<&String>) {
        if self.print {
            match mux {
                Some(id) => output::out(format_args!("accepted: {key} on {vc} (mux {id})")),
                None => output::out(format_args!("accepted: {key} on {vc} ([[relays]])")),
            }
        }
        self.accepted.entry(key.to_string()).or_default().push(vc.to_string());
    }
}

/// Each of `keys` on its own indented line, to append to a message
fn key_lines(keys: impl IntoIterator<Item = impl Display>) -> String {
    keys.into_iter().map(|key| format!("\n  {key}")).collect()
}

/// Fails only before contacting a validator client; every later failure is on
/// the report
pub async fn run_apply(
    projection: &Projection,
    targets: &Targets,
    opts: &ApplyOptions,
) -> Result<ApplyReport> {
    ensure!(
        !targets.vcs.is_empty(),
        "no validator client given: pass --vc <keymanager URL>=<token file>"
    );
    let mut report = ApplyReport { print: opts.print, ..Default::default() };

    let advertised = Url::parse(&targets.advertised_url)?;
    // client -> the keys it lists
    let mut listings: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for vc in &targets.vcs {
        if let Some(keys) = apply_to_vc(vc, projection, &advertised, opts, &mut report).await {
            listings.insert(vc.url.as_str(), keys);
        }
    }
    // key -> the clients that list it, in `--vc` order
    let mut listed: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut unlisted = Vec::new();
    for vc in &targets.vcs {
        match listings.get(vc.url.as_str()) {
            Some(keys) => {
                for key in keys {
                    listed.entry(key).or_default().push(vc.url.as_str());
                }
            }
            None => unlisted.push(vc.url.as_str()),
        }
    }
    // A client that could not be listed may hold any key no other client lists
    let may_hold = if unlisted.is_empty() {
        String::new()
    } else {
        format!("; {} could not be listed and may hold some", unlisted.join(", "))
    };

    if listed.is_empty() && unlisted.is_empty() {
        // A sidecar can run before its client has keys
        if opts.partial {
            report.warn("no validator client given lists a key");
        } else {
            report.error("no validator client lists a key");
        }
    }
    if projection.relays_doc.is_none() {
        let outside = listed.keys().filter(|key| !projection.mux_docs.contains_key(**key)).count();
        if outside > 0 {
            report.warn(format!("keys in no mux, with no [[relays]] to write for them: {outside}"));
        }
    }
    // A loader lists keys no client of this operator holds, such as exited ones
    let (fetched, named): (Vec<&String>, Vec<&String>) = projection
        .mux_docs
        .keys()
        .filter(|key| !listed.contains_key(key.as_str()))
        .partition(|key| projection.fetched_keys.contains(*key));
    if !named.is_empty() {
        let count = named.len();
        if opts.partial {
            report.warn(format!("keys in a mux that no validator client given holds: {count}"));
        } else {
            report.error(format!(
                "keys in a mux that no validator client lists: {count}{may_hold}{}",
                key_lines(named)
            ));
        }
    }
    if !fetched.is_empty() {
        report.warn(format!(
            "keys a URL or registry loader lists that no validator client holds: {}{may_hold}",
            fetched.len()
        ));
    }
    // holders -> the keys they all list
    let mut shared: BTreeMap<&[&str], Vec<&str>> = BTreeMap::new();
    for (key, holders) in listed.iter().filter(|(_, holders)| holders.len() > 1) {
        shared.entry(holders.as_slice()).or_default().push(key);
    }
    for (holders, keys) in shared {
        report.error(format!(
            "keys held by more than one validator client ({}): {}; each is a slashing risk, so \
             keep it on one{}",
            holders.join(", "),
            keys.len(),
            key_lines(keys)
        ));
    }

    Ok(report)
}

/// A request that got no answer, rather than a refusal
fn is_unanswered(err: &eyre::Report) -> bool {
    err.downcast_ref::<reqwest::Error>().is_some_and(|err| err.is_timeout() || err.is_request())
}

/// `run` after a key's last request: one more if it got no answer, else 0
fn next_unanswered(run: usize, err: Option<&eyre::Report>) -> usize {
    if err.is_some_and(is_unanswered) { run + 1 } else { 0 }
}

/// Writes the projection to one client and returns the keys it lists, or `None`
/// when they could not be listed. A failure is recorded on the report and stops
/// only this client.
async fn apply_to_vc(
    vc: &VcConfig,
    projection: &Projection,
    advertised: &Url,
    opts: &ApplyOptions,
    report: &mut ApplyReport,
) -> Option<BTreeSet<String>> {
    let name = vc.url.as_str();
    if vc.url.scheme() != "https" && !is_loopback(&vc.url) {
        report.warn(format!(
            "{name}: not HTTPS and not loopback, so the bearer token is sent in cleartext"
        ));
    }
    let client = match KmClient::from_token_file(vc.url.clone(), &vc.token_path) {
        Ok(client) => client,
        Err(err) => {
            report.error(format!("{name}: setup failed: {err:#}"));
            return None;
        }
    };
    let listed = match client.list_keys().await {
        Ok(keys) => keys,
        Err(err) => {
            report.error(format!("{name}: key listing failed: {err:#}"));
            return None;
        }
    };
    let to_write = listed.iter().filter(|key| projection.doc_for(key).is_some()).count();

    // A 404 for a key the client lists means the route is missing
    let Some(probe) = listed.first() else {
        report.warn(format!("{name}: lists no validator keys"));
        return Some(listed);
    };
    let failure = match client.get_builder_config(probe).await {
        Ok(Some(_)) => None,
        Ok(None) => Some("no builder_config support (keymanager-APIs #88)".to_string()),
        Err(err) => Some(format!("builder_config probe failed: {err:#}")),
    };
    if let Some(failure) = failure {
        report.error(format!("{name}: {failure}; none of its {to_write} keys written"));
        report.unwritten += to_write;
        return Some(listed);
    }

    // Set once the client refuses a cap above 0, as Lodestar does without its flag
    let mut cap_refused = false;
    let (mut written, mut unanswered) = (0, 0);
    // Only the keys the client lists: some clients accept a write for any key
    for (i, key) in listed.iter().enumerate() {
        if unanswered == MAX_UNANSWERED {
            let left = listed
                .iter()
                .skip(i)
                .filter(|key| {
                    projection
                        .doc_for(key)
                        .is_some_and(|doc| !(cap_refused && doc.has_nonzero_cap()))
                })
                .count();
            if left > 0 {
                report.error(format!(
                    "{name}: {MAX_UNANSWERED} writes in a row got no answer, so its other {left} \
                     keys were not written"
                ));
            }
            break;
        }
        let Some(doc) = projection.doc_for(key) else { continue };
        let merged;
        let doc = if opts.preserve_entries {
            match client.get_builder_config(key).await {
                Ok(Some(stored)) => {
                    merged = merge_preserved_entries(doc, &stored, advertised);
                    let entries = merged.builders.as_ref().map_or(0, Vec::len);
                    if entries > MAX_BUILDER_ENTRIES {
                        report.error(format!(
                            "{name}: {key} would keep {entries} builder entries, over the \
                             {MAX_BUILDER_ENTRIES} a builder config holds"
                        ));
                        continue;
                    }
                    &merged
                }
                Ok(None) => doc,
                Err(err) => {
                    unanswered = next_unanswered(unanswered, Some(&err));
                    report.error(format!("{name}: preserve-entries GET for {key} failed: {err:#}"));
                    continue;
                }
            }
        } else {
            doc
        };
        if cap_refused && doc.has_nonzero_cap() {
            continue;
        }

        let result = client.set_builder_config(key, doc).await;
        unanswered = next_unanswered(unanswered, result.as_ref().err());
        match result {
            Ok(SetOutcome::Accepted) => {
                report.accept(key, name, projection.mux_ids.get(key));
                written += 1;
            }
            Ok(SetOutcome::KeyNotFound) => {
                report.error(format!("{name}: lists {key} but answered 404 to its write"))
            }
            // A 403 before any write lands refuses every write, as Lodestar does
            // under --proposerSettingsFile
            Ok(SetOutcome::Forbidden(message)) if written == 0 => {
                report.error(format!(
                    "{name}: answered 403 before any write landed ({message}), as under a \
                     proposer settings file; no further key was written to it"
                ));
                break;
            }
            Ok(SetOutcome::Forbidden(message)) => {
                report.error(format!("{name}: POST {key} refused: {message}"))
            }
            // Lodestar refuses every capped write alike, so one error says it all
            Err(err) if format!("{err:#}").contains(LODESTAR_CAP_FLAG) => {
                report.error(format!(
                    "{name}: refuses a max_execution_payment above 0 unless the validator client \
                     runs with {LODESTAR_CAP_FLAG}; restart it with that flag. No further key \
                     with a cap above 0 was written to it: {err:#}"
                ));
                cap_refused = true;
            }
            Err(err) => report.error(format!("{name}: POST {key} failed: {err:#}")),
        }
    }

    report.unwritten += to_write - written;
    if opts.print {
        let unwritten = to_write - written;
        let unwritten =
            if unwritten > 0 { format!(", {unwritten} not written") } else { String::new() };
        output::out(format_args!(
            "{name}: {} keys listed, {written} written{unwritten}",
            listed.len()
        ));
    }
    Some(listed)
}

/// The projection plus the stored entries at other URLs. Stored entries at the
/// advertised URL, this tool's or global builders the GET resolved, are dropped
fn merge_preserved_entries(
    projected: &BuilderConfig,
    stored: &BuilderConfig,
    advertised: &Url,
) -> BuilderConfig {
    let mut merged = projected.clone();
    let others = stored.builders.iter().flatten().filter(|entry| !same_url(&entry.url, advertised));
    merged.builders.get_or_insert_default().extend(others.cloned());
    merged
}

/// Equal once parsed, so a trailing slash does not hide a match
fn same_url(url: &str, other: &Url) -> bool {
    Url::parse(url).is_ok_and(|url| url == *other)
}
