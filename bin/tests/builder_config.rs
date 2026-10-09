//! `commit-boost builder-config` against a mock keymanager API (axum).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use cb_common::config::CommitBoostConfig;
use cb_km::{
    apply::{ApplyOptions, ApplyReport, run_apply},
    project::{Projection, mux_keys, parse_config, project},
    targets::Targets,
};

const RELAY_PK_A: &str = "0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2";
const RELAY_PK_B: &str = "0xa119589bb33ef52acbb8116832bec2b58fca590fe5c85eac5d3230b44d5bc09fe73ccd21f88eab31d6de16194d17782e";
const TOKEN: &str = "test-token";

#[derive(Clone, Default)]
struct MockVc {
    /// keys this VC holds (lowercase hex)
    keystores: Vec<String>,
    /// keys this VC holds through a remote signer; None: no remotekeys route
    remotekeys: Option<Vec<String>>,
    /// whether the VC serves the #88 builder_config route
    supports_builder_config: bool,
    /// stored docs returned on GET
    stored: HashMap<String, serde_json::Value>,
    /// POST status override per key, answered with an ErrorResponse body
    /// (default: 202 when held, else 404)
    post_status: HashMap<String, u16>,
    /// GET builder_config status override for every key
    get_status: Option<u16>,
    /// GET builder_config status override per key
    get_status_for: HashMap<String, u16>,
    /// remotekeys status override
    remotekeys_status: Option<u16>,
    /// answers 202 to a write for a key it does not hold, as some clients do
    accepts_any_key: bool,
    /// refuses a write with a cap above 0, as Lodestar does without its flag
    lodestar_cap_refusal: bool,
    /// keys whose builder_config GET or POST it drops the connection on,
    /// leaving the request unanswered
    hangs_up_on: Vec<String>,
    /// hangs up on the writes in `hangs_up_on` only, answering their reads
    answers_reads: bool,
    /// (pubkey, raw body) of every builder_config POST
    posts: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockVc {
    fn holding(keys: &[String]) -> Self {
        Self { keystores: keys.to_vec(), supports_builder_config: true, ..Default::default() }
    }

    fn holds(&self, key: &String) -> bool {
        self.keystores.contains(key) || self.remotekeys.iter().flatten().any(|k| k == key)
    }

    fn posts(&self) -> Vec<(String, String)> {
        self.posts.lock().unwrap().clone()
    }
}

/// A key as a client may list it: the spec allows uppercase hex
fn listed(pk: &str) -> String {
    format!("0x{}", pk[2..].to_uppercase())
}

fn authed(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == format!("Bearer {TOKEN}"))
}

async fn keystores(State(vc): State<MockVc>, headers: HeaderMap) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let data: Vec<_> = vc
        .keystores
        .iter()
        .map(|pk| serde_json::json!({ "validating_pubkey": listed(pk) }))
        .collect();
    axum::Json(serde_json::json!({ "data": data })).into_response()
}

async fn remotekeys(State(vc): State<MockVc>, headers: HeaderMap) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if let Some(status) = vc.remotekeys_status {
        return (StatusCode::from_u16(status).unwrap(), "overridden").into_response();
    }
    let Some(keys) = &vc.remotekeys else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let data: Vec<_> = keys
        .iter()
        .map(|pk| serde_json::json!({ "pubkey": listed(pk), "url": "https://signer.example.com", "readonly": false }))
        .collect();
    axum::Json(serde_json::json!({ "data": data })).into_response()
}

async fn get_config(
    State(vc): State<MockVc>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    // A panic ends the connection's task, closing it without a response
    if !vc.answers_reads && vc.hangs_up_on.contains(&pubkey) {
        panic!("hanging up on the read");
    }
    if let Some(status) = vc.get_status.or(vc.get_status_for.get(&pubkey).copied()) {
        return (StatusCode::from_u16(status).unwrap(), "overridden").into_response();
    }
    if !vc.supports_builder_config || !vc.holds(&pubkey) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let doc = vc.stored.get(&pubkey).cloned().unwrap_or(serde_json::json!({}));
    axum::Json(serde_json::json!({ "data": doc })).into_response()
}

async fn post_config(
    State(vc): State<MockVc>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let capped = doc["builders"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|entry| entry["max_execution_payment"] != "0");
    vc.posts.lock().unwrap().push((pubkey.clone(), body));
    if vc.hangs_up_on.contains(&pubkey) {
        panic!("hanging up on the write");
    }
    if !vc.supports_builder_config {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if vc.lodestar_cap_refusal && capped {
        let message = "Configuring a builder max execution payment above 0 requires \
                       --allowDangerousTrustedPayments";
        let body = serde_json::json!({ "code": 400, "message": message });
        return (StatusCode::BAD_REQUEST, axum::Json(body)).into_response();
    }
    if let Some(&status) = vc.post_status.get(&pubkey) {
        let message = serde_json::json!({ "message": format!("refused with {status}") });
        return (StatusCode::from_u16(status).unwrap(), axum::Json(message)).into_response();
    }
    if vc.holds(&pubkey) || vc.accepts_any_key {
        StatusCode::ACCEPTED
    } else {
        StatusCode::NOT_FOUND
    }
    .into_response()
}

/// Serves a mock VC on an ephemeral port, returning its base URL.
async fn serve(vc: MockVc) -> String {
    let app = Router::new()
        .route("/eth/v1/keystores", get(keystores))
        .route("/eth/v1/remotekeys", get(remotekeys))
        .route("/eth/v1/validator/{pubkey}/builder_config", get(get_config).post(post_config))
        .with_state(vc);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A keymanager URL nothing listens on. The socket keeps the port bound while
/// it lives, so another test's server cannot take it
fn down_url() -> (String, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    (format!("http://{}", socket.local_addr().unwrap()), socket)
}

fn random_key() -> String {
    cb_common::types::BlsSecretKey::random().public_key().as_hex_string()
}

struct TestEnv {
    cfg: CommitBoostConfig,
    targets: Targets,
    token_file: tempfile::NamedTempFile,
    /// config.toml, for the binary
    dir: tempfile::TempDir,
}

impl TestEnv {
    /// A mux of `keys` behind two relays, applied to the VCs at `vc_urls`
    fn new(keys: &[String], vc_urls: &[String]) -> Self {
        Self::build(keys, vc_urls, "")
    }

    /// `new`, with a `[[relays]]` entry for the keys outside the mux
    fn with_relays(keys: &[String], vc_urls: &[String]) -> Self {
        let relays =
            format!("[[relays]]\nurl = \"https://{RELAY_PK_B}@default-relay.example.com\"\n");
        Self::build(keys, vc_urls, &relays)
    }

    /// `new`, with `top` after `[pbs]`'s `min_bid_eth`, for more `[pbs]` lines
    /// and `[[relays]]`
    fn build(keys: &[String], vc_urls: &[String], top: &str) -> Self {
        let keys = keys.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ");
        let cfg_text = format!(
            r#"
chain = "Holesky"

[pbs]
min_bid_eth = 0.5
{top}
[[mux]]
id = "mux1"
validator_pubkeys = [{keys}]

[[mux.relays]]
url = "https://{RELAY_PK_A}@relay-a.example.com"

[[mux.relays]]
url = "https://{RELAY_PK_B}@relay-b.example.com"
"#
        );
        let cfg = parse_config(&cfg_text).unwrap();

        let token_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token_file.path(), format!("{TOKEN}\n")).unwrap();
        let vcs = vc_urls
            .iter()
            .map(|url| format!("{url}={}", token_file.path().display()).parse().unwrap())
            .collect();
        let targets = Targets::new("https://cb.example.com".to_string(), vcs).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), cfg_text).unwrap();
        Self { cfg, targets, token_file, dir }
    }

    /// Runs `builder-config apply` on this config and these targets
    async fn apply_cli(&self, args: &[&str]) -> std::process::Output {
        self.command(args).output().await.unwrap()
    }

    /// `builder-config apply` on these targets, not yet run, from this config
    /// unless `args` name another source
    fn command(&self, args: &[&str]) -> tokio::process::Command {
        let mut cmd = builder_config("apply");
        if !args.contains(&"--from") {
            cmd.arg("--config").arg(self.dir.path().join("config.toml"));
        }
        cmd.arg("--advertised-url").arg(&self.targets.advertised_url);
        for vc in &self.targets.vcs {
            cmd.arg("--vc").arg(format!("{}={}", vc.url, vc.token_path.display()));
        }
        cmd.args(args);
        cmd
    }

    /// Runs `builder-config print` on this config
    async fn print(&self) -> std::process::Output {
        let mut cmd = builder_config("print");
        cmd.arg("--config").arg(self.dir.path().join("config.toml"));
        cmd.arg("--advertised-url").arg(&self.targets.advertised_url);
        cmd.output().await.unwrap()
    }

    async fn projection(&self) -> Projection {
        let mux_keys = mux_keys(&self.cfg).await.unwrap();
        project(&self.cfg, &mux_keys, &self.targets.advertised_url).unwrap()
    }

    async fn apply(&self, opts: ApplyOptions) -> ApplyReport {
        run_apply(&self.projection().await, &self.targets, &opts).await.unwrap()
    }

    /// The builder config apply writes for `key`, serialized as it POSTs it
    async fn projected(&self, key: &str) -> String {
        serde_json::to_string(self.projection().await.doc_for(key).unwrap()).unwrap()
    }
}

/// `commit-boost builder-config <subcommand>`, with no CB_CONFIG inherited
fn builder_config(subcommand: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_commit-boost"));
    cmd.env_remove("CB_CONFIG").arg("builder-config").arg(subcommand);
    cmd
}

fn third_party_entry(url: &str, auth_hex: &str) -> serde_json::Value {
    serde_json::json!({ "url": url, "auth_data": auth_hex, "builder_pubkeys": [RELAY_PK_B] })
}

// Each key goes to the client that holds it, and the POST body is the
// projection, without the entries the client stored before
#[tokio::test]
async fn apply_partitioned_keys_accepted_once_each() {
    let (k1, k2) = (random_key(), random_key());
    let mut vc1 = MockVc::holding(std::slice::from_ref(&k1));
    vc1.stored.insert(
        k1.clone(),
        serde_json::json!({ "builders": [third_party_entry("https://third-party.example.com", "0xc0ffee")] }),
    );
    let vc2 = MockVc::holding(std::slice::from_ref(&k2));
    let (url1, url2) = (serve(vc1.clone()).await, serve(vc2.clone()).await);

    let env = TestEnv::new(&[k1.clone(), k2.clone()], &[url1, url2]);
    let report = env.apply(ApplyOptions::default()).await;

    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.accepted.get(&k1).map(Vec::len), Some(1));
    assert_eq!(report.accepted.get(&k2).map(Vec::len), Some(1));
    let accepted: Vec<_> = vc1.posts().into_iter().filter(|(pk, _)| pk == &k1).collect();
    assert_eq!(accepted, [(k1.clone(), env.projected(&k1).await)]);
}

// A client whose setup, key listing or probe fails is skipped with that
// failure's own error; only a probe 404 reads as missing builder_config support
#[tokio::test]
async fn preflight_failures_skip_the_vc() {
    for (token, supports_builder_config, get_status, expected) in [
        (None, true, None, "unable to read token file"),
        (Some("wrong-token"), true, None, "key listing failed: keystores: 401 Unauthorized"),
        (
            Some(TOKEN),
            false,
            None,
            "no builder_config support (keymanager-APIs #88); none of its 1 keys",
        ),
        (
            Some(TOKEN),
            true,
            Some(500),
            "probe failed: 500 Internal Server Error; none of its 1 keys written",
        ),
        (Some(TOKEN), true, Some(200), "invalid builder_config response: error decoding"),
    ] {
        let key = random_key();
        let mut vc = MockVc::holding(std::slice::from_ref(&key));
        vc.supports_builder_config = supports_builder_config;
        vc.get_status = get_status;
        let url = serve(vc.clone()).await;

        let env = TestEnv::new(std::slice::from_ref(&key), &[url]);
        match token {
            Some(token) => std::fs::write(env.token_file.path(), token).unwrap(),
            None => std::fs::remove_file(env.token_file.path()).unwrap(),
        }
        let report = env.apply(ApplyOptions::default()).await;
        assert!(report.errors.iter().any(|err| err.contains(expected)), "{:?}", report.errors);
        assert!(vc.posts().is_empty(), "{expected}");
    }
}

// A key is written only to the clients that list it: a client that accepts a
// write for any key would otherwise count as a second holder
#[tokio::test]
async fn apply_writes_only_to_clients_that_list_the_key() {
    let (key, other) = (random_key(), random_key());
    let empty_vc = MockVc::holding(&[]);
    let any_key_vc =
        MockVc { accepts_any_key: true, ..MockVc::holding(std::slice::from_ref(&other)) };
    let holder_vc = MockVc::holding(std::slice::from_ref(&key));
    let urls =
        [serve(empty_vc.clone()).await, serve(any_key_vc.clone()).await, serve(holder_vc).await];

    let env = TestEnv::new(std::slice::from_ref(&key), &urls);
    let report = env.apply(ApplyOptions::default()).await;
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.accepted.get(&key), Some(&vec![urls[2].clone() + "/"]));
    assert!(empty_vc.posts().is_empty() && any_key_vc.posts().is_empty());
    assert!(
        report.warnings.iter().any(|w| w.contains("lists no validator keys")),
        "{:?}",
        report.warnings
    );
}

// A client may list a remote-signer key as a keystore too; it holds it once
#[tokio::test]
async fn a_key_listed_twice_by_one_client_is_held_once() {
    let key = random_key();
    let vc = MockVc {
        remotekeys: Some(vec![key.clone()]),
        ..MockVc::holding(std::slice::from_ref(&key))
    };
    let url = serve(vc.clone()).await;

    let env = TestEnv::new(std::slice::from_ref(&key), &[url]);
    let report = env.apply(ApplyOptions::default()).await;
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(vc.posts().len(), 1);
}

#[tokio::test]
async fn a_key_no_client_lists_is_an_error() {
    let (projected, other) = (random_key(), random_key());
    // the VC lists a different key, so nothing is written
    let vc = MockVc::holding(std::slice::from_ref(&other));
    let url = serve(vc.clone()).await;

    let env = TestEnv::new(std::slice::from_ref(&projected), &[url]);
    let report = env.apply(ApplyOptions::default()).await;
    let expected = format!("keys in a mux that no validator client lists: 1\n  {projected}");
    assert_eq!(report.errors, [expected]);
    assert!(
        report.warnings.iter().any(|w| w.ends_with("no [[relays]] to write for them: 1")),
        "{:?}",
        report.warnings
    );
    assert!(vc.posts().is_empty());
}

// A key only a URL or registry loader lists, such as an exited one, is counted
// in one warning, while a key the config names is an error
#[tokio::test]
async fn an_unheld_fetched_key_is_a_warning() {
    let (held, fetched) = (random_key(), random_key());
    let url = serve(MockVc::holding(std::slice::from_ref(&held))).await;

    let env = TestEnv::new(&[held.clone(), fetched.clone()], &[url]);
    let mut projection = env.projection().await;
    // A fetched key a client holds is not counted
    projection.fetched_keys.extend([held, fetched]);
    let report = run_apply(&projection, &env.targets, &ApplyOptions::default()).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let expected = "keys a URL or registry loader lists that no validator client holds: 1";
    assert_eq!(report.warnings, [expected]);
}

// An unlisted client may hold the keys no other client lists, so the error for
// unheld mux keys and the loader warning both name it
#[tokio::test]
async fn an_unlisted_client_may_hold_the_unheld_keys() {
    let (held, unheld, fetched) = (random_key(), random_key(), random_key());
    let (down, _bound) = down_url();
    let up = serve(MockVc::holding(std::slice::from_ref(&held))).await;

    let env = TestEnv::new(&[held, unheld.clone(), fetched.clone()], &[down.clone(), up]);
    let mut projection = env.projection().await;
    projection.fetched_keys.insert(fetched);
    let report = run_apply(&projection, &env.targets, &ApplyOptions::default()).await.unwrap();
    let may_hold = format!("; {down}/ could not be listed and may hold some");
    assert_eq!(report.errors.len(), 2, "{:?}", report.errors);
    assert!(report.errors[0].starts_with(&format!("{down}/: key listing failed")));
    let expected = format!("keys in a mux that no validator client lists: 1{may_hold}\n  {unheld}");
    assert_eq!(report.errors[1], expected);
    let expected =
        format!("keys a URL or registry loader lists that no validator client holds: 1{may_hold}");
    assert_eq!(report.warnings, [expected]);

    // With no client listed, its own failure says why nothing was written
    let (down, _bound) = down_url();
    let env = TestEnv::new(&[random_key()], &[down]);
    let report = env.apply(ApplyOptions::default()).await;
    assert!(!report.errors.iter().any(|err| err == "no validator client lists a key"));
}

// Keys two clients share are one alarm that names both clients and lists the
// keys, whether or not the clients list the same keys: two clients with
// identical keys are a migration or failover left running
#[tokio::test]
async fn the_slashing_alarm_groups_keys_by_their_clients() {
    let mut shared = [random_key(), random_key()];
    shared.sort();
    for identical in [false, true] {
        let mut second = shared.to_vec();
        if !identical {
            second.push(random_key());
        }
        let (url1, url2) =
            (serve(MockVc::holding(&shared)).await, serve(MockVc::holding(&second)).await);

        let env = TestEnv::with_relays(&shared, &[url1.clone(), url2.clone()]);
        let report = env.apply(ApplyOptions::default()).await;
        let expected = format!(
            "keys held by more than one validator client ({url1}/, {url2}/): 2; each is a \
             slashing risk, so keep it on one\n  {}\n  {}",
            shared[0], shared[1]
        );
        assert_eq!(report.errors, [expected]);
    }
}

// After 3 requests in a row get no answer, writes or --preserve-entries reads,
// apply stops writing to that client, once, and counts the keys it left with a
// config to write: the last key is in no mux, so it has none
#[tokio::test]
async fn three_unanswered_writes_stop_the_client() {
    let mut keys: Vec<String> = (0..7).map(|_| random_key()).collect();
    keys.sort();
    // An answered read before an unanswered write leaves the write counted
    for (preserve_entries, answers_reads, posts) in
        [(false, false, 4), (true, false, 1), (true, true, 4)]
    {
        // The probe, of the lowest key, is answered
        let vc =
            MockVc { hangs_up_on: keys[1..].to_vec(), answers_reads, ..MockVc::holding(&keys) };
        let url = serve(vc.clone()).await;

        let env = TestEnv::new(&keys[..6], std::slice::from_ref(&url));
        let report = env.apply(ApplyOptions { preserve_entries, ..Default::default() }).await;
        assert_eq!(vc.posts().len(), posts, "{preserve_entries} {answers_reads}");
        let stop = format!(
            "{url}/: 3 writes in a row got no answer, so its other 2 keys were not written"
        );
        let stops: Vec<_> = report.errors.iter().filter(|err| err.contains("in a row")).collect();
        assert_eq!(stops, [&stop], "{preserve_entries}");
    }
}

// The keys a stopped client is left owing leave out the capped keys its cap
// refusal already skips: keys[0] and keys[4] are in no mux, so they get the
// capped [[relays]] config, which a Lodestar without its flag refuses
#[tokio::test]
async fn an_unanswered_stop_counts_only_the_keys_left_to_write() {
    let mut keys: Vec<String> = (0..6).map(|_| random_key()).collect();
    keys.sort();
    let mux_keys = [&keys[1..4], &keys[5..]].concat();
    let vc = MockVc {
        lodestar_cap_refusal: true,
        hangs_up_on: keys[1..4].to_vec(),
        ..MockVc::holding(&keys)
    };
    let url = serve(vc).await;
    let top = format!(
        "max_execution_payment_gwei = 0\n[[relays]]\n\
         url = \"https://{RELAY_PK_B}@default-relay.example.com\"\n\
         max_execution_payment_gwei = \"unclamped\"\n"
    );
    let env = TestEnv::build(&mux_keys, std::slice::from_ref(&url), &top);
    let report = env.apply(ApplyOptions::default()).await;
    let stop =
        format!("{url}/: 3 writes in a row got no answer, so its other 1 keys were not written");
    assert!(report.errors.contains(&stop), "{:?}", report.errors);
}

// Any answer, a refusal included, resets the count, so two requests left
// unanswered on each side of it do not stop the writes. The middle key alone
// gets the capped [[relays]] config, which a Lodestar without its flag refuses
#[tokio::test]
async fn an_answer_resets_the_unanswered_count() {
    let mut keys: Vec<String> = (0..7).map(|_| random_key()).collect();
    keys.sort();
    let middle = keys[3].clone();
    let mux_keys: Vec<String> = keys.iter().filter(|key| **key != middle).cloned().collect();
    let hangs_up_on = vec![keys[1].clone(), keys[2].clone(), keys[4].clone(), keys[5].clone()];
    let vc = MockVc { hangs_up_on, ..MockVc::holding(&keys) };
    let refusing =
        |status| MockVc { post_status: HashMap::from([(middle.clone(), status)]), ..vc.clone() };
    let unreadable =
        MockVc { get_status_for: HashMap::from([(middle.clone(), 500)]), ..vc.clone() };
    let top = format!(
        "max_execution_payment_gwei = 0\n[[relays]]\n\
         url = \"https://{RELAY_PK_B}@default-relay.example.com\"\n\
         max_execution_payment_gwei = \"unclamped\"\n"
    );
    for (vc, preserve_entries) in [
        (vc.clone(), false),
        (refusing(404), false),
        (refusing(400), false),
        (MockVc { lodestar_cap_refusal: true, ..vc.clone() }, false),
        (unreadable, true),
    ] {
        let env = TestEnv::build(&mux_keys, &[serve(vc).await], &top);
        let report = env.apply(ApplyOptions { preserve_entries, ..Default::default() }).await;
        assert!(report.accepted.contains_key(&keys[6]), "{:?}", report.errors);
    }
}

// Keys are grouped by the exact clients that list them, named in --vc order
#[tokio::test]
async fn the_slashing_alarm_keeps_distinct_holder_sets_apart() {
    let (pair_key, trio_key) = (random_key(), random_key());
    let both = [pair_key.clone(), trio_key.clone()];
    let mut pair = [serve(MockVc::holding(&both)).await, serve(MockVc::holding(&both)).await];
    // Against URL order, which must not reorder them
    pair.sort_by(|a, b| b.cmp(a));
    let [first, second] = pair;
    let third = serve(MockVc::holding(std::slice::from_ref(&trio_key))).await;

    let env = TestEnv::new(&both, &[first.clone(), second.clone(), third.clone()]);
    let report = env.apply(ApplyOptions::default()).await;
    let alarm = |clients: String, key: &str| {
        format!(
            "keys held by more than one validator client ({clients}): 1; each is a slashing \
             risk, so keep it on one\n  {key}"
        )
    };
    assert_eq!(report.errors, [
        alarm(format!("{first}/, {second}/"), &pair_key),
        alarm(format!("{first}/, {second}/, {third}/"), &trio_key),
    ]);
}

#[tokio::test]
async fn no_client_listing_a_key_is_an_error() {
    let url = serve(MockVc::holding(&[])).await;
    let env = TestEnv::with_relays(&[random_key()], &[url]);
    let report = env.apply(ApplyOptions::default()).await;
    let expected = "no validator client lists a key".to_string();
    assert!(report.errors.contains(&expected), "{:?}", report.errors);
}

// The alarm covers a key outside every mux, which here gets no write
#[tokio::test]
async fn a_key_outside_every_mux_two_clients_list_raises_the_slashing_alarm() {
    let (mux_key, outside) = (random_key(), random_key());
    let vc1 = MockVc::holding(&[mux_key.clone(), outside.clone()]);
    let vc2 = MockVc::holding(std::slice::from_ref(&outside));
    let (url1, url2) = (serve(vc1).await, serve(vc2).await);

    let env = TestEnv::new(std::slice::from_ref(&mux_key), &[url1, url2]);
    let report = env.apply(ApplyOptions::default()).await;
    assert!(
        report
            .errors
            .iter()
            .any(|err| err.contains("held by more than one validator client") &&
                err.contains(&outside)),
        "{:?}",
        report.errors
    );
}

// A key held by two clients, here as a keystore on one and through a remote
// signer on the other, is a slashing risk. The remote-signer key is listed, so
// that client is probed rather than written to blind
#[tokio::test]
async fn a_key_two_clients_list_raises_the_slashing_alarm() {
    let key = random_key();
    let vc1 = MockVc::holding(std::slice::from_ref(&key));
    let vc2 = MockVc { remotekeys: Some(vec![key.clone()]), ..MockVc::holding(&[]) };
    let (url1, url2) = (serve(vc1).await, serve(vc2).await);

    let env = TestEnv::new(std::slice::from_ref(&key), &[url1.clone(), url2.clone()]);
    let report = env.apply(ApplyOptions::default()).await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    // The alarm names both clients
    let alarm = format!("held by more than one validator client ({url1}/, {url2}/)");
    assert!(report.errors.iter().any(|err| err.contains(&alarm)), "{:?}", report.errors);
}

// A second client that lists the key but refuses the write still holds it
#[tokio::test]
async fn apply_duplicate_holder_that_refuses_raises_slashing_alarm() {
    for status in [403, 400] {
        let key = random_key();
        let vc1 = MockVc::holding(std::slice::from_ref(&key));
        let mut vc2 = MockVc::holding(std::slice::from_ref(&key));
        vc2.post_status.insert(key.clone(), status);
        let (url1, url2) = (serve(vc1).await, serve(vc2).await);

        let env = TestEnv::new(std::slice::from_ref(&key), &[url1, url2]);
        let report = env.apply(ApplyOptions::default()).await;
        assert!(
            report.errors.iter().any(|err| err.contains("a slashing risk")),
            "{status}: {:?}",
            report.errors
        );
    }
}

// A refused write is one error, quoting the keymanager's message, such as
// Lodestar's refusal of a cap
#[tokio::test]
async fn apply_post_refusals() {
    for (status, expected) in [
        (400, r#"400 Bad Request: "refused with 400""#),
        (403, r#"403 Forbidden: "refused with 403""#),
        (404, "but answered 404 to its write"),
    ] {
        let key = random_key();
        let mut vc = MockVc::holding(std::slice::from_ref(&key));
        vc.post_status.insert(key.clone(), status);
        let url = serve(vc).await;

        let env = TestEnv::new(std::slice::from_ref(&key), &[url]);
        let report = env.apply(ApplyOptions::default()).await;
        assert!(
            report.errors.iter().any(|msg| msg.contains(expected)),
            "{status}: {:?}",
            report.errors
        );
        assert_eq!(report.errors.len(), 1, "{status}: {:?}", report.errors);
    }
}

// A 403 before any write lands, as Lodestar answers every write under
// --proposerSettingsFile, is one error and stops writes to that client; after
// a write lands, a 403 is that key's error
#[tokio::test]
async fn a_403_before_any_write_stops_the_client() {
    let mut keys = [random_key(), random_key(), random_key()];
    keys.sort();
    // From `first`, the keys are in the mux; keys[0] outside it has no config,
    // so a 403 on keys[1] still comes before any write lands
    for (first, refused, posts, stopped) in [(0, 0, 1, true), (0, 1, 3, false), (1, 1, 1, true)] {
        let mut vc = MockVc::holding(&keys);
        vc.post_status.insert(keys[refused].clone(), 403);
        let env = TestEnv::new(&keys[first..], &[serve(vc.clone()).await]);
        let report = env.apply(ApplyOptions::default()).await;
        assert_eq!(vc.posts().len(), posts, "{refused}");
        let stop = report.errors.iter().any(|err| err.contains("answered 403 before any write"));
        assert_eq!(stop, stopped, "{:?}", report.errors);
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        assert!(report.errors[0].contains("refused with 403"), "{:?}", report.errors);
        assert_eq!(report.unwritten, if stopped { 3 - first } else { 1 });
    }
}

// --preserve-entries writes at most the 64 entries a builder config holds; the
// projection here has two
#[tokio::test]
async fn preserve_entries_refuses_more_than_64_entries() {
    for (kept, refused) in [(62, false), (63, true)] {
        let key = random_key();
        let mut vc = MockVc::holding(std::slice::from_ref(&key));
        let others: Vec<_> = (0..kept)
            .map(|i| third_party_entry(&format!("https://builder-{i}.example.com"), "0xbb"))
            .collect();
        vc.stored.insert(key.clone(), serde_json::json!({ "builders": others }));
        let url = serve(vc.clone()).await;

        let env = TestEnv::new(std::slice::from_ref(&key), &[url]);
        let report = env.apply(ApplyOptions { preserve_entries: true, ..Default::default() }).await;
        let errored = report.errors.iter().any(|err| err.contains("would keep 65 builder entries"));
        assert_eq!(errored, refused, "{kept}: {:?}", report.errors);
        assert_eq!(vc.posts().is_empty(), refused, "{kept}");
    }
}

// --preserve-entries keeps stored entries at other URLs, after the projected
// ones. One at the advertised URL, here with the trailing slash a client may
// add, is replaced, and the key-level values stay the projection's
#[tokio::test]
async fn preserve_entries_keeps_only_entries_at_other_urls() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    let env = TestEnv::new(std::slice::from_ref(&key), &[]);
    let projected: serde_json::Value = serde_json::from_str(&env.projected(&key).await).unwrap();
    let mut stored = projected.clone();
    stored["min_bid"] = serde_json::json!("1");
    let third_party = third_party_entry("https://third-party.example.com", "0xc0ffee");
    let builders = stored["builders"].as_array_mut().unwrap();
    builders.push(third_party.clone());
    // "cb.example.com"
    builders.push(third_party_entry("https://cb.example.com/", "0x63622e6578616d706c652e636f6d"));
    vc.stored.insert(key.clone(), stored);
    let url = serve(vc.clone()).await;

    let env = TestEnv::new(std::slice::from_ref(&key), &[url]);
    let report = env.apply(ApplyOptions { preserve_entries: true, ..Default::default() }).await;
    assert!(report.errors.is_empty(), "{:?}", report.errors);

    let mut expected = projected;
    expected["builders"].as_array_mut().unwrap().push(third_party);
    let posts = vc.posts();
    let posted: serde_json::Value = serde_json::from_str(&posts[0].1).unwrap();
    assert_eq!(posted, expected);
}

// Under --preserve-entries, a key whose GET answers 404 has nothing to keep, so
// it gets the projection rather than being skipped
#[tokio::test]
async fn preserve_entries_writes_a_key_whose_get_is_404() {
    let mut keys = [random_key(), random_key()];
    keys.sort();
    let [probed, missing] = keys;
    let mut vc = MockVc::holding(&[probed.clone(), missing.clone()]);
    vc.get_status_for.insert(missing.clone(), 404);
    let url = serve(vc.clone()).await;

    let env = TestEnv::new(&[probed, missing.clone()], &[url]);
    let report = env.apply(ApplyOptions { preserve_entries: true, ..Default::default() }).await;
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(
        vc.posts().contains(&(missing.clone(), env.projected(&missing).await)),
        "{:?}",
        vc.posts()
    );
}

// A key outside every mux gets the `[[relays]]` builder config, a mux key its
// mux's
#[tokio::test]
async fn a_key_outside_every_mux_gets_the_relays_config() {
    let (in_mux, outside) = (random_key(), random_key());
    let vc = MockVc::holding(&[in_mux.clone(), outside.clone()]);
    let url = serve(vc.clone()).await;

    let env = TestEnv::with_relays(std::slice::from_ref(&in_mux), &[url]);
    let report = env.apply(ApplyOptions::default()).await;
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    // auth data is each relay's hex hostname: default-relay and relay-a
    let (default_relay, relay_a) = (
        "0x64656661756c742d72656c61792e6578616d706c652e636f6d",
        "0x72656c61792d612e6578616d706c652e636f6d",
    );
    let posts = vc.posts();
    let body = |key: &str| &posts.iter().find(|(pk, _)| pk == key).unwrap().1;
    assert!(body(&outside).contains(default_relay) && !body(&outside).contains(relay_a));
    assert!(body(&in_mux).contains(relay_a) && !body(&in_mux).contains(default_relay));
}

// Lodestar refuses a cap above 0 without its flag, for every key alike, so
// apply reports it once, names the fix and writes no further capped key there.
// A key with cap 0 is still written
#[tokio::test]
async fn a_lodestar_cap_refusal_stops_capped_writes_to_that_client() {
    // the capped keys sort around the uncapped mux key
    let mut keys = [random_key(), random_key(), random_key()];
    keys.sort();
    let [capped, mux_key, capped_later] = keys.clone();
    let vc = MockVc { lodestar_cap_refusal: true, ..MockVc::holding(&keys) };
    let url = serve(vc.clone()).await;

    let top = format!(
        "max_execution_payment_gwei = 0\n[[relays]]\n\
         url = \"https://{RELAY_PK_B}@default-relay.example.com\"\n\
         max_execution_payment_gwei = \"unclamped\"\n"
    );
    let env = TestEnv::build(std::slice::from_ref(&mux_key), &[url], &top);
    let report = env.apply(ApplyOptions::default()).await;
    let refusals: Vec<_> =
        report.errors.iter().filter(|err| err.contains("restart it with that flag")).collect();
    assert_eq!(refusals.len(), 1, "{:?}", report.errors);
    let posted: Vec<_> = vc.posts().into_iter().map(|(pk, _)| pk).collect();
    assert_eq!(posted, [capped, mux_key.clone()]);
    assert!(!posted.contains(&capped_later));
    assert_eq!(report.accepted.into_keys().collect::<Vec<_>>(), [mux_key]);
    assert_eq!(report.unwritten, 2);
}

// A key whose stored config cannot be read is not written: --preserve-entries
// would erase the entries it keeps
#[tokio::test]
async fn unreadable_config_is_not_written() {
    // apply probes the lowest key, so the unreadable one sorts after it
    let mut keys = [random_key(), random_key()];
    keys.sort();
    let unreadable = keys[1].clone();
    let mut vc = MockVc::holding(&keys);
    vc.get_status_for.insert(unreadable.clone(), 500);
    let url = serve(vc.clone()).await;

    let env = TestEnv::new(&keys, &[url]);
    let report = env.apply(ApplyOptions { preserve_entries: true, ..Default::default() }).await;
    let expected = "preserve-entries GET";
    assert!(report.errors.iter().any(|err| err.contains(expected)), "{:?}", report.errors);
    assert!(vc.posts().iter().all(|(pk, _)| pk != &unreadable));
}

// A remote-key listing that fails, other than with the 404 of a client without
// remote signing, skips the client rather than dropping its remote keys
#[tokio::test]
async fn remotekeys_failure_skips_the_vc() {
    for (status, expected) in [
        (500, "key listing failed: remotekeys: 500"),
        (200, "key listing failed: invalid remotekeys response: error decoding"),
    ] {
        let key = random_key();
        let vc = MockVc {
            remotekeys_status: Some(status),
            ..MockVc::holding(std::slice::from_ref(&key))
        };
        let url = serve(vc.clone()).await;

        let env = TestEnv::new(std::slice::from_ref(&key), &[url]);
        let report = env.apply(ApplyOptions::default()).await;
        assert!(report.errors.iter().any(|err| err.contains(expected)), "{:?}", report.errors);
        assert!(vc.posts().is_empty());
    }
}

// A failing client does not stop the run, and the keys it lists still count as
// held, so a key it shares with the next client raises the slashing alarm
#[tokio::test]
async fn a_failing_client_does_not_stop_the_others() {
    for (supports_builder_config, get_status, expected) in [
        (false, None, "no builder_config support"),
        (true, Some(500), "builder_config probe failed"),
    ] {
        let key = random_key();
        let broken = MockVc {
            supports_builder_config,
            get_status,
            ..MockVc::holding(std::slice::from_ref(&key))
        };
        let holder = MockVc::holding(std::slice::from_ref(&key));
        let (broken_url, holder_url) = (serve(broken).await, serve(holder).await);

        let env = TestEnv::new(std::slice::from_ref(&key), &[broken_url, holder_url]);
        let report = env.apply(ApplyOptions::default()).await;
        assert_eq!(report.accepted.get(&key).map(Vec::len), Some(1), "{expected}");
        assert_eq!(report.unwritten, 1, "{expected}");
        assert!(report.errors.iter().any(|err| err.contains(expected)), "{:?}", report.errors);
        assert!(
            report.errors.iter().any(|err| err.contains("a slashing risk")),
            "{:?}",
            report.errors
        );
    }
}

// The bearer token goes in cleartext to a client that is neither HTTPS nor
// loopback, so apply warns
#[tokio::test]
async fn warns_on_a_cleartext_token_to_a_remote_client() {
    for (url, warns) in [
        ("http://vc.example.com:5062", true),
        ("http://10.0.0.5:5062", true),
        ("https://vc.example.com:5062", false),
        ("http://localhost:5062", false),
        ("http://[::ffff:127.0.0.1]:5062", false),
        ("http://[::1]:5062", false),
    ] {
        let env = TestEnv::new(&[random_key()], &[url.to_string()]);
        // without a token file, setup fails before any request goes out
        std::fs::remove_file(env.token_file.path()).unwrap();
        let report = env.apply(ApplyOptions::default()).await;
        let warned = report.warnings.iter().any(|w| w.contains("cleartext"));
        assert_eq!(warned, warns, "{url}: {:?}", report.warnings);
    }
}

// print writes only the document to stdout: each mux's config once with its
// keys, and the `[[relays]]` config as the default. Its counts and the
// Lodestar note go to stderr, and it contacts no client
#[tokio::test]
async fn cli_print_contacts_no_client() {
    let key = random_key();
    let vc = MockVc::holding(std::slice::from_ref(&key));
    let url = serve(vc.clone()).await;

    let env = TestEnv::with_relays(std::slice::from_ref(&key), &[url]);
    let out = env.print().await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mux = &printed["muxes"]["mux1"];
    let json = |text: String| serde_json::from_str::<serde_json::Value>(&text).unwrap();
    assert_eq!(mux["config"], json(env.projected(&key).await));
    assert_eq!(mux["keys"], serde_json::json!([key]));
    assert_eq!(mux["fetched_keys"], serde_json::json!([]));
    assert_eq!(printed["default"], json(env.projected(&random_key()).await));
    assert_eq!(printed["advertised_url"], env.targets.advertised_url);
    assert_eq!(printed["version"], 1);
    assert!(stderr.contains("mux mux1: 1 keys"), "{stderr}");
    assert!(stderr.contains("NOTE: the builder config sets a max_execution_payment above 0"));
    assert!(out.stdout.ends_with(b"}\n"));
    assert!(vc.posts().is_empty());

    // Without [[relays]] the default is null, so other keys are left alone, and
    // without a cap above 0 there is no note
    let env = TestEnv::build(std::slice::from_ref(&key), &[], "max_execution_payment_gwei = 0\n");
    let out = env.print().await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(printed["default"].is_null(), "{printed}");
    assert!(!stderr.contains("NOTE:"), "{stderr}");
}

// print exits 2 on an --advertised-url apply would refuse, and 1 when it
// cannot write the document, such as to a closed pipe
#[tokio::test]
async fn cli_print_exit_codes() {
    let env = TestEnv::with_relays(&[random_key()], &[]);
    let print = |advertised_url: &str| {
        let mut cmd = builder_config("print");
        cmd.arg("--config").arg(env.dir.path().join("config.toml"));
        cmd.arg("--advertised-url").arg(advertised_url);
        cmd
    };
    let out = print("localhost:18550").output().await.unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("is not an http(s) URL"), "{stderr}");

    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut cmd = print(&env.targets.advertised_url);
    cmd.stdout(writer).stderr(std::process::Stdio::piped());
    let out = cmd.spawn().unwrap().wait_with_output().await.unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("ERROR: could not write the document"), "{stderr}");
}

// A key only a loader lists is printed under fetched_keys, and apply --from
// counts one no client holds in a warning, as apply from the config does
#[tokio::test]
async fn print_and_apply_from_keep_fetched_keys_apart() {
    let (held, unheld) = (random_key(), random_key());
    let body = format!(r#"["{held}", "{unheld}"]"#);
    let app = Router::new().route("/keys", get(move || async move { body }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let vc = MockVc::holding(std::slice::from_ref(&held));
    let env = TestEnv::new(&[random_key()], &[serve(vc.clone()).await]);
    let cfg = format!(
        "chain = \"Holesky\"\n[pbs]\n[[mux]]\nid = \"m\"\nloader = {{ url = \"http://{addr}/keys\" }}\n\
         [[mux.relays]]\nurl = \"https://{RELAY_PK_A}@relay-a.example.com\"\n"
    );
    std::fs::write(env.dir.path().join("config.toml"), cfg).unwrap();
    let printed = env.print().await.stdout;
    let mux = &serde_json::from_slice::<serde_json::Value>(&printed).unwrap()["muxes"]["m"];
    let mut fetched = [held.clone(), unheld];
    fetched.sort();
    assert_eq!(mux["keys"], serde_json::json!([]));
    assert_eq!(mux["fetched_keys"], serde_json::json!(fetched));

    let path = env.dir.path().join("printed.json");
    std::fs::write(&path, &printed).unwrap();
    let out = env.apply_cli(&["--from", path.to_str().unwrap()]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    let warning = "WARN: keys a URL or registry loader lists that no validator client holds: 1";
    assert!(stdout.contains(warning), "{stdout}");
    assert_eq!(vc.posts().into_iter().map(|(key, _)| key).collect::<Vec<_>>(), [held]);
}

// Applying the printed document writes what applying the config writes, from
// a file or from stdin
#[tokio::test]
async fn cli_apply_from_a_printed_document_writes_what_apply_config_writes() {
    let (mux_key, other) = (random_key(), random_key());
    for stdin in [false, true] {
        let from_config = MockVc::holding(&[mux_key.clone(), other.clone()]);
        let from_print = MockVc::holding(&[mux_key.clone(), other.clone()]);
        let mut env =
            TestEnv::with_relays(std::slice::from_ref(&mux_key), &[
                serve(from_config.clone()).await
            ]);
        assert!(env.apply_cli(&[]).await.status.success());

        let printed = env.print().await.stdout;
        let path = env.dir.path().join("printed.json");
        std::fs::write(&path, &printed).unwrap();
        env.targets.vcs[0].url = serve(from_print.clone()).await.parse().unwrap();
        let out = if stdin {
            let mut cmd = env.command(&["--from", "-"]);
            cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut input, &printed).await.unwrap();
            drop(input);
            child.wait_with_output().await.unwrap()
        } else {
            env.apply_cli(&["--from", path.to_str().unwrap()]).await
        };
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let sorted = |mut posts: Vec<(String, String)>| {
            posts.sort();
            posts
        };
        assert_eq!(sorted(from_print.posts()), sorted(from_config.posts()), "stdin {stdin}");
    }
}

// apply --from refuses, before contacting a client, a document for another
// URL or version, with an entry elsewhere, auth data that is not hex, a field
// print does not write, or a key in two muxes or one that is not a validator
// key
#[tokio::test]
async fn cli_apply_from_refuses_a_mismatched_document() {
    let key = random_key();
    let vc = MockVc::holding(std::slice::from_ref(&key));
    let env = TestEnv::with_relays(std::slice::from_ref(&key), &[serve(vc.clone()).await]);
    let printed: serde_json::Value = serde_json::from_slice(&env.print().await.stdout).unwrap();
    let edited = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut printed = printed.clone();
        edit(&mut printed);
        printed
    };
    for (document, expected) in [
        (edited(&|p| p["advertised_url"] = "http://other:18550".into()), "not --advertised-url"),
        (
            edited(&|p| {
                let url = format!("{}/", p["advertised_url"].as_str().unwrap());
                p["advertised_url"] = url.into();
            }),
            "not --advertised-url",
        ),
        (
            edited(&|p| p["muxes"]["mux1"]["config"]["builders"][0]["auth_data"] = "cb".into()),
            "not 0x-prefixed hex",
        ),
        (
            edited(&|p| {
                p["muxes"]["mux1"]["config"]["builders"][0]["max_execution_paymnet"] = "0".into()
            }),
            "a field `print` does not write",
        ),
        (edited(&|p| p["version"] = 2.into()), "is version 2"),
        (edited(&|p| p["version"] = 0.into()), "is version 0"),
        // The second entry, so every entry is checked
        (
            edited(&|p| p["muxes"]["mux1"]["config"]["builders"][1]["url"] = "http://evil".into()),
            "has an entry at http://evil",
        ),
        (
            edited(&|p| p["default"]["builders"][0]["url"] = "http://evil".into()),
            "default's config has an entry at http://evil",
        ),
        // Written as is, so a URL that only parses the same is refused too
        (
            edited(&|p| {
                let url = format!("{}/", p["advertised_url"].as_str().unwrap());
                p["muxes"]["mux1"]["config"]["builders"][0]["url"] = url.into();
            }),
            "has an entry at",
        ),
        (
            edited(&|p| {
                p["muxes"]["mux2"] = p["muxes"]["mux1"].clone();
                p["muxes"]["mux2"]["keys"] =
                    serde_json::json!([key.to_uppercase().replace("0X", "0x")]);
            }),
            "is in both mux mux1 and mux mux2",
        ),
        (
            edited(&|p| p["muxes"]["mux1"]["keys"] = serde_json::json!(["0x1234"])),
            "is not a validator key",
        ),
        (edited(&|p| p["extra"] = 1.into()), "is not a printed document"),
    ] {
        let path = env.dir.path().join("printed.json");
        std::fs::write(&path, document.to_string()).unwrap();
        let out = env.apply_cli(&["--from", path.to_str().unwrap()]).await;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{expected}: {stderr}");
        assert!(stderr.contains(expected), "{expected}: {stderr}");
    }
    assert!(vc.posts().is_empty());
}

// --config defaults to CB_CONFIG, and --from wins over it
#[tokio::test]
async fn cli_apply_reads_cb_config_and_from_wins_over_it() {
    let key = random_key();
    let vc = MockVc::holding(std::slice::from_ref(&key));
    let env = TestEnv::new(std::slice::from_ref(&key), &[serve(vc.clone()).await]);
    let mut cmd = builder_config("apply");
    cmd.env("CB_CONFIG", env.dir.path().join("config.toml"));
    cmd.arg("--advertised-url").arg(&env.targets.advertised_url);
    for vc in &env.targets.vcs {
        cmd.arg("--vc").arg(format!("{}={}", vc.url, vc.token_path.display()));
    }
    assert!(cmd.output().await.unwrap().status.success());

    let path = env.dir.path().join("printed.json");
    std::fs::write(&path, env.print().await.stdout).unwrap();
    let mut cmd = env.command(&["--from", path.to_str().unwrap()]);
    cmd.env("CB_CONFIG", "/nonexistent.toml");
    let out = cmd.output().await.unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(vc.posts().len(), 2);
}

// The loaders' own warnings reach stderr, here for a keys URL over HTTP, even
// under a RUST_LOG meant for another program, and count in the tally; each
// mux's key count is printed
#[tokio::test]
async fn cli_shows_the_loaders_warnings() {
    let key = random_key();
    let body = format!(r#"["{key}"]"#);
    let app = Router::new().route("/keys", get(move || async move { body }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let env = TestEnv::new(&[random_key()], &[serve(MockVc::holding(&[key])).await]);
    let cfg = format!(
        "chain = \"Holesky\"\n[pbs]\n[[mux]]\nid = \"m\"\nloader = {{ url = \"http://{addr}/keys\" }}\n\
         [[mux.relays]]\nurl = \"https://{RELAY_PK_A}@relay-a.example.com\"\n"
    );
    std::fs::write(env.dir.path().join("config.toml"), cfg).unwrap();
    for rust_log in
        [None, Some(""), Some("lighthouse=debug"), Some("info"), Some("error"), Some("off")]
    {
        let mut cmd = env.command(&[]);
        match rust_log {
            Some(rust_log) => cmd.env("RUST_LOG", rust_log),
            None => cmd.env_remove("RUST_LOG"),
        };
        let out = cmd.output().await.unwrap();
        let (stdout, stderr) =
            (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "{rust_log:?}: {stderr}");
        assert!(stderr.contains("is insecure"), "{rust_log:?}: {stderr}");
        assert!(!stderr.contains('\u{1b}'), "ANSI codes on a piped stderr: {stderr:?}");
        assert!(stdout.contains("mux m: 1 keys"), "{stdout}");
        assert!(stdout.contains("; 0 errors, 1 warnings"), "{stdout}");
    }
}

// A sidecar can run before its client has keys: with --partial that is a
// warning, not a failure
#[tokio::test]
async fn partial_allows_a_client_with_no_keys() {
    let env = TestEnv::with_relays(&[random_key()], &[serve(MockVc::holding(&[])).await]);
    for (args, code) in [(&[][..], 1), (&["--partial"][..], 0)] {
        let out = env.apply_cli(args).await;
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {stdout}");
    }
    let out = env.apply_cli(&["--partial"]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("WARN: no validator client given lists a key"), "{stdout}");
}

// A reader that stops early, such as `| head -1`, closes stdout, and the
// writes still finish
#[tokio::test]
async fn a_closed_stdout_does_not_stop_the_writes() {
    use tokio::io::AsyncBufReadExt;

    let keys: Vec<String> = (0..50).map(|_| random_key()).collect();
    let vc = MockVc::holding(&keys);
    let env = TestEnv::new(&keys, &[serve(vc.clone()).await]);
    let mut cmd = env.command(&[]);
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    stdout.read_line(&mut first).await.unwrap();
    assert!(first.starts_with("mux mux1: 50 keys"), "{first}");
    drop(stdout);
    assert_eq!(child.wait().await.unwrap().code(), Some(0));
    assert_eq!(vc.posts().len(), 50);
}

// Nor does a closed stderr, which the errors go to; the tally counts the keys
// of a client that could not take them
#[tokio::test]
async fn a_closed_stderr_does_not_stop_the_writes() {
    let keys: Vec<String> = (0..5).map(|_| random_key()).collect();
    let vc = MockVc::holding(&keys[..3]);
    let unsupported = MockVc { supports_builder_config: false, ..MockVc::holding(&keys[3..]) };
    let env = TestEnv::new(&keys, &[serve(unsupported).await, serve(vc.clone()).await]);
    let closed_stderr = || {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        writer
    };
    let mut cmd = env.command(&[]);
    cmd.stdout(std::process::Stdio::piped()).stderr(closed_stderr());
    let out = cmd.spawn().unwrap().wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert_eq!(vc.posts().len(), 3);
    assert!(stdout.contains("done: 3 keys written, 2 not written, on 1 of 2"), "{stdout}");

    // A run that stops before contacting a client still exits 2
    let mut cmd = TestEnv::new(&keys, &[]).command(&[]);
    cmd.stdout(std::process::Stdio::null()).stderr(closed_stderr());
    assert_eq!(cmd.status().await.unwrap().code(), Some(2));
}

#[tokio::test]
async fn cli_refuses_a_config_with_nothing_to_write() {
    let env = TestEnv::new(&[random_key()], &[serve(MockVc::holding(&[])).await]);
    std::fs::write(env.dir.path().join("config.toml"), "chain = \"Holesky\"\n[pbs]\n").unwrap();
    let out = env.print().await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("ERROR: nothing to write"), "{stderr}");
}

// Bad flags and unreadable token files stop the run with exit 2 before any
// client is contacted
#[tokio::test]
async fn cli_refuses_bad_targets() {
    let env = TestEnv::new(&[random_key()], &[]);
    let vc = format!("http://127.0.0.1:1={}", env.token_file.path().display());
    let empty = tempfile::NamedTempFile::new().unwrap();
    let empty = format!("http://127.0.0.1:2={}", empty.path().display());
    let cb = "http://cb.example.com";
    for (args, expected) in [
        (vec!["--advertised-url", cb], "no validator client given"),
        (vec!["--advertised-url", "localhost:18550", "--vc", &vc], "is not an http(s) URL"),
        (vec!["--advertised-url", cb, "--vc", &vc, "--vc", &vc], "given twice"),
        (vec!["--advertised-url", cb, "--vc", "localhost:1=/t"], "not an http(s) URL"),
        (vec!["--advertised-url", cb, "--vc", "http://127.0.0.1:1=~/t"], "use $HOME"),
        // A token file after the first is read too
        (vec!["--advertised-url", cb, "--vc", &vc, "--vc", &empty], "is empty"),
        (
            vec![
                "--advertised-url",
                cb,
                "--vc",
                "http://localhost:1=/t",
                "--vc",
                "http://127.0.0.1:1=/t",
            ],
            "one validator client given twice",
        ),
    ] {
        let out = builder_config("apply")
            .arg("--config")
            .arg(env.dir.path().join("config.toml"))
            .args(&args)
            .output()
            .await
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }
}

// apply exits 1 on any error, such as a mux key no client lists, which
// --partial turns into a warning. It prints where each key's config came
// from, a line per client and a closing tally
#[tokio::test]
async fn cli_exit_code() {
    for (held, args, code) in
        [(true, &[][..], 0), (false, &[][..], 1), (false, &["--partial"][..], 0)]
    {
        let key = random_key();
        let other = random_key();
        let url = serve(MockVc::holding(&[if held { key.clone() } else { other.clone() }])).await;

        let env = TestEnv::with_relays(std::slice::from_ref(&key), std::slice::from_ref(&url));
        let out = env.apply_cli(args).await;
        let (stdout, stderr) =
            (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.status.code(), Some(code), "{args:?}: {stderr}");
        let unheld = "keys in a mux that no validator client lists";
        assert_eq!(stderr.contains(unheld), code == 1, "{stderr}");
        let partial = "WARN: keys in a mux that no validator client given holds: 1";
        assert_eq!(stdout.contains(partial), !args.is_empty(), "{stdout}");
        let (accepted, source) = if held { (&key, "mux mux1") } else { (&other, "[[relays]]") };
        assert!(stdout.contains(&format!("accepted: {accepted} on {url}/ ({source})")), "{stdout}");
        assert!(stdout.contains(&format!("{url}/: 1 keys listed, 1 written")), "{stdout}");
        let errors = usize::from(code == 1);
        assert!(
            stdout.contains(&format!(
                "done: 1 keys written, 0 not written, on 1 of 1 validator clients; {errors} errors"
            )),
            "{stdout}"
        );
    }
}

// A client written to gets a line counting only the keys with a config to
// write, here not the key in no mux. The tally counts each write, so a key on
// two clients (a slashing error) counts twice, and counts the clients written
// to out of every client given. The Lodestar note is for print only
#[tokio::test]
async fn cli_prints_a_line_per_client_and_a_tally() {
    let mut keys = [random_key(), random_key(), random_key()];
    keys.sort();
    let [a, b, c] = keys.clone();
    let (vc1, vc2) = (MockVc::holding(&[a, c.clone(), random_key()]), MockVc::holding(&[b, c]));
    let urls = [serve(vc1).await, serve(vc2).await, serve(MockVc::holding(&[])).await];

    let env = TestEnv::new(&keys, &urls);
    let out = env.apply_cli(&[]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    for line in [
        format!("{}/: 3 keys listed, 2 written\n", urls[0]),
        format!("{}/: 2 keys listed, 2 written\n", urls[1]),
        format!("WARN: {}/: lists no validator keys\n", urls[2]),
        "done: 4 keys written, 0 not written, on 2 of 3 validator clients; 1 errors, 2 warnings\n"
            .to_string(),
    ] {
        assert!(stdout.contains(&line), "{line}{stdout}");
    }
    assert!(!stdout.contains("NOTE:"), "{stdout}");
}
