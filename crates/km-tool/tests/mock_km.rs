//! Integration tests against a mock keymanager server (axum): auth,
//! preflight, POST outcome handling, prune body shape, dry-run/emit network
//! silence, and canonical check comparison.

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
use cb_km_tool::{
    Overlay, ProjectionInput,
    apply::{ApplyOptions, run_apply},
    check::{Tier, run_check},
    project,
};

const RELAY_PK_A: &str = "0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2";
const RELAY_PK_B: &str = "0xa119589bb33ef52acbb8116832bec2b58fca590fe5c85eac5d3230b44d5bc09fe73ccd21f88eab31d6de16194d17782e";
const TOKEN: &str = "test-token";

#[derive(Clone, Default)]
struct MockVc {
    /// keys this VC holds (lowercase hex)
    keystores: Vec<String>,
    /// whether the VC serves the #88 builder_config route
    supports_builder_config: bool,
    /// stored docs returned on GET (raw JSON, so tests control hex case and
    /// entry order)
    stored: HashMap<String, serde_json::Value>,
    /// POST status override per key (default: 202 when held, else 404)
    post_status: HashMap<String, u16>,
    /// blanket GET builder_config status override (e.g. 500)
    get_status: Option<u16>,
    /// recorded (pubkey, raw body) of every builder_config POST
    posts: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockVc {
    fn holding(keys: &[String]) -> Self {
        Self { keystores: keys.to_vec(), supports_builder_config: true, ..Default::default() }
    }

    fn posts(&self) -> Vec<(String, String)> {
        self.posts.lock().unwrap().clone()
    }
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
    let data: Vec<_> =
        vc.keystores.iter().map(|pk| serde_json::json!({ "validating_pubkey": pk })).collect();
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
    if let Some(status) = vc.get_status {
        return (StatusCode::from_u16(status).unwrap(), "overridden").into_response();
    }
    if !vc.supports_builder_config || !vc.keystores.contains(&pubkey) {
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
    if !vc.supports_builder_config {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    vc.posts.lock().unwrap().push((pubkey.clone(), body));
    let status = vc
        .post_status
        .get(&pubkey)
        .copied()
        .unwrap_or_else(|| if vc.keystores.contains(&pubkey) { 202 } else { 404 });
    StatusCode::from_u16(status).unwrap().into_response()
}

/// Serves a mock VC on an ephemeral port, returning its base URL.
async fn serve(vc: MockVc) -> String {
    let app = Router::new()
        .route("/eth/v1/keystores", get(keystores))
        .route("/eth/v1/validator/{pubkey}/builder_config", get(get_config).post(post_config))
        .with_state(vc);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn random_key() -> String {
    cb_common::types::BlsSecretKey::random().public_key().as_hex_string()
}

fn config_toml(keys: &[String]) -> String {
    let keys = keys.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ");
    format!(
        r#"
chain = "Holesky"

[pbs]
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

struct TestEnv {
    input: ProjectionInput,
    overlay: Overlay,
    _token_file: tempfile::NamedTempFile,
}

fn env_for(keys: &[String], vc_urls: &[String]) -> TestEnv {
    let token_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(token_file.path(), format!("{TOKEN}\n")).unwrap();
    let vcs = vc_urls
        .iter()
        .map(|url| {
            format!("[[vcs]]\nurl = \"{url}\"\ntoken_path = \"{}\"\n", token_file.path().display())
        })
        .collect::<Vec<_>>()
        .join("\n");
    let overlay =
        Overlay::parse_str(&format!("advertised_url = \"https://cb.example.com\"\n{vcs}")).unwrap();
    let input = ProjectionInput::parse_str(&config_toml(keys)).unwrap();
    TestEnv { input, overlay, _token_file: token_file }
}

#[tokio::test]
async fn apply_partitioned_keys_accepted_once_each() {
    let (k1, k2) = (random_key(), random_key());
    let vc1 = MockVc::holding(std::slice::from_ref(&k1));
    let vc2 = MockVc::holding(std::slice::from_ref(&k2));
    let (url1, url2) = (serve(vc1.clone()).await, serve(vc2.clone()).await);

    let env = env_for(&[k1.clone(), k2.clone()], &[url1, url2]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();

    assert!(report.ok(), "{:?}", report.errors);
    assert_eq!(report.accepted.get(&k1).map(Vec::len), Some(1));
    assert_eq!(report.accepted.get(&k2).map(Vec::len), Some(1));

    // the accepted POST body is the projected doc
    let posts = vc1.posts();
    let accepted: Vec<_> = posts.iter().filter(|(pk, _)| pk == &k1).collect();
    assert_eq!(accepted.len(), 1);
    let projection = project(&env.input, &env.overlay).unwrap();
    let expected = projection
        .docs
        .iter()
        .find(|(pk, _)| pk.to_string() == k1)
        .map(|(_, doc)| serde_json::to_string(doc).unwrap())
        .unwrap();
    assert_eq!(accepted[0].1, expected);
}

#[tokio::test]
async fn apply_401_reports_preflight_error() {
    let key = random_key();
    let vc = MockVc::holding(std::slice::from_ref(&key));
    let url = serve(vc).await;

    let mut env = env_for(std::slice::from_ref(&key), &[url]);
    // wrong token
    std::fs::write(env._token_file.path(), "wrong-token").unwrap();
    env.overlay = Overlay::parse_str(&format!(
        "advertised_url = \"https://cb.example.com\"\n[[vcs]]\nurl = \"{}\"\ntoken_path = \"{}\"\n",
        env.overlay.vcs[0].url,
        env._token_file.path().display()
    ))
    .unwrap();

    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(!report.ok());
    assert!(report.errors.iter().any(|e| e.contains("keystores preflight failed")));
}

#[tokio::test]
async fn apply_detects_missing_88_support() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    vc.supports_builder_config = false;
    let url = serve(vc).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(!report.ok());
    assert!(
        report.errors.iter().any(|e| e.contains("no builder_config support")),
        "{:?}",
        report.errors
    );
}

#[tokio::test]
async fn apply_probe_transport_failure_is_its_own_error() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    vc.get_status = Some(500);
    let url = serve(vc.clone()).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(!report.ok());
    assert!(
        report.errors.iter().any(|e| e.contains("builder_config probe failed")),
        "{:?}",
        report.errors
    );
    assert!(!report.errors.iter().any(|e| e.contains("no builder_config support")));
    // a failed probe skips the VC: nothing POSTed
    assert!(vc.posts().is_empty());
}

#[tokio::test]
async fn apply_empty_keystore_vc_warns_and_still_posts() {
    let key = random_key();
    let empty_vc = MockVc::holding(&[]);
    let holder_vc = MockVc::holding(std::slice::from_ref(&key));
    let (empty_url, holder_url) = (serve(empty_vc.clone()).await, serve(holder_vc).await);

    let env = env_for(std::slice::from_ref(&key), &[empty_url, holder_url]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    assert!(
        report.warnings.iter().any(|w| w.contains("no keys to probe")),
        "{:?}",
        report.warnings
    );
    // supported-unknown: the empty VC still gets the POST; its 404 answers
    assert_eq!(empty_vc.posts().len(), 1);
    assert_eq!(report.accepted.get(&key).map(Vec::len), Some(1));
}

#[tokio::test]
async fn apply_zero_acceptors_is_an_error() {
    let (projected, other) = (random_key(), random_key());
    // the VC holds a DIFFERENT key: POST of the projected key 404s
    let vc = MockVc::holding(std::slice::from_ref(&other));
    let url = serve(vc).await;

    let env = env_for(std::slice::from_ref(&projected), &[url]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(!report.ok());
    assert!(report.errors.iter().any(|e| e.contains("accepted by NO vc")), "{:?}", report.errors);
    // coverage warning fires for the enumerated-but-unprojected key
    assert!(report.warnings.iter().any(|w| w.contains(&other) && w.contains("unprojected")));
}

#[tokio::test]
async fn apply_duplicate_acceptance_raises_slashing_alarm() {
    let key = random_key();
    let vc1 = MockVc::holding(std::slice::from_ref(&key));
    let vc2 = MockVc::holding(std::slice::from_ref(&key));
    let (url1, url2) = (serve(vc1).await, serve(vc2).await);

    let env = env_for(std::slice::from_ref(&key), &[url1, url2]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(!report.ok());
    assert!(
        report.errors.iter().any(|e| e.contains("DUPLICATE KEY") && e.contains("slashing")),
        "{:?}",
        report.errors
    );
}

#[tokio::test]
async fn apply_403_is_config_file_managed_warning() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    vc.post_status.insert(key.clone(), 403);
    let url = serve(vc).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(
        report.warnings.iter().any(|w| w.contains("config-file-managed")),
        "{:?}",
        report.warnings
    );
    // not accepted anywhere -> still an error overall
    assert!(!report.ok());
}

#[tokio::test]
async fn prune_posts_exactly_empty_object() {
    let (projected, stale) = (random_key(), random_key());
    let vc = MockVc::holding(&[projected.clone(), stale.clone()]);
    let url = serve(vc.clone()).await;

    let env = env_for(std::slice::from_ref(&projected), &[url]);
    let opts = ApplyOptions { prune: true, ..Default::default() };
    let report = run_apply(&env.input, &env.overlay, &opts).await.unwrap();

    let posts = vc.posts();
    let prune_posts: Vec<_> = posts.iter().filter(|(pk, _)| pk == &stale).collect();
    assert_eq!(prune_posts.len(), 1);
    assert_eq!(prune_posts[0].1, "{}");
    assert_eq!(report.pruned.len(), 1);
}

#[tokio::test]
async fn dry_run_and_emit_post_nothing() {
    let key = random_key();
    let vc = MockVc::holding(std::slice::from_ref(&key));
    let url = serve(vc.clone()).await;
    let env = env_for(std::slice::from_ref(&key), &[url]);

    let report =
        run_apply(&env.input, &env.overlay, &ApplyOptions { dry_run: true, ..Default::default() })
            .await
            .unwrap();
    assert!(report.ok());
    assert!(vc.posts().is_empty());

    let emit_dir = tempfile::tempdir().unwrap();
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions {
        emit_dir: Some(emit_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(report.ok());
    assert!(vc.posts().is_empty());
    assert!(emit_dir.path().join(format!("{key}.json")).exists());
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(emit_dir.path().join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["keys"][0]["pubkey"], serde_json::json!(key));
}

/// Our projected doc for `key`, as the JSON value a VC would store.
fn projected_value(env: &TestEnv, key: &str) -> serde_json::Value {
    serde_json::from_str(&projected_string(env, key)).unwrap()
}

/// Our projected doc for `key`, serialized exactly as the tool POSTs it.
fn projected_string(env: &TestEnv, key: &str) -> String {
    let projection = project(&env.input, &env.overlay).unwrap();
    let doc = projection.docs.iter().find(|(pk, _)| pk.to_string() == key).map(|(_, d)| d).unwrap();
    serde_json::to_string(doc).unwrap()
}

fn third_party_entry(url: &str, auth_hex: &str) -> serde_json::Value {
    serde_json::json!({ "url": url, "auth_data": auth_hex, "builder_pubkeys": [RELAY_PK_B] })
}

/// Collects the (url, auth_data) pairs in a POSTed builder_config body.
fn posted_entries(body: &str) -> Vec<(String, String)> {
    let doc: serde_json::Value = serde_json::from_str(body).unwrap();
    doc["builders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (e["url"].as_str().unwrap().to_string(), e["auth_data"].as_str().unwrap().to_string())
        })
        .collect()
}

// (a) Without the flag, a stored third-party entry is IGNORED: the POST body is
// our projection exactly, unchanged from today's full-replace behavior.
#[tokio::test]
async fn without_flag_post_body_is_projection_and_ignores_stored() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    let env = env_for(std::slice::from_ref(&key), &[]);
    let mut stored = projected_value(&env, &key);
    stored["builders"]
        .as_array_mut()
        .unwrap()
        .push(third_party_entry("https://third-party.example.com", "0xc0ffee"));
    vc.stored.insert(key.clone(), stored);
    let url = serve(vc.clone()).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let report = run_apply(&env.input, &env.overlay, &ApplyOptions::default()).await.unwrap();
    assert!(report.ok(), "{:?}", report.errors);

    let posts = vc.posts();
    let posted = posts.iter().find(|(pk, _)| pk == &key).unwrap();
    assert_eq!(posted.1, projected_string(&env, &key));
}

// (b) With the flag, a pre-existing third-party entry survives the apply: the
// POSTed body contains BOTH our projected entries and theirs.
#[tokio::test]
async fn preserve_entries_keeps_third_party_entry() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    let env = env_for(std::slice::from_ref(&key), &[]);
    let mut stored = projected_value(&env, &key);
    stored["builders"]
        .as_array_mut()
        .unwrap()
        .push(third_party_entry("https://third-party.example.com", "0xc0ffee"));
    vc.stored.insert(key.clone(), stored);
    let url = serve(vc.clone()).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let opts = ApplyOptions { preserve_entries: true, ..Default::default() };
    let report = run_apply(&env.input, &env.overlay, &opts).await.unwrap();
    assert!(report.ok(), "{:?}", report.errors);

    let posts = vc.posts();
    let posted = posts.iter().find(|(pk, _)| pk == &key).unwrap();
    let entries = posted_entries(&posted.1);
    // our two projected entries plus the third party's, no more
    assert_eq!(entries.len(), 3, "{entries:?}");
    assert!(
        entries.iter().any(|(u, a)| u == "https://third-party.example.com" && a == "0xc0ffee"),
        "{entries:?}"
    );
    // both of ours (advertised URL) still present
    assert_eq!(entries.iter().filter(|(u, _)| u == "https://cb.example.com").count(), 2);
}

// (c) A stored third-party entry sharing OUR identity (url + auth_data) is
// REPLACED by ours, not duplicated -> no (url, auth_data) collision (no 400).
#[tokio::test]
async fn preserve_entries_collision_is_replaced_not_duplicated() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    let env = env_for(std::slice::from_ref(&key), &[]);
    // stored = a doc whose entries share our identity but carry a foreign
    // pubkey and a VC-resolved boost (simulating a resolved GET of our doc)
    let mut stored = projected_value(&env, &key);
    for entry in stored["builders"].as_array_mut().unwrap() {
        entry["builder_pubkeys"] = serde_json::json!([RELAY_PK_A]);
        entry["builder_boost_factor"] = serde_json::json!("100");
    }
    vc.stored.insert(key.clone(), stored);
    let url = serve(vc.clone()).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let opts = ApplyOptions { preserve_entries: true, ..Default::default() };
    let report = run_apply(&env.input, &env.overlay, &opts).await.unwrap();
    assert!(report.ok(), "{:?}", report.errors);

    let posts = vc.posts();
    let posted = posts.iter().find(|(pk, _)| pk == &key).unwrap();
    let entries = posted_entries(&posted.1);
    // no identity duplicated: exactly our two projected entries
    assert_eq!(entries.len(), 2, "{entries:?}");
    // ours win: the POST body equals our pure projection (resolved defaults
    // dropped)
    assert_eq!(posted.1, projected_string(&env, &key));
}

// (d) A merge that would exceed the KM 64-entry cap fails loudly with no POST.
#[tokio::test]
async fn preserve_entries_over_cap_fails_without_posting() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    let env = env_for(std::slice::from_ref(&key), &[]);
    let mut stored = projected_value(&env, &key);
    let builders = stored["builders"].as_array_mut().unwrap();
    // our 2 entries + 63 distinct third-party entries = 65 > 64
    for i in 0..63 {
        builders.push(third_party_entry(&format!("https://third-{i}.example.com"), "0xabcdef"));
    }
    vc.stored.insert(key.clone(), stored);
    let url = serve(vc.clone()).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let opts = ApplyOptions { preserve_entries: true, ..Default::default() };
    let report = run_apply(&env.input, &env.overlay, &opts).await.unwrap();

    assert!(!report.ok());
    assert!(
        report.errors.iter().any(|e| e.contains("exceeding the KM maximum")),
        "{:?}",
        report.errors
    );
    // the merge aborts BEFORE any POST for this key
    assert!(!vc.posts().iter().any(|(pk, _)| pk == &key), "{:?}", vc.posts());
}

#[tokio::test]
async fn check_reordered_uppercase_stored_doc_is_not_drift() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));

    // the stored doc: same content as the projection, but entries REVERSED,
    // auth_data hex UPPERCASED, and VC-resolved values for fields the
    // projection omits
    let env0 = env_for(std::slice::from_ref(&key), &[]);
    let projection = project(&env0.input, &env0.overlay).unwrap();
    let projected_doc = projection.docs.values().next().unwrap();
    let mut stored = serde_json::to_value(projected_doc).unwrap();
    let builders = stored["builders"].as_array_mut().unwrap();
    builders.reverse();
    for entry in builders.iter_mut() {
        let upper = entry["auth_data"].as_str().unwrap().to_uppercase().replacen("0X", "0x", 1);
        entry["auth_data"] = serde_json::json!(upper);
        // VC-side resolution fills fields the projection left out
        entry["builder_boost_factor"] = serde_json::json!("100");
    }
    stored["builder_boost_factor"] = serde_json::json!("100");
    vc.stored.insert(key.clone(), stored);
    let url = serve(vc).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let report = run_check(&env.input, &env.overlay).await.unwrap();
    assert!(!report.fails(Tier::Warn), "{:?}", report.findings);
}

#[tokio::test]
async fn check_flags_drift_and_unroutable_auth_data() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    vc.stored.insert(
        key.clone(),
        serde_json::json!({
            "min_bid": "1",
            "builders": [
                { "url": "https://cb.example.com", "auth_data": "0xdead" }
            ]
        }),
    );
    let url = serve(vc).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let report = run_check(&env.input, &env.overlay).await.unwrap();
    assert!(
        report.findings.iter().any(|f| f.code == "unroutable-auth-data" &&
            f.tier == Tier::Warn &&
            f.msg.contains("served via the pipe")),
        "{:?}",
        report.findings
    );
    assert!(report.findings.iter().any(|f| f.code == "drift" && f.tier == Tier::Warn));
    assert!(report.fails(Tier::Warn));
    assert!(!report.fails(Tier::Error));
}

#[tokio::test]
async fn check_errors_when_no_builder_config_route() {
    let key = random_key();
    let mut vc = MockVc::holding(std::slice::from_ref(&key));
    vc.supports_builder_config = false;
    let url = serve(vc).await;

    let env = env_for(std::slice::from_ref(&key), &[url]);
    let report = run_check(&env.input, &env.overlay).await.unwrap();
    assert!(
        report.findings.iter().any(|f| f.code == "no-builder-config-route" &&
            f.tier == Tier::Error &&
            f.msg.contains("#88")),
        "{:?}",
        report.findings
    );
    assert!(report.fails(Tier::Error));
}

#[tokio::test]
async fn check_flags_duplicate_key_across_vcs() {
    let key = random_key();
    let vc1 = MockVc::holding(std::slice::from_ref(&key));
    let vc2 = MockVc::holding(std::slice::from_ref(&key));
    let (url1, url2) = (serve(vc1).await, serve(vc2).await);

    let env = env_for(std::slice::from_ref(&key), &[url1, url2]);
    let report = run_check(&env.input, &env.overlay).await.unwrap();
    assert!(
        report.findings.iter().any(|f| f.code == "duplicate-key" && f.tier == Tier::Error),
        "{:?}",
        report.findings
    );
}
