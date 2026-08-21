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
    let report = run_apply(
        &env.input,
        &env.overlay,
        &ApplyOptions { emit_dir: Some(emit_dir.path().to_path_buf()), ..Default::default() },
    )
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
        report
            .findings
            .iter()
            .any(|f| f.code == "no-builder-config-route" &&
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
