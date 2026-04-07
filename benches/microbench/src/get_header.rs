//! Criterion benchmarks for the `get_header` PBS flow.
//!
//! # What this measures
//!
//! The per-request `get_header` pipeline: HTTP request to a single in-process
//! mock relay, response parsing, header validation, signature verification, and
//! bid selection. This is wall-clock timing — useful for local development
//! feedback and catching latency regressions across validation configurations.
//!
//! A single relay is used because relay fan-out uses `join_all` (not
//! `tokio::spawn`), so all futures are polled on the same task. HTTP requests
//! are truly concurrent but CPU-bound validation work (deserialization, BLS sig
//! verification) is interleaved on one thread. Validation cost therefore scales
//! roughly linearly with relay count — one relay is sufficient to measure the
//! per-relay cost, and N relays can be estimated as ~N× that baseline.
//!
//! # Benchmark dimensions
//!
//! **Validation mode** (`HeaderValidationMode`):
//! - `None` — light path: skips full deserialization and sig verification,
//!   extracts only fork + bid value, forwards raw bytes. Fastest option,
//!   requires complete trust in relays.
//! - `Standard` — full deserialization, header validation (block hash, parent
//!   hash, timestamp, fork), BLS signature verification. Default mode.
//! - `Extra` — Standard + parent block validation via RPC. NOTE: without a live
//!   RPC endpoint the parent block fetch returns None and `extra_validation` is
//!   skipped, so Extra degrades to Standard in this bench. It is included to
//!   catch any overhead from the mode flag itself and Accept header
//!   differences. A meaningful Extra benchmark would require a mock RPC server.
//!
//! **Encoding type** (`EncodingType`):
//! - JSON only — validator requests `application/json`
//! - SSZ only — validator requests `application/octet-stream`
//! - Both — validator accepts either (CB picks the best available)
//!
//! Note: in Standard and Extra modes, `get_header` always requests both
//! encodings from relays regardless of what the validator asked for, because it
//! needs to unpack the body. The encoding dimension therefore only affects the
//! None (light) path where the response is forwarded raw and must match what
//! the validator accepts.
//!
//! Total: 3 modes × 3 encodings = 9 benchmark cases.
//!
//! Criterion runs each benchmark hundreds of times, applies statistical
//! analysis, and reports mean ± standard deviation. Results are saved to
//! `target/criterion/` as HTML reports (open `report/index.html`).
//!
//! # Running
//!
//! ```bash
//! # Run all benchmarks
//! cargo bench --package cb-bench-micro
//!
//! # Run only the light (None) mode benchmarks
//! cargo bench --package cb-bench-micro -- none
//!
//! # Compare modes for SSZ encoding
//! cargo bench --package cb-bench-micro -- ssz
//!
//! # Save a named baseline to compare against later
//! cargo bench --package cb-bench-micro -- --save-baseline main
//!
//! # Compare against a saved baseline
//! cargo bench --package cb-bench-micro -- --load-baseline main --save-baseline current
//! ```
//!
//! # What is NOT measured
//!
//! - PBS HTTP server overhead (we call `get_header()` directly, bypassing axum
//!   routing)
//! - Mock relay startup time (server is started once in setup, before timing
//!   begins)
//! - `HeaderMap` allocation (created once in setup, cloned cheaply per
//!   iteration)
//! - Extra mode's RPC fetch (no live RPC endpoint in bench environment)

use std::{collections::HashSet, path::PathBuf, sync::Arc};

use alloy::primitives::B256;
use axum::http::HeaderMap;
use cb_common::{
    config::HeaderValidationMode, pbs::GetHeaderParams, signer::random_secret, types::Chain,
    utils::EncodingType,
};
use cb_pbs::{PbsState, get_header};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    utils::{generate_mock_relay, get_free_listener, get_pbs_config, to_pbs_config},
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

const CHAIN: Chain = Chain::Hoodi;

const MODES: [(HeaderValidationMode, &str); 3] = [
    (HeaderValidationMode::None, "none"),
    (HeaderValidationMode::Standard, "standard"),
    // Extra degrades to Standard without a live RPC endpoint — included to
    // measure any overhead from the mode flag and Accept header differences.
    // See module doc comment for details.
    (HeaderValidationMode::Extra, "extra"),
];

const ENCODINGS: [(&str, &[EncodingType]); 3] = [
    ("json", &[EncodingType::Json]),
    ("ssz", &[EncodingType::Ssz]),
    ("both", &[EncodingType::Json, EncodingType::Ssz]),
];

/// Build a `PbsState` for a specific validation mode with a single relay.
///
/// Port 0 is used because we call `get_header()` directly — no PBS server is
/// started, so the port is never bound. The actual relay endpoint is carried
/// inside the `RelayClient` object.
fn make_pbs_state(mode: HeaderValidationMode, relay: cb_common::pbs::RelayClient) -> PbsState {
    let mut pbs_config = get_pbs_config(0);
    pbs_config.header_validation_mode = mode;
    let config = to_pbs_config(CHAIN, pbs_config, vec![relay]);
    PbsState::new(config, PathBuf::new())
}

/// Benchmarks `get_header` across all validation modes and encoding types.
///
/// # Setup (runs once, not measured)
///
/// A single mock relay is started up-front and shared across all variants.
/// Each variant gets its own `PbsState` configured with the appropriate
/// `HeaderValidationMode`. The mock relay is an in-process axum server on
/// localhost.
///
/// # Per-iteration (measured)
///
/// Each call to `b.iter(|| ...)` runs `get_header()` once:
/// - Sends an HTTP request to the mock relay
/// - Parses and validates the relay response (or skips in None mode)
/// - Returns the bid
///
/// `black_box(...)` prevents the compiler from optimizing away inputs or the
/// return value.
///
/// # Criterion grouping
///
/// Groups are structured as `get_header/{encoding}` with the validation mode
/// as the bench function name. Each Criterion chart directly compares None vs
/// Standard vs Extra for the same encoding — the comparison that matters most
/// for understanding the latency cost of validation.
fn bench_get_header(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    // Start a single mock relay. It gets its own OS-assigned port via
    // get_free_listener() so there is no TOCTOU race.
    let (relay_client, params) = rt.block_on(async {
        let signer = random_secret();
        let pubkey = signer.public_key();
        let mock_state = Arc::new(MockRelayState::new(CHAIN, signer));

        let listener = get_free_listener().await;
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(start_mock_relay_service_with_listener(mock_state, listener));
        let relay_client = generate_mock_relay(port, pubkey.clone()).expect("relay client");

        // Give the server time to start accepting before benchmarking begins.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let params = GetHeaderParams { slot: 0, parent_hash: B256::ZERO, pubkey };
        (relay_client, params)
    });

    // Empty HeaderMap matches what the PBS route handler receives for requests
    // without custom headers. Created once here to avoid measuring its
    // allocation per iteration.
    let headers = HeaderMap::new();

    for &(encoding_name, encoding_types) in &ENCODINGS {
        let encodings: HashSet<EncodingType> = encoding_types.iter().copied().collect();
        let mut group = c.benchmark_group(format!("get_header/{encoding_name}"));

        for &(mode, mode_name) in &MODES {
            let state = make_pbs_state(mode, relay_client.clone());
            let params = params.clone();
            let headers = headers.clone();
            let encodings = encodings.clone();

            group.bench_function(mode_name, |b| {
                b.iter(|| {
                    rt.block_on(get_header(
                        black_box(params.clone()),
                        black_box(headers.clone()),
                        black_box(state.clone()),
                        black_box(encodings.clone()),
                    ))
                    .expect("get_header failed")
                })
            });
        }

        group.finish();
    }
}

// criterion_group! registers bench_get_header as a benchmark group named
// "benches". criterion_main! generates the main() entry point that Criterion
// uses to run them.
criterion_group!(benches, bench_get_header);
criterion_main!(benches);
