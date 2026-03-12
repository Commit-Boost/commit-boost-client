//! Criterion benchmarks for the `get_header` PBS flow.
//!
//! # What this measures
//!
//! The full `get_header` pipeline end-to-end: HTTP fan-out to N in-process mock
//! relays, response parsing, header validation, signature verification, and bid
//! selection. This is wall-clock timing — useful for local development feedback
//! and catching latency regressions across relay counts.
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
//! # Run a specific variant by filter
//! cargo bench --package cb-bench-micro -- 3_relays
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
//! - Mock relay startup time (servers are started once in setup, before timing
//!   begins)
//! - `HeaderMap` allocation (created once in setup, cloned cheaply per
//!   iteration)

use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::B256;
use axum::http::HeaderMap;
use cb_common::{pbs::GetHeaderParams, signer::random_secret, types::Chain};
use cb_pbs::{PbsState, get_header};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service},
    utils::{generate_mock_relay, get_pbs_static_config, to_pbs_config},
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

// Ports 19201–19205 are reserved for the microbenchmark mock relays.
const BASE_PORT: u16 = 19200;
const CHAIN: Chain = Chain::Hoodi;
const MAX_RELAYS: usize = 5;
const RELAY_COUNTS: [usize; 3] = [1, 3, MAX_RELAYS];

/// Benchmarks `get_header` across three relay-count variants.
///
/// # Setup (runs once, not measured)
///
/// All MAX_RELAYS mock relays are started up-front and shared across variants.
/// Each variant gets its own `PbsState` pointing to a different relay subset.
/// The mock relays are in-process axum servers on localhost.
///
/// # Per-iteration (measured)
///
/// Each call to `b.iter(|| ...)` runs `get_header()` once:
/// - Fans out HTTP requests to N mock relays concurrently
/// - Parses and validates each relay response (header data + BLS signature)
/// - Selects the highest-value bid
///
/// `black_box(...)` prevents the compiler from optimizing away inputs or the
/// return value. Without it, the optimizer could see that the result is unused
/// and eliminate the call entirely, producing a meaningless zero measurement.
fn bench_get_header(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    // Start all mock relays once and build one PbsState per relay-count variant.
    // All relays share the same MockRelayState (and therefore the same signing
    // key).
    let (states, params) = rt.block_on(async {
        let signer = random_secret();
        let pubkey = signer.public_key();
        let mock_state = Arc::new(MockRelayState::new(CHAIN, signer));

        let relay_clients: Vec<_> = (0..MAX_RELAYS)
            .map(|i| {
                let port = BASE_PORT + 1 + i as u16;
                tokio::spawn(start_mock_relay_service(mock_state.clone(), port));
                generate_mock_relay(port, pubkey.clone()).expect("relay client")
            })
            .collect();

        // Give all servers time to bind before benchmarking starts.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let params = GetHeaderParams { slot: 0, parent_hash: B256::ZERO, pubkey };

        // Port 0 here is the port the PBS service itself would bind to for incoming
        // validator requests. We call get_header() as a function directly, so no
        // PBS server is started and this port is never used. The actual relay
        // endpoints are carried inside the RelayClient objects (ports 19201–19205).
        let states: Vec<PbsState> = RELAY_COUNTS
            .iter()
            .map(|&n| {
                let config =
                    to_pbs_config(CHAIN, get_pbs_static_config(0), relay_clients[..n].to_vec());
                PbsState::new(config, PathBuf::new())
            })
            .collect();

        (states, params)
    });

    // Empty HeaderMap matches what the PBS route handler receives for requests
    // without custom headers. Created once here to avoid measuring its
    // allocation per iteration.
    let headers = HeaderMap::new();

    // A BenchmarkGroup groups related functions so Criterion produces a single
    // comparison table and chart. All variants share the name "get_header/".
    let mut group = c.benchmark_group("get_header");

    for (i, relay_count) in RELAY_COUNTS.iter().enumerate() {
        let state = states[i].clone();
        let params = params.clone();
        let headers = headers.clone();

        // bench_function registers one timing function. The closure receives a
        // `Bencher` — calling `b.iter(|| ...)` is the measured hot loop.
        // Everything outside `b.iter` is setup and not timed.
        group.bench_function(format!("{relay_count}_relays"), |b| {
            b.iter(|| {
                // block_on drives the async future to completion on the shared
                // runtime. get_header takes owned args, so we clone cheap types
                // (Arc-backed state, stack-sized params) on each iteration.
                rt.block_on(get_header(
                    black_box(params.clone()),
                    black_box(headers.clone()),
                    black_box(state.clone()),
                ))
                .expect("get_header failed")
            })
        });
    }

    group.finish();
}

// criterion_group! registers bench_get_header as a benchmark group named
// "benches". criterion_main! generates the main() entry point that Criterion
// uses to run them.
criterion_group!(benches, bench_get_header);
criterion_main!(benches);
