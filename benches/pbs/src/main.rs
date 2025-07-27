use std::time::{Duration, Instant};

use alloy::primitives::B256;
use cb_common::{
    config::RelayConfig,
    pbs::{GetHeaderResponse, RelayClient, RelayEntry},
    types::{BlsPublicKey, BlsSecretKey, Chain},
    utils::TestRandomSeed,
};
use cb_tests::mock_relay::{start_mock_relay_service, MockRelayState};
use comfy_table::Table;
use config::{load_static_config, BenchConfig};
use histogram::Histogram;

mod config;

fn get_random_hash() -> B256 {
    B256::from(rand::random::<[u8; 32]>())
}

#[tokio::main]
async fn main() {
    let config = load_static_config();

    // start mock relay
    let relay = config.commit_boost.relays.first().expect("missing relay config");
    tokio::spawn(start_mock_relay(config.commit_boost.chain, relay.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut bench_results = Vec::with_capacity(config.bench.len());

    // get_header benchmark
    for bench in config.bench {
        print!("Benching {}...", bench.id);
        let total_start = Instant::now();

        let mock_validator = get_mock_validator(bench);

        // max ~1s
        let mut histo = Histogram::new(12, 20).unwrap();

        // bench
        for slot in 0..config.benchmark.n_slots {
            let parent_hash = get_random_hash();
            let validator_pubkey = BlsPublicKey::test_random();
            let url = mock_validator.get_header_url(slot, &parent_hash, &validator_pubkey).unwrap();

            for _ in 0..config.benchmark.headers_per_slot {
                let url = url.clone();

                let start = Instant::now();
                let res = mock_validator.client.get(url).send().await;
                let end = start.elapsed();

                let res = res
                    .expect("failed to get header")
                    .bytes()
                    .await
                    .expect("failed to decode response");

                assert!(
                    serde_json::from_slice::<GetHeaderResponse>(&res).is_ok(),
                    "invalid header returned"
                );

                histo.increment(end.as_micros() as u64).unwrap();
            }
        }

        println!("took {:?}", total_start.elapsed());

        let p50 = histo.percentile(50.).expect("failed to get p50").unwrap().end();
        let p90 = histo.percentile(90.).expect("failed to get p90").unwrap().end();
        let p95 = histo.percentile(95.).expect("failed to get p95").unwrap().end();
        let p99 = histo.percentile(99.).expect("failed to get p99").unwrap().end();

        bench_results.push(BenchResults { id: mock_validator.id.to_string(), p50, p90, p95, p99 });
    }

    let best_p50 = bench_results.iter().min_by_key(|b| b.p50).unwrap().p50;
    let best_p90 = bench_results.iter().min_by_key(|b| b.p90).unwrap().p90;
    let best_p95 = bench_results.iter().min_by_key(|b| b.p95).unwrap().p95;
    let best_p99 = bench_results.iter().min_by_key(|b| b.p99).unwrap().p99;

    let mut table = Table::new();
    table.set_header(vec!["ID", "p50", "p90", "p95", "p99"]);

    for result in bench_results {
        let p50_ms = result.p50 as f64 / 1000.;
        let r50 = if result.p50 == best_p50 {
            format!("{p50_ms:.2}ms (*)")
        } else {
            let slow_pct = (result.p50 as f64 / best_p50 as f64 - 1.0) * 100.;
            format!("{p50_ms:.2}ms (+{slow_pct:.2}%)")
        };

        let p90_ms = result.p90 as f64 / 1000.;
        let r90 = if result.p90 == best_p90 {
            format!("{p90_ms:.2}ms (*)")
        } else {
            let slow_pct = (result.p90 as f64 / best_p90 as f64 - 1.0) * 100.;
            format!("{p90_ms:.2}ms (+{slow_pct:.2}%)")
        };

        let p95_ms = result.p95 as f64 / 1000.;
        let r95 = if result.p95 == best_p95 {
            format!("{p95_ms:.2}ms (*)")
        } else {
            let slow_pct = (result.p95 as f64 / best_p95 as f64 - 1.0) * 100.;
            format!("{p95_ms:.2}ms (+{slow_pct:.2}%)")
        };

        let p99_ms = result.p99 as f64 / 1000.;
        let r99 = if result.p99 == best_p99 {
            format!("{p99_ms:.2}ms (*)")
        } else {
            let slow_pct = (result.p99 as f64 / best_p99 as f64 - 1.0) * 100.;
            format!("{p99_ms:.2}ms (+{slow_pct:.2}%)")
        };

        table.add_row(vec![result.id, r50, r90, r95, r99]);
    }

    println!();

    println!("Bench results (lower is better)");
    println!("Lowest is indicated with *, percentages are relative to lowest");
    println!("{table}");
}

// mock relay
const MOCK_RELAY_SECRET: [u8; 32] = [
    131, 231, 162, 159, 42, 4, 109, 144, 166, 131, 12, 91, 185, 48, 106, 219, 55, 145, 120, 57, 51,
    152, 98, 59, 240, 181, 131, 47, 1, 180, 255, 245,
];
async fn start_mock_relay(chain: Chain, relay_config: RelayConfig) {
    let signer = BlsSecretKey::deserialize(&MOCK_RELAY_SECRET).unwrap();
    let pubkey: BlsPublicKey = signer.public_key();

    assert_eq!(relay_config.entry.pubkey, pubkey, "Expected relay pubkey to be 0xb060572f535ba5615b874ebfef757fbe6825352ad257e31d724e57fe25a067a13cfddd0f00cb17bf3a3d2e901a380c17");

    let relay_port = relay_config.entry.url.port().expect("missing port");

    let mock_relay = MockRelayState::new(chain, signer);
    start_mock_relay_service(mock_relay.into(), relay_port)
        .await
        .expect("failed to start mock relay");
}

fn get_mock_validator(bench: BenchConfig) -> RelayClient {
    let entry = RelayEntry { id: bench.id, pubkey: BlsPublicKey::test_random(), url: bench.url };
    let config = RelayConfig {
        entry,
        id: None,
        headers: None,
        get_params: None,
        enable_timing_games: false,
        target_first_request_ms: None,
        frequency_get_header_ms: None,
        validator_registration_batch_size: None,
    };

    RelayClient::new(config).unwrap()
}

struct BenchResults {
    id: String,
    p50: u64,
    p90: u64,
    p95: u64,
    p99: u64,
}
