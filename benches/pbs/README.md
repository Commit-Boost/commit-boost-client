
# PBS Benchmark

Benchmark of the PBS module and the [MEV-Boost go-client](https://github.com/flashbots/mev-boost).

## Benchmark info 
Last updated: `02-Sep-2024`
- MEV-Boost: docker image `flashbots/mev-boost:1.8.1`, digest: `sha256:1ce07514249dbd9648773cf5ddfd75f74344c7e49ba8bbc38cec2531e26751a1`
- Commit-Boost: commit hash: `c1503b2447c8535f5d3e7d3ae37e31544f6e18e6`

<details><summary>Runtime info</summary>

### `rustc` version
```
rustc 1.79.0 (129f3b996 2024-06-10)
binary: rustc
commit-hash: 129f3b9964af4d4a709d1383930ade12dfe7c081
commit-date: 2024-06-10
host: x86_64-unknown-linux-gnu
release: 1.79.0
LLVM version: 18.1.7
```

### CPU info
```
Architecture:           x86_64
  CPU op-mode(s):       32-bit, 64-bit
  Address sizes:        46 bits physical, 48 bits virtual
  Byte Order:           Little Endian
CPU(s):                 20
  On-line CPU(s) list:  0-19
Vendor ID:              GenuineIntel
  Model name:           13th Gen Intel(R) Core(TM) i7-1370P
    CPU family:         6
    Model:              186
    Thread(s) per core: 2
    Core(s) per socket: 14
    Socket(s):          1
    Stepping:           2
    CPU(s) scaling MHz: 26%
    CPU max MHz:        5200.0000
    CPU min MHz:        400.0000
    BogoMIPS:           4377.60
    Flags:              fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dt
                        es64 monitor ds_cpl smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb ssbd ibrs ibpb stibp ibrs_enhanced fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid r
                        dseed adx smap clflushopt clwb intel_pt sha_ni xsaveopt xsavec xgetbv1 xsaves split_lock_detect avx_vnni dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp hwp_pkg_req hfi umip pku ospke waitpkg gfni vaes vpclmulqdq tme rdpid movdiri movdir64b fsrm md_clear ser
                        ialize pconfig arch_lbr ibt flush_l1d arch_capabilities
Caches (sum of all):
  L1d:                  544 KiB (14 instances)
  L1i:                  704 KiB (14 instances)
  L2:                   11.5 MiB (8 instances)
  L3:                   24 MiB (1 instance)
NUMA:
  NUMA node(s):         1
  NUMA node0 CPU(s):    0-19
Vulnerabilities:
  Gather data sampling: Not affected
  Itlb multihit:        Not affected
  L1tf:                 Not affected
  Mds:                  Not affected
  Meltdown:             Not affected
  Mmio stale data:      Not affected
  Retbleed:             Not affected
  Spec rstack overflow: Not affected
  Spec store bypass:    Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:           Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:           Mitigation; Enhanced / Automatic IBRS; IBPB conditional; RSB filling; PBRSB-eIBRS SW sequence; BHI BHI_DIS_S
  Srbds:                Not affected
  Tsx async abort:      Not affected
```
</details>

## Setup
To isolate the performance of the sidecar, we create a mock validator that will trigger the sidecar, and a mock relay that will answer calls from the sidecar. Currently we support a single mock relay.

### Setup sidecars
Setup the sidecars and fill the `bench-config.toml` file accordingly.

#### MEV-Boost
Follow [these instructions](https://github.com/flashbots/mev-boost?tab=readme-ov-file#installing). To launch the docker image use this command:

```bash
sudo docker run -d --network host --name mev_boost_bench flashbots/mev-boost:1.8.1 -addr 0.0.0.0:18650 -holesky -relay http://0xb060572f535ba5615b874ebfef757fbe6825352ad257e31d724e57fe25a067a13cfddd0f00cb17bf3a3d2e901a380c17@172.17.0.1:18450
```
After the benchmark, clean up the container:
```bash
docker rm --force mev_boost_bench
```


#### Commit-Boost
You can run the provided `docker-compose` file:
```bash
commit-boost start --docker benches/pbs/bench.docker-compose.yml
```
or regenerate it using `commit-boost init`.

Make sure that the pbs image is available. If not, build it:
```bash
docker build -t commitboost_pbs_default . -f ./docker/pbs.Dockerfile
```

To clean up after then benchmark, run:
```bash
commit-boost stop --docker benches/pbs/bench.docker-compose.yml
```

### Running the benchmark
Run the benchmark with
```bash
cargo run --release --bin cb-bench-pbs -- benches/pbs/bench-config.toml
```
Based on the `bench-config.toml` file, this will simulate multiple calls to each sidecar and measure the latency.

## Results
### Get Header
For each `get_header` call we measure the latency. Note that this latency also includes some small network overhead, and the internal overhead of the mock relay. The assumption is these overheads are ~constants across test cases. This also means that a single latency measurement is not significative, but only useful to be compared across test cases.


```bash
Bench results (lower is better)
Lowest is indicated with *, percentages are relative to lowest

+--------------+-------------------+------------------+------------------+------------------+
| ID           | p50               | p90              | p95              | p99              |
+===========================================================================================+
| mev_boost    | 4.31ms (+142.45%) | 5.08ms (+33.99%) | 5.94ms (+44.48%) | 6.88ms (+48.92%) |
|--------------+-------------------+------------------+------------------+------------------|
| commit_boost | 1.78ms (*)        | 3.79ms (*)       | 4.11ms (*)       | 4.62ms (*)       |
+--------------+-------------------+------------------+------------------+------------------+
```