# Dynamic transport benchmark

This benchmark compares Aya RingBuf with Samurai Mold while both capture the
same syscall pointer payload. Python only builds, launches, measures, validates,
and summarizes the compiled Rust and BPF processes; it is not in the measured
producer or consumer hot path.

## Setup

Place an Aya checkout beside Samurai, apply `aya_dynamic.patch`, and install the
fixture example:

```sh
git clone https://github.com/aya-rs/aya ../aya
git -C ../aya apply ../samurai/benches/aya_dynamic.patch
mkdir -p ../aya/aya/examples
cp benches/aya_dynamic_fixture/dynamic_controlled_bench.rs \
  ../aya/aya/examples/dynamic_controlled_bench.rs
```

The runner requires Linux, root BPF/perf access, Rust, clang with the BPF
backend, `perf`, and `/usr/bin/time`. Producer and consumer CPU lists should use
separate physical cores when the machine has enough cores.

## Reproducible runs

Compare the intended production topologies and collect latency:

```sh
sudo python3 benches/dynamic_transport_comparison.py \
  --pairs 10 --warmups 2 --calls 100000 \
  --shape bytes --payload-bytes 128 --latency \
  --mold-consumers per-lane \
  --producer-cpus 0,1,2,3 --consumer-cpus 5,4,6,7
```

Compare equal consumer-thread counts:

```sh
sudo python3 benches/dynamic_transport_comparison.py \
  --pairs 10 --warmups 1 --calls 100000 \
  --shape both --payload-bytes 128 \
  --mold-consumers single \
  --producer-cpus 0,1,2,3 --consumer-cpus 7
```

Inject an identical periodic consumer pause:

```sh
sudo python3 benches/dynamic_transport_comparison.py \
  --pairs 5 --calls 100000 --shape bytes \
  --mold-consumers single --capacity 8192 \
  --consumer-pause-every 256 --consumer-pause-us 200 \
  --producer-cpus 0,1,2,3 --consumer-cpus 7
```

Repeat the production command with `--payload-bytes 8`, `32`, and `128` for a
record-size sweep. Raw rows, commands, arguments, compiler versions, kernel
metadata, and CPU metadata are written beneath
`target/dynamic-transport-comparison/<timestamp>/results.json`.

## OCI VM results, 2026-10-15

Host: Linux 6.12, Intel Xeon Platinum 8167M, four physical cores/eight logical
CPUs, Rust 1.99, clang 21. The VM did not provide four isolated physical
consumer cores, so maximum-latency outliers include virtualization and SMT
scheduling noise.

Production topology: four producers, Aya with one pinned shared-ring consumer,
Mold with one pinned consumer per lane, ten alternating pairs, two warmups,
100,000 calls per producer, and latency measurement enabled.

| Payload | Mold producer rate | Mold delivered rate | Mold task clock | Aya p50 | Mold p50 | Aya p99 | Mold p99 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 B | +26.30% | +16.55% | +19.36% | 0.32 us | 0.47 us | 1.65 us | 0.80 us |
| 32 B | +25.39% | +15.75% | +20.02% | 0.34 us | 0.48 us | 1.71 us | 0.84 us |
| 128 B | +26.56% | +14.25% | +19.73% | 0.39 us | 0.51 us | 1.91 us | 0.95 us |

Every production-topology run reported zero loss. Mold improved p99 and
throughput but used four consumers and approximately 20% more aggregate CPU.
Mold's observed maxima were less stable, including one 15 ms VM scheduling
outlier; do not treat this host as an extreme-tail validation platform.

With one consumer on each side, Mold used less aggregate CPU and retained its
throughput advantage, but its round-robin lane scanner had worse p99. That mode
is a resource-normalized experiment, not the intended production topology.

Under forced consumer stalls, Aya retained more records because its shared ring
can lend all free capacity to a hot producer. Mold's fixed lanes provide
isolation and exact gap accounting but can strand capacity in quiet lanes.

## Interpretation limits

- Bootstrap intervals describe variation across paired runs on this host; they
  do not establish portability to other machines.
- Per-record latency measurement calls `clock_gettime` in both consumers and is
  kept separate from throughput-only claims where possible.
- `perf stat` covers process startup, teardown, and all benchmark threads.
- Maximum latency on a shared cloud VM is dominated by scheduling outliers.
- A production HFT claim requires isolated bare-metal cores, controlled CPU
  frequency, IRQ placement, NUMA placement, and longer p99.9/p99.99 runs.
