# Tracepoint ID read benchmark

Measured 2026-09-19 on this Apple aarch64 Linux machine, using rustc 1.98.1
with `-O`. Both implementations were pinned to CPU 5: CPU capacity 1024,
maximum frequency 4.056 GHz. The governor remained `schedutil`; frequency
was not locked, and the core was not isolated from other workloads.

The benchmark compares Aya's `read_to_string` + `trim` + integer parse
success path with Samurai's current fixed-buffer reader, included directly
from its source. Both open, read, parse, and close the same file on each
iteration. Path construction, directory discovery, attachment, and stored
tracepoint names are excluded. Results are consumed and checked.

Input: a warm local regular file containing `1234\n`. The real tracefs ID
file was inaccessible, including outside the sandbox; sudo required a
password. These results must not be presented as tracefs or attachment
benchmarks. Filesystem behavior can affect the comparison.

Each process warmed up for 10,000 operations and measured 500,000 operations.
Twelve pairs alternated execution order. `perf stat` wrapped every measured
process; the per-operation wall times came from Rust's `Instant` around the
measurement loop. Perf task-clock measurements include warmup and startup.

| Implementation | Median ns/op | Min–max ns/op | Median perf task-clock (ms) |
| --- | ---: | ---: | ---: |
| Aya-style string read | 1244.020 | 1235.578–1259.264 | 633.005 |
| Samurai fixed buffer | 1074.705 | 1065.320–1082.047 | 546.455 |

The fixed buffer took 13.6% less time in this experiment, about 169 ns per
lookup. This does not establish the impact on real tracepoint attachment.

Hardware cycles/instructions events were unsupported. Available software
counters were collected with the `:u` restriction imposed by the current
permissions. They reported zero migrations and context switches; those
restricted counts are not evidence of an interference-free CPU. Page faults
were 48–49 per process.

Reproduce from the repository root:

```sh
rustc --edition=2024 -O benches/tracepoint_read.rs -o target/tracepoint-read-bench
python3 benches/run_tracepoint_read.py
```

The runner uses CPU 5; select an appropriate performance CPU on other hosts.
Raw measurements are saved in `target/tracepoint-benchmark/results.json` and
individual `.perf.csv` files. The benchmark executable also accepts an
accessible real ID path directly: `<aya|fixed> <id-file> <iterations>`.

Aya reference: https://github.com/aya-rs/aya/blob/main/aya/src/programs/trace_point.rs
The success path is adapted locally rather than benchmarking the entire Aya
crate. Its MIT license notice is retained in `LICENSES/aya-MIT.txt`.
