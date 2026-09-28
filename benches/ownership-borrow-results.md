# Bounded loading versus clone and Arc

Release build on performance CPU 5, 12 rounds of all three modes. All six
execution orders were used twice. Each case runs 200 warmups and 2,000 timed
iterations. The table gives medians of the 12 process means, in nanoseconds.

| Workload | Clone | Arc | Borrow |
| --- | ---: | ---: | ---: |
| Current counter | 284.1 | 306.8 | 247.2 |
| 32 unique small functions | 4404.3 | 5442.6 | 2342.8 |
| 32 aliases, small function | 3262.8 | 2251.0 | 1577.1 |
| 32 unique large functions | 60529.4 | 6753.1 | 3230.7 |
| 32 aliases, large function | 21457.1 | 2290.7 | 1596.0 |

Unlike the older two-way comparison, this experiment includes ownership
preparation, identical mock loads, and full input/output destruction in every
variant. Input reconstruction is outside the timer. Numbers therefore must
not be compared directly with the earlier preparation-only measurements.

The borrow variant invokes the production `load_programs` helper with a mock
load callback that observes the license and instruction slice and returns a
dummy integer handle. No BPF syscalls occur in any timed variant. Clone and
Arc reconstruct the previous wrapper representations, then invoke the same
callback. This isolates userspace ownership costs; it does not measure actual
kernel loading, attachment, or event throughput.

The counter uses the compiled, relocated fixture. Other cases are synthetic
ownership workloads derived from it; large means 4,096 instructions per
function. They are not valid workloads for kernel verification. No allocator
or RSS measurements were collected.

`perf stat` wraps every process with task-clock:u, context-switches:u,
cpu-migrations:u and page-faults:u. Whole-process counters also include clang,
input setup and warmup, so table timings come from the scoped Rust `Instant`
measurements. Frequency was not fixed and the CPU was not isolated.

Raw data: `target/ownership-results-1790071749493131787/`.

Reproduce:

```sh
cargo test --offline --release --lib --no-run --message-format=json > target/ownership-build.json
python3 benches/ownership.py
```

The current runner performs this three-way experiment. The older report is
retained as historical preparation-only evidence.
