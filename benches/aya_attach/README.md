# Aya attachment comparison

Build from the repository root:

```sh
python3 benches/aya_attach/build.py
```

The build pins Aya to `15593549d93cd39decf008f6d859fd054ba40bcf`, creates
an unmodified and patched copy under `target/`, and builds the same harness
against each. Dependency lockfiles match. The patch replaces only the
tracepoint ID reader, retaining Aya's filename-bearing error wrapper.
Samurai's reader is extracted directly from `src/utils/tracepoint.rs`.
Inspect `target/aya-attach-benchmark/reader.patch` for the exact difference.
Dependencies require network access on the first build; clang needs its BPF
target enabled. Original upstream sources retain their licenses.

Run on this machine's performance CPU 5:

```sh
sudo python3 benches/aya_attach/run.py --cpu 5 --pairs 10 --iterations 500
```

Each process loads the same trivial tracepoint BPF program before timing,
warms up with 25 attach/detach operations, then times each call to
`TracePoint::attach("sched", "sched_switch")`. Detachment happens outside
the timer after every operation, and failure aborts the run. No links are
intentionally kept alive. The event fires normally while each link is alive.
Clock-reading overhead is included equally in both variants.

The runner alternates process order for each pair, pins both perf and its
child to the selected CPU, and saves raw perf output, benchmark logs, JSON,
and summary statistics in a timestamped directory under
`target/aya-attach-benchmark/`. CPU frequency is not locked and the CPU is
not isolated. Check migration counts and scheduling noise in the raw files.

Compare `attach_ns_per_op`, not perf's total duration: perf covers program
loading, warmup, attachment, and detach. Hardware counters are unavailable
on the current host, so the runner uses software events. The paired
bootstrap interval describes variation across these pairs, not systematic
bias or portability to other hosts. If it includes zero, this experiment
does not resolve an attachment speedup. Repeat a full experiment to check
stability before making an upstream performance claim.

This measures warmed attachment through Aya's actual attach implementation.
It does not measure cold startup, program loading, or event-processing
throughput. It requires root access to tracefs, BPF, and perf on this host.
