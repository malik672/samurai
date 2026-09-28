# Actual Aya Function ownership benchmark

This compares upstream Aya against Arc and raw-pointer patches, all at commit
`15593549d93cd39decf008f6d859fd054ba40bcf`. It does not benchmark Samurai's
bounded-loading lifecycle and does not compare mock load callbacks.

The patch moves functions into one `Arc` per referenced function key during
program preparation. `ProgramData` stores that Arc, and loading borrows its
contents. Program configuration and explicit per-program loading remain
available for the Arc variant. Original Aya and the patched variants use identical dependencies,
compiler settings and harness source. The exact diff is saved as
`target/aya-ownership/arc.patch`. Aya's license remains in both source trees.

The third variant (`raw.patch`) retains the parsed object's original
`BTreeMap<(usize, u64), Function>` inside `Ebpf`. Programs point directly to its
entries. The tree is never mutated after pointer creation: moving its owner
preserves the heap-node addresses. Program wrappers drop before this owner.
There are no extra per-function boxes, owner vector, reference counts, or
lookup table. Keeping the original tree retains its node storage and any
non-entry functions; this is a measurable memory tradeoff.

**The raw patch is a benchmark-only restricted-lifetime prototype.** It is not
a sound drop-in implementation of Aya's public API: a caller can take a program
out of its Ebpf owner, drop that owner, and later dereference a dangling pointer
when loading. Raw pointers also change automatic Send/Sync behavior. The
harness never lets programs escape, including in the privileged stage.
Production use would require enforcing lifetimes through a redesigned API.
No production Samurai code uses this patch.

## Build

Requires the clean, pinned checkout `target/aya-attach-source` from the prior
Aya benchmark and its dependency lockfile. No production Samurai code changes.

```sh
python3 benches/aya_ownership/build.py
```

Six release binaries are produced: original/Arc/raw, each with an uninstrumented
timing build and a separate allocation-instrumented build. The counting global
allocator is compiled out of the timing binaries.

## Measure

```sh
python3 benches/aya_ownership/run.py --pairs 30 --iterations 2000
sudo python3 benches/aya_ownership/run.py --kernel --pairs 20 --iterations 20
```

The first measures actual `Ebpf::load()` (ELF parsing, relocations, runtime map
and program preparation) using objects with no maps, allowing unprivileged
execution. It does not submit programs to the kernel. The second additionally
calls `TracePoint::load()` for every program and includes a map-backed counter
object. It requires BPF privileges and has not been validated unless an actual
kernel run succeeds. Neither phase attaches programs or measures event rates.

Input bytes are read before timing. Five warmup loads precede measurement to
initialize lazy kernel-feature probes and caches. Each iteration creates a
fresh Ebpf instance. `load_ns` excludes its destruction; `cycle_ns` includes
destruction. The binaries assert successful loading; the runner checks the
number of programs. All cases abort on errors instead of timing failure paths.

The fixtures are compiled C ELF objects, not fabricated instruction vectors:
one small tracepoint; 32 separate small tracepoints; 32 ELF aliases of one small
function; the corresponding large cases; and 32 map-updating programs for the
privileged phase. Large functions contain 256 volatile arithmetic steps to
prevent optimization into a trivial return. These are controlled generated
workloads, not a representative collection of deployed applications. They
exclude BTF/CO-RE metadata; more varied real objects are needed for upstream
generalization. Alias cases deliberately stress sharing, not typical usage.

The runner pins both variants to CPU 5, the performance core used in prior
measurements on this host. It randomizes case order with a fixed seed and
cycles through all six variant orders. Frequency is not locked and the CPU is not isolated.
`perf stat` captures software counters around each process; these totals
include warmup and teardown. Scoped `Instant` measurements produce the table.
Userspace-restricted perf counters are used for unprivileged runs. They do not
prove absence of kernel scheduling interference. Hardware PMU events are not
available on this host.

Time summaries use means across process averages and a paired bootstrap
interval. Intervals reflect sampled variation, not allocator layout bias or
all systematic errors. Independent repeated runs should be considered together.

## Memory

Three separate processes per mode/case measure a single warmed load:

- Allocation calls, including successful reallocations.
- Cumulative requested allocation bytes, including full reallocation sizes.
- Live requested bytes retained by the resulting Ebpf instance.
- Peak live requested bytes above the warmed baseline.
- Live-byte delta after dropping Ebpf, asserted to be zero.

These are Rust allocator measurements, not RSS or kernel memory. They exclude
allocator metadata/rounding, input-file storage, and pre-existing warm caches.
Timing and memory builds intentionally differ only in instrumentation.

Raw logs, software perf counters, timings, allocation measurements, binary
hashes, compiler version, CPU metadata and summaries are written to a new
`target/aya-ownership/results-<phase>-<timestamp>/` directory for each run.
