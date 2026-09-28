# Samurai

Samurai uses `aya-obj` to parse compiled BPF ELF objects and relocate map
references and BPF function calls. Map creation, program loading, perf event
attachment, and reading map values use Samurai's own Linux syscalls; the Aya
runtime is not a dependency.

The loader sequence is adapted from Aya's `aya/src/bpf.rs` at revision
`15593549d93cd39decf008f6d859fd054ba40bcf`, under the MIT license retained in
`LICENSES/aya-MIT.txt`. This is a reduced adaptation, not Aya's full loader:
Samurai keeps its syscalls, `FxHashMap` collections, and the supported scope
listed below. Samurai returns owned perf descriptors instead of Aya link IDs.

`ObjectLoader::load()` creates maps, relocates and loads every program before
returning. Each program borrows its function's instructions during the load
syscall; aliases borrow the same buffer. Parsed functions are dropped at the
end of loading. Returned program handles contain only kernel FDs, with no
instruction copies or reference counting. A failure drops already-created
programs and maps; retry by parsing the object again.

Use `loaded.program(name)` and call its `attach()` method. There is no separate
program `load()` call. Array-map operations live in `src/bpf/map.rs`; program
loading and attachment live in `src/bpf/program.rs`.

## Compiled tracepoint counter

Requires Linux, Rust, and clang with the BPF backend. Build from this directory:

```sh
mkdir -p target
clang -target bpfel -O2 -c examples/bpf/counter.c -o target/counter.bpf.o
cargo build --example counter
./target/debug/examples/counter target/counter.bpf.o --check
sudo ./target/debug/examples/counter target/counter.bpf.o 10
```

The last command attaches to `sched/sched_switch` for ten seconds, increments a
CPU-local value in a per-CPU array map, and prints the summed count approximately
once per second. Tracepoint BPF programs execute on every CPU that fires the
event, but each CPU is the sole writer of its local counter, so no atomic
increment is needed. The perf descriptor keeps the attachment alive and closes
on exit.
Tracing must be mounted and accessible. BPF/perf privileges are needed to run;
`--check` only parses and validates the supported format without kernel access.

Initial object support is intentionally limited to little-endian hosts and
objects, tracepoint programs, and legacy `maps` array, per-CPU array, queue,
and ring-buffer definitions with no flags or pinning. BTF/CO-RE, `.maps` BTF definitions,
global data, and other program/map types are rejected. Compile the examples
without `-g`. The `read_u64` array APIs require a u32 key and an eight-byte
value. Per-CPU reads use caller-owned storage sized once during initialization.
Queue values are copied into an exactly sized byte slice and removed atomically
by the kernel.

## Pollable scheduler recorder

The ring-buffer example records scheduler fields for each context switch:

```sh
clang -target bpfel -O2 -c examples/bpf/record.c -o target/record.bpf.o
cargo build --example raw_record
./target/debug/examples/raw_record target/record.bpf.o --check
sudo ./target/debug/examples/raw_record target/record.bpf.o 10 5
```

The BPF program reserves and fills fixed 40-byte records directly inside a
one-MiB `BPF_MAP_TYPE_RINGBUF`. `RingBufferRecorder` memory-maps the shared
consumer, producer, and data pages. It blocks in `poll()` when caught up, then
decodes committed records directly from the mapping and advances the consumer
position with release ordering. There is no syscall or intermediate copy per
record. The optional third argument pins the single consumer to one CPU.

A separate per-CPU array-map counter reports reservations dropped when the
bounded ring is full. The drop counter is summed after detachment. The example
keeps eight samples for display, drains remaining committed records, and reports
the loss rate.

A second per-CPU map stores the last switch timestamp. The BPF program computes
the completed timeslice on the CPU that observed it, so the userspace reducer
does not reconstruct global event order. The final
report ranks tasks by runtime and includes CPU percentage, switch counts,
voluntary and involuntary switches, and average and maximum timeslice.

## Molded scheduler recorder

Mold is Samurai's fixed, marked-generation transport. Every producer owns one
preallocated lane and every lane has one assigned consumer. A producer writes a
fixed payload between WRITING and committed generation marks; the consumer
accepts it only when both mark reads identify the expected generation. The
protocol has no lock, CAS retry loop, shared reservation cursor, or SeqCst
operation. If a producer laps its consumer, `Gap(n)` reports the exact loss.

The public implementation is `samurai::mold`; `marked_mold` constructs an
in-process lane, and the context-switch helpers compile the six-word schema
into the type. The BPF prototype uses the same ownership and generation
protocol over an mmapable array map. Its default 512K-slot lanes retained every
record in the current controlled trials.

```sh
clang -target bpfel -mcpu=v3 -O2 \
  -c examples/bpf/marked_controlled.c \
  -o target/marked_controlled.bpf.o
cargo build --release --example marked_controlled
sudo ./target/release/examples/marked_controlled \
  target/marked_controlled.bpf.o 2000000 0,1,2,3 5,4,6,7
```

The fixed capacity is the retention guarantee. Userspace publishes diagnostic
progress every 128 records, while the producer hot path remains independent of
consumer progress. Per-lane capacity isolation and loss of global arrival order
are explicit tradeoffs.

Record layouts are declared once on the Rust side with `mold_record!`. Field
order is the ABI that the BPF handler writes into its fixed slot:

```rust
samurai::mold_record!(ContextSwitchRecord, 6 {
    timestamp_ns: u64,
    runtime_ns: u64,
    previous_pid: u32,
    next_pid: u32,
    cpu: u32,
    previous_state: i64,
});
```

`MoldProducer::produce_record` and `MoldWorker::try_next_record` encode and
decode that type without allocation or runtime schema lookup. Supporting
another fixed-size event requires its Rust record and schema declaration plus a
BPF handler that writes fields in the declared order. The lane, mark, gap, and
retention protocol remains unchanged.

`openat` is the second complete event implementation and uses the library's
generic mapped-lane reader:

```sh
clang -target bpfel -mcpu=v3 -O2 -I examples/bpf \
  -c examples/bpf/openat.c \
  -o target/openat.bpf.o
cargo build --release --example openat
sudo ./target/release/examples/openat target/openat.bpf.o 5
```

The example attaches to `syscalls:sys_enter_openat`, uses the same bounded
user-string helper as Aya to capture up to 63 pathname bytes, reads every CPU
lane as typed `OpenAtRecord` values, and reports exact gaps. Its 64K-slot lanes
reserve about 72 MiB for the wider path-bearing records.

### Generate a tracepoint schema

Samurai can turn Linux's authoritative tracepoint format into a fixed Mold BPF
producer and matching Rust record:

```sh
cargo build --release --example generate_tracepoint
sudo ./target/release/examples/generate_tracepoint \
  sched sched_switch target/generated

clang -target bpfel -mcpu=v3 -O2 -I examples/bpf \
  -c target/generated/sched_sched_switch.bpf.c \
  -o target/generated/sched_sched_switch.bpf.o
```

The generator includes a timestamp and CPU, maps fixed scalars and arrays from
their kernel-provided offsets, calculates a power-of-two lane capacity within a
64 MiB total transport budget, and emits `mold_record!` code. It deliberately
rejects pointers and `__data_loc` fields because those need an explicit bounded
read policy like the pathname policy in the `openat` example.

### Reproducible transport comparison

`benches/transport_comparison.py` runs alternating paired trials against Aya,
including warmups, `perf stat`, peak RSS, exact accounting checks, deterministic
paired bootstrap intervals, raw output, and machine/compiler metadata.
It reports attempted producer rate separately from loss-adjusted delivery rate.
The end-to-end delivery rate uses records received divided by complete process
wall time measured with a nanosecond monotonic clock, so dropped records cannot
make a transport appear faster.

Equal-memory mode compares Aya's four-MiB ring with four 16K-record Mold lanes
(also four MiB total):

```sh
sudo python3 benches/transport_comparison.py --scenario equal --pairs 20
```

Retention mode compares Aya with Samurai's 512K-record, eight-lane production
configuration (256 MiB total):

```sh
sudo python3 benches/transport_comparison.py --scenario retained --pairs 20
```

Use `--scenario both` to run both experiments. Results are stored below
`target/transport-comparison/`; comparisons should only be made within one
scenario and run.

## Kernel aggregate profiler

For cumulative scheduler statistics, Samurai can avoid the ring transport
entirely. The BPF program reduces switches into an LRU per-CPU task map while
the workload runs. Userspace remains asleep. After detachment, CPU partitions
are read, processed in parallel, and merged once.

```sh
clang -target bpfel -O2 -c examples/bpf/aggregate.c -o target/aggregate.bpf.o
cargo build --release --example record
sudo ./target/release/examples/record target/aggregate.bpf.o 10
```

The report compares the CPU-local record counter with records retained in the
task map. A nonzero eviction count means the configured 16,384-task LRU capacity
was insufficient for the recording.

Handwritten instructions and `examples/load.rs` remain small syscall fixtures.
The independent Aya comparison harness in `benches/aya_attach` has its own
build script and is excluded from Cargo's automatic benchmark discovery.

## Checks

```sh
cargo test --all-targets
```

Object-loader tests compile the C fixture using clang, then exercise parsing,
unsupported-input rejection, and relocations without requiring root.

## License

Samurai is licensed under the [MIT License](LICENSE). Code adapted from Aya
retains its original notice in [LICENSES/aya-MIT.txt](LICENSES/aya-MIT.txt).
