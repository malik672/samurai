# Samurai

Samurai is an experimental Linux tracing engine built with eBPF and Mold, its
high-throughput per-CPU event transport. It discovers tracepoint layouts from
the running kernel, captures selected fields, follows process descendants, and
writes versioned `.smr` recordings for offline analysis.

Samurai's main advantage comes from Mold. Each logical CPU publishes into an
independent preallocated lane instead of competing for a shared reservation
cursor, allowing high throughput when many CPUs produce events concurrently.

Samurai can currently answer questions such as:

- Which files did a program and its child processes open?
- Which CPUs and processes produced the most events?
- Which tracepoint field values occurred most frequently?

## Requirements

- Linux on a little-endian architecture
- Rust
- clang with the BPF backend
- A mounted, readable tracefs
- Permission to load and attach BPF programs

## Build

```sh
cargo build --release --bin samurai
```

The executable embeds its generic BPF capture program.

## Quick start

Record completed file opens, closes, reads, and writes performed by a command
and its descendants:

```sh
sudo ./target/release/samurai record --preset files \
  --command 'cargo build' \
  --output cargo-build.smr
```

Analyze the recording:

```sh
./target/release/samurai analyze cargo-build.smr
```

The analysis includes event rate, received and dropped records, exact per-CPU
counts, the captured process tree, busy processes by name and PID, requested
and completed I/O per file, and frequent captured values. General rankings use
bounded memory. File correlation allocates its timestamp-ordering workspace
once from the completed recording's event count. High-cardinality PID and field
rankings use fixed-capacity tables and label estimates with error bounds.

Preset recordings produce a concise domain-specific report by default. Use
`samurai analyze --raw` to include the underlying tracepoint rankings. Relative
paths remain relative because resolving them correctly requires the working
directory or `openat` directory descriptor from that exact point in time.

## Commands

```sh
# Discover tracepoints.
samurai list [CATEGORY]

# Inspect the kernel event layout and Samurai capture policy.
samurai inspect CATEGORY:EVENT [--fields FIELD,...]

# Validate a capture plan without attaching BPF.
samurai validate CATEGORY:EVENT [--fields FIELD,...]

# Record an existing process and descendants for ten seconds.
sudo samurai trace CATEGORY:EVENT \
  --pid PID --fields FIELD,... --duration 10s --output capture.smr

# Launch and record a command from its first instruction.
sudo samurai trace CATEGORY:EVENT \
  --fields FIELD,... --command 'COMMAND' --output capture.smr

# Record the built-in group of file-related events in one recording.
sudo samurai record --preset files \
  --command 'COMMAND' --output files.smr

# Validate a completed recording and print its metadata and totals.
samurai report capture.smr

# Perform bounded offline analysis.
samurai analyze capture.smr

# Limit a file report to its ten busiest paths.
samurai analyze capture.smr --top 10

# Include low-level CPU, PID, event, and field rankings.
samurai analyze capture.smr --raw

# Show the busiest written files under target/.
samurai analyze capture.smr --path target/ --writes-only --sort writes

# Show failed file operations.
samurai analyze capture.smr --errors-only --sort errors

# Ignore files with less than one MiB of completed I/O.
samurai analyze capture.smr --min-bytes 1MiB
```

Use `samurai --help` or `samurai <command> --help` for all options.

## Capture behavior

Samurai loads one configured BPF entry program per selected event. All entries
publish into the same per-CPU Mold transport. Each occurrence is published once
to the Mold lane belonging to the logical CPU on which it occurred. Different
CPUs can produce concurrently without duplicating an event across all lanes.

`--pid PID` filters events in BPF and tracks descendants. Attaching to an
already-running process cannot atomically snapshot its existing process tree,
so Samurai scans `/proc` before and after attaching to narrow that race.
Process names and parent relationships are captured separately from Mold's hot
event path and stored in the recording for later analysis.

`--command` avoids the startup race. Samurai configures tracing and starts its
consumers before releasing the command. When invoked through `sudo`, the
workload drops back to `SUDO_UID` and `SUDO_GID`.

Capture plans support fixed fields and explicitly configured bounded strings,
byte buffers, `__data_loc`, and `__rel_loc` values. Inputs may be dynamic, but
Mold records remain fixed-size and preallocated. An externally supplied BPF
object must use the layout expected by Samurai.

## Recordings and limitations

The `.smr` format stores one or more event schemas, the CPU list, data frames,
Mold gap frames, process metadata, and final totals. Ordering is preserved
within each CPU lane; cross-CPU analysis uses the captured monotonic timestamps.
The format is documented in [docs/SMR_FORMAT.md](docs/SMR_FORMAT.md).

Mold is deliberately lossy when a producer laps its consumer. Samurai records
the detected gap instead of silently presenting the capture as complete. The
format does not currently include a cryptographic checksum.

Do not use Samurai as the only source of production audit or billing data. It
still needs broader bare-metal validation, hostile-condition memory-ordering
tests, and fuzzing before it should be considered production ready.

The default embedded object retains 16,384 records per selected CPU and uses
approximately 5 MiB per CPU. Set `SAMURAI_MOLD_CAPACITY` at build time to
choose another power-of-two capacity.

## License

Samurai uses `aya-obj` for ELF parsing and relocations, but its own Linux
syscall layer for loading and attachment. Its reduced loader was adapted from
Aya under the retained MIT notice in
[LICENSES/aya-MIT.txt](LICENSES/aya-MIT.txt).

Samurai is licensed under the [MIT License](LICENSE).
