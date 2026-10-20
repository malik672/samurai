# Samurai

Samurai is an experimental Linux tracing engine built with eBPF and Mold, its
high-throughput per-CPU event transport. It discovers tracepoint layouts from
the running kernel, captures selected fields, follows process descendants, and
writes versioned `.smr` recordings for offline analysis.

Samurai's main advantage comes from Mold. Each logical CPU publishes into an
independent preallocated lane instead of competing for a shared reservation
cursor, allowing high throughput when many CPUs produce events concurrently.

Samurai can currently answer questions such as:

- Which files did a program and its child processes open, transfer, map,
  synchronize, rename, unlink, or create as directories?
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

Record completed file operations performed by a command and its descendants:

```sh
sudo ./target/release/samurai record --preset files \
  --command 'cargo build' \
  --output cargo-build.smr
```

Analyze the recording:

```sh
./target/release/samurai analyze cargo-build.smr
```

Create a self-contained HTML report:

```sh
./target/release/samurai report cargo-build.smr
```

The analysis includes event rate, received and dropped records, exact per-CPU
counts, the captured process tree, busy processes by name and PID, requested
and completed I/O per file, and frequent captured values. General rankings use
bounded memory. File correlation allocates its timestamp-ordering workspace
once from the completed recording's event count. High-cardinality PID and field
rankings use fixed-capacity tables and label estimates with error bounds.

Preset recordings produce a concise domain-specific report by default. Use
`samurai analyze --raw` to include the underlying tracepoint rankings. The file
preset correlates `openat`, `openat2`, `close`, `read`, `write`, `pread64`,
`pwrite64`, `readv`, `writev`, `dup`, `dup2`, `dup3`, `rename`, `renameat`,
`renameat2`, `unlink`, `mkdir`, `fsync`, `fdatasync`, and file-backed `mmap` and
`munmap` entry and exit events. It also tracks successful `chdir` and `fchdir` calls.
It follows duplicated descriptors and resolves relative `openat` paths through
a captured directory descriptor when that descriptor is known. Paths relative
to the process working directory use the initial `/proc/PID/cwd` snapshot and
subsequent successful directory changes when that history is known. If exact
CWD evidence is missing, the path remains explicitly labeled with that PID's
unknown CWD rather than being presented as absolute.

`mmap` and `munmap` coverage describes successful file mapping lifecycles,
including partially unmapped ranges. "Still tracked" means a range was not
removed by an observed `munmap` or overlapping replacement; process exit and
`exec` can discard mappings without issuing `munmap`, so it is not proof that
the memory remained active at capture end.
The file preset uses `sched_process_exec`, which is emitted only after a
successful program replacement, to classify those discarded ranges separately
as released by `exec`. Failed `execve` and `execveat` attempts do not clear the
tracked mappings.
Ordinary memory loads and stores through an established mapping are
not syscalls and therefore do not produce additional events. Vectored I/O
reports completed bytes; the current capture does not walk user `iovec` arrays
to calculate requested bytes. Rename records contain both source and destination
paths. Plain `rename` paths are bounded to 112 bytes each; `renameat` and
`renameat2` paths are bounded to 96 bytes each to leave room for their directory
descriptors and flags. All variants fit the existing fixed Mold record without
increasing every lane's memory footprint.

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

# Generate capture.html, or choose a destination with --output.
samurai report capture.smr [--output report.html]

# Restrict the report to an application process, or remove build tooling.
samurai report capture.smr --process my-application
samurai report capture.smr --exclude-process cargo --exclude-process rustc

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
