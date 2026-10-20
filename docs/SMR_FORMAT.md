# Samurai recording format (`.smr`)

This document defines version 6 of Samurai's append-only recording format.
Every integer is unsigned and little-endian. Strings are UTF-8 bytes prefixed
by a `u16` byte length. A reader must reject a truncated file, an unknown frame
type, invalid metadata, totals that disagree with the frames, or bytes after
the footer. Samurai readers also accept versions 2 through 4. Versions 2 and 3
contain one event schema, version 2 has no process frames, and versions before
5 do not store a thread ID in each data frame. Versions before 6 do not store
initial process working directories.

## Header

| Field | Type | Meaning |
|---|---:|---|
| magic | `[u8; 8]` | `SAMURAI\0` |
| version | `u16` | `6` |
| byte-order marker | `u16` | `0x0102` |
| maximum record words | `u16` | Largest event payload in this recording; currently 2–32 |
| CPU count | `u16` | Number of following CPU identifiers |
| event count | `u16` | Number of following event descriptors; currently 1–47 |
| reserved | `u16` | Zero |
| start realtime | `u64` | `CLOCK_REALTIME` nanoseconds near trace startup |
| start monotonic | `u64` | `CLOCK_MONOTONIC` nanoseconds paired with start realtime |
| CPUs | `CPU count × u32` | Sorted, unique Linux logical CPU identifiers |
| events | variable | `event count` descriptors defined below |

Each event descriptor contains category string, event string, record words
`u16`, field count `u16`, then its field descriptors. Each field contains its
name string followed by: capture-kind `u8`, signed flag `u8` (zero or one),
destination word `u16`, word count `u16`, source size `u16`, and dynamic capture
bound `u32`. Its destination range must fit in that event's record.

The two start clocks are sampled consecutively, not atomically. They provide a
wall-clock approximation for monotonic BPF timestamps; their sampling skew is
the uncertainty of that conversion.

## Frames

Frames continue until exactly one footer.

- Data (`type = 1`): type `u8`, CPU `u32`, event ID `u16`, thread ID `u32`,
  then the number of `u64` words declared by that event descriptor. Word zero
  is the BPF monotonic timestamp. The low 32 bits of word one identify the CPU
  and must equal the frame CPU.
- Gap (`type = 2`): type `u8`, CPU `u32`, missed-record count `u64`. A gap means
  Mold overwrote that many generations before this consumer copied them.
- Process (`type = 3`): type `u8`, PID `u32`, parent PID `u32`, then the
  process command name as a NUL-padded `[u8; 16]`. Process frames occur after
  data and gap frames, are sorted by PID, and contain unique nonzero PIDs.
- Initial CWD (`type = 4`): type `u8`, PID `u32`, then the initial working
  directory as a length-prefixed UTF-8 string. CWD frames occur after process
  frames, are sorted by PID, and contain unique nonzero PIDs. They are captured
  from `/proc/PID/cwd`; absence means the recorder could not establish an
  initial directory and readers must not infer one.
- Footer (`type = 255`): type `u8`, received data frames `u64`, total missed
  records `u64`, end realtime nanoseconds `u64`, and end monotonic nanoseconds
  `u64`.

A missing footer means the recording did not close cleanly. No frame may follow
the footer.

## Ordering and integrity

Data and gap order is meaningful within each CPU lane. Interleaving between
CPU lanes reflects writer arrival order and is not a global event ordering;
consumers should use payload timestamps when they need a cross-lane view.

The footer provides truncation and accounting checks, and the reader validates
all structural bounds, event IDs, and CPU identities. Version 6 has no checksum
or digital signature. It therefore cannot promise detection of arbitrary
corruption or tampering.
