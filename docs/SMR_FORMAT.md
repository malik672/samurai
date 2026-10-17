# Samurai recording format (`.smr`)

This document defines version 2 of Samurai's append-only recording format.
Every integer is unsigned and little-endian. Strings are UTF-8 bytes prefixed
by a `u16` byte length. A reader must reject a truncated file, an unknown frame
type, invalid metadata, totals that disagree with the frames, or bytes after
the footer.

## Header

| Field | Type | Meaning |
|---|---:|---|
| magic | `[u8; 8]` | `SAMURAI\0` |
| version | `u16` | `2` |
| byte-order marker | `u16` | `0x0102` |
| record words | `u16` | Fixed words in every data payload; currently 2–34 |
| CPU count | `u16` | Number of following CPU identifiers |
| field count | `u16` | Number of following field descriptors |
| reserved | `u16` | Zero |
| start realtime | `u64` | `CLOCK_REALTIME` nanoseconds near trace startup |
| start monotonic | `u64` | `CLOCK_MONOTONIC` nanoseconds paired with start realtime |
| category | string | Tracepoint category |
| event | string | Tracepoint event |
| CPUs | `CPU count × u32` | Sorted, unique Linux logical CPU identifiers |
| fields | variable | `field count` descriptors defined below |

Each field descriptor contains its name string followed by: capture-kind `u8`,
signed flag `u8` (zero or one), destination word `u16`, word count `u16`, source
size `u16`, and dynamic capture bound `u32`. The destination range must fit in
the fixed record.

The two start clocks are sampled consecutively, not atomically. They provide a
wall-clock approximation for monotonic BPF timestamps; their sampling skew is
the uncertainty of that conversion.

## Frames

Frames continue until exactly one footer.

- Data (`type = 1`): type `u8`, CPU `u32`, then `record words × u64`. Word zero
  is the BPF monotonic timestamp. The low 32 bits of word one identify the CPU
  and must equal the frame CPU.
- Gap (`type = 2`): type `u8`, CPU `u32`, missed-record count `u64`. A gap means
  Mold overwrote that many generations before this consumer copied them.
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
all structural bounds and CPU identities. Version 2 has no checksum or digital
signature. It therefore cannot promise detection of arbitrary corruption or
tampering.
