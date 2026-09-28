# Raw pointers into the existing function tree

Run: `target/aya-ownership/results-prepare-1790088671866074734`.
30 rounds, 2,000 Ebpf::load calls per timing sample, CPU 5, release builds.
All six orders were used five times. Separate allocation builds ran three
trials per case. Every memory trial returned to baseline after dropping Ebpf.

The raw variant now retains the original parsed BTreeMap in Ebpf. It takes
pointers to entries after relocation and never mutates the tree afterward.
No extra function Boxes, owner Vec, reference counts or deduplication map.
It retains the original tree's storage, including any non-entry functions.

| Workload | Original (us) | Arc (us) | Raw tree (us) | Raw vs Arc | Paired 95% interval |
| --- | ---: | ---: | ---: | ---: | --- |
| One small program | 1.477 | 1.498 | 1.481 | -1.09% | -5.33% to +3.68% |
| 32 unique small | 22.316 | 23.626 | 19.875 | -15.88% | -17.16% to -14.51% |
| 32 small aliases | 18.541 | 18.249 | 17.288 | -5.26% | -6.60% to -3.95% |
| 32 unique large | 86.995 | 81.642 | 77.369 | -5.23% | -6.80% to -3.79% |
| 32 large aliases | 54.957 | 50.609 | 49.062 | -3.06% | -5.07% to -0.90% |

Single-small timing remains inconclusive. All four multi-program cases favor
the raw-tree variant over Arc in this run. Compare variants within this run;
absolute timing drift makes comparisons against previous runs unreliable.

| Workload | Original retained bytes | Arc retained bytes | Raw-tree retained bytes |
| --- | ---: | ---: | ---: |
| One small program | 1,522 | 1,114 | 2,810 |
| 32 unique small | 24,884 | 21,044 | 25,084 |
| 32 small aliases | 24,894 | 15,040 | 16,736 |
| 32 unique large | 287,540 | 283,700 | 287,740 |
| 32 large aliases | 287,550 | 23,248 | 24,944 |

Retaining the tree costs more live heap space than Arc in every measured case,
despite reducing total allocation calls and cumulative requested bytes.
These are requested Rust heap bytes, not RSS or kernel memory.

This is a benchmark-only lifetime design, not a sound replacement for Aya's
public API. Programs must not outlive their owner; the harness enforces this
by never extracting them. No production Samurai code was changed. The
benchmark measures actual ELF parsing/preparation, not BPF_PROG_LOAD,
attachment, or event throughput. Generated fixtures lack BTF/CO-RE; CPU
frequency and scheduling are uncontrolled. See README.md for reproduction.
