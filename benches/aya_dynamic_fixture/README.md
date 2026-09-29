# Aya dynamic benchmark fixture

`../aya_dynamic.patch` records the required changes to a sibling Aya checkout.
`dynamic_controlled_bench.rs` is included separately because it is a new file
in that checkout. The benchmark currently builds `~/eni/aya` and expects these
changes to be applied there.

The fixture loads one Aya program per producer CPU. Those programs share the
ring-buffer, configuration, and drop-counter maps; each retains a private CPU
filter map so every syscall is emitted exactly once.
