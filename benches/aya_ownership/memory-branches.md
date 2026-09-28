# Memory and branch-counter comparison

Uses three allocation-instrumented trials per variant from the raw-tree run.
Values are median requested Rust heap bytes, not RSS or kernel memory.
Cumulative bytes include reallocations; peak and retained bytes are above the warmed baseline.
All variants returned to the baseline after dropping Ebpf.

## retained_bytes

| Workload | Clone | Arc | Raw tree |
| --- | ---: | ---: | ---: |
| single_small | 1,522 | 1,114 | 2,810 |
| unique_32_small | 24,884 | 21,044 | 25,084 |
| aliases_32_small | 24,894 | 15,040 | 16,736 |
| unique_32_large | 287,540 | 283,700 | 287,740 |
| aliases_32_large | 287,550 | 23,248 | 24,944 |

## peak_bytes

| Workload | Clone | Arc | Raw tree |
| --- | ---: | ---: | ---: |
| single_small | 4,901 | 4,576 | 4,300 |
| unique_32_small | 49,201 | 40,211 | 39,163 |
| aliases_32_small | 40,324 | 30,552 | 30,276 |
| unique_32_large | 574,513 | 302,547 | 301,819 |
| aliases_32_large | 311,188 | 38,760 | 38,484 |

## allocated_bytes

| Workload | Clone | Arc | Raw tree |
| --- | ---: | ---: | ---: |
| single_small | 5,346 | 5,021 | 4,745 |
| unique_32_small | 66,282 | 64,760 | 56,244 |
| aliases_32_small | 58,213 | 48,441 | 48,165 |
| unique_32_large | 854,250 | 590,072 | 581,556 |
| aliases_32_large | 846,181 | 573,753 | 573,477 |

## allocations

| Workload | Clone | Arc | Raw tree |
| --- | ---: | ---: | ---: |
| single_small | 37 | 37 | 35 |
| unique_32_small | 401 | 374 | 337 |
| aliases_32_small | 397 | 335 | 333 |
| unique_32_large | 401 | 374 | 337 |
| aliases_32_large | 397 | 335 | 333 |

## Branch prediction

`perf stat -e branches:u,branch-misses:u taskset -c 5 true` failed with
`The branches:u event is not supported`, both inside and outside the sandbox.
Exposed event-source devices: breakpoint, kprobe, software, tracepoint, uprobe.
No hardware CPU PMU is exposed in this environment. Branch counts and miss rates
are unavailable for all three variants; no ranking is inferred.

Timing measurements use separate uninstrumented builds. Raw pointers retain
the parsed tree and require the restricted owner lifetime described in README.md.
The memory advantage/disadvantage is specific to these generated fixtures.

Raw measurements: `target/aya-ownership/results-prepare-1790088671866074734/memory.json`.
