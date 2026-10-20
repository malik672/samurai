Zero Technical Debt

Code, like steel, is easier to change while it's hot. Do it right the first time, the best you know how, because you may not get another chance, and because quality builds momentum. This is the only way to make steady progress, knowing that the foundations are solid.


Performance

The lack of back-of-the-envelope sketches is the root of all evil.

Think about performance from the outset. The time to solve performance, and get the 1000x wins, is in the design phase, when you can't profile. It's hard to fix a system after implementation, and the gains are less. Have mechanical sympathy. Like a carpenter, work with the grain.

Zero Copy / Deserialization

Per core memory bandwidth is a new bottleneck:

    Do things in the most direct way possible
    Don't copy memory in the data planeidg whs
    Don't thrash the CPU cache
    Don't serialize or deserialize data
    Use fixed-size cache line aligned structs
    Align structs to their largest field

Static Memory Allocation

Allocate all memory at startup. Don't allocate after initialization. Kernel-side
state must use bounded BPF maps whose maximum capacity is fixed before the
program is attached. Runtime map insertion may occupy a preallocated slot, but
must never imply unbounded growth; capacity exhaustion and update failures must
be observable.

This centralizes and simplifies resource management, solves fragmentation, forces you to think through “the physics of the system”, and leads to an elegant design, with efficient, predictable performance.can I f

Cache Data-Plane State

Resolve and cache invariant data-plane state during initialization. This includes
mapped addresses, counter pointers, capacities, masks, and locally owned cursor
positions. Do not reconstruct pointers or reload invariant metadata for every
record.

Keep the consumer position in local state and publish diagnostics at an
amortized interval. Benchmark frontier caching against per-record reads for the
actual transport: Mold's measured per-record path is faster than its batched
path, so batching is not part of the current protocol.


Layer and Prior-Art Audit

Before proposing a new abstraction, optimization, or upstream contribution,
trace the complete path from producer to consumer in the current code. Inspect
both sides of every boundary and write down which layer already provides each
property: typing, ownership, allocation, copying, synchronization, validation,
and lifetime safety.

Do not infer that a property is missing from one API surface alone. A byte
slice may already borrow zero-copy transport memory; a producer may already be
typed even when the consumer API is type-erased; an application may already
own the protocol that connects them.

Separate transport, representation, and processing claims. In particular:

    Zero-copy transport does not imply a typed application API.
    A typed API does not remove producer/consumer synchronization.
    A schema can enable a precomputed processing plan without changing the
    transport.

Before claiming novelty or performance value:

    Read the producer API, consumer API, implementation, and tests.
    Find escape hatches that weaken the apparent type or ownership contract.
    Build the smallest working prototype on top of the existing API.
    Benchmark the isolated mechanism against the existing path.
    State exactly which layer changes and which costs remain.

Prefer an application-level wrapper when the application already controls both
sides of the protocol. Propose a library change only when the guarantee cannot
be implemented safely or efficiently above the library, or when repeated users
would otherwise duplicate a substantial abstraction.

# eBPF Hook-Based Profiler — Agent Guidelines

## Core Philosophy

This project is a hook-based Linux profiler built using eBPF
and Rust.

The profiler observes execution at explicitly instrumented
kernel and user-space hook points.

It does not provide complete instruction-level execution
tracing.

Every measurement and conclusion must be supported by
events observable through the installed hooks.

## Hook Selection

- Prefer stable kernel tracepoints when available.
- Use fentry/fexit where supported and appropriate.
- Use kprobes/kretprobes when necessary.
- Use uprobes/uretprobes for user-space functions.
- Verify kernel and architecture compatibility.
- Do not assume all functions can be safely hooked.
- Consider hook frequency and overhead before attaching.

## Latency Measurement

- Use a consistent monotonic time source.
- Correlate function entry and exit events correctly.
- Compute elapsed duration from matching timestamps.
- Account for recursion, nesting, and concurrent execution.
- Handle missing entry or exit events gracefully.
- Distinguish elapsed duration from actual CPU execution time.

Never describe entry-to-exit elapsed time as CPU time
without additional supporting measurements.

## Event Correlation

- Associate events with the correct process and thread.
- Preserve timestamps, CPU IDs, and relevant context.
- Use operation identifiers when tracing asynchronous work.
- Account for PID/TID reuse and incomplete lifecycles.
- Do not infer a causal relationship merely because
  two events occurred close together.

## Kernel-Space Efficiency

- Keep eBPF hook handlers small and predictable.
- Minimize work performed at high-frequency hooks.
- Avoid unnecessary map lookups and updates.
- Perform early filtering where appropriate.
- Prefer kernel-side aggregation when raw events
  are not required.
- Track observable event drops and map failures.
- Move expensive processing to Rust user space.

## Profiling Output

The profiler should report:

- Hook or function name
- Process and thread identification
- Event frequency
- Measured latency where available
- Minimum, maximum, and distribution statistics
- Relevant stack traces when explicitly captured
- Event loss and collection limitations

Never manufacture missing information.

## Analysis Principles

- Distinguish expensive function execution from
  delays caused by scheduling or waiting.
- Investigate repeated operations and unnecessary work.
- Pay special attention to tail latency.
- Do not assume the most frequently called function
  is the primary performance bottleneck.
- Do not attribute latency to a specific cause
  without supporting hook measurements.

## Correctness and Validation

- Test entry/exit correlation.
- Test concurrent and nested execution.
- Validate timestamps and duration calculations.
- Test behavior when events are missed.
- Measure profiler overhead on representative workloads.
- Verify that hooks detach and resources are cleaned up.
- Document limitations imposed by the selected hooks.

## Development Rule

Before implementing any profiling feature, establish:

1. What behavior must be measured?
2. Which hook points expose the necessary information?
3. What events and identifiers are needed?
4. How will the measurements be correlated?
5. What information cannot be observed?
6. What overhead will the instrumentation introduce?

Never implement a measurement based on assumptions
about events the profiler does not actually observe.
