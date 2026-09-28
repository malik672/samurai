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

Allocate all memory at startup. Don't allocate after initialization.

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
