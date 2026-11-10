# Backend extension boundary

This distribution contains a new Apache-2.0 implementation of the local allocation authority. It does not bundle a separate research runtime. Extensions must preserve the ownership and cleanup contracts below.

* Inventory adapters return `Snapshot` and explicit whole `Resource` identities/capabilities. Unknown health/process inventory denies admission; there is no generic fractional-memory promise.
* A workload backend accepts an exact immutable lease ID/generation and returns matching runtime evidence. A custom context or checkpoint adapter must stay within one physical lease and one explicitly trusted application domain until stronger isolation is independently qualified.
* Cleanup returns typed `CleanupProof` tied to exact lease/generation/resource identities and fresh backend evidence. Releasing serving-engine memory or an application context cannot independently release the physical lease.
* Serving integrations are versioned by exact upstream source commits/image digests in `serving.py`; engine lifecycle and physical ownership are separate state machines. Version pinning is not hardware qualification.
* Kubernetes delegates physical admission to the existing scheduler and device plugin. A future DRA implementation must replace or integrate that authority, not run alongside it as an independent allocator.

Before distributing an additional backend: resolve its license and ownership, pin its complete dependency boundary, retain upstream notices, integrate exact lifecycle/fencing evidence, test crash/partial-start cleanup, and qualify its actual hardware/framework support against a preregistered performance target. CPU tests or benchmarks of another stack do not establish support.
