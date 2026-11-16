# Dev15 candidate: private partition authority

`0.1.0.dev15` is a source and package candidate. The latest published download
remains dev14 until the reviewed dev15 assets are released.

This candidate adds exact MIG device observations and a private v2 partition
authority. A local workload can retain one partition while the allocator reserves
a disjoint sibling for a platform claim. Durable incarnation and configuration
fences, exact request tombstones, and CPU/RAM/scratch reservations protect that
ownership. Cleanup must verify the exact lease; expiry or uncertainty retains its
reservations. Whole-host v1 consent remains separate.

**Connected partition execution remains unavailable.** The production executor
and explicit partition-agreement provider are unset. Synthetic providers exercise
the allocator; they are not supported GPU execution backends. No new lending
offer, scheduler integration, payment flow or host-confidential execution is
enabled by installing this candidate.

The underlying authority source `84490a6eb05a6467bfc08a1608dc0def65585e3c`
passed 207 Python checks, with four optional checks skipped. An independent Linux
run exercised the actual Go client against that source's Python private socket,
SQLite store and external registry. It covered all six routes, sibling resource
accounting, stale scope, replay, cleanup, expiry and database rollback using
synthetic devices and enforcement. These are source-level protocol and allocator
results, not tests of a dev15 release wheel. Candidate package, installed-path and
artifact compatibility checks have their own exact-source receipts.

Schema 4 state requires the independent authority registry. Older packages must
refuse it; activation cannot discard that state or release held work. Stop the
daemon and use the normal installer only after cleanly releasing allocations.
An unresolved registry/database mismatch requires explicit drained recovery,
not deletion or restoration of one file. The owning installer regression uses
the immutable published dev14 wheel to verify downgrade refusal.

Serving engine commands and numerical profiles are unchanged. The recipe
generator also accepts dev15. No additional SGLang numerical profile ships here.

There remain zero fully qualified production configurations. Earlier A100
training and inference observations retain their original source, binary,
driver and workload bindings. The separate optimized inference benchmark is not
qualification of the packaged serving defaults. The experimental sandbox phase
stopped at CDI preflight before GPU probes; it provides no runtime qualification.
All earlier negative results and release assets remain unchanged.

See the [private partition contract](partition-authority-v2.md),
[device observation boundary](experimental-partition-lending.md),
[operator workflows](operator-workflows.md), and [support matrix](support-matrix.md).
