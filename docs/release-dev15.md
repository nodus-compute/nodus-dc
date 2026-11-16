# Dev15 development prerelease: private partition authority

`0.1.0.dev15` is a development prerelease of the local GPU management package.
Its allocator and private protocol are verified within the limits below;
production GPU execution and connected partition lending remain unqualified.

## Known issue: MIG configuration on some Linux hosts

A hardware test of the published dev15 wheel on an A100 with driver 580.105.08 failed final MIG device verification with `partition_binding_unavailable` after configuration had begun. The maintenance lease remained held, and normal restoration was not verified. Experimental sandbox tests did not start.

A confirmed compatibility bug in this release requires exactly 24 hexadecimal characters for the NVIDIA module source ID; valid Linux hosts have also reported 23. This is a candidate explanation for the failed run, whose source ID was not captured. A fix is under validation.

Avoid using dev15 for new MIG configuration changes until the fix is qualified. If configuration has already failed, retain the authority state and held lease; do not delete the state or force a reset to bypass recovery.

Dev15 adds exact MIG device observations and a private v2 partition
authority. A local workload can retain one partition while the allocator reserves
a disjoint sibling for a platform claim. Durable incarnation and configuration
fences, exact request tombstones, and CPU/RAM/scratch reservations protect that
ownership. Cleanup must verify the exact lease; expiry or uncertainty retains its
reservations. Whole-host v1 consent remains separate.

**Connected partition execution remains unavailable.** The production executor
and explicit partition-agreement provider are unset. Synthetic providers exercise
the allocator; they are not supported GPU execution backends. No new lending
offer, scheduler integration, payment flow or host-confidential execution is
enabled by installing this prerelease.

The underlying authority source `84490a6eb05a6467bfc08a1608dc0def65585e3c`
passed 207 Python checks, with four optional checks skipped. An independent Linux
run exercised the actual Go client against that source's Python private socket,
SQLite store and external registry. It covered all six routes, sibling resource
accounting, stale scope, replay, cleanup, expiry and database rollback using
synthetic devices and enforcement. These are source-level protocol and allocator
results, not tests of a dev15 release wheel. Package, installed-path and
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
