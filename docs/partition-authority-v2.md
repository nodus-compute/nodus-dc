# Experimental partition authority

The local package implements the private v2 partition claim protocol. **Connected partition execution is not admitted.** The production service installs neither a qualified partition executor nor an explicit partition-agreement provider, so it advertises no partition offers. Existing whole-host consent and v1 readiness remain v1 only. The observed A100 and experimental runsc results do not change these gates.

The intended first shape is one external MIG GPU instance while local work occupies another GPU instance on the same parent. One compute instance per GPU instance and one platform borrower per host are supported by this protocol. It does not promise arbitrary multi-borrower packing, root access inside an untrusted container, or confidentiality against the host administrator.

## Durable ownership

An independent private registry at `/var/lib/nodus-dc-authority/fence.json` binds the database pathname, a random authority incarnation and a sequence. Every transaction after activation advances that registry before committing SQLite. Database rollback/replacement, registry loss or a crash between those writes refuses further authority operations. Do not remove either record to clear an error. Recovery requires a separately reviewed, explicitly drained recovery procedure; automatic restoration while any owner is active or uncertain is unsupported. The registry trusts the host administrator and does not defeat malicious root rollback of both stores.

Schema 4 prevents older package versions from ignoring these records. Fresh initialization commits separately before ordinary fallible request validation, so an unqualified/rejected request does not strand the host. A real interrupted registry write/SQLite commit remains fenced.

MIG configure records `changing` and advances a separate parent configuration generation before the first driver mutation. The existing exclusive parent maintenance lease excludes child allocations. A complete fresh observation commits the exact UUID/PCI/GI/CI/profile/capability devices and boot/driver identity. Ordinary inventory never adopts a configuration. Missing, stale, malformed or changed observation, or a continuity-monitor failure, durably quarantines it. Returning to the previous hash does not revive it.

Existing drained MIG layouts can be adopted explicitly under a live `gpu_configuration` lease:

```sh
nodus-dc --allocation-authority standalone adopt-partitions "$LEASE_ID" \
  --generation "$LEASE_GENERATION" --request-key adopt-layout-1
```

Use the normal reserve/release workflow to obtain and hand back that parent maintenance lease. Adoption is read-only with respect to GPU configuration and does not qualify the runtime or publish an offer. A polling hash cannot detect an unobserved A→B→A administrative change; an executor must supply independently qualified continuous configuration authority before offers or checks can pass.

## Private wire contract

All methods are POSTs under `/v2/bridge/partitions/` on the existing private bridge Unix socket. Local credentials, the local management socket and loopback HTTP cannot use it. Duplicate, missing, unknown and nonfinite fields are refused; v2 bodies are limited to 64 KiB. There is no v1 fallback.

The wire matches `nodus-platform/internal/node/authority/partitions.go`. Its nested Workload reuses the existing `workload_image` and `workload_kind` JSON names. Every response echoes the full immutable request; only an unknown local generation may resolve to the recorded positive generation.

| Operation | Result |
| --- | --- |
| `offers` | Current qualified observations, never execution permission |
| `claim` | Atomic child lease plus CPU/RAM/scratch reservation |
| `check` | Exact configuration, runtime, policy, agreement, expiry and enforcement revalidation |
| `reclaim` | Retires the exact immutable tuple before uncertain-claim inspection |
| `inspect` | Reports the original scope and whether it remains held |
| `complete` | Releases only after a positive exact-lease cleanup proof |

Tombstones retain the complete normalized payload, including workload, resources, offer and expiry. An unknown tuple acquires no device ownership and authorizes no device cleanup. All v1 tuple methods reject v2 tuples, and vice versa. A held completion requires its resolved generation. Failed cleanup, expiry and quarantine retain all reservations. No v2 method calls whole-host cleanup or resets a GPU parent.

Platform sharing generation is persisted separately from local policy and lease generations. An explicit current partition-agreement provider remains required; the current whole-host sharing response is never reinterpreted as partition consent.

## Shared host resources and executor boundary

The durable host account includes all unreleased local and external leases, including draining and quarantined leases. An existing owner without a declared, verified budget blocks offers. Scratch is memory-backed and bounded within the same RAM limit; it is not an additional RAM allowance. Host capacity must already exclude operator/system headroom.

The local reserve API accepts an optional `host_resources` object with positive `cpu_millis` and `memory_bytes`, plus `scratch_bytes` between zero and the RAM limit. Budgeted local execution currently requires a hardware-partition lease and a qualified enforcement provider. Its Docker command applies CPU period/quota, equal memory/swap limits, a PID limit and bounded tmpfs/shared memory. Writable host output binds and published ports are refused for this bounded shape. Before starting a budgeted container, the backend inspects the created container and refuses any mismatch in resolved CPU, RAM/swap or scratch limits. Neither command construction nor this inspect gate proves that the target kernel enforced the limits.

The executor seam must provide `host_capacity`, `qualification`, `prepare_reservation`, `verify_reservation`, `check_execution` and `verify_clean`. `prepare_reservation` is a read-only prerequisite/plan operation: it must not create a container, cgroup or other external owner before the SQLite claim commits. Reserved leases require verified enforcement prerequisites; active leases require actual exact-owner limits. `qualification` must bind the observed device tuple and runtime digest and detect monitoring gaps. `verify_clean` must verify only that lease's device/runtime/cgroup ownership, retain uncertainty and never reset a parent. No production implementation of this qualified seam is shipped by this change.

## Verification boundary

The owning Python seams use the real SQLite store and private Unix HTTP handler with declared synthetic device/enforcement providers. They cover sibling hierarchy, retained host budgets, exact lost-response/tombstone recovery, cross-version refusal, configuration-change intent, mismatch/monitor-gap quarantine, SQLite rollback, registry/commit interruption, expiry and changed agreement generation. Docker command tests verify requested limits, not live cgroups.

`examples/experimental/partition-authority-fixture.py` serves the real Python authority over its private socket for a separately invoked real Go-client integration exercise. It uses only synthetic GPU/enforcement data, a synthetic clock and a public fixture token; it performs no GPU or provider operations. It is not automatic CI infrastructure or an installed service. A successful cross-component exercise still cannot establish hardware isolation, resource enforcement, billing, product watchdog/restart or active-sibling preservation. Those remain required before publishing a supported configuration.
