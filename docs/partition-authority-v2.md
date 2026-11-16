# Experimental partition authority

The local package implements the private v2 partition claim protocol. **Connected partition execution is not admitted.** The production service installs neither a qualified partition executor nor an explicit partition-agreement provider, so it advertises no partition offers. Existing whole-host consent and v1 readiness remain v1 only. The observed A100 and experimental runsc results do not change these gates.

The intended first shape is one external MIG GPU instance while local work occupies another GPU instance on the same parent. One compute instance per GPU instance and one platform borrower per host are supported by this protocol. It does not promise arbitrary multi-borrower packing, root access inside an untrusted container, or confidentiality against the host administrator.

## Durable ownership

An independent private registry at `/var/lib/nodus-dc-authority/fence.json` binds the database pathname, a random authority incarnation and a sequence. Every transaction after activation advances that registry before committing SQLite. Database rollback/replacement, registry loss or a crash between those writes refuses further authority operations. Do not remove either record to clear an error. Recovery requires a separately reviewed, explicitly drained recovery procedure; automatic restoration while any owner is active or uncertain is unsupported. The registry trusts the host administrator and does not defeat malicious root rollback of both stores.

Schema 4 prevents older package versions from ignoring allocation records. The first successful independent policy update advances state to schema 5, so published dev15 and earlier packages cannot reopen policy-bearing state. Fresh initialization commits separately before ordinary fallible request validation, so an unqualified/rejected request does not strand the host. A real interrupted registry write/SQLite commit remains fenced.

MIG configure records `changing` and advances a separate parent configuration generation before the first driver mutation. The existing exclusive parent maintenance lease excludes child allocations. A complete fresh observation commits the exact UUID/PCI/GI/CI/profile/capability devices and boot/driver identity. Ordinary inventory never adopts a configuration. Missing, stale, malformed or changed observation, or a continuity-monitor failure, durably quarantines it. Returning to the previous hash does not revive it.

Existing drained MIG layouts can be adopted explicitly under a live `gpu_configuration` lease:

```sh
nodus-dc --allocation-authority standalone adopt-partitions "$LEASE_ID" \
  --generation "$LEASE_GENERATION" --request-key adopt-layout-1
```

Use the normal reserve/release workflow to obtain and hand back that parent maintenance lease. Adoption is read-only with respect to GPU configuration and does not qualify the runtime or publish an offer. A polling hash cannot detect an unobserved A→B→A administrative change; an executor must supply independently qualified continuous configuration authority before offers or checks can pass.

## Private wire contract

All methods are POSTs under `/v2/bridge/partitions/` on the existing private bridge Unix socket. Local credentials, the local management socket and loopback HTTP cannot use it. Duplicate, missing, unknown and nonfinite fields are refused; v2 bodies are limited to 64 KiB. There is no v1 fallback.

An `offers` response contains at most 64 complete offers, allowing an eight-GPU host with seven instances per GPU when the complete serialized response also fits 64 KiB. A count or byte overflow refuses the whole report with `partition_offer_report_too_large`; it never truncates the list. This observation limit grants no execution permission and leaves the one-borrower-per-host and production-provider gates unchanged.

The optional request `{"include_host_budget":true}` adds `host_budget: {capacity, local_reserved}` to that same response. Both values contain exact `cpu_millis`, `memory_bytes` and `scratch_bytes` integers; local reservations may be zero. The authority computes this report and the offers in one serialized SQLite observation. `capacity` is the executor's enforced managed budget after system headroom, not physical inventory or utilization. `local_reserved` includes every unreleased local owner, including uncertain and draining leases. Platform reservations remain included in local admission checks but are excluded from this field: the platform must subtract its own retained/pending allocations exactly once. Unavailable permission or accounting returns `offers: []` and `host_budget: null`; missing proof is never a zero commitment. The legacy `{}` request still returns only `offers`. The complete budget-inclusive response retains the same count and 64 KiB limits.

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

## Partition permission delivery (unregistered)

`PartitionPolicy` implements the standalone half of permission delivery. The production service leaves both `service.partition_policy` and `partitions.policy_provider` unset. Context/update requests return `partition_policy_unavailable` until a trusted integration explicitly installs verified enrollment and independent local image-restriction callbacks. Installing this provider does not install a device observer or qualified executor. No new daemon, file watcher, platform credential file, or background poller is introduced.

Two additional POST routes use the same private socket and bridge credential:

* `/v2/bridge/partition-policy/context` accepts `{}` and returns `context: {nonce, boot_id}` plus `boottime_ns`. Both IDs are canonical nonzero UUIDs. The nonce is fresh for this process, independent of the persisted authority incarnation. The existing node agent must forward it through its authenticated Hello and receive the exact echoed context before updating policy.
* `/v2/bridge/partition-policy/update` accepts one of the strict variants below. Unknown, missing, duplicate and nonfinite fields are rejected. Integers are signed 64-bit nonnegative values unless specified otherwise. All requests and serialized responses remain bounded to 64 KiB.

Every update contains `action`, `context`, `node_id` (exact enrolled `bnod_` spelling), `host_epoch` (zero for ordinary BYOC, otherwise the exact positive reserved-host epoch), and positive `stream_epoch`.

| Action | Additional required fields |
| --- | --- |
| `grant` | `grant: {agreement, terms_json, allowed_images}` and `freshness: {echoed_boottime_ns, valid_for_ns, available_until_unix_millis}` |
| `withdraw` | `agreement` |
| `session_revoke` | None |

`agreement` retains exactly the existing four fields: `node_id`, canonical nonzero UUID `consent_id`, positive sharing `generation`, and lowercase `terms_sha256`. `terms_json` carries the exact UTF-8 bytes emitted by the platform's Go terms serializer. Its SHA-256 must equal the agreement digest; Python never reserializes terms to compute that digest. The parsed object must be valid `MIGPartitionV1` terms with exact priced shapes. The delivery subset permits at most 24 KiB of terms and `allowed_images` either null or at most 16 unique digest-pinned image references of at most 512 UTF-8 bytes each. The exact encoded response is checked before mutation; escape-heavy text may exceed the response limit even within those individual bounds and is refused without truncation.

`allowed_images` is an additional platform restriction. It intersects the independently supplied local partition image restriction; null cannot broaden local restrictions. Only digest-pinned Jobs are supported. The immutable grant comprises agreement, exact terms string and ordered image restriction. Same-generation differing immutable data is refused. Freshness is separate: `valid_for_ns` is 1 through 30,000,000,000; checked addition produces the fixed returned deadline `echoed_boottime_ns + valid_for_ns`. Future echoes, already expired deadlines and backwards heartbeat echoes are refused. Wall-clock `available_until_unix_millis` is an additional finite cap. Rolling renewal changes neither the immutable grant nor its local policy revision, and never changes an already held lease's frozen expiry.

Every update response has exactly `context`, `node_id`, `host_epoch`, `stream_epoch`, `state`, `policy_revision`, `grant`, `agreement`, and `valid_until_boottime_ns`. A grant returns state `active`, its exact grant and agreement, and the checked deadline. Withdrawal returns `withdrawn`, null grant, exact agreement, and deadline zero. Session revocation returns `session_revoked`, null grant/agreement, and deadline zero. Local policy revisions are positive; they change on replacement of permission/session or local restrictions, not ordinary renewal.

Positive permission exists only in memory. SQLite plus the independent registry retain immutable generation payloads, withdrawal fences, stream closure and local revisions. A restart starts with no permission and a new nonce; the same persisted stream cannot reauthorize it. A new authenticated stream/context handshake is required. Higher sharing generations supersede earlier ones even if an intermediate withdrawal was lost. Expiry durably closes the stream and retires its claims, including when an ordinary admission transaction must roll back. A delayed refresh cannot reopen that stream or publish fresh offers: a higher authenticated stream epoch is required. The old claim stays retired/held throughout; no new grant extends its expiry.

The existing six partition routes remain distinct. Offers, new claims and checks require current independent permission, exact runtime/device evidence and budget enforcement. Inspect, reclaim and complete require authenticated exact retained scope but do not require current permission. Withdrawal, expiry, session loss and uncertain replies never release hardware or host budgets. Only the original scoped cleanup proof releases a held lease; parent reset remains forbidden.

The wire allows one offer per compute instance. The provider selects the first canonical approved price shape matching the accelerator, MIG profile and GPU memory that fits available host resources. Its exact CPU/RAM/scratch bundle becomes `offer.capacity`; a claim must request that complete bundle. There is no proportional price fallback or implicit alternate-shape selector. Funded platform placement and the final resource-specific price remain separate requirements.

## Shared host resources and executor boundary

The durable host account includes all unreleased local and external leases, including draining and quarantined leases. An existing owner without a declared, verified budget blocks offers. Scratch is memory-backed and bounded within the same RAM limit; it is not an additional RAM allowance. Host capacity must already exclude operator/system headroom.

The local reserve API accepts an optional `host_resources` object with positive `cpu_millis` and `memory_bytes`, plus `scratch_bytes` between zero and the RAM limit. Budgeted local execution currently requires a hardware-partition lease and a qualified enforcement provider. Its Docker command applies CPU period/quota, equal memory/swap limits, a PID limit and bounded tmpfs/shared memory. Writable host output binds and published ports are refused for this bounded shape. Before starting a budgeted container, the backend inspects the created container and refuses any mismatch in resolved CPU, RAM/swap or scratch limits. Neither command construction nor this inspect gate proves that the target kernel enforced the limits.

The executor seam must provide `host_capacity`, `verify_host_accounting`, `qualification`, `prepare_reservation`, `verify_reservation`, `check_execution` and `verify_clean`. The read-only `verify_host_accounting(capacity, held, scope)` receives the exact configured capacity, all retained lease/resource pairs, durable authority incarnation and current parent configuration generations/boots. It must prove the actual managed isolation/accounting boundary reserves that budget against both current and future unmanaged work. A process-list snapshot is insufficient. If the host is not governed by such an enforced boundary, it must refuse. This prerequisite applies independently to every new Claim, every Check and budgeted local admission, as well as offer reports; an older executor without it advertises no offers. Missing or failed proof retains existing leases and cleanup authority.

`prepare_reservation` is a read-only prerequisite/plan operation: it must not create a container, cgroup or other external owner before the SQLite claim commits. Reserved leases require verified enforcement prerequisites; active leases require actual exact-owner limits. `qualification` must bind the observed device tuple and runtime digest and detect monitoring gaps. `verify_clean` must verify only that lease's device/runtime/cgroup ownership, retain uncertainty and never reset a parent. No production implementation of this qualified seam is shipped by this change. Reporting a shared budget does not remove the current single-borrower restriction or qualify multi-lease packing.

## Verification boundary

The owning Python seams use the real SQLite store and private Unix HTTP handler with declared synthetic device/enforcement providers. They cover sibling hierarchy, retained host budgets, exact lost-response/tombstone recovery, cross-version refusal, configuration-change intent, mismatch/monitor-gap quarantine, SQLite rollback, registry/commit interruption, expiry and changed agreement generation. Docker command tests verify requested limits, not live cgroups.

`examples/experimental/partition-authority-fixture.py` serves the real Python authority over its private socket for a separately invoked real Go-client integration exercise. It uses only synthetic GPU/enforcement data, a synthetic clock and a public fixture token; it performs no GPU or provider operations. It is not automatic CI infrastructure or an installed service. A successful cross-component exercise still cannot establish hardware isolation, resource enforcement, billing, product watchdog/restart or active-sibling preservation. Those remain required before publishing a supported configuration.
