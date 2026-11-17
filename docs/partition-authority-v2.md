# Experimental partition authority

The local package implements the private v2 partition claim protocol. **Connected partition execution is not admitted.** The production service installs neither a qualified partition executor nor an explicit partition-agreement provider, so it advertises no partition offers. Existing whole-host consent and v1 readiness remain v1 only. The observed A100 and experimental runsc results do not change these gates.

The authority admits disjoint external MIG GPU instances while local work occupies other instances on the same parent. Each allocation contains one compute instance per GPU instance. Every retained local and external owner consumes the same enforced host budget; configuration and ancestor exclusion remain mandatory. This local capability does not establish connected multi-borrower placement, a compatible node journal, actual runtime isolation, root access inside an untrusted container, or confidentiality against the host administrator.

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

An `offers` response contains at most 64 complete offers, allowing an eight-GPU host with seven instances per GPU when the complete serialized response also fits 64 KiB. A count or byte overflow refuses the whole report with `partition_offer_report_too_large`; it never truncates the list. This observation limit grants no execution permission and leaves production-provider gates unchanged.

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

The durable host account includes all unreleased local and external leases, including draining and quarantined leases. An existing owner without a declared, verified budget blocks offers. Under the legacy accounting contract, scratch is memory-backed and bounded within the same RAM limit; it is not an additional RAM allowance. Host capacity must already exclude operator/system headroom.

The local reserve API accepts an optional `host_resources` object with positive `cpu_millis` and `memory_bytes`, plus `scratch_bytes` between zero and the RAM limit. Budgeted local execution currently requires a hardware-partition lease and a qualified enforcement provider. Its Docker command applies CPU period/quota, equal memory/swap limits, a PID limit and bounded tmpfs/shared memory. Writable host output binds and published ports are refused for this bounded shape. Before starting a budgeted container, the backend inspects the created container and refuses any mismatch in resolved CPU, RAM/swap or scratch limits. Neither command construction nor this inspect gate proves that the target kernel enforced the limits.

The executor seam must provide `host_capacity`, `verify_host_accounting`, `qualification`, `prepare_reservation`, `verify_reservation`, `check_execution` and `verify_clean`. The read-only `verify_host_accounting(capacity, held, scope)` receives the exact configured capacity, all retained lease/resource pairs, durable authority incarnation and current parent configuration generations/boots. It must prove the actual managed isolation/accounting boundary reserves that budget against both current and future unmanaged work. A process-list snapshot is insufficient. If the host is not governed by such an enforced boundary, it must refuse. This prerequisite applies independently to every new Claim, every Check and budgeted local admission, as well as offer reports; an older executor without it advertises no offers. Missing or failed proof retains existing leases and cleanup authority.

`prepare_reservation` is a read-only prerequisite/plan operation: it must not create a container, cgroup or other external owner before the SQLite claim commits. Reserved leases require verified enforcement prerequisites; active leases require actual exact-owner limits. `qualification` must bind the observed device tuple and runtime digest and detect monitoring gaps. `verify_clean` must verify only that lease's device/runtime/cgroup ownership, retain uncertainty and never reset a parent. No production implementation of this qualified seam is shipped by this change. Concurrent new claims serialize under the same local authority and SQLite transaction. A failed cleanup retains its budget and exact partition while disjoint siblings continue; releasing that one allocation cannot clean or reconfigure a sibling.

The owning synthetic Unix/SQLite journey starts local A, retains external B, then races two disjoint external requests for the remaining budget. Exactly one may acquire it. It exercises immutable replay, forged same-GI scope refusal, retained failed cleanup, exact release/reuse and unchanged A/B ownership. This source case is pending Linux execution; it does not prove GPU progress, runtime enforcement or funded platform multi-lease execution.

## Verification boundary

The owning Python seams use the real SQLite store and private Unix HTTP handler with declared synthetic device/enforcement providers. They cover sibling hierarchy, retained host budgets, exact lost-response/tombstone recovery, cross-version refusal, configuration-change intent, mismatch/monitor-gap quarantine, SQLite rollback, registry/commit interruption, expiry and changed agreement generation. Docker command tests verify requested limits, not live cgroups.

`examples/experimental/partition-authority-fixture.py` serves the real Python authority over its private socket for a separately invoked real Go-client integration exercise. It uses only synthetic GPU/enforcement data, a synthetic clock and a public fixture token; it performs no GPU or provider operations. It is not automatic CI infrastructure or an installed service. A successful cross-component exercise still cannot establish hardware isolation, resource enforcement, billing, product watchdog/restart or active-sibling preservation. Those remain required before publishing a supported configuration.

## Private execution identity and reader floor

The optional private `bind` operation accepts a positive exact `lease` and a runtime
`ref` (`attempt_id`, `epoch`). It freezes the full lease, local lease ID, observed
MIG/driver evidence, approved runtime/CDI/library/hook identities, and the digest of
the original reservation proof. This is identity only: the versioned
`partition-execution-binding.v1` contract does not establish a runtime owner,
installed limits, or executable readiness. Requested task memory remains unchanged;
it is not relabeled as an aggregate host reservation. A later limit contract must
charge full task RAM plus bounded host scratch and per-owner overhead, subtract
shared headroom once, and use the same versioned charge for fit and Claim.

The authority stores this binding under `nodus.execution_binding` in the existing
`host_reservations.enforcement` object. Providers cannot supply any `nodus.*` member.
Legacy provider hooks receive their original proof only after strict validation of
the complete reserved member and its lease binding. Unknown, null or unreadable
reserved data refuses; it is never discarded to manufacture valid enforcement.
The immutable digest excludes phase/revision and hashes the original provider proof
without self-reference. There is no second ownership ledger.

`begin` accepts the exact lease/ref/binding digest and expected revision 1. It commits
`committed/1` to `materialization-begun/2` before any future side effects. Retrying that
same CAS returns the same revision; different/stale inputs refuse. Neither operation
accepts a caller-selected phase or `runnable`. Existing Check means current permission,
not materialization completion. Reclaim and policy retirement advance once to
`retired`; Complete still requires exact independent cleanup proof. Released claim
and reservation rows retain the full binding and terminal phase; they cannot revive.

The first successful bind commits schema floor 6 through the existing write-ahead
fence protocol. The registry and SQLite fence tuple acquire the exact optional
`reader_schema: 6` field together with their sequence. d9/dev16 readers opened before
binding reject this unknown field on their next authority transaction; newly opened
readers also reject schema 6. A failed precommit bind leaves the prior floor. A crash
after registry write retains the ordinary registry/SQLite mismatch refusal, with no
repair or sequence reset. Policy updates cannot lower this floor. An old reader may
still perform read-only inventory observation before reaching its transaction, but
cannot pass the tested execution/provider callbacks or commit mutations.

The existing real Unix/SQLite journey and Go client seam cover identity/CAS replay,
full task memory, malformed reserved data, retirement and sibling preservation. The
owning distribution case keeps actual pinned d9 and dev16 Store processes open before
first binding, then checks refusal of Check/Claim/Reclaim/Complete/local start/release,
zero execution-provider calls, unchanged database/registry and reopening refusal.
These new cases require bounded Linux qualification; no runtime, GPU, aggregate limit
or production provider qualification is implied.

## Closed ephemeral aggregate profile

The private lease may carry `ephemeral` with exact contract
`scoped-ephemeral-test.v1`. Absence preserves the legacy protocol; null, empty,
unknown or malformed values refuse. This test profile freezes a spec digest,
explicit unsupported-feature refusals, declared input ceilings and a normalized
charge. It does not install host scratch or make a lease executable. Profile
Check is always unauthorized; bind/begin return `ephemeral_enforcement_unavailable`.

Task CPU C is 10..64000 millicores; task memory M is 64 MiB..1 TiB and scratch S is
4 KiB..64 MiB, both page aligned. The fixed charge is stage T=2S+8 MiB,
host H=S+T+128 MiB helper+64 MiB metadata, owner O=128 MiB. The reservation is
`{cpu_millis:C+350, memory_bytes:M+H+O, scratch_bytes:S}`. The lease retains full
task C/M/S. Scratch remains a separate ceiling and is not added to RAM subtraction
again. Input bytes mean the sum of positive declared `max_bytes` ceilings, not a
measurement; up to 16 inputs and 16 outputs fit the profile. Continuity must be
ephemeral, with no restore manifest, checkpoint policy, snapshot/lazy inputs or
outside outputs. The platform must independently compile and verify the spec.

Profile offers require `include_host_budget:true` and
`accounting_version:"partition-aggregate-test.v1"`. The existing `host_capacity`
hook receives that keyword and must return exactly `{accounting_version,capacity}`;
the host must already exclude shared headroom once. No raw physical capacity or
legacy task reservation is reinterpreted as an aggregate budget. The existing
accounting-verifier scope includes this version. The first slice refuses mixed
live legacy/profile reservations until a qualified mixed accounting contract exists.

The unchanged `prepare_reservation(lease,resources)` hook receives the aggregate
vector and must return the same `accounting_version` in its original proof.
This remains a prerequisite/plan hook, never an instruction to materialize H.
The authority adds `nodus.ephemeral_claim` provenance binding the exact lease and
original proof digest to the aggregate row. Provider verification receives the
aggregate row and original proof only after validation. Missing, altered, or mixed
reserved metadata refuses. Local Docker task limits are unchanged; they do not
accept aggregate rows. Released claims retain this provenance after exact cleanup.

The first successful profile Claim advances schema/registry reader floor to 7 in
the same write-ahead transaction. Already-open and fresh ecfa/floor6 readers must
refuse before provider execution or mutation. Failed admission leaves the old floor;
registry-before-SQLite interruption remains an unrecoverable mismatch without drained
recovery. Existing Unix/SQLite and distribution cases cover this contract, including
concurrent aggregate fit, full M, retained failed cleanup, and real old-reader refusal.
These additions are source-only pending bounded Linux verification. Production
provider registration, aggregate kernel enforcement and funded dispatch remain closed.

## Private trusted-host execution binding (source only)

An explicitly constructed `LinuxPartitionProvider` can validate the proposed
qualified-image Claim and execution binding v2. It is not registered by the
service, installer or connection flow. Ordinary v1 binding and unqualified
aggregate reservation behavior remain unchanged. This source is not native
qualification, production readiness, funded placement, or host confidentiality.

Qualified Claim adds `qualified_image` to the existing flat request; the lease
wire stays unchanged. The first accepted qualified Claim raises the same
write-ahead SQLite/registry reader floor to 8. The immutable provider proof retains
the exact image, host budget and provider configuration digest. Binding v2 stores
both authority provenance members in the same reservation row: task resources
remain C/M/S, the reservation remains aggregate C/A/S. A runtime Ref cannot be
reassigned to a different lease, even after release.

The only creation permission comes from the existing Begin transaction:
`committed/1 → creation-issued/2 → creation-consumed/3 → host-published/4`.
Issue returns random capability A once and stores only its hash. Consume verifies
A and the exact live Unix peer, burns A and returns a distinct B once. The peer
identity comes from SO_PEERCRED, a live pidfd, boot/start ticks, executable bytes
and PID/user/cgroup namespaces; no request supplies a PID or an original-call flag.
The original platform call keeps B transiently in memory. Replaying or recovering
a transition never returns either capability. Lost responses go cleanup-only.
Plain Check cannot recover creation permission; B permits repeated read-only
creation checks only in phase3. Publish requires independent current owner/scope
verification before phase4; B stops authorizing after publication. Reclaim is
terminal from every phase and keeps the full reservation until positive cleanup.

The provider uses the existing seven hooks and the existing SQLite authority;
it owns no ledger, service or mutable readiness inventory. It reads only bounded
protected files, kernel cgroups and mount/process identities under the authority
lock. It never calls back into the Go executor. See
[the explicit provider configuration and proof boundary](trusted-host-provider.md).

The Unix/SQLite owning cases use actual Linux socket peer identities and source-pinned
old b18 readers, but explicitly synthetic GPU, image and enforcement facts. Those
cases cannot qualify the Linux provider or a full Agent/MIG lifecycle. The existing
full Agent journey must establish the real host envelope, image cache and runtime,
then prove normal completion/STOP, unchanged sibling and exact retirement before
production construction can be enabled.

Retired v2 Bind is a cleanup-only identity read: the existing endpoint validates
its full stored lease, Ref, proof and independent authority fence, then returns
the unchanged binding with terminal phase/revision. It does not consult live
permission or issue a creation token, and a different Ref refuses. This permits
normal cleanup after expiry/restart without reauthorizing a job. Generic Check,
Begin and runtime creation remain denied; unproved cleanup still retains A.
The legacy v1 Bind contract is unchanged.

An optional literal `purpose:"retirement"` on that same Bind endpoint returns
exactly `{contract:"partition-retirement.v1", lease, disposition, state}`. The
request still carries the exact full lease and a valid Ref. It requires the
retired qualified row, matching floor8 authority fence and original complete
reservation proof; it invokes no inventory or provider admission hook. Absent
purpose retains the existing Bind behavior; null, unknown purposes and legacy
leases refuse this additional read.

`never-bound` means no execution binding was ever stored in this row: state is
null, and the supplied Ref is not echoed as observed ownership. A stored retired
v2 binding must match the exact requested Ref and full lease. Its revision2/3
returns `never-consumed`; revision4/5 returns `scope-required`, both with the full
unchanged terminal state. Replay is an identity read, never a creator capability.
These dispositions do not prove kernel/daemon absence or release the reservation.
The caller still performs its ordinary teardown and Complete still requires the
provider's positive cleanup proof. A consumed row with missing scope stays held.

Published renewal uses the existing Check request with one optional exact
`published_ref:{attempt_id,epoch}`. Presence is mutually exclusive with
`creation_token`, including null; malformed Ref, legacy lease and non-published
target refuse. The server derives the target from the current same-row qualified
binding, exact full lease and Ref, and requires phase `host-published`, revision4.
The reply remains `{lease,authorized}`. No request carries a ready flag or chooses
an accounting strength. Default Check, Claim, Bind, Begin and creator checks retain
strict admission accounting.

Only that published target's accounting pass receives an internal
`renewal_target:{local_lease_id,binding_sha256,ref,phase_revision:4}` context. Exactly
one live held row must match. The target's image, policy, live owner, device and
expiry checks stay strict. Other held consumed or retired-consumed rows can retain
their full C/A/S using the finite record-pair predicate described in the provider
contract. Released history never uses that predicate. No reservation or phase is
changed by renewal, and no incomplete sibling becomes executable or clean.

The paired Go client must route only this typed request around its creation gate;
ordinary requests remain gated. Without that integration an Agent can still wait
before HTTP until its prior guardian deadline expires. A fresh authorized sibling
renewal does not extend the original creator's deadline. The existing Unix/SQLite
case exercises routing with synthetic owner evidence; real kernel continuity and
the complete Agent path remain unqualified. Consumed cancellation before a complete
record pair still requires separate positive original-creator retirement work.
