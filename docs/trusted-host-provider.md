# Private Linux provider contract

This is unregistered source for the experimental trusted-host profile. It does
not create a host envelope or establish host confidentiality. No installer,
CLI or connection flow constructs it. The full task M limit is unchanged; the same
finite profile reserves A=M+H+O once, with S as total customer data and Internal
charged within H. Numerical sizing and the complete Agent path need their native
owning proof.

`LinuxPartitionProvider(config_path, config_sha256, clock=...)` consumes an exact
root-owned regular JSON file with protected ancestry. Its strict fields are:

- `version:1`, `host_budget`, `namespace`, `snapshotter`, `fifo_dir`, `content_root`.
- `creator_path`, `creator_sha256`, and at most sixteen `shared_executables`, each
  containing `path` and `sha256`.
- `runtime_identity` (the existing binding identity), `runtime_files` mapping its
  runsc/sentry/scoped-shim/containerd-shim/CDI digest keys to absolute files.
- `devices`, at most 64 exact admitted `{device, accelerator}` observations, and
  `qualification_path`.

The qualification record has exact fields `version:1`,
`retirement_contract:"scoped-host-workload-retirement.v3"`, `runtime_identity`
(excluding its own qualification digest), `creator_sha256`, `devices` and
`artifacts`. Its raw file hash equals `runtime_identity.qualification_sha256`.
Artifacts are at most128 unique `{path,sha256}` entries covering every CDI mount
source and hook executable, with exact set equality. The protected qualification
is an explicit operator admission of that runtime/device tuple; this reader does
not generate it or infer qualification from inventory. Current source has no
such production configuration. A native fixture must create its exact configuration
from actual bounded setup and retained qualification evidence.

The provider independently hashes bounded manifest/config bytes from the existing
containerd content store, rejects image indexes/foreign layer URLs and non-root
user forms, and joins the exact linux/amd64 manifest, rootfs chain, namespace,
snapshotter and compiled spec digest. Current containerd namespace metadata and
IsUnpacked are separate, repeated Go checks before Claim and before Prepare/Ensure.
A content hash is not a current unpack-state receipt. There is no BoltDB parser,
image pull, unpack, executor RPC or caller-ready boolean in these hooks.

The host budget binds a boot/authority incarnation, the actual namespaces and
finite CPU/RAM/PID root/shared controls by device/inode. Shared is one direct child
of the managed allocation root. The provider requires the authority and every
shared process to be inside that bounded domain with an admitted executable hash.
This is bounded cgroup membership verification, not a free-RAM or whole-host process
scan. Immutable capacity is root minus Shared; each held row contributes its complete
aggregate C/A/S. Additional memory admission also subtracts a fresh root.current
observation, as specified below. Mixed legacy/profile owners refuse. Unknown root children,
partial owners, truncated inventories and unaccounted work close admission.
At most64 live claims and256 historical reservation rows are supported by this
initial profile; exhausting that finite history refuses rather than truncates.
Released provenance is read from the same SQLite rows to verify retained runtime
tombstones without charging A twice. No mutable parallel registry is added.

Retired but unreleased rows remain part of strict admission accounting. A retired
committed/issued binding (revision2/3) requires absence of its exact guard, owner
and H paths. A retired consumed binding (revision4) requires full positive-clean
owner proof or the original-call abort proof below. Revision5 always requires the
full existing scope proof. Released history applies the same checks.
Directory names alone are insufficient. The complete A remains reserved until
Complete succeeds; this strict admission path neither releases capacity nor grants
a partial owner execution. Published-target renewal is a separate predicate below.

The provider verifies original v5 guard identity, raw `scoped-limits.json` and
Plan2 `host-scope.json` hashes, full MIG grant digest, fixed S/T/Internal identities,
owner/H controls and live guardian evidence. `metadata-intent.json` version2 binds
the same Guard, explicit Snapshotter, deterministic ContainerID/SnapshotKey and
original daemon identity. The snapshotter must equal the immutable binding image.
Canonical admitted `att_` IDs plus the bounded epoch always take the runtime's
ordinary `<attempt>-e<epoch>` key branch; arbitrary IDs/fallback approximations are
not admitted. Missing and older records
are not upgraded. Created-but-unpublished uncertainty stays reserved. Creation
uses only the original consumed capability and peer, never missing-owner fallback.

Daemon provenance comes from the corrected runtime's actual Unix SO_PEERCRED and
explicit root/state/address validation. The provider rechecks that original live
pidfd, boot/start ticks, namespaces, executable, socket and root/state identities,
and the daemon's retained open metadata-store FD/inode. It neither reads BoltDB
contents nor makes a daemon RPC. Content blobs must come from that same root's
`io.containerd.content.v1.content`; the daemon must be inside the bounded shared
domain. The socket alone may be root:root group-writable with no world-write bit;
its ancestry and all non-socket protected paths reject group/world writes.
Daemon restart, socket replacement or store-FD drift refuses, including cleanup.

Normal consumed/published cleanup requires the strict scope4 workload-retirement
pair described below. It preserves exact source/guard/metadata, original lock,
seven cgroup identities and mount retirement joins while allowing recorded
nonzero residual kernel charge. It does not claim instant physical freeing or
no future deferred charge. Missing/foreign identities or incomplete proof keep
the complete reservation. A never-bound or never-consumed row can release only
because no creation capability has existed; a consumed row with missing scope
remains held unless its original source-qualified call left the exact positive
abort proof below. Missing files alone never suffice.

The corrected, pinned runtime is responsible for actual container, task and exact
original snapshotter/key NotFound checks before durably publishing removed.json.
The provider independently verifies kernel retirement and exact receipt provenance;
it does not call receipt-only daemon metadata absence independent. Current older
runtime Remove code is insufficient for this contract, particularly its former
missing-container/orphan-snapshot path. Production registration stays closed until
that corrected source, the complete seven-hook/Agent path and native negative
cases are qualified together.

Each read pass has a finite two-second observation window, bounded file sizes and
bounded enumeration. These checks do not promise a physical deadline for a blocked
kernel or filesystem operation. The protocol's original policy/lease deadline is
rechecked before commit and is never reset by an observation. Secret creation
capabilities, image grants and request bodies are never stored in these records.

The custom source budget is approximately one thousand added production lines:
same-row protocol/reader-floor changes, real Unix-peer capability observation and
the concrete protected Linux verifier. SQLite supplies atomicity, containerd
supplies daemon lifecycle, and Linux supplies the kernel identities and limits;
none supplies this cross-component Ref/image/phase/creator/aggregate-retirement
join. The implementation reuses those mechanisms and introduces no process
service, scheduler, reservation table or production registration. Its size is a
review obligation, not evidence of qualification.

The reader caches at most256 immutable artifact hashes by freshly checked protected
path, device/inode, size, mtime and ctime. It does not cache kernel controls,
membership, mount state, ownership or readiness. Each request's creator observation
hashes its executable once and refuses metadata changes during subsequent pidfd
rechecks. These bounded content optimizations do not extend a lease or qualify
validation latency before the native journey measures it.

The original platform creation call keeps its finite issue/consume/local scope/
publish authority. Generic Check deliberately denies issued/consumed states, and
strict admission refuses partial owners. A runtime callback mutex alone does not
serialize a separate Agent watcher. Published renewal needs the separately typed
client route below; it never reconstructs original creation permission.

For an exact server-validated host-published target only, `_accounted_owner` may
retain another held consumed or retired-consumed row's full C/A/S. It independently
reads the protected limits/Plan2 scope pair and original Ref, boot, namespaces,
allocation root, binding/budget/device/spec hashes, owner/H control identities,
fixed topology and S/T/Internal mount identities. Both complete raw records are
required; a directory name or partial pair cannot qualify. Root/shared caps,
complete ownership census and the single shared subtraction remain mandatory.
No live kernel facts are cached. Two finite passes recheck the record identities,
control values, bounded membership and mount state.

Owner M+O and H remain separately capped, with swap0, burst0, pids512/64 and group
OOM policy; OOM-exempt members refuse. A sibling guardian may have exited and its
OOM counters may be nonzero while the original capped domain still accounts for
the held charge. Exact per-mount unmount intent plus fresh absence may replace a
still-mounted identity during retirement. Contradictory present intent, metadata,
guardian or retirement records refuse. A present metadata intent retains the
strict original daemon verification. None of these observations authorizes the
incomplete sibling or substitutes for its full positive cleanup proof.

The renewal target itself, released history and every default admission path keep
the strict owner validators. Unknown roots, missing/replaced capped identities,
pre-pair creation uncertainty and incomplete mount evidence still refuse. The
original-call abort reader below does not authorize renewal from partial evidence.
Actual sibling continuity requires the bounded runtime/Agent proof; production
registration remains absent.

## Original-call pre-pair retirement

Only a retired consumed revision4 can use `creation-intent.json` and
`creation-retired.json` in its existing guard directory. The intent remains strict
version2; the final record requires version3 / `scoped-host-original-abort.v3`
and the explicit nullable `Drain` field. Original proof2 is refused, not upgraded.
The qualified node binds its handle to the one opaque successful issue invocation
before consume. The reader does not reconstruct that handle or verify past joins
from absence: the pinned node record attests the original in-process join and prior
zero-charge observations. Only the fixed, joined original cleanup child is allowed
before this proof; it cannot create a guardian, runtime or workload.
The exact creator executable, qualification, full binding/lease, Creator, issue/start
hashes, limits, Plan2, shared domain and boot/time namespaces must agree.

Both records are bounded to 64 KiB, have exact fixed fields and integer forms, and
bind the retained raw intent digest. Seven original cgroup slots, three mount slots
and four underlying directory slots are fixed nullable identities. Null means
the original invocation never created that object and its exact path is now
absent; it cannot encode an unknown outcome. Present slots require prior empty
teardown and current absence. Optional pre-pair `scoped-limits.json` must match
the original slots/plan; complete scope, metadata, guardian or later retirement
records prohibit the abort proof. Malformed or mixed proofs never fall back to
normal scope cleanup. Successful v5 publication retains the required original
intent and validates it with the same strict tuple/codec; it never accepts a
`creation-retired.json` alongside that full scope.

`Drain: null` forbids `original-high-intent.json`, `original-high-outcome.json`
and their exact `.json.tmp` files. Nonnull Drain commits both raw file hashes:
losing either or both files refuses. The closed intent binds the original raw
creation intent, retained lock, retired revision4 and first cleanup boot interval
(positive int64, at most 10 seconds), plus at least one fixed Host/Owner target.
Each selected target joins its exact original path/identity and ten control values,
including the original finite caps, to a nonnull final populated0/current0 slot.
Retained Owner controls must also agree with any completed `scoped-limits.json`. Only joined outcome status0
qualifies; it does not replace actual zero-charge teardown and current absence.
The existing source-qualified runtime attests the historical child/proxy join and
timely first proof; the reader cannot derive either from present absence.

The exact Shared leaf and ordered 2..128-node ancestry remain present and unchanged
through every authority/tombstone replay. Existing canonical `max` descendants
remain bounded by the finite Shared root. Missing/replaced ancestry or changed
control identities/values refuse, even after Complete. Test-host disposal may
remove Shared only after final checks and without reusing that authority state.
Both sidecars use the existing 64 KiB / 512-node protected record parser with
closed fields, duplicate/type/integer rejection and repeated raw-hash/inode reads.
OSS does not impose a new JSON field-order or whitespace encoding; the qualified
Go writer is canonical and the exact retained raw bytes are hash-bound. Normal
scope4 uses qualification version1 / `scoped-host-workload-retirement.v3`;
original intent2/retired3 remains the strict-zero contract. Exact new
node/reader/source/artifact identities must be qualified together. Normal v5 cleanup refuses all original drain files and temporaries.

Under the retained protected bootstrap lock, the reader checks exact record and
directory identities twice, original topology absence and the absence of recorded
mount IDs/devices. Guard directory, lock and proof remain. Their retained name is
accounted separately from absent owner/H roots only after fresh positive proof;
unexpected names still refuse. Every other row preserves the all-three-root key
check, so a late ordinary guard-only/owner-only creation cannot be normalized by
sampling separate expected root sets after its earlier reservation validation.
All held C/A/S remains charged until Complete. Complete validates the exact target
plus root/shared envelope; it does not perform a second all-owner row scan. The
existing admission/renewal accounting still verifies every held owner and released
history before admitting capacity. No new table, reader floor, service or RPC is
introduced.

An already-positive proof can replay after the original caller exits, with fresh
kernel absence checks. A crash or lost handle before durable proof stays held.
Complete pair/metadata failures remain on strict v5 cleanup, without downgrade.
Old node/shim binaries are not assumed to understand new files; exact node/provider
source qualification must reject incompatible admission. Managed runsc/shim bytes
are unchanged. The HTTP/SQLite owning case uses real files/flock but synthetic
kernel history and envelope evidence; native original-cancellation/retirement and
the full Agent path remain unqualified.


## Finite H parent and one worker

Scope version4 retains the finite H parent and one exact `worker` child, and
captures EpochParent and GuardianParent identities before publication. Plan2 and
M/S/T/O/A are unchanged. Older normal scope/terminal records are refused, never
upgraded. The existing qualification file now requires
`scoped-host-workload-retirement.v3`. Scope4 commits the raw creation-intent2
hash and all seven group identities on the allocation device. Original abort3
remains separate: every present pre-pair slot still requires recorded zero charge
and current absence.

Active checks require empty direct H-parent membership, exactly one worker
without descendants, finite parent H/group-OOM1 and worker max/group-OOM0.
Existing CPU/PID/swap/burst controls, exact control identities, effective unfrozen
state, high=max and zero active OOM counters remain mandatory. Historical OOM may
be accepted for finite held accounting, retaining the complete A. Worker absence
requires its exact worker-offline record, source/guardian/mount joins and observed
zero population; its recorded charge may be nonzero.

Normal retirement uses protected `workload-offline.json` version1, then
`workload-retired.json` version1 committing its exact raw hash. The offline record
joins Guard, raw scope/creation hashes, creator lock and seven required nonnull
`{Identity,Populated,MemoryCurrent}` objects. Population is zero; memory values
are strict uint64 observations, not freed-byte claims. Worker memory agrees with
its earlier offline record. The source-qualified runtime attests creator/task/
helper/guardian joins and actual metadata/device closure before normal offlining.
The reader independently requires current absence of all seven exact paths and
all three mount identities, the current protected root/Shared envelope, original
daemon provenance, exact removed/owner-empty receipts and the locked final pair.
Fixed backing directories remain empty and protected. Unknown or temporary guard
entries, path recreation, owner-empty alone, missing/lost pair, older host-retired
or normal high files, and mixed original-abort files refuse. Incomplete offlining
cannot be resumed by this reader; no first final proof is reconstructed.

Complete validates this exact target and retained root/Shared infrastructure;
it does not add an all-owner scan. The same SQL rows retain released history.
Admission/renewal census accepts a guard-only normal history entry only after
fresh validation of the complete workload proof, preserving the ordinary
all-three-root rule for a late partial creator. Unknown retirement retains full A.
Root and Shared must remain unchanged for the entire authority/history lifetime.

## Conservative additional admission

The private profile hook `verify_host_accounting` now returns exactly
`{contract:"partition-host-headroom.v1",host_budget,memory_current}`. The budget
is the existing immutable shape; current is a freshly read, protected uint64
counter with FD/path identity checks and surrounding envelope validation. Bool,
float, negative or oversized values refuse. Old bool-only profile providers
refuse; ordinary nil-profile hooks remain unchanged. No public endpoint, SQL
column, ledger or caller-selected mode is added.

Only the authority's offers/new-Claim call site selects admission. After all
existing owner/history/census checks, available memory is the lesser of the
static root-minus-Shared-minus-full-held-A value and
`floor(max(0, root.max - Shared - sum(full held A) - root.current)/4096)*4096`.
Arithmetic is checked before fitting the complete new A, never raw task M.
Counter overflow or exhausted headroom closes new admission. Existing Check and
private creation continuation select continuation internally: every immutable
cap, exact target, owner, phase, deadline and all-owner check still applies, but
current usage exceeding max or leaving no additional headroom does not itself
revoke a valid owner. No live observation is cached.

This deliberately double-counts live and Shared usage, reducing utilization.
Deferred kernel charges may grow after the snapshot; cgroup memory.max can
transiently overshoot. This is finite containment plus conservative sampling,
not a universal no-OOM, physical-free or no-future-charge guarantee. The retained
ancestor's group-OOM policy can terminate Shared and sibling workloads. Full task
M/CPU/PID/scratch caps remain unchanged, but unconditional neighbor QoS or full-M
availability under ancestor pressure is not promised.

The existing HTTP/SQLite owning case covers typed values, byte/page headroom,
refused additional Claim with valid continuation, protected final-pair parsing,
nonzero historical counters, partial/lost/mixed records, replay/census and full A
on refusal. Kernel/history/runtime evidence in that protocol case is explicitly
synthetic. Static checks do not qualify native offlining, counter behavior, the
full Agent/MIG path or production registration; those remain closed pending the
joined native proof.
