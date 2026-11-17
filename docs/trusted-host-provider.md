# Private Linux provider contract

This is unregistered source for the experimental trusted-host profile. It does
not create a host envelope or establish host confidentiality. No installer,
CLI or connection flow constructs it. Full task M remains available; the same
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
`retirement_contract:"scoped-host-positive-retirement.v1"`, `runtime_identity`
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
scan. Root and shared CPU/RAM are subtracted once; each held row contributes its
aggregate C/A/S. Mixed legacy/profile owners refuse. Unknown root children,
partial owners, truncated inventories and unaccounted work close admission.
At most64 live claims and256 historical reservation rows are supported by this
initial profile; exhausting that finite history refuses rather than truncates.
Released provenance is read from the same SQLite rows to verify retained runtime
tombstones without charging A twice. No mutable parallel registry is added.

Retired but unreleased rows remain part of strict admission accounting. A retired
committed/issued binding (revision2/3) requires absence of its exact guard, owner
and H paths. A retired consumed/published binding (revision4/5) requires the same
full positive-clean owner proof used for released history, or admission refuses.
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

Cleanup is independent of equality to current limit values or current image bytes.
For a published/consumed owner it joins exact intent/removed/revoked/owner-empty,
guardian/retired, host-retired and all three per-mount unmount intents. It takes
the existing creator lock nonblocking, proves actual original cgroup identities,
no members, zero remaining owner/H charges and mount absence. Limit tampering
cannot turn that positive retirement into permission to execute. Missing/foreign
identities or a creator still holding the lock keep the reservation. A never-bound
or never-consumed row can release only because no creation capability has existed;
a consumed row with missing scope remains held for explicit reconciliation.

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
pre-pair creation uncertainty and incomplete mount evidence still refuse. This
slice adds no creator handle, abort tombstone, schema floor, ledger or service.
Original-call cancellation before the pair and actual sibling continuity require
the later bounded runtime/Agent proof; production registration remains absent.
