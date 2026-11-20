# Managed installation (unshipped)

The ordinary offline installer and standalone/Monitor commands are unchanged. The prospective
`install --managed` mode installs the same dependency-free public wheel only when the installed,
signed managed release already names a qualified Python installation. This repository contains no
such release. Operators do not write qualification JSON or pass readiness flags.

The managed bootstrap must be born without host site initialization:

```sh
sudo /usr/bin/python3.12 -I -S -B install.py install --managed \
  --wheel /path/to/the-reviewed-wheel.whl --prefix /opt/nodus/managed-local/python \
  --state-dir /path/to/the-managed-host/authority
```

This prospective command needs the installed genuine signed release and exact qualified host tuple;
it is not usable merely by downloading this source. A flag check inside Python cannot undo an earlier
host startup hook, so every installer/acquisition caller must supply `-I -S -B` from process birth.

Installation version 2 is a complete owned prefix, not a venv referring back to `/usr`.
The canonical path is `/opt/nodus/managed-local/python/releases/<wheel-SHA-first20>`.
It contains a regular exact copy of qualified `/usr/bin/python3.12`, selected complete stdlib bytes at
`lib/python3.12`, and this same dependency-free wheel at Ubuntu's non-venv `lib/python3/dist-packages`.
The public console and authority retain their ordinary isolated `-IB` and `-I -B -m nodus_dc` entries.
`current` is a user convenience link, never the protected executable pin.

Acquisition enumerates the entire source stdlib without following links. The measured census records
copied bytes and explicit exclusions: startup customization modules/packages, bytecode/cache files,
foreign site/dist-package trees and path-configuration files. Excluded symlinks are recorded by lstat
only; their targets/content are not trusted or copied. Acquisition version 2 has one explicit
compatibility exception: the root-owned `/usr/lib/python3.12/_sysconfigdata__linux_x86_64-linux-gnu.py`
link may name only the actual relative literal `_sysconfigdata__x86_64-linux-gnu.py`. The installer
checks that literal before opening the fixed same-directory regular, root-owned target with no group/other write permission.
The source row retains the actual symlink metadata and null source hash; separate target evidence
must match the independently enumerated ordinary source file. Both private destinations are regular
copies with identical target bytes, and both count against the original 512 MiB bound. Link, target
and parent identities remain fixed in memory across census and copying; replacement or drift refuses.
The exact relative entry `config-3.12-x86_64-linux-gnu/libpython3.12.so` is excluded as
`external-library-link`: Ubuntu installs this development link to its external multiarch library.
Its ordinary ten-field row retains only lstat metadata, with null destination/hash; acquisition never
follows or reads its target. The existing case requires that entry absent from the private tree.
This does not exclude the config directory or waive any actual ELF/mapped-library dependency identity.
Every other non-excluded source alias, alias chain, unprotected target or special file refuses. No host
file is deleted or changed. The complete private prefix admits no customization, `.pth`, `._pth`,
`pyvenv.cfg`, build-directory override, bytecode, aliases or extra import roots. The installed wheel
and all retained stdlib files must match the signed map; a different source/native tuple cannot replace
an existing same-wheel installation. No upgrade mechanism is added.

Qualification must observe all four actual prefix values equal the private prefix, exact ordered private
`sys.path`, private `sys._stdlib_dir`, every actual import origin, and recursive ELF/mapped-library closure.
A compiled `/usr` fallback or a libpython-dependent relocation mismatch refuses; version strings alone do
not establish portability. The signature binds actual source acquisition, OS/package/native identities
and the private file/directory map. Copied CPython, incorporated code and distribution files retain their
applicable PSF/third-party/distribution license and notice provenance; they are not relicensed as Nodus code.

Use the paired Go host directory's `authority` subdirectory as `--state-dir`. Managed install never
creates an absent Go host directory or authority. When a managed host directory already exists, replacement, activation and removal refuse; only
exact previously installed qualified bytes can report an unchanged result under its existing owner
and authority locks. Retained rows/history are not deleted. Upgrade/migration requires separate
qualification and is not inferred from a clean stop. Managed installation
starts no daemon and enables no external sharing.

Explicit fresh `install --managed` bootstraps cosign v3.0.6 for Linux amd64 at
`/opt/nodus/managed-local/verifier/v3.0.6/cosign-linux-amd64`. The reviewed installer
bakes its official SHA256 independently of the release and bundle it verifies.
Under the installation lock it downloads once from the fixed HTTPS release URL,
allows only HTTPS GitHub release redirects, limits bytes to 256 MiB and bounds the
child to 30 seconds within the original 120-second managed verification deadline.
It hashes private temporary bytes before executable mode, then publishes without
replacement. Exact protected 0555 bytes are reused; unsafe or different existing
files refuse. Existing managed host state permits no missing-verifier bootstrap.
Ordinary offline installation does not enter this path or download anything.

Both this installer and the paired Go preparation entry use that canonical path
and baked hash, with the existing fixed main-workflow signer and issuer. Neither
accepts a PATH verifier, alternate version or identity. Install the paired Python
package before starting `prepare-local-host`; the older preprepared service
installer is separate and has not gained this bootstrap. A download or checksum
match is not a successful signature or host qualification. Publication still
requires the actual cosign version/ELF dependency receipt and Apache-2.0 license
and notice custody, plus genuine signed-entry verification.

Publication must first preserve current public main/help, produce the final wheel/sdist/provenance,
review the minimal paired Go/runtime source export and dependency notices, and qualify the actual
installed import/native closure using the existing Linux distribution owner. The paired normal host
owner must then prove installed start/work/stop/resume and failed-setup retry. This source is not an
operator-ready release or a positive clean-host result.

The existing reproducible-build/offline-install distribution case has a separate opt-in Linux
component measurement arm. Its protected `NODUS_MANAGED_COMPONENT_INPUT` and separately supplied
SHA name one reviewed source/target and a fresh private output directory. The case uses its original
wheel, before constructing its synthetic upgrade wheel. One private mount/PID namespace and
task-owned overlays contain assembly and six restored refusal checks; all children share the
original 240-second component deadline, within the separately enforced 300-second case limit.

This arm runs the actual copied interpreter, public console, and `-I -B -m nodus_dc` observe-only
serve/status commands. A companion imports every shipped module except `__main__` (covered by
the actual module commands). Whole private-prefix files, source acquisition/exclusions, import origins, mapped native files and
recursive ELF dependencies are measured. Extra startup files, ambiguous loader-cache resolutions,
or a different expected OS/package tuple refuse. A hosted-runner result applies only to byte-identical
Python/OS/native installations; the same case must measure a different target separately.

The component signature subprocess is an explicit test seam around the installer
parser/checker. In its proved private parent mount/PID namespace and `/opt` overlay, the case invokes actual first verifier download under the
existing installation lock, unchanged reuse, missing-retained/alias/checksum refusals and restoration.
There is at most one official download within the original 30-second limit. Actual version/ELF output
must establish the pinned static Linux-amd64 verifier shape; an unexpected dynamic shape fails this
bounded phase. The parent then launches the measurement child with the unchanged 16 MiB soft/hard file limit
and the same original absolute end. Exact verifier device/inode/bytes/hash and inherited overlays join
both processes; natural joined exits and outer mount absence are required. There is no shared `/opt`
mutation or file-limit override. The production canonical file/hash check remains active.
No fake verifier executable, valid bundle, or signed release is produced. Controlled
assembly precedes measurement; `qualification_sha256` names the actual import-closure receipt.
Only a fully measured, naturally reaped, restored and cleaned case emits the twelve-file PASS set.
Early failures retain partial owned evidence without inventing a complete receipt. The result always
states `entry_signature_verified=false`, `host_lifecycle_qualified=false`, and `production_ready=false`.
Real signature verification and managed preparation/work/retirement remain later owning checks.

The existing outer distribution-test interpreter remains an ordinary harness seam. All managed child
bootstrap/measurement commands skip site from birth. The earlier retained native experiment already
records the old host `sitecustomize` import; this case never repeats that unsafe site-enabled host birth.
A known marker in the owning private `/usr` overlay checks corrected `-I -S -B` children. Before the
first private console/module command, the copied interpreter runs with `-I -S -B` and must show the
exact private pre-site prefixes, path and Ubuntu site-directory list. A host fallback refuses before
site-enabled execution. The private source copy contains no customization candidates or cached code.
The original host hook is restored before final source/target acquisition; no sentinel-overlaid source
tuple can be signed as the stock target. Six restored refusal records cover member tamper, extra startup
file, private-prefix override, interpreter alias, native alias drift and missing pin. They do not
substitute for genuine signature or installed managed-provider execution.
The same twelve outputs and original 240-second component/300-second case limits remain in force.

Component cleanup compares mount records for the exact source/output paths and the existing
`/usr`, `/etc`, `/opt`, `/var/lib`, and `/proc` isolation targets, including their ancestors and
descendants. An unrelated host mount disappearing does not establish an owned leak. Bounded raw
before/after snapshots (256 KiB each) and namespace identities remain in `closure.json`; whole
mount-census equality is reported separately from owned-mount closure. Every record is also checked
for owned scratch references, including overlay options and filesystem-relative bind roots. A new
bind of a scratch ancestor elsewhere refuses; the unchanged original covering mount remains valid.
Missing, malformed, truncated, ambiguously anchored or namespace-changing observations refuse.
The same case includes bounded pure projection/capture counterexamples; these are not native mount
evidence. Natural child/group closure, source and authority checks remain mandatory. The existing
4 MiB individual-output and 16 MiB total-output limits apply to the added evidence. Historical
failed measurements stay negative; this source change does not qualify any host or installation.

The same component owner checks the actual sysconfig pair and both regular copies, then requires
wrong-literal, target-chain, unprotected-target, same-byte link-replacement and same-byte target-replacement
refusals. Mutations occur only in its proved private `/usr` overlay. Original entries are restored,
and a fresh final census is taken; ctime restoration is not asserted. These acquisition controls are
recorded in the existing raw native evidence, separately from the unchanged six installation refusals.
The distro source defines the permitted literal, but neither the actual target nor a successful copy
is inferred from that policy: both remain required observations of the bounded Linux case.

### Prepared enrollment boundary (source-only qualification)

A separately reviewed Go installer may hand a positively stopped signed allocation to the normal
nodusd enrollment owner. Its protected record is generated by that installer, never authored by an
operator. The same Service/Store/fence/incarnation starts with the exact provider and private local
socket. Only its separate partition bridge is enabled; it rejects legacy whole-host bridge routes and
constructs no Connection worker. The `connection` CLI refuses this retained mode rather than creating
a second enrollment/synchronizer. `status` remains local inventory/leases and the legacy disabled
bridge-policy projection; it does not assert Agent registration or current partition-sharing permission.

Before opening the listener, the normal clean-start path requires every lease released, every
external claim retired, whole-host policy disabled, and the prior partition scope positively closed
(or no partition history at all). Full provider accounting still runs. Retained agreement rows do not
become permission: a new daemon starts with no live grant and a new nonce. Old nonce/same-stream replay
refuses, while a newer authenticated stream can renew the original agreement. On exit this same scope
proof must still hold; unknown closure is retained as failure. The Go owner preserves the original
finite deadline and local workloads across external stream loss. No enduring sharing activation,
automatic renewal, signed release, native qualification or real systemd activation is asserted here.
