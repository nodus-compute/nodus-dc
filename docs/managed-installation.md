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
only; their targets/content are not trusted or copied. Unknown aliases or special files refuse. No host
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
bootstrap/measurement commands skip site from birth. A known hook exists only in the owning private
`/usr` overlay: the explicit old-startup control must execute it, whereas corrected bootstrap and private
runtime children must not. The original hook is restored before final source/target acquisition; no
sentinel-overlaid source tuple can be signed as the stock target. Six restored refusal records cover
member tamper, extra startup file, private-prefix override, interpreter alias, native alias drift and
missing pin. They do not substitute for genuine signature or installed managed-provider execution.
The same twelve outputs and original 240-second component/300-second case limits remain in force.
