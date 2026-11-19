# Managed installation (unshipped)

The ordinary offline installer and standalone/Monitor commands are unchanged. The prospective
`install --managed` mode installs the same dependency-free public wheel only when the installed,
signed managed release already names a qualified Python installation. This repository contains no
such release. Operators do not write qualification JSON or pass readiness flags.

The initial supported shape is a qualified host `/usr/bin/python3.12` copied to
`/opt/nodus/managed-local/python/releases/<wheel-SHA-first20>/bin/python`. The installer creates that
versioned venv with copies and without pip, verifies every member of the same wheel before writing,
and uses the existing activation journal. The managed authority runs with `-I -B -m nodus_dc`; the
public console script uses the same isolated entry point. `current` remains a user convenience link,
not a protected runtime executable pin.

The release signature binds the exact CPython patch, base stdlib/native files and aliases, loader cache,
pyvenv configuration, whole package tree and native qualification evidence. An extra module, package
bytecode, `.pth` hook, customization file, changed alias or unknown base/runtime refuses. A wheel hash,
Python version probe or local inventory alone is not qualification. No manifest or signature is emitted
by the installer.

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
the actual module commands). Whole stdlib/site files, import origins, mapped native files and
recursive ELF dependencies are measured. Extra startup files, ambiguous loader-cache resolutions,
or a different expected OS/package tuple refuse. A hosted-runner result applies only to byte-identical
Python/OS/native installations; the same case must measure a different target separately.

The component signature subprocess is an explicit test seam around the installer
parser/checker. Its owner must stage the actual independently pinned cosign bytes
at the canonical path before the case; the production file/hash check remains active.
No fake verifier executable, valid bundle, or signed release is produced. Controlled
assembly precedes measurement; `qualification_sha256` names the actual import-closure receipt.
Only a fully measured, naturally reaped, restored and cleaned case emits the twelve-file PASS set.
Early failures retain partial owned evidence without inventing a complete receipt. The result always
states `entry_signature_verified=false`, `host_lifecycle_qualified=false`, and `production_ready=false`.
Real signature verification and managed preparation/work/retirement remain later owning checks.
