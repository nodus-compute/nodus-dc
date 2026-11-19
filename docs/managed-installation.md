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

Publication must first preserve current public main/help, produce the final wheel/sdist/provenance,
review the minimal paired Go/runtime source export and dependency notices, and qualify the actual
installed import/native closure using the existing Linux distribution owner. The paired normal host
owner must then prove installed start/work/stop/resume and failed-setup retry. This source is not an
operator-ready release or a positive clean-host result.
