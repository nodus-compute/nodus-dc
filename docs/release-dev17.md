# Dev17 development prerelease: standalone A100 MIG lifecycle

`0.1.0.dev17` packages public source
`0429d47f56352720f391a6751a4b6171f417ad81` under a new version. All 26 non-version
Python runtime modules and the installer remain byte-identical to that source.
The serving recipe adds dev17 to its existing version allowlist without changing
the pinned framework images, model settings or workload descriptors.

The published dev16 wheel differs from that public source in `partitions.py`.
Its existing tag, checksums and assets must remain unchanged. Dev17 avoids placing
different bytes behind the old version or claiming that an unpublished source
build is the public dev16 artifact.

## Artifact validation and publication

Build the wheel and source distribution once on native Linux with the existing
standard-library build backend. Freeze both archives, the unchanged installer
and their checksums before hardware evaluation. Hardware work must install that
exact wheel; publication must upload those same retained bytes, not rebuild them
afterward. Verify the wheel's runtime modules, metadata and RECORD against the
reviewed source. A later publication must recheck that the new tag and release do
not already exist, then use the normal reviewed release process.

Keep actual qualification receipts outside the immutable wheel. A receipt must
name the artifact hash, source revision, GPU and driver, framework image, model,
request settings, outcome and cleanup scope. A version bump or source comparison
is not a successful GPU test. In particular, whole-GPU A10 serving observations
would not establish MIG support, connected Agent execution, host-administrator
confidentiality or inference consolidation benefit.

## Exact retained artifacts and standalone result

The release wheel is `nodus_datacenter-0.1.0.dev17-py3-none-any.whl`, SHA-256
`c20090c48a12f5aabff86f59c40dc2d5e70f7567d14b64187f819d41f8d4c732`.
The retained source distribution is SHA-256
`5e57a5f311fa536d64aff1f714aa198f0e6b41af48b3fd193730d83fc619fa89`,
built from `91cd83711c9939be0b6ed2bfc30e28aca9d19b6b`. The installer is unchanged,
SHA-256 `43b728d40533c89c42412a446bb5ed02429eb6cc23259a5b4e56fd8533c1a314`.
Native Linux packaging verified the wheel RECORD, source and installed hashes of
all 27 Python modules, installation and owned-fixture cleanup. The release keeps
those exact wheel, source-distribution and installer bytes. Repository and release
attachment documentation includes later wording fixes; it is not part of the
retained source distribution or a rebuilt wheel.

On November 19, 2026, that exact installed wheel passed a bounded standalone
public-CLI lifecycle on NVIDIA A100-SXM4-40GB, driver 580.105.08, Ubuntu 24.04:

- Create two `3g.20gb` partitions and run correct CUDA concurrently on distinct
  MIG devices, with their processes verified in the same GPU inventory sample.
- Release the first allocation while the second continues making CUDA progress.
- Reopen the durable state from fresh CLI processes, reserve the released
  partition with a newer generation, run CUDA again, and reject a stale release.
- Refuse conflicting physical-GPU and active-reconfiguration requests, then
  release every lease and restore the original MIG-disabled geometry without
  deleting the authority database or resetting the GPU.

The worker used the exact retained CUDA source and one recorded `sm_80` build;
its same resulting bytes ran in the digest-pinned CUDA image. Final observations
showed no workload containers or NVIDIA processes. The independent reader passed
and the task's instance, key, apps and storage were closed. The release's
`standalone-mig-qualification.json` records exact identities and scope without
changing the wheel's historical provenance. Earlier unsuccessful attempts remain
unsuccessful; this result does not reinterpret them.

This is one hardware/driver/workload combination. It does not establish inference
performance or output equivalence, connected work, daemon/systemd lifecycle,
post-reboot restoration, native customer return, payment or host confidentiality.

## Existing boundaries

This candidate adds no allocation backend or production registration. Partition
policy and execution providers remain unset. Installation does not enroll a host,
accept sharing terms or enable external work. Monitor remains separate from the
standalone allocator and Execute path. Host administrators remain trusted.

Historical results and failures keep their original source and artifact bindings.
The [dev16 change record](release-dev16.md) and [support matrix](support-matrix.md)
remain the record of those observations; there are still zero fully qualified
production configurations. Follow the [normal installer and recovery guidance](operator-workflows.md#recovery-and-upgrades)
and preserve held or quarantined state.
