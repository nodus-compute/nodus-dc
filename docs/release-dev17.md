# Dev17 development prerelease: exact package identity

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
