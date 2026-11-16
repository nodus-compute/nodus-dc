# Dev16 development prerelease: MIG driver compatibility

`0.1.0.dev16` corrects NVIDIA driver observations that could prevent managed MIG
configuration from completing. It retains the local dashboard, standalone
allocation workflow and pinned vLLM/SGLang recipes.

## Changes

- Accept the observed 23- and 24-character hexadecimal NVIDIA module source IDs,
  preserving their exact values in device identity.
- Resolve either the unified `nvidia-frontend` registration or the split
  `nvidia`/`nvidiactl` registration with matching majors. Mixed, incomplete or
  conflicting layouts remain unavailable.
- Read the complete MIG minor table within a 128 KiB limit. Other driver metadata
  retains its 64 KiB limit; oversized or ambiguous observations are refused.
- Check fresh inventory, loaded driver identity and supported character-device
  registration before enabling/configuring MIG. Failed final verification keeps
  the maintenance lease and durably quarantines the configuration.
- Include the private partition permission protocol with explicit agreement,
  finite freshness, withdrawal and restart fences. Its production providers
  remain unset; installing the package does not enable partition lending.

## Observed hardware result

On November 16, 2026, an unpublished source build on an NVIDIA A100-SXM4-40GB
with driver `580.105.08` completed the normal managed workflow: create two
`3g.20gb` partitions, verify their exact device bindings, release the maintenance
lease, disable MIG and release the restoration lease. A subsequent fresh CUDA
allocation on the restored whole GPU completed a 1 MiB memory round trip and
normal release. Final inventory had no held leases or uncertain mutation.

The installed source was `2e86502fd826d0b2f0658e6f5494394063d605d5` and its wheel
SHA-256 was `47b27b15a253c8bdd4e47d386779e8886f0abaaf52149609487b957803f601aa`.
That wheel carried development metadata `0.1.0.dev15`; it was **not** the published
dev15 wheel or the dev16 release wheel. All 26 non-version Python runtime modules
in dev16 match that hardware-tested source byte for byte. Release packaging,
installation and downgrade checks are recorded separately with the release
artifacts. This is scoped evidence for the managed configuration/restoration
path, not complete product qualification.

The same experiment's separate sandbox phase failed before launching a workload:
its private Docker daemon could not bind an overlong Unix socket path. It provides
no sandbox execution or tenant-isolation qualification. Earlier failed hardware
runs and published release assets retain their original outcomes.

## Upgrade and limits

Use the [normal installer](operator-workflows.md#recovery-and-upgrades) after
cleanly stopping managed work. An already held or quarantined configuration is
not cleared by this update. Preserve its state and use the documented recovery
workflow; never delete authority records to bypass a failed check.

The first successful independent partition policy update advances authority state
to schema 5. Published dev15 and earlier packages must refuse that state. The
installer's downgrade checks use immutable published wheels and must preserve
the database, registry, held leases and active installation on refusal.

Connected partition execution, funded placement, customer bare-metal return,
host-confidential execution and production performance qualification remain
incomplete. Host administrators remain trusted. There are still zero fully
qualified production configurations. The recipe generator accepts dev16 without
changing the pinned engine arguments or numerical profiles.

See the [support matrix](support-matrix.md), [driver identity rules](driver-identity.md),
[private partition contract](partition-authority-v2.md) and
[operator workflows](operator-workflows.md).
