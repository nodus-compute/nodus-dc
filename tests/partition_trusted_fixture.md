# Real provider entry for the private Agent journey

The existing platform bridge child may explicitly call
`prepare_trusted_partition_fixture(private_dir, template_path, template_sha256,
expires_at=original_setup_deadline)` from `tests.partition_trusted_fixture`.
This helper is not an installed CLI mode or a production constructor. Importing it
does not inspect or change the host.

Before that call, the owning native fixture must establish the actual finite
allocation/shared cgroups and move the bridge, Agent and containerd processes into
their declared domains. It must supply the actual installed runtime, one qualified
physical GPU's observed partitions, protected qualification artifacts and exact
daemon/content-store paths. The root-private directory is existing, empty of the
helper's four fixed files, and mode0700. The template has the exact provider config
schema except `host_budget.authority_incarnation:null`; every other field is kept.
Its bytes are pinned by the explicit expected SHA256. No caller supplies a ready
boolean, replacement inventory, fake device reader or synthetic enforcement.

The helper uses the normal `NvidiaDockerBackend(allocation_authority="standalone")`
with current wall time and real `nvidia-smi` plus Docker inventory readers. A missing
or unhealthy existing reader refuses; this helper starts no Docker or containerd
daemon. The existing physical-host registry at `/var/lib/nodus-dc` and independent
fence at `/var/lib/nodus-dc-authority/fence.json` must be owned by this exact database
or not yet bound. A conflicting registry is never deleted, redirected or rewritten.

Only the actual newly initialized authority incarnation replaces the template's
null member. The fixed config is exclusively written and fsynced, then consumed
by `LinuxPartitionProvider` at its emitted exact hash. The existing complete host
accounting path validates the real empty envelope. The existing local parent
maintenance lease explicitly adopts the observed MIG configuration and is released
through normal positive cleanup. There is no MIG reconfiguration or device reset.
The setup deadline is caller-supplied, at most five minutes away, and never renewed.

The returned Service has the real provider, but no partition-policy callback or
policy installed. The existing bridge fixture must install its current real
`PartitionPolicy`, create its usual `BridgeUnixServer`, and return only safe socket,
image/budget/config identities through its existing private readiness channel.
Neither policy nor any creation capability is invented by this helper. The actual
qualified Claim/Begin/Agent journey remains required.

Any failure retains the exact database/config/physical-host provenance and any
uncertain maintenance lease for the owning fixture's normal reconciliation. This
helper neither deletes a registry nor fabricates a cleanup receipt. The full native
owner remains responsible for positive lease/runtime/kernel retirement before host
teardown; a setup exception is not closure. No helper or full-host behavior has been
executed by this source change.
