# Recovering a quarantined GPU allocation

An interrupted start retains its lease even when no GPU process is visible. A
late Docker request might still execute. Do not delete the database, change its
lease rows, reset generations, or treat a clean process list as an execution
fence.

Ordinary installation, rollback and uninstall require all leases released. If a
software defect prevents recovery, a trusted operator can explicitly install a
compatible recovery-capable wheel while **every held lease is quarantined,
local and non-native**:

```sh
sudo systemctl stop nodus-dc.service
sudo python3 tools/install.py install \
  --wheel /secure/nodus_datacenter-CANDIDATE-py3-none-any.whl \
  --prefix /opt/nodus-dc --state-dir /var/lib/nodus-dc \
  --recovery-upgrade
```

Use the reviewed installer and wheel from the same candidate distribution, and
verify their artifact hashes first. This option requires an existing owned
installation, stopped daemon and no concurrent local command. The candidate
must open a consistent copy of the current SQLite state and advertise recovery
protocol1. Active/reserved/draining leases, external leases, native handoff or
terminal-return intent, incompatible old wheels, rollback and uninstall are
refused. Installation does not start a service, touch the GPU, release a lease,
or alter the authoritative database. The activation journal retains this
recovery intent across interruption; repeat the same command to finish it.

After collecting workload logs and ensuring that all other work is safely
stopped, reboot this operator-controlled host through its normal management
interface. A package or daemon restart is insufficient. Then invoke recovery
with the **original** lease identity and generation:

```sh
sudo /opt/nodus-dc/current/bin/nodus-dc \
  --state-dir /var/lib/nodus-dc --allocation-authority standalone \
  recover ORIGINAL_LEASE_ID --generation ORIGINAL_GENERATION \
  --request-key RECOVERY_REQUEST_ID
```

For a hardware-partition lease, recovery first requires every other allocation
on its original physical GPU to be released. The backend removes only that
lease's exact labelled containers, verifies a changed real boot ID, the same
host and physical GPU identities, PCI address, driver and memory capacity, and
fresh healthy, known-idle inventory for the parent and every present child.
Unknown processes, ambiguous device assignment, a busy sibling, missing
physical identity, or an invalid cleanup proof retain quarantine.

MIG mode and instance UUIDs may disappear across a reboot. Once the execution
fence and physical-parent cleanup are verified, recovery can retire the old
partition lease without recreating its UUID. The original resources, generation
and baseline remain in the audit record; cleanup records the observed current
geometry. It neither resets the GPU nor silently adopts a replacement MIG
instance. Configure a new desired layout under a new maintenance lease after
recovery succeeds. Perform a driver upgrade only **after** recovery, because
this proof deliberately requires the original driver identity.

Keep customer access closed until the operation reports `released`. A failed
proof remains quarantined and can be retried after correcting the observed
problem. A crash after the durable recovery intent also retains ownership and
can resume through this command. Native/root-customer handoffs require their
separate credential and provisioning protocol; this reboot proof does not
establish native customer return or hostile-tenant isolation.

CPU tests use declared synthetic device evidence. Actual device, driver and
container combinations require hardware qualification; this procedure does not
broaden the published support matrix by itself.
