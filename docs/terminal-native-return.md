# Terminal native owner return (unqualified dev2 candidate)

This command permanently retires a previously connected host installation before
its operator restores existing native SSH/customer access. It does not create
accounts or SSH credentials, enable SSH, provision or reimage a server, or prove
that a machine is safe to lend after a customer has held root access. After
return, this installation cannot reconnect, release its native host lease, or
lend again. A later return to lending needs a fresh trusted image and independent
operator provisioning; that cycle is not implemented.

The implementation is a candidate. CPU tests exercise durable SQLite transitions,
filesystem checks and simulated platform/service/device responses. These are not
actual GPU cleanup, Linux service shutdown, native customer login or hosted
retirement qualification. The platform must expose `credentialUID` on APIKey
`GET /auth/whoami` responses; earlier servers fail closed for this feature.

## Start with a dedicated connection key

Before this installation's first connection, create one dedicated, non-service-
account API key with exactly these organization scopes: `pools:read`,
`nodes:read`, `nodes:write`, `apikeys:read`, `apikeys:write`. Keep its token in one
private root-owned file; keep personal/session credentials off the host. This
key can retire the enrolled Node and itself. Only the human owner/admin can
accept or revoke sharing consent through the console.

Add `--terminal-native-return` to the normal `connection connect` command from
the first connection. Keep the same canonical token-file path, token, platform
origin, organization, pool and enrolled Node throughout this installation.
The runtime records a SHA-256 fingerprint and identity metadata, never the key.
A changed managed connection binding or an observed token rotation permanently
makes automatic terminal return unavailable. Identical CLI reapplication, daemon
restart and ordinary network reconnection preserve the tracked history; the flag
is required for the first connection. Restoring the
old file does not restore eligibility. The operator remains trusted before native
grant; this is not a claim to discover arbitrary secrets placed on a root-owned
host or to attest against an operator who edits local state.

Existing dev1 connection history cannot establish this guarantee. Upgrading
keeps ordinary local management and connected operation usable, but automatic
terminal return stays unavailable for those previously connected installations.
Once dev2 records connection history, authority schema version 2 prevents older
binaries from opening that state. Rolling back a package does not roll back the
retirement guard. Use dev2 to operate schema-2 state; never restore an old state
snapshot to bypass fencing. If an older package was activated, stop its daemon
and reactivate/reinstall the same reviewed schema-2-capable release against the
existing state directory. Keep the authority database, connection record and
physical-host registry. This is recovery by restoring compatible code, not a
successful downgrade to dev1. A tested schema-2-compatible older rollback target
does not yet exist; the new feature's downgrade/rollback criterion is incomplete.

## Return the host

1. In the Nodus console, revoke the exact host's accepted sharing consent. Wait
   for external reclaim, termination and cleanup to finish. A local disconnect
   alone does not revoke remote permission.
2. Run `connection disconnect`. All external claims and local workloads must
   already be cleanly released. Reserve a new unused `exclusive_host` lease via
   normal `reserve --resource HOST_ID --mode exclusive_host --ttl-seconds 3600`.
3. Run the following as root while native customer access remains closed. Supply
   the exact name of the current dedicated API key, not its secret. Preserve the
   request key for retries.

   ```sh
   nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone \
     native-return LEASE_ID --generation GENERATION \
     --request-key terminal-owner-return --api-key-name HOST_KEY_NAME
   ```

4. Only after the returned `native_access_ready` is `true`, restore the operator's
   existing native SSH/customer access using the operator's normal procedure.
   Nodus HostSSH remains disabled in connected local-authority mode. The command
   neither changes the customer's SSH keys nor claims to revoke root access.

The command supports the official Linux systemd `nodusd.service` and
`/var/lib/nodus/node.json` layout. An unconsumed
`/etc/nodus/bootstrap-token` blocks retirement. It does not stop Docker,
containerd, unrelated services or unknown owner processes.

## Durable retirement and failures

A single connection lock and host ownership lock prevent local admission races.
An unused, clean whole-host lease becomes a sticky native hold before any remote
mutation. The command verifies the exact accepted consent is revoked and binds
Node identity, API-key identity and request generation into its SQLite journal.
It then:

- Deletes the exact Node with its wire UID and resourceVersion preconditions,
  Background propagation, and requires the matching successful deletion
  acknowledgement. The platform transaction revokes all credentials bound to
  that Node and removes enrolled membership. Active external leases block it.
- Durably records that acknowledgement before deleting the exact current API
  key. API-key names are immutable and cannot be reused after revocation, so the
  UID-verified name lookup cannot target a replacement key.
- Waits 31 seconds on a monotonic clock, exceeding the documented 30-second
  authentication-cache bound, then requires HTTP 401 from authenticated HTTPS
  `GET /auth/whoami` using the revoked key. A restart repeats the entire wait.
- Stops and disables the installed nodusd service, verifies inactive/dead state,
  no main/control PID or pending job and the installed control-group kill policy,
  and removes only the bound managed token
  and node-identity files. Remote revocation is the credential fence; deleting
  files is cleanup, not evidence that copied credentials stopped working.
- Requires fresh, generation-bound device/workload cleanup evidence before
  recording native access ready. The whole-host lease remains held forever.

A crash after a durable stage resumes safely. A crash or lost response between a
remote DELETE and its durable acknowledgement leaves an **uncertain** journal
stage. The command refuses a blind retry or inference from HTTP 404, and cannot
grant access. Keep the host quarantined and use an external authorized operator
for platform reconciliation. Automated import of external retirement evidence
is not implemented; do not edit SQLite or restore a snapshot to advance it.
Network errors, HTTP 403, failed service stop, changed credential files or failed
device cleanup also keep access closed. The command never retries a paid job or
creates platform resources.

Lease expiry, drain, daemon restart and a new boot do not prove native customer
return. They can mark the native hold quarantined but cannot release its
resources. Repeating an already completed command returns the recorded terminal
result; it does not re-attest arbitrary subsequent root/customer activity.
