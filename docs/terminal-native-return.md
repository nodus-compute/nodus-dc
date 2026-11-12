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
`GET /auth/whoami` responses and the Node `retirement` read subresource for
normal retirement and uncertain-node recovery; earlier servers fail closed for
these features.

## Start with a dedicated connection key

Before this installation's first connection, create one dedicated, non-service-
account API key with exactly these organization scopes: `pools:read`,
`nodes:read`, `nodes:write`, `apikeys:read`, `apikeys:write`. Keep its token in one
private root-owned file; keep personal/session credentials off the host. This
key can retire the enrolled Node and itself. Only the human owner/admin can
accept or revoke sharing consent through the console.

The retirement check reads the normal APIKey object: identity from `metadata`,
scopes and project restrictions from `spec`. It refuses flat or conflicting
responses and never retains APIKey `status` or a returned token. Authentication
identity (`/auth/whoami`) and audit receipts keep their own response formats.
WhoAmI reports effective scopes, including the platform's implicit `models:read`
and `offerings:read`. The runtime requires exactly the stored retirement grants
plus those two reads, while the APIKey object's stored grants remain exact.
Do not add the implicit reads when creating the dedicated key. The same rule
applies to recovery keys; their stored grants additionally include `auditevents:read`.

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

A fresh installation can connect for metrics with `--participation disabled --terminal-native-return`, using that dedicated key from its first connection. This does not accept sharing terms. Keep the signed node agent's local-authority URL/token configured, the Pool's external participation disabled, and any unrelated remote workload routing off. Observation does not enable local policy or external claims. Later explicit `--participation enabled` retains all normal consent, workload and finite-availability requirements.

Participation history is durable. Missing/legacy history never means “never participated”; any enabled bridge policy permanently records `ever_enabled`, even if no external work starts. Returning to observation preserves prior consent and does not reset this history. A continuously tracked host that has never enabled participation may return without inventing or accepting capacity terms: the protocol verifies current remote nonacceptance, then requires the exact positive NodeRetirement proof after deleting the enrolled Node.

Existing dev1 connection history cannot establish continuous credential tracking. A compatible upgrade preserves ordinary local management but does not restore missing history. Previously tracked schema-2 connections retain the existing exact-consent-revocation path. New observation or enabled policy selects authority schema 3; dev5 and earlier refuse it. The installer checks the actual target's state reader before activation, leaving installed code and authority state unchanged on refusal. Compatible activation still requires stopping the daemon and respecting held leases. Never restore an old database to bypass this fence; retain the authority database, connection record and physical-host registry and restore compatible code when needed.

## Return the host

1. If this host ever enabled sharing, revoke its exact accepted consent in the
   Nodus console and wait for external reclaim, termination and cleanup. A local
   disconnect alone does not revoke remote permission. A genuinely fresh tracked
   observation host needs no consent to revoke, but remote sharing must be
   nonaccepting and no current accepted consent may cover it.
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
mutation. The command verifies either exact consent revocation or durable
never-enabled history with current remote nonacceptance, then binds Node identity,
API-key identity and request generation into its SQLite journal.
It then:

- Deletes the exact Node with its wire UID and resourceVersion preconditions,
  Background propagation, and requires the matching successful deletion
  acknowledgement. The platform transaction revokes all credentials bound to
  that Node and removes enrolled membership. Active external leases block it.
  Every new retirement requires a positive same-org, exact-UID
  `NodeRetirement` response with a revoked identity generation before key deletion;
  a missing Node, HTTP 404 or deletion acknowledgement alone is insufficient.
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
stage. Ordinary resume refuses a blind retry or inference from HTTP404.
Use the explicit recovery command below; keep native access closed until ready.
Network errors, HTTP 403, failed service stop, changed credential files or failed
device cleanup also keep access closed. The command never retries a paid job or
creates platform resources.

Lease expiry, drain, daemon restart and a new boot do not prove native customer
return. They can mark the native hold quarantined but cannot release its
resources. Repeating an already completed command returns the recorded terminal
result; it does not re-attest arbitrary subsequent root/customer activity.

An authenticated `GET /v1/leases/LEASE_ID/terminal-retirement` on the existing
local API projects retained retirement evidence. It requires the exact ready,
unexpired host lease and journal, the affirmative saved `NodeRetirement`, key
revocation/rejection evidence, and matching current inventory host identity.
The response includes the lease generation, Node and key UIDs, safe retirement
fields, and current host/boot IDs. It exposes no token, credential path, or file
fingerprint and changes no state. Local-only `native-handoff` and older journals
without affirmative retirement proof are refused. This observation grants no
authority and does not attest subsequent customer activity; an external owner
must independently bind the physical host and verify current platform retirement
and key revocation before granting access.

An older interrupted journal at `node_retired` may still have its dedicated key
but only the DELETE acknowledgement. Ordinary resume reads affirmative retirement
proof once with that key and saves it before key revocation; failed proof leaves
the key and quarantined hold intact. A saved proof is revalidated before this
transition. This does not repair already-completed journals after their key was
removed.

## Recover a stopped service that systemd marks failed

The stop check deliberately requires `inactive/dead`, disabled state, zero main
and control PIDs, no pending job, `KillMode=control-group`, and `SendSIGKILL=yes`.
A service whose processes ignored SIGTERM can be fully killed at its stop timeout
while systemd retains `failed/failed` with `Result=timeout`. The command refuses
that state and keeps the native hold quarantined. It does not automatically clear
the failure or grant access because the main PID disappeared.

Keep customer access closed. As the trusted host operator, inspect the exact
`nodusd.service`, its journal, and its entire owned cgroup subtree. Verify it is
disabled, has no pending job or main/control PID, and no known owned process is
still alive. For the official unit, the cgroup is
`/sys/fs/cgroup/system.slice/nodusd.service`: its absence, or `populated 0` in
`cgroup.events`, establishes that the whole subtree is empty. An empty top-level
`cgroup.procs` alone is insufficient because child cgroups can contain processes.
Unreadable, changed or unfamiliar cgroup paths are uncertainty, not cleanup proof.
Do not clear the failed state while any such uncertainty remains.

After independently establishing that quiescence and investigating the stop
failure, explicitly clear only this unit's failure marker:

```sh
sudo systemctl reset-failed nodusd.service
```

Then repeat the ordinary `native-return` command with the original lease,
generation, request key and key name. If recovery credentials were already
retired, repeat `--recover` without supplying a new recovery token. The command
must freshly verify the strict stopped state, managed-file cleanup and device
cleanup before returning `native_access_ready: true`. Resetting the systemd
marker itself never grants access or changes the authority journal. Do not edit
the database, remove the native hold, or bypass the normal retry.

## Recover an interrupted remote retirement

Repeat the same lease, generation, request key and original key name with
`--recover`. A retained exact Node retirement proof can reconcile a lost Node
DELETE acknowledgement using the original still-active key. If the exact Node
is still live, recovery reads its current resourceVersion and conditionally
deletes only the frozen UID. A missing or different Node never substitutes for
positive proof.

If the original key was revoked but its DELETE acknowledgement was lost, an
authorized operator must create a temporary, non-service-account API key in the
same organization. Give it exactly the original five scopes plus
`auditevents:read`, without project restrictions. Use the same human owner/admin
who owns the original key, so normal key-management permissions authorize its
retirement. Save it in a separate private root-owned file, then run:

```sh
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone \
  native-return LEASE_ID --generation GENERATION \
  --request-key terminal-owner-return --api-key-name HOST_KEY_NAME --recover \
  --recovery-token-file /var/lib/nodus-dc/recovery.token \
  --recovery-api-key-name RECOVERY_KEY_NAME
```

The introduction boundary is the command's acceptance of a private canonical
recovery-token path and exact key name. It durably records that unresolved file
fingerprint as an obligation **before the first authenticated read**. UID/org
discovery and the exact key metadata are then verified. A crash during discovery,
a wrong identity or an invalid credential cannot be forgotten by ordinary resume.
Only the path, fingerprint and identity/proof metadata are retained, never tokens.
Unrelated caller-owned credentials are outside automatic discovery and must not
be placed on the host before native grant.

For uncertain key deletion, recovery requires an exact same-org successful
`apikeys.delete` AuditEvent binding both immutable key UUID and name. The audit
scan is capped at20pages of1000events. Missing/expired evidence, permission errors
or exhausted limits remain quarantined. Every introduced recovery key must also
be irrevocably retired; all keys must return HTTP401 after one fresh31-second
monotonic wait before agent shutdown, file cleanup and final GPU verification.
The recovery key is retired last. A lost acknowledgement for that key can be
resolved by a subsequent tracked key; the journal accepts at most four. An
unresolved token revoked before its UID was discovered cannot be safely mapped
from its filename or a404 and remains quarantined. No database repair is supported.

After all keys are rejected, repeat the command with `--recover` and omit the
recovery file/name arguments to resume local shutdown/cleanup or read the terminal
result. Do not introduce a new key after agent shutdown. A later native-to-lending
cycle still requires independent trusted reprovisioning.
