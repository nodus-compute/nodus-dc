# Local API and ownership

All API requests use JSON. The dashboard and read-only GET APIs use loopback HTTP. Every mutating local API uses `unix:///run/nodus-dc/local.sock`; every bridge API uses the separate `unix:///run/nodus-dc/bridge.sock`. Production listeners require root, a root-owned 0700 parent, a 0600 socket, no symlink or group/world-writable ancestor, and OS peer UID verification. Bridge clients must verify the same path and peer identity before sending credentials. Loopback bearer authentication alone does not authenticate a server and is rejected for privileged calls.

Except HTTP `/health` and the HTML shell, routes require `Authorization: Bearer <token>`. Tokens are separate owned regular files, mode 0600, at least 32 characters. Local and bridge token values must differ. The browser uses the local read token; it cannot invoke privileged APIs without a root-peer Unix connection. Do not paste the bridge token into a browser. Bodies reject duplicate keys, unknown fields and nonfinite numbers. There is no permissive CORS policy.

Local token routes (GET also available over HTTP; POST only on the local Unix socket):

* `GET /v1/inventory`, `GET /v1/status`, `GET /v1/leases/{id}`.
* `POST /v1/reserve`: `resources` array, `mode`, absolute `expires_at` within 24 hours, `request_key`.
* `POST /v1/leases/{id}/start`: exact `generation`, `request_key`, `workload`.
* `POST /v1/leases/{id}/drain` and `/release`: exact `generation`, `request_key` (drain optionally `reason`).
* `POST /v1/leases/{id}/configure`: exact `generation`, `request_key`, `plan` with `enabled` and `profiles`.
* `POST /v1/leases/{id}/recover`: exact `generation`, `request_key`; requires a verified host boot transition.
* `POST /v1/leases/{id}/native-handoff`: exact `generation`, `request_key`, opaque `provisioner_reference`; records only a sticky private-operator intent, with no supported return/provisioning API.
* `POST /v1/reconcile`: empty object.

`GET /v1/status` returns the last inventory snapshot with its original
`observed_at`; it does not sample hardware or promise current GPU health. Request
`GET /v1/inventory` for fresh observations, as the local dashboard does on refresh.
Explicit `reconcile` also refreshes inventory. The daemon's five-second lease
maintenance checks expiry and interrupted launches without a redundant full GPU
scan; every admission and cleanup still obtains its own fresh evidence. `/health`
reports local maintenance/connection errors, not a hardware readiness proof.

`status` also returns a read-only `availability` projection from one database
snapshot. It reports each resource's local eligibility, supported available
modes, blocking lease IDs, and separate GPU/partition counts. Whole-host and
ancestor allocations block overlapping devices; expired and quarantined leases
remain held until verified release. Observe-only and Kubernetes authority never
report locally allocatable devices. Missing, future, older-than-30-second or
clock-uncertain observations report no available capacity. The dashboard expires
the view using the returned remaining freshness interval and marks failed reads
unavailable. `status` does not refresh hardware, reconcile, or change leases.

This projection is neither a reservation nor external lending eligibility.
Admission still performs the ordinary fresh resource and ownership checks.
Capacity participation policy is displayed separately; it does not establish
authorization for a particular external workload or a clean host handback.

Bridge token routes, all POST and only on the bridge Unix socket:

| Path under `/v1/bridge/` | Body | Result |
| --- | --- | --- |
| `policy` | `enabled`, increasing integer `policy_revision`, verified opaque `consent_reference`, `authorization_id`, `expires_at` | Current policy; any change drains existing external lease |
| `status` | `{}` | `available`, `policy_revision`, `reason` |
| `claim` | `platform_lease_id`, positive `platform_epoch`, `policy_revision`, `idempotency_key`, optional `expires_at`, exact `workload_image` and `workload_kind` | Local `lease_id`, monotonic `generation`, held/retired/state |
| `check` | platform tuple and exact `generation` | `authorized`; required immediately before launch and during execution |
| `inspect` | platform tuple | Held reservation even when revoked/dirty; never authorizes launch |
| `reclaim` | platform tuple, optional exact generation | Retires tuple; absent tuple gets durable tombstone before inspection |
| `complete` | platform tuple, optional exact generation, `cleanup_verified:true` | `released` only after independent backend checks |

The trusted bridge verifies the consent record/signature and customer association before storing its opaque reference. A bearer credential alone is not operator consent. The local runtime has no cloud account or signing key, and never automatically enables policy. The dashboard does not expose bridge credentials or policy mutation controls.

`connection connect --participation disabled` records an observation connection without accepting terms or creating a consent reference. It leaves bridge policy disabled and never authorizes a claim, including during sync/restart. The enrolled node agent must still use the local-authority socket/token; observe-only cloud enrollment is not permission to run jobs outside the local allocator. CLI connect/sync retain the separate bridge-token-file input.

Authority schema 3 records participation history. Only a fresh first observation with no prior connection, policy, claim or external-lease history can record `never_enabled`. Every enabled policy transaction, including direct bridge calls, records `ever_enabled` atomically. Disable, reconnect and package restart cannot erase this fact; absent or legacy history is unknown. Schema-2-only releases refuse schema 3. The existing installer probes the actual target binary against a private authority snapshot before activation.

The connection monitor checks the persisted enrolled-node identity before/after platform verification and on every claim/admission check. Its last verified permission must be at most 20 seconds old and not from the future. A slow platform response cannot extend this local freshness bound. The original availability window is at most 24 hours; it is an upper bound, not permission to ignore stale consent. Revocation/replacement of accepted consent, changed enrolled identity and explicit disconnect are sticky until another operator connection. Publishing new terms alone does not replace an existing immutable accepted consent: permission and priced offers continue to use that accepted consent until revoked/replaced. The digest returned by an explicit terms-accept request must equal the exact reviewed published digest.

New external claims additionally enforce the operator's explicit workload policy: either exact approved digest-pinned image references or all platform-qualified digest-pinned `Job` images. `workload_image` and `workload_kind` become immutable claim authorization metadata; retries with changed metadata fail. The internal `maintenance` kind is reserved for trusted node qualification/cleanup, not customer jobs. Missing workload metadata defaults only support synthetic/internal compatibility; production Connection policy denies unspecified customer images. Image approval is not a hostile-workload isolation or hardware qualification claim.

Socket listeners hold an owner-only lifetime lock, refuse an active endpoint, replace only an owned inactive socket and unlink only their own socket inode on close. HTTP rejects every POST before authentication/body parsing; local Unix rejects bridge routes and bridge Unix rejects local routes. Example local API request: `curl --unix-socket /run/nodus-dc/local.sock http://localhost/v1/reserve` with the separately supplied local bearer and JSON body. Avoid embedding tokens in shell history or command arguments.

The platform journals the tuple **before** claim. Claim replay returns the same reservation after revoke to recover an uncertain response, but only `check` authorizes execution. Reclaim is called before inspect to prevent delayed admission. If inspect says no held claim, the bridge must not reset GPUs or stop local owner workloads. Completing an unknown tuple creates a tombstone without touching resources. If a claim exists, cleanup must terminate the exact platform workload and verify it before complete. Generation may be omitted only for crash recovery of the immutable platform tuple. Completed tuples can never be reactivated.

SQLite transactions serialize admission and atomically record resource ownership plus external claims. A canonical physical-host flock binds a single database path; the per-state lock covers backend side effects. Lease generations never decrement. No expiration, failed RPC or low utilization frees resources. Authenticated local operators and root administrators are trusted.

Native handoff intent is rejected if the host is bridge-enabled, enrolled, has a connection record or has any durable connection/policy/claim history. A connection attempt records its durable marker under the same host lock before any remote GET/Accept; it is refused if a native handoff is already held. This prevents a normal-interface connect/handoff race. Native handoffs remain held through idle inventory, expiry, release, drain, restart and reboot recovery; expiration/drain produces quarantine. The local HTTP/Unix API has no native-return endpoint. The separate CLI [terminal native return](terminal-native-return.md) protocol retires continuously tracked platform credentials; it does not relax this never-connected native-handoff guard. The private-operator guard assumes the host has never been enrolled or granted remote permission outside the recorded system; it does not establish that fact against a dishonest root administrator.
