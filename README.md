# Nodus Datacenter

Local GPU inventory, explicit allocations, controlled hardware partitioning and opt-in capacity participation. The local runtime works offline without a Nodus account. This is a development release; CPU verification is not hardware qualification.

## Current implementation

| Mode | Scope | Boundary | Qualification |
| --- | --- | --- | --- |
| Observe | NVIDIA GPU inventory and utilization | No allocation ownership | Parser/HTTP CPU tests |
| `exclusive_gpu` | One or more whole GPUs | Exclusive scheduling within this authority; Docker device selection | GPU qualification pending |
| `exclusive_host` | Entire host GPU inventory | Whole-host allocation lock | GPU/host qualification pending |
| `hardware_partition` | Existing whole MIG instances | NVIDIA MIG hardware boundary; driver/platform limits apply | GPU qualification pending |
| `gpu_configuration` | One physical GPU maintenance lease | Exact-device MIG create/destroy plan; no automatic reset | GPU qualification pending |
| `trusted_mps` | One whole GPU, 2–16 cooperating clients | Shared IPC/PID namespaces; cooperative compute/memory settings, **no hostile-tenant isolation** | Explicit opt-in; GPU qualification pending |
| Native handoff intent | Sticky guard on an unused local whole-host lease | Refuses connected/enrolled/history-bearing hosts; expiry quarantines, never auto-returns | No SSH provisioning or supported native return adapter |
| Connected | Whole-host external lease only | Shared authority, explicit finite consent, monotonic generation, verified cleanup | Cross-component/hardware qualification pending |
| Kubernetes | Pinned vLLM/SGLang Pod and NetworkPolicy generator | Existing scheduler/device plugin owns GPU resources; no local co-allocation | GPU cluster qualification pending |

AMD, Intel, vGPU licensing, CUDA interception, hostile multi-tenant MPS, VM passthrough, live migration and fractional external lending are not implemented by this package. Model sleep is not permission to lend a GPU.

For an existing GPU cluster, use `python -m nodus_dc.kubernetes render` and follow [Kubernetes integration](kubernetes/README.md). Run local inventory in `--allocation-authority kubernetes` mode on those nodes. Generated resource requests use the cluster's actual device-plugin semantics; `nvidia.com/gpu` alone is not a claim of exclusive hardware isolation.

## Offline build and install

Python 3.11+ is required. Runtime/build have no third-party Python dependencies. Build uses only the standard library and produces deterministic wheel/sdist archives:

```sh
python3 build_backend.py
python3 tools/install.py install --wheel dist/nodus_datacenter-0.1.0.dev2-py3-none-any.whl --prefix /opt/nodus-dc --state-dir /var/lib/nodus-dc
```

Installation does not start services, change drivers or opt into participation. Preinstall a supported NVIDIA driver, Docker and NVIDIA Container Toolkit. Preload digest-pinned workload images and model files; the runtime never pulls them. Run the Linux daemon as the trusted host operator with Docker/GPU management permissions. Actual allocation binds a canonical authority registry in `/var/lib/nodus-dc`, so it normally requires root. Do not expose Docker or the local token to customers.

```sh
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc inventory
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone serve
```

Open `http://127.0.0.1:7441/` and enter the local token from the daemon's printed file path. Use SSH port forwarding for remote viewing. The dashboard keeps the token in memory only. Default authority is `observe`; choose `standalone` only after draining other schedulers and routing all managed workloads through this service. Root and other Docker administrators remain trusted; this tool cannot fence independent administrator launches or out-of-band hardware access.

## Allocate and launch

`inventory` returns exact resource IDs and supported modes. Every allocation consumes the entire selected resource. Reserved, starting, draining, verifying and quarantined leases all retain capacity.

```sh
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone reserve --resource GPU-EXACT-UUID --mode exclusive_gpu --ttl-seconds 3600 --request-key job-1
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone start LEASE_ID --generation 1 --workload examples/workload.json
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone release LEASE_ID --generation 1
```

Use the returned generation, not the illustrative `1`. Resource IDs and image digests in examples are placeholders. Workloads are digest-pinned Docker images with an argv command, optional executable entrypoint, read-only model mounts, no network by default, optional ports bound only to loopback, and bounded shared memory. Loopback mode uses Docker bridge networking and therefore can permit outbound network access; it does not promise egress isolation. Customer sandbox policy belongs in a separately qualified backend.

`exclusive_host` normally means exclusive managed Docker GPU passthrough. It does not automatically grant or track customer SSH/root access. A private operator with a never-enrolled host may record an explicit `native-handoff LEASE_ID --generation N --provisioner-reference TICKET` before using a separate provisioning system. This is only a protective intent record: it provides no SSH provisioning, isolation or return proof. The lease stays held even when the GPU is idle; TTL/drain quarantines it, and release/recover cannot return it even after reboot. Connected/enrolled hosts or any recorded connection attempt/history reject this operation because the package cannot prove a durable out-of-band platform revocation fence. A host-root tenant can alter local software, so actual return requires an external trusted provisioner to revoke credentials/reimage and establish a new authoritative fence. That integration and the complete native customer journey remain unsupported.

Run the daemon for periodic expiry cleanup. A CLI-only deployment reconciles when `reconcile` is invoked; lease expiry denies new admissions but never proves cleanup. Retries with identical request keys return the current lease. Changed inputs with reused keys fail. Retrying a failed cleanup uses a new request key.

## Partitioning and trusted sharing

Reserve `gpu_configuration` on a physical GPU, then `configure LEASE_ID --generation N --plan examples/mig-plan.json`. The operation journals intent, destroys existing instances only on that exclusively held GPU, creates the exact desired named profiles and verifies inventory. Release the maintenance lease before reserving the resulting `MIG-...` instances. Disabling MIG uses `{"enabled":false,"profiles":[]}`. A driver-required reboot/reset or partial configuration leaves the resource quarantined. The tool never resets unrelated devices.

For a cooperating application group, start the daemon with `--enable-trusted-mps`, reserve one `trusted_mps` GPU, and start `examples/mps-pool.json`. The image must contain a compatible MPS control binary. Clients share a private IPC/PID namespace and are reclaimed together. Compute percentages sum to at most 100%; memory limits plus 512 MiB headroom fit reported GPU memory. These client settings are cooperative, not reservations or security limits; clients can change their own environment or spawn processes. MPS may improve or worsen workload latency and throughput; measure your workloads before adoption.

## Recovery and upgrades

Interrupted starts stay held because an earlier Docker request could still execute. `recover LEASE_ID --generation N` requires a new Linux boot ID, then removes exact owned containers and independently checks cleanup. It never accepts an operator's unsupported “clean” assertion. MIG recovery replays the durable desired plan after that execution fence. Driver/configuration drift or missing device identities keeps capacity quarantined. Preserve the SQLite database, its WAL and authority registry across upgrades; restoring an old database while work may exist is unsupported.

The reboot recovery path explicitly excludes native handoffs: a new boot does not establish credential revocation or trustworthy provisioning when a customer had host-root access. Do not clear the lease by editing its database or deleting state.

Stop the daemon and release all allocations before changing installation. `tools/install.py install` stages a wheel under its content hash and switches `current`; `activate --release HASH` rolls back to an already installed release. Schema-changing downgrades are rejected by the runtime. `uninstall` removes only manifest-owned install files and preserves state, GPU configuration, authority registry and untracked files. The installer refuses held leases and a live daemon lock. It does not recursively delete Docker resources or system directories.

Installation and activation use a durable journal. Retry the same normal command after interruption: an incomplete installation tree is preserved under the installation prefix's `preserved/` directory, and an interrupted activation completes its recorded release selection. A ready release's ownership manifest is committed before the `current` link changes. Uninstall is likewise resumable and retains the installation ownership marker; a later reinstall preserves old untracked leftovers before reusing a release path. Inspect preserved directories separately—they are not active runtimes or automatic deletion targets.

## API, connection and verification

See [API contract](docs/api.md), [operator service configuration](docs/operations.md) and `PROVENANCE.json`. The bridge is disabled unless a separate owner-only bridge token file is configured. External work requires explicit finite authorization and shares the exact local host lock/database. Disconnect, expiry or failed health checks request reclaim; capacity remains held until exact generation cleanup is independently verified.

The [support matrix](docs/support-matrix.md) separates implemented candidates from qualified hardware. The [threat model](docs/threat-model.md) states trusted actors, enforcement boundaries and excluded guarantees.

The companion platform node installer must receive `--local-authority-url unix:///run/nodus-dc/bridge.sock --local-authority-token-file /var/lib/nodus-dc/bridge.token`. Use the same bridge file for the local daemon. The privileged local API has a separate socket at `/run/nodus-dc/local.sock`; HTTP is read-only. Production sockets require root-owned private paths and OS peer UID checks. The cloud API credential is a different private token file. `connection review` displays current exact-node terms without accepting them. `connection connect` verifies the enrolled node UUID from `/var/lib/nodus/node.json`, checks accepted terms/compensation and grants only an explicit availability window of at most 24 hours. Passing `--accept-terms-digest` is the operator's explicit action to accept that exact reviewed digest; omit it to require already accepted terms.

```sh
nodus-dc --state-dir /var/lib/nodus-dc connection review --platform-url https://YOUR_PLATFORM --namespace YOUR_NAMESPACE --pool YOUR_POOL --node YOUR_ENROLLED_NODE_UUID --token-file /secure/platform.token
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone connection connect --platform-url https://YOUR_PLATFORM --namespace YOUR_NAMESPACE --pool YOUR_POOL --node YOUR_ENROLLED_NODE_UUID --token-file /secure/platform.token --bridge-token-file /var/lib/nodus-dc/bridge.token --available-until UNIX_TIMESTAMP --required-compensation CashUSD --allow-image YOUR_APPROVED_IMAGE@sha256:EXACT_DIGEST
nodus-dc --state-dir /var/lib/nodus-dc connection disconnect
```

Choose permitted workloads explicitly: repeat `--allow-image` for approved immutable image digests, or use `--allow-qualified-jobs` to permit all platform-qualified digest-pinned Job images. The claim records exact image/kind metadata and rejects changed retries. Internal node maintenance remains a separate trusted execution path.

The daemon periodically verifies accepted consent with the platform. Every claim/check requires a permission receipt no more than 20 seconds old and a matching current enrolled-node identity, even if the network worker stalls. Changed/revoked accepted consent, outages, failed parsing and expiration deny external admission; owner workloads keep their independent local lifecycle. Publication of new terms alone does not revoke the existing immutable accepted consent used by permission and priced offers. A local disconnect or identity/accepted-consent revocation persists and never automatically resumes. Credits are a separate explicitly chosen compensation mode and do not prove a cash payout. Actual cash settlement belongs to the connected platform qualification.

Run CPU verification with `PYTHONPATH=src python3 -m unittest discover -s tests`. Fixtures declare synthetic hardware. The support matrix records the qualification gaps; no hardware claims are implied by these CPU tests.

New code is Apache-2.0. Third-party research source is not included in this distribution.

The development candidate also includes an explicit, one-way
[terminal native return](docs/terminal-native-return.md) protocol for a fresh
tracked connection. It is unqualified on hardware and requires the matching
platform credential-identity API. Published dev1 artifacts remain unchanged.
