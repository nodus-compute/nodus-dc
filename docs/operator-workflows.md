# Operator workflows

Local GPU inventory, explicit allocations, controlled hardware partitioning and opt-in capacity participation. The local runtime works offline without a Nodus account. This is a development release; CPU verification is not hardware qualification.

The package includes live daemon diagnostics, persistent training checkpoint directories,
and explicit workload privacy requirements. Dev16 corrects MIG driver compatibility
and retains private partition authority and durable ownership fences. Connected
partition execution remains unavailable. See the [dev16 change record](release-dev16.md)
for the scoped A100 configuration/restoration result and remaining limits.

The source tree now builds the separate [dev17 candidate](release-dev17.md).
The README continues to link the immutable dev16 downloads until new artifacts
are published. Source-build and published-wheel identities are not interchangeable.

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

Workloads currently trust the host operator. `status` reports this under `privacy`.
Use `reserve --required-privacy host_confidential` when host confidentiality is
mandatory: the current backend refuses that request before allocation. The same
requirement is available on bridge claims and Kubernetes rendering. It cannot
silently fall back to ordinary Docker, MIG or MPS execution. See the
[confidentiality requirements and remaining implementation](threat-model.md#workload-confidentiality).

For an existing GPU cluster, use `/opt/nodus-dc/current/bin/python -m nodus_dc.kubernetes render` and follow [Kubernetes integration](../kubernetes/README.md). Run local inventory in `--allocation-authority kubernetes` mode on those nodes. Generated resource requests use the cluster's actual device-plugin semantics; `nvidia.com/gpu` alone is not a claim of exclusive hardware isolation.

For standalone inference, follow the [versioned vLLM and SGLang recipes](serving-profiles.md). The generator supports the installed dev7 through dev17 packages and requires an explicit numerical profile. [Dev7 hardware observations](hardware-evidence-dev7.md) record successful paths and retained failures; complete production qualification remains in progress.

## Offline build and install

Python 3.11+ is required. Runtime/build have no third-party Python dependencies. From an unpacked source archive or repository checkout, build deterministic wheel/sdist archives using only the standard library:

```sh
python3 build_backend.py &&
python3 tools/install.py install --wheel dist/nodus_datacenter-0.1.0.dev17-py3-none-any.whl --prefix /opt/nodus-dc --state-dir /var/lib/nodus-dc
```

The installer keeps the CLI and Python interpreter under `/opt/nodus-dc/current/bin`;
it does not add them to your shell PATH. The commands below use that installed path.

Installation does not start services, change drivers or opt into participation. For local workload execution, preinstall a supported NVIDIA driver, Docker and NVIDIA Container Toolkit. Preload digest-pinned workload images and model files; the runtime never pulls them. Run the Linux daemon as the trusted host operator with Docker/GPU management permissions. Actual allocation binds a canonical authority registry in `/var/lib/nodus-dc`, so it normally requires root. Do not expose Docker or the local token to customers.

```sh
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc inventory
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone serve
```

Open `http://127.0.0.1:7441/` and enter the local token from the daemon's printed file path. Use SSH port forwarding for remote viewing. The dashboard keeps the token in memory only. Press Enter after entering it. Refresh runs one read at a time and announces progress or errors. A refresh stops waiting after 120 seconds; this browser timeout does not stop a daemon scan. Availability still expires normally while a refresh is pending. Local availability is a recent observation of unheld resources under this allocator. Reserve through the API before use; a displayed count does not grant ownership or authorize external work. Default authority is `observe`; choose `standalone` only after draining other schedulers and routing all managed workloads through this service. Root and other Docker administrators remain trusted; this tool cannot fence independent administrator launches or out-of-band hardware access.

After starting or restarting the service, use the [read-only readiness checks](operations.md#checking-after-a-start-or-restart) to distinguish a running service, daemon health, fresh inventory and allocatable resources. A successful `status` command alone does not confirm that the daemon is serving.

## Allocate and launch

The wheel does not include `examples/`. If you followed the README's dev16 wheel
installation, download the [matching source archive](https://github.com/nodus-compute/nodus-dc/releases/download/v0.1.0-dev16/nodus_datacenter-0.1.0.dev16.tar.gz)
into the same directory as its verified `SHA256SUMS`. Verify before unpacking,
then run the examples from the unpacked source directory:

```sh
sha256sum --check --ignore-missing SHA256SUMS &&
tar -xzf nodus_datacenter-0.1.0.dev16.tar.gz &&
cd nodus_datacenter-0.1.0.dev16
```

For the dev17 source build above, use that source directory instead. Keep examples
matched to the installed release and edit their image, paths and GPU profiles for
your host before reserving resources; the supplied values are examples.

`inventory` returns exact resource IDs and supported modes. Every allocation consumes the entire selected resource. Reserved, starting, draining, verifying and quarantined leases all retain capacity.

```sh
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone reserve --resource GPU-EXACT-UUID --mode exclusive_gpu --ttl-seconds 3600 --request-key job-1
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone start LEASE_ID --generation 1 --workload examples/workload.json
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone release LEASE_ID --generation 1
```

Use the returned generation, not the illustrative `1`. Resource IDs and image digests in examples are placeholders. Workloads are digest-pinned Docker images with an argv command, optional executable entrypoint, read-only model mounts, no network by default, optional ports bound only to loopback, and bounded shared memory. Loopback mode uses Docker bridge networking and therefore can permit outbound network access; it does not promise egress isolation. Customer sandbox policy belongs in a separately qualified backend.

`exclusive_host` normally means exclusive managed Docker GPU passthrough. It does not automatically grant or track customer SSH/root access. A private operator with a never-enrolled host may record an explicit `native-handoff LEASE_ID --generation N --provisioner-reference TICKET` before using a separate provisioning system. This is only a protective intent record: it provides no SSH provisioning, isolation or return proof. The lease stays held even when the GPU is idle; TTL/drain quarantines it, and release/recover cannot return it even after reboot. Connected/enrolled hosts or any recorded connection attempt/history reject this operation because the package cannot prove a durable out-of-band platform revocation fence. A host-root tenant can alter local software, so actual return requires an external trusted provisioner to revoke credentials/reimage and establish a new authoritative fence. That integration and the complete native customer journey remain unsupported.

Run the daemon for periodic expiry cleanup. A CLI-only deployment reconciles when `reconcile` is invoked; lease expiry denies new admissions but never proves cleanup.

An API replay returns the current lease only when both the request key and the
complete payload are identical, including the original absolute `expires_at`.
Changed inputs with a reused key fail. The CLI's `reserve --ttl-seconds` computes
a new expiry on each invocation, so repeating the same command is not an
identical reserve replay. After an uncertain result, inspect `status` and the
current lease before deciding what to do; do not blindly repeat reserve or use a
new key to work around an unknown outcome. Retrying a failed cleanup uses a new
request key after reviewing the retained lease state.

## Partitioning and trusted sharing

Use the matching source examples prepared in [Allocate and launch](#allocate-and-launch).

Reserve `gpu_configuration` on a physical GPU, then `configure LEASE_ID --generation N --plan examples/mig-plan.json`. The operation journals intent, destroys existing instances only on that exclusively held GPU, creates the exact desired named profiles and verifies inventory. Release the maintenance lease before reserving the resulting `MIG-...` instances. Disabling MIG uses `{"enabled":false,"profiles":[]}`. A driver-required reboot/reset or partial configuration leaves the resource quarantined. The tool never resets unrelated devices.

For a cooperating application group, start the daemon with `--enable-trusted-mps`, reserve one `trusted_mps` GPU, and start `examples/mps-pool.json`. The image must contain a compatible MPS control binary. Clients share a private IPC/PID namespace and are reclaimed together. Compute percentages sum to at most 100%; memory limits plus 512 MiB headroom fit reported GPU memory. These client settings are cooperative, not reservations or security limits; clients can change their own environment or spawn processes. MPS may improve or worsen workload latency and throughput; measure your workloads before adoption.

## Recovery and upgrades

For independent training jobs, use the [local training adapter](training.md). It generates offline workloads with read-only code/data and an explicitly authorized persistent checkpoint directory at `/outputs`. Each job retains its ordinary whole-GPU or MIG lease; checkpointing never releases GPU ownership. Hardware qualification and performance claims remain separate.

Interrupted starts stay held because an earlier Docker request could still execute. `recover LEASE_ID --generation N` requires a new Linux boot ID, then removes exact owned containers and independently checks cleanup. It never accepts an operator's unsupported “clean” assertion. MIG recovery replays the durable desired plan after that execution fence. Driver/configuration drift or missing device identities keeps capacity quarantined. Preserve the SQLite database, its WAL and authority registry across upgrades; restoring an old database while work may exist is unsupported.

For a quarantined hardware-partition lease whose MIG UUID disappears after a
reboot, [partition recovery and explicit recovery upgrades](recovery-upgrade.md)
require an idle, independently verified original physical GPU. Original lease
identities and fencing history remain unchanged; native handoffs are excluded.

The reboot recovery path explicitly excludes native handoffs: a new boot does not establish credential revocation or trustworthy provisioning when a customer had host-root access. Do not clear the lease by editing its database or deleting state.

Stop the daemon and release all allocations before changing installation. From the README download directory, use `python3 install.py`; from a source checkout or unpacked source archive, use `python3 tools/install.py`. Keep the installation's original `--prefix` and `--state-dir` on every command. For example, to uninstall the README installation:

```sh
python3 install.py uninstall --prefix /opt/nodus-dc --state-dir /var/lib/nodus-dc
```

The `install --wheel PATH` action stages a wheel under its content hash and switches `current`; `activate --release HASH` rolls back to an already installed release. Schema-changing downgrades are rejected by the runtime. `uninstall` removes only manifest-owned install files and preserves state, GPU configuration, authority registry and untracked files. The installer refuses held leases and a live daemon lock. It does not recursively delete Docker resources or system directories.

Installation and activation use a durable journal. Retry the same normal command after interruption: an incomplete installation tree is preserved under the installation prefix's `preserved/` directory, and an interrupted activation completes its recorded release selection. A ready release's ownership manifest is committed before the `current` link changes. Uninstall is likewise resumable and retains the installation ownership marker; a later reinstall preserves old untracked leftovers before reusing a release path. Inspect preserved directories separately—they are not active runtimes or automatic deletion targets.

## API, connection and verification

See [API contract](api.md), [operator service configuration](operations.md) and `PROVENANCE.json`.

The [support matrix](support-matrix.md) separates implemented candidates from qualified hardware. The [threat model](threat-model.md) states trusted actors, enforcement boundaries and excluded guarantees.

### Monitoring-only dashboard connection

Use this path only when **Get install command** in the [Data-center dashboard](https://data-center.nodus-compute.ai) explicitly confirms monitoring only. If that confirmation is absent, leave the host unchanged; do not substitute an Execute enrollment command. The monitoring-only command enrolls a `nodusd` agent in **Monitor** mode, separately from `nodus-dc connection connect`. It reports host inventory and GPU observations without authorizing remote jobs or capacity sharing.

Monitor requires a Linux host with systemd and a working NVIDIA driver/NVML. It does not require Docker, NVIDIA Container Toolkit, a CUDA workload probe or the allocator's local-authority URL/token options. Use the dashboard's install command unchanged; do not add the Execute options below.

The documented standalone package uses `/opt/nodus-dc`, `/var/lib/nodus-dc` and, if configured, `nodus-dc.service`. Monitor uses `/opt/nodus/bin/nodusd`, `/etc/nodus`, `/var/lib/nodus` and `nodusd.service`. Keep these paths, services and credentials distinct. The standalone allocator's local/bridge tokens are not enrollment tokens, and monitoring does not require enabling its bridge. Existing local workloads remain under their current allocator; this source separation is not yet a live workload-coexistence qualification.

Monitor requires a fresh `nodusd` installation. The installer refuses existing agent binaries, configuration, bootstrap token or service, and nonempty agent state. An existing **Execute** `nodusd` cannot be converted by running the Monitor installer. Preserve its state; this installer supplies no Execute-to-Monitor migration. Do not delete state to bypass the refusal.

Monitor enrollment creates `/var/lib/nodus/node.json`, so this package's never-enrolled `native-handoff` path subsequently refuses the host. Monitoring does not establish eligibility for the separate [terminal native return](terminal-native-return.md) workflow or provide confidentiality from the host operator.

Follow the [dashboard setup guide](https://nodus-compute.ai/docs/guides/pools/data-center/) to select your organization, project and host group and get the Monitor install command. After installation, confirm that the expected host and GPUs appear there and that the GPU sample time advances. These checks confirm monitoring only; workload execution and capacity sharing require separate authorization.

After enrollment, check the GPU sample time; **Last seen** is a heartbeat, not proof of fresh GPU measurements. Stale or missing readings remain unavailable, not 0%. Follow [Disconnect a monitoring host](https://nodus-compute.ai/docs/guides/pools/data-center/#disconnect-a-monitoring-host) to stop and disable the verified Monitor agent, retire the exact saved Node UID and its credentials, and revoke unused enrollment tokens. Require positive retirement confirmation; a missing Node alone is insufficient. Local installation files and private state remain. This is separate from `nodus-dc connection disconnect` below.

### Execute agent and optional capacity sharing

The following instructions apply to an **Execute** agent using this package's allocation authority, including its observation-only participation setting. They are not Monitor installation instructions. The bridge is disabled unless a separate owner-only bridge token file is configured. External work requires explicit finite authorization and shares the exact local host lock/database. Disconnect, expiry or failed health checks request reclaim; capacity remains held until exact generation cleanup is independently verified.

For this Execute connection, start with `--participation disabled`. This setting verifies the enrolled node and keeps external work disabled; it does not accept capacity terms or require a payment mode, availability window or workload permission. Metrics come from the enrolled `nodusd` agent. Keep its local-authority protection configured even for this observation setting: enrollment alone must never give remote jobs a second allocation path around local workloads. Execute GPU installation also requires the [public digest-pinned CUDA probe](../probe/README.md); preserve its normal driver, runtime and allocation-authority checks.

The companion platform node installer must receive `--local-authority-url unix:///run/nodus-dc/bridge.sock --local-authority-token-file /var/lib/nodus-dc/bridge.token`. Use the same bridge file for the local daemon. The privileged local API has a separate socket at `/run/nodus-dc/local.sock`; HTTP is read-only. Production sockets require root-owned private paths and OS peer UID checks. The cloud API credential is a different private token file. `connection review` displays current exact-node terms without accepting them. `connection connect --participation enabled` verifies the enrolled node UUID from `/var/lib/nodus/node.json`, checks accepted terms/compensation and grants only an explicit availability window of at most 24 hours. Passing `--accept-terms-digest` explicitly accepts that exact reviewed digest and requires a human owner/admin session credential. An on-host API key cannot accept terms; use the console to accept them, then omit this flag to connect with the host's read credential.

Choose the credential path **before this installation's first connection**:

- For ordinary metrics and sharing-status reads, use a host API key with `pools:read` and omit `--terminal-native-return` from the first command below. This does not establish terminal-return eligibility.
- If you need terminal native return, follow the [terminal return guide](terminal-native-return.md) **before connecting for the first time**. It requires a separate dedicated key with the guide's exact five organization scopes and continuous credential tracking from that first connection. The ordinary `pools:read` preset is insufficient; adding the flag or replacing the key later does not restore missing tracking history.

The first connect command below shows the terminal-return path. Use its dedicated
key and retain the flag only after completing that guide's first-connection setup.

```sh
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone connection connect --participation disabled --terminal-native-return --platform-url https://YOUR_PLATFORM --namespace YOUR_NAMESPACE --pool YOUR_POOL --node YOUR_ENROLLED_NODE_UUID --token-file /secure/platform.token --bridge-token-file /var/lib/nodus-dc/bridge.token
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc connection review --platform-url https://YOUR_PLATFORM --namespace YOUR_NAMESPACE --pool YOUR_POOL --node YOUR_ENROLLED_NODE_UUID --token-file /secure/platform.token
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone connection connect --participation enabled --platform-url https://YOUR_PLATFORM --namespace YOUR_NAMESPACE --pool YOUR_POOL --node YOUR_ENROLLED_NODE_UUID --token-file /secure/platform.token --bridge-token-file /var/lib/nodus-dc/bridge.token --available-until UNIX_TIMESTAMP --required-compensation CashUSD --allow-image YOUR_APPROVED_IMAGE@sha256:EXACT_DIGEST
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc connection disconnect
```

Enabling participation is a separate explicit step after reviewing and accepting the exact capacity terms. The enabled mode remains the default for existing commands with sharing arguments. `--terminal-native-return` requires the dedicated first-connection key described in the [terminal return guide](terminal-native-return.md); omit it only when terminal return is not needed. Switching back to observation drains current external admission and preserves any prior consent and participation history.

For enabled participation, choose permitted workloads explicitly: repeat `--allow-image` for approved immutable image digests, or use `--allow-qualified-jobs` to permit all platform-qualified digest-pinned Job images. The claim records exact image/kind metadata and rejects changed retries. Internal node maintenance remains a separate trusted execution path.

The daemon periodically verifies accepted consent with the platform. Every claim/check requires a permission receipt no more than 20 seconds old and a matching current enrolled-node identity, even if the network worker stalls. Changed/revoked accepted consent, outages, failed parsing and expiration deny external admission; owner workloads keep their independent local lifecycle. Publication of new terms alone does not revoke the existing immutable accepted consent used by permission and priced offers. A local disconnect or identity/accepted-consent revocation persists and never automatically resumes. Credits are a separate explicitly chosen compensation mode and do not prove a cash payout. Actual cash settlement belongs to the connected platform qualification.

The source archive also includes [runnable bounded safety models](../verification/models/README.md) for allocation, reclaim/fencing, financial replay and terminal return. Their original reference runs retain 40 deliberate mutation witnesses, with 20 additional witnesses in the separate observation/schema3 extension, explicit assumptions and a [source mapping](../verification/models/mapping.md); abstract safety is not implementation or hardware proof. The runtime wheel omits this verification tooling.

Run CPU verification with `PYTHONPATH=src python3 -m unittest discover -s tests`. Fixtures declare synthetic hardware. The support matrix records the qualification gaps; no hardware claims are implied by these CPU tests.

New code is Apache-2.0. Third-party research source is not included in this distribution.

The development candidate also includes an explicit, one-way
[terminal native return](terminal-native-return.md) protocol for a fresh
tracked connection. It is unqualified on hardware and requires the matching
platform credential-identity and Node retirement APIs. Bounded recovery retains
every introduced temporary-key obligation across crashes and requires exact
retirement evidence before customer access. Published dev1 artifacts remain unchanged.
