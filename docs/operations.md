# Operating one physical authority

Drain and disable any existing independent allocator before selecting standalone mode. Kubernetes and Slurm nodes need an integrating authority adapter; do not point two schedulers at the same GPU. The physical authority record at `/var/lib/nodus-dc/authority-path.json` binds a host ID and exact database path. Do not delete it to bypass a conflict. A planned state migration requires all workloads cleaned, both daemons stopped and the complete database moved with its authority record under operator control.

Example systemd unit (review paths locally; installer never writes or starts it):

```ini
[Unit]
Description=Nodus local GPU authority
After=docker.service
Requires=docker.service

[Service]
Type=simple
UMask=0077
ExecStart=/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone serve --port 7441
Restart=on-failure
RestartSec=3
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
```

Enable trusted MPS only for one cooperating trust domain by adding `--enable-trusted-mps` before `serve`. Configure `--bridge-token-file` only when the matching nodusd bridge is installed; nodusd connects to `unix:///run/nodus-dc/bridge.sock`, never TCP. Its token file is not the cloud platform credential. Root creates `/run/nodus-dc` as 0700, with separate 0600 `local.sock` and `bridge.sock` listeners that verify OS peer UID. Do not use `/tmp`, symlinked or writable ancestor paths for authority sockets. `--local-socket` and `--bridge-socket` override only to equally protected canonical paths.

Keep all authority state and tokens owner-only. HTTP exposes the read-only dashboard/GET APIs; all POSTs are rejected. A process impersonating the dashboard port could still deceive a person or capture the read token, so use a trusted host and authenticated SSH forwarding for remote viewing. The read token alone cannot perform privileged mutations: local and bridge Unix APIs additionally require root peer identity, with different route scopes and tokens. Never enter the bridge credential into the dashboard. Rootless observe-only serving exposes no privileged Unix API.

Local listeners start independently of platform connectivity. The connection worker initially denies external admission, refreshes every five seconds after completion, and every claim/check independently rejects permission older than twenty seconds. Root nodusd must continue its local monitoring/reclaim loop; a denied check triggers workload termination and clean handback, not immediate reallocation. An explicit availability window cannot override stale or revoked permission.

Production checks still required: real driver/toolkit/container matrix, hardware cleanup verification, MPS client attachment and limits, MIG create/destroy/reset behavior, concurrent serving memory/latency, node restart and disconnect handling, GPU health/ECC behavior and external consent/metering/payout lifecycle. A GPU process list alone cannot prove all device handles are closed; the intended exclusive platform backend must add its own cleanup evidence. This development backend checks Docker assignment, NVIDIA process inventory and exact selected-device configuration, and fails closed when those observations are unavailable.

An allocation does not expose an arbitrary SSH session or raw device file to a tenant. The local adapter launches controlled Docker descriptors as an operator convenience; hostile workloads need a separately qualified isolation backend. No image pull or model download occurs implicitly.

## Connected owner reservations and reclaim policy

Before enabling capacity participation, sign in to the Nodus console as the owning organization’s owner or admin. Open Infrastructure, select the enrolled Pool and exact host, then open **Availability settings**. Set the IANA time zone and recurring **Owner-use windows**, a **One-time ready by** deadline if needed, and **Minimum ready machines** to reserve qualified machines in the same pool and hardware class. Select **Review availability settings** and confirm the displayed policy. Those normal platform controls own scheduled reclaim and the shared reserve; the local connection's finite deadline is an additional admission limit. Local owner GPU/partition/host reservations always exclude conflicting whole-host external claims.

The same normal API is `POST /apis/nodus.dev/v1/namespaces/{namespace}/pools/{pool}/sharing` with a UUID `Idempotency-Key` header and body `{"action":"Policy","node":"YOUR_NODE","generation":CURRENT_SHARING_GENERATION,"policyGeneration":CURRENT_HOST_POLICY_GENERATION,"policy":{"timeZone":"America/Los_Angeles","ownerWindows":[{"days":[1,2,3,4,5],"start":"09:00","end":"17:00"}],"minimumReady":1}}`. Read both current generations from `GET /apis/nodus.dev/v1/namespaces/{namespace}/pools/{pool}/sharing?node={node}` before preparing a request. A write identifies the node in its body; the platform rejects a node query on POST. Values here are examples, not a command to alter an existing operator's policy. A stale generation is a conflict requiring review of the current state.

The accepted compensation agreement supplies its maximum reclaim notice; it is shown with the terms and cannot be silently rewritten by the local package. For planned customer use, set an owner window or ready-by deadline early enough for the platform's readiness lead (at least fifteen minutes in the initial policy). For an immediate local stop, `connection disconnect` denies new external claims and requests reclaim; it does not promise instant successful cleanup. Wait for the local lease to become released and platform readiness to confirm clean handback before assigning the server. A quarantine, stale permission, disconnected node or failed device check never means owner-ready.

Use the console to accept/revoke commercial consent and configure payouts with a human owner/admin session. An on-host API key can read permission but cannot accept commercial terms; it is not a substitute for that console identity. Explicit local image allowlists (`--allow-image`) or `--allow-qualified-jobs` control the permitted pinned Job images in addition to the platform's mandatory sandbox and workload eligibility rules. The one-way [terminal native return](terminal-native-return.md) protocol requires fresh, continuously tracked dedicated credentials, exact platform retirement, stopped-agent verification and final device cleanup. It preserves the operator's existing native access procedure; real host qualification is still required. Reconnecting after native/root access, reimaging and a full provisioning cycle remain unsupported without independent physical control.
