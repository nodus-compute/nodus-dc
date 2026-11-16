# Trust and failure model

This development release does not claim hostile-tenant GPU isolation. The local management plane is an operator tool. Root, Docker administrators, device-plugin administrators, the configured bridge process and the physical host are trusted. Anyone who can edit the authority database or use an independent privileged GPU launcher can bypass the managed ownership model.

## Workload confidentiality

This package currently runs workloads with a trusted host operator. TLS protects
traffic on a configured encrypted connection; it does not hide decrypted inputs,
models, memory, logs or outputs from that operator. MIG resource separation and
cooperative MPS sharing do not establish host confidentiality.

Callers can require `host_confidential` through `reserve --required-privacy`, the
reserve/bridge-claim API, or Kubernetes rendering. The package refuses these
requests with no allocation or generated Pod. `trusted_host` remains the explicit
default for existing workloads. Status reports this boundary under `privacy`.
No hardware name, inventory flag, image label or RuntimeClass name overrides it.

A future confidential backend must verify fresh CPU and every assigned GPU's
attestation, approved guest/workload measurements, production security modes and
certificate/reference validity, then release workload keys only to the bound
approved guest. It also needs protected inputs/outputs/storage and a qualified
GPU reset/reassignment lifecycle. These are missing implementation and hardware
qualification requirements, not assurances supplied by the current API.
[NVIDIA's CVM threat model](https://docs.nvidia.com/confidential-computing/virtual-machines/v1.0.0/threat-model)
requires whole-GPU assignment and excludes MIG/MPS in its documented CC
configurations. Fractional packing and confidentiality therefore need separate
qualified execution paths; there is no automatic downgrade to ordinary sharing.

The upstream integration candidate is
[Confidential Containers with NVIDIA GPU Operator](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/25.10/confidential-containers-deploy.html):
Kata supplies the guest boundary and Trustee appraises CPU/GPU evidence before
releasing secrets. Its documented early-access status and platform constraints
require evaluation before production adoption. Nodus does not yet deploy or
qualify this stack.

## Existing boundaries

| Asset / boundary | Implemented control | Residual risk / required qualification |
| --- | --- | --- |
| Physical GPU ownership | Canonical host-to-database registry, interprocess flock, SQLite immediate transactions, ancestor/descendant conflicts | All managed admission paths must use this authority; independent administrator workloads remain outside it |
| Lease execution | Immutable lease ID, monotonic generation, durable start intent, exact container labels and resource selection | Docker and driver must enforce the requested device set; no bare-metal tenant SSH adapter is supplied |
| Native customer root access | Sticky private handoff intent or the candidate [one-way terminal return](terminal-native-return.md): continuous dedicated-key history, exact remote retirement, fresh revocation wait, stopped-agent verification and final cleanup; no later lending | Host root can alter the local agent/database. Physical cleanup, actual customer access and hosted retirement remain unqualified; a new provisioning/re-enrollment cycle requires independent physical control |
| Local API | Read-only HTTP; mutating APIs on private root-owned Unix sockets, verified OS peer UID, separate 0600 bearer files, bounded bodies/threads, no CORS grant | A fake HTTP dashboard can deceive a person/capture read access, but cannot invoke private mutations without root peer identity; root is trusted |
| External consent | Exact currently enrolled node UUID on every admission, reviewed/accepted digest equality, verified permission heartbeat ≤20 seconds, explicit compensation mode and finite window, no redirect/proxy token forwarding | Platform account permissions and consent authenticity remain the platform/bridge's responsibility; malformed or stale permission denies admission |
| Permitted workload | Explicit image allowlist or all platform-qualified digest-pinned Job images; immutable claim image/kind metadata | Approval of an image does not independently constrain all job arguments or prove sandbox/hardware isolation; trusted internal maintenance is separately classified |
| Bridge server identity | `unix:///run/nodus-dc/bridge.sock`, root-owned0700 parent/0600 socket, protected non-symlink ancestors, peer UID checks on both sides, lifetime lock and inode-specific cleanup | Root may impersonate other root services and remains trusted; TCP bearer authentication is deliberately unavailable for bridge authority |
| External reclaim | Immutable platform tuple, durable retirement tombstones, generation check, reclaim before inspect, exact workload cleanup proof plus local inspection | The remote bridge must not reset hardware for a denied/unknown claim and must itself fence all launch paths |
| Lost responses / duplicate delivery | Claim replay recovers same tuple, completed tuples cannot relaunch, operation keys reject changed inputs | Callers must retain original request keys/tuple; timeout never means no work ran |
| Daemon or host crash | Durable SQLite WAL/full sync, starting→quarantine, reboot ID required for uncertain local commands, exact owned cleanup | Database restoration/rollback while work may exist is unsupported; driver resets may change MIG identities |
| Installer crash | Atomically published ownership marker, durable install/activation/uninstall journal, ready manifest before current-link switch, ordinary retry recovery | Incomplete trees and untracked files are preserved, not recursively deleted; package rollback is not database rollback |
| MPS clients | One exclusive physical pool lease, bounded declared client budgets, private shared IPC/PID and exact owned volume cleanup | All clients must cooperate; client settings are bypassable, faults and timing interference are shared |
| MIG | Exact physical device maintenance lease, explicit profile plan, observed configuration verification | Hardware isolation guarantees and reset behavior depend on actual GPU, firmware and driver qualification |
| Model assets / workloads | Preloaded digest image, read-only model mounts/root filesystem, cap drop, no-new-privileges, no implicit image pull | Docker containers alone are not the promised sandbox for adversarial external customers; operator mounts must not contain secrets |
| Offline mode | No platform connection absent configuration; local runtime/build have no Python package dependencies; no implicit registry access | Loopback-published Docker bridge mode can allow egress; network denial requires a qualified firewall/backend policy |
| Cleanup / privacy | Stop/remove exact owned containers, fresh process/assignment observations, selected-device configuration checks, failure→quarantine | A clean process listing is not proof of erased GPU memory, no open handles, PCI reset or cross-tenant privacy; real hardware testing is mandatory |
| Kubernetes integration | Existing scheduler/device plugin owns GPU requests; no local co-allocation; generated restricted Pod/NetworkPolicy | Resource names inherit plugin sharing semantics; NetworkPolicy requires an enforcing CNI; unreachable nodes need existing quarantine policy |
| Money | Local connection requires explicit accepted compensation mode | This package is not the settlement ledger. Test-mode or fixture receipts never establish actual cash payment |

No GPU load percentage grants permission to lend. A memory-sleep acknowledgment, container disappearance, expired timer or disconnected controller never by itself returns ownership. Quarantined resources consume capacity until the documented cleanup/recovery path succeeds. The [runnable bounded state models and source mapping](../verification/models/README.md) are included in the source archive. They check only finite abstract safety under explicit assumptions, exclude unmodeled hardware failures and cannot establish implementation conformance, GPU security, performance or payment.
