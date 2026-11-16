# Partition lending: experimental implementation

The package includes experimental device observation, local partition authority
and a private permission protocol. Their production execution providers remain
unset. Connected lending still reserves a whole host; it does not yet lend an
idle MIG instance alongside an operator workload. See the
[private partition contract](partition-authority-v2.md) for the implemented seams.

The first implemented prerequisite is read-only device evidence. The internal
`Service.partition_binding(lease_id, generation=...)` seam holds the existing
allocation lock, checks a live local lease, and resolves its single MIG instance
to exactly five character devices: its physical GPU, NVIDIA control, UVM, and
the assigned GI and CI access capabilities. It never grants execution, creates
devices, changes partition geometry, or resets a physical GPU. There is no new
HTTP endpoint, bridge admission mode, scheduler offer, or supported executor.

The resolver joins the PCI address and physical GPU UUID to the kernel's device
minor. NVIDIA documents that this minor can differ from the `nvidia-smi` index.
It cross-checks capability metadata, minor mappings, registered device majors,
and actual character-device numbers. Sibling, configuration and monitoring
capabilities are excluded. See the [NVIDIA device-node contract](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/latest/device-nodes-and-capabilities.html).

The evidence includes host boot identity, parent and partition UUIDs, GI/CI,
driver-reported memory, profile, parent geometry, loaded driver version and
source-version metadata, and exact device major/minor pairs. Two observations
must agree with each other and the lease's original boot and partition identity.
Telemetry is excluded from the digest, so ordinary sibling activity does not
invalidate it. One CI per GI is required. Synthetic seam tests cover stale and
changed identity, incorrect and aliased capability nodes, ambiguous metadata,
multi-CI rejection, and regular-file/symlink rejection.

This digest is evidence, not an attestation or a capability token. Driver
metadata identifies a build, not a particular module-load incarnation. Identical
recycled identifiers cannot be distinguished by this observation: admission
also needs a durable monotonic configuration generation under retained authority.
The partition authority now records that generation separately; the observer
alone does not establish continuous configuration ownership. It neither
protects against host root nor proves driver/runtime compatibility. The future
executor must match a separately qualified runtime/driver tuple and revalidate
this identity under authority immediately before using any grant. The current
Nodus runtime does not have a qualified MIG execution path.

## Remaining connected implementation

1. Port and qualify the assigned-MIG gVisor implementation against Nodus's exact
   runtime pin, preserving its existing patches and driver checks. Test hostile
   sibling access and teardown on real hardware.
2. Complete and qualify the node execution path using the existing private v2
   protocol. Preserve exact partition evidence, local generation, policy revision
   and execution limits throughout admission, cleanup and replay. A legacy
   whole-host caller must never receive a partition claim.
3. Install qualified resource enforcement and scoped teardown for the existing
   transactional GPU/CPU/RAM/scratch reservations. Verify that disjoint operator
   leases remain protected and teardown never resets the shared parent GPU.
4. Advertise and price the exact leased partition, attribute actual work, and
   reconcile borrower charges and operator compensation from the frozen rate.
5. Verify one complete cycle: operator training on A; borrower inference on B;
   revoke B; preserve A; clean and reuse B; reject delayed messages; reconcile
   accounting. Repeat across interruption/restart and lost connectivity.

The hardware acceptance case must retain negative results and raw provenance.
Neither these synthetic checks nor standalone Docker coexistence establish
connected tenant isolation, host-confidential execution, or payment settlement.
