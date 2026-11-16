# Dev14 local dashboard, diagnostics and training checkpoints

`0.1.0.dev14` adds four operator-facing capabilities:

- The local dashboard groups physical GPUs and MIG partitions, shows measured
  GPU use and memory, and supports resource search and availability filters.
  Allocation details stay available without crowding the overview. Tokens stay
  in page memory; locking cancels pending refreshes and clears the view. Missing,
  invalid or expired snapshots do not appear as available capacity or zero use.

- `nodus-dc doctor` reads live daemon health and saved inventory without creating
  state, scanning hardware or taking allocation ownership. It distinguishes
  service health, inventory freshness and held or available capacity. Reads have
  absolute deadlines and inventory that expires in transit is reported stale.
- Local workloads may explicitly mount an operator-owned private checkpoint
  directory at `/outputs`. The authority prevents overlapping writers and
  reader/writer conflicts across held jobs, including quarantine and MPS clients.
  Cleanup retains checkpoint files. The training descriptor and PyTorch example
  demonstrate explicit application-owned checkpoint/resume behavior.
- `required_privacy` lets clients state `host_confidential` for reservations,
  bridge claims and Kubernetes rendering. This release refuses that requirement
  before resource actions or replay because its execution backend trusts the
  host operator. Status exposes that boundary; encryption or a RuntimeClass name
  is not treated as attestation.

CPU verification exercises the actual CLI and local HTTP/Unix routes, lease
transactions, Docker argument generation and independent checkpoint ownership.
The training example compares uninterrupted and resumed model, optimizer, RNG,
loss and step state. A CPU example result is not a GPU training result.

There remain **zero fully hardware-qualified production configurations** at
candidate preparation. This release does not establish a throughput improvement,
host-confidential execution, hostile-tenant packing, distributed training,
automatic checkpointing, or completed external lending and cash payout.
Hardware tests bind their results to exact artifacts and environments separately;
earlier hardware failures and release artifacts remain unchanged.

The A100 test candidate is source `57adf15890ab213abd483656262a61a6a6eba55a`
and wheel SHA-256
`facab1fe831650f4c6b435ab5c5199f84f18196ae6e19a79457c31b44f2a89dc`.
That candidate predates the final dashboard and documentation changes. Its
hardware observations must not be described as tests of the final release wheel.

See [operations](operations.md#checking-after-a-start-or-restart),
[training and checkpoints](training.md),
[workload confidentiality](threat-model.md#workload-confidentiality), and the
[support matrix](support-matrix.md).
