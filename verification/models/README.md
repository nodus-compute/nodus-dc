# Bounded executable safety models

These Python standard-library specifications exhaustively explore finite transition graphs. They are abstract models, **not proofs that the implementation, GPUs, sandbox, remote APIs or payment processor conform**. The checked result covers safety within the stated bounds. It proves no liveness, fairness, eventual cleanup, real-time deadline, isolation or performance guarantee.

Source distributions include this directory; runtime wheels deliberately omit verification tooling. From a checkout or extracted source archive, run:

```sh
cd verification/models
python3 run_models.py --mutations --output results/core-my-run
python3 run_native_recovery.py --output results/native-my-run
python3 run_native_observation.py --output results/observation-my-run
```

Use a new output directory for every run; all commands refuse existing destinations. No network, account, service, GPU or third-party Python package is used. Python3.11+ is supported. Each runner returns nonzero if a baseline fails or is incomplete, or if a deliberate mutation fails to expose its intended property violation. `--max-states 1` demonstrates honest incomplete reporting; it must return nonzero. The state limit is an operational guard, not a pruning rule that permits a pass.

## Reference results

The committed [core summary](reference-results/core-v1/summary.json) and [native-return summary](reference-results/native-return-v1/summary.json) are fresh runs of the bundled sources. Each summary binds raw receipts by SHA256. Receipts contain exact source hashes, finite bounds, assumptions, invariants, transition counts and full shortest counterexample traces. Only this current bundled run is published; no completeness claim about historical experiments follows.

| Baseline | Finite scope | States | Transitions |
|---|---|---:|---:|
| Allocation hierarchy | One host, two GPUs, fixed partitions, three lease slots, trusted synthetic budgets and owner/scheduler reservations | 204 | 1,273 |
| Reclaim/fencing/offline | One host/GPU, two generations/incarnations, replayable launches, two TTL ticks, crashes, disconnects and failed cleanup | 26,016 | 151,146 |
| Cash financial replay | One usage/charge lineage, three revisions, two payout identities, symbolic exact units and response loss | 26,498 | 190,790 |
| Lease-to-usage/finance | Two host lease generations, physical work, reclaim and historical payment lineage | 702 | 4,856 |
| Terminal return/recovery | One held host, exact/stale identities, two wait ticks, four temporary recovery keys and uncertain acknowledgments | 3,622 | 16,946 |
| Total, five separate graphs | Not one combined system proof | 57,042 | 365,011 |

All40 intentional guard mutations produced their expected violations:23 across the four core models and17 in terminal return/recovery. These are sensitivity checks of the model, not findings that the released runtime contains those faults. The native model imports the shared terminal-return transitions from `native_handback.py`; it adds recovery obligations without treating an absent remote object as revocation proof.

The additive [schema3 observation model](native-observation.md) retains a separate [reference run](reference-results/native-observation-v1/summary.json): four origin graphs, 83,156 states and 458,410 transitions, with 20 additional intended counterexamples. The earlier five graphs and their 40 witnesses are unchanged. The observation runner binds exact model sources; each referenced receipt retains its full witness. The new extension is not a combined system proof or implementation refinement. Its no-consent abstraction is a conservative subset of the runtime's historical revoked-consent case.

## Method and trust assumptions

`checker.py` performs breadth-first exploration from each immutable initial state. Hashable states are deduplicated; every enabled successor is traversed until the reachable graph is exhausted, an invariant fails or the explicit state guard stops the run. A parent map reconstructs a shortest action/state counterexample. Repeated actions and self-loops count as transitions. No sampling, symmetry reduction, fairness assumption, temporal-logic/SCC liveness analysis or implementation execution is hidden in these counters.

Each model declares `bounds`, `assumptions` and `properties` beside its transition relation. In particular:

- Abstract transactions and persistent state are atomic/durable. Concrete SQLite, concurrency, restart and restore behavior require separate tests. Database rollback while work exists is outside the model.
- Fixed hardware profiles are assumed disjoint. Memory/compute tokens are symbolic declarations; they do not establish CUDA behavior, MIG/MPS enforcement, hostile-tenant isolation or arbitrary profile compatibility.
- Scheduler-held but idle capacity still has an owner. Utilization does not grant consent. External fractional lending is disabled in the allocation model.
- Reclaim permits residual physical work while draining/quarantined. Handback requires affirmative cleanup. Disconnection, timer expiry or an empty process list alone is not a safe return proof.
- Financial amounts are synthetic integer tokens, not prices or commercial percentages. The model assumes stable business identities, atomic settlement deltas and external processor idempotency. It excludes FX, micros-to-cent rounding, partial transfer reversals and actual banking internals. Connected-account transfer and bank payout are distinct states; neither model state proves money was paid.
- Terminal return assumes trusted operator control before grant, verified HTTPS, exact immutable remote identities, truthful retained retirement/audit proofs, durable local obligations and a known authentication-cache bound. Systemd/GPU checks are truthful abstract predicates, not hardware measurements. Four temporary keys are finite; exhausted proof/history/key bounds can remain quarantined forever.

The [trust and failure model](../../docs/threat-model.md) describes product boundaries. The [source mapping](mapping.md) identifies related public implementation anchors and explicit mismatches. No refinement/conformance theorem is supplied.

## Interpreting negative traces

A receipt with `outcome=counterexample` names the deliberate mutation, intended property and actual violations. Its trace begins at `Init`; every next action/state is an enabled transition under that mutation. The runners require the intended property, not merely any failure. Do not interpret the first counterexample as full exploration of an unsafe mutant: search stops at the witness.

A baseline `incomplete_state_limit` is neither a pass nor a counterexample. Preserve that receipt and rerun only with an explicitly larger resource allowance if desired. Existing result directories are never overwritten. Models and documentation use the repository's Apache-2.0 license; no proprietary research runtime or credentials are included.
