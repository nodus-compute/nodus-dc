# Bounded observation-only participation model

`native_observation.py` extends the existing terminal-return/recovery state
machine; the checker and original two transition modules are unchanged. Run:

```sh
python3 run_native_observation.py --output results/observation-check
```

The four initial-origin profiles represent a fresh continuously tracked
observation connection, legacy state without known consent, legacy state with
known consent, and known earlier enablement. Each has one host, one held
whole-host lease, exact-or-stale Node/key identities, schema2/3, three monotonic
wait buckets and up to **four** introduced recovery keys. Arbitrary crash cycles
are finite transitions; no fairness or eventual-completion guarantee is assumed.
External history is a Boolean summary of completed earlier claims, not an active
allocation overlapping the preconditioned exclusive host lease.

The extension checks durable schema3 before participation-history semantics,
fresh-origin classification, sticky ever-enabled history across disable/restart,
denial of observation-only allocation, exact-consent revocation for enabled or
unknown histories, and the extra affirmative NodeRetirement proof before key
retirement on the never-enabled route. A DELETE acknowledgement or 404 cannot
substitute for that proof. Schema2 readers must refuse the new state.

All original dedicated-key, full fresh revocation-cache wait/401, stopped-agent,
bound credential-file, final device-cleanup and sticky-host-hold requirements
remain. The extension replaces only the consent-specific premise for a genuinely
never-enabled route; it does not synthesize a consent record. Four recovery-key
slots remain exhaustively explored. Six inherited guard-omission witnesses are
required to traverse the new never-enabled route, checking that this extension
has not accidentally removed those cleanup obligations.

The current reference search explores **83,156 states and 458,410 transitions**
across all four unmutated origin profiles. All twenty deliberate omissions
produce their intended safety counterexamples: fourteen new history/schema/
observation/proof cases and six inherited cleanup/key/wait cases. Every source
file and counterexample is retained. A separate `--max-states 1` check returns
incomplete and nonzero, never a proof. The state guard is an operational limit,
not an additional assumption that makes unexplored states safe.

These are finite abstract-model results, **not a formal refinement proof for the
implementation**. SQLite atomic durability, verified HTTPS/authoritative remote
retirement truth, the authentication-cache bound and truthful kernel/device
observations are assumptions. The model has no credential bytes, unbounded
database, GPU kernel behavior, actual clock duration or remote packet execution.
The exact-origin oracle must be enforced by the implementation's record checks.

There is one deliberate conservative subset: the model's `consent_known` combines
historical/current consent, so its no-consent route does not cover the runtime's
additional permitted case of a never-enabled history with already-revoked
historical remote consent. The runtime's positive-integer generation check is
part of its authenticated retirement proof parser; the model's exact-proof
predicate is not a separate local frozen-generation equality check.

Implementation guard anchors (not proof of refinement):

| Model obligation | Owning implementation |
| --- | --- |
| Schema3 and genuine first observation | `Service.record_connection_attempt`, `Store.__init__` |
| Every enable records sticky history | `Service.bridge_policy` |
| Observation is not allocation permission | `Connection._authorization_current`, `connect`, `sync` |
| Never-enabled versus exact-consent return | `Handback._prepare` |
| Positive exact NodeRetirement before key revoke | `node_retirement_proof`, `Handback.run`, `Recovery.node` |
| Original key/wait/service/device obligations | `Handback.run`, `Recovery.run` |

Owning CPU protocol/installer tests and guard omissions are separate evidence
for selected implementation behaviors; remote/service/device outcomes in those
tests are simulated. Actual artifact, hosted Node/key, service and GPU journeys
must retain their own independent receipts and limitations. None is established
merely by passing this model or by a source-anchor mapping.
