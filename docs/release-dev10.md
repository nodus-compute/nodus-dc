# Dev10 permission freshness

`0.1.0.dev10` counts platform request time within the existing 20-second
permission freshness limit. Previously, a delayed response started a new
20-second window when it arrived. Enabled connection, explicit terms acceptance
and permission refresh now retain the request-start timestamp. An over-age
response or a backward/invalid request clock refuses authorization.

The change preserves exact enrolled-node identity, explicit opt-in, accepted
terms, workload policy, lease generations and normal cleanup requirements.
Persisted dev9 permission timestamps have no request-start provenance and are
denied until an ordinary fresh permission GET succeeds. The marker binds its
exact timestamp, so an older writer cannot preserve the marker while replacing
the timestamp. Connection settings, accepted consent and history are retained;
no renewed terms acceptance or database migration is required.

Observation-only requests continue to create no execution permission. A fresh
successful request can restore permission through the existing policy path;
it cannot release held ownership or revive a draining lease.

One focused regression uses the real local SQLite allocation and admission path
with an explicitly simulated platform response and clock. It fails on the dev9
code and passes on dev10: a response taking 19 seconds has no remaining validity
two seconds later, an ordinary fresh response recovers, and a response taking
21 seconds refuses permission. The 26 existing affected connection, observation
and CLI tests passed locally. An additional persisted-record regression checks
legacy, unknown and mismatched timestamp markers after restarting Connection;
a fresh GET restores admission without changing consent, policy revision or
event history. This is CPU implementation evidence, not a deployed
connected GPU or commercial-consent test.

Only `connection.py` and the package-version module change in the runtime wheel
relative to dev9. The other 16 modules, including allocation authority, SQLite,
GPU backends, MIG, trusted sharing, serving controls, dashboard and availability,
are byte-identical. The installer is unchanged. The recipe generator accepts
dev10 and emits the same pinned vLLM/SGLang descriptors; it does not allocate or
launch work. Build and installed-file checks are recorded separately in the
release verification summary.

There remain **zero fully hardware-qualified production configurations**.
Historical hardware results keep their original package, device, driver, image,
model, deadlines and acceptance criteria. Unchanged source permits a scoped
applicability review; it does not convert those results into a new dev10 hardware
run or turn a failed qualification into a pass. The [support matrix](support-matrix.md)
and [dev7 hardware report](hardware-evidence-dev7.md) retain these limits.
Fresh installation, complete Kubernetes acceptance, framework inference on MIG,
inference-consolidation benefit, production connected work and cash settlement,
and the complete native customer-return journey remain incomplete. Native-to-lending
reprovisioning remains unsupported. No existing release asset or historical
evidence is replaced by this prerelease.
