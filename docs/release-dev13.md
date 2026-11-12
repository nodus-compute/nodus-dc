# Dev13 terminal-retirement evidence

`0.1.0.dev13` adds an authenticated read-only projection at
`GET /v1/leases/LEASE_ID/terminal-retirement` on the existing local API. It joins
the ready, unexpired host lease and retained handback journal with affirmative
Node retirement, dedicated-key rejection, saved cleanup, and current host/boot
identity. The response contains safe identity fields and retirement evidence,
without credentials, credential paths or file fingerprints. It grants no access
and does not attest activity after a customer has held root.

Every new terminal handback now reads affirmative same-org, exact-Node retirement
proof after the conditional Node deletion and before dedicated-key revocation.
An older interrupted `node_retired` journal can obtain the missing proof while
its key still exists. Missing or invalid proof preserves that key and keeps the
hold quarantined. An already-completed old journal without affirmative proof
remains ineligible for the new projection. There is no implicit database repair,
credential issuance, new retry, or timeout extension.

CPU checks cover the actual authenticated HTTP route, unchanged database state,
stale and conflicting evidence, normal retirement ordering, and persisted
pre-upgrade resume. Simulated remote responses and synthetic hardware do not
qualify the hosted retirement path. The release verification summary separately
records reproducible packaging and installed-artifact checks.

Fifteen runtime modules and the installer are byte-identical to dev12. Changes
are limited to `api.py`, `handback.py`, and version metadata; serving recipe
generation retains the same descriptors and accepts the new package version.
All earlier release assets and historical outcomes remain unchanged.

There remain **zero fully hardware-qualified production configurations**. This
release does not qualify native customer login, external provisioning or reimage,
post-customer isolation, or return to lending. The external owner still needs
independent physical-host, remote retirement and key-revocation verification.
See the [terminal return guide](terminal-native-return.md) and
[support matrix](support-matrix.md).
