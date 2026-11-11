# Dev8 connection compatibility fix

`0.1.0.dev8` corrects the request used by an operator who explicitly supplies
`--accept-terms-digest`. The previous client sent a node query parameter on the
sharing POST, which the platform rejects. Dev8 sends `node` in the existing JSON
body and keeps the exact-node query for GET review and permission reads.

Consent still requires the platform's normal human owner/admin session and the
exact reviewed terms digest. Host API keys do not acquire consent authority.
This fix does not accept terms automatically or enable capacity participation.

Only `connection.py` and the package version module change in the runtime wheel
relative to dev7. The serving client, allocation, MIG/MPS, Kubernetes, local
bridge, state schema, recovery and installer sources are unchanged. The serving
recipe accepts both versions and emits the same descriptors.

The focused connection regression reproduces the old platform rejection and
checks the corrected method, URL and JSON body. Its platform transport is an
explicitly synthetic fixture; its SQLite and local policy changes execute for
real. It does not establish a deployed acceptance, workload or payout journey.

The [dev7 hardware report](hardware-evidence-dev7.md) remains version-bound to
the actual dev7 artifact. Its successful checks and negative results are
retained. Dev8 is an unqualified development prerelease; there are no fully
qualified production configurations. Artifact reproducibility and installed
package checks are recorded in the release verification summary.
