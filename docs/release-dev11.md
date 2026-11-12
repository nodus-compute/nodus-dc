# Dev11 local dashboard usability

`0.1.0.dev11` improves the read-only local dashboard. The token form supports
Enter, controls show when a refresh is in progress, and duplicate refreshes
share a single pending operation. Status and errors have live announcement
regions, keyboard focus is visible, and focus returns to the initiating control
when disabling it caused the browser to lose focus. Moving focus elsewhere is
respected.

The browser bounds the complete inventory-and-status refresh, including response
bodies, to 120 seconds. A timeout restores the controls and reports an error;
it does not claim to cancel work already running on the server. Existing
30-second freshness and stale-data behavior continue while a refresh is pending
or fails. There is no new background polling. The token remains in browser
memory only, and the dashboard still sends only read requests.

Local Chromium checks exercised Enter, successful and failed refreshes,
duplicate submissions, recovery, stalled requests and response bodies, expiry
during a pending refresh, focus retention and narrow screens. Timeout checks
used controlled browser time rather than waiting 120 seconds of wall time.
The layout was checked at 320 CSS pixels with long resource identifiers.
These checks use local synthetic HTTP responses, not a GPU or a deployed
platform. Live-region markup is checked; no screen-reader audit is claimed.

Only `dashboard.py` and the package-version module change in the runtime wheel
relative to dev10. The other 16 modules, including permission freshness,
allocation authority, SQLite, GPU backends, MIG, trusted sharing, serving and
availability, are byte-identical. The installer is unchanged. The recipe
generator accepts dev11 without changing its pinned workload descriptors.
Reproducible archive and offline Linux installation results are recorded in the
release verification summary.

There remain **zero fully hardware-qualified production configurations**.
Earlier actual installation, inference and lifecycle observations keep their
original release, device, driver, image, model and acceptance bindings. They
are not repeated or relabeled as dev11 hardware runs. This release does not
close framework-on-MIG, complete Kubernetes, consolidation-benefit, connected
commercial-work or native customer-return qualification gaps. Existing failed
results and release assets remain unchanged. See the
[support matrix](support-matrix.md) for the development support boundary.
