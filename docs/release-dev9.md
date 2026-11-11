# Dev9 local availability and dashboard freshness

`0.1.0.dev9` reports locally available GPUs and hardware partitions through
`status`, `/v1/status` and the local dashboard. The read-only projection combines
the last inventory with current allocation authority and all unreleased leases.
A whole-host lease blocks its GPU and partition descendants. A lease on a missing
partition continues to hold its recorded parent. Expired and quarantined leases
remain held until the ordinary release or recovery path verifies cleanup.

Availability requires standalone authority and an observation no older than
30 seconds. Missing observations, uncertain clocks, unresolved ownership and
scheduler-managed resources remain unavailable. The displayed counts are a
snapshot; an actual reservation is still required. They do not determine whether
capacity may run external workloads or earn compensation.

The dashboard counts response transit time and browser suspension when aging
an observation. A failed refresh, stale sample or backward/invalid clock removes
positive availability and utilization displays while retaining the last recorded
allocation rows. A fresh successful request can restore the display. Measured
zero utilization remains visible as zero.

The new availability module, status projection, dashboard and package version
change in the runtime wheel relative to dev8. Allocation enforcement, SQLite
schema, GPU backends, serving controls, partitioning, connection and installer
behavior are unchanged. The recipe generator accepts dev9 and produces the same
versioned vLLM/SGLang workload descriptors.

Five allocation/freshness regression tests and focused browser clock cases cover
the new behavior. Synthetic browser checks exercise idle, held, stale, failed
and recovered states; they do not establish real-GPU dashboard qualification.
Build, installed-package and hardware results are recorded separately in the
release verification summary. The [dev7 hardware report](hardware-evidence-dev7.md)
keeps its original artifact binding, successful checks and negative results.
Dev9 is a development prerelease; full production qualification is incomplete.
