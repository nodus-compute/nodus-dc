# Dev12 first-run instructions

`0.1.0.dev12` corrects two first-run documentation errors. Commands use the
installed executable at `/opt/nodus-dc/current/bin/nodus-dc`; the installer does
not add it to the shell PATH. The serving guide shows matching generator and
client examples for vLLM and SGLang, including each engine's drain, memory-release
and resume operations. A vLLM workload must use `ServingClient('vllm', ...)`.
The README also distinguishes the ordinary read-only connection credential from
the dedicated credential and tracking required before a first connection that
must preserve terminal-return eligibility.

The recipe generator accepts dev12 with the same image digests, numerical
profiles, arguments, model mounts and networking choices. These instructions
still require preloaded images and model data, an actual GPU UUID and the lease
ID and generation returned by the local authority. They do not pull or launch
work automatically.

All 17 non-version Python runtime modules and the installer are byte-identical
to dev11. Only package-version metadata changes in the runtime wheel. Package
reproduction, installed-path and example checks are recorded separately in the
release verification summary. Local checks do not establish new GPU results.

There remain **zero fully hardware-qualified production configurations**.
Earlier installation, inference and lifecycle observations retain their exact
release and hardware bindings. This release does not close framework-on-MIG,
complete Kubernetes, consolidation-benefit, connected commercial-work or native
customer-return qualification gaps. All earlier release assets and negative
results remain unchanged. See the [support matrix](support-matrix.md).
