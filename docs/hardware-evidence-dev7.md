# Nodus DC dev7: hardware verification results

Draft supplement, 11 November 2026. Kubernetes, connected service and
further serving qualification are still in progress. This report records scoped
results; it does not qualify the complete product for production. Raw receipts
are retained privately; their hashes identify the recorded evidence and are not
public download links.

## Tested release and environment

- Public release: `v0.1.0-dev7`; source
  `29274be6d7344b232c9d24bb83275d9be45e7144`.
- Installed wheel SHA-256:
  `a804eeeed75935a80e09e610ef391bb88320f124d94fb4898cf3c54073c59991`.
  All 17 installed Python modules were compared with this wheel at phase entry.
- NVIDIA H100 PCIe, driver 580.178.04, Ubuntu 24.04,
  kernel 6.8.0-1064-nvidia, Python 3.12.3, Docker 29.9.2 and
  NVIDIA Container Toolkit 1.18.1. The test machines were KVM guests with GPU
  passthrough. These runs do not establish physical bare-metal reprovisioning.
- vLLM 0.30.0 image digest:
  `5f5e535216848d0c52159c8c13a0af04be5f6fe1a84e79914300610796f76d40`.
- SGLang 0.5.23 image digest:
  `f7876bef696ccf9cf75a2bf7ccb82970f5fac577f082fb8ca95c9a59d2160eb5`.
- Qwen2.5-0.5B-Instruct revision
  `7ae557604adf67be50417f59c2c2f167def9a775`, BF16, tensor parallelism 1,
  eager execution, context length 2048 and memory fraction 0.45.

## Whole-GPU serving

Both engines passed the original online correctness, concurrency, overhead and
drain/release/resume checks. The managed results matched their dedicated stock
references exactly for recorded text, tokens and log probabilities.

| Measurement | vLLM | SGLang |
| --- | ---: | ---: |
| Managed / stock throughput | 0.9932 | 1.0263 |
| Added p95 request latency | 8.394 ms | -15.464 ms |
| Combined observer and daemon CPU | 0.03948 cores | 0.03358 cores |
| Drain / release / resume | 0.364 / 1.040 / 0.572 s | 0.176 / 0.440 / 1.305 s |
| Normal cleanup | 11.322 s | 13.162 s |

With host outbound connectivity disabled, both engines still passed inference
correctness, throughput, CPU and lifecycle checks. Both failed the fixed added-p95
limit of 10 ms: vLLM added 26.984 ms and SGLang added 36.309 ms against their stock
references. The failures remain part of qualification. They have not been
reclassified as passes because other measurements were favorable.

During the host-offline phase the local dashboard HTML and authenticated API were
available; unauthenticated status access was refused. CLI and API agreed on the
observed idle state. This was an HTTP check, not a browser rendering check.

Independent online review SHA-256:
`dc3d3d0bfbebed18e1a8b4ff933871fcec74a3a0c211b1e7351d06b04f84204f`.

A later, separately admitted default-profile vLLM diagnostic alternated direct
and managed requests within the same engine process while host outbound access
was blocked. All 424 requests were retained, including 384 measured requests in
12 counterbalanced blocks. It also failed performance targets: managed/direct
throughput was 0.8607 and added p95 latency was 259.161 ms. The slowdown was
concentrated in the middle blocks, while measured client processing before and
after transport stayed below 0.1 ms at p95 in every managed block. These timings
do not establish a causal explanation. No blocks were removed or rerun to obtain
a favorable result. Normal cleanup took 11.591 seconds; firewall and transient
process restoration passed. Root replayed all 126 archived files and the complete
assessment: `50a8d4a28d9e3f3cbb00df2f66e660b702d309536bbf77a21f2510e4f610db65`.

The separately invoked SGLang diagnostic passed the same fixed comparison:
managed/direct throughput was 1.0173, added p95 latency was -3.946 ms and measured
observer/daemon CPU was 0.03660 cores. All 424 requests and 12 measured blocks
were retained. Normal cleanup took 14.677 seconds, with firewall and transient
process restoration verified. Root replayed all 126 archived files and the
assessment: `4994e460c246074d882cde8c8014a9f0f5ee0849d2d1f007b67133616c0d096b`.
This is a same-process diagnostic result, not a replacement for the original
separate-launch offline negative or a full lifecycle/performance qualification.

### Longer offline vLLM confirmation

A separately preregistered deterministic-profile run passed its declared offline
comparison. It retained 160 counterbalanced four-block groups (80 ABBA and
80 BAAB), 640 blocks and all 20,480 measured responses. Every measured completion,
token and token log probability matched the fresh serial reference exactly.
Public and platform connectivity were blocked during measurement.

| Measurement | Observed | Primary conditional bound | Required |
| --- | ---: | ---: | ---: |
| Managed / direct throughput | 1.001800 | Lower: 0.989895 | ≥0.95 |
| Added p95 request latency | -0.000276 ms | Upper: 2.773465 ms | ≤10 ms |
| Controller CPU | 0.067173 cores | Upper: 0.067694 cores | ≤0.1 cores |

The primary analysis used circular 16-group bootstrap blocks and 9,999 draws,
with a nominal per-bound error rate of 1/120. The required eight-group sensitivity analysis
also passed. All prespecified time/order strata and dependence diagnostics passed.
These are approximate bounds conditional on the stated dependence assumptions;
the diagnostics do not prove stationarity or finite-sample coverage. Earlier
failed and inconclusive runs were retained and were not pooled into this result.

Independent review verified all 150 archived evidence files, exact inference
outputs, CPU arithmetic, resampling indices and reported bounds. Normal cleanup
took 11.041585 seconds. The run left no held leases, GPU processes or containers;
firewall restoration and SSH closure were verified. This establishes the recorded
offline comparison, not a sharing benefit or the complete product's qualification.

Raw archive SHA-256:
`8fe1871ec178d3be0c901c44a740c25dc31f74e7a6f0a06b051ef5a90d4456c7`.
Independent review:
`9313715c5c487bfe8b6d8f088407f68cfa2b967f0684441893e6cf19ee066e09`.

## Hardware partitions

The documented maintenance-lease and allocation commands created two `3g.40gb`
MIG partitions on one physical H100. Both ran CUDA computations that checked all
4,096 output elements. Driver UUIDs, GPU/compute instance IDs and container worker
ancestry established that the workloads ran concurrently in distinct partitions.

Restarting the local daemon preserved both active leases and running containers.
Releasing the first partition left the second computing correctly. Reusing the
released partition advanced its lease generation; a release using the old
generation was refused. Normal cleanup removed the partitions, restored
MIG-disabled geometry, and left no held leases or GPU processes.

This qualifies the recorded partition lifecycle. It does not establish vLLM or
SGLang inference performance inside MIG partitions, arbitrary resizing, live
migration, or a full native-customer return workflow.

Raw archive SHA-256:
`3dcd3c59a8fcec6163f7fee615832a5ba8e90824a93d093af6e9ef1a4c0de957`.
Independent replay of all 115 manifest files and 116 archive members:
`9dd88305490eb2f2f812b62aba20626795427a629fbc4d171c5b401b1d7537af`.

## Trusted cooperative sharing

The MPS boundary test successfully allocated 32,000 MiB, then received CUDA
out-of-memory when an additional 8,001 MiB would exceed its 40,000 MiB client cap,
despite more physical memory being free. Targeted termination stopped the selected
client while its sibling continued to produce correct results. The physical GPU
lease remained held, and a competing exclusive allocation was refused. Normal
cleanup completed in 16.893 seconds.

MPS clients remain in one trusted domain. The settings are cooperative limits;
this result does not establish hostile-tenant or fatal-GPU-fault isolation.

The two-GPU-to-one-GPU inference experiment **failed correctness**. The candidate
used two MPS clients, each capped at 50% active threads and 40,000 MiB. In all three
trials, both engines completed their offered work within the timing targets but
produced outputs that differed too much from their dedicated references.

| Correctness measurement | Required | vLLM | SGLang |
| --- | ---: | ---: | ---: |
| Exact completion fraction | ≥0.96875 | 0.65625 | 0.81250 |
| Token identity fraction | ≥0.99 | 0.68850 | 0.83926 |
| Maximum matching-token logprob difference | ≤0.1 | 2.13645 | 0.40931 |

The dedicated baselines matched the earlier primary stock outputs exactly. The
shared candidate repeatedly produced its own altered outputs. Input/source and
timing checks did not establish a measurement error that would invalidate the
failure. The numerical cause remains unproven. There is no qualified inference
consolidation benefit for this configuration, and these serving profiles should
remain disabled for MPS optimization.

Independent benefit review SHA-256:
`719ad50b3e898f43d92abee8a59a7d656adeb90d602fb00385d805a4692c7dcc`.
MPS memory/termination review SHA-256:
`026a558ea5ef9276a0c08fc90603c1b97b447f289cbdf41a0abaf40651bd1a3c`.

A new deterministic profile passed a narrower numerical feasibility experiment.
vLLM added `VLLM_BATCH_INVARIANT=1`; SGLang added
`--enable-deterministic-inference --attention-backend fa3`. Both dedicated and
shared runs used these same settings. Each engine's 32 shared serial responses
matched its dedicated reference exactly for completion text, token identities
and token log probabilities, while both engines remained attached to the actual
MPS server with the same 50% and 40,000 MiB client limits.

The first attempt completed its dedicated references but reached its operational
deadline before shared serial measurements. That attempt remains failed. A
separate shared-only continuation strictly bound those completed references,
the same host boot, source, model, images and descriptors. It completed in
195.902 seconds, including 15.515 seconds of normal cleanup. Root independently
replayed all 65 archive files, all 64 numerical comparisons and actual MPS client
attachment. This establishes numerical feasibility for the new profile;
performance, full lifecycle and two-GPU-to-one benefit remain unqualified.

Shared-only raw archive SHA-256:
`5094c5d1fd967a4266833e346d7fa7e1819890c2c01b83754ad4e6cba4b031dc`.
Independent replay:
`cf905b18d08008b4088b8bdc18b9380bb7eda35370d1f5021eb7295d6d8c9ab1`.

The new deterministic vLLM full primary test preserved exact outputs across its
serial, concurrent, and resumed requests, but **failed the frozen performance
targets**. Stock p95 was 0.418650 seconds; managed p95 was 0.716179 seconds,
an increase of 0.297529 seconds. Managed throughput was 86.36% of stock.
Combined observer and daemon CPU averaged 0.03055 cores. Draining took 0.4718 seconds, memory
release 1.0950 seconds, and resume to a correct response 0.6720 seconds.
Normal cleanup took 12.0250 seconds and left no held allocations, containers,
or GPU processes.

The third managed concurrent trial contained most of the slowdown. The cause
is not established, and every trial remains in the result. Root replayed all
30 stock and 28 managed archive members and all 308 recorded requests. The
observer naturally exited with failure status 1, and the unchanged assessor
rejects the pair. The two-GPU benefit gate remains closed.

Independent deterministic primary negative review SHA-256:
`5fd3867bc438fbebd07a538912fd1d5a94455da8ce75ac9eedae5be52c8f58e7`.

The independently launched deterministic SGLang stock and managed pair passed
all its frozen primary checks. Managed throughput was 100.036% of stock, and
p95 decreased by 8.619 ms (0.806246 to 0.797627 seconds). Combined observer and daemon CPU averaged
0.02121 cores. All serial, concurrent, and resumed completions/tokens matched
exactly with zero token-logprob difference. Draining took 0.2815 seconds, memory
release 0.4382 seconds, and resume 1.4155 seconds. Both observers exited normally
with status 0; managed cleanup took 14.1453 seconds. Root replayed both complete
30-member archives and all 308 request records. This scoped SGLang pass does not
waive the vLLM failure or establish a consolidation benefit.

Independent SGLang primary review SHA-256:
`103e6f12f2c466b4730181d94005918be1134eb96cbdd27bb729891bfcde9608`.

A later complete SGLang numerical prerequisite was run after the latest host
reboot. It compared 32 dedicated responses with 32 responses from each of two
simultaneously attached SGLang MPS clients. Both shared clients matched the
dedicated text, tokens and token log probabilities exactly. Dedicated and shared
normal cleanup took 16.518328 and 15.949605 seconds respectively. Independent
review verified all 113 archived files and all 64 comparisons, with no remaining
held leases, containers or GPU processes. This is a current-boot numerical and
cleanup result; throughput benefit remains unqualified.

Raw archive SHA-256:
`1931ab9d0fa039c484f5cb1d8f37324a0fca1b7089ed062df2c3f00f4e35249d`.
Independent review:
`b77c2d9c4d8477075a680d740cee94d831684141b4b170df17cbeb5af521e291`.

## Standalone admission and fault recovery

A bounded dev7 fault phase passed on the same H100 boot. It created four new
leases and exercised two fixed, overlapping two-client reserve schedules. Each
schedule admitted one request and refused the other with an allocation conflict.
Exact reserve replays returned the original lease; changed inputs using the same
request key were refused. Repeated starts preserved the same container and
process identity while CUDA continued checking all 4,096 output elements. A stale
generation release and a late start of an already released lease were refused.

The phase then killed the exact running standalone daemon and started the normal
service. The active lease and container survived, with the same container process
and CUDA iteration progress from 1 to 14. The original 120-second request expiry
was not extended. Daemon maintenance completed physical cleanup 12.161351 seconds
after expiry, within the fixed 45-second grace, without an explicit reconcile,
drain or release call for that lease.

A separately identified, task-owned foreign CUDA container made the next cleanup
refuse a clean handback and quarantine the lease. New allocations were refused
while the GPU was busy and remained refused after the foreign container was
removed, until normal cleanup verification released the held lease. Normal
release durations in this phase were 7.084036, 7.034123 and 6.233135 seconds.

The complete phase took 305.688118 seconds. Independent reviews verified all 570
archived files. The prior 66 lease records were unchanged; all 70 leases were
released cleanly at completion. No GPU processes or containers remained. The
normal service was active with its original unit configuration, the phase unit
was inactive, and the host boot and provider deadline were unchanged.

This covers four new leases and two fixed admission schedules on dev7. It does
not establish every race interleaving or crash point, host-unreachable recovery,
connected or financial behavior, or qualification of another release.

Raw archive SHA-256:
`a66a4a6e61c5c1dc613a28cbad7a3d719be6297b98093af938ee97a31487c841`.
Independent case review:
`d795254780800fa0230232a25df06c11286bb549174ff569c3d5ecdd84439395`.
Independent source-bound raw replay:
`0a80df7ab268400c78f0254da08501cdcf2be16459de8b080ce25c3d3dec2790`.

## Installation lifecycle and host recovery

The supported installer lifecycle passed on the H100 after a controlled reboot.
The sequence rolled dev7 back to dev6, ran managed CUDA, verified that an active
daemon and a stopped daemon with a held lease both refuse an upgrade, released
the workload normally, upgraded to dev7, ran native Docker CUDA, uninstalled,
ran native Docker CUDA again, and reinstalled dev7. The refusal checks preserved
the running CUDA process and its continued progress. Both native CUDA runs
completed 17 iterations with 4,096 correct elements each.

The sequence took 119.838 seconds, with normal workload cleanup taking 10.452
seconds. Authority/history state survived the supported transitions. The final
installation was dev7, stopped and disabled, with no GPU processes. An earlier
fixture failed because it requested a named Docker runtime that the host does
not have; the successful fixture used the host's normal runc runtime and explicit
GPU device request. Docker and NVIDIA configuration were not changed to hide
that failure.

Independent replay of all 314 archived files and the lifecycle manifest:
`f993d7656b467ec90037b9577514e8d8d2e85a601d93b579707d33c70cf30edc`.

One Kubernetes setup attempt failed before creating any qualification
Pods, Jobs or namespaces. Its original cleanup also failed its module-state
check. The fixture-created dummy network interface accounted for the additional
module. A separately bounded recovery restored the three changed sysctls,
preserved the authority database, performed one controlled reboot, and verified
the absence of cluster processes, mounts, GPU processes and all ten declared
module additions. The standalone service returned active and disabled.

That recovery passed; the original Kubernetes setup and cleanup remain failed.
The reboot changed the boot identity and requires fresh serving references.
Full module-set equality is not claimed: nine optional original modules were
absent after reboot. Independent replay of all 142 recovery archive files:
`13ae37aeb2228641e17f35035a95f60e161a6e9ec69a43fc479076f55e166e86`.

A later Kubernetes attempt stopped earlier, during local image export. Docker
save reached its 300-second preparation limit after writing a 6.65 GB partial
archive. No cluster, qualification workload, or allocator transition started.
The export process exited, no process retained the partial file, and fresh checks
showed no held allocation, container, or GPU work. The partial remains private
as an incomplete artifact. The two installed images report 87.17 GB combined
expanded size; their digest-bound compressed layer descriptors total 24.84 GB.
A separate run subsequently used a reviewed compressed OCI export path and
an adequate preparation budget. This input failure remains separate from the
later setup results.

Independent input-failure review SHA-256:
`5859c6c1b166dc709f1268f61e12d4a3f1ec11a4e1bcb1304e747215879312a2`.

A subsequent private-runtime attempt passed source, image and host entry checks,
then refused the runtime identity during bootstrap. K3s had rewritten the child
process title to `containerd `, so the check could not match its expected command
name and original config arguments. The qualification setup, inference-image
import and GPU-workload stages did not start. This is a failed qualification
attempt.

Bounded cleanup completed in 11.184 seconds, followed by planned reboot and
restoration in 56.582 seconds, within their original 240- and 300-second limits.
All 70 released lease records remained unchanged. The GPU and Docker were empty;
the original network policy, sysctls, runtime executable/unit configuration and
standalone active/manual-disabled service state were restored. Eight optional
original kernel modules were absent after reboot; full module equality is not
claimed. Early SSH readiness failures are retained alongside the eventual
successful restoration. The new boot requires fresh numerical references for
another Kubernetes attempt; earlier serving results remain historical evidence.

Raw archive SHA-256 (475 regular files):
`ed1d762d78205e850bc6cbdf01b478397579cd2f3cc2304d4a1b08b9ccbd74f5`.
Independent negative and restoration review:
`4989d25f5d7f9a566efca29fe74aff822a5c31cea6d7e761047ec586b958fe61`.

## Remaining qualification

Kubernetes authority, connected host enrollment and retirement, paid workload execution, native
customer handback, and processor payout qualification remain separate gates.
No cash payout or complete operator journey is established by this report.
Temporary compute costs are tracked as estimates until actual provider billing
is available; full resource closure is recorded after the remaining phases.
