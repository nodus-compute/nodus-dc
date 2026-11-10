# Dev4 hardware observations — 10 November 2026

These are measured development results, not a production support declaration. They used the published [v0.1.0-dev4 artifacts](https://github.com/nodus-compute/nodus-dc/releases/tag/v0.1.0-dev4), source `6cf69cb12740ec5b4950b47e03f642866b9e9f5f`, wheel SHA-256 `7a518528356ca83e6eead0c1f7aff195072e642ce3213bce3e7937d723a4a8a3`. Later package changes require their own affected-path checks.

The machine exposed one NVIDIA H100 PCIe with 81,559 MiB, Ubuntu 24.04, kernel `6.8.0-1064-nvidia`, Docker 29.9.2, NVIDIA Container Toolkit 1.18.1, and Python 3.12.3. It was a **KVM/QEMU virtual machine**. Its GPU results do not qualify physical bare-metal provisioning, customer root access, or a native return/reimage cycle.

## Partition and recovery observations

On driver **580.105.08**, two `3g.40gb` MIG instances ran concurrent correct CUDA work with distinct observed GI/CI process mappings. Restarting the controller preserved both workers. Releasing one partition left its sibling running; a reused partition received a new lease generation and rejected the stale generation. Final normal cleanup returned the GPU to MIG-disabled state with no held leases.

The earlier dev3 sibling-start failure remains a failure. Installing published dev4 preserved its SQLite authority and original lease identity. Recovery refused the same boot and succeeded after an actual reboot and cleanup checks. This did not restore an old MIG geometry or prove native customer return.

On driver **580.178.04**, a deliberately retained foreign CUDA worker caused cleanup to fail closed: the lease remained held and new admission was refused. Removing that exact test worker did not itself reopen capacity; normal cleanup retry was required. A separate CUDA allocation requested total device memory plus 64 MiB, observed `CUDA_ERROR_OUT_OF_MEMORY`, and verified correct CUDA output before and after. The worker then intentionally exited with code 77. The lease stayed held until normal release; only then could a new generation allocate. This was a CUDA worker test, not a vLLM/SGLang or MPS fault-containment test.

## Exclusive serving observations

Serving used driver **580.178.04**, the image digests in the [support matrix](support-matrix.md), and `Qwen/Qwen2.5-0.5B-Instruct` revision `7ae557604adf67be50417f59c2c2f167def9a775`. Both engines used BF16, tensor parallelism 1, eager execution, maximum model length 2048, and memory fraction 0.45. Each engine compared against its own unmodified stock image.

The recorded plan specified 32 prompts, 8 warmup requests, temperature/seed 0, at most 32 output tokens, logprobs, four concurrent clients, and three timed repetitions. Targets included exact completion match ≥96.875%, token match ≥99%, logprob difference ≤0.1, p95 ≤5 seconds and ≤1.25× stock, throughput ≥95% of stock, added p95 ≤10 ms, and controller CPU ≤0.1 core. Lifecycle targets were drain ≤10 seconds, memory release ≤15 seconds, resume to correct inference ≤30 seconds, at least 50% and 128 MiB memory reduction, and final normal cleanup ≤60 seconds. Memory release had to retain the lease.

| Engine/run | Requests/second | p95 seconds | Correctness and lifecycle | Frozen performance targets |
| --- | ---: | ---: | --- | --- |
| vLLM stock | 12.3582 | 0.64824 | Reference | Reference |
| vLLM managed, host online | 16.4066 | 0.33993 | Passed | Passed |
| vLLM managed, host offline | 9.4662 | 0.68911 | Passed | **Failed** |
| SGLang stock | 11.9345 | 0.52612 | Reference | Reference |
| SGLang managed, host offline | 12.4153 | 0.48677 | Passed | Passed |

Observed completion/token matches were 100%, with zero matching-token logprob difference. vLLM memory use fell from 39,017 to 719 MiB during release and returned to 36,639 MiB after resume. The offline vLLM throughput ratio was **0.765987**, below 0.95; added p95 was **40.866 ms**, above 10 ms. These failed targets remain unchanged. The online pass does not replace the offline failure, and these short measurements establish neither a general speedup nor a two-GPU-to-one benefit.

Host-offline runs denied host IPv4/IPv6 outbound traffic while preserving only loopback and the exact established SSH return connection used for control and evidence collection. Engine containers had no network. Platform/public IPv4 probes increased the owned rejection counters; IPv6 had no default route and was also fenced. Dependencies were preinstalled. The SGLang fence lasted 175.18 seconds. Normal allocation, inference, drain, release and final checks completed within the fence; unrelated firewall rules were restored and the independent restore timer was cleaned up.

## Evidence identity and remaining scope

The following SHA-256 values identify the retained raw archives. This document is a summary; those raw archives and the experiment harness are not bundled into this package, so the table alone is not an independently reproducible qualification kit.

| Retained archive | SHA-256 |
| --- | --- |
| Dev4 MIG/recovery | `f166ca0768beeef507326a8bedd0c2479e30642b6e57784323f4e8a5f2246223` |
| Cleanup failure/quarantine | `bc10368dec5dd0af492c2adbd8c3576bddd77f0f8b25cee780ed5c374342a9ac` |
| CUDA OOM/worker exit | `561505f65fa11fe8099b486e4c5188666db63f879a35651a035fa0e4fb6cced5` |
| vLLM stock | `469ef4c3aa3bc8280dbe5103d2ba23528716fec224f0be39e30e38773d9f0cc1` |
| vLLM managed online | `fe266b5391fc819eda9256e820eb068701250422be38f828936545e3cd7107d4` |
| vLLM managed offline — failed performance | `60ed111a3a583e05b6d36776c9366ce7d60dcb79c9c61fdc5df5e38ad2994fe8` |
| SGLang stock | `f17908e24626a3b9858c6796ad9c91fdf511a1977629b977bb1332a37447cd5c` |
| SGLang managed offline | `db6687129a3c0101f93b12d9e308c9e4ecad7b25e77496522cb73b5761100efc` |

MPS attachment/benefit, framework inference on MIG, actual GPU Kubernetes execution, connected paid workload/handback, native customer access, cash payout, and the full final-release journey remain outside these passed checks. Driver 580.105.08 MIG results are not relabeled as 580.178.04 results. Hostile-tenant isolation and arbitrary-process live migration are not claimed.
