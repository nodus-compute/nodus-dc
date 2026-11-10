# Development support and qualification matrix

There are currently **zero hardware-qualified release configurations**. The following entries describe implemented adapter paths and candidate test requirements, not production support claims.

| Component | Implemented / pinned path | Qualification status |
| --- | --- | --- |
| Python | 3.11+ syntax/API; stdlib runtime/build; CPU suite run on 3.12.14/macOS arm64 | CPU tests and install/upgrade/rollback/uninstall passed; Linux host installation still requires target-host check |
| NVIDIA inventory | `nvidia-smi -q -x`, `-L`, driver UUIDs, process and Docker assignment observations | Fixture parser/guard tests; no exact GPU/driver combination qualified |
| Exclusive GPU / host | Docker + NVIDIA Container Toolkit UUID selection, standalone authority only | Control-plane CPU tests; real inference/cleanup/isolation unqualified |
| Native customer handoff | Sticky intent guard for private never-connected operators; TTL/release/recover never return ownership | No SSH/native provisioning or verified return adapter; full native customer acceptance incomplete |
| Existing MIG | Whole advertised `MIG-...` instances, conservative parent process visibility | No hardware qualification; per-instance concurrent activity may conservatively block cleanup/admission |
| MIG creation | Driver-advertised MIG-capable device; explicit standard named profiles, exact-device create/destroy | No hardware qualification; automatic reset/reboot and persistent post-reboot geometry restoration are not implemented |
| Trusted MPS | Explicit opt-in; queried compute capability ≥7; MIG disabled; compatible MPS control binary in pinned image | Command/lifecycle fixture tests; actual MPS attachment, memory limits, correctness, failure coupling and benefit unqualified |
| vLLM | 0.30.0, Linux/amd64 image `vllm/vllm-openai@sha256:5f5e535216848d0c52159c8c13a0af04be5f6fe1a84e79914300610796f76d40` | Versioned adapter and CPU lifecycle tests; real GPU acceptance pending |
| SGLang | 0.5.23, Linux/amd64 image `lmsysorg/sglang@sha256:f7876bef696ccf9cf75a2bf7ccb82970f5fac577f082fb8ca95c9a59d2160eb5` | Versioned adapter and CPU lifecycle tests; real GPU acceptance pending |
| Kubernetes | Generated Pods and NetworkPolicies using existing NVIDIA extended resources | Strict server dry-run on Kubernetes 1.35.8 passed in separate disposable kind evidence; no GPU execution qualified |
| Connected whole host | Exact-node consent, whole-host bridge claim/check/reclaim/inspect/complete | Synthetic local/platform transport and actual HTTP seam tests; deployed real work/handback/cash unqualified |
| Other GPU vendors / arbitrary frameworks | No allocation backend | Unsupported; explicit refusal/observe-only behavior |

Model/framework images must be preloaded for disconnected operation. The qualification runner pins a small model snapshot separately; it is not distributed inside this package. Real support requires exact GPU UUID/model, firmware/driver, OS/kernel, container runtime/toolkit, image digest and model snapshot receipts tied to the final release, with correctness, latency, overhead and reclaim acceptance criteria recorded before evaluation.
