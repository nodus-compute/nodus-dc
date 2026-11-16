# A100 functional observations — 2026-11-16

One NVIDIA A100-SXM4-40GB host completed the partition, training and restore
checks below. **The inference run failed its declared SGLang repeatability
check.** These observations do not qualify a production configuration or prove a
performance improvement.

The standalone CLI created two distinct `3g.20gb` MIG GPU instances. vLLM and
SGLang each saw one assigned instance. After serving, the same host ran the
checkpoint example on both instances, returned to a whole GPU through the normal
release/restore path, and passed a fresh whole-GPU CUDA check. No new GPU was
launched for the continuation, and the original deadlines were retained.

## Results

| Check | Observation | Scope |
| --- | --- | --- |
| Public package installation | Dev13 installer and wheel installed successfully | One Linux host; not a fresh install of the final dev14 wheel |
| Partition creation | Two `3g.20gb` instances, each reporting 21,072,183,296 bytes | Normal maintenance lease and exact-device configuration |
| Concurrent inference | Eight successful completions per engine | vLLM 0.30.0 and SGLang 0.5.23, one instance each; a small serving smoke |
| vLLM repeatability | Four of four same-engine prompt pairs had identical text | Greedy repeats under concurrent MIG load |
| SGLang repeatability | **Three of four pairs had identical text; one differed** | Completion token counts matched; the original failure remains a failure |
| CUDA training | Two independent jobs, 4,096 steps per uninterrupted/resumed path | Each partition executed a full baseline plus a 2,048-step prefix and 2,048-step resume; each process saw one MIG instance |
| Checkpoint resume | Exact model, optimizer, CPU/CUDA RNG, loss sequence and step equality | Uninterrupted execution compared with a fresh-process resume after step 2,048 |
| Concurrent training | 3.734 seconds of overlapping measured training intervals | Demonstrates simultaneous execution of this small fixture, not an efficiency gain |
| Checkpoint retention | Six checkpoint files retained and rehashed after normal release | An independent CPU reader also compared the saved tensors and state |
| Whole-GPU restoration | MIG disabled, one full GPU, no owned serving/training containers remaining | Normal release and restore; no emergency cleanup |
| Post-restore CUDA | One visible A100, 1 MiB round-trip equality | Fresh whole-GPU lease; 42,405,855,232 bytes reported usable |
| Live diagnostics | Healthy daemon, fresh inventory, one available GPU, zero partitions | Actual `nodus-dc doctor` result after restoration |
| Resource closure | Test machine, temporary SSH key and controller resources removed | Independent machine-absence observation retained |

The training fixture reduced its loss from 38.868522644 to 0.502991557. This is
an application checkpoint/recovery check, not an LLM training or convergence
benchmark. The [training example](../examples/training/checkpoint_training.py)
owns saving and loading its state; the package does not restore process memory.
Training used PyTorch `2.14.1+cu130` inside the pinned SGLang image listed below.

## Artifact boundaries

The host used Ubuntu 24.04, driver `580.105.08` and kernel `6.8.0-1064-nvidia`.
Inference ran
with the public dev13 wheel. Training, restore and diagnostics ran after a normal
upgrade to the frozen dev14 candidate. The final dev14 release was prepared
after these GPU observations.

| Artifact | Identity |
| --- | --- |
| Inference wheel SHA-256 | `e23358e43841d3a1d0d94de960623001ae631b5946f0100595b6b11996228f18` |
| GPU-tested dev14 candidate source | `57adf15890ab213abd483656262a61a6a6eba55a` |
| GPU-tested candidate wheel SHA-256 | `facab1fe831650f4c6b435ab5c5199f84f18196ae6e19a79457c31b44f2a89dc` |
| Training example SHA-256 | `203f832dfbc4a7f65fa21743856446e330e7e66208b0df6ad3406e2714359e95` |
| Published dev14 source | `c2b5fe80fcb93cfb57b0bf06d34abfb3720fef73` |
| Published dev14 wheel SHA-256 | `8ef7558a94a52f9ecb1319fa18431b727c7f9021e5d9134b99edb0f520efc625` |

The inference model was `Qwen/Qwen2.5-0.5B-Instruct` at revision
`7ae557604adf67be50417f59c2c2f167def9a775`, with all eight model files checked
against the frozen manifest. Images were
`vllm/vllm-openai@sha256:5f5e535216848d0c52159c8c13a0af04be5f6fe1a84e79914300610796f76d40`
and
`lmsysorg/sglang@sha256:f7876bef696ccf9cf75a2bf7ccb82970f5fac577f082fb8ca95c9a59d2160eb5`.
Both used BF16, tensor parallelism 1, seed 0, maximum model length 2,048,
memory fraction 0.45 and eager execution without CUDA graphs. SGLang used the
Triton attention backend **without** its deterministic-inference flag. Four
prompts were submitted twice each, with temperature 0, seed 0 and at most 24
completion tokens. A fixed sampling seed alone did not make every SGLang text
repeat identical; the run does not establish that MIG caused the mismatch.

A member-by-member comparison of the candidate and published wheels found only
`nodus_dc/dashboard.py` and the wheel's `RECORD` changed. All other wheel members
were identical. The hardware results therefore describe the recorded candidate
and its unchanged execution modules; **the final wheel was not rerun on this
GPU**. Its installation and dashboard checks are separate. Download the exact
[dev14 release](https://github.com/nodus-compute/nodus-dc/releases/tag/v0.1.0-dev14)
and verify its published checksums.

The retained hardware receipt has SHA-256
`cea8d943df020636b439ae3e5bf7a4992e96d49d942d8b279d9d3332055edfd6`;
the raw host archive has SHA-256
`889dab4f83090b5e753c59d453f52ce5ea53ba6d50730a41934463aa3bb9c6a4`.
Those operational records are retained separately and are not public release
downloads. These hashes identify the records; they are not independent proof of
the results. This page omits account, host and temporary-resource identities.

## Remaining qualification

The small prompt set does not establish general model correctness. Neither
throughput/latency superiority against stock engines or public nodes, SGLang
determinism, hostile-tenant isolation, encrypted execution from the host,
physical bare-metal customer handoff, nor a connected scheduling and cash-payment
cycle was established. A clean device/process listing is not proof of secure
memory erasure. Earlier H100 failures retain their original outcomes in the
[dev7 report](hardware-evidence-dev7.md).
