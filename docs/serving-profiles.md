# vLLM and SGLang on dev7

Use the pinned serving recipes with the installed `0.1.0.dev7` package. They
generate workload JSON for the normal allocation commands; generation does not
reserve a GPU, pull an image, launch a container, or enable capacity lending.
The [hardware report](hardware-evidence-dev7.md) and
[support matrix](support-matrix.md) record the limits of the observed results.

## Generate and start a workload

Preload the exact engine image listed in the support matrix and a local model
snapshot containing `config.json`. The hardware experiments used
`Qwen/Qwen2.5-0.5B-Instruct` revision
`7ae557604adf67be50417f59c2c2f167def9a775`. Other models need their own correctness,
memory and performance measurements. These recipes use BF16, one tensor-parallel
worker, context length 2048, eager execution, memory fraction 0.45, and the served
model name `nodus-qualification`.

From this source checkout, with the package installed:

```sh
/opt/nodus-dc/current/bin/python examples/serving_profile.py \
  --engine sglang --model-directory /srv/models/qwen \
  --numerical-profile deterministic-v1 --host-port 18000 > sglang.json
```

Choose `--engine vllm` for vLLM. The generated descriptor pins the engine image
digest, mounts the model read-only, and publishes inference only on host loopback.
The `loopback` network uses Docker bridge networking and permits outbound access;
offline model flags do not implement an outbound firewall. `--network none`
removes networking and published ports. The hardware qualification used a
separate controlled in-container client and a verified host firewall for its
offline observations.

With the standalone daemon configured as described in the main README, obtain
the exact GPU UUID from inventory, reserve it, and use the returned lease ID and
generation:

```sh
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone \
  reserve --resource GPU-EXACT-UUID --mode exclusive_gpu \
  --ttl-seconds 3600 --request-key my-serving-job
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone \
  start LEASE_ID --generation GENERATION --workload sglang.json
```

Wait for the engine to become ready before calling `ServingClient.activate()`.
Keep one client in the application process that owns managed request admission:

```python
from nodus_dc.serving import ServingClient

client = ServingClient('sglang', 'http://127.0.0.1:18000')
client.activate()
result = client.complete('The capital of France is', max_tokens=16)
client.drain()
client.release_memory()
client.resume()
```

Independent clients bypass that client's request counter. Route all managed
requests through its admission gate. Engine pause/sleep controls inference and
memory; it does not release a GPU or allow another tenant onto it. To end the
workload, use the normal `release LEASE_ID --generation GENERATION` command. A
successful engine response alone is not proof of clean hardware handback.

## Numerical profiles

`default-v1` produces the existing dev7 command without extra numerical flags.
`deterministic-v1` adds `VLLM_BATCH_INVARIANT=1` for vLLM, or
`--enable-deterministic-inference --attention-backend fa3` for SGLang. It leaves
the pinned image, model settings, allocation and memory limits unchanged.
Use the same numerical profile for dedicated reference and shared measurements.
The name identifies a tested configuration; it does not promise exact outputs on
every model, GPU, driver or attention backend.

On the recorded H100 configuration, both deterministic profiles matched their
dedicated serial references under trusted MPS sharing. SGLang also passed its
separate full primary test. vLLM's full primary test failed the fixed performance
targets despite correct outputs. The default shared profiles failed numerical
targets. No two-GPU-to-one inference benefit is qualified yet; this recipe does
not automatically enable sharing or mark any configuration hardware-qualified.

The generator deliberately requires an explicit profile and the dev7 package.
It does not alter the installed serving module or its default behavior. For
Kubernetes use the [scheduler integration](../kubernetes/README.md); a Docker
descriptor is not a Kubernetes allocation and must not be used to bypass the
cluster's device plugin.
