# vLLM and SGLang on dev7 through dev12

Use the pinned serving recipes with the installed `0.1.0.dev7`, `0.1.0.dev8`, `0.1.0.dev9`, `0.1.0.dev10`, `0.1.0.dev11` or `0.1.0.dev12` package. They
generate workload JSON for the normal allocation commands; generation does not
reserve a GPU, pull an image, launch a container, or enable capacity lending.
The [hardware report](hardware-evidence-dev7.md) and
[support matrix](support-matrix.md) record the limits of the observed results.

Dev8 changes the platform consent request encoding. Its serving, allocation and
partitioning modules are byte-identical to dev7. The linked GPU measurements
were performed on dev7; they are not a new dev8 hardware qualification. Dev9 adds
a read-only availability projection to status and changes the local dashboard;
its allocation enforcement, partitioning and serving modules are unchanged.
Dev10 corrects the age of platform permission responses; its GPU allocation,
partitioning and serving modules remain byte-identical to dev9. The dev10 recipe
generator emits the same workload descriptors. These historical measurements
retain their original artifact and hardware bindings; they do not automatically
qualify a later complete release.

Dev11 changes only the dashboard and version module in the runtime wheel. Its
serving implementation is byte-identical to dev10, and its recipe generator
adds dev11 to the accepted versions without changing descriptor generation.
Dev12 corrects these command paths and engine-specific examples; it adds dev12
to the recipe version guard without changing runtime behavior or descriptors.

## Generate and start a workload

Preload the exact engine image listed in the support matrix and a local model
snapshot containing `config.json`. The hardware experiments used
`Qwen/Qwen2.5-0.5B-Instruct` revision
`7ae557604adf67be50417f59c2c2f167def9a775`. Other models need their own correctness,
memory and performance measurements. These recipes use BF16, one tensor-parallel
worker, context length 2048, eager execution, memory fraction 0.45, and the served
model name `nodus-qualification`.

From this source checkout, with the package installed, choose one engine.
The commands use the installed interpreter and CLI directly; no global package
or shell PATH change is required. Replace `/srv/models/qwen` with your preloaded
model snapshot directory.

For vLLM:

```sh
/opt/nodus-dc/current/bin/python examples/serving_profile.py \
  --engine vllm --model-directory /srv/models/qwen \
  --numerical-profile deterministic-v1 --host-port 18000 > vllm.json
```

For SGLang instead:

```sh
/opt/nodus-dc/current/bin/python examples/serving_profile.py \
  --engine sglang --model-directory /srv/models/qwen \
  --numerical-profile deterministic-v1 --host-port 18000 > sglang.json
```

The generated descriptor pins the engine image
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
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone \
  reserve --resource GPU-EXACT-UUID --mode exclusive_gpu \
  --ttl-seconds 3600 --request-key my-serving-job
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone \
  start LEASE_ID --generation GENERATION --workload vllm.json
```

For SGLang, use `--workload sglang.json` in the start command. Run only the
client block that matches the descriptor you started. Both examples use port
18000, so release the first workload before starting the other on that port.

Both pinned engines expose the same read-only health endpoint on the selected
host port. Check it before calling `ServingClient.activate()`:

```sh
curl --fail --show-error --max-time 10 http://127.0.0.1:18000/health
```

A successful response means the engine reports healthy. A refused connection,
HTTP error or timeout can mean it is still loading or has failed; do not continue
to the client block on an error. Check `docker logs CONTAINER_ID`, using the
container ID in the start result, and repeat the health check after resolving
the cause. The 10-second bound applies only to this HTTP request, not to engine
startup. Health alone is not inference validation: `activate()` also checks the
served model and performs a one-token completion.

Keep one client in the application process that owns managed request admission.
For vLLM:

```sh
/opt/nodus-dc/current/bin/python - <<'PY'
from nodus_dc.serving import ServingClient

client = ServingClient('vllm', 'http://127.0.0.1:18000')
client.activate()
result = client.complete('The capital of France is', max_tokens=16)
print(result)
client.drain()
client.release_memory()
client.resume()
PY
```

For SGLang:

```sh
/opt/nodus-dc/current/bin/python - <<'PY'
from nodus_dc.serving import ServingClient

client = ServingClient('sglang', 'http://127.0.0.1:18000')
client.activate()
result = client.complete('The capital of France is', max_tokens=16)
print(result)
client.drain()
client.release_memory()
client.resume()
PY
```

Independent clients bypass that client's request counter. Route all managed
requests through its admission gate. Engine pause/sleep controls inference and
memory; it does not release a GPU or allow another tenant onto it. To end the
workload, release the same returned lease and generation through the installed CLI:

```sh
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone \
  release LEASE_ID --generation GENERATION
```

A successful engine response alone is not proof of clean hardware handback.

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
targets despite correct outputs; a later preregistered, longer offline comparison
passed its declared correctness, throughput, latency and CPU checks, subject to
the statistical assumptions in the hardware report. The default shared profiles
failed numerical targets. No two-GPU-to-one inference benefit is qualified yet; this recipe does
not automatically enable sharing or mark any configuration hardware-qualified.

The generator requires an explicit profile and the dev7, dev8, dev9, dev10, dev11 or dev12 package.
It does not alter the installed serving module or its default behavior. For
Kubernetes use the [scheduler integration](../kubernetes/README.md); a Docker
descriptor is not a Kubernetes allocation and must not be used to bypass the
cluster's device plugin.
