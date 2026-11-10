# Kubernetes serving integration

This integration renders pinned vLLM or SGLang Pods using the cluster's existing NVIDIA device plugin or GPU Operator. The Kubernetes scheduler and kubelet own allocations. Nodus does not claim the same devices in SQLite, create a second device plugin, edit GPU Operator configuration, repartition nodes, or make a platform capacity offer. Run the local inventory component in `--allocation-authority kubernetes` observe-only mode on these hosts.

The module is implemented and locally contract-tested. Strict server-side dry-runs have also been checked against a disposable Kubernetes API server. A valid manifest is not a qualified GPU runtime tuple. Engine startup as the non-root user, model access, CNI enforcement, actual inference, contention, and Pod removal/clean handback require a real cluster qualification receipt before describing a tuple as supported for production.

## Prerequisites and allocation semantics

- A Linux/amd64 NVIDIA GPU node with working drivers, container runtime integration and existing device plugin. No CPU fallback is rendered.
- An existing namespace and read-only model PVC containing the complete `Qwen/Qwen2.5-0.5B-Instruct` snapshot at revision `7ae557604adf67be50417f59c2c2f167def9a775` at the PVC root. Verify its file manifest against the pinned model before deployment and record that manifest's SHA-256. An annotation records this digest; it does not verify PVC contents by itself.
- Either `nvidia.com/gpu` or an exact resource name already advertised by the plugin, such as `nvidia.com/mig-1g.10gb`. One integer unit is requested with equal request and limit. The resource name's semantics depend on operator configuration: `nvidia.com/gpu` can expose a physical GPU, a single-strategy MIG instance, or a time-sliced replica. Explicit MIG profiles can also be time-sliced. Review actual plugin configuration and node labels; the manifest does not establish isolation.
- A CNI that enforces NetworkPolicy. The generated policy requests denial of ingress and egress for the Pod. Other policies are additive; check their combined effect. Kubernetes port-forward provides the operator's local control path. No Service, Ingress, NodePort or LoadBalancer is created. Keep port-forward bound to loopback because engine developer lifecycle endpoints are privileged.
- A model volume readable by UID/GID 1000, writable scratch space, and enough CPU/RAM. The manifests use a read-only root filesystem, drop capabilities, disable service-account token mounting, and run as non-root. These settings need runtime qualification with the exact images; they are not an untrusted multitenancy security claim.

The engine images are immutable Linux/amd64 digests from the same versioned profiles as `nodus_dc.serving`: vLLM 0.30.0 and SGLang 0.5.23. They are qualification candidates. The Kubernetes path reuses the exact engine command builder, offline Hugging Face settings, BF16, eager execution, single tensor parallel worker and sleep/memory-saver configuration. Cache writes go to `/tmp`; the model volume is mounted read-only at `/models`. Image pull is performed by the cluster if needed and is distinct from workload egress. For disconnected installations, preload the exact image digest on the target nodes through the operator's image distribution process.

## Render and deploy through the existing allocator

With the package installed, render JSON accepted by kubectl. Supply the SHA-256 of the prepared model file manifest; do not copy a placeholder into a production deployment.

```sh
python -m nodus_dc.kubernetes render \
  --engine vllm --version 0.30.0 \
  --name nodus-vllm --namespace gpu-serving --model-pvc qwen-pinned \
  --model-manifest-sha256 "$MODEL_MANIFEST_SHA256" \
  --resource-key nvidia.com/gpu > nodus-vllm.json

kubectl --context "$TARGET_CONTEXT" apply --dry-run=server --validate=strict -f nodus-vllm.json
kubectl --context "$TARGET_CONTEXT" apply -f nodus-vllm.json
kubectl --context "$TARGET_CONTEXT" -n gpu-serving wait --for=condition=Ready pod/nodus-vllm --timeout=600s
kubectl --context "$TARGET_CONTEXT" -n gpu-serving port-forward --address 127.0.0.1 pod/nodus-vllm 18000:8000
```

For SGLang, use `--engine sglang --version 0.5.23`. For an existing mixed-strategy MIG profile, use its advertised resource name, for example `--resource-key nvidia.com/mig-1g.10gb`. The generator does not create that profile or guarantee the model fits it. Add `--runtime-class nvidia` only when that RuntimeClass exists and is required by your cluster. Engine profiles support exactly one GPU-resource unit and Linux/amd64; other architectures, arbitrary engine versions, multi-node tensor parallelism and automatic GPU partition changes are outside this integration.

Before submitting, inspect `kubectl --context "$TARGET_CONTEXT" get nodes -o json` and the existing device-plugin configuration. If resource capacity is missing or a Pod is Pending, diagnose its Events and the operator. Do not label fake capacity, remove its GPU request, or start the local standalone allocator to bypass Kubernetes.

The Pod has `restartPolicy: Never`. A failed Pod remains visible for diagnosis; operator replacement is explicit. Its HTTP readiness probe is engine process readiness, not numerical inference correctness. Call `ServingClient.activate()` and run the frozen real-GPU qualification workload over the loopback port-forward to test actual inference.

## Sleep, reclaim and removal

Use `ServingClient` over `http://127.0.0.1:18000` to gate managed requests, pause generation, release engine memory, resume, and probe inference. The GPU extended-resource allocation remains assigned to the Pod while it sleeps. Memory release never edits its Kubernetes resource request, releases a Nodus lease, or makes marketplace capacity available.

After draining managed traffic, delete the exact Pod through Kubernetes and observe termination with the cluster's normal tools. A deletion acknowledgment, disappearance after force deletion, node unreachable state, or scheduler resource accounting alone is not proof that GPU processes stopped or that cross-customer memory was cleared. This integration provides no verified clean handback to external customers, no force-delete shortcut, and no external fractional leases. Keep uncertain nodes under the operator's existing quarantine/remediation process. Delete the matching NetworkPolicy once the Pod has gone if no longer needed.

## Qualification and primary sources

The local test `tests/test_kubernetes.py` exercises unsupported input rejection, pinned engine profiles, resource equality, private control exposure, and independence of repeated renders. Independent disposable-cluster validation covered strict server-side dry-runs of both engines with full-GPU and explicit MIG resource names and a negative request/limit mismatch. It did not start the generated Pods or establish GPU support.

Real qualification must separately record cluster/API-server, device-plugin/GPU Operator, driver/runtime/CNI and GPU/MIG configuration versions, exact image and model hashes, Pod UID/node/device allocation, actual inference/logprob and latency results, sleep/resume behavior, competing GPU-request scheduling, operator restart, node loss and clean reclaim evidence. The frozen serving plan and its numerical gates remain authoritative; a successful schema check does not satisfy them.

Primary references: [Kubernetes GPU scheduling](https://kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/), [NVIDIA GPU Operator MIG configuration](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-operator-mig.html), [NVIDIA GPU time slicing and isolation limits](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-sharing.html), [kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/).
