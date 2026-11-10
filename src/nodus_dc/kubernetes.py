"""Generate pinned serving Pods owned entirely by Kubernetes/device plugins.

No local store, GPU discovery, allocator, bridge or partition mutation is invoked.
Schema acceptance is separate from qualification on a real GPU cluster.
"""
import argparse
import json
import re
import sys

from .serving import engine_command, profile, ServingError


MODEL_ID = 'Qwen/Qwen2.5-0.5B-Instruct'
MODEL_REVISION = '7ae557604adf67be50417f59c2c2f167def9a775'
DNS_LABEL = re.compile(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z')
RESOURCE_KEY = re.compile(r'nvidia\.com/(?:gpu|mig-[1-9][0-9]*g(?:\.[1-9][0-9]*c)?\.[1-9][0-9]*gb)\Z')


def _name(value, label):
    if not isinstance(value, str) or not DNS_LABEL.fullmatch(value):
        raise ServingError(f'{label} must be a DNS label of at most 63 characters')
    return value


def render(engine, *, name, namespace, model_pvc, resource_key='nvidia.com/gpu',
           model_manifest_sha256, runtime_class=None, memory_fraction=0.45,
           version=None):
    """One GPU-resource unit, one pinned model, no public or cluster service.

    The operator must verify the read-only PVC is the annotated exact snapshot.
    Resource names delegate allocation semantics to the existing device plugin:
    nvidia.com/gpu can mean full GPU, MIG-single, or time-sliced access.
    NetworkPolicy requires an enforcing CNI and is not a security attestation.
    """
    spec = profile(engine, version)
    for value, label in ((name, 'name'), (namespace, 'namespace'), (model_pvc, 'model_pvc')):
        _name(value, label)
    if not isinstance(resource_key, str) or not RESOURCE_KEY.fullmatch(resource_key):
        raise ServingError('resource_key must be nvidia.com/gpu or an explicit nvidia.com/mig-Ng.Ngb profile')
    if not isinstance(model_manifest_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', model_manifest_sha256):
        raise ServingError('model_manifest_sha256 must identify the prepared PVC asset manifest')
    if runtime_class is not None:
        _name(runtime_class, 'runtime_class')
    labels = {'app.kubernetes.io/name': 'nodus-serving', 'app.kubernetes.io/instance': name}
    metadata = {'name': name, 'namespace': namespace, 'labels': labels}
    annotations = {
        'nodus.dev/allocation-authority': 'kubernetes-device-plugin',
        'nodus.dev/qualification': 'candidate-unqualified',
        'nodus.dev/engine-version': spec.version,
        'nodus.dev/model-id': MODEL_ID,
        'nodus.dev/model-revision': MODEL_REVISION,
        'nodus.dev/model-manifest-sha256': model_manifest_sha256,
        'nodus.dev/resource-semantics': 'defined-by-existing-device-plugin-configuration',
    }
    pod_spec = {
        'automountServiceAccountToken': False,
        'enableServiceLinks': False,
        'restartPolicy': 'Never',
        'terminationGracePeriodSeconds': 60,
        'nodeSelector': {'kubernetes.io/os': 'linux', 'kubernetes.io/arch': 'amd64'},
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000,
                            'fsGroup': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
        'containers': [{
            'name': 'engine', 'image': spec.image, 'imagePullPolicy': 'IfNotPresent',
            'command': ['/usr/bin/env'],
            'args': engine_command(engine, memory_fraction=memory_fraction, version=version),
            'env': [{'name': key, 'value': value} for key, value in {
                'HOME': '/tmp', 'HF_HOME': '/tmp/huggingface', 'HF_HUB_OFFLINE': '1',
                'XDG_CACHE_HOME': '/tmp/cache', 'NUMBA_CACHE_DIR': '/tmp/numba',
                'TRITON_CACHE_DIR': '/tmp/triton'}.items()],
            'ports': [{'name': 'inference', 'containerPort': 8000, 'protocol': 'TCP'}],
            'resources': {'requests': {'cpu': '2', 'memory': '8Gi', resource_key: 1},
                          'limits': {'cpu': '4', 'memory': '16Gi', resource_key: 1}},
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                'capabilities': {'drop': ['ALL']}},
            'volumeMounts': [{'name': 'model', 'mountPath': '/models', 'readOnly': True},
                             {'name': 'tmp', 'mountPath': '/tmp'},
                             {'name': 'shm', 'mountPath': '/dev/shm'}],
            'startupProbe': {'httpGet': {'path': '/health', 'port': 'inference'},
                             'periodSeconds': 5, 'timeoutSeconds': 2, 'failureThreshold': 120},
            'readinessProbe': {'httpGet': {'path': '/health', 'port': 'inference'},
                               'periodSeconds': 5, 'timeoutSeconds': 2, 'failureThreshold': 3},
        }],
        'volumes': [{'name': 'model', 'persistentVolumeClaim': {'claimName': model_pvc, 'readOnly': True}},
                    {'name': 'tmp', 'emptyDir': {'sizeLimit': '8Gi'}},
                    {'name': 'shm', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Gi'}}],
    }
    if runtime_class:
        pod_spec['runtimeClassName'] = runtime_class
    pod = {'apiVersion': 'v1', 'kind': 'Pod',
           'metadata': {**metadata, 'annotations': annotations}, 'spec': pod_spec}
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
              'metadata': {**metadata},
              'spec': {'podSelector': {'matchLabels': labels},
                       'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
    return {'apiVersion': 'v1', 'kind': 'List', 'items': [policy, pod]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    cmd = commands.add_parser('render', help='print JSON; never contact or modify a cluster')
    cmd.add_argument('--engine', choices=['vllm', 'sglang'], required=True)
    cmd.add_argument('--version')
    cmd.add_argument('--name', required=True)
    cmd.add_argument('--namespace', required=True)
    cmd.add_argument('--model-pvc', required=True)
    cmd.add_argument('--model-manifest-sha256', required=True)
    cmd.add_argument('--resource-key', default='nvidia.com/gpu')
    cmd.add_argument('--runtime-class')
    cmd.add_argument('--memory-fraction', type=float, default=0.45)
    args = vars(parser.parse_args(argv))
    args.pop('command')
    try:
        json.dump(render(**args), sys.stdout, indent=2, allow_nan=False)
        sys.stdout.write('\n')
    except ServingError as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
