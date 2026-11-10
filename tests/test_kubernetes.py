import copy
import unittest

from nodus_dc.kubernetes import MODEL_REVISION, render
from nodus_dc.serving import PROFILES, ServingError


class KubernetesContractTest(unittest.TestCase):
    def render(self, engine='vllm', **overrides):
        args = dict(name='nodus-serving', namespace='nodus-test', model_pvc='qwen-model',
                    model_manifest_sha256='a' * 64)
        args.update(overrides)
        return render(engine, **args)

    def test_existing_plugin_is_sole_allocator_for_both_engines(self):
        for engine in PROFILES:
            result = self.render(engine)
            policy, pod = result['items']
            container = pod['spec']['containers'][0]
            self.assertEqual(container['image'], PROFILES[engine].image)
            self.assertEqual(container['resources']['requests']['nvidia.com/gpu'], 1)
            self.assertEqual(container['resources']['limits']['nvidia.com/gpu'], 1)
            self.assertEqual(pod['metadata']['annotations']['nodus.dev/model-revision'], MODEL_REVISION)
            self.assertFalse(pod['spec']['automountServiceAccountToken'])
            self.assertEqual(pod['spec']['nodeSelector']['kubernetes.io/arch'], 'amd64')
            self.assertNotIn('hostPID', pod['spec'])
            self.assertNotIn('hostNetwork', pod['spec'])
            self.assertNotIn('nodeName', pod['spec'])
            self.assertNotIn('runtimeClassName', pod['spec'])
            self.assertEqual(policy['spec']['ingress'], [])
            self.assertEqual(policy['spec']['egress'], [])
            self.assertTrue(all('hostPath' not in volume for volume in pod['spec']['volumes']))
            self.assertTrue(container['volumeMounts'][0]['readOnly'])

    def test_explicit_mig_only_changes_plugin_resource_request(self):
        result = self.render('sglang', resource_key='nvidia.com/mig-1g.10gb', runtime_class='nvidia')
        pod = result['items'][1]
        self.assertEqual(pod['spec']['runtimeClassName'], 'nvidia')
        resource = pod['spec']['containers'][0]['resources']
        self.assertNotIn('nvidia.com/gpu', resource['limits'])
        self.assertEqual(resource['requests']['nvidia.com/mig-1g.10gb'], 1)
        self.assertEqual(resource['limits']['nvidia.com/mig-1g.10gb'], 1)

    def test_rejects_unsupported_resource_names_missing_pins_and_mutable_version(self):
        cases = [{'resource_key': x} for x in ('gpu', 'nvidia.com/gpu.shared', 'amd.com/gpu', 'nvidia.com/mig-foo', 'nvidia.com/mig-1g.10gb\n')]
        cases += [{'model_manifest_sha256': ''}, {'model_manifest_sha256': 'x' * 64},
                  {'version': 'latest'}, {'namespace': '../default'}, {'name': 'Bad_Name'},
                  {'runtime_class': 'nvidia;cmd'}, {'memory_fraction': float('nan')}]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ServingError):
                self.render(**args)

    def test_invocations_do_not_mutate_previous_manifests(self):
        first = self.render()
        before = copy.deepcopy(first)
        second = self.render(name='second')
        second['items'][1]['spec']['containers'][0]['args'].append('changed')
        self.assertEqual(first, before)


if __name__ == '__main__':
    unittest.main()
