"""Exercise the recipe CLI and backend admission; no engine or GPU execution."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from nodus_dc.backend import NvidiaDockerBackend
from nodus_dc.serving import build_workload


ROOT = Path(__file__).resolve().parents[1]


class ServingRecipeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.model = Path(temporary.name).resolve() / 'model with spaces'
        self.model.mkdir()
        (self.model / 'config.json').write_text('{}')

    def recipe(self, engine, profile, network='loopback'):
        return subprocess.run(
            [sys.executable, str(ROOT / 'examples/serving_profile.py'),
             '--engine', engine, '--model-directory', str(self.model),
             '--numerical-profile', profile, '--network', network,
             '--host-port', '18001'],
            env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
            cwd=self.model.parent, capture_output=True, text=True, timeout=10)

    def test_triton_cli_emits_admissible_pinned_descriptor_without_launch(self):
        for network in ('loopback', 'none'):
            with self.subTest(network=network):
                result = self.recipe('sglang', 'deterministic-triton-v1', network)
                self.assertEqual(result.returncode, 0, result.stderr)
                workload = json.loads(result.stdout)
                expected = build_workload('sglang', self.model, host_port=18001)
                expected['command'] += [
                    '--enable-deterministic-inference', '--attention-backend', 'triton']
                if network == 'none':
                    expected['network'] = 'none'
                    del expected['ports']
                self.assertEqual(workload, expected)
                calls = []
                backend = NvidiaDockerBackend(host_id='fixture',
                                              command=lambda *args, **kw: calls.append(args))
                for mode in ('exclusive_gpu', 'hardware_partition'):
                    backend.validate_workload(workload, {'mode': mode})
                self.assertEqual(calls, [])

    def test_existing_profile_commands_remain_unchanged(self):
        for engine in ('vllm', 'sglang'):
            expected = build_workload(engine, self.model, host_port=18001)
            for profile in ('default-v1', 'deterministic-v1'):
                with self.subTest(engine=engine, profile=profile):
                    result = self.recipe(engine, profile)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if profile == 'deterministic-v1':
                        if engine == 'vllm':
                            expected['command'].insert(0, 'VLLM_BATCH_INVARIANT=1')
                        else:
                            expected['command'] += [
                                '--enable-deterministic-inference', '--attention-backend', 'fa3']
                    self.assertEqual(json.loads(result.stdout), expected)

    def test_triton_profile_refuses_other_engine_and_invalid_profile_without_json(self):
        for engine, profile, message in (
            ('vllm', 'deterministic-triton-v1', 'requires --engine sglang'),
            ('sglang', 'unknown-profile', 'invalid choice'),
        ):
            with self.subTest(engine=engine, profile=profile):
                result = self.recipe(engine, profile)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertIn(message, result.stderr)


if __name__ == '__main__':
    unittest.main()
