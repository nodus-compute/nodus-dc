"""Adapter contract tests only; fake transport is not GPU qualification evidence."""
import json
from pathlib import Path
import tempfile
import threading
import unittest

from nodus_dc.serving import LocalHTTP, ServingClient, ServingError, build_workload


class EngineTransport:
    def __init__(self):
        self.calls = []
        self.fail_path = None
        self.pause_confirmed = True
        self.block_prompt = None
        self.entered = threading.Event()
        self.finish = threading.Event()

    def __call__(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path == self.fail_path:
            raise ServingError('synthetic transport loss after ambiguous effect')
        if path == '/v1/models':
            return {'data': [{'id': 'nodus-qualification'}]}
        if path == '/v1/completions':
            if payload['prompt'] == self.block_prompt:
                self.entered.set()
                if not self.finish.wait(3):
                    raise ServingError('test synchronization timeout')
            return {'choices': [{'text': ' two', 'logprobs': {'tokens': [' two'], 'token_logprobs': [-0.1]}}],
                    'usage': {'prompt_tokens': 5, 'completion_tokens': 1}}
        if path == '/is_paused':
            return {'is_paused': self.pause_confirmed}
        if path == '/is_sleeping':
            return {'is_sleeping': True}
        return None


class ServingContractTests(unittest.TestCase):
    def client(self, engine='vllm'):
        transport = EngineTransport()
        client = ServingClient(engine, 'http://127.0.0.1:18000', transport=transport)
        client.activate()
        return client, transport

    def test_launch_pins_and_offline_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'config.json').write_text('{}')
            for engine in ('vllm', 'sglang'):
                workload = build_workload(engine, directory)
                self.assertIn('@sha256:', workload['image'])
                self.assertEqual(workload['entrypoint'], '/usr/bin/env')
                self.assertEqual(workload['mounts'], [{'source': str(Path(directory).resolve()), 'target': '/models'}])
                self.assertIn('TRANSFORMERS_OFFLINE=1', workload['command'])
                self.assertIn('/models', workload['command'])
            with self.assertRaises(ServingError):
                build_workload('sglang', directory, version='unknown')

    def test_admin_connection_rejects_remote_proxy_and_redirect_targets(self):
        for url in ('http://example.com:8000', 'http://localhost:8000', 'http://127.0.0.1:8000/path',
                    'http://user:password@127.0.0.1:8000', 'http://127.0.0.1:8000?remote=1'):
            with self.assertRaises(ServingError):
                LocalHTTP(url)

    def test_memory_release_does_not_release_lease(self):
        for engine in ('vllm', 'sglang'):
            client, transport = self.client(engine)
            client.drain()
            result = client.release_memory()
            self.assertEqual(result['engine_state'], 'memory_released')
            self.assertFalse(result['lease_released'])
            self.assertFalse(result['clean_handback_verified'])
            with self.assertRaises(ServingError):
                client.complete('must remain blocked')
            client.resume()
            self.assertTrue(client.status()['accepting'])
            self.assertFalse(any('/lease' in path for _, path, _ in transport.calls))

    def test_uncertain_release_fails_closed_and_cannot_resume_blindly(self):
        client, transport = self.client('sglang')
        client.drain()
        transport.fail_path = '/release_memory_occupation'
        with self.assertRaises(ServingError):
            client.release_memory()
        self.assertEqual(client.status()['engine_state'], 'unknown')
        self.assertFalse(client.status()['accepting'])
        before = len(transport.calls)
        with self.assertRaises(ServingError):
            client.resume()
        self.assertEqual(len(transport.calls), before)

    def test_uncertain_resume_remains_closed(self):
        client, transport = self.client()
        client.drain()
        client.release_memory()
        transport.fail_path = '/wake_up'
        with self.assertRaises(ServingError):
            client.resume()
        self.assertEqual(client.status()['engine_state'], 'unknown')
        self.assertFalse(client.status()['accepting'])

    def test_pause_receipt_must_be_true(self):
        client, transport = self.client()
        transport.pause_confirmed = False
        with self.assertRaises(ServingError):
            client.drain()
        self.assertEqual(client.status()['engine_state'], 'unknown')
        self.assertFalse(client.status()['accepting'])

    def test_drain_waits_for_owned_inflight_and_closes_admissions(self):
        client, transport = self.client()
        transport.block_prompt = 'blocked inference'
        worker = threading.Thread(target=client.complete, args=('blocked inference',))
        worker.start()
        self.assertTrue(transport.entered.wait(1))
        errors = []
        finished = threading.Event()
        def drain():
            try:
                client.drain(timeout=2)
            except Exception as exc:
                errors.append(exc)
            finally:
                finished.set()
        drainer = threading.Thread(target=drain)
        drainer.start()
        # Condition acquisition serializes with the admission-closing write.
        for _ in range(100):
            if not client.status()['accepting']:
                break
            finished.wait(0.01)
        self.assertFalse(client.status()['accepting'])
        with self.assertRaises(ServingError):
            client.complete('new request after drain')
        self.assertFalse(any(path.startswith('/pause') for _, path, _ in transport.calls))
        transport.finish.set()
        worker.join(2)
        drainer.join(2)
        self.assertFalse(errors)
        self.assertTrue(finished.is_set())
        self.assertEqual(client.status()['engine_state'], 'paused')

    def test_no_memory_release_before_drain(self):
        client, transport = self.client()
        count = len(transport.calls)
        with self.assertRaises(ServingError):
            client.release_memory()
        self.assertEqual(len(transport.calls), count)


if __name__ == '__main__':
    unittest.main()
