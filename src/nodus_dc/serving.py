"""Versioned serving lifecycle adapters, independent of resource lease release.

Profiles are qualification candidates until a real-GPU support-matrix receipt is
published. Engine pause/sleep only controls inference and memory. This module
never releases a Nodus allocation or asserts clean bare-metal handback.
"""
from dataclasses import dataclass
import ipaddress
import json
import math
from pathlib import Path
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


ADAPTER_VERSION = '1.0.0'


class ServingError(RuntimeError):
    pass


@dataclass(frozen=True)
class Profile:
    engine: str
    version: str
    image: str
    source_commit: str
    qualification: str = 'candidate_unqualified'
    architecture: str = 'linux/amd64'


PROFILES = {
    'vllm': Profile(
        'vllm', '0.30.0',
        'vllm/vllm-openai@sha256:5f5e535216848d0c52159c8c13a0af04be5f6fe1a84e79914300610796f76d40',
        'ced6857afa0ea7b2e3f0846a62e1394e90f15607'),
    'sglang': Profile(
        'sglang', '0.5.23',
        'lmsysorg/sglang@sha256:f7876bef696ccf9cf75a2bf7ccb82970f5fac577f082fb8ca95c9a59d2160eb5',
        '297e54fd105e974cdf401e5b4d20253a22c16f90'),
}


def profile(engine, version=None):
    result = PROFILES.get(engine)
    if result is None or (version is not None and version != result.version):
        raise ServingError('unsupported engine/version; use a documented pinned profile')
    return result


def engine_command(engine, *, memory_fraction=0.45, served_model='nodus-qualification',
                   max_model_length=2048, version=None):
    """Pinned engine command shared by Docker and Kubernetes deployment paths."""
    profile(engine, version)
    if isinstance(memory_fraction, bool) or not isinstance(memory_fraction, (float, int)) or not math.isfinite(memory_fraction) or not 0.05 <= memory_fraction <= 0.9:
        raise ServingError('memory_fraction must be finite and between 0.05 and 0.9')
    if type(max_model_length) is not int or not 128 <= max_model_length <= 32768:
        raise ServingError('max_model_length must be between 128 and 32768')
    if not isinstance(served_model, str) or not served_model or '\0' in served_model:
        raise ServingError('served_model must be a nonempty name')
    if engine == 'vllm':
        command = [
            'VLLM_SERVER_DEV_MODE=1', 'VLLM_NO_USAGE_STATS=1',
            'DO_NOT_TRACK=1', 'TRANSFORMERS_OFFLINE=1',
            'python3', '-m', 'vllm.entrypoints.cli.main', 'serve', '/models',
            '--served-model-name', served_model, '--host', '0.0.0.0',
            '--port', '8000', '--dtype', 'bfloat16',
            '--max-model-len', str(max_model_length),
            '--gpu-memory-utilization', str(memory_fraction),
            '--tensor-parallel-size', '1', '--seed', '0',
            '--enable-sleep-mode', '--enforce-eager',
        ]
    else:
        command = [
            'DO_NOT_TRACK=1', 'TRANSFORMERS_OFFLINE=1',
            'python3', '-m', 'sglang.launch_server', '--model-path', '/models',
            '--served-model-name', served_model, '--host', '0.0.0.0',
            '--port', '8000', '--dtype', 'bfloat16',
            '--context-length', str(max_model_length),
            '--mem-fraction-static', str(memory_fraction),
            '--tp-size', '1', '--random-seed', '0',
            '--enable-memory-saver', '--enable-weights-cpu-backup',
            '--disable-cuda-graph',
        ]
    return command


def build_workload(engine, model_directory, *, host_port=18000,
                   memory_fraction=0.45, served_model='nodus-qualification',
                   max_model_length=2048, version=None):
    """Return a validated-backend workload descriptor; do not launch/pull anything.

    The official image and model assets must already be present. Container root is
    read-only; the backend mounts the model directory read-only. Networking is
    loopback-published bridge networking, NOT proof of outbound denial. Enforce
    the qualification firewall/network policy separately for offline acceptance.
    """
    spec = profile(engine, version)
    directory = Path(model_directory).expanduser().resolve()
    if not directory.is_dir() or not (directory / 'config.json').is_file():
        raise ServingError('model_directory must contain a local model config.json')
    if type(host_port) is not int or not 1024 <= host_port <= 65535:
        raise ServingError('host_port must be an unprivileged TCP port')
    command = engine_command(engine, memory_fraction=memory_fraction,
                             served_model=served_model,
                             max_model_length=max_model_length, version=version)
    return {
        'image': spec.image, 'entrypoint': '/usr/bin/env', 'command': command,
        'mounts': [{'source': str(directory), 'target': '/models'}],
        'network': 'loopback', 'ports': [{'host': host_port, 'container': 8000}],
        'shm_bytes': 1 << 30,
    }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LocalHTTP:
    """Bounded loopback-only HTTP; no proxies, redirects or automatic mutation retries."""
    def __init__(self, base_url, timeout=30.0, api_key=None):
        parsed = urlsplit(base_url)
        try:
            loopback = ipaddress.ip_address(parsed.hostname or '').is_loopback
            port = parsed.port
        except ValueError:
            loopback, port = False, None
        if parsed.scheme != 'http' or not loopback or port is None or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
            raise ServingError('serving control requires an explicit loopback http://IP:port URL')
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ServingError('HTTP timeout must be finite, positive and at most 300 seconds')
        if api_key is not None and (not isinstance(api_key, str) or '\r' in api_key or '\n' in api_key):
            raise ServingError('invalid API key format')
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.api_key = api_key
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __call__(self, method, path, payload=None):
        if not path.startswith('/') or path.startswith('//'):
            raise ServingError('invalid local API path')
        headers = {'Accept': 'application/json'}
        body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
        if body is not None:
            headers['Content-Type'] = 'application/json'
        if self.api_key:
            headers['Authorization'] = 'Bearer ' + self.api_key
        request = Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                data = response.read(4 * 1024 * 1024 + 1)
                if len(data) > 4 * 1024 * 1024:
                    raise ServingError('engine response exceeded the 4 MiB limit')
        except HTTPError as exc:
            # Avoid recording credentials or arbitrary private engine error bodies.
            raise ServingError(f'engine HTTP {exc.code} for {method} {path}; operation outcome may be unknown') from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ServingError(f'engine transport failed for {method} {path}; operation outcome may be unknown') from exc
        if not data.strip():
            return None
        try:
            result = json.loads(data)
        except (ValueError, UnicodeError) as exc:
            raise ServingError('engine returned invalid JSON') from exc
        if isinstance(result, dict) and (result.get('error') or result.get('success') is False):
            raise ServingError('engine reported an unsuccessful operation')
        return result


class ServingClient:
    """Managed-client admission plus explicit engine pause/release/resume.

    Route managed inference through this client or an equivalent external ingress
    gate. Its request counter cannot observe clients bypassing it. Engine-level
    pause handles the scheduler; no operation grants or releases GPU ownership.
    A failed lifecycle request closes admissions and leaves state unknown.
    """
    def __init__(self, engine, base_url, *, version=None,
                 model='nodus-qualification', timeout=30.0, api_key=None,
                 transport=None):
        self.profile = profile(engine, version)
        self.model = model
        # Validate URL even for a test transport, so tests cannot bypass policy.
        http = LocalHTTP(base_url, timeout=timeout, api_key=api_key)
        self._request = transport or http
        self._condition = threading.Condition()
        self._lifecycle = threading.Lock()
        self._state = 'new'
        self._accepting = False
        self._active = 0
        self._released = False

    def status(self):
        with self._condition:
            return {'adapter_version': ADAPTER_VERSION, 'engine': self.profile.engine,
                    'expected_engine_version': self.profile.version,
                    'qualification': self.profile.qualification,
                    'engine_state': self._state, 'accepting': self._accepting,
                    'active_client_requests': self._active,
                    'lease_released': False, 'clean_handback_verified': False}

    @staticmethod
    def _completion(result):
        if not isinstance(result, dict) or not isinstance(result.get('choices'), list) or not result['choices']:
            raise ServingError('engine did not return a completion choice')
        choice = result['choices'][0]
        if not isinstance(choice, dict) or not isinstance(choice.get('text'), str):
            raise ServingError('engine completion text is missing')
        return result

    def _probe(self):
        self._request('GET', '/health')
        models = self._request('GET', '/v1/models')
        if not isinstance(models, dict) or self.model not in [m.get('id') for m in models.get('data', []) if isinstance(m, dict)]:
            raise ServingError('expected served model is absent')
        return self._completion(self._request('POST', '/v1/completions', {
            'model': self.model, 'prompt': 'The number after one is',
            'max_tokens': 1, 'temperature': 0, 'seed': 0,
        }))

    def _unknown(self):
        with self._condition:
            self._state = 'unknown'
            self._accepting = False

    def activate(self):
        """Open admissions only after actual bounded inference, not /health alone."""
        with self._lifecycle:
            with self._condition:
                if self._state not in ('new', 'unknown'):
                    raise ServingError('activate is only for initial attach or explicit unknown-state recovery')
            try:
                self._probe()
            except Exception:
                self._unknown()
                raise
            with self._condition:
                self._state, self._accepting, self._released = 'ready', True, False
            return self.status()

    def complete(self, prompt, *, max_tokens=32, logprobs=1):
        if not isinstance(prompt, str) or not prompt:
            raise ServingError('prompt must be nonempty text')
        if type(max_tokens) is not int or not 1 <= max_tokens <= 4096:
            raise ServingError('max_tokens must be between 1 and 4096')
        if type(logprobs) is not int or not 0 <= logprobs <= 5:
            raise ServingError('logprobs must be between 0 and 5')
        with self._condition:
            if not self._accepting or self._state != 'ready':
                raise ServingError('engine admissions are closed')
            self._active += 1
        try:
            return self._completion(self._request('POST', '/v1/completions', {
                'model': self.model, 'prompt': prompt, 'max_tokens': max_tokens,
                'temperature': 0, 'seed': 0, 'logprobs': logprobs,
            }))
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    def drain(self, timeout=30.0):
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or timeout <= 0:
            raise ServingError('drain timeout must be finite and positive')
        with self._lifecycle:
            with self._condition:
                if self._state != 'ready':
                    raise ServingError('drain requires a ready engine')
                self._accepting = False
                self._state = 'draining'
                deadline = time.monotonic() + timeout
                while self._active:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._state = 'unknown'
                        raise ServingError('client drain timed out; admissions remain closed')
                    self._condition.wait(remaining)
            try:
                if self.profile.engine == 'vllm':
                    self._request('POST', '/pause?mode=wait')
                    paused = self._request('GET', '/is_paused')
                    if not isinstance(paused, dict) or paused.get('is_paused') is not True:
                        raise ServingError('vLLM pause was not confirmed')
                else:
                    # All requests routed through this client have finished.
                    # Abort mode also clears any bypassed requests; callers must
                    # not claim this preserves untracked external requests.
                    self._request('POST', '/pause_generation', {'mode': 'abort'})
            except Exception:
                self._unknown()
                raise
            with self._condition:
                self._state = 'paused'
            return self.status()

    def release_memory(self):
        with self._lifecycle:
            with self._condition:
                if self._state != 'paused' or self._active:
                    raise ServingError('memory release requires a completed drain')
            try:
                if self.profile.engine == 'vllm':
                    self._request('POST', '/sleep?level=1&mode=wait')
                    sleeping = self._request('GET', '/is_sleeping')
                    if not isinstance(sleeping, dict) or sleeping.get('is_sleeping') is not True:
                        raise ServingError('vLLM sleep was not confirmed')
                else:
                    self._request('POST', '/release_memory_occupation', {'tags': ['kv_cache', 'weights']})
            except Exception:
                self._unknown()
                raise
            with self._condition:
                self._state, self._released = 'memory_released', True
            return self.status()

    def resume(self):
        with self._lifecycle:
            with self._condition:
                if self._state not in ('paused', 'memory_released'):
                    raise ServingError('resume requires a confirmed paused/released engine; unknown state needs explicit recovery')
                released = self._released
            try:
                if self.profile.engine == 'vllm':
                    if released:
                        self._request('POST', '/wake_up')
                    self._request('POST', '/resume')
                else:
                    if released:
                        self._request('POST', '/resume_memory_occupation', {'tags': ['weights', 'kv_cache']})
                    self._request('POST', '/continue_generation', {})
                self._probe()
            except Exception:
                self._unknown()
                raise
            with self._condition:
                self._state, self._accepting, self._released = 'ready', True, False
            return self.status()
