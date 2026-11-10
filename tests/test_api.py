import http.client
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from nodus_dc.api import BridgeUnixServer, LocalUnixServer, Server, token_file
from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix=".nodus-api-", dir=Path.home().resolve())
        self.clock = Clock()
        service = Service(Store(Path(self.tmp.name)/"state.sqlite3"), Backend(self.clock), clock=self.clock, bridge_enabled=True)
        self.server = Server(("127.0.0.1", 0), service, "local-"+"x"*40)
        self.bridge = BridgeUnixServer(str(Path(self.tmp.name)/"bridge.sock"), service, "bridge-"+"x"*40, owner_uid=os.geteuid())
        self.bridge_thread = threading.Thread(target=self.bridge.serve_forever, daemon=True)
        self.bridge_thread.start()
        self.local = LocalUnixServer(str(Path(self.tmp.name)/"local.sock"), service, self.server.local_token, owner_uid=os.geteuid())
        self.local_thread = threading.Thread(target=self.local.serve_forever, daemon=True)
        self.local_thread.start()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.local.shutdown()
        self.local.server_close()
        self.local_thread.join()
        self.bridge.shutdown()
        self.bridge.server_close()
        self.bridge_thread.join()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def call(self, path, value=None, token=None, raw=None, *, transport="auto"):
        if transport == "local_unix":
            c = UnixHTTPConnection(self.local.path)
        elif transport == "unix" or transport == "auto" and path.startswith("/v1/bridge/"):
            c = UnixHTTPConnection(self.bridge.path)
        else:
            c = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Content-Type":"application/json"}
        if token:
            headers["Authorization"] = "Bearer "+token
        body = raw if raw is not None else json.dumps(value or {})
        c.request("POST", path, body, headers)
        r = c.getresponse()
        result = r.status, json.loads(r.read())
        c.close()
        return result

    def test_bridge_scope_is_distinct_from_local_scope(self):
        self.assertEqual(self.call("/v1/bridge/status", token=self.server.local_token)[0], 401)
        self.assertEqual(self.call("/v1/reserve", token=self.bridge.bridge_token)[0], 403)
        self.assertEqual(self.call("/v1/reserve", token=self.bridge.bridge_token, transport="local_unix")[0], 401)
        self.assertEqual(self.call("/v1/bridge/status", token=self.bridge.bridge_token, transport="local_unix")[0], 403)
        self.assertEqual(self.call("/v1/reserve", token=self.bridge.bridge_token, transport="unix")[0], 404)
        self.assertEqual(self.call("/v1/bridge/status", token=self.bridge.bridge_token)[0], 200)
        self.assertEqual(self.call("/v1/bridge/status", token=self.bridge.bridge_token, transport="tcp")[0], 403)

    def test_daemon_maintenance_runs_expiry_without_inventory_scan(self):
        service = self.server.service
        lease = service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1001, request_key="expiry")
        service.backend.clean = False
        def unavailable():
            raise Error("inventory_unavailable", "hardware observation unavailable", 503)
        service.backend.inventory = unavailable
        self.clock.now = 1002
        class OneTick:
            def __init__(self): self.calls = []
            def wait(self, interval):
                self.calls.append(interval)
                return len(self.calls) > 1
        original = self.server.stop_event
        tick = OneTick()
        try:
            self.server.stop_event = tick
            self.server.maintain()
        finally:
            self.server.stop_event = original
        self.assertEqual(tick.calls, [5, 5])
        self.assertIsNone(self.server.maintenance_error)
        self.assertEqual(service.get(lease["id"])["state"], "quarantined")
        self.assertEqual(service.backend.verify_calls, 1)

    def test_privileged_local_mutation_requires_private_socket_and_token(self):
        body = {"resources": ["GPU-aaaa"], "mode": "exclusive_gpu", "expires_at": 1500, "request_key": "unix-owner"}
        self.assertEqual(self.call("/v1/reserve", body, self.server.local_token, transport="tcp")[0], 403)
        self.assertEqual(self.call("/v1/reserve", body, self.server.local_token, transport="local_unix")[0], 200)
        self.assertEqual(len(self.server.service.status()["leases"]), 1)

    def test_unknown_fields_and_duplicate_keys_do_not_mutate(self):
        self.assertEqual(self.call("/v1/bridge/status", {"unexpected":True}, self.bridge.bridge_token)[0], 400)
        self.assertEqual(self.call("/v1/bridge/reclaim", token=self.bridge.bridge_token,
                                  raw='{"platform_lease_id":"a","platform_lease_id":"b","platform_epoch":1}')[0], 400)
        self.assertEqual(self.server.service.status()["leases"], [])

    def test_real_unix_bridge_lifecycle_preserves_fence(self):
        token = self.bridge.bridge_token
        self.assertEqual(self.call("/v1/bridge/policy", {"enabled":True,"policy_revision":1,
                    "consent_reference":"receipt-1","authorization_id":"auth-1","expires_at":2000},token)[0],200)
        body={"platform_lease_id":"lease-1","platform_epoch":4,"policy_revision":1,"idempotency_key":"lease-1"}
        status, claim = self.call("/v1/bridge/claim",body,token)
        self.assertEqual(status,200)
        identity={"platform_lease_id":"lease-1","platform_epoch":4,"generation":claim["generation"]}
        self.assertTrue(self.call("/v1/bridge/check",identity,token)[1]["authorized"])
        self.assertEqual(self.call("/v1/bridge/reclaim",identity,token)[0],200)
        self.assertFalse(self.call("/v1/bridge/check",identity,token)[1]["authorized"])
        self.assertTrue(self.call("/v1/bridge/complete",dict(identity,cleanup_verified=True),token)[1]["released"])
        self.assertFalse(self.call("/v1/bridge/check",identity,token)[1]["authorized"])

    def test_token_permissions_and_symlinks_are_rejected(self):
        path=Path(self.tmp.name)/"token"
        value=token_file(path,create=True)
        self.assertEqual(len(value),64)
        os.chmod(path,0o644)
        with self.assertRaises(Error):
            token_file(path)
        os.chmod(path,0o600)
        link=Path(self.tmp.name)/"link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            token_file(link)


if __name__ == "__main__":
    unittest.main()
