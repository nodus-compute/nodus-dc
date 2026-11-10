import tempfile
import unittest
from pathlib import Path

from nodus_dc.cli import parser, sync_connection
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class CliTests(unittest.TestCase):
    def test_connection_flags_bind_scope_and_explicit_window(self):
        args = parser().parse_args(["connection", "connect", "--platform-url", "https://platform.example",
                                    "--namespace", "ns", "--pool", "pool", "--node", "node", "--token-file", "cloud.token",
                                    "--bridge-token-file", "bridge.token", "--available-until", "1234", "--allow-qualified-jobs"])
        self.assertEqual(args.required_compensation, "CashUSD")
        self.assertEqual(args.node_identity_file, "/var/lib/nodus/node.json")
        self.assertEqual(args.available_until, 1234)

    def test_unexpected_connection_failure_revokes_runtime_admission_in_memory(self):
        class Broken:
            def sync(self):
                raise ValueError("malformed external protocol")
        class Healthy:
            def sync(self):
                return {"connected": True, "active": True}
        with tempfile.TemporaryDirectory() as folder:
            clock = Clock()
            service = Service(Store(Path(folder) / "authority.sqlite3"), Backend(clock), clock=clock, bridge_enabled=True)
            service.bridge_policy(enabled=True, policy_revision=1, authorization_id="auth", consent_reference="consent", expires_at=2000)
            claim = service.bridge_claim(platform_lease_id="platform", platform_epoch=1, policy_revision=1, idempotency_key="platform")
            values = {"platform_lease_id": "platform", "platform_epoch": 1, "generation": claim["generation"]}
            self.assertTrue(service.bridge_check(**values)["authorized"])
            result = sync_connection(service, Broken())
            self.assertFalse(result["active"])
            self.assertFalse(service.bridge_status()["available"])
            self.assertFalse(service.bridge_check(**values)["authorized"])
            self.assertTrue(service.bridge_inspect(platform_lease_id="platform", platform_epoch=1)["held"])
            sync_connection(service, Healthy())
            self.assertFalse(service.bridge_check(**values)["authorized"])
            self.assertFalse(service.bridge_policy_state()["enabled"])


if __name__ == "__main__":
    unittest.main()
