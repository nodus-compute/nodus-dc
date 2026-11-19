import tempfile
import unittest
import contextlib
import io
import json
from unittest.mock import patch
from pathlib import Path

from nodus_dc.cli import main, parser, sync_connection
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class CliTests(unittest.TestCase):
    def test_preparation_refuses_bridge_or_expired_setup_before_opening_state(self):
        for extra in (["--bridge-token-file", "must-not-be-read"], ["--prepare-until", "99"], ["--require-clean-start"]):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as folder:
                state = Path(folder) / "must-not-be-created"
                stderr = io.StringIO()
                with patch("nodus_dc.cli.os.geteuid", return_value=0), \
                     patch("nodus_dc.cli.time.time", return_value=100), \
                     patch("nodus_dc.cli.Store", side_effect=AssertionError("preparation opened a Store")), \
                     patch("nodus_dc.cli.NvidiaDockerBackend", side_effect=AssertionError("preparation opened a backend")), \
                     patch("nodus_dc.cli.token_file", side_effect=AssertionError("preparation read a credential")), \
                     contextlib.redirect_stderr(stderr):
                    code = main(["--state-dir", str(state), "--allocation-authority", "standalone", "serve",
                                 "--prepare-local-template", "/protected/template.json",
                                 "--prepare-local-sha256", "1" * 64, "--prepare-until", "200", *extra])
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(stderr.getvalue())["error"]["code"], "local_preparation_unavailable")
                self.assertFalse(state.exists())

    def test_managed_cli_uses_existing_private_owner_without_opening_another_store(self):
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder)/"must-not-be-created"
            stdout=io.StringIO()
            with patch("nodus_dc.cli.Store",side_effect=AssertionError("managed client opened a store")), \
                 patch("nodus_dc.cli.NvidiaDockerBackend",side_effect=AssertionError("managed client opened a backend")), \
                 patch("nodus_dc.partition_local_cli.request",return_value={"leases":[],"has_more":False}) as call, \
                 contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["--state-dir",str(state),"managed","status"]),0)
            self.assertFalse(state.exists())
            call.assert_called_once_with("/run/nodus-dc/local.sock",state/"local.token","pending",{"after_generation":0})
            self.assertEqual(json.loads(stdout.getvalue()),{"leases":[],"scope":"ordered_observation_not_permission"})

    def test_confidential_reserve_stops_before_gpu_inventory_or_allocation(self):
        with tempfile.TemporaryDirectory() as folder:
            stderr, stdout = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                result = main(["--state-dir", folder, "--allocation-authority", "standalone", "reserve",
                               "--resource", "GPU-aaaa", "--mode", "exclusive_gpu", "--ttl-seconds", "60",
                               "--required-privacy", "host_confidential"])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(stderr.getvalue())["error"]["code"], "privacy_unavailable")
            self.assertEqual(stdout.getvalue(), "")
            with Store(Path(folder) / "authority.sqlite3").connection() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM leases").fetchone()[0], 0)
                self.assertIsNone(db.execute("SELECT value FROM meta WHERE key='inventory'").fetchone())

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
            self.assertEqual(sync_connection(service, Healthy()),{"connected":True,"active":True})
            self.assertFalse(service.bridge_check(**values)["authorized"])
            self.assertFalse(service.bridge_policy_state()["enabled"])


if __name__ == "__main__":
    unittest.main()
