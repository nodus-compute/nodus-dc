"""The diagnostic client observes a live API without acquiring local authority."""
import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from nodus_dc.api import Server
from nodus_dc.cli import main
from nodus_dc.diagnostics import inspect_daemon
from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.clock = Clock()
        backend = Backend(self.clock)
        backend.allocation_authority = "standalone"
        self.service = Service(Store(self.root / "authority.sqlite3"), backend, clock=self.clock)
        self.service.inventory()
        self.token = self.root / "local.token"
        self.token.write_text("local-" + "x" * 40)
        self.token.chmod(0o600)
        self.server = Server(("127.0.0.1", 0), self.service, self.token.read_text())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def inspect(self):
        return inspect_daemon(port=self.server.server_port, token_path=self.token)

    def test_cli_reads_live_daemon_without_creating_state_or_sampling_gpu(self):
        self.service.backend.inventory = lambda: self.fail("doctor sampled hardware")
        with self.service.store.connection() as db:
            before = list(db.iterdump())
        state = self.root / "absent-state"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--state-dir", str(state), "doctor", "--port", str(self.server.server_port),
                         "--local-token-file", str(self.token)])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(result["daemon_healthy"])
        self.assertEqual((result["available_gpus"], result["available_partitions"]), (1, 2))
        self.assertFalse(state.exists())
        with self.service.store.connection() as db:
            self.assertEqual(list(db.iterdump()), before)
        self.assertTrue(result["reservation_required"])
        self.assertFalse(result["external_capacity_evaluated"])

    def test_health_freshness_and_held_capacity_remain_distinct(self):
        self.service.reserve(resources=["host-a"], mode="exclusive_host", expires_at=self.clock() + 100,
                             request_key="owner")
        result = self.inspect()
        self.assertTrue(result["ok"])
        self.assertEqual((result["available_gpus"], result["available_partitions"]), (0, 0))
        self.assertGreater(result["resource_reasons"]["held"], 0)
        self.clock.now += 31
        stale = self.inspect()
        self.assertTrue(stale["daemon_healthy"])
        self.assertFalse(stale["ok"])
        self.assertEqual(stale["inventory_state"], "stale")
        self.service.inventory()
        self.service.bridge_health_error = "permission_unavailable"
        unhealthy = self.inspect()
        self.assertFalse(unhealthy["daemon_healthy"])
        self.assertEqual(unhealthy["inventory_state"], "fresh")
        self.assertEqual(self.service.status()["leases"][0]["state"], "reserved")

    def test_wrong_scope_and_unreachable_listener_do_not_read_or_create_state(self):
        self.token.write_text("bridge-" + "y" * 40)
        with self.assertRaises(Error) as error:
            self.inspect()
        self.assertEqual(error.exception.code, "diagnostic_unauthorized")
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        with self.assertRaises(Error) as error:
            self.inspect()
        self.assertEqual(error.exception.code, "daemon_unreachable")

    def test_malformed_status_never_becomes_ready(self):
        self.service.status = lambda: {"availability": {"state": "fresh"}}
        with self.assertRaises(Error) as error:
            self.inspect()
        self.assertEqual(error.exception.code, "diagnostic_response")

    def test_inventory_that_expires_during_read_never_reports_capacity(self):
        original = self.service.status
        def expired():
            value = original()
            value["availability"]["fresh_for_seconds"] = 0
            return value
        self.service.status = expired
        result = self.inspect()
        self.assertFalse(result["ok"])
        self.assertEqual(result["inventory_state"], "stale")
        self.assertEqual((result["available_gpus"], result["available_partitions"]), (0, 0))

    def test_total_deadline_cancels_a_stalled_response(self):
        release = threading.Event()
        original = self.service.status
        def stalled():
            release.wait(2)
            return original()
        self.service.status = stalled
        started = time.monotonic()
        try:
            with self.assertRaises(Error):
                inspect_daemon(port=self.server.server_port, token_path=self.token, timeout=0.1)
            self.assertLess(time.monotonic() - started, 1)
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
