"""Native intent is a sticky protective fence, not a native provisioning adapter."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class NativeGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.backend = Backend(self.clock)
        self.service = Service(Store(Path(self.tmp.name)/"state.db"), self.backend, clock=self.clock)
        self.lease = self.service.reserve(resources=["host-a"], mode="exclusive_host", expires_at=1100, request_key="whole-host")

    def handoff(self):
        return self.service.native_handoff(self.lease["id"], generation=self.lease["generation"],
                                            request_key="handoff", provisioner_reference="private-provisioner-ticket")

    def test_idle_native_host_expiry_quarantines_without_cleanup_or_capacity_return(self):
        result = self.handoff()
        self.assertFalse(result["runtime"]["return_supported"])
        self.clock.now = 1200
        self.service.reconcile()
        self.assertEqual(self.service.get(self.lease["id"])["state"], "quarantined")
        self.assertEqual(self.backend.cleanup_calls, 0)
        with self.assertRaises(Error):
            self.service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1300, request_key="cannot-reuse")

    def test_release_drain_restart_and_new_boot_cannot_prove_native_return(self):
        self.handoff()
        with self.assertRaises(Error) as result:
            self.service.release(self.lease["id"], generation=self.lease["generation"], request_key="release")
        self.assertEqual(result.exception.code, "native_return_unsupported")
        self.service.drain(self.lease["id"], generation=self.lease["generation"], request_key="drain")
        self.backend.boot_id = lambda: "another-boot"
        restarted = Service(Store(self.service.store.path), self.backend, clock=self.clock)
        with self.assertRaises(Error) as result:
            restarted.recover(self.lease["id"], generation=self.lease["generation"], request_key="recover")
        self.assertEqual(result.exception.code, "native_return_unsupported")
        self.assertEqual(self.backend.cleanup_calls, 0)
        self.assertEqual(restarted.get(self.lease["id"])["state"], "quarantined")

    def test_connection_attempt_history_permanently_refuses_native_handoff(self):
        self.service.record_connection_attempt()
        with self.assertRaises(Error) as result:
            self.handoff()
        self.assertEqual(result.exception.code, "native_platform_fence_unsupported")
        self.assertEqual(self.service.get(self.lease["id"])["state"], "reserved")

    def test_native_handoff_refuses_connect_before_remote_accept(self):
        self.handoff()
        with self.assertRaises(Error) as result:
            self.service.record_connection_attempt()
        self.assertEqual(result.exception.code, "native_handoff_active")
        self.service.bridge_enabled = True
        with self.assertRaises(Error) as result:
            self.service.bridge_policy(enabled=True, policy_revision=1, authorization_id="invalid", consent_reference="invalid", expires_at=2000)
        self.assertEqual(result.exception.code, "native_handoff_active")

    def test_handoff_and_connection_attempt_race_has_only_one_winner(self):
        def attempt(action):
            try:
                action()
                return "success"
            except Error as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [self.handoff, self.service.record_connection_attempt]))
        self.assertEqual(results.count("success"), 1)
        self.assertTrue("native_handoff_active" in results or "native_platform_fence_unsupported" in results)


if __name__ == "__main__":
    unittest.main()
