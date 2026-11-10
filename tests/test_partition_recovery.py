"""Real SQLite/authority transitions; device proof is explicitly synthetic."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from nodus_dc.errors import Error
from nodus_dc.model import CleanupProof
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Clock
from tests.test_configuration import ConfigurationBackend


class RetiredPartitionBackend(ConfigurationBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.calls = []
        self.failure = None
        self.invalid = None

    def inventory(self):
        snap = super().inventory()
        if self.boot != "boot-one":
            snap = replace(snap, resources=tuple(r for r in snap.resources if r.kind != "partition"))
        return snap

    def recover_partition(self, lease, previous_boot_id, current_boot_id):
        self.calls.append((lease["id"], previous_boot_id, current_boot_id))
        if self.failure:
            raise self.failure
        return CleanupProof(True, self.clock(), lease["id"],
                            lease["generation"] + (1 if self.invalid == "generation" else 0),
                            ("MIG-replacement",) if self.invalid == "resource" else tuple(lease["resources"]),
                            {"synthetic": True, "retired_partition_leases": lease["resources"]})


class PartitionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.backend = RetiredPartitionBackend(self.clock)
        self.path = Path(self.tmp.name) / "authority.sqlite3"
        self.service = Service(Store(self.path), self.backend, clock=self.clock)
        self.lease = self.service.reserve(resources=["MIG-aaaa"], mode="hardware_partition",
                                          expires_at=1100, request_key="partition")
        self.backend.start_error = RuntimeError("synthetic uncertain launch")
        with self.assertRaises(Error):
            self.service.start(self.lease["id"], generation=self.lease["generation"],
                               request_key="start", workload={"test_workload": True})
        self.original = self.service.get(self.lease["id"])

    def tearDown(self):
        self.tmp.cleanup()

    def recover(self, key="recover"):
        return self.service.recover(self.lease["id"], generation=self.lease["generation"], request_key=key)

    def test_real_boot_guard_then_retire_absent_identity_without_rewriting_baseline(self):
        with self.assertRaises(Error) as raised:
            self.recover()
        self.assertEqual(raised.exception.code, "execution_fence_required")
        self.assertFalse(self.backend.calls)
        self.backend.boot = "boot-two"
        self.service.inventory()  # The original MIG IDs are now absent.
        result = self.recover()
        self.assertEqual(result["state"], "released")
        for key in ("id", "generation", "resources", "baseline"):
            self.assertEqual(result[key], self.original[key])
        self.assertEqual(result["cleanup"]["resource_ids"], ["MIG-aaaa"])
        self.assertEqual(self.recover()["state"], "released")
        self.assertEqual(len(self.backend.calls), 1)

    def test_sibling_lease_blocks_parent_recovery_even_after_mig_disappears(self):
        sibling = self.service.reserve(resources=["MIG-bbbb"], mode="hardware_partition",
                                       expires_at=1100, request_key="sibling")
        self.backend.boot = "boot-two"
        self.service.inventory()
        with self.assertRaises(Error) as raised:
            self.recover()
        self.assertEqual(raised.exception.code, "recovery_parent_busy")
        self.assertFalse(self.backend.calls)
        self.assertEqual(self.service.get(sibling["id"])["state"], "reserved")

    def test_unrelated_physical_gpu_does_not_block_recovery(self):
        other = self.service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key="other")
        self.backend.boot = "boot-two"
        self.assertEqual(self.recover()["state"], "released")
        self.assertEqual(self.service.get(other["id"])["state"], "reserved")

    def test_invalid_or_failed_proof_persists_quarantine_and_restarts_safely(self):
        self.backend.boot = "boot-two"
        for index, invalid in enumerate(("generation", "resource")):
            self.backend.invalid = invalid
            self.assertEqual(self.recover("bad-"+str(index))["state"], "quarantined")
        self.backend.invalid = None
        self.backend.failure = RuntimeError("synthetic cleanup uncertainty")
        self.assertEqual(self.recover("exception")["state"], "quarantined")
        self.service = Service(Store(self.path), self.backend, clock=self.clock)
        self.assertEqual(self.service.get(self.lease["id"])["resources"], ["MIG-aaaa"])
        self.backend.failure = None
        self.assertEqual(self.recover("retry")["state"], "released")

    def test_crash_after_recovery_intent_retries_same_boot_without_forged_new_identity(self):
        self.backend.boot = "boot-two"
        self.backend.failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.recover()
        self.assertEqual(self.service.get(self.lease["id"])["state"], "verifying")
        self.service = Service(Store(self.path), self.backend, clock=self.clock)
        self.backend.failure = None
        self.assertEqual(self.recover()["state"], "released")

    def test_stale_generation_never_calls_recovery_backend(self):
        self.backend.boot = "boot-two"
        with self.assertRaises(Error) as raised:
            self.service.recover(self.lease["id"], generation=self.lease["generation"]+1, request_key="stale")
        self.assertEqual(raised.exception.code, "stale_generation")
        self.assertFalse(self.backend.calls)


if __name__ == "__main__":
    unittest.main()
