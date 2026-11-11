"""Availability is a read projection, never a substitute for reserve/cleanup."""
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class AvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.backend = Backend(self.clock)
        self.backend.allocation_authority = "standalone"
        self.store = Store(Path(self.tmp.name) / "state.sqlite3")
        self.service = Service(self.store, self.backend, clock=self.clock)

    def rows(self):
        return {row["resource_id"]: row for row in self.service.status()["availability"]["resources"]}

    def reserve(self, resource, mode, request):
        return self.service.reserve(resources=[resource], mode=mode,
                                    expires_at=self.clock() + 10, request_key=request)

    def test_held_host_blocks_idle_children_until_verified_release(self):
        lease = self.reserve("host-a", "exclusive_host", "host")
        self.assertTrue(all(not row["available"] for row in self.rows().values()))
        self.clock.now += 11
        self.service.inventory()
        self.assertEqual(self.rows()["GPU-aaaa"]["reason"], "held")
        with self.assertRaises(Error) as error:
            self.reserve("GPU-aaaa", "exclusive_gpu", "competing")
        self.assertEqual(error.exception.code, "allocation_conflict")
        self.service.release(lease["id"], generation=lease["generation"], request_key="release")
        a = self.service.status()["availability"]
        self.assertEqual((a["available_gpus"], a["available_partitions"]), (1, 2))
        self.assertTrue(a["reservation_required"])
        self.assertFalse(a["external_capacity_evaluated"])

    def test_disappeared_partition_keeps_parent_held_without_blocking_sibling(self):
        lease = self.reserve("MIG-aaaa", "hardware_partition", "partition")
        self.assertFalse(self.rows()["GPU-bbbb"]["available"])
        self.assertTrue(self.rows()["MIG-bbbb"]["available"])
        original = self.backend.inventory()
        self.backend.inventory = lambda: replace(original, observed_at=self.clock(), resources=tuple(
            row for row in original.resources if row.id != "MIG-aaaa"))
        self.service.inventory()
        rows = self.rows()
        self.assertEqual(rows["GPU-bbbb"]["held_by"], [lease["id"]])
        self.assertEqual(rows["host-a"]["reason"], "held")
        self.assertTrue(rows["MIG-bbbb"]["available"])

    def test_freshness_clock_and_authority_never_make_unknown_capacity_available(self):
        self.assertEqual(self.service.status()["availability"]["state"], "missing")
        self.service.inventory()
        self.clock.now += 31
        self.assertEqual(self.service.status()["availability"]["state"], "stale")
        self.assertTrue(all(not row["available"] for row in self.rows().values()))
        self.service.inventory()
        self.clock.now -= 2
        self.assertEqual(self.service.status()["availability"]["state"], "clock_uncertain")
        self.clock.now += 2
        for authority, reason in [("observe", "observe_only"), ("kubernetes", "scheduler_managed")]:
            self.backend.allocation_authority = authority
            # Even a still-fresh older standalone snapshot cannot grant authority.
            self.assertEqual(self.rows()["GPU-aaaa"]["reason"], reason)
            self.assertTrue(all(not row["available"] for row in self.rows().values()))

    def test_status_does_not_refresh_reconcile_or_write_authority(self):
        self.reserve("GPU-aaaa", "exclusive_gpu", "held")
        self.clock.now += 11
        self.backend.inventory = lambda: self.fail("status sampled hardware")
        with self.store.connection() as db:
            before = list(db.iterdump())
        status = self.service.status()
        with self.store.connection() as db:
            self.assertEqual(list(db.iterdump()), before)
        self.assertEqual(status["leases"][0]["state"], "reserved")
        self.assertEqual(self.backend.cleanup_calls, 0)

    def test_failed_cleanup_stays_held_and_foreign_activity_is_unavailable(self):
        lease = self.reserve("GPU-aaaa", "exclusive_gpu", "held")
        self.backend.clean = False
        self.service.release(lease["id"], generation=lease["generation"], request_key="release")
        self.assertEqual(self.service.status()["leases"][0]["state"], "quarantined")
        self.assertEqual(self.rows()["GPU-aaaa"]["reason"], "held")
        snapshot = self.backend.inventory()
        self.backend.inventory = lambda: replace(snapshot, observed_at=self.clock(), resources=tuple(
            replace(row, busy=True) if row.id == "MIG-bbbb" else row for row in snapshot.resources))
        self.service.inventory()
        self.assertEqual(self.rows()["MIG-bbbb"]["reason"], "busy")


if __name__ == "__main__":
    unittest.main()
