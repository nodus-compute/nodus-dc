"""Lease-level topology changes and uncertain-operation recovery controls."""
from dataclasses import replace
import tempfile
from pathlib import Path
import unittest

from nodus_dc.errors import Error
from nodus_dc.model import Resource
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class ConfigurationBackend(Backend):
    def __init__(self, clock):
        super().__init__(clock)
        self.boot = "boot-one"
        self.profiles = []
        self.configures = 0
        self.fail_configuration = False

    def boot_id(self):
        return self.boot

    def inventory(self):
        snapshot = super().inventory()
        resources = [replace(r, details={**r.details, "boot_id": self.boot}) if r.kind == "host" else
                     replace(r, modes=("exclusive_gpu", "gpu_configuration")) if r.id == "GPU-aaaa" else r
                     for r in snapshot.resources]
        resources += [Resource("MIG-config"+str(i), "partition", "GPU-aaaa", "MIG-config"+str(i),
                               modes=("hardware_partition",), healthy=True, details={"profile": p})
                      for i, p in enumerate(self.profiles)]
        return replace(snapshot, resources=tuple(resources))

    def configure_mig(self, lease, plan):
        self.configures += 1
        self.profiles = plan["profiles"]
        if self.fail_configuration:
            raise Error("fixture_partial_failure", "hardware command outcome is unknown")
        return self.inventory()


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.backend = ConfigurationBackend(self.clock)
        self.service = Service(Store(Path(self.tmp.name) / "authority.sqlite3"), self.backend, clock=self.clock)

    def tearDown(self):
        self.tmp.cleanup()

    def test_configuration_has_exclusive_capacity_and_updates_verified_baseline(self):
        lease = self.service.reserve(resources=["GPU-aaaa"], mode="gpu_configuration", expires_at=1100, request_key="maintenance")
        plan = {"enabled": True, "profiles": ["1g.10gb", "1g.10gb"]}
        changed = self.service.configure(lease["id"], generation=lease["generation"], request_key="configure", plan=plan)
        self.assertEqual(changed["state"], "reserved")
        self.assertEqual(len([r for r in changed["baseline"] if r["kind"] == "partition"]), 2)
        with self.assertRaises(Error):
            self.service.reserve(resources=["MIG-config0"], mode="hardware_partition", expires_at=1100, request_key="too-early")
        self.service.configure(lease["id"], generation=lease["generation"], request_key="configure", plan=plan)
        self.assertEqual(self.backend.configures, 1)
        self.service.release(lease["id"], generation=lease["generation"], request_key="release")
        partition = self.service.reserve(resources=["MIG-config0"], mode="hardware_partition", expires_at=1100, request_key="after-release")
        self.assertGreater(partition["generation"], lease["generation"])

    def test_partial_configuration_stays_held_until_reboot_and_reapplied_plan(self):
        lease = self.service.reserve(resources=["GPU-aaaa"], mode="gpu_configuration", expires_at=1100, request_key="maintenance")
        self.backend.fail_configuration = True
        with self.assertRaises(Error):
            self.service.configure(lease["id"], generation=lease["generation"], request_key="configure",
                                   plan={"enabled": True, "profiles": ["1g.10gb"]})
        self.assertEqual(self.service.get(lease["id"])["state"], "quarantined")
        with self.assertRaises(Error) as ctx:
            self.service.recover(lease["id"], generation=lease["generation"], request_key="recover")
        self.assertEqual(ctx.exception.code, "execution_fence_required")
        self.backend.fail_configuration = False
        self.backend.boot = "boot-two"
        recovered = self.service.recover(lease["id"], generation=lease["generation"], request_key="recover")
        self.assertEqual(recovered["state"], "released")
        self.assertEqual(self.backend.configures, 2)

    def test_uncertain_launch_recovery_never_uses_a_clean_process_list_alone(self):
        lease = self.service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key="local")
        self.backend.start_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.service.start(lease["id"], generation=lease["generation"], request_key="start", workload={"test_workload": True})
        self.service.reconcile()
        with self.assertRaises(Error):
            self.service.recover(lease["id"], generation=lease["generation"], request_key="recover")
        self.assertEqual(self.backend.cleanup_calls, 0)
        self.backend.boot = "boot-two"
        self.backend.start_error = None
        recovered = self.service.recover(lease["id"], generation=lease["generation"], request_key="recover")
        self.assertEqual(recovered["state"], "released")
        self.assertEqual(self.backend.cleanup_calls, 1)


if __name__ == "__main__":
    unittest.main()
