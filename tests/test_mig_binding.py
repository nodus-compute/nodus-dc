"""Synthetic kernel-device seam cases; these do not qualify a runtime or GPU."""
import copy
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from nodus_dc.errors import Error
from nodus_dc.mig_binding import LinuxDevices, observe, observe_lease
from nodus_dc.model import Resource, Snapshot
from nodus_dc.service import Service
from nodus_dc.store import Store


BOOT = "01234567-0123-0123-0123-0123456789ab"


class Devices:
    def __init__(self):
        self.files = {
            "/proc/sys/kernel/random/boot_id": BOOT,
            "/sys/module/nvidia/version": "580.105.08",
            "/sys/module/nvidia/srcversion": "A" * 24,
            "/proc/driver/nvidia/version": "NVRM version: NVIDIA UNIX Kernel Module 580.105.08",
            "/proc/driver/nvidia/gpus/0000:07:00.0/information": "GPU UUID: GPU-aaaa\nDevice Minor: 3\n",
            "/proc/devices": "Character devices:\n195 nvidia-frontend\n508 nvidia-caps\n511 nvidia-uvm\n\nBlock devices:\n8 sd\n",
            "/proc/driver/nvidia-caps/mig-minors": "config 1\nmonitor 2\ngpu3/gi7/access 67\ngpu3/gi7/ci0/access 68\ngpu3/gi8/access 69\ngpu3/gi8/ci0/access 70\n",
            "/proc/driver/nvidia/capabilities/gpu3/mig/gi7/access": "DeviceFileMinor: 67\nDeviceFileMode: 256\nDeviceFileModify: 1\n",
            "/proc/driver/nvidia/capabilities/gpu3/mig/gi7/ci0/access": "DeviceFileMinor: 68\nDeviceFileMode: 256\n",
        }
        self.nodes = {"/dev/nvidia3": (195, 3), "/dev/nvidiactl": (195, 255),
                      "/dev/nvidia-uvm": (511, 0), "/dev/nvidia-caps/nvidia-cap67": (508, 67),
                      "/dev/nvidia-caps/nvidia-cap68": (508, 68)}

    def text(self, path):
        return self.files[path]

    def device(self, path):
        return self.nodes[path]


def inventory():
    return Snapshot("host-a", 1000, (
        Resource("host-a", "host", None, healthy=True, details={"boot_id": BOOT}),
        Resource("GPU-aaaa", "gpu", "host-a", "GPU-aaaa", healthy=True, busy=True,
                 details={"mig_mode": "Enabled", "driver_version": "580.105.08", "pci_bus_id": "00000000:07:00.0"}),
        Resource("MIG-aaaa", "partition", "GPU-aaaa", "MIG-aaaa", healthy=True, modes=("hardware_partition",),
                 details={"gpu_instance_id": 7, "compute_instance_id": 0, "profile": "3g.20gb",
                          "process_inventory_scope": "gpu_compute_instance", "memory_capacity_bytes": 21072183296}),
        Resource("MIG-bbbb", "partition", "GPU-aaaa", "MIG-bbbb", healthy=True, busy=True,
                 details={"gpu_instance_id": 8, "compute_instance_id": 0, "profile": "3g.20gb",
                          "process_inventory_scope": "gpu_compute_instance", "memory_capacity_bytes": 21072183296}),
    ), driver_version="580.105.08")


class Backend:
    clock = staticmethod(lambda: 1000)

    def __init__(self):
        self.snapshot = inventory()
        self.after_read = lambda: None

    def inventory(self):
        result = self.snapshot
        self.after_read()
        return result


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.devices = Devices()
        self.backend = Backend()
        self.lease = {"id": "held-partition", "generation": 8, "mode": "hardware_partition", "state": "reserved",
                      "resources": ["MIG-aaaa"], "baseline": [r.record() for r in inventory().resources]}

    def binding(self):
        return observe_lease(self.backend, self.lease, devices=self.devices)

    def test_exact_devices_use_physical_minor_and_exclude_sibling_and_management(self):
        result = self.binding()
        nodes = result["binding"]["devices"]
        self.assertEqual([r["path"] for r in nodes], ["/dev/nvidia3", "/dev/nvidiactl", "/dev/nvidia-uvm",
                         "/dev/nvidia-caps/nvidia-cap67", "/dev/nvidia-caps/nvidia-cap68"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["hardware_qualified"])
        self.assertEqual((result["lease_id"], result["generation"]), ("held-partition", 8))

    def test_sibling_activity_does_not_change_binding(self):
        before = self.binding()
        rows = list(self.backend.snapshot.resources)
        rows[3] = replace(rows[3], busy=False, details={**rows[3].details, "process_ids": [], "memory_used_bytes": 12})
        self.backend.snapshot = replace(self.backend.snapshot, resources=tuple(rows), observed_at=1001)
        self.assertEqual(self.binding(), before)

    def test_missing_or_ambiguous_kernel_devices_are_refused(self):
        mutations = [
            lambda d: d.nodes.update({"/dev/nvidia3": (195, 0)}),
            lambda d: d.nodes.update({"/dev/nvidia-caps/nvidia-cap68": (508, 70)}),
            lambda d: d.files.pop("/sys/module/nvidia/srcversion"),
            lambda d: d.files.update({"/proc/driver/nvidia-caps/mig-minors": d.files["/proc/driver/nvidia-caps/mig-minors"] + "gpu3/gi9/access 67\n"}),
            lambda d: d.files.update({"/proc/driver/nvidia/capabilities/gpu3/mig/gi7/access": "DeviceFileMinor: 67\nDeviceFileMinor: 69\n"}),
            lambda d: d.files.update({"/proc/driver/nvidia/gpus/0000:07:00.0/information": "GPU UUID: GPU-other\nDevice Minor: 3\n"}),
            lambda d: d.files.update({"/sys/module/nvidia/version": "580.196.07"}),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                self.devices = Devices()
                mutate(self.devices)
                with self.assertRaises(Error) as caught:
                    self.binding()
                self.assertEqual(caught.exception.code, "partition_binding_unavailable")

    def test_changed_boot_or_partition_identity_cannot_rebind_held_lease(self):
        for field, value in (("gpu_instance_id", 6), ("compute_instance_id", 1), ("profile", "1g.5gb")):
            with self.subTest(field=field):
                lease = copy.deepcopy(self.lease)
                lease["baseline"][2]["details"][field] = value
                with self.assertRaises(Error) as caught:
                    observe_lease(self.backend, lease, devices=self.devices)
                self.assertEqual(caught.exception.code, "partition_binding_changed")
        self.lease["baseline"][0]["details"]["boot_id"] = "different-boot"
        with self.assertRaises(Error):
            self.binding()

    def test_lease_expiry_during_observation_returns_no_evidence(self):
        now = [1000]
        self.backend.clock = lambda: now[0]
        with tempfile.TemporaryDirectory() as directory:
            service = Service(Store(Path(directory) / "authority.sqlite3"), self.backend, clock=self.backend.clock)
            lease = service.reserve(resources=["MIG-aaaa"], mode="hardware_partition",
                                    expires_at=1001, request_key="binding-expiry")
            self.backend.after_read = lambda: now.__setitem__(0, 1002)
            with patch("nodus_dc.mig_binding.LinuxDevices", return_value=self.devices):
                with self.assertRaises(Error) as caught:
                    service.partition_binding(lease["id"], generation=lease["generation"])
            self.assertEqual(caught.exception.code, "lease_expired")
            self.assertEqual(service.get(lease["id"])["state"], "reserved")

    def test_mid_observation_geometry_change_and_stale_inventory_are_refused(self):
        def change():
            rows = list(self.backend.snapshot.resources)
            rows[3] = replace(rows[3], id="MIG-new-sibling", device_uuid="MIG-new-sibling")
            self.backend.snapshot = replace(self.backend.snapshot, resources=tuple(rows))
        self.backend.after_read = change
        with self.assertRaises(Error) as caught:
            self.binding()
        self.assertEqual(caught.exception.code, "partition_binding_changed")
        self.backend.after_read = lambda: None
        self.backend.snapshot = replace(self.backend.snapshot, observed_at=900)
        with self.assertRaises(Error) as caught:
            self.binding()
        self.assertEqual(caught.exception.code, "stale_inventory")

    def test_multi_ci_gpu_instance_and_non_device_files_are_refused(self):
        rows = list(self.backend.snapshot.resources)
        rows[3] = replace(rows[3], details={**rows[3].details, "gpu_instance_id": 7, "compute_instance_id": 1})
        with self.assertRaises(Error):
            observe(replace(self.backend.snapshot, resources=tuple(rows)), "MIG-aaaa", devices=self.devices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nvidia3"
            path.write_text("not a device")
            with self.assertRaises(ValueError):
                LinuxDevices().device(path)
            path.unlink()
            path.symlink_to("/dev/null")
            with self.assertRaises(ValueError):
                LinuxDevices().device(path)


if __name__ == "__main__":
    unittest.main()
