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

    def test_documented_registration_layouts_preserve_exact_binding(self):
        original = self.binding()
        self.devices.files["/proc/devices"] = "Character devices:\n195 nvidia\n195 nvidiactl\n508 nvidia-caps\n511 nvidia-uvm\n\nBlock devices:\n8 sd\n"
        self.assertEqual(self.binding(), original)
        self.devices.nodes["/dev/nvidiactl"] = (196, 255)
        with self.assertRaises(Error) as caught:
            self.binding()
        self.assertEqual(caught.exception.code, "partition_binding_unavailable")

    def test_full_source_derived_mig_table_uses_bounded_real_reader(self):
        # NVIDIA 580.105.08 nv-caps.c exports every table entry, even absent GPUs.
        # This is source-derived data, not a captured /proc/devices observation.
        lines, number = ["config 1\n", "monitor 2\n"], 3
        for gpu in range(32):
            for gi in range(15):
                prefix = f"gpu{gpu}/gi{gi}"
                lines.append(f"{prefix}/access {number}\n"); number += 1
                for ci in range(8):
                    lines.append(f"{prefix}/ci{ci}/access {number}\n"); number += 1
        mapping = "".join(lines)
        self.assertEqual((len(lines), len(mapping.encode())), (4322, 109408))
        rows = list(self.backend.snapshot.resources)
        rows[1] = replace(rows[1], details={**rows[1].details, "pci_bus_id":"00000000:06:00.0"})
        for i, gi in ((2, 1), (3, 2)):
            rows[i] = replace(rows[i], details={**rows[i].details, "gpu_instance_id":gi})
        self.backend.snapshot = replace(self.backend.snapshot, resources=tuple(rows))
        self.lease["baseline"] = [r.record() for r in rows]
        self.devices.files["/proc/driver/nvidia/gpus/0000:06:00.0/information"] = "GPU UUID: GPU-aaaa\nDevice Minor: 0\n"
        self.devices.files["/proc/devices"] = "Character devices:\n195 nvidia\n195 nvidiactl\n234 nvidia-uvm\n237 nvidia-caps\n\nBlock devices:\n8 sd\n"
        self.devices.nodes = {"/dev/nvidia0":(195,0), "/dev/nvidiactl":(195,255), "/dev/nvidia-uvm":(234,0)}
        for gi, minor in ((1,12), (2,21)):
            for suffix, value in (("access",minor), ("ci0/access",minor+1)):
                self.devices.files[f"/proc/driver/nvidia/capabilities/gpu0/mig/gi{gi}/{suffix}"] = f"DeviceFileMinor: {value}\n"
                self.devices.nodes[f"/dev/nvidia-caps/nvidia-cap{value}"] = (237,value)
        path = "/proc/driver/nvidia-caps/mig-minors"
        original_text = self.devices.text
        with tempfile.TemporaryDirectory() as directory:
            captured = Path(directory)/"source-derived-mig-minors"
            captured.write_text(mapping)
            real_open = Path.open
            def read_open(requested, *args, **kwargs):
                return real_open(captured if str(requested) == path else requested, *args, **kwargs)
            with patch.object(Path, "open", read_open), patch.object(self.devices, "text", side_effect=lambda p: LinuxDevices().text(p) if p == path else original_text(p)):
                first = self.binding()["binding"]["devices"]
                self.assertEqual([(r["major"],r["minor"]) for r in first], [(195,0),(195,255),(234,0),(237,12),(237,13)])
                other = observe(self.backend.snapshot, "MIG-bbbb", devices=self.devices)
                self.assertEqual([r["minor"] for r in other["devices"][-2:]], [21,22])
                captured.write_text(mapping + "gpu0/gi1/access 12\n")
                with self.assertRaisesRegex(Error, "duplicate MIG capability mapping"):
                    self.binding()
                captured.write_text(mapping.replace("gpu0/gi14/access 129\n", "gpu0/gi14/access 12\n"))
                with self.assertRaisesRegex(Error, "not uniquely scoped"):
                    self.binding()
                captured.write_text("x" * 131073)
                with self.assertRaisesRegex(Error, "observation limit"):
                    self.binding()
            captured.write_text("x" * 65537)
            with self.assertRaisesRegex(ValueError, "observation limit"):
                LinuxDevices().text(captured)

    def test_captured_linux_module_source_version_preserves_exact_identity(self):
        # Recorded independently on two A100 / Linux 6.8 / 580.105.08 hosts.
        captured = "12B00758E1DCB3540DF2F3A"
        original = self.binding()["binding"]
        for source_version in (captured, captured.lower(), "A" * 24):
            with self.subTest(source_version=source_version):
                self.devices.files["/sys/module/nvidia/srcversion"] = source_version
                binding = self.binding()["binding"]
                self.assertEqual(binding["driver_source_version"], source_version)
                self.assertEqual(binding["driver_version"], "580.105.08")
                self.assertEqual(binding["devices"], original["devices"])
                if source_version != "A" * 24:
                    self.assertNotEqual(binding["binding_digest"], original["binding_digest"])

    def test_module_identity_format_and_version_mismatches_remain_refused(self):
        path = "/sys/module/nvidia/srcversion"
        for value in ("", "A" * 22, "A" * 25, "G" * 23, "0x" + "A" * 23, "A" * 11 + " " + "A" * 11):
            with self.subTest(source_version=value):
                self.devices = Devices()
                self.devices.files[path] = value
                with self.assertRaises(Error) as caught:
                    self.binding()
                self.assertEqual(caught.exception.code, "partition_binding_unavailable")
        for path, value in (("/sys/module/nvidia/version", ""),
                            ("/sys/module/nvidia/version", "580.196.07"),
                            ("/proc/driver/nvidia/version", "NVRM version: 580.196.07")):
            with self.subTest(path=path, value=value):
                self.devices = Devices()
                self.devices.files["/sys/module/nvidia/srcversion"] = "12B00758E1DCB3540DF2F3A"
                self.devices.files[path] = value
                with self.assertRaises(Error) as caught:
                    self.binding()
                self.assertEqual(caught.exception.code, "partition_binding_unavailable")

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

    def test_regressed_clock_cannot_revalidate_partition_evidence(self):
        now = [1000]
        self.backend.clock = lambda: now[0]
        with tempfile.TemporaryDirectory() as directory:
            service = Service(Store(Path(directory) / "authority.sqlite3"), self.backend, clock=self.backend.clock)
            lease = service.reserve(resources=["MIG-aaaa"], mode="hardware_partition",
                                    expires_at=1100, request_key="binding-clock")
            now[0] = 998
            with self.assertRaises(Error) as caught:
                service.partition_binding(lease["id"], generation=lease["generation"])
            self.assertEqual(caught.exception.code, "clock_regression")

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
