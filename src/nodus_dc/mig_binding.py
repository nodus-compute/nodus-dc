"""Read-only device evidence for the experimental MIG executor.

This observation is neither an execution grant nor hardware qualification. The
caller holds the allocation authority while observing and consuming the result.
"""
from __future__ import annotations

import os
import math
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import Error
from .model import Snapshot, digest


def observe_lease(backend, lease, *, devices=None):
    """Observe a held partition twice, preserving its original boot/device fence."""
    if (lease["mode"] != "hardware_partition" or len(lease["resources"]) != 1
            or lease["state"] not in {"reserved", "active"}):
        raise Error("partition_binding_unavailable", "one reserved or active hardware partition is required", 409)
    baseline = {row["id"]: row for row in lease.get("baseline") or []}
    resource_id = lease["resources"][0]
    original = baseline.get(resource_id)
    if original is None:
        raise Error("partition_binding_unavailable", "held partition has no baseline", 409)
    def current():
        snapshot = backend.inventory()
        if (not isinstance(snapshot, Snapshot) or not math.isfinite(snapshot.observed_at)
                or abs(backend.clock() - snapshot.observed_at) > 30):
            raise Error("stale_inventory", "fresh inventory is required for device binding", 503)
        return observe(snapshot, resource_id, devices=devices)

    first = current()
    host = baseline.get(first["host_id"], {})
    parent = baseline.get(first["parent_uuid"], {})
    child_details = original.get("details", {})
    if (host.get("details", {}).get("boot_id") != first["boot_id"]
            or original.get("kind") != "partition" or parent.get("kind") != "gpu"
            or parent.get("device_uuid") != first["parent_uuid"]
            or original.get("parent") != first["parent_uuid"]
            or original.get("device_uuid") != first["partition_uuid"]
            or any(child_details.get(field) != first[field] for field in
                   ("gpu_instance_id", "compute_instance_id", "profile"))
            or child_details.get("memory_capacity_bytes") != first["memory_bytes"]
            or parent.get("details", {}).get("driver_version") != first["driver_version"]):
        raise Error("partition_binding_changed", "held partition no longer matches its allocation baseline", 409)
    second = current()
    if first != second:
        raise Error("partition_binding_changed", "device binding changed during observation", 409)
    return {"lease_id": lease["id"], "generation": lease["generation"], "binding": second,
            "execution_authorized": False, "hardware_qualified": False}


@dataclass(frozen=True)
class LinuxDevices:
    """Read the kernel's current device metadata without creating device nodes."""

    def text(self, path):
        with Path(path).open() as stream:
            value = stream.read(65537)
        if len(value) > 65536:
            raise ValueError("device metadata exceeds the observation limit")
        return value

    def device(self, path):
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISCHR(info.st_mode):
            raise ValueError("expected a character device without a symlink")
        return os.major(info.st_rdev), os.minor(info.st_rdev)


def _fields(text):
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        name, separator, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if not separator or name in result:
            raise ValueError("ambiguous device metadata")
        result[name] = value
    return result


def _number(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
        raise ValueError("invalid device number")
    result = int(value)
    if result > 2**32 - 1:
        raise ValueError("device number exceeds the supported range")
    return result


def _scope(snapshot, resource_id):
    if not isinstance(snapshot, Snapshot):
        raise ValueError("typed inventory is required")
    rows = {row.id: row for row in snapshot.resources}
    if len(rows) != len(snapshot.resources) or snapshot.warnings:
        raise ValueError("inventory is incomplete or ambiguous")
    child = rows[resource_id]
    parent = rows[child.parent]
    host = rows[snapshot.host_id]
    if (child.kind != "partition" or parent.kind != "gpu" or host.kind != "host"
            or parent.parent != host.id or not all(r.healthy for r in (host, parent, child))
            or child.device_uuid != child.id or parent.device_uuid != parent.id
            or not re.fullmatch(r"MIG-[A-Za-z0-9_-]{4,160}", child.id)
            or not re.fullmatch(r"GPU-[A-Za-z0-9_-]{4,160}", parent.id)
            or parent.details.get("mig_mode") != "Enabled"):
        raise ValueError("requested resource is not a healthy hardware partition")
    children = [row for row in rows.values() if row.parent == parent.id]
    geometry, gis = [], set()
    for row in children:
        gi, ci = row.details.get("gpu_instance_id"), row.details.get("compute_instance_id")
        if (row.kind != "partition" or row.details.get("process_inventory_scope") != "gpu_compute_instance"
                or type(gi) is not int or type(ci) is not int or not 0 <= gi < 2**32
                or not 0 <= ci < 2**32 or gi in gis or not row.details.get("profile")):
            raise ValueError("one complete compute instance per GPU instance is required")
        gis.add(gi)
        geometry.append({"uuid": row.device_uuid, "gi": gi, "ci": ci, "profile": row.details["profile"]})
    capacity = child.details.get("memory_capacity_bytes")
    if type(capacity) is not int or capacity <= 0:
        raise ValueError("driver-reported partition capacity is required")
    return host, parent, child, sorted(geometry, key=lambda row: row["gi"])


def observe(snapshot: Snapshot, resource_id: str, *, devices=None):
    """Resolve one MIG instance to exact kernel devices; never grant a whole GPU.

    Busy sibling telemetry is deliberately absent from the identity digest.
    Observed boot, driver, geometry or device changes invalidate the digest.
    Identical recycled metadata needs a separate durable configuration fence.
    """
    devices = devices or LinuxDevices()
    try:
        host, parent, child, geometry = _scope(snapshot, resource_id)
        boot = devices.text("/proc/sys/kernel/random/boot_id").strip()
        if (not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
                or host.details.get("boot_id") != boot):
            raise ValueError("inventory boot identity does not match the running kernel")
        version = devices.text("/sys/module/nvidia/version").strip()
        source_version = devices.text("/sys/module/nvidia/srcversion").strip()
        if (not version or version != snapshot.driver_version
                or version != parent.details.get("driver_version")
                # Linux modpost can emit 23 hex digits after reserving its NUL.
                # Preserve the exact observed build metadata in the binding.
                or not re.fullmatch(r"[A-Fa-f0-9]{23,24}", source_version)):
            raise ValueError("loaded driver identity is unavailable or inconsistent")
        driver_banner = devices.text("/proc/driver/nvidia/version").strip()
        if not driver_banner or version not in driver_banner:
            raise ValueError("loaded driver banner does not match the inventory")

        # NVIDIA capability gpuN uses the physical device minor, not NVML index.
        pci = parent.details.get("pci_bus_id", "")
        match = re.fullmatch(r"([0-9a-fA-F]{4}|0000[0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", pci)
        if not match:
            raise ValueError("canonical physical PCI identity is required")
        bdf = f"{int(match[1], 16):04x}:{match[2].lower()}:{match[3].lower()}.{match[4]}"
        physical = _fields(devices.text(f"/proc/driver/nvidia/gpus/{bdf}/information"))
        if physical.get("GPU UUID") != parent.device_uuid:
            raise ValueError("PCI and GPU UUID identities disagree")
        minor = _number(physical["Device Minor"])

        majors, section = {}, None
        for line in devices.text("/proc/devices").splitlines():
            if line.endswith("devices:"):
                section = line
            elif line.strip() and section == "Character devices:":
                number, name = line.split()
                if name in {"nvidia-frontend", "nvidia-uvm", "nvidia-caps"}:
                    if name in majors:
                        raise ValueError("duplicate driver device major")
                    majors[name] = _number(number)
        if set(majors) != {"nvidia-frontend", "nvidia-uvm", "nvidia-caps"}:
            raise ValueError("required NVIDIA character-device drivers are missing")

        mapping = {}
        for line in devices.text("/proc/driver/nvidia-caps/mig-minors").splitlines():
            if not line.strip():
                continue
            name, number = line.split()
            if name in mapping:
                raise ValueError("duplicate MIG capability mapping")
            mapping[name] = _number(number)
        gi, ci = child.details["gpu_instance_id"], child.details["compute_instance_id"]
        prefix = f"gpu{minor}/gi{gi}"
        cap_minors = []
        for suffix in ("access", f"ci{ci}/access"):
            name = f"{prefix}/{suffix}"
            expected = mapping[name]
            fields = _fields(devices.text(f"/proc/driver/nvidia/capabilities/gpu{minor}/mig/gi{gi}/{suffix}"))
            if _number(fields["DeviceFileMinor"]) != expected:
                raise ValueError("MIG capability observations disagree")
            if expected in {mapping["config"], mapping["monitor"]} or expected in cap_minors:
                raise ValueError("MIG access aliases another capability")
            if sum(value == expected for value in mapping.values()) != 1:
                raise ValueError("MIG capability is not uniquely scoped")
            cap_minors.append(expected)

        nodes = []
        targets = [(f"/dev/nvidia{minor}", "nvidia-frontend", minor),
                   ("/dev/nvidiactl", "nvidia-frontend", 255),
                   ("/dev/nvidia-uvm", "nvidia-uvm", 0)]
        targets += [(f"/dev/nvidia-caps/nvidia-cap{number}", "nvidia-caps", number) for number in cap_minors]
        for path, driver, expected_minor in targets:
            actual = devices.device(path)
            if actual != (majors[driver], expected_minor):
                raise ValueError("device node does not match kernel capability metadata")
            nodes.append({"path": path, "type": "c", "major": actual[0], "minor": actual[1]})
        if devices.text("/proc/sys/kernel/random/boot_id").strip() != boot:
            raise ValueError("boot identity changed during observation")
        result = {"protocol": "mig-device-evidence-v1", "host_id": host.id, "boot_id": boot,
                  "parent_uuid": parent.device_uuid, "partition_uuid": child.device_uuid,
                  "pci_bus_id": bdf, "gpu_instance_id": gi, "compute_instance_id": ci,
                  "profile": child.details["profile"], "memory_bytes": child.details["memory_capacity_bytes"],
                  "parent_geometry": geometry, "driver_version": version,
                  "driver_source_version": source_version, "driver_banner_digest": digest(driver_banner),
                  "devices": nodes}
        return {**result, "binding_digest": digest(result)}
    except (KeyError, TypeError, AttributeError, ValueError, OSError) as exc:
        raise Error("partition_binding_unavailable", f"exact MIG device binding unavailable: {exc}", 503) from None
