"""Host-only NVIDIA/Docker backend. Hardware behavior requires separate qualification."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import platform
import re
import signal
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path

from .errors import Error
from .model import CleanupProof, Resource, Snapshot, canonical

LABEL = "ai.nodus.datacenter"
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}\Z")


def run(argv, *, timeout=30):
    """No shell, bounded execution, kill the exact subprocess group on timeout."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise Error("backend_timeout", f"{argv[0]} did not complete in time", 503) from None
    if proc.returncode:
        raise Error("backend_command_failed", f"{argv[0]} failed: {err.strip()[:500]}", 503)
    if len(out) > 16 * 1024 * 1024:
        raise Error("backend_output_limit", "backend output exceeded the safety limit", 503)
    return out


def memory_bytes(text):
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(MiB|GiB)\s*", text or "")
    return int(float(match[1]) * (2**20 if match[2] == "MiB" else 2**30)) if match else 0


def physical_query(raw, capabilities):
    """Join a fresh physical index/UUID query, never XML order or minor number."""
    indices, compute = {}, {}
    try:
        for row in csv.reader(io.StringIO(raw)):
            if not row:
                continue
            row = [value.strip() for value in row]
            if len(row) != (4 if capabilities else 3):
                raise ValueError("unexpected physical query columns")
            index, uuid, mig_mode = row[:3]
            if (not re.fullmatch(r"0|[1-9][0-9]*", index)
                    or not re.fullmatch(r"GPU-[A-Za-z0-9-]+", uuid)
                    or index in indices or uuid in indices.values() or mig_mode != "Disabled"):
                raise ValueError("ambiguous physical identity or MIG mode changed")
            indices[index] = uuid
            if capabilities and re.fullmatch(r"[0-9]+\.[0-9]+", row[3]):
                value = float(row[3])
                if math.isfinite(value):
                    compute[uuid] = value
    except (csv.Error, ValueError) as exc:
        raise Error("invalid_inventory", str(exc), 503) from None
    return indices, compute


def mig_process_scopes(gpu, children):
    """Join driver MIG indices to UUIDs and GI/CI process identities.

    Never infer partition occupancy from its marketing profile or PID order.
    An incomplete/ambiguous join returns no fine-grained evidence: callers
    retain the conservative physical-GPU process scope. Multiple compute
    instances sharing one GPU instance are outside this whole-instance mode.
    """
    def index(node, name):
        value = node.findtext(name, "")
        if not re.fullmatch(r"\d+", value):
            raise ValueError("unknown MIG identity")
        return int(value)

    try:
        rows = gpu.findall("mig_devices/mig_device")
        if not children or len(rows) != len(children):
            return None
        by_index, by_pair, gpu_instances = {}, {}, set()
        for row in rows:
            number = index(row, "index")
            pair = (index(row, "gpu_instance_id"), index(row, "compute_instance_id"))
            if number in by_index or pair in by_pair or pair[0] in gpu_instances:
                return None
            info = {"gpu_instance_id": pair[0], "compute_instance_id": pair[1],
                    "process_ids": [],
                    "memory_capacity_bytes": memory_bytes(row.findtext("fb_memory_usage/total")),
                    "memory_used_bytes": memory_bytes(row.findtext("fb_memory_usage/used"))}
            by_index[number] = info
            by_pair[pair] = info
            gpu_instances.add(pair[0])
        numbers = [number for _, _, number in children]
        uuids = [uuid for uuid, _, _ in children]
        if (len(set(numbers)) != len(numbers) or len(set(uuids)) != len(uuids)
                or set(numbers) != set(by_index)):
            return None
        for process in gpu.findall("processes/process_info"):
            pair = (index(process, "gpu_instance_id"), index(process, "compute_instance_id"))
            if pair not in by_pair:
                return None
            by_pair[pair]["process_ids"].append(process.findtext("pid", "unknown"))
        return {uuid: by_index[number] for uuid, _, number in children}
    except ValueError:
        return None


class NvidiaDockerBackend:
    def __init__(self, *, command=run, clock=time.time, host_id=None, allocation_authority="observe", enable_trusted_mps=False):
        self.command = command
        self.clock = clock
        if allocation_authority not in {"observe", "standalone", "kubernetes"}:
            raise ValueError("unknown allocation authority")
        self.allocation_authority = allocation_authority
        self.enable_trusted_mps = enable_trusted_mps
        if host_id is None:
            machine = Path("/etc/machine-id")
            identity = machine.read_text().strip() if machine.exists() else platform.node()
            host_id = "host-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
        self.host_id = host_id

    def _containers(self, *, all_containers=False):
        ids = self.command(["docker", "ps", "-aq" if all_containers else "-q"], timeout=15).split()
        if not ids:
            return []
        return json.loads(self.command(["docker", "inspect", *ids], timeout=30))

    def inventory(self):
        warnings = []
        devices = []
        gpu_indices = {}
        driver = ""
        try:
            xml = ET.fromstring(self.command(["nvidia-smi", "-q", "-x"], timeout=20))
            driver = xml.findtext("driver_version", "")
            gpus = xml.findall("gpu")
            physical_only = bool(gpus) and all(
                gpu.findtext("mig_mode/current_mig") == "Disabled"
                and (gpu.find("mig_devices") is None or (
                    len(gpu.find("mig_devices")) == 0
                    and (gpu.findtext("mig_devices") or "").strip() in {"", "None"}))
                for gpu in gpus)
            listing = ""
            compute = {}
            if physical_only:
                # Preserve two fresh observations and explicit physical indices.
                # MIG instances/unknown modes still need the complete -L join.
                fields = "index,uuid,mig.mode.current" + (",compute_cap" if self.enable_trusted_mps else "")
                raw = self.command(["nvidia-smi", "--query-gpu=" + fields, "--format=csv,noheader"], timeout=15)
                gpu_indices, compute = physical_query(raw, self.enable_trusted_mps)
                if self.enable_trusted_mps and len(compute) != len(gpu_indices):
                    warnings.append("MPS compute capability unavailable; trusted sharing disabled")
            else:
                listing = self.command(["nvidia-smi", "-L"], timeout=15)
            if self.enable_trusted_mps and not physical_only:
                try:
                    for line in self.command(["nvidia-smi", "--query-gpu=uuid,compute_cap", "--format=csv,noheader"], timeout=15).splitlines():
                        identity, capability = [part.strip() for part in line.split(",")]
                        compute[identity] = float(capability)
                except (Error, ValueError):
                    warnings.append("MPS compute capability unavailable; trusted sharing disabled")
            children = {}
            parent = None
            for line in listing.splitlines():
                match = re.search(r"^GPU (\d+):.*\(UUID: (GPU-[^)]+)\)", line)
                if match:
                    parent = match[2]
                    if match[1] in gpu_indices or parent in gpu_indices.values():
                        raise Error("invalid_inventory", "duplicate physical GPU listing identity", 503)
                    gpu_indices[match[1]] = parent
                else:
                    match = re.search(r"MIG (\S+)\s+Device\s+(\d+):\s*\(UUID: (MIG-[^)]+)\)", line)
                    if match and parent:
                        children.setdefault(parent, []).append((match[3], match[1], int(match[2])))
                    elif line.strip():
                        raise Error("invalid_inventory", "unrecognized GPU/MIG listing; geometry is unknown", 503)
            xml_uuids = [gpu.findtext("uuid", "") for gpu in xml.findall("gpu")]
            if len(set(xml_uuids)) != len(xml_uuids) or set(xml_uuids) != set(gpu_indices.values()):
                raise Error("invalid_inventory", "physical GPU XML/listing identities disagree", 503)
            for gpu in xml.findall("gpu"):
                gpu_uuid = gpu.findtext("uuid", "")
                if not gpu_uuid.startswith("GPU-"):
                    raise Error("invalid_inventory", "GPU UUID is missing", 503)
                mig_mode = gpu.findtext("mig_mode/current_mig", "N/A")
                processes = gpu.find("processes")
                processes_known = (processes is not None and not (processes.text or "").strip()
                                   and all(p.tag == "process_info" and not (p.tail or "").strip() for p in processes))
                pids = [p.findtext("pid", "unknown") for p in gpu.findall("processes/process_info")]
                healthy = processes_known and gpu.findtext("gpu_recovery_action", "None") in {"None", "N/A", ""}
                busy = bool(pids) or not processes_known
                child_rows = children.get(gpu_uuid, [])
                scopes = mig_process_scopes(gpu, child_rows) if processes_known else None
                mig_devices = gpu.find("mig_devices")
                mig_xml_known = (mig_devices is not None
                                 and (mig_devices.text or "").strip() in ({"", "None"} if len(mig_devices) == 0 else {""})
                                 and all(d.tag == "mig_device" and not (d.tail or "").strip() for d in mig_devices))
                geometry_known = (mig_mode in {"Disabled", "N/A"} and not child_rows
                                  and (mig_devices is None or (mig_xml_known and len(mig_devices) == 0))) or (
                    mig_mode == "Enabled" and mig_xml_known and
                    (scopes is not None or (not child_rows and len(mig_devices) == 0)))
                if not geometry_known:
                    healthy = False
                    busy = True
                    warnings.append(f"{gpu_uuid}: MIG identity/process mapping unavailable or ambiguous")
                modes = []
                if mig_mode != "Enabled":
                    modes.append("exclusive_gpu")
                if mig_mode in {"Enabled", "Disabled"}:
                    modes.append("gpu_configuration")
                if self.enable_trusted_mps and compute.get(gpu_uuid, 0) >= 7 and mig_mode != "Enabled":
                    modes.append("trusted_mps")
                resource = Resource(gpu_uuid, "gpu", self.host_id, gpu_uuid,
                                    gpu.findtext("product_name", ""), memory_bytes(gpu.findtext("fb_memory_usage/total")),
                                    tuple(modes), healthy, busy,
                                    {"mig_mode": mig_mode, "pci_bus_id": gpu.findtext("pci/pci_bus_id", ""),
                                     "driver_version": driver, "process_ids": pids,
                                     "process_inventory_known": processes_known, "compute_capability": compute.get(gpu_uuid),
                                     "utilization_gpu": gpu.findtext("utilization/gpu_util", "N/A"),
                                     "memory_used_bytes": memory_bytes(gpu.findtext("fb_memory_usage/used")),
                                     "sharing_isolation": "trusted_cooperative_only"})
                devices.append(resource)
                for child, profile, _ in child_rows:
                    # Whole hardware instances are allocated. Do not invent a
                    # fractional byte capacity from the profile's marketing name.
                    detail = {"profile": profile, "memory_capacity_source": "driver_enforced_whole_instance",
                              "process_inventory_scope": "conservative_parent_gpu"}
                    child_busy = busy
                    if scopes is not None:
                        detail.update(scopes[child], process_inventory_scope="gpu_compute_instance")
                        child_busy = bool(scopes[child]["process_ids"])
                    devices.append(Resource(child, "partition", gpu_uuid, child, profile, 0,
                                            ("hardware_partition",), healthy, child_busy, detail))
        except (Error, OSError, ET.ParseError) as exc:
            warnings.append(str(exc))
            devices = []
        try:
            containers = self._containers()
            container_busy = bool(containers)
            gpu_ids = [r.id for r in devices if r.kind == "gpu"]
            assigned = set()
            unknown_assignment = False
            for container in containers:
                host_config = container.get("HostConfig", {})
                # Legacy NVIDIA runtime/environment activation can expose GPUs
                # without a DeviceRequest (including while no CUDA PID exists).
                # Its visibility contract is not a qualified allocation backend.
                if host_config.get("Runtime") == "nvidia" and not any(
                        any("gpu" in group for group in request.get("Capabilities") or [])
                        and request.get("Driver") in {"", "nvidia"}
                        for request in host_config.get("DeviceRequests") or []):
                    unknown_assignment = True
                for request in container.get("HostConfig", {}).get("DeviceRequests") or []:
                    if request.get("Driver") not in {"", "nvidia"}:
                        continue
                    if not any("gpu" in group for group in request.get("Capabilities") or []):
                        continue
                    requested = request.get("DeviceIDs") or []
                    if not requested:
                        unknown_assignment = True
                    for device in requested:
                        if str(device) in gpu_indices and gpu_indices[str(device)] in gpu_ids:
                            assigned.add(gpu_indices[str(device)])
                        elif any(r.id == device for r in devices):
                            assigned.add(device)
                        else:
                            unknown_assignment = True
            parent_of = {r.id: r.parent for r in devices}
            # Child occupancy blocks its physical GPU, but must not propagate
            # back down to unrelated sibling GPU instances. Explicit whole-GPU
            # assignments and unknown device requests still block all children.
            occupied_parents = {parent_of[x] for x in assigned if parent_of.get(x) in gpu_ids}
            conservative_parents = {r.parent for r in devices if r.id in assigned and r.kind == "partition"
                                    and r.details.get("process_inventory_scope") != "gpu_compute_instance"}
            devices = [replace(r, busy=True) if (unknown_assignment or r.id in assigned
                       or r.parent in assigned or r.id in occupied_parents
                       or r.parent in conservative_parents) else r
                       for r in devices]
        except (Error, OSError, ValueError) as exc:
            warnings.append("container inventory unavailable: " + str(exc))
            container_busy = True
            devices = [replace(r, busy=True) for r in devices]
        if self.allocation_authority != "standalone":
            devices = [replace(r, modes=()) for r in devices]
        gpu_devices = [r for r in devices if r.kind == "gpu"]
        host_healthy = bool(gpu_devices) and all(r.healthy for r in gpu_devices) and not warnings
        host_busy = container_busy or any(r.busy for r in gpu_devices)
        whole_gpu_mode = all(r.details.get("mig_mode") != "Enabled" for r in gpu_devices)
        host = Resource(self.host_id, "host", None, name=platform.node(),
                        modes=("exclusive_host",) if self.allocation_authority == "standalone" and whole_gpu_mode else (), healthy=host_healthy, busy=host_busy,
                        details={"os": platform.platform(), "architecture": platform.machine(),
                                 "driver_version": driver, "running_containers": container_busy,
                                 "trusted_sharing": "opt_in_mps_pool_unqualified" if self.enable_trusted_mps else "disabled",
                                 "partition_creation": "mig_maintenance_lease_unqualified",
                                 "boot_id": self.boot_id(),
                                 "allocation_authority": self.allocation_authority})
        return Snapshot(self.host_id, self.clock(), tuple([host, *devices]), driver,
                        platform.platform(), tuple(warnings), hardware_qualified=False)

    def host_ready_for_external(self):
        snapshot = self.inventory()
        host = next(r for r in snapshot.resources if r.kind == "host")
        return host.healthy and not host.busy and all(r.details.get("mig_mode") != "Enabled"
                                                     for r in snapshot.resources if r.kind == "gpu")

    def bind_authority(self, state_path):
        """Prevent accidentally starting competing databases on the same host.

        Root administrators remain trusted; Linux deployment owns this registry.
        Observe-only tools never bind an allocation authority.
        """
        if self.allocation_authority != "standalone":
            return None
        registry = Path("/var/lib/nodus-dc")
        registry.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = registry / "physical-host.lock"
        import fcntl
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            owner = registry / "authority-path.json"
            identity = {"database": str(Path(state_path).resolve()), "host_id": self.host_id}
            if owner.exists():
                if json.loads(owner.read_text()) != identity:
                    raise Error("competing_authority", "this physical host is bound to another allocation database")
            else:
                out = os.open(owner, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(out, "w") as stream:
                    stream.write(canonical(identity))
                    stream.flush()
                    os.fsync(stream.fileno())
                directory = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def validate_workload(self, workload, lease):
        if lease["mode"] == "gpu_configuration":
            raise Error("unsupported_workload", "configuration leases cannot launch workloads", 400)
        if lease["mode"] == "trusted_mps":
            from .sharing import validate_pool
            return validate_pool(self, workload, lease)
        allowed = {"image", "command", "mounts", "ports", "network", "shm_bytes", "entrypoint"}
        if set(workload) - allowed or not IMAGE.fullmatch(str(workload.get("image", ""))):
            raise Error("invalid_workload", "workload requires a digest-pinned image and supported fields", 400)
        command = workload.get("command", [])
        if "entrypoint" in workload and (not isinstance(workload["entrypoint"], str) or not workload["entrypoint"] or "\0" in workload["entrypoint"]):
            raise Error("invalid_workload", "entrypoint must be a nonempty executable string", 400)
        if not isinstance(command, list) or not command or any(not isinstance(a, str) or "\0" in a for a in command):
            raise Error("invalid_workload", "command must be a nonempty argument list", 400)
        if workload.get("network", "none") not in {"none", "loopback"}:
            raise Error("invalid_workload", "network must be none or loopback", 400)
        if workload.get("ports") and workload.get("network") != "loopback":
            raise Error("invalid_workload", "published ports require loopback networking", 400)
        for port in workload.get("ports", []):
            if (not isinstance(port, dict) or set(port) != {"host", "container"}
                    or any(type(v) is not int or not 1024 <= v <= 65535 for v in port.values())):
                raise Error("invalid_workload", "ports must specify high host/container port numbers", 400)
        for mount in workload.get("mounts", []):
            if not isinstance(mount, dict) or set(mount) != {"source", "target"}:
                raise Error("invalid_workload", "mounts require source and target", 400)
            source, target = Path(mount["source"]).resolve(), Path(mount["target"])
            if not source.is_dir() or not target.is_absolute() or str(source) in {"/", "/var/run", "/run", "/etc", "/dev"}:
                raise Error("invalid_workload", "model mounts must be existing dedicated directories", 400)
            if any("\0" in str(p) or "," in str(p) for p in (source, target)):
                raise Error("invalid_workload", "invalid mount path", 400)
        shm = workload.get("shm_bytes", 1024**3)
        if type(shm) is not int or not 64 * 1024**2 <= shm <= 64 * 1024**3:
            raise Error("invalid_workload", "shm_bytes must be between 64 MiB and 64 GiB", 400)

    def _owned(self, lease):
        found = []
        for container in self._containers(all_containers=True):
            labels = container.get("Config", {}).get("Labels") or {}
            if labels.get(LABEL + ".lease") == lease["id"]:
                if labels.get(LABEL + ".generation") != str(lease["generation"]):
                    raise Error("container_fence_mismatch", "lease container has a different generation", 503)
                if labels.get(LABEL + ".resources") != canonical(lease["resources"]):
                    raise Error("container_resource_mismatch", "lease container has a different allocation", 503)
                found.append(container)
        return found

    def start(self, lease):
        self.require_management()
        workload = lease["workload"]
        self.validate_workload(workload, lease)
        if lease["mode"] == "trusted_mps":
            from .sharing import start_pool
            return start_pool(self, lease)
        if self._owned(lease):
            raise Error("existing_runtime", "a runtime already exists for this lease")
        # Pulling is deliberately separate: offline local operation must not
        # trigger a registry or platform request as a side effect.
        self.command(["docker", "image", "inspect", workload["image"]], timeout=15)
        snapshot = self.inventory()
        by_id = {r.id: r for r in snapshot.resources}
        if any(r not in by_id or not by_id[r].healthy or by_id[r].busy for r in lease["resources"]):
            raise Error("resource_changed", "allocation is no longer clean and available")
        if lease["mode"] == "exclusive_host":
            devices = [r.device_uuid for r in snapshot.resources if r.kind == "gpu"]
        else:
            devices = [by_id[r].device_uuid for r in lease["resources"]]
        if not devices or any(not d for d in devices):
            raise Error("missing_devices", "allocation has no usable GPU device UUID")
        container_id = self._launch_container(lease, workload, devices)
        containers = self._owned(lease)
        if len(containers) != 1 or containers[0]["Id"] != container_id or not containers[0]["State"]["Running"]:
            raise Error("runtime_not_running", "container did not enter the running state", 503)
        return {"lease_id": lease["id"], "generation": lease["generation"], "container_id": container_id,
                "device_uuids": devices, "started_at": self.clock()}

    def _launch_container(self, lease, workload, devices, *, suffix="", extra=()):
        args = ["docker", "create", "--name", f"nodus-dc-{lease['generation']}{suffix}", "--init", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,exec,nosuid,size=8g",
                "--shm-size", str(workload.get("shm_bytes", 1024**3)),
                "--label", LABEL + ".lease=" + lease["id"],
                "--label", LABEL + ".generation=" + str(lease["generation"]),
                "--label", LABEL + ".resources=" + canonical(lease["resources"]),
                "--gpus", '"device=' + ",".join(devices) + '"',
                "--network", "none" if workload.get("network", "none") == "none" else "bridge",
                "--env", "HF_HUB_OFFLINE=1", "--env", "HF_HOME=/tmp/huggingface", "--env", "HOME=/tmp"]
        for mount in workload.get("mounts", []):
            args += ["--mount", f"type=bind,src={Path(mount['source']).resolve()},dst={mount['target']},readonly"]
        for port in workload.get("ports", []):
            args += ["--publish", f"127.0.0.1:{port['host']}:{port['container']}"]
        if "entrypoint" in workload:
            args += ["--entrypoint", workload["entrypoint"]]
        args += list(extra)
        args += [workload["image"], *workload["command"]]
        container_id = self.command(args, timeout=30).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise Error("invalid_container_identity", "Docker did not return an exact container ID", 503)
        self.command(["docker", "start", container_id], timeout=60)
        return container_id

    def _remove_owned_containers(self, lease):
        owned = self._owned(lease)
        # MPS clients stop before their shared control daemon.
        owned.sort(key=lambda c: c.get("Name", "").endswith("-mps"))
        for container in owned:
            cid = container["Id"]
            if container.get("State", {}).get("Running"):
                self.command(["docker", "stop", "--time", "20", cid], timeout=30)
            self.command(["docker", "rm", cid], timeout=15)
        if self._owned(lease):
            raise Error("runtime_cleanup_incomplete", "owned runtime remains after cleanup", 503)

    def cleanup(self, lease):
        self.require_management()
        self._remove_owned_containers(lease)
        if lease["mode"] == "trusted_mps":
            from .sharing import remove_pool_volume
            remove_pool_volume(self, lease)
        return self.verify_clean(lease)

    def recover_partition(self, lease, previous_boot_id, current_boot_id):
        """Retire an old partition lease after a real host execution fence.

        The service holds the physical authority lock and excludes every other
        held lease on the original parent GPUs before invoking this operation.
        Hopper may lose its MIG geometry at reboot. A vanished UUID is not an
        unchanged device: record its retirement and the actual current geometry,
        retaining the original lease resources and baseline as audit evidence.
        """
        self.require_management()
        if (lease.get("owner") != "local" or lease.get("mode") != "hardware_partition"
                or not previous_boot_id or not current_boot_id or previous_boot_id == current_boot_id
                or self.boot_id() != current_boot_id):
            raise Error("execution_fence_required", "partition recovery requires a verified host reboot")
        baseline = {r["id"]: r for r in lease.get("baseline", [])}
        host = baseline.get(self.host_id)
        if (not host or host["kind"] != "host"
                or host["details"].get("boot_id") != previous_boot_id):
            raise Error("invalid_recovery_baseline", "original host and boot identity are required")
        parents = set()
        for resource_id in lease["resources"]:
            original = baseline.get(resource_id)
            if not original or original["kind"] != "partition" or original["device_uuid"] != resource_id:
                raise Error("invalid_recovery_baseline", "original partition identity is required")
            parent = baseline.get(original["parent"])
            if not parent or parent["kind"] != "gpu" or parent["parent"] != self.host_id:
                raise Error("invalid_recovery_baseline", "original physical GPU identity is required")
            parents.add(parent["id"])
        if not parents:
            raise Error("invalid_recovery_baseline", "partition recovery requires a physical GPU")
        self._remove_owned_containers(lease)
        snapshot = self.inventory()
        current = {r.id: r.record() for r in snapshot.resources}
        reasons = list(snapshot.warnings)
        current_host = current.get(self.host_id)
        if (not current_host or not current_host["healthy"]
                or current_host["details"].get("boot_id") != current_boot_id
                or self.boot_id() != current_boot_id):
            reasons.append("current host execution fence or health could not be verified")
        for parent_id in parents:
            original, row = baseline[parent_id], current.get(parent_id)
            if not row or not row["healthy"] or row["busy"] or not row["details"].get("process_inventory_known"):
                reasons.append(f"{parent_id}: physical GPU is absent, unobservable, unhealthy or busy")
                continue
            for field in ("kind", "parent", "device_uuid", "memory_bytes"):
                if row[field] != original[field]:
                    reasons.append(f"{parent_id}: physical {field} changed")
            for field in ("pci_bus_id", "driver_version"):
                if not original["details"].get(field) or row["details"].get(field) != original["details"][field]:
                    reasons.append(f"{parent_id}: physical {field} changed or unavailable")
            if row["details"].get("mig_mode") not in {"Enabled", "Disabled"}:
                reasons.append(f"{parent_id}: current hardware partitioning mode is unknown")
            for child in current.values():
                if child["parent"] == parent_id and (not child["healthy"] or child["busy"]):
                    reasons.append(f"{child['id']}: current child is unhealthy or busy")
        return CleanupProof(not reasons, self.clock(), lease["id"], lease["generation"], tuple(lease["resources"]),
                            {"reasons": reasons, "previous_boot_id": previous_boot_id,
                             "recovery_boot_id": current_boot_id, "retired_partition_leases": list(lease["resources"]),
                             "physical_gpu_ids": sorted(parents),
                             "current_geometry": [r for r in current.values() if r["id"] in parents or r["parent"] in parents],
                             "inventory_revision": snapshot.record()["revision"],
                             "verification_scope": "host reboot fence, exact owned Docker cleanup, unchanged idle physical GPUs; original MIG geometry is not restored"})

    @staticmethod
    def boot_id():
        path = Path("/proc/sys/kernel/random/boot_id")
        return path.read_text().strip() if path.exists() else None

    def require_management(self):
        if self.allocation_authority != "standalone":
            raise Error("observe_only", "this backend does not own local allocation authority", 403)

    def configure_mig(self, lease, plan):
        self.require_management()
        from .partitioning import configure_mig
        return configure_mig(self, lease, plan)

    def verify_clean(self, lease):
        snapshot = self.inventory()
        current = {r.id: r.record() for r in snapshot.resources}
        reasons = []
        for resource_id in lease["resources"]:
            row = current.get(resource_id)
            if row is None or not row["healthy"] or row["busy"]:
                reasons.append(f"{resource_id}: absent, unhealthy or busy")
        for original in lease.get("baseline") or []:
            row = current.get(original["id"])
            if row is None:
                reasons.append(f"{original['id']}: baseline device missing")
                continue
            for field in ("kind", "parent", "device_uuid", "memory_bytes"):
                if canonical(row[field]) != canonical(original[field]):
                    reasons.append(f"{original['id']}: {field} changed")
            for field in ("mig_mode", "driver_version", "profile"):
                if row["details"].get(field) != original["details"].get(field):
                    reasons.append(f"{original['id']}: {field} changed")
        if lease["mode"] == "exclusive_host" and not self.host_ready_for_external():
            reasons.append("host still has workload activity or incompatible GPU mode")
        return CleanupProof(not reasons, self.clock(), lease["id"], lease["generation"], tuple(lease["resources"]),
                            {"reasons": reasons, "inventory_revision": snapshot.record()["revision"],
                             "verification_scope": "Docker inventory, NVIDIA processes and allocated device configuration"})
