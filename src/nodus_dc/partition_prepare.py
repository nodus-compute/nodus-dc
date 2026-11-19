"""Initialize the existing local authority from a release-approved host observation.

The normal daemon lock and the original child deadline belong to the caller.
No runtime, cgroup, MIG topology, release qualification or replacement registry is created here.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from pathlib import Path

from . import ephemeral
from .backend import NvidiaDockerBackend
from .errors import Error
from .mig_binding import observe
from .model import canonical, digest
from .partition_host import Evidence, LinuxPartitionProvider, path
from .partitions import fields, integer, sha
from .service import Service
from .store import Store

RUNTIME_FILES = "runsc_sha256 sentry_sha256 scoped_shim_sha256 containerd_shim_sha256"
RUNTIME_POLICY = "manifest_sha256 " + RUNTIME_FILES + " libraries_sha256 hooks_sha256"
REQUEST = ("version release_policy raw_cdi parent_uuid host_budget namespace snapshotter fifo_dir content_root "
           "creator_path shared_executables runtime_files runtime_manifest_path")
DEVICE_POLICY = ("accelerator model parent_memory_bytes profile partition_memory_bytes driver_version "
                 "driver_source_version driver_banner_digest")


def refused(message="local host preparation did not complete; retain its authority state"):
    return Error("local_preparation_unavailable", message, 503)


def pinned_record(pointer, limit=256 << 10):
    fields(pointer, "path sha256"); sha(pointer["sha256"])
    value, observed = Evidence().record(path(pointer["path"]), limit)
    if observed != pointer["sha256"]:
        raise refused()
    return value


def release_policy(request):
    # The ordinary host entry verifies the installed release-pair signature before pinning this file.
    policy = pinned_record(request["release_policy"])
    fields(policy, "version retirement_contract runtime_identity creator_sha256 artifacts qualified_device qualification_evidence_sha256")
    if type(policy["version"]) is not int or policy["version"] != 1 or policy["retirement_contract"] != "scoped-host-workload-retirement.v4":
        raise refused()
    fields(policy["runtime_identity"], RUNTIME_POLICY)
    for value in policy["runtime_identity"].values(): sha(value)
    sha(policy["creator_sha256"]); sha(policy["qualification_evidence_sha256"])
    if policy["creator_sha256"] != policy["runtime_identity"]["scoped_shim_sha256"]:
        raise refused()
    device = policy["qualified_device"]; fields(device, DEVICE_POLICY)
    for key in ("accelerator", "model", "profile", "driver_version", "driver_source_version"):
        if not isinstance(device[key], str) or not device[key] or not device[key].isascii() or len(device[key]) > 128:
            raise refused()
    integer(device["parent_memory_bytes"], 1); integer(device["partition_memory_bytes"], 1)
    sha(device["driver_banner_digest"])
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", device["driver_version"]) or not re.fullmatch(r"[A-Fa-f0-9]{23,24}", device["driver_source_version"]):
        raise refused()
    artifacts = policy["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 128:
        raise refused()
    seen = set()
    for item in artifacts:
        fields(item, "path sha256"); path(item["path"]); sha(item["sha256"])
        if item["path"] in seen: raise refused()
        seen.add(item["path"])
    fields(request["runtime_files"], RUNTIME_FILES)
    for key, name in request["runtime_files"].items():
        if Evidence().file_hash(path(name), 256 << 20) != policy["runtime_identity"][key]: raise refused()
    if (request["creator_path"] != request["runtime_files"]["scoped_shim_sha256"]
            or path(request["runtime_manifest_path"]) != path(request["runtime_files"]["runsc_sha256"]).parent / "manifest.json"
            or Evidence().file_hash(path(request["runtime_manifest_path"]), 128 << 10) != policy["runtime_identity"]["manifest_sha256"]):
        raise refused()
    return policy


def device_rows(service, parent_uuid, policy):
    snapshot = service.backend.inventory()
    if not math.isfinite(snapshot.observed_at) or abs(time.time() - snapshot.observed_at) > 30:
        raise refused()
    parents = [r for r in snapshot.resources if r.id == parent_uuid]
    children = sorted((r for r in snapshot.resources if r.parent == parent_uuid), key=lambda r: r.id)
    expected = policy["qualified_device"]
    if (len(parents) != 1 or parents[0].kind != "gpu" or parents[0].name != expected["model"]
            or parents[0].memory_bytes != expected["parent_memory_bytes"] or parents[0].busy
            or not 1 <= len(children) <= 64 or any(r.busy for r in children)):
        raise refused()
    devices = [observe(snapshot, row.id) for row in children]
    for device in devices:
        if (device["parent_uuid"] != parent_uuid or device["profile"] != expected["profile"]
                or device["memory_bytes"] != expected["partition_memory_bytes"]
                or any(device[key] != expected[key] for key in ("driver_version", "driver_source_version", "driver_banner_digest"))):
            raise refused()
    return devices


def compute_cdi(raw, devices, policy):
    """Reduce the admitted toolkit shape to the observed compute nodes and pinned artifacts."""
    if (not isinstance(raw, dict) or set(raw) - {"cdiVersion", "kind", "devices", "containerEdits", "annotations"}
            or raw.get("kind") != "nvidia.com/gpu" or not isinstance(raw.get("cdiVersion"), str)
            or not isinstance(raw.get("devices"), list) or len(raw["devices"]) > 256):
        raise refused()
    spec = copy.deepcopy(raw); names = {d["partition_uuid"] for d in devices}
    selected = [d for d in spec["devices"] if isinstance(d, dict) and d.get("name") in names]
    if len(selected) != len(names) or {d["name"] for d in selected} != names: raise refused()
    spec["devices"] = selected
    common = spec.get("containerEdits")
    if not isinstance(common, dict) or set(common) - {"env", "deviceNodes", "mounts", "hooks"}: raise refused()
    for key in ("deviceNodes", "mounts", "hooks"):
        if not isinstance(common.get(key, []), list) or len(common.get(key, [])) > 128: raise refused()
    driver = policy["qualified_device"]["driver_version"]
    frontend = devices[0]["devices"][0]["major"]; uvm = devices[0]["devices"][2]["major"]
    removable = {"/dev/nvidia-modeset": (frontend, 254), "/dev/nvidia-uvm-tools": (uvm, 1)}
    retained = []
    for node in common.get("deviceNodes", []):
        if not isinstance(node, dict): raise refused()
        if node.get("path") not in removable:
            retained.append(node); continue
        info = os.lstat(node["path"]); pair = (os.major(info.st_rdev), os.minor(info.st_rdev))
        if (not stat.S_ISCHR(info.st_mode) or pair != removable[node["path"]]
                or node.get("hostPath", node["path"]) != node["path"] or node.get("type", "c") != "c"
                or (node.get("major", pair[0]), node.get("minor", pair[1])) != pair): raise refused()
    common["deviceNodes"] = retained
    mounts = []
    for item in common.get("mounts", []):
        if not isinstance(item, dict): raise refused()
        if item.get("hostPath") not in ("/run/nvidia-persistenced/socket", "/var/run/nvidia-persistenced/socket"):
            mounts.append(item); continue
        if item.get("containerPath") != item["hostPath"] or not stat.S_ISSOCK(os.stat(item["hostPath"]).st_mode): raise refused()
    common["mounts"] = mounts
    artifacts, libraries, hooks = {}, {}, {}
    for entry, device in zip(sorted(selected, key=lambda v: v["name"]), devices):
        if set(entry) - {"name", "containerEdits", "annotations"} or not isinstance(entry.get("containerEdits"), dict): raise refused()
        edits = [common, entry["containerEdits"]]
        if any(not isinstance(e.get("env", []), list) for e in edits): raise refused()
        environment = [v for e in edits for v in e.get("env", [])]
        if (any(not isinstance(v, str) for v in environment)
                or sorted(environment) != sorted(["NVIDIA_VISIBLE_DEVICES=void", "NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/x86_64-linux-gnu"])): raise refused()
        expected = {v["path"]: v for v in device["devices"]}; seen = set()
        for edit in edits:
            if set(edit) - {"env", "deviceNodes", "mounts", "hooks"}: raise refused()
            for key in ("deviceNodes", "mounts", "hooks"):
                if not isinstance(edit.get(key, []), list) or len(edit.get(key, [])) > 128: raise refused()
            for node in edit.get("deviceNodes", []):
                if not isinstance(node, dict) or set(node) - {"path", "hostPath", "type", "major", "minor", "fileMode", "permissions", "uid", "gid"}: raise refused()
                name = node.get("path"); want = expected.get(name)
                if want is None or name in seen: raise refused()
                seen.add(name)
                if (node.get("hostPath", name) != name or node.get("type", "c") != "c"
                        or node.get("major", want["major"]) != want["major"] or node.get("minor", want["minor"]) != want["minor"]
                        or node.get("permissions", "rwm") not in ("rw", "rwm") or node.get("uid", 0) != 0 or node.get("gid", 0) != 0
                        or any(type(node[k]) is not int for k in ("major", "minor", "uid", "gid") if k in node)
                        or type(node.get("fileMode", 0)) is not int or node.get("fileMode", 0) & ~0o666): raise refused()
                node.update(type="c", major=want["major"], minor=want["minor"], permissions=node.get("permissions", "rwm"))
            for mount in edit.get("mounts", []):
                if (not isinstance(mount, dict) or set(mount) - {"hostPath", "containerPath", "options", "type"}
                        or mount.get("type", "bind") != "bind" or not isinstance(mount.get("options"), list)
                        or any(not isinstance(v, str) for v in mount["options"])
                        or set(mount["options"]) != {"ro", "nosuid", "nodev", "rbind", "rprivate"}): raise refused()
                for name in (mount.get("hostPath"), mount.get("containerPath")):
                    path(name)
                    if not name.startswith(("/usr/lib/", "/usr/bin/", "/lib/firmware/nvidia/" + driver + "/")): raise refused()
                if mount["containerPath"].startswith("/lib/"):
                    if not Path("/lib").is_symlink() or Path("/lib").resolve() != Path("/usr/lib"): raise refused()
                    resolved = str(Path(mount["containerPath"]).resolve(strict=True))
                    if (not resolved.startswith("/usr/lib/firmware/nvidia/" + driver + "/")
                            or mount["hostPath"] not in (mount["containerPath"], resolved)): raise refused()
                    mount["hostPath"] = resolved
                elif mount["hostPath"] != mount["containerPath"]: raise refused()
                name = mount["hostPath"]; artifacts[name] = libraries[name] = Evidence().file_hash(name)
            for hook in edit.get("hooks", []):
                if (not isinstance(hook, dict) or set(hook) - {"hookName", "path", "args", "env", "timeout"}
                        or hook.get("hookName") not in ("prestart", "createRuntime", "createContainer")
                        or hook.get("path") != "/usr/bin/nvidia-cdi-hook" or not isinstance(hook.get("args"), list)
                        or not 2 <= len(hook["args"]) <= 32 or any(not isinstance(v, str) or len(v) > 4096 for v in hook["args"])
                        or hook["args"][0] not in ("nvidia-cdi-hook", hook["path"])
                        or hook["args"][1] not in ("create-symlinks", "update-ldcache", "enable-cuda-compat", "disable-device-node-modification")): raise refused()
                if (not isinstance(hook.get("env", []), list) or len(hook.get("env", [])) > 32
                        or any(not isinstance(v, str) or len(v) > 4096 for v in hook.get("env", []))
                        or "timeout" in hook and (type(hook["timeout"]) is not int or not 1 <= hook["timeout"] <= 30)): raise refused()
                name = hook["path"]; artifacts[name] = hooks[name] = Evidence().file_hash(name)
        if seen != set(expected): raise refused()
        library = "/usr/lib/x86_64-linux-gnu/libcuda.so." + driver
        if sum(m["hostPath"] == m["containerPath"] == library for e in edits for m in e.get("mounts", [])) != 1: raise refused()
    if ({v["path"]: v["sha256"] for v in policy["artifacts"]} != artifacts
            or digest(libraries) != policy["runtime_identity"]["libraries_sha256"]
            or digest(hooks) != policy["runtime_identity"]["hooks_sha256"]): raise refused()
    for edit in [common, *[v["containerEdits"] for v in selected]]:
        if "env" in edit: edit["env"] = [v for v in edit["env"] if not v.startswith("NVIDIA_CTK_LIBCUDA_DIR=")]
        for mount in edit.get("mounts", []): mount["options"] = [v for v in mount["options"] if v != "rprivate"]
    common.setdefault("env", []).append("LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu")
    return spec


def daemon_lock(directory):
    """Keep the same protected inode across a pre-Store setup refusal."""
    directory = path(str(directory)); owner = Evidence().protected(directory, directory=True)
    if owner.st_gid != 0 or owner.st_mode & 0o077: raise refused()
    name = directory / "daemon.lock"
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    stream = os.fdopen(fd, "r+")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        observed = os.fstat(fd)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_gid != 0
                or stat.S_IMODE(observed.st_mode) != 0o600 or observed.st_nlink != 1
                or not os.path.samestat(observed, os.lstat(name))
                or not os.path.samestat(owner, Evidence().protected(directory, directory=True))): raise refused()
        return stream
    except BaseException:
        stream.close()
        raise


def publish(name, value):
    """A destination is absent or complete; exact retained bytes are never replaced."""
    raw = canonical(value).encode()
    if len(raw) > 256 << 10: raise refused()
    if os.path.lexists(name):
        info = Evidence().protected(name)
        if not stat.S_ISREG(info.st_mode) or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600: raise refused()
        current, _ = Evidence().read(name, 256 << 10)
        if current != raw: raise refused("preparation artifact differs; retain it for diagnosis")
        return hashlib.sha256(raw).hexdigest()
    # Interrupted temporary writes remain evidence; only this invocation's complete temporary is removed.
    if len(Evidence().names(name.parent, limit=128)) >= 128: raise refused()
    temporary = name.with_name("." + name.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(raw); file.flush(); os.fsync(file.fileno())
        written = os.fstat(file.fileno())
    if not os.path.samestat(written, os.lstat(temporary)): raise refused()
    try:
        os.link(temporary, name, follow_symlinks=False)
    except FileExistsError:
        if Evidence().read(name, 256 << 10)[0] != raw: raise refused()
    fd = os.open(name.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
        if not os.path.samestat(written, os.lstat(temporary)): raise refused()
        temporary.unlink()
        os.fsync(fd)
    finally: os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def preparation_history(service, db, parent, request_sha):
    """Only this input's unused maintenance history can continue preparation."""
    if service.store.fence is None: raise refused()
    anchor = service.store.fence.verify(db)
    prefix = "local-prepare:" + request_sha + ":"
    rows = db.execute("SELECT * FROM leases ORDER BY generation LIMIT 33").fetchall()
    if len(rows) > 32 or rows and anchor is None or any(db.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone() for table in
            ("bridge_policy", "platform_claims", "partition_claims", "partition_policy_grants", "host_reservations", "local_partition_demands")):
        raise refused("preparation found other authority history; use its owning recovery path")
    leases = [Store.decode(row) for row in rows]
    by_id = {lease["id"]: lease for lease in leases}
    for index, lease in enumerate(leases, 1):
        payload = {"resources": [parent], "mode": "gpu_configuration", "expires_at": lease["expires_at"],
                   "owner": "local", "authorization": None}
        if (lease["request_key"] != prefix + str(index) or lease["request_hash"] != digest(payload)
                or lease["owner"] != "local" or lease["mode"] != "gpu_configuration" or lease["resources"] != [parent]
                or any(lease[key] is not None for key in ("authorization", "workload", "runtime", "error"))
                or lease["state"] not in ("reserved", "released")):
            raise refused("preparation maintenance is ambiguous; retain its lease and authority")
        if lease["state"] == "released":
            proof = lease["cleanup"]
            if (not isinstance(proof, dict) or proof.get("clean") is not True or proof.get("lease_id") != lease["id"]
                    or proof.get("generation") != lease["generation"] or proof.get("resource_ids") != [parent]): raise refused()
        elif lease is not leases[-1] or lease["cleanup"] is not None:
            raise refused()
    operations = db.execute("SELECT * FROM operations LIMIT 65").fetchall()
    if len(operations) > 64: raise refused()
    adopted, released = set(), set()
    for operation in operations:
        lease = by_id.get(operation["lease_id"]); action = operation["action"]
        if (lease is None or action not in ("adopt_partitions", "release") or operation["generation"] != lease["generation"]
                or operation["request_key"] != lease["request_key"] + (":adopt" if action == "adopt_partitions" else ":release")
                or operation["request_hash"] != digest({"lease": lease["id"], "generation": lease["generation"], "action": action, "payload": {}})):
            raise refused()
        (adopted if action == "adopt_partitions" else released).add(lease["id"])
    if released != {lease["id"] for lease in leases if lease["state"] == "released"}:
        raise refused("preparation cleanup did not return a verified release; retain its state")
    configs = db.execute("SELECT * FROM partition_configurations LIMIT 2").fetchall()
    committed = dict(configs[0]) if len(configs) == 1 else None
    if (len(configs) > 1 or len(adopted) > 1 or bool(adopted) != bool(committed)
            or committed and (committed["parent_uuid"] != parent or committed["state"] != "committed"
                or committed["error"] is not None or not leases or adopted != {leases[-1]["id"]}
                or committed["operation_id"] != leases[-1]["request_key"] + ":adopt")):
        raise refused("preparation adoption is ambiguous; retain its configuration and lease")
    return leases, committed


def prepare_local_host(directory, template_path, template_sha256, *, expires_at):
    """Return the same Service only after observed policy binding and maintenance release."""
    now = time.time()
    if (os.geteuid() != 0 or type(expires_at) not in (int, float) or not math.isfinite(expires_at)
            or not now < expires_at <= now + 300): raise refused()
    end = time.monotonic() + expires_at - now
    root = path(str(directory)); owner = Evidence().protected(root, directory=True)
    if owner.st_gid != 0 or owner.st_mode & 0o077: raise refused()
    def live():
        current = Evidence().protected(root, directory=True)
        if (time.time() >= expires_at or time.monotonic() >= end or current.st_gid != 0 or current.st_mode & 0o077
                or (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino)): raise refused()
    request = pinned_record({"path": template_path, "sha256": template_sha256}); fields(request, REQUEST)
    if (type(request["version"]) is not int or request["version"] != 1 or not isinstance(request["host_budget"], dict)
            or request["host_budget"].get("authority_incarnation", "missing") is not None
            or not isinstance(request["parent_uuid"], str) or not re.fullmatch(r"GPU-[A-Za-z0-9_-]{4,160}", request["parent_uuid"])): raise refused()
    policy = release_policy(request)
    store_path, config_path, cdi_path, qualification_path = (root / name for name in
            ("authority.sqlite3", "provider-config.json", "devices.json", "qualification.json"))
    inputs_path, authority_path = root / "preparation-input.json", root / "preparation-authority.json"
    retained = (store_path, Path(str(store_path) + "-wal"), Path(str(store_path) + "-shm"), config_path, cdi_path, qualification_path)
    if not os.path.lexists(inputs_path) and any(os.path.lexists(p) for p in (*retained, authority_path)):
        raise refused("existing authority has no matching preparation input; retain it for diagnosis")
    live(); publish(inputs_path, {"version": 1, "request_sha256": template_sha256,
                                 "directory_device": owner.st_dev, "directory_inode": owner.st_ino})
    for name in retained:
        if os.path.lexists(name):
            info = Evidence().protected(name)
            if not stat.S_ISREG(info.st_mode) or info.st_gid != 0 or info.st_mode & 0o077: raise refused()
    if not store_path.exists() and any(os.path.lexists(p) for p in (*retained[1:], authority_path)): raise refused()
    if authority_path.exists():
        saved, _ = Evidence().record(authority_path)
        fields(saved, "version request_sha256 database_device database_inode authority_incarnation")
        database = Evidence().protected(store_path)
        if (type(saved["version"]) is not int or saved["version"] != 1 or saved["request_sha256"] != template_sha256
                or any(type(saved[key]) is not int for key in ("database_device", "database_inode"))
                or (saved["database_device"], saved["database_inode"]) != (database.st_dev, database.st_ino)):
            raise refused("preparation database identity changed; retain the original authority")
    live()
    service = Service(Store(store_path), NvidiaDockerBackend(allocation_authority="standalone"), bridge_enabled=False)
    with service.authority():
        live()
        if service.store.fence is None: raise refused()
        with service.store.connection() as db:
            anchor = service.store.fence.verify(db)
            leases, committed = preparation_history(service, db, request["parent_uuid"], template_sha256)
            if anchor is None and (leases or committed or authority_path.exists() or any(p.exists() for p in retained[3:])): raise refused()
            if not authority_path.exists() and (leases or committed): raise refused()
        if anchor is None:
            service.partitions.ensure_durable()
            with service.store.connection() as db: anchor = service.store.fence.verify(db)
        database = Evidence().protected(store_path)
        live(); publish(authority_path, {"version": 1, "request_sha256": template_sha256,
                                       "database_device": database.st_dev, "database_inode": database.st_ino,
                                       "authority_incarnation": anchor["incarnation"]})
    if request["host_budget"].get("boot_id") != service.backend.boot_id(): raise refused()
    if committed and (committed["boot_id"] != request["host_budget"]["boot_id"]
                      or not all(p.exists() for p in retained[3:])): raise refused()
    # A known unused reservation retires through the ordinary proof path before any new finite attempt.
    if leases and leases[-1]["state"] == "reserved":
        live(); previous = leases[-1]
        previous = service.release(previous["id"], generation=previous["generation"], request_key=previous["request_key"] + ":release")
        if previous["state"] != "released": raise refused()
    if not committed:
        if len(leases) >= 32: raise refused("bounded preparation history is full; retain it for diagnosis")
        live()
        held = service.reserve(resources=[request["parent_uuid"]], mode="gpu_configuration", expires_at=expires_at,
                               request_key="local-prepare:" + template_sha256 + ":" + str(len(leases) + 1))
    live()
    with service.authority():
        live()
        if committed and service.partitions._observation(service.backend.inventory(), request["parent_uuid"]) != json.loads(committed["binding"]):
            raise refused("prepared configuration changed; retain the original authority")
        devices = device_rows(service, request["parent_uuid"], policy)
        cdi = compute_cdi(pinned_record(request["raw_cdi"], 1 << 20), devices, policy)
        if devices != device_rows(service, request["parent_uuid"], policy): raise refused()
        live(); cdi_sha = publish(cdi_path, cdi)
        identity = {**policy["runtime_identity"], "cdi_path": str(cdi_path), "cdi_sha256": cdi_sha}
        qualified = [{"device": d, "accelerator": policy["qualified_device"]["accelerator"]} for d in devices]
        qualification = {"version": 1, "retirement_contract": policy["retirement_contract"], "runtime_identity": identity,
                         "creator_sha256": policy["creator_sha256"], "devices": qualified, "artifacts": policy["artifacts"]}
        live(); qualification_sha = publish(qualification_path, qualification)
        identity = {**identity, "qualification_sha256": qualification_sha}
        budget = {**request["host_budget"], "authority_incarnation": anchor["incarnation"]}
        config = {key: copy.deepcopy(request[key]) for key in ("namespace", "snapshotter", "fifo_dir", "content_root", "creator_path", "shared_executables")}
        config.update(version=1, host_budget=budget, creator_sha256=policy["creator_sha256"], runtime_identity=identity,
                      runtime_files={**request["runtime_files"], "cdi_sha256": str(cdi_path)}, devices=qualified,
                      qualification_path=str(qualification_path))
        live(); config_sha = publish(config_path, config)
        service.partitions.executor = LinuxPartitionProvider(str(config_path), config_sha)
        if service.partitions.devices is not None or service.partitions.executor.verify_startup(anchor["incarnation"]) is not True: raise refused()
    live()
    if not committed:
        service.adopt_partitions(held["id"], generation=held["generation"], request_key=held["request_key"] + ":adopt")
    with service.authority():
        live()
        if devices != device_rows(service, request["parent_uuid"], policy): raise refused()
    if not committed:
        live(); released = service.release(held["id"], generation=held["generation"], request_key=held["request_key"] + ":release")
        if released["state"] != "released": raise refused()
    # The maintenance lease has no host reservation; accounting it as a workload would correctly refuse.
    with service.authority(), service.store.transaction(time.time()) as db:
        live(); service.partitions._host_account(db, accounting_version=ephemeral.ACCOUNTING)
    live()
    return service, {"config_path": str(config_path), "config_sha256": config_sha,
                     "host_budget": copy.deepcopy(budget), "runtime_identity": copy.deepcopy(identity)}
