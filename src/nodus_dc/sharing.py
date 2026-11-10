"""Legacy NVIDIA MPS: one exclusively held GPU, one cooperating trust domain.

This is not tenant isolation. Limits are cooperative client settings and can be
changed by trusted client code. A pool's members share IPC/PID namespaces.
All clients are reclaimed together; the physical lease stays exclusive.
"""
from .errors import Error
from .model import canonical, key

LABEL = "ai.nodus.datacenter"


def validate_pool(backend, workload, lease):
    if not backend.enable_trusted_mps:
        raise Error("unsupported_mode", "trusted MPS must be explicitly enabled", 400)
    if set(workload) != {"trust_domain", "controller_image", "clients"} or len(lease["resources"]) != 1:
        raise Error("invalid_mps_pool", "MPS requires one GPU, trust_domain, controller_image and clients", 400)
    key(workload["trust_domain"], "trust_domain")
    clients = workload["clients"]
    if not isinstance(clients, list) or not 2 <= len(clients) <= 16:
        raise Error("invalid_mps_pool", "a trusted pool needs 2 to 16 clients", 400)
    ordinary = dict(lease, mode="exclusive_gpu")
    backend.validate_workload({"image": workload["controller_image"], "command": ["nvidia-cuda-mps-control", "-f"]}, ordinary)
    percent = memory = 0
    ports = []
    for client in clients:
        if not isinstance(client, dict) or set(client) != {"workload", "active_thread_percent", "memory_mib"}:
            raise Error("invalid_mps_pool", "each client needs workload and explicit compute/memory limits", 400)
        p, m = client["active_thread_percent"], client["memory_mib"]
        if type(p) is not int or not 1 <= p <= 100 or type(m) is not int or m < 64:
            raise Error("invalid_mps_pool", "client limits are integer percent and MiB", 400)
        backend.validate_workload(client["workload"], ordinary)
        percent += p
        memory += m * 1024**2
        ports += [row["host"] for row in client["workload"].get("ports", [])]
    gpu = next((row for row in lease["baseline"] if row["id"] == lease["resources"][0]), None)
    if not gpu or gpu["kind"] != "gpu" or "trusted_mps" not in gpu["modes"]:
        raise Error("unsupported_mode", "device does not advertise trusted MPS")
    if percent > 100 or memory + 512 * 1024**2 > gpu["memory_bytes"] or len(ports) != len(set(ports)):
        raise Error("mps_capacity_exceeded", "pool limits exceed GPU capacity, headroom or unique ports")


def volume_name(lease):
    return f"nodus-dc-{lease['generation']}-mps"


def _labels(lease):
    return {LABEL + ".lease": lease["id"], LABEL + ".generation": str(lease["generation"]),
            LABEL + ".resources": canonical(lease["resources"])}


def start_pool(backend, lease):
    import json
    import time
    workload = lease["workload"]
    validate_pool(backend, workload, lease)
    if backend._owned(lease):
        raise Error("existing_runtime", "pool already has a runtime")
    gpu = next((r for r in backend.inventory().resources if r.id == lease["resources"][0]), None)
    if gpu is None or not gpu.healthy or gpu.busy or "trusted_mps" not in gpu.modes:
        raise Error("resource_changed", "MPS GPU is no longer available")
    for image in {workload["controller_image"], *[c["workload"]["image"] for c in workload["clients"]]}:
        backend.command(["docker", "image", "inspect", image], timeout=15)
    name = volume_name(lease)
    # Do not attach a preexisting volume with a guessed name.
    existing = backend.command(["docker", "volume", "ls", "--format", "{{.Name}}"], timeout=15).splitlines()
    if name in existing:
        raise Error("existing_mps_volume", "pool volume already exists; recovery is required")
    args = ["docker", "volume", "create"]
    for k, v in _labels(lease).items():
        args += ["--label", k + "=" + v]
    backend.command([*args, name], timeout=15)
    info = json.loads(backend.command(["docker", "volume", "inspect", name], timeout=15))[0]
    if any((info.get("Labels") or {}).get(k) != v for k, v in _labels(lease).items()):
        raise Error("mps_volume_identity", "created volume identity does not match")
    common = ["--user", "0:0", "--mount", f"type=volume,src={name},dst=/mps",
              "--env", "CUDA_MPS_PIPE_DIRECTORY=/mps", "--env", "CUDA_MPS_LOG_DIRECTORY=/tmp/mps-log"]
    controller = backend._launch_container(lease, {"image": workload["controller_image"],
                      "entrypoint": "/usr/bin/nvidia-cuda-mps-control", "command": ["-f"]},
                      [gpu.device_uuid], suffix="-mps", extra=[*common, "--ipc", "shareable"])
    # The CUDA 13 control endpoint is a UNIX socket, not a FIFO. A stale
    # socket alone is insufficient: require a read-only daemon round trip.
    # Bound the client inside the container too; timing out docker exec alone
    # need not terminate its remote process. No server is expected yet, so an
    # empty successful get_server_list response is valid.
    ready = False
    for _ in range(50):
        try:
            backend.command(["docker", "exec", controller, "/bin/sh", "-c",
                             "test -S /mps/control && printf 'get_server_list\\n' | "
                             "timeout -s KILL 1 /usr/bin/nvidia-cuda-mps-control"], timeout=2)
            ready = True
            break
        except Error:
            time.sleep(0.1)
    if not ready:
        raise Error("mps_not_ready", "MPS control socket did not answer readiness query", 503)
    ids = []
    for i, client in enumerate(workload["clients"]):
        extra = [*common, "--ipc", "container:" + controller, "--pid", "container:" + controller,
                 "--env", f"CUDA_MPS_ACTIVE_THREAD_PERCENTAGE={client['active_thread_percent']}",
                 "--env", f"CUDA_MPS_PINNED_DEVICE_MEM_LIMIT=0={client['memory_mib']}M"]
        ids.append(backend._launch_container(lease, client["workload"], [gpu.device_uuid], suffix=f"-client-{i}", extra=extra))
    owned = backend._owned(lease)
    expected = {controller, *ids}
    if {c["Id"] for c in owned} != expected or any(not c["State"]["Running"] for c in owned):
        raise Error("mps_runtime_incomplete", "all pool members must be running", 503)
    return {"lease_id": lease["id"], "generation": lease["generation"], "controller_id": controller,
            "client_ids": ids, "volume": name, "trust_domain": workload["trust_domain"],
            "isolation": "trusted_cooperative_only", "hardware_qualified": False}


def remove_pool_volume(backend, lease):
    import json
    name = volume_name(lease)
    names = backend.command(["docker", "volume", "ls", "--format", "{{.Name}}"], timeout=15).splitlines()
    if name not in names:
        return
    rows = json.loads(backend.command(["docker", "volume", "inspect", name], timeout=15))
    if len(rows) != 1 or any((rows[0].get("Labels") or {}).get(k) != v for k, v in _labels(lease).items()):
        raise Error("mps_volume_identity", "refusing to delete a volume with different ownership")
    backend.command(["docker", "volume", "rm", name], timeout=15)
