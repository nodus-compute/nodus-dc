"""Exact Docker prerequisites for budgeted trusted local sibling workloads.

This does not qualify the separate untrusted partition executor. Scratch is
memory-backed and charged within the same hard memory limit; host outputs are
not admitted by this bounded execution shape.
"""
from .errors import Error


def docker_arguments(resources, workload):
    from .partitions import budget
    budget(resources)
    if workload.get("output_directory") or workload.get("ports"):
        raise Error("host_resources_unenforced", "budgeted siblings require memory-backed scratch and no published ports", 409)
    shm = workload.get("shm_bytes", 64*1024**2) if resources["scratch_bytes"] else 0
    if type(shm) is not int or not 0 <= shm <= resources["scratch_bytes"]:
        raise Error("host_resources_unenforced", "shared memory must fit the reserved scratch limit", 409)
    args = ["--cpu-period", "100000", "--cpu-quota", str(resources["cpu_millis"]*100),
            "--memory", str(resources["memory_bytes"]), "--memory-swap", str(resources["memory_bytes"]),
            "--pids-limit", "512", "--log-opt", "max-size=1m", "--log-opt", "max-file=1"]
    args += ["--shm-size", str(shm)] if shm else ["--ipc", "none"]
    remaining = resources["scratch_bytes"]-shm
    if remaining: args += ["--tmpfs", f"/tmp:rw,exec,nosuid,nodev,size={remaining}"]
    return args


def verify_container(container, resources, workload):
    """Require Docker's resolved limits before starting the exact created ID."""
    expected = docker_arguments(resources, workload)
    values = {expected[i]:expected[i+1] for i in range(0,len(expected),2)}
    config = container.get("HostConfig") or {}
    for field, option in (("CpuPeriod","--cpu-period"),("CpuQuota","--cpu-quota"),
                          ("Memory","--memory"),("MemorySwap","--memory-swap"),("PidsLimit","--pids-limit")):
        if type(config.get(field)) is not int or config[field] != int(values[option]):
            raise Error("host_resources_unenforced", "Docker did not retain the exact reserved host limits", 503)
    if config.get("ReadonlyRootfs") is not True:
        raise Error("host_resources_unenforced", "budgeted root filesystem must remain read-only", 503)
    if "--shm-size" in values:
        if config.get("ShmSize") != int(values["--shm-size"]) or config.get("IpcMode") not in {"", "private"}:
            raise Error("host_resources_unenforced", "shared memory limit or namespace changed", 503)
    elif config.get("IpcMode") != "none":
        raise Error("host_resources_unenforced", "zero scratch requires disabled shared memory", 503)
    tmpfs = config.get("Tmpfs") or {}
    wanted = {"/tmp":values["--tmpfs"].split(":",1)[1]} if "--tmpfs" in values else {}
    if set(tmpfs) != set(wanted) or any(set(tmpfs[p].split(",")) != set(wanted[p].split(",")) for p in wanted):
        raise Error("host_resources_unenforced", "memory-backed scratch mount differs from its reservation", 503)
