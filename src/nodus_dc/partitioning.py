"""Device-scoped MIG changes under an exclusive GPU configuration lease."""
import re
from collections import Counter

from .errors import Error

PROFILE = re.compile(r"[1-9][0-9]*g\.[1-9][0-9]*gb(?:\+me)?\Z")


def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {"enabled", "profiles"} or type(plan["enabled"]) is not bool:
        raise Error("invalid_mig_plan", "MIG plan requires enabled boolean and profiles list", 400)
    profiles = plan["profiles"]
    if (not isinstance(profiles, list) or len(profiles) > 32
            or any(not isinstance(p, str) or not PROFILE.fullmatch(p) for p in profiles)
            or (not plan["enabled"] and profiles)):
        raise Error("invalid_mig_plan", "use explicit MIG profile names; disabled mode has no profiles", 400)


def configure_mig(backend, lease, plan):
    validate_plan(plan)
    if lease["mode"] != "gpu_configuration" or len(lease["resources"]) != 1:
        raise Error("configuration_lease_required", "MIG changes require one exclusively held physical GPU")
    gpu_id = lease["resources"][0]
    before = backend.inventory()
    gpu = next((r for r in before.resources if r.id == gpu_id), None)
    if gpu is None or not gpu.healthy or gpu.busy or "gpu_configuration" not in gpu.modes:
        raise Error("resource_changed", "GPU must be healthy, empty and support MIG configuration")
    children = [r for r in before.resources if r.parent == gpu_id]
    desired = Counter(plan["profiles"])
    current = Counter(r.details["profile"] for r in children)
    enabled = gpu.details["mig_mode"] == "Enabled"
    if enabled == plan["enabled"] and desired == current:
        return before
    if children:
        backend.command(["nvidia-smi", "mig", "-i", gpu_id, "-dci"], timeout=30)
        backend.command(["nvidia-smi", "mig", "-i", gpu_id, "-dgi"], timeout=30)
    if enabled != plan["enabled"]:
        backend.command(["nvidia-smi", "-i", gpu_id, "-mig", "1" if plan["enabled"] else "0"], timeout=60)
    if desired:
        backend.command(["nvidia-smi", "mig", "-i", gpu_id, "-cgi", ",".join(plan["profiles"]), "-C"], timeout=60)
    after = backend.inventory()
    actual = next((r for r in after.resources if r.id == gpu_id), None)
    actual_profiles = Counter(r.details["profile"] for r in after.resources if r.parent == gpu_id)
    if (actual is None or not actual.healthy or actual.busy
            or (actual.details["mig_mode"] == "Enabled") != plan["enabled"] or actual_profiles != desired):
        raise Error("mig_configuration_unverified", "driver did not confirm the exact MIG plan; GPU stays held", 503)
    return after
