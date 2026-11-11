"""Read-only local admission projection. A snapshot is never an allocation grant."""
from __future__ import annotations

import math

from .errors import Error
from .model import LOCAL_MODES, overlap


def project(inventory, leases, records, *, authority, now, last_wall_time):
    """Use the same stored resource tree and holding states as local admission.

    Historical parents matter: a quarantined, disappeared partition still holds
    its physical parent. Expiry alone never releases a lease. This function does
    not refresh inventory, contact the platform, reserve, or reconcile anything.
    """
    observed = inventory.get("observed_at") if inventory else None
    valid_time = lambda value: type(value) in (int, float) and math.isfinite(value)
    state = "fresh"
    if not valid_time(now) or not valid_time(last_wall_time) or now + 1 < last_wall_time:
        state = "clock_uncertain"
    elif not valid_time(observed):
        state = "missing"
    elif observed > now:
        state = "clock_uncertain"
    elif now - observed > 30:
        state = "stale"

    current = inventory.get("resources", []) if inventory else []
    parents = {row["id"]: row["parent"] for row in records}
    stored = {row["id"]: row for row in records}
    held = [lease for lease in leases if lease["state"] != "released"]
    # An unresolvable holding record cannot establish which devices are free.
    unresolved = any(resource not in parents for lease in held for resource in lease["resources"])
    output = []
    for resource in current:
        identity = resource["id"]
        row = stored.get(identity)
        blockers = []
        try:
            blockers = [lease["id"] for lease in held
                        if overlap({identity}, set(lease["resources"]), parents)]
        except Error:
            unresolved = True
        modes = sorted(set(resource["modes"]) & LOCAL_MODES)
        if state != "fresh":
            reason = state
        elif unresolved or row is None or not row["present"]:
            reason = "unknown"
        elif (not valid_time(row["observed_at"]) or row["observed_at"] > now
              or now - row["observed_at"] > 30):
            reason = "stale"
        elif authority != "standalone":
            reason = "scheduler_managed" if authority == "kubernetes" else "observe_only"
        elif blockers:
            reason = "held"
        elif not resource["healthy"]:
            reason = "unhealthy"
        elif resource["busy"]:
            reason = "busy"
        elif not modes:
            reason = "unsupported"
        else:
            reason = "available"
        output.append({"resource_id": identity, "kind": resource["kind"],
                       "available": reason == "available", "reason": reason,
                       "modes": modes if reason == "available" else [], "held_by": blockers})
    # If a later row exposed a corrupt hierarchy, no earlier positive survives.
    if unresolved:
        for row in output:
            row.update(available=False, modes=[], reason="unknown")
    return {"scope": "local_snapshot_only", "allocation_authority": authority,
            "state": state, "observed_at": observed,
            "evaluated_at": now if valid_time(now) else None,
            "fresh_for_seconds": max(0, 30 - (now - observed)) if state == "fresh" else 0,
            "reservation_required": True, "external_capacity_evaluated": False,
            "available_gpus": sum(row["available"] and bool(set(row["modes"]) & {"exclusive_gpu", "trusted_mps"})
                                  for row in output if row["kind"] == "gpu"),
            "available_partitions": sum(row["available"] and "hardware_partition" in row["modes"]
                                        for row in output if row["kind"] == "partition"),
            "resources": output}
