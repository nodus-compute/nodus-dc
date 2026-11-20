"""Closed test-profile accounting; this is not scratch or runtime enforcement."""
from __future__ import annotations

import copy
import json

from .errors import Error
from .model import digest
from .partitions import fields, integer, sha, budget

CONTRACT = "scoped-ephemeral-test.v1"
ACCOUNTING = "partition-aggregate-test.v1"
MEMBER = "nodus.ephemeral_claim"
MIB = 1024**2


def charge(resources):
    budget(resources)
    c, m, s = (resources[k] for k in ("cpu_millis", "memory_bytes", "scratch_bytes"))
    integer(c, 10, 64000); integer(m, 64*MIB, 1024**4); integer(s, 4096, 64*MIB)
    if m % 4096 or s % 4096:
        raise Error("invalid_request", "ephemeral memory limits must be page aligned", 400)
    stage = 2*s + 8*MIB
    host = s + stage + 192*MIB
    aggregate = {"cpu_millis":c+350, "memory_bytes":m+host+128*MIB, "scratch_bytes":s}
    budget(aggregate)
    return {"host_memory_bytes":host, "stage_bytes":stage, "owner_overhead_bytes":128*MIB,
            "host_cpu_millis":250, "owner_cpu_millis":100, "aggregate":aggregate}


def validate(value, resources):
    fields(value, "contract spec_sha256 features charge")
    if value["contract"] != CONTRACT:
        raise Error("invalid_request", "unsupported ephemeral profile", 400)
    sha(value["spec_sha256"])
    f = value["features"]
    fields(f, "continuity restore_manifest checkpoint_policy snapshot_inputs lazy_inputs outside_outputs input_count input_bytes output_count")
    if (f["continuity"] != "ephemeral" or any(f[k] is not False for k in (
            "restore_manifest", "checkpoint_policy", "snapshot_inputs", "lazy_inputs", "outside_outputs"))):
        raise Error("invalid_request", "ephemeral profile contains unsupported features", 400)
    integer(f["input_count"], 0, 16); integer(f["output_count"], 0, 16)
    integer(f["input_bytes"], f["input_count"], resources["scratch_bytes"])
    # input_bytes is the sum of positive declared max_bytes ceilings, not a scan.
    if bool(f["input_count"]) != bool(f["input_bytes"]):
        raise Error("invalid_request", "inputs require positive declared byte ceilings", 400)
    expected = charge(resources)
    fields(value["charge"], "host_memory_bytes stage_bytes owner_overhead_bytes host_cpu_millis owner_cpu_millis aggregate")
    for k in expected:
        if k == "aggregate": budget(value["charge"][k])
        else: integer(value["charge"][k])
    if value["charge"] != expected:
        raise Error("invalid_request", "ephemeral charge differs from the normalized profile", 400)
    return copy.deepcopy(value)


def metadata(request, proof):
    return {"accounting_version":ACCOUNTING, "lease":copy.deepcopy(request),
            "provider_proof_sha256":digest(proof)}


def split(row, proof, local=None):
    """Validate reserved authority provenance before exposing original provider data."""
    value = proof.pop(MEMBER)
    fields(value, "accounting_version lease provider_proof_sha256")
    from . import partition_origin as origin
    lease = origin.validate(value["lease"])
    if (value["accounting_version"] != ACCOUNTING or "ephemeral" not in lease
            or not origin.generation(lease) or value["provider_proof_sha256"] != digest(proof)
            or proof.get("accounting_version") != ACCOUNTING
            or any(row[k] != lease["ephemeral"]["charge"]["aggregate"][k] for k in lease["resources"])):
        raise Error("invalid_execution_binding", "aggregate reservation provenance differs", 409)
    if local is not None and (local["id"] != row["lease_id"] or not origin.matches_row(lease, local)):
        raise Error("invalid_execution_binding", "aggregate reservation owner differs", 409)
    if proof.get("contract") == origin.LOCAL_PENDING:
        from .partition_execution import pending_local_proof
        pending_local_proof(proof, lease)
    return value


def reservation_profile(reservation, local):
    from .partition_binding import provider_reservation
    provider_reservation(reservation, local)  # Never hide malformed reserved data.
    return json.loads(reservation["enforcement"]).get(MEMBER)


def require_unavailable(request):
    if "ephemeral" in request:
        raise Error("ephemeral_enforcement_unavailable", "host scratch enforcement is not installed", 503)
