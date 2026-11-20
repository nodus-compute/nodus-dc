"""Closed internal projections shared by local and external scoped execution.

Wire entry points validate their own origin before reaching these readers.
No projection manufactures an external agreement, Attempt or platform lease.
"""
from __future__ import annotations

import hashlib
import json

from . import partition_local as local
from .errors import Error
from .model import digest
from .partitions import validate_lease as external_lease

LOCAL_BINDING = "partition-local-execution-binding.v1"
LOCAL_PENDING = "partition-trusted-local-pending.v1"


def is_local(lease):
    return isinstance(lease, dict) and lease.get("contract") == local.LEASE


def validate(lease):
    return local.validate_lease(lease) if is_local(lease) else external_lease(lease)


def partition(lease):
    return lease["partition"] if is_local(lease) else lease["offer"]["partition"]


def runtime(lease):
    return lease["runtime_sha256"] if is_local(lease) else lease["offer"]["runtime_sha256"]


def image(lease):
    return lease["workload"]["image"] if is_local(lease) else lease["workload"]["workload_image"]


def generation(lease):
    return lease["ref"]["generation"] if is_local(lease) else lease["generation"]


def authorization(lease):
    if is_local(lease):
        return {"protocol":"managed-local-v1", "lease_sha256":digest(lease)}
    return {"protocol":"partition-v2", "request_hash":digest({**lease,"generation":0})}


def matches_row(lease, row):
    return (row["owner"] == ("local" if is_local(lease) else "external")
            and row["generation"] == generation(lease)
            and row["authorization"] == authorization(lease)
            and (not is_local(lease) or (row["id"] == lease["ref"]["lease_id"]
                 and row["workload"] == lease["workload"] and row["resources"] == [partition(lease)["resource_id"]])))


def binding_digest(binding):
    if binding.get("contract") != LOCAL_BINDING:
        return digest(binding)
    # Go's fixed local encoder sorts keys, keeps UTF-8, disables HTML escaping,
    # and escapes the two JavaScript line separators. External bytes stay exact.
    raw = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    raw = raw.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def reference(ref, lease):
    if is_local(lease):
        value = local.reference(ref)
        if value != lease["ref"]:
            raise Error("invalid_execution_binding", "local reference differs from its immutable lease", 409)
        return value
    from .partition_binding import reference as external_reference
    return external_reference(ref, lease["platform_epoch"])


def runtime_reference(ref):
    """The internal runtime record has a name/epoch key; it is not an external wire Ref."""
    if isinstance(ref, dict) and set(ref) == {"authority_incarnation", "lease_id", "generation"}:
        value = local.runtime_identity(ref)
        return {"attempt_id":value["name"], "epoch":value["generation"]}
    from .partition_binding import reference as external_reference
    return external_reference(ref, ref.get("epoch") if isinstance(ref, dict) else None)
