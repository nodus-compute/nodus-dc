"""Closed managed-local identity; no route or execution capability is installed."""
from __future__ import annotations

import base64
import copy
import hashlib
import re
import struct
import uuid

from . import ephemeral
from .errors import Error
from .partitions import fields, guid, integer, sha, validate_partition

LEASE = "partition-local-lease.v1"
DISPATCH = "partition-local-dispatch.v1"
REF_DOMAIN = b"nodus.local-execution.v1\0"
WORK_DOMAIN = b"nodus.local-workload.v1\0"


def reference(value):
    fields(value, "authority_incarnation lease_id generation")
    guid(value["authority_incarnation"]); guid(value["lease_id"])
    integer(value["generation"], 1)
    return copy.deepcopy(value)


def runtime_identity(value):
    """Return a disjoint runtime name and epoch, never a platform Attempt."""
    ref = reference(value)
    raw = REF_DOMAIN + uuid.UUID(ref["authority_incarnation"]).bytes + uuid.UUID(ref["lease_id"]).bytes
    name = base64.b32encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=").lower()
    return {"name":"l_" + name, "generation":ref["generation"]}


def workload(value, resources):
    fields(value, "image command args workdir")
    image = value["image"]
    if (not isinstance(image, str) or len(image) > 512
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", image)
            or not isinstance(value["workdir"], str)
            or value["workdir"] not in {"/", "/nodus/state", "/nodus/outputs", "/tmp"}):
        raise Error("invalid_local_workload", "managed local work requires a pinned image and owned cwd", 400)
    total = 0
    for name in ("command", "args"):
        values = value[name]
        if not isinstance(values, list) or len(values) > 64 or (name == "command" and not values):
            raise Error("invalid_local_workload", "managed local argv exceeds its fixed bounds", 400)
        for item in values:
            if not isinstance(item, str) or "\0" in item:
                raise Error("invalid_local_workload", "managed local arguments must be strings without NUL", 400)
            try:
                size = len(item.encode("utf-8"))
            except UnicodeError:
                raise Error("invalid_local_workload", "managed local arguments must be valid UTF-8", 400) from None
            if size > 4096:
                raise Error("invalid_local_workload", "managed local argument exceeds its fixed bound", 400)
            total += size
    if not value["command"][0] or total > 32768:
        raise Error("invalid_local_workload", "managed local argv requires an executable within its byte bound", 400)
    charge = ephemeral.charge(resources)
    # Fixed-length framing avoids language-specific JSON escaping and array ambiguity.
    raw = bytearray(WORK_DOMAIN)
    def text(item):
        data = item.encode("utf-8")
        raw.extend(struct.pack(">I", len(data))); raw.extend(data)
    text(image)
    for name in ("command", "args"):
        raw.extend(struct.pack(">I", len(value[name])))
        for item in value[name]: text(item)
    text(value["workdir"])
    for name in ("cpu_millis", "memory_bytes", "scratch_bytes"):
        raw.extend(struct.pack(">Q", resources[name]))
    return {"contract":ephemeral.CONTRACT, "spec_sha256":hashlib.sha256(raw).hexdigest(),
            "features":{"continuity":"ephemeral", "restore_manifest":False, "checkpoint_policy":False,
                        "snapshot_inputs":False, "lazy_inputs":False, "outside_outputs":False,
                        "input_count":0, "input_bytes":0, "output_count":0}, "charge":charge}


def validate_lease(value):
    fields(value, "contract ref partition policy_revision workload resources ephemeral runtime_sha256 expires_at_unix_millis")
    ref = reference(value["ref"])
    part = validate_partition(value["partition"])
    integer(value["policy_revision"], 1); integer(value["expires_at_unix_millis"], 1)
    sha(value["runtime_sha256"])
    profile = workload(value["workload"], value["resources"])
    ephemeral.validate(value["ephemeral"], value["resources"])
    if (value["contract"] != LEASE or ref["authority_incarnation"] != part["authority_incarnation"]
            or profile != value["ephemeral"]):
        raise Error("invalid_local_lease", "managed local identity or workload differs", 400)
    return copy.deepcopy(value)


def dispatch(value):
    """A start request selects the immutable held row; it carries no new workload or permission."""
    fields(value, "contract ref request_key")
    reference(value["ref"])
    if (value["contract"] != DISPATCH or not isinstance(value["request_key"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value["request_key"])):
        raise Error("invalid_local_dispatch", "managed local dispatch identity is invalid", 400)
    return copy.deepcopy(value)
