"""Portable resource and evidence records. Software sharing is not a security boundary."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .errors import Error

API_VERSION = "nodus.datacenter.v1"
TERMINAL = frozenset({"released"})
HOLDING = frozenset({"reserved", "starting", "active", "draining", "verifying", "quarantined"})
LOCAL_MODES = frozenset({"exclusive_host", "exclusive_gpu", "hardware_partition", "gpu_configuration", "trusted_mps"})
UUID = re.compile(r"(?:GPU|MIG)-[A-Za-z0-9_-]{4,160}\Z")
KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def key(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not KEY.fullmatch(value):
        raise Error("invalid_request", f"{field_name} must be a nonempty identifier of at most 128 characters", 400)
    return value


def finite_time(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise Error("invalid_request", f"{field_name} must be a finite timestamp", 400)
    return float(value)


@dataclass(frozen=True)
class Resource:
    id: str
    kind: str
    parent: str | None
    device_uuid: str | None = None
    name: str = ""
    memory_bytes: int = 0
    modes: tuple[str, ...] = ()
    healthy: bool = False
    busy: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def record(self):
        return asdict(self)


@dataclass(frozen=True)
class Snapshot:
    host_id: str
    observed_at: float
    resources: tuple[Resource, ...]
    driver_version: str = ""
    os_release: str = ""
    warnings: tuple[str, ...] = ()
    hardware_qualified: bool = False

    def record(self):
        out = asdict(self)
        out["revision"] = digest({"host_id": self.host_id, "resources": out["resources"],
                                  "driver_version": self.driver_version, "os_release": self.os_release})
        return out


@dataclass(frozen=True)
class CleanupProof:
    clean: bool
    observed_at: float
    lease_id: str
    generation: int
    resource_ids: tuple[str, ...]
    evidence: dict[str, Any]

    def record(self):
        return asdict(self)


def overlap(left: set[str], right: set[str], parents: dict[str, str | None]) -> bool:
    """Two selections overlap if either contains an ancestor of the other."""
    def ancestors(item):
        seen = set()
        while item is not None:
            if item in seen:
                raise Error("invalid_inventory", "resource hierarchy contains a cycle", 503)
            seen.add(item)
            item = parents.get(item)
        return seen
    return any(b in ancestors(a) or a in ancestors(b) for a in left for b in right)
