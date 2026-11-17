"""Private immutable execution identity; no runnable limit plan or runtime owner."""
from __future__ import annotations

import copy
import json
import posixpath
import re

from .errors import Error
from .model import canonical, digest
from .partitions import fields, guid, integer, sha, validate_lease
from .store import Store

MEMBER = "nodus.execution_binding"
CONTRACT = "partition-execution-binding.v1"
IDENTITY_FIELDS = ("manifest_sha256 qualification_sha256 runsc_sha256 sentry_sha256 "
                   "scoped_shim_sha256 containerd_shim_sha256 cdi_sha256 cdi_path "
                   "libraries_sha256 hooks_sha256")


def provider_proof(value):
    if not isinstance(value, dict) or any(not isinstance(key, str) or key.startswith("nodus.") for key in value):
        raise Error("invalid_execution_binding", "provider proof cannot use the authority namespace", 409)
    return value


def runtime_identity(value, manifest):
    fields(value, IDENTITY_FIELDS)
    for key, item in value.items():
        if key != "cdi_path": sha(item)
    path = value["cdi_path"]
    if (not isinstance(path, str) or not path.isascii() or len(path) > 4096
            or not path.startswith("/") or path == "/" or "\x00" in path
            or posixpath.normpath(path) != path or "//" in path
            or value["manifest_sha256"] != manifest):
        raise Error("invalid_execution_binding", "runtime identity is not an exact immutable plan", 409)
    return copy.deepcopy(value)


def reference(value, epoch):
    fields(value, "attempt_id epoch")
    if not isinstance(value["attempt_id"], str) or not re.fullmatch(r"att_[0-7][0-9a-hjkmnp-tv-z]{25}", value["attempt_id"]):
        raise Error("invalid_execution_binding", "runtime attempt must be a canonical platform Attempt ID", 409)
    integer(value["epoch"], 1)
    if value["epoch"] != epoch:
        raise Error("invalid_execution_binding", "runtime epoch differs from the held lease", 409)
    return copy.deepcopy(value)


def split_reservation(reservation, local=None):
    """Validate authority data before projecting the unchanged provider proof."""
    row = dict(reservation)
    try:
        proof = json.loads(row["enforcement"])
        if not isinstance(proof, dict): raise ValueError()
        present = MEMBER in proof
        state = proof.pop(MEMBER, None)
        from . import ephemeral
        if ephemeral.MEMBER in proof:
            if present: raise ValueError()
            ephemeral.split(row, proof, local)
        elif proof.get("accounting_version") == ephemeral.ACCOUNTING:
            raise ValueError()  # Aggregate provider data is never a legacy reservation.
        provider_proof(proof)
        if present:
            fields(state, "binding binding_sha256 phase phase_revision")
            binding = state["binding"]
            fields(binding, "contract lease local_lease_id ref requested_resources device_observation runtime_identity reservation_proof_sha256")
            lease = validate_lease(binding["lease"])
            if not lease["generation"] or binding["contract"] != CONTRACT: raise ValueError()
            guid(binding["local_lease_id"])
            if local is not None and (local["id"] != binding["local_lease_id"]
                    or local["generation"] != lease["generation"]
                    or local["authorization"] != {"protocol":"partition-v2", "request_hash":digest({**lease,"generation":0})}):
                raise ValueError()
            reference(binding["ref"], lease["platform_epoch"])
            runtime_identity(binding["runtime_identity"], lease["offer"]["runtime_sha256"])
            device = binding["device_observation"]
            if (binding["local_lease_id"] != row["lease_id"]
                    or binding["requested_resources"] != lease["resources"]
                    or any(row[key] != lease["resources"][key] for key in lease["resources"])
                    or binding["reservation_proof_sha256"] != digest(proof)
                    or state["binding_sha256"] != digest(binding)
                    or digest({"device":device,"runtime_sha256":lease["offer"]["runtime_sha256"]}) != lease["offer"]["partition"]["binding_sha256"]
                    or state["phase"] not in {"committed", "materialization-begun", "retired"}
                    or type(state["phase_revision"]) is not int
                    or (state["phase"], state["phase_revision"]) not in {
                        ("committed",1), ("materialization-begun",2), ("retired",2), ("retired",3)}):
                raise ValueError()
        row["enforcement"] = canonical(proof)
        return row, state
    except (ValueError, TypeError, KeyError, Error):
        raise Error("invalid_execution_binding", "retained execution binding is unreadable or inconsistent", 409) from None


def provider_reservation(reservation, local):
    return split_reservation(reservation, local)[0]


def save(db, reservation, state):
    proof = json.loads(split_reservation(reservation)[0]["enforcement"])
    db.execute("UPDATE host_reservations SET enforcement=? WHERE lease_id=?",
               (canonical({**proof, MEMBER:state}), reservation["lease_id"]))


def retire(db, local_id):
    row = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (local_id,)).fetchone()
    if row is None: return
    _, state = split_reservation(row, Store.lease(db, local_id))
    if state is not None and state["phase"] != "retired":
        save(db, row, {**state,"phase":"retired","phase_revision":state["phase_revision"]+1})


def resolve(authority, *, lease, ref, binding_sha256=None, expected_phase_revision=None):
    request = validate_lease(lease)
    from .ephemeral import require_unavailable
    require_unavailable(request)
    if not request["generation"]:
        raise Error("stale_generation", "execution binding requires a held generation", 409)
    ref = reference(ref, request["platform_epoch"])
    begin = binding_sha256 is not None or expected_phase_revision is not None
    if begin:
        sha(binding_sha256); integer(expected_phase_revision, 1)
    authority._active()
    service = authority.service
    with service.authority():
        service._inventory()
        with authority._admission_transaction() as db:
            authority._durable(db)
            claim = authority._lookup(db, request)
            checked = authority._checked(db, request, claim)
            if checked is None:
                raise Error("partition_execution_denied", "current held permission is required", 403)
            local, device, qualification, reservation = checked
            provider, state = split_reservation(reservation, local)
            binding = {"contract":CONTRACT,"lease":request,"local_lease_id":local["id"],"ref":ref,
                       "requested_resources":request["resources"],"device_observation":device,
                       "runtime_identity":runtime_identity(qualification.get("execution_identity"), request["offer"]["runtime_sha256"]),
                       "reservation_proof_sha256":digest(json.loads(provider["enforcement"]))}
            if state is None:
                if begin:
                    raise Error("execution_binding_required", "commit an immutable binding before beginning materialization", 409)
                state = {"binding":binding,"binding_sha256":digest(binding),"phase":"committed","phase_revision":1}
            elif state["binding"] != binding or state["phase"] == "retired":
                raise Error("execution_binding_conflict", "the retained owner or immutable plan differs", 409)
            if begin:
                if binding_sha256 != state["binding_sha256"] or expected_phase_revision != 1:
                    raise Error("stale_execution_binding", "materialization CAS differs from its committed identity", 409)
                if state["phase"] == "committed":
                    state = {**state,"phase":"materialization-begun","phase_revision":2}
                elif state["phase"] != "materialization-begun":
                    raise Error("stale_execution_binding", "materialization cannot revive a retired owner", 409)
            # The complete response must fit before either the binding or reader floor commits.
            if len(json.dumps(state, sort_keys=True, allow_nan=False).encode()) > 65536:
                raise Error("execution_binding_too_large", "complete execution binding exceeds its wire limit", 409)
            policy = authority._policy(db, request=request)
            if policy["agreement"] != request["offer"]["agreement"] or local["expires_at"] <= service.clock():
                raise Error("partition_execution_denied", "permission expired during binding", 403)
            save(db, reservation, state)
            db.execute("UPDATE meta SET value='6' WHERE key='schema_version' AND CAST(value AS INTEGER)<6")
            return copy.deepcopy(state)
