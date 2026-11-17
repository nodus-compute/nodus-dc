"""Strict same-row v2 provenance and one-return creator capabilities."""
from __future__ import annotations

import copy
import hashlib
import hmac
import posixpath
import re
import secrets

from .errors import Error
from .model import digest
from .partitions import fields, guid, integer, sha, budget
from . import ephemeral

CONTRACT = "partition-execution-binding.v2"
PROVIDER = "partition-trusted-host.v1"
STATE_FIELDS = "binding binding_sha256 phase phase_revision creator issue_sha256 start_sha256 host_scope_sha256"
CREATOR_FIELDS = "boot_id pid start_ticks uid gid pid_namespace user_namespace cgroup_namespace executable_sha256"
IMAGE_FIELDS = "version reference manifest_sha256 config_sha256 rootfs_chain_sha256 os architecture user workdir namespace snapshotter spec_sha256"
BINDING_FIELDS = "contract lease local_lease_id ref requested_resources device_observation runtime_identity reservation_proof_sha256 accounting_version aggregate_resources image host_budget"


def _denied():
    return Error("partition_execution_denied", "the exact current creation or owner evidence is unavailable", 403)


def qualified_image(value, lease):
    fields(value, IMAGE_FIELDS)
    if type(value["version"]) is not int or value["version"] != 1: raise _denied()
    for name in ("manifest_sha256", "config_sha256", "rootfs_chain_sha256", "spec_sha256"):
        sha(value[name])
    workdir = value["workdir"]
    if ("ephemeral" not in lease or value["reference"] != lease["workload"]["workload_image"]
            or not value["reference"].endswith("@sha256:" + value["manifest_sha256"])
            or value["spec_sha256"] != lease["ephemeral"]["spec_sha256"]
            or value["os"] != "linux" or value["architecture"] != "amd64" or value["user"] not in {"", "0:0"}
            or not isinstance(workdir, str) or len(workdir) > 256
            or (workdir not in {"/", "/nodus/state", "/nodus/outputs", "/tmp"}
                and not re.fullmatch(r"/nodus/inputs/[A-Za-z][A-Za-z0-9_]{0,63}", workdir))):
        raise _denied()
    for name in ("namespace", "snapshotter"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", value[name]):
            raise _denied()
    return copy.deepcopy(value)


def host_budget(value, lease):
    fields(value, "version accounting_version boot_id authority_incarnation cgroup_namespace user_namespace pid_namespace root shared capacity max_claims")
    if type(value["version"]) is not int or value["version"] != 1 or value["accounting_version"] != ephemeral.ACCOUNTING:
        raise _denied()
    guid(value["boot_id"]); guid(value["authority_incarnation"])
    for name in ("pid", "user", "cgroup"):
        if not isinstance(value[name + "_namespace"], str) or not re.fullmatch(name + r":\[[1-9][0-9]*\]", value[name + "_namespace"]):
            raise _denied()
    integer(value["max_claims"], 1, 64)
    for item in (value["root"], value["shared"]):
        fields(item, "path device inode cpu_millis memory_bytes pids")
        path = item["path"]
        if (not isinstance(path, str) or not path.startswith("/sys/fs/cgroup/") or len(path) > 4096
                or "\x00" in path or posixpath.normpath(path) != path):
            raise _denied()
        for name in ("device", "inode", "cpu_millis", "memory_bytes", "pids"):
            integer(item[name], 1, 2**63 - 1)
        if item["memory_bytes"] % 4096 or item["cpu_millis"] > (2**63-1)//100: raise _denied()
    root, shared = value["root"], value["shared"]
    capacity = budget(value["capacity"])
    if (not shared["path"].startswith(root["path"] + "/")
            or shared["device"] != root["device"] or shared["inode"] == root["inode"]
            or capacity["cpu_millis"] != root["cpu_millis"] - shared["cpu_millis"]
            or capacity["memory_bytes"] != root["memory_bytes"] - shared["memory_bytes"]
            or root["pids"] < shared["pids"] + 576 * value["max_claims"]
            or value["boot_id"] != lease["offer"]["partition"]["boot_id"]
            or value["authority_incarnation"] != lease["offer"]["partition"]["authority_incarnation"]):
        raise _denied()
    return copy.deepcopy(value)


def creator(value):
    fields(value, CREATOR_FIELDS)
    guid(value["boot_id"]); sha(value["executable_sha256"])
    integer(value["pid"], 1, 2**31 - 1); integer(value["start_ticks"], 1, 2**63 - 1)
    integer(value["uid"], 0, 2**32 - 1); integer(value["gid"], 0, 2**32 - 1)
    for name in ("pid", "user", "cgroup"):
        if not isinstance(value[name + "_namespace"], str) or not re.fullmatch(name + r":\[[1-9][0-9]*\]", value[name + "_namespace"]):
            raise _denied()
    return copy.deepcopy(value)


def validate_state(state, proof):
    fields(state, STATE_FIELDS)
    binding = state["binding"]
    fields(binding, BINDING_FIELDS)
    lease = binding["lease"]
    if (binding["contract"] != CONTRACT or "ephemeral" not in lease
            or binding["accounting_version"] != ephemeral.ACCOUNTING
            or binding["aggregate_resources"] != lease["ephemeral"]["charge"]["aggregate"]
            or proof.get("contract") != PROVIDER or proof.get("enforcement_ready") is not True
            or proof.get("qualified_image") != binding["image"] or proof.get("host_budget") != binding["host_budget"]):
        raise _denied()
    qualified_image(binding["image"], lease); host_budget(binding["host_budget"], lease)
    phase, revision = state["phase"], state["phase_revision"]
    integer(revision, 1, 5)
    live = {"committed":1, "creation-issued":2, "creation-consumed":3, "host-published":4}
    if phase == "retired":
        if revision < 2: raise _denied()
        predecessor = revision - 1
    elif live.get(phase) == revision:
        predecessor = revision
    else: raise _denied()
    if predecessor == 1:
        if state["creator"] is not None: raise _denied()
    else:
        creator(state["creator"])
        if any(state["creator"][key] != binding["host_budget"][key] for key in (
                "boot_id", "pid_namespace", "user_namespace", "cgroup_namespace")): raise _denied()
    for key, minimum in (("issue_sha256", 2), ("start_sha256", 3), ("host_scope_sha256", 4)):
        if predecessor >= minimum: sha(state[key])
        elif state[key] != "": raise _denied()
    if state["start_sha256"] and state["start_sha256"] == state["issue_sha256"]:
        raise _denied()


def capability_hash(token):
    sha(token)
    return hashlib.sha256(bytes.fromhex(token)).hexdigest()


def authorize_creator(state, peer, token, kind):
    if peer is None or state is None: raise _denied()
    expected = {"consume":("creation-issued", "issue_sha256"),
                "create":("creation-consumed", "start_sha256"),
                "publish":("creation-consumed", "start_sha256")}[kind]
    if (state["phase"] != expected[0]
            or not hmac.compare_digest(capability_hash(token), state[expected[1]])):
        raise _denied()
    return peer.verify(state["creator"])


def issue_token(excluded=""):
    token = secrets.token_hex(32)
    if excluded and hmac.compare_digest(capability_hash(token), excluded):
        raise _denied()
    return token


def qualified_proof(proof, lease):
    if (not isinstance(proof, dict) or proof.get("contract") != PROVIDER or proof.get("accounting_version") != ephemeral.ACCOUNTING
            or proof.get("enforcement_ready") is not True):
        raise _denied()
    qualified_image(proof.get("qualified_image"), lease)
    host_budget(proof.get("host_budget"), lease)
    return proof


def permission(state, purpose, peer=None, token=None, host_scope_sha256=None):
    """Build verified hook context; no boolean supplied by the requester authorizes creation."""
    who = None
    if purpose in {"consume", "create", "publish"}:
        who = authorize_creator(state, peer, token, purpose)
    elif purpose == "issue":
        if state is None or state["phase"] != "committed" or peer is None: raise _denied()
        who = peer.verify()
    elif purpose == "check":
        if state is not None and state["phase"] not in {"committed", "host-published"}: raise _denied()
    elif purpose == "bind":
        if state is not None and state["phase"] == "retired": raise _denied()
    else: raise _denied()
    if purpose == "publish": sha(host_scope_sha256)
    elif host_scope_sha256 is not None: raise _denied()
    return {"binding_state":copy.deepcopy(state), "purpose":purpose, "creator":who,
            "host_scope_sha256":host_scope_sha256}


def resolve(authority, *, lease, ref, binding_sha256=None, expected_phase_revision=None,
            operation=None, token=None, host_scope_sha256=None, peer=None):
    from .partitions import validate_lease
    from .partition_binding import reference, runtime_identity, split_reservation, save
    from .model import canonical
    from .store import Store
    import json
    request = validate_lease(lease)
    if "ephemeral" not in request or not request["generation"]: raise _denied()
    ref = reference(ref, request["platform_epoch"])
    if operation is not None:
        if operation not in {"issue", "consume", "publish"}: raise _denied()
        sha(binding_sha256); integer(expected_phase_revision, 1, 3)
        if (expected_phase_revision != {"issue":1,"consume":2,"publish":3}[operation]
                or (operation == "issue" and token is not None)
                or (operation != "publish" and host_scope_sha256 is not None)):
            raise _denied()
    elif any(value is not None for value in (binding_sha256, expected_phase_revision, token, host_scope_sha256, peer)):
        raise _denied()
    authority._active()
    service = authority.service
    with service.authority():
        if operation is None:
            # Cleanup recovery reads terminal identity without reauthorizing an expired or revoked job.
            with service.store.transaction(service.clock()) as db:
                authority._durable(db)
                prior = authority._lookup(db,request)
                if prior and prior["retired"]:
                    if not prior["lease_id"]: raise _denied()
                    local = Store.lease(db,prior["lease_id"])
                    row = db.execute("SELECT * FROM host_reservations WHERE lease_id=?",(local["id"],)).fetchone()
                    provider,state = split_reservation(row,local)
                    if (state is None or state["phase"]!="retired" or state["binding"]["lease"]!=request
                            or state["binding"]["ref"]!=ref): raise _denied()
                    qualified_proof(json.loads(provider["enforcement"]),request)
                    return copy.deepcopy(state)
        service._inventory()
        with authority._admission_transaction() as db:
            authority._durable(db)
            claim = authority._lookup(db, request)
            if claim and claim["lease_id"]:
                original = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (claim["lease_id"],)).fetchone()
                projected, _ = split_reservation(original, Store.lease(db, claim["lease_id"]))
                if json.loads(projected["enforcement"]).get("contract") != PROVIDER:
                    ephemeral.require_unavailable(request)
            checked = authority._checked(db, request, claim, purpose=operation or "bind", peer=peer,
                                         token=token, host_scope_sha256=host_scope_sha256)
            if checked is None: raise _denied()
            local, device, qualification, reservation = checked
            provider, state = split_reservation(reservation, local)
            proof = qualified_proof(json.loads(provider["enforcement"]), request)
            binding = {"contract":CONTRACT,"lease":request,"local_lease_id":local["id"],"ref":ref,
                "requested_resources":request["resources"],"aggregate_resources":request["ephemeral"]["charge"]["aggregate"],
                "accounting_version":ephemeral.ACCOUNTING,"image":proof["qualified_image"],"host_budget":proof["host_budget"],
                "device_observation":device,"runtime_identity":runtime_identity(qualification.get("execution_identity"), request["offer"]["runtime_sha256"]),
                "reservation_proof_sha256":digest(proof)}
            if state is None:
                if operation is not None: raise _denied()
                # A Ref is a runtime tombstone key; another lease may never reuse it, even after release.
                used = db.execute("SELECT 1 FROM host_reservations WHERE lease_id!=? AND "
                    "json_extract(enforcement,?)=? AND json_extract(enforcement,?)=? LIMIT 1",
                    (local["id"], '$."nodus.execution_binding".binding.ref.attempt_id', ref["attempt_id"],
                     '$."nodus.execution_binding".binding.ref.epoch', ref["epoch"])).fetchone()
                if used: raise _denied()
                state = {"binding":binding,"binding_sha256":digest(binding),"phase":"committed","phase_revision":1,
                         "creator":None,"issue_sha256":"","start_sha256":"","host_scope_sha256":""}
            elif state["binding"] != binding or state["phase"] == "retired":
                raise _denied()
            returned = ""
            if operation is not None:
                if binding_sha256 != state["binding_sha256"] or expected_phase_revision != state["phase_revision"]:
                    raise _denied()
                if operation == "issue":
                    who = peer.verify()
                    creator(who)
                    if any(who[key] != binding["host_budget"][key] for key in (
                            "boot_id", "pid_namespace", "user_namespace", "cgroup_namespace")): raise _denied()
                    returned = issue_token()
                    state = {**state,"phase":"creation-issued","phase_revision":2,"creator":who,
                             "issue_sha256":capability_hash(returned)}
                elif operation == "consume":
                    authorize_creator(state, peer, token, "consume")
                    returned = issue_token(state["issue_sha256"])
                    state = {**state,"phase":"creation-consumed","phase_revision":3,"start_sha256":capability_hash(returned)}
                else:
                    authorize_creator(state, peer, token, "publish")
                    # _checked's provider independently validates the supplied identity against the live exact scope.
                    sha(host_scope_sha256)
                    state = {**state,"phase":"host-published","phase_revision":4,"host_scope_sha256":host_scope_sha256}
            validate_state(state, proof)
            response = {"state":state,"creation_token":returned} if operation is not None else state
            if len(canonical(response).encode()) > 65536: raise _denied()
            policy = authority._policy(db, request=request)
            if policy["agreement"] != request["offer"]["agreement"] or local["expires_at"] <= service.clock():
                raise _denied()
            if peer is not None: peer.verify(state["creator"])
            save(db, reservation, state)
            db.execute("UPDATE meta SET value='8' WHERE key='schema_version' AND CAST(value AS INTEGER)<8")
            # Store commits its independent write-ahead floor and the same row before Python returns the one-time token.
            return copy.deepcopy(response)
