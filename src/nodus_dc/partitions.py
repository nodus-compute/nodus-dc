"""Durable v2 partition claims. Production offers require separately qualified enforcement.

The default has no executor or partition-terms provider. Local hardware evidence,
whole-host consent and the experimental runtime cannot enable this protocol.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import json
import math
import re
import uuid

from .errors import Error
from .model import Snapshot, canonical, digest, overlap
from .store import Store
from . import mig_binding

MAX = 2**63 - 1


class _ContinuityFailure(Exception):
    """Escape request rollback before committing configuration invalidation."""


class _PolicyExpiry(Error):
    """Persist session closure even if the surrounding admission rolls back."""
    def __init__(self, commit):
        super().__init__("partition_policy_expired", "expired partition stream requires a new authenticated handshake", 403)
        self.commit = commit


def fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise Error("invalid_request", "v2 requires every declared field and rejects unknown fields", 400)


def integer(value, minimum=0, maximum=MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Error("invalid_request", "v2 integer is outside its supported range", 400)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
        raise Error("invalid_request", "v2 identifier is invalid", 400)


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Error("invalid_request", "v2 digest is invalid", 400)


def guid(value):
    try:
        parsed = uuid.UUID(value)
        if not parsed.int or str(parsed) != value: raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Error("invalid_request", "v2 UUID must be canonical and nonzero", 400) from None


def budget(value):
    fields(value, "cpu_millis memory_bytes scratch_bytes")
    integer(value["cpu_millis"], 1); integer(value["memory_bytes"], 1)
    integer(value["scratch_bytes"], 0, value["memory_bytes"])
    return value


def validate_lease(value):
    profile = isinstance(value, dict) and "ephemeral" in value
    fields(value, "platform_lease_id platform_epoch generation offer workload resources expires_at_unix_millis" + (" ephemeral" if profile else ""))
    identifier(value["platform_lease_id"]); integer(value["platform_epoch"], 1); integer(value["generation"])
    offer = value["offer"]
    fields(offer, "partition policy_revision agreement accelerator profile gpu_memory_bytes driver_version runtime_sha256 capacity available_until_unix_millis")
    part = offer["partition"]
    fields(part, "resource_id authority_incarnation configuration_generation boot_id parent_uuid mig_uuid gpu_instance compute_instance binding_sha256")
    identifier(part["resource_id"]); guid(part["authority_incarnation"]); guid(part["boot_id"])
    integer(part["configuration_generation"], 1)
    for name, prefix in (("parent_uuid", "GPU-"), ("mig_uuid", "MIG-")):
        if not isinstance(part[name], str) or not part[name].startswith(prefix):
            raise Error("invalid_request", "v2 device prefix is invalid", 400)
        guid(part[name][len(prefix):])
    integer(part["gpu_instance"], 0, 31); integer(part["compute_instance"], 0, 31); sha(part["binding_sha256"])
    agreement = offer["agreement"]
    fields(agreement, "node_id consent_id generation terms_sha256")
    identifier(agreement["node_id"]); identifier(agreement["consent_id"])
    integer(agreement["generation"], 1); sha(agreement["terms_sha256"])
    integer(offer["policy_revision"], 1); integer(offer["gpu_memory_bytes"], 1)
    for name in ("accelerator", "profile", "driver_version"): identifier(offer[name])
    sha(offer["runtime_sha256"]); budget(offer["capacity"]); budget(value["resources"])
    if profile:
        from .ephemeral import validate
        validate(value["ephemeral"], value["resources"])
    if any(value["resources"][k] > offer["capacity"][k] for k in value["resources"]):
        raise Error("invalid_request", "reservation exceeds frozen offer capacity", 400)
    integer(offer["available_until_unix_millis"], 1)
    integer(value["expires_at_unix_millis"], 1, offer["available_until_unix_millis"])
    fields(value["workload"], "workload_image workload_kind")
    image = value["workload"]["workload_image"]
    if (value["workload"]["workload_kind"] != "Job" or not isinstance(image, str) or len(image) > 512
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", image)):
        raise Error("invalid_request", "v2 supports digest-pinned Jobs only", 400)
    return copy.deepcopy(value)


class PartitionAuthority:
    def __init__(self, service):
        self.service = service
        self.executor = None
        self.policy_provider = None
        self.devices = None

    def ensure_durable(self):
        if self.service.store.fence is None:
            raise Error("authority_fence_unavailable", "v2 ownership requires an independent authority registry", 503)
        # Initialization has no fallible request work after its external write.
        with self.service.store.transaction(self.service.clock()) as db:
            self.service.store.fence.activate(db)

    def _durable(self, db):
        if self.service.store.fence is None:
            raise Error("authority_fence_unavailable", "v2 ownership requires an independent authority registry", 503)
        value = self.service.store.fence.verify(db)
        if value is None: raise Error("authority_continuity_lost", "authority incarnation has not been initialized", 503)
        return value

    def _qualification(self, binding):
        try:
            value = self.executor.qualification(binding)
        except Exception as exc:
            raise _ContinuityFailure() from exc
        if not isinstance(value, dict) or value.get("continuous_configuration_authority") is not True:
            raise _ContinuityFailure()
        return value

    @contextmanager
    def _admission_transaction(self):
        try:
            with self.service.store.transaction(self.service.clock()) as db:
                yield db
        except _PolicyExpiry as exc:
            exc.commit()
            raise
        except _ContinuityFailure:
            # The failed admission transaction has rolled back before this
            # revocation commits. Identical later observations cannot revive it.
            self.invalidate_all("configuration_qualification_unavailable")
            raise Error("partition_continuity_lost", "configuration monitoring continuity was lost", 503) from None

    def _active(self):
        if not self.service.bridge_enabled:
            raise Error("bridge_disabled", "partition bridge is not configured", 403)

    def _policy(self, db, *, request=None):
        if self.policy_provider is None:
            raise Error("partition_policy_unavailable", "independent current partition policy is required", 403)
        return self.policy_provider(db, expected_revision=request["offer"]["policy_revision"] if request else None,
                                    workload=request["workload"] if request else None)

    @staticmethod
    def _shape(policy, accelerator, profile, memory, capacity, accounting_version=None):
        # The strict wire permits one offer per CI. Pick the first approved exact
        # bundle which fits; never derive a fractional price or overstate capacity.
        for row in policy["shapes"]:
            shape = row["shape"]
            budget = {"cpu_millis":shape["cpuMillis"], "memory_bytes":shape["memoryBytes"], "scratch_bytes":shape["scratchBytes"]}
            charged = budget
            if accounting_version is not None:
                from .ephemeral import charge
                try: charged = charge(budget)["aggregate"]
                except Error: continue  # Unsupported shapes never become profile offers.
            if (shape["accelerator"] == accelerator and shape["profile"] == profile and shape["gpuMemoryBytes"] == memory
                    and all(charged[k] <= capacity[k] for k in charged)):
                return budget
        return None

    def _observation(self, snapshot, parent):
        resources = {r.id: r for r in snapshot.resources}
        gpu = resources[parent]; host = resources[snapshot.host_id]
        if gpu.kind != "gpu" or gpu.parent != host.id or not gpu.healthy or not host.healthy or snapshot.warnings:
            raise Error("partition_binding_unavailable", "complete healthy parent inventory is required", 503)
        children = [r for r in snapshot.resources if r.parent == parent]
        bindings = [mig_binding.observe(snapshot, r.id, devices=self.devices) for r in children]
        return {"host_id": host.id, "boot_id": host.details.get("boot_id"), "parent_uuid": parent,
                "driver_version": snapshot.driver_version, "pci_bus_id": gpu.details.get("pci_bus_id"),
                "mig_mode": gpu.details.get("mig_mode"), "bindings": sorted(bindings, key=lambda b: b["partition_uuid"])}

    def preflight_configuration(self, lease):
        if self.service.store.fence is None:
            return  # Legacy backends cannot publish durable partition authority.
        snapshot = self.service.backend.inventory()
        if (not isinstance(snapshot, Snapshot) or not math.isfinite(snapshot.observed_at)
                or abs(self.service.clock() - snapshot.observed_at) > 30):
            raise Error("stale_inventory", "fresh inventory is required before MIG configuration", 503)
        mig_binding.observe_driver(snapshot, lease["resources"][0], devices=self.devices)
        try:
            mig_binding.character_device_majors(self.devices or mig_binding.LinuxDevices())
        except (KeyError, TypeError, AttributeError, ValueError, OSError) as exc:
            raise Error("partition_binding_unavailable", f"exact driver registration unavailable: {exc}", 503) from None

    def begin_configuration(self, db, lease, operation):
        if self.service.store.fence is None:
            return False  # Legacy/synthetic observers cannot publish partition authority.
        anchor = self._durable(db)
        parent = lease["resources"][0]
        old = db.execute("SELECT generation FROM partition_configurations WHERE parent_uuid=?", (parent,)).fetchone()
        generation = old[0] + 1 if old else 1
        db.execute("INSERT INTO partition_configurations VALUES(?,?,'changing',NULL,NULL,?,NULL,?) "
                   "ON CONFLICT(parent_uuid) DO UPDATE SET generation=excluded.generation,state='changing',"
                   "binding=NULL,operation_id=excluded.operation_id,error=NULL,updated_at=excluded.updated_at",
                   (parent, generation, operation, self.service.clock()))
        return anchor["incarnation"]

    def commit_configuration(self, db, lease, snapshot):
        row = db.execute("SELECT * FROM partition_configurations WHERE parent_uuid=?", (lease["resources"][0],)).fetchone()
        if row is None: return
        observed = self._observation(snapshot, row["parent_uuid"])
        guid(observed["boot_id"])
        db.execute("UPDATE partition_configurations SET state='committed',boot_id=?,binding=?,error=NULL,updated_at=? WHERE parent_uuid=?",
                   (observed["boot_id"], canonical(observed), self.service.clock(), row["parent_uuid"]))

    def quarantine(self, db, parent, reason):
        now = float(db.execute("SELECT value FROM meta WHERE key='last_wall_time'").fetchone()[0])
        db.execute("UPDATE partition_configurations SET state='quarantined',error=?,updated_at=? WHERE parent_uuid=?",
                   (reason, now, parent))
        records = {r["id"]: r["parent"] for r in db.execute("SELECT id,parent FROM resources")}
        for raw in db.execute("SELECT * FROM leases WHERE owner='external' AND state!='released'").fetchall():
            lease = Store.decode(raw)
            if overlap({parent}, set(lease["resources"]), records):
                Store.update(db, lease, now, state="quarantined", error=reason)

    def observe_inventory(self, snapshot):
        # Invalidation commits separately from a later admission refusal.
        with self.service.store.transaction(self.service.clock()) as db:
            for row in db.execute("SELECT * FROM partition_configurations WHERE state='committed'").fetchall():
                try:
                    unchanged = self._observation(snapshot, row["parent_uuid"]) == json.loads(row["binding"])
                except (Error, KeyError): unchanged = False
                if unchanged and self.executor is not None:
                    for binding in json.loads(row["binding"])["bindings"]:
                        try:
                            qualification = self._qualification(binding)
                        except Exception:
                            qualification = None
                        if qualification is None or qualification.get("continuous_configuration_authority") is not True:
                            unchanged = False
                if not unchanged: self.quarantine(db, row["parent_uuid"], "configuration_observation_changed")

    def invalidate_all(self, reason):
        # An unavailable clock cannot prevent writing a revocation. Use only its
        # existing durable high-water mark; this never extends any lease/window.
        with self.service.store.connection() as db:
            last = float(db.execute("SELECT value FROM meta WHERE key='last_wall_time'").fetchone()[0])
        with self.service.store.transaction(last) as db:
            for row in db.execute("SELECT parent_uuid FROM partition_configurations WHERE state='committed'").fetchall():
                self.quarantine(db,row["parent_uuid"],reason)

    def _host_account(self, db, ignore=None, accounting_version=None, renewal_target=None, *, continuation=False):
        if self.executor is None:
            raise Error("partition_executor_unqualified", "no qualified partition executor is installed", 503)
        from . import ephemeral
        if accounting_version is None:
            capacity = dict(budget(self.executor.host_capacity()))
        else:
            try:
                declared = self.executor.host_capacity(accounting_version=accounting_version)
                fields(declared, "accounting_version capacity")
                if declared["accounting_version"] != ephemeral.ACCOUNTING: raise ValueError()
                capacity = dict(budget(declared["capacity"]))
            except (TypeError, ValueError, Error):
                raise Error("host_resources_unaccounted", "explicit aggregate capacity is unavailable", 409) from None
        available = dict(capacity)
        local_reserved = {key: 0 for key in capacity}
        held = []
        from .partition_binding import split_reservation
        from . import partition_execution as execution
        from .partition_execution import PROVIDER, renewal_matches
        targets = 0
        if renewal_target is not None and (ignore is not None or accounting_version != ephemeral.ACCOUNTING):
            raise Error("host_resources_unaccounted", "published renewal requires complete aggregate accounting", 409)
        live = db.execute("SELECT id FROM leases WHERE state!='released'" + (" LIMIT 65" if accounting_version else "")).fetchall()
        if accounting_version and len(live) > 64:
            raise Error("host_resources_unaccounted", "bounded live ownership inventory is exhausted", 409)
        for row in live:
            if row["id"] == ignore: continue
            reservation = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (row["id"],)).fetchone()
            if reservation is None:
                raise Error("host_resources_unaccounted", "every concurrent owner needs enforced host resource reservations", 409)
            lease = Store.lease(db, row["id"])
            profile = ephemeral.reservation_profile(reservation, lease)
            if (profile is not None) != (accounting_version is not None):
                raise Error("host_resources_unaccounted", "mixed accounting requires a separately qualified contract", 409)
            provider, state = split_reservation(reservation, lease)
            qualified = json.loads(provider["enforcement"]).get("contract") == PROVIDER
            context = {"lease":profile["lease"], "binding_state":state, "purpose":"account"} if qualified and profile else None
            if renewal_target is not None:
                if context is None: raise Error("host_resources_unaccounted", "renewal ownership is unqualified", 409)
                targets += int(renewal_matches(renewal_target, state, lease["id"]))
                context["renewal_target"] = copy.deepcopy(renewal_target)
            verified = self.executor.verify_reservation(lease, provider, context=context) if context else self.executor.verify_reservation(lease, provider)
            if verified is not True:
                raise Error("host_resources_unenforced", "a concurrent host resource limit is unverified", 503)
            resources = dict(budget({key: reservation[key] for key in capacity}))
            held.append({"lease":lease, "resources":resources, **({"provider_row":provider,"binding_state":state} if qualified else {})})
            for key in capacity:
                available[key] -= resources[key]
                if lease["owner"] == "local": local_reserved[key] += resources[key]
        verify = getattr(self.executor, "verify_host_accounting", None)
        if not callable(verify):
            raise Error("host_resources_unaccounted", "complete enforced host accounting is unavailable", 409)
        anchor = self.service.store.fence.verify(db) if self.service.store.fence else None
        if not anchor:
            raise Error("authority_continuity_lost", "host accounting requires durable allocation authority", 503)
        if renewal_target is not None and targets != 1:
            raise Error("host_resources_unaccounted", "published renewal target is not held exactly once", 409)
        scope = {"authority_incarnation": anchor["incarnation"], "configurations": [dict(row) for row in db.execute(
            "SELECT parent_uuid,generation,boot_id,state FROM partition_configurations ORDER BY parent_uuid")]}
        if accounting_version is not None:
            scope["accounting_version"] = accounting_version
            # This purpose comes only from the authority call site, never the request body.
            scope["purpose"] = "continuation" if continuation else "admission"
            if renewal_target is not None: scope["renewal_target"] = copy.deepcopy(renewal_target)
            # Exact released tombstones remain in the same rows; they consume no A twice.
            # Bound history rather than accepting a truncated runtime-owner inventory.
            retired = db.execute("SELECT r.* FROM host_reservations r JOIN leases l ON l.id=r.lease_id WHERE l.state='released' ORDER BY l.generation LIMIT 257").fetchall()
            if len(retired) > 256:
                raise Error("host_resources_unaccounted", "bounded retired ownership inventory is exhausted", 409)
            scope["retired"] = []
            for row in retired:
                local = Store.lease(db,row["lease_id"])
                provider, state = split_reservation(row,local)
                if json.loads(provider["enforcement"]).get("contract") == PROVIDER:
                    scope["retired"].append({"lease":local,"provider_row":provider,"binding_state":state})
        observed = verify(copy.deepcopy(capacity), copy.deepcopy(held), scope)
        if accounting_version is None and observed is not True:
            raise Error("host_resources_unaccounted", "complete enforced host accounting is unavailable", 409)
        if any(value < 0 for value in available.values()):
            raise Error("host_resources_unaccounted", "retained host reservations exceed enforced capacity", 409)
        if accounting_version is not None:
            fields(observed,"contract host_budget memory_current")
            if observed["contract"] != execution.HOST_ACCOUNTING:
                raise Error("host_resources_unaccounted", "versioned host headroom is unavailable", 409)
            value=observed["host_budget"]
            if not isinstance(value,dict): raise execution._denied()
            b=execution.host_budget(value,{"offer":{"partition":{"boot_id":value.get("boot_id"),
                "authority_incarnation":scope["authority_incarnation"]}}})
            if b["capacity"]!=capacity or len(held)>b["max_claims"]: raise execution._denied()
            for item in held:
                provider=item.get("provider_row")
                if provider is not None and json.loads(provider["enforcement"])["host_budget"]!=b:
                    raise execution._denied()
            current=observed["memory_current"]
            if type(current) is not int or not 0<=current<2**64: raise execution._denied()
            charged=b["shared"]["memory_bytes"]+sum(item["resources"]["memory_bytes"] for item in held)
            if charged>=2**64: raise execution._denied()
            if not continuation:
                if charged+current>=2**64: raise execution._denied()
                # Count current usage AND complete live reservations; no physical-free promise.
                headroom=max(0,b["root"]["memory_bytes"]-charged-current)//4096*4096
                available["memory_bytes"]=min(available["memory_bytes"],headroom)
                if len(held)>=b["max_claims"]:
                    available={key:0 for key in available}
        available["scratch_bytes"] = min(available["scratch_bytes"], available["memory_bytes"])
        account = {"capacity": capacity, "local_reserved": local_reserved, "available": available}
        if accounting_version is not None: account["accounting_version"] = accounting_version
        return account

    def _capacity(self, db, ignore=None, accounting_version=None, renewal_target=None, *, continuation=False):
        return self._host_account(db, ignore, accounting_version, renewal_target, continuation=continuation)["available"]

    def reserve_local(self, db, lease, resources):
        resources = budget(resources)
        if lease["mode"] != "hardware_partition" or lease["owner"] != "local":
            raise Error("host_resources_unsupported", "budgeted local execution currently requires one hardware partition", 409)
        if self.service.store.fence is None:
            raise Error("authority_fence_unavailable", "durable host budgets require an independent registry", 503)
        self._durable(db)
        capacity = self._capacity(db, ignore=lease["id"])
        if any(resources[k] > capacity[k] for k in resources):
            raise Error("host_resource_conflict", "host resource reservations exceed enforced capacity", 409)
        proof = self.executor.prepare_reservation(lease, resources)
        if not isinstance(proof, dict) or proof.get("enforcement_ready") is not True:
            raise Error("host_resources_unenforced", "CPU, RAM and memory-backed scratch limits are required", 503)
        from .partition_binding import provider_proof
        provider_proof(proof)
        from .ephemeral import ACCOUNTING
        if proof.get("accounting_version") == ACCOUNTING:
            raise Error("host_resources_unaccounted", "local aggregate task limits are not implemented", 409)
        db.execute("INSERT INTO host_reservations VALUES(?,?,?,?,?)",
                   (lease["id"], resources["cpu_millis"], resources["memory_bytes"], resources["scratch_bytes"], canonical(proof)))

    def _offer_rows(self, db, host_account=None, accounting_version=None):
        policy = self._policy(db)
        agreement = policy["agreement"]
        if not isinstance(agreement, dict): raise Error("partition_terms_unavailable", "partition terms are not authorized", 403)
        capacity = self._capacity(db, accounting_version=accounting_version) if host_account is None else host_account["available"]
        if capacity["cpu_millis"] <= 0 or capacity["memory_bytes"] <= 0: return []
        anchor = self.service.store.fence.verify(db) if self.service.store.fence else None
        if not anchor: raise Error("authority_continuity_lost", "durable configuration authority has not been adopted", 503)
        parents = {r["id"]: r["parent"] for r in db.execute("SELECT id,parent FROM resources")}
        held = [Store.decode(r) for r in db.execute("SELECT * FROM leases WHERE state!='released'")]
        result = []
        for row in db.execute("SELECT * FROM partition_configurations WHERE state='committed'"):
            observation = json.loads(row["binding"])
            for binding in observation["bindings"]:
                if any(overlap({binding["partition_uuid"]},set(l["resources"]),parents) for l in held): continue
                raw = db.execute("SELECT record,present FROM resources WHERE id=?", (binding["partition_uuid"],)).fetchone()
                if raw is None or not raw["present"]: continue
                resource = json.loads(raw["record"])
                if resource["busy"] or not resource["healthy"]: continue
                qualification = self._qualification(binding)
                if (not isinstance(qualification, dict) or qualification.get("qualified") is not True
                        or qualification.get("continuous_configuration_authority") is not True): continue
                runtime = qualification["runtime_sha256"]; sha(runtime)
                bundle = self._shape(policy, qualification["accelerator"], binding["profile"], binding["memory_bytes"], capacity, accounting_version)
                if bundle is None: continue
                result.append({"partition": {"resource_id": binding["partition_uuid"], "authority_incarnation": anchor["incarnation"],
                    "configuration_generation": row["generation"], "boot_id": row["boot_id"], "parent_uuid": row["parent_uuid"],
                    "mig_uuid": binding["partition_uuid"], "gpu_instance": binding["gpu_instance_id"],
                    "compute_instance": binding["compute_instance_id"], "binding_sha256": digest({"device":binding,"runtime_sha256":runtime})},
                    "policy_revision": policy["policy_revision"], "agreement": agreement,
                    "accelerator": qualification["accelerator"], "profile": binding["profile"],
                    "gpu_memory_bytes": binding["memory_bytes"], "driver_version": binding["driver_version"],
                    "runtime_sha256": runtime, "capacity": bundle,
                    "available_until_unix_millis": policy["available_until_unix_millis"]})
        return result

    def offers(self, **request):
        from .ephemeral import ACCOUNTING
        versioned = "accounting_version" in request
        fields(request, "include_host_budget accounting_version" if versioned else ("include_host_budget" if request else ""))
        if versioned and request["accounting_version"] != ACCOUNTING:
            raise Error("invalid_request", "unsupported host accounting contract", 400)
        accounting_version = ACCOUNTING if versioned else None
        include_budget = bool(request)
        if include_budget and request["include_host_budget"] is not True:
            raise Error("invalid_request", "host budget reporting must be explicitly requested", 400)
        self._active()
        with self.service.authority():
            self.service._inventory()
            account = None
            try:
                with self._admission_transaction() as db:
                    if include_budget: account = self._host_account(db, accounting_version=accounting_version)
                    offers = self._offer_rows(db, account, accounting_version)
            except Error as exc:
                if exc.code in {"partition_executor_unqualified", "partition_terms_unavailable", "partition_policy_unavailable", "partition_policy_expired", "host_resources_unaccounted", "host_resources_unenforced", "external_not_authorized"}:
                    offers, account = [], None
                else: raise
            report = {"offers": offers}
            if include_budget:
                report["host_budget"] = None if account is None else {key: account[key] for key in ("capacity", "local_reserved")}
                if account is not None and versioned: report["host_budget"]["accounting_version"] = ACCOUNTING
            # Match the Unix API serializer; never silently omit eligible partitions.
            if len(offers) > 64 or len(json.dumps(report, sort_keys=True, allow_nan=False).encode()) > 65536:
                raise Error("partition_offer_report_too_large", "complete partition offer report exceeds its wire limit", 503)
            return report

    @staticmethod
    def _identity(request): return request["platform_lease_id"], request["platform_epoch"]

    def _lookup(self, db, request):
        if db.execute("SELECT 1 FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?", self._identity(request)).fetchone():
            raise Error("platform_protocol_conflict", "platform tuple belongs to the v1 whole-host protocol", 409)
        row = db.execute("SELECT * FROM partition_claims WHERE platform_lease_id=? AND platform_epoch=?", self._identity(request)).fetchone()
        if row:
            normalized = {**request, "generation": 0}
            if row["request_hash"] != digest(normalized):
                raise Error("idempotency_conflict", "platform tuple has a different immutable partition request", 409)
            if request["generation"] not in (0, row["generation"]):
                raise Error("stale_generation", "partition lease generation differs", 409)
        elif request["generation"] != 0:
            raise Error("stale_generation", "unknown tuple cannot have a known local generation", 409)
        return row

    @staticmethod
    def _echo(row): return {**json.loads(row["request"]), "generation": row["generation"]}

    def claim(self, **request):
        qualified = "qualified_image" in request
        image = request.pop("qualified_image", None)
        request = validate_lease(request); self._active()
        from . import ephemeral
        from . import partition_execution as execution
        if qualified: image = execution.qualified_image(image, request)
        accounting_version = ephemeral.ACCOUNTING if "ephemeral" in request else None
        with self.service.authority():
            self.ensure_durable()
            self.service._inventory()
            with self._admission_transaction() as db:
                self._durable(db)
                prior = self._lookup(db, request)
                if prior:
                    if not prior["generation"]: raise Error("platform_claim_retired", "tuple retired before acquisition", 409)
                    if qualified:
                        from .partition_binding import split_reservation
                        reservation = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (prior["lease_id"],)).fetchone()
                        provider, _ = split_reservation(reservation, Store.lease(db, prior["lease_id"]))
                        proof = execution.qualified_proof(json.loads(provider["enforcement"]), self._echo(prior))
                        if proof["qualified_image"] != image: raise execution._denied()
                    return {"lease": self._echo(prior)}
                self.service._expires(request["expires_at_unix_millis"]/1000)
                self._policy(db, request=request)
                current = self._offer_rows(db, accounting_version=accounting_version)
                if not any(o["available_until_unix_millis"] >= request["offer"]["available_until_unix_millis"]
                        and {**o,"available_until_unix_millis":request["offer"]["available_until_unix_millis"]} == request["offer"] for o in current):
                    raise Error("stale_partition_offer", "partition offer or current independent authority changed", 409)
                if request["resources"] != request["offer"]["capacity"]:
                    raise Error("partition_shape_mismatch", "claim must reserve the exact approved resource bundle", 403)
                if db.execute("SELECT 1 FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?", self._identity(request)).fetchone():
                    raise Error("platform_claim_exists", "tuple belongs to the whole-host protocol", 409)
                generation = Store.generation(db); lease_id = str(uuid.uuid4()); now = self.service.clock()
                resource = request["offer"]["partition"]["resource_id"]
                normalized = {**request, "generation": 0}
                authorization = {"protocol": "partition-v2", "request_hash": digest(normalized)}
                records = [json.loads(r[0]) for r in db.execute("SELECT record FROM resources WHERE present=1")]
                parents = {r["id"]:r["parent"] for r in records}
                baseline = [r for r in records if overlap({resource},{r["id"]},parents)]
                db.execute("INSERT INTO leases(id,generation,owner,mode,state,resources,created_at,updated_at,expires_at,request_key,request_hash,authorization,baseline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (lease_id,generation,"external","hardware_partition","reserved",canonical([resource]),now,now,
                     request["expires_at_unix_millis"]/1000,"partition:"+digest(self._identity(request)),digest(normalized),canonical(authorization),canonical(baseline)))
                # The new lease is not counted until its reservation is inserted.
                resources = request["ephemeral"]["charge"]["aggregate"] if accounting_version else request["resources"]
                if qualified:
                    anchor = self.service.store.fence.verify(db)
                    context = {"lease":{**request,"generation":generation}, "qualified_image":image,
                               "authority_scope":{"authority_incarnation":anchor["incarnation"],"accounting_version":accounting_version}}
                    proof = self.executor.prepare_reservation(Store.lease(db,lease_id), resources, context=context)
                    execution.qualified_proof(proof, {**request,"generation":generation})
                    if proof["qualified_image"] != image: raise execution._denied()
                else:
                    proof = self.executor.prepare_reservation(Store.lease(db,lease_id), resources)
                if not isinstance(proof,dict) or proof.get("enforcement_ready") is not True:
                    raise Error("host_resources_unenforced", "partition host limits cannot be enforced", 503)
                from .partition_binding import provider_proof
                provider_proof(proof)
                if accounting_version:
                    if proof.get("accounting_version") != accounting_version:
                        raise Error("host_resources_unenforced", "aggregate reservation contract is unavailable", 503)
                    proof = {**proof, ephemeral.MEMBER:ephemeral.metadata({**request,"generation":generation}, proof)}
                elif proof.get("accounting_version") == ephemeral.ACCOUNTING:
                    raise Error("host_resources_unaccounted", "aggregate proof requires the explicit profile", 409)
                self.service._expires(request["expires_at_unix_millis"]/1000)
                policy = self._policy(db,request=request)
                if policy["agreement"]!=request["offer"]["agreement"]:
                    raise Error("partition_terms_changed", "partition agreement changed during admission", 409)
                db.execute("INSERT INTO host_reservations VALUES(?,?,?,?,?)",(lease_id,*[resources[k] for k in ("cpu_millis","memory_bytes","scratch_bytes")],canonical(proof)))
                db.execute("INSERT INTO partition_claims VALUES(?,?,?,?,?,?,0,?,?)",(*self._identity(request),canonical(normalized),digest(normalized),lease_id,generation,now,now))
                if accounting_version:
                    floor = 8 if qualified else 7
                    db.execute("UPDATE meta SET value=? WHERE key='schema_version' AND CAST(value AS INTEGER)<?", (str(floor), floor))
                return {"lease": {**request,"generation":generation}}

    def inspect(self, **request):
        request=validate_lease(request); self._active()
        with self.service.authority(), self.service.store.transaction(self.service.clock()) as db:
            row=self._lookup(db,request)
            held=bool(row and row["lease_id"] and Store.lease(db,row["lease_id"])["state"]!="released")
            return {"lease":self._echo(row) if row else request,"held":held}

    def reclaim(self, **request):
        request=validate_lease(request); self._active()
        with self.service.authority():
            self.ensure_durable()
            return self._reclaim(request)

    def _reclaim(self, request):
        with self.service.store.transaction(self.service.clock()) as db:
            self._durable(db)
            row=self._lookup(db,request); now=self.service.clock()
            if row is None:
                normalized={**request,"generation":0}
                db.execute("INSERT INTO partition_claims VALUES(?,?,?,?,NULL,0,1,?,?)",(*self._identity(request),canonical(normalized),digest(normalized),now,now))
            else:
                db.execute("UPDATE partition_claims SET retired=1,updated_at=? WHERE platform_lease_id=? AND platform_epoch=?",(now,*self._identity(request)))
                if row["lease_id"]:
                    from .partition_binding import retire
                    retire(db, row["lease_id"])
                    lease=Store.lease(db,row["lease_id"])
                    if lease["state"]!="released": Store.update(db,lease,now,state="draining",error="partition_reclaim")
            return {"lease":self._echo(self._lookup(db,request)),"retired":True}

    def _checked(self, db, request, row, *, purpose="check", peer=None, token=None, host_scope_sha256=None, published_ref=None):
        from .partition_binding import split_reservation
        from . import ephemeral, partition_execution as execution
        profile = "ephemeral" in request
        authorized=False
        lease = binding = qualification = reservation = None
        if row and not row["retired"] and row["lease_id"]:
            lease=Store.lease(db,row["lease_id"])
            try:
                policy = self._policy(db,request=request)
                config=db.execute("SELECT * FROM partition_configurations WHERE parent_uuid=?",(request["offer"]["partition"]["parent_uuid"],)).fetchone()
                matching = config and config["state"]=="committed" and config["generation"]==request["offer"]["partition"]["configuration_generation"]
                current_agreement=policy["agreement"]
                anchor=self.service.store.fence.verify(db) if self.service.store.fence else None
                matching=bool(matching and anchor and anchor["incarnation"]==request["offer"]["partition"]["authority_incarnation"]
                    and config["boot_id"]==request["offer"]["partition"]["boot_id"])
                binding=next((b for b in json.loads(config["binding"])["bindings"]
                    if b["partition_uuid"]==request["offer"]["partition"]["mig_uuid"]),None) if matching else None
                qualification=self._qualification(binding) if binding and self.executor else None
                matching=bool(matching and qualification and qualification.get("qualified") is True
                    and qualification.get("continuous_configuration_authority") is True
                    and qualification.get("runtime_sha256")==request["offer"]["runtime_sha256"]
                    and digest({"device":binding,"runtime_sha256":qualification["runtime_sha256"]})==request["offer"]["partition"]["binding_sha256"])
                target = None
                if published_ref is not None:
                    if not profile or purpose != "check": raise execution._denied()
                    reservation=db.execute("SELECT * FROM host_reservations WHERE lease_id=?",(lease["id"],)).fetchone()
                    if reservation is None: raise execution._denied()
                    provider, state = split_reservation(reservation, lease)
                    execution.qualified_proof(json.loads(provider["enforcement"]), request)
                    target = execution.renewal_target(state, request, published_ref)
                capacity=self._capacity(db, accounting_version=ephemeral.ACCOUNTING if profile else None, renewal_target=target, continuation=True)
                matching=matching and all(v>=0 for v in capacity.values())
                matching=matching and request["resources"]==request["offer"]["capacity"] and self._shape(
                    policy,request["offer"]["accelerator"],request["offer"]["profile"],
                    request["offer"]["gpu_memory_bytes"],request["ephemeral"]["charge"]["aggregate"] if profile else request["resources"],
                    accounting_version=ephemeral.ACCOUNTING if profile else None)==request["resources"]
                reservation=db.execute("SELECT * FROM host_reservations WHERE lease_id=?",(lease["id"],)).fetchone()
                verified = allowed = False
                if (matching and current_agreement==request["offer"]["agreement"] and self.executor
                        and lease["expires_at"]>self.service.clock() and lease["state"] in {"reserved","active"} and reservation):
                    provider, state = split_reservation(reservation, lease)
                    if profile:
                        execution.qualified_proof(json.loads(provider["enforcement"]), request)
                        context = execution.permission(state, purpose, peer, token, host_scope_sha256)
                        verified = self.executor.verify_reservation(lease, provider, context={"lease":request,**context}) is True
                        allowed = self.executor.check_execution(lease, request, context=context) is True
                        if context["creator"] is not None: peer.verify(context["creator"])
                    else:
                        verified = self.executor.verify_reservation(lease, provider) is True
                        allowed = self.executor.check_execution(lease,request) is True
                authorized=bool(matching and current_agreement==request["offer"]["agreement"] and self.executor
                    and lease["expires_at"]>self.service.clock() and lease["state"] in {"reserved","active"}
                    and verified and allowed)
                if authorized:
                    # A slow runtime check cannot extend a finite grant.
                    policy = self._policy(db,request=request)
                    authorized=bool(policy["agreement"]==request["offer"]["agreement"]
                                    and lease["expires_at"]>self.service.clock())
            except Error as exc:
                authorized=False
                if exc.code=="clock_regression": raise
        return (lease, binding, qualification, reservation) if authorized else None

    def check(self, *, _peer=None, **request):
        creation = "creation_token" in request
        published = "published_ref" in request
        token = request.pop("creation_token", None)
        ref = request.pop("published_ref", None)
        if creation and published: raise Error("invalid_request", "creation and published renewal are distinct", 400)
        request=validate_lease(request); self._active()
        if published:
            from .partition_binding import reference
            if "ephemeral" not in request: raise Error("invalid_request", "published renewal requires the qualified profile", 400)
            ref = reference(ref, request["platform_epoch"])
        if creation and "ephemeral" not in request: raise Error("invalid_request", "creation context requires the qualified profile", 400)
        if not request["generation"]: raise Error("stale_generation","check requires a held generation",409)
        with self.service.authority():
            self.service._inventory()
            with self._admission_transaction() as db:
                row=self._lookup(db,request)
                checked=self._checked(db,request,row,purpose="create" if creation else "check",peer=_peer,token=token,published_ref=ref)
                if checked and checked[0]["state"]=="reserved": Store.update(db,checked[0],self.service.clock(),state="active")
                return {"lease":self._echo(row) if row else request,"authorized":checked is not None}

    def bind(self, *, lease, ref, **request):
        if request:
            fields(request, "purpose")
            if request["purpose"] != "retirement":
                raise Error("invalid_request", "unsupported binding read purpose", 400)
            from .partition_execution import retirement
            return retirement(self, lease=lease, ref=ref)
        from .partition_binding import resolve
        return resolve(self, lease=lease, ref=ref)

    def begin(self, *, lease, ref, binding_sha256, expected_phase_revision, operation=None,
              creation_token=None, host_scope_sha256=None, _peer=None):
        if "ephemeral" in lease:
            if operation is None:
                from .ephemeral import require_unavailable
                require_unavailable(lease)
            from .partition_execution import resolve
            return resolve(self,lease=lease,ref=ref,binding_sha256=binding_sha256,expected_phase_revision=expected_phase_revision,
                           operation=operation,token=creation_token,host_scope_sha256=host_scope_sha256,peer=_peer)
        if operation is not None or creation_token is not None or host_scope_sha256 is not None or _peer is not None:
            raise Error("invalid_request", "legacy binding has no creator capability", 400)
        from .partition_binding import resolve
        return resolve(self, lease=lease, ref=ref, binding_sha256=binding_sha256,
                       expected_phase_revision=expected_phase_revision)

    def complete(self, *, lease, cleanup_verified):
        request=validate_lease(lease); self._active()
        if cleanup_verified is not True: raise Error("incomplete_cleanup","exact scoped runtime cleanup is required",409)
        with self.service.authority():
            self.ensure_durable()
            with self.service.store.transaction(self.service.clock()) as db:
                self._durable(db)
                row=self._lookup(db,request)
                if row is None:
                    now=self.service.clock(); normalized={**request,"generation":0}
                    db.execute("INSERT INTO partition_claims VALUES(?,?,?,?,NULL,0,1,?,?)",(*self._identity(request),canonical(normalized),digest(normalized),now,now))
                    return {"lease":request,"released":True}
                if not row["retired"]: raise Error("reclaim_required","retire the exact tuple first",409)
                echo=self._echo(row)
                if not row["lease_id"]: return {"lease":echo,"released":True}
                if request["generation"]==0: raise Error("stale_generation","held completion requires the resolved local generation",409)
                local=Store.lease(db,row["lease_id"])
                from .partition_binding import split_reservation
                reservation=db.execute("SELECT * FROM host_reservations WHERE lease_id=?",(local["id"],)).fetchone()
                if reservation:
                    provider, bound=split_reservation(reservation,local)
                    if bound and bound["phase"]!="retired":
                        raise Error("reclaim_required","retire the exact execution binding first",409)
                if local["state"]=="released": return {"lease":echo,"released":True}
                local=Store.update(db,local,self.service.clock(),state="verifying")
            # This seam is scoped to one lease. Whole-host cleanup/reset is never called.
            if self.executor is None: raise Error("partition_executor_unavailable","scoped cleanup verifier is unavailable",503)
            from .partition_execution import PROVIDER
            qualified = reservation and json.loads(provider["enforcement"]).get("contract") == PROVIDER
            proof=(self.executor.verify_clean(local,echo,context={"provider_row":provider,"binding_state":bound})
                   if qualified else self.executor.verify_clean(local,echo))
            local=self.service._apply_cleanup(local,proof,additional={"protocol":"partition-v2"})
            return {"lease":echo,"released":local["state"]=="released"}
