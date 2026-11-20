"""Host-owned local grants in the existing allocation ledger and creator engine."""
from __future__ import annotations

import copy
import json
import uuid

from . import ephemeral, partition_binding as binding, partition_execution as execution
from . import partition_local as local, partition_origin as origin
from .errors import Error
from .model import canonical, digest, key, overlap
from .partitions import fields, integer, sha
from .store import Store


def managed(row):
    return (row.get("authorization") or {}).get("protocol") == "managed-local-v1"


def demand_pending(db, now):
    return db.execute("SELECT 1 FROM local_partition_demands WHERE status='waiting' AND expires_at>? LIMIT 1", (now,)).fetchone() is not None


class LocalPartitionAuthority:
    def __init__(self, service):
        self.service = service
        self.authority = service.partitions

    def _active(self):
        if self.authority.executor is None or self.service.store.fence is None:
            raise Error("local_partition_unavailable", "a protected prepared-host provider is required", 503)

    @staticmethod
    def _floor(db):
        db.execute("UPDATE meta SET value='9' WHERE key='schema_version' AND CAST(value AS INTEGER)<9")

    def _device(self, db, resource_id):
        anchor = self.authority._durable(db)
        raw = db.execute("SELECT record,present FROM resources WHERE id=?", (resource_id,)).fetchone()
        if raw is None or not raw["present"]:
            raise Error("local_partition_unavailable", "the requested partition is not present", 409)
        resource = json.loads(raw["record"])
        config = db.execute("SELECT * FROM partition_configurations WHERE parent_uuid=?", (resource["parent"],)).fetchone()
        if resource["kind"] != "partition" or not resource["healthy"] or not config or config["state"] != "committed":
            raise Error("local_partition_unavailable", "the partition has no continuous configuration authority", 409)
        devices = [v for v in json.loads(config["binding"])["bindings"] if v["partition_uuid"] == resource_id]
        if len(devices) != 1: raise execution._denied()
        device = devices[0]
        qualified = self.authority._qualification(device)
        if qualified.get("qualified") is not True: raise execution._denied()
        runtime = qualified["runtime_sha256"]; sha(runtime)
        part = {"resource_id":resource_id, "authority_incarnation":anchor["incarnation"],
                "configuration_generation":config["generation"], "boot_id":config["boot_id"],
                "parent_uuid":config["parent_uuid"], "mig_uuid":resource_id,
                "gpu_instance":device["gpu_instance_id"], "compute_instance":device["compute_instance_id"],
                "binding_sha256":digest({"device":device,"runtime_sha256":runtime})}
        local.validate_partition(part)
        return part, device, qualified, resource

    def _row(self, db, request):
        anchor = self.authority._durable(db)
        row = Store.lease(db, request["ref"]["lease_id"])
        reservation = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (row["id"],)).fetchone()
        if (not managed(row) or not origin.matches_row(request, row) or reservation is None
                or request["ref"]["authority_incarnation"] != anchor["incarnation"]):
            raise execution._denied()
        provider, state = binding.split_reservation(reservation, row)
        if ephemeral.reservation_profile(reservation, row)["lease"] != request: raise execution._denied()
        return row, reservation, provider, state

    @staticmethod
    def _dispatched(db, row):
        return db.execute("SELECT 1 FROM operations WHERE lease_id=? AND generation=? AND action='local-dispatch' LIMIT 1",
                          (row["id"], row["generation"])).fetchone() is not None

    @staticmethod
    def _retired(row, state):
        return row["state"] not in {"reserved", "active"} or bool(state and state["phase"] == "retired")

    @staticmethod
    def _wire_bound(lease, proof, device, qualified):
        """Refuse before admission if any later exact response cannot fit the wire."""
        image = {"version":1,"reference":lease["workload"]["image"],
                 "manifest_sha256":"f"*64,"config_sha256":"f"*64,"rootfs_chain_sha256":"f"*64,
                 "os":"linux","architecture":"amd64","user":"0:0","workdir":lease["workload"]["workdir"],
                 "namespace":"n"*64,"snapshotter":"s"*64,"spec_sha256":"f"*64}
        host = proof["host_budget"]
        creator = {k:host[k] for k in ("boot_id","pid_namespace","user_namespace","cgroup_namespace")}
        creator.update(pid=2**31-1,start_ticks=2**63-1,uid=2**32-1,gid=2**32-1,executable_sha256="f"*64)
        value = {"contract":origin.LOCAL_BINDING,"lease":lease,"local_lease_id":lease["ref"]["lease_id"],"ref":lease["ref"],
            "requested_resources":lease["resources"],"aggregate_resources":lease["ephemeral"]["charge"]["aggregate"],
            "accounting_version":ephemeral.ACCOUNTING,"image":image,"host_budget":host,"device_observation":device,
            "runtime_identity":binding.runtime_identity(qualified["execution_identity"],lease["runtime_sha256"]),
            "reservation_proof_sha256":"f"*64}
        state = {"binding":value,"binding_sha256":"f"*64,"phase":"creation-consumed","phase_revision":5,
                 "creator":creator,"issue_sha256":"f"*64,"start_sha256":"f"*64,"host_scope_sha256":"f"*64}
        responses = ({"contract":"partition-local-retirement.v1","lease":lease,"disposition":"never-consumed","state":state},
                     {"state":state,"creation_token":"f"*64})
        if max(len(json.dumps(v,sort_keys=True,allow_nan=False).encode()) for v in responses) > 65536:
            raise Error("local_wire_bound", "encoded local grant exceeds the bounded runtime envelope", 400)

    def _checked(self, db, request, *, purpose="check", peer=None, token=None, host_scope_sha256=None, published_ref=None):
        row, reservation, provider, state = self._row(db, request)
        if (self._retired(row, state) or row["expires_at"] <= self.service.clock()
                or not self._dispatched(db, row)):
            raise execution._denied()
        part, device, qualified, _ = self._device(db, request["partition"]["resource_id"])
        if part != request["partition"] or qualified["runtime_sha256"] != request["runtime_sha256"]:
            raise execution._denied()
        target = None
        if published_ref is not None:
            origin.reference(published_ref, request)
            target = execution.renewal_target(state, request, published_ref)
        self.authority._capacity(db, accounting_version=ephemeral.ACCOUNTING, renewal_target=target, continuation=True)
        context = execution.permission(state, purpose, peer, token, host_scope_sha256)
        if (self.authority.executor.verify_reservation(row, provider, context={"lease":request, **context}) is not True
                or self.authority.executor.check_execution(row, request, context=context) is not True):
            raise execution._denied()
        if context["creator"] is not None: peer.verify(context["creator"])
        if row["expires_at"] <= self.service.clock(): raise execution._denied()
        return row, reservation, provider, state, device, qualified

    def reserve(self, *, resource_id, workload, resources, expires_at_unix_millis, request_key):
        self._active(); key(request_key, "request_key"); integer(expires_at_unix_millis, 1)
        if not isinstance(resource_id, str) or len(resource_id) > 256: raise execution._denied()
        profile = local.workload(workload, resources)
        payload = {"resource_id":resource_id,"workload":workload,"resources":resources,
                   "expires_at_unix_millis":expires_at_unix_millis,"request_key":request_key}
        request_hash = digest(payload); result = None
        with self.service.authority():
            self.authority.ensure_durable(); self.service._inventory()
            with self.authority._admission_transaction() as db:
                demand = db.execute("SELECT * FROM local_partition_demands WHERE request_key=?", (request_key,)).fetchone()
                if demand:
                    if demand["request_hash"] != request_hash:
                        raise Error("idempotency_conflict", "local demand key has different immutable inputs", 409)
                    if demand["lease_id"]:
                        row = Store.lease(db, demand["lease_id"])
                        reservation = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (row["id"],)).fetchone()
                        return {"lease":ephemeral.reservation_profile(reservation, row)["lease"]}
                self.service._expires(expires_at_unix_millis / 1000)
                part, device, qualified, resource = self._device(db, resource_id)
                account = self.authority._capacity(db, accounting_version=ephemeral.ACCOUNTING)
                charge = profile["charge"]["aggregate"]
                parents = {r["id"]:r["parent"] for r in db.execute("SELECT id,parent FROM resources")}
                held = [Store.decode(r) for r in db.execute("SELECT * FROM leases WHERE state!='released' ORDER BY generation LIMIT 65")]
                if len(held) > 64: raise execution._denied()
                conflicting = [r for r in held if overlap({resource_id},set(r["resources"]),parents)]
                if any(r["owner"] != "external" for r in conflicting):
                    raise Error("local_partition_conflict", "a local owner still holds this partition", 409)
                short = any(charge[k] > account[k] for k in charge)
                victims = [r for r in held if r["owner"] == "external"] if short else conflicting
                if conflicting or short:
                    if not victims:
                        raise Error("host_resource_conflict", "local capacity is insufficient without changing another local owner", 409)
                    if demand is None:
                        if db.execute("SELECT COUNT(*) FROM local_partition_demands WHERE status='waiting' AND expires_at>?", (self.service.clock(),)).fetchone()[0] >= 64:
                            raise execution._denied()
                        db.execute("INSERT INTO local_partition_demands VALUES(?,?,?,?,?,NULL,?)",
                                   (request_key, request_hash, canonical(payload), expires_at_unix_millis/1000, "waiting", canonical([r["id"] for r in victims])))
                    else:
                        names=sorted(set(json.loads(demand["victims"]))|{r["id"] for r in victims})
                        if len(names)>64: raise execution._denied()
                        db.execute("UPDATE local_partition_demands SET victims=? WHERE request_key=?", (canonical(names),request_key))
                    for victim in victims:
                        claim = db.execute("SELECT 1 FROM partition_claims WHERE lease_id=?", (victim["id"],)).fetchone()
                        if claim is None: raise execution._denied()
                        db.execute("UPDATE partition_claims SET retired=1,updated_at=? WHERE lease_id=?", (self.service.clock(),victim["id"]))
                        binding.retire(db, victim["id"])
                        if victim["state"] != "draining":
                            Store.update(db, victim, self.service.clock(), state="draining", error="managed_local_demand")
                    self._floor(db)
                else:
                    if resource["busy"]: raise Error("resource_busy", "the partition has unaccounted work", 409)
                    generation = Store.generation(db); lease_id = str(uuid.uuid4()); now = self.service.clock()
                    ref = {"authority_incarnation":part["authority_incarnation"],"lease_id":lease_id,"generation":generation}
                    lease = local.validate_lease({"contract":local.LEASE,"ref":ref,"partition":part,"policy_revision":generation,
                        "workload":workload,"resources":resources,"ephemeral":profile,"runtime_sha256":qualified["runtime_sha256"],
                        "expires_at_unix_millis":expires_at_unix_millis})
                    records = [json.loads(r[0]) for r in db.execute("SELECT record FROM resources WHERE present=1")]
                    baseline = [r for r in records if overlap({resource_id},{r["id"]},parents)]
                    db.execute("INSERT INTO leases(id,generation,owner,mode,state,resources,created_at,updated_at,expires_at,request_key,request_hash,authorization,workload,baseline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (lease_id,generation,"local","hardware_partition","reserved",canonical([resource_id]),now,now,
                         expires_at_unix_millis/1000,request_key,request_hash,canonical(origin.authorization(lease)),canonical(workload),canonical(baseline)))
                    proof = self.authority.executor.prepare_local_reservation(Store.lease(db,lease_id), charge,
                        context={"lease":lease,"authority_scope":{"authority_incarnation":ref["authority_incarnation"],"accounting_version":ephemeral.ACCOUNTING}})
                    execution.pending_local_proof(proof, lease); binding.provider_proof(proof)
                    self._wire_bound(lease,proof,device,qualified)
                    proof = {**proof, ephemeral.MEMBER:ephemeral.metadata(lease, proof)}
                    db.execute("INSERT INTO host_reservations VALUES(?,?,?,?,?)", (lease_id, *[charge[k] for k in ("cpu_millis","memory_bytes","scratch_bytes")], canonical(proof)))
                    if demand:
                        db.execute("UPDATE local_partition_demands SET status='fulfilled',lease_id=? WHERE request_key=?", (lease_id,request_key))
                    else:
                        db.execute("INSERT INTO local_partition_demands VALUES(?,?,?,?,?,?,?)", (request_key,request_hash,canonical(payload),expires_at_unix_millis/1000,"fulfilled",lease_id,"[]"))
                    self.service._expires(expires_at_unix_millis/1000); self._floor(db)
                    result = {"lease":lease}
        if result is None:
            raise Error("local_demand_pending", "borrower retirement is durable; repeat the identical request after positive cleanup", 409)
        return result

    def dispatch(self, **request):
        request = local.dispatch(request); self._active()
        with self.service.authority(), self.service.store.transaction(self.service.clock()) as db:
            row = Store.lease(db, request["ref"]["lease_id"])
            reservation = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (row["id"],)).fetchone()
            lease = ephemeral.reservation_profile(reservation, row)["lease"]
            origin.reference(request["ref"], lease)
            row, _, _, state = self._row(db, local.validate_lease(lease))
            if self._retired(row,state) or row["expires_at"] <= self.service.clock(): raise execution._denied()
            self.service._operation(db,row,row["generation"],"local-dispatch",request["request_key"],request)
            return {"lease":lease,"dispatched":True}

    def pending(self, *, after_generation):
        integer(after_generation); self._active()
        with self.service.authority(), self.service.store.transaction(self.service.clock()) as db:
            self.authority._durable(db)
            rows = [Store.decode(r) for r in db.execute("SELECT * FROM leases WHERE state!='released' ORDER BY generation LIMIT 65")]
            if len(rows) > 64: raise execution._denied()
            selected = [r for r in rows if managed(r) and r["generation"] > after_generation]
            result = []
            for row in selected[:1]:
                reservation = db.execute("SELECT * FROM host_reservations WHERE lease_id=?", (row["id"],)).fetchone()
                lease = ephemeral.reservation_profile(reservation, row)["lease"]
                row, _, _, state = self._row(db, lease)
                result.append({"lease":lease,"dispatched":self._dispatched(db,row),
                               "retired":self._retired(row,state) or row["expires_at"] <= self.service.clock()})
            response = {"leases":result,"has_more":len(selected)>1}
            if len(json.dumps(response,sort_keys=True,allow_nan=False).encode()) > 65536: raise execution._denied()
            return response

    def _resolve(self, lease, ref, *, image=None, operation=None, binding_sha256=None, expected_phase_revision=None,
                 token=None, host_scope_sha256=None, peer=None):
        request = local.validate_lease(lease); origin.reference(ref,request); self._active()
        with self.service.authority():
            self.service._inventory()
            with self.authority._admission_transaction() as db:
                row, reservation, provider, state = self._row(db, request)
                proof = json.loads(provider["enforcement"])
                if image is not None:
                    image = execution.qualified_image(image,request)
                    if proof["contract"] == origin.LOCAL_PENDING and state is None:
                        if self._retired(row,state) or row["expires_at"] <= self.service.clock(): raise execution._denied()
                        proof = self.authority.executor.prepare_reservation(row, request["ephemeral"]["charge"]["aggregate"],
                            context={"lease":request,"qualified_image":image,"authority_scope":{
                                "authority_incarnation":ref["authority_incarnation"],"accounting_version":ephemeral.ACCOUNTING}})
                        execution.qualified_proof(proof,request)
                        db.execute("UPDATE host_reservations SET enforcement=? WHERE lease_id=?",
                                   (canonical({**proof,ephemeral.MEMBER:ephemeral.metadata(request,proof)}),row["id"]))
                    elif proof.get("qualified_image") != image: raise execution._denied()
                row, reservation, provider, state, device, qualified = self._checked(db,request,purpose=operation or "bind",
                    peer=peer,token=token,host_scope_sha256=host_scope_sha256)
                proof = execution.qualified_proof(json.loads(provider["enforcement"]),request)
                value = {"contract":origin.LOCAL_BINDING,"lease":request,"local_lease_id":row["id"],"ref":ref,
                    "requested_resources":request["resources"],"aggregate_resources":request["ephemeral"]["charge"]["aggregate"],
                    "accounting_version":ephemeral.ACCOUNTING,"image":proof["qualified_image"],"host_budget":proof["host_budget"],
                    "device_observation":device,"runtime_identity":binding.runtime_identity(qualified["execution_identity"],request["runtime_sha256"]),
                    "reservation_proof_sha256":digest(proof)}
                response = execution.transition(value,state,proof,operation=operation,binding_sha256=binding_sha256,
                    expected_phase_revision=expected_phase_revision,token=token,host_scope_sha256=host_scope_sha256,peer=peer)
                state = response["state"] if operation is not None else response
                if row["expires_at"] <= self.service.clock(): raise execution._denied()
                if peer is not None: peer.verify(state["creator"])
                binding.save(db,reservation,state); self._floor(db)
                return copy.deepcopy(response)

    def bind(self, *, lease, ref, **extra):
        if "purpose" in extra:
            fields(extra,"purpose")
            if extra["purpose"] != "retirement": raise execution._denied()
            request = local.validate_lease(lease); origin.reference(ref,request); self._active()
            with self.service.authority(), self.service.store.transaction(self.service.clock()) as db:
                row, _, _, state = self._row(db,request)
                if not self._retired(row,state): raise execution._denied()
                if state is not None and state["phase"] != "retired": raise execution._denied()
                disposition = "never-bound" if state is None else ("never-consumed" if state["phase_revision"]<=3 else "scope-required")
                return {"contract":"partition-local-retirement.v1","lease":request,"disposition":disposition,"state":copy.deepcopy(state)}
        fields(extra,"qualified_image" if extra else "")
        if "qualified_image" in extra:
            execution.qualified_image(extra["qualified_image"],local.validate_lease(lease))
        return self._resolve(lease,ref,image=extra.get("qualified_image"))

    def begin(self, *, lease, ref, binding_sha256, expected_phase_revision, operation, creation_token=None, host_scope_sha256=None, _peer=None):
        if operation not in {"issue","consume","publish"}: raise execution._denied()
        sha(binding_sha256); integer(expected_phase_revision,1,3)
        if (expected_phase_revision != {"issue":1,"consume":2,"publish":3}[operation]
                or (operation == "issue" and creation_token is not None)
                or (operation != "publish" and host_scope_sha256 is not None)): raise execution._denied()
        return self._resolve(lease,ref,operation=operation,binding_sha256=binding_sha256,
            expected_phase_revision=expected_phase_revision,token=creation_token,host_scope_sha256=host_scope_sha256,peer=_peer)

    def check(self, *, lease, _peer=None, **extra):
        fields(extra,"creation_token" if "creation_token" in extra else ("published_ref" if extra else ""))
        request = local.validate_lease(lease); self._active()
        if "published_ref" in extra: origin.reference(extra["published_ref"],request)
        with self.service.authority():
            self.service._inventory()
            with self.authority._admission_transaction() as db:
                try:
                    row, *_ = self._checked(db,request,purpose="create" if "creation_token" in extra else "check",
                        peer=_peer,token=extra.get("creation_token"),published_ref=extra.get("published_ref"))
                    if row["state"] == "reserved": Store.update(db,row,self.service.clock(),state="active")
                except Error as exc:
                    if exc.code == "clock_regression": raise
                    return {"lease":request,"authorized":False}
                return {"lease":request,"authorized":True}

    def reclaim(self, *, lease):
        request = local.validate_lease(lease); self._active()
        with self.service.authority(), self.service.store.transaction(self.service.clock()) as db:
            row, _, _, _ = self._row(db,request)
            binding.retire(db,row["id"])
            if row["state"] != "released": Store.update(db,row,self.service.clock(),state="draining",error="managed_local_reclaim")
            return {"lease":request,"retired":True}

    def complete(self, *, lease, cleanup_verified):
        request = local.validate_lease(lease); self._active()
        if cleanup_verified is not True: raise Error("incomplete_cleanup","exact scoped runtime cleanup is required",409)
        with self.service.authority():
            with self.service.store.transaction(self.service.clock()) as db:
                row, _, provider, state = self._row(db,request)
                if not self._retired(row,state) or (state and state["phase"] != "retired"):
                    raise Error("reclaim_required","retire the exact local grant first",409)
                if row["state"] == "released": return {"lease":request,"released":True}
                row = Store.update(db,row,self.service.clock(),state="verifying")
            proof = self.authority.executor.verify_clean(row,request,context={"provider_row":provider,"binding_state":state})
            row = self.service._apply_cleanup(row,proof,additional={"protocol":"managed-local-v1"})
            return {"lease":request,"released":row["state"] == "released"}
