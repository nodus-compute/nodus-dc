"""One durable local owner for whole hosts, GPUs and hardware partitions."""
from __future__ import annotations

import fcntl
import json
import math
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .errors import Error
from .model import (API_VERSION, HOLDING, LOCAL_MODES, CleanupProof, Snapshot,
                    canonical, digest, finite_time, key, overlap)
from .store import Store

# Explicit installer capability: this implementation can retire a disappeared
# MIG identity only after an actual boot fence and physical-parent cleanup proof.
RECOVERY_UPGRADE_PROTOCOL = 1


class Service:
    def __init__(self, store: Store, backend, *, clock=time.time, bridge_enabled=False):
        self.store = store
        self.backend = backend
        self.clock = clock
        self.bridge_enabled = bridge_enabled
        self.bridge_health_error = None
        self.bridge_authorization_check = None
        self.lock_path = str(Path(store.path).with_name("host.lock"))

    @contextmanager
    def authority(self):
        """Also held by bridge calls. This lock never expires and is not a lease."""
        physical = self.backend.bind_authority(self.store.path) if hasattr(self.backend, "bind_authority") else None
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            if physical is not None:
                fcntl.flock(physical, fcntl.LOCK_UN)
                os.close(physical)

    def _inventory(self):
        snapshot = self.backend.inventory()
        if not isinstance(snapshot, Snapshot):
            raise Error("invalid_inventory", "backend did not provide a typed inventory", 503)
        now = self.clock()
        if not math.isfinite(snapshot.observed_at) or abs(now - snapshot.observed_at) > 30:
            raise Error("stale_inventory", "GPU inventory is stale or from the future", 503)
        record = snapshot.record()
        rows = record["resources"]
        by_id = {r["id"]: r for r in rows}
        if len(by_id) != len(rows) or snapshot.host_id not in by_id:
            raise Error("invalid_inventory", "inventory has duplicate or missing host resource", 503)
        host = by_id[snapshot.host_id]
        if host["kind"] != "host" or host["parent"] is not None:
            raise Error("invalid_inventory", "host resource has invalid hierarchy", 503)
        for row in rows:
            if row["kind"] == "host" and row["id"] != snapshot.host_id:
                raise Error("invalid_inventory", "inventory must describe exactly one host", 503)
            if row["kind"] not in {"host", "gpu", "partition"} or row["memory_bytes"] < 0:
                raise Error("invalid_inventory", "inventory contains an invalid resource", 503)
            if row["kind"] != "host" and row["parent"] not in by_id:
                raise Error("invalid_inventory", "inventory has an unknown parent", 503)
            if row["kind"] == "gpu" and row["parent"] != snapshot.host_id:
                raise Error("invalid_inventory", "GPU does not belong to this host", 503)
            if row["kind"] == "partition" and by_id[row["parent"]]["kind"] != "gpu":
                raise Error("invalid_inventory", "partition parent is not a physical GPU", 503)
        with self.store.transaction(now) as db:
            old_host = db.execute("SELECT value FROM meta WHERE key='host_id'").fetchone()
            if old_host and old_host[0] != snapshot.host_id:
                raise Error("host_identity_changed", "state belongs to a different physical host", 503)
            db.execute("INSERT OR IGNORE INTO meta VALUES('host_id',?)", (snapshot.host_id,))
            db.execute("UPDATE resources SET present=0")
            for row in rows:
                db.execute("INSERT INTO resources VALUES(?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET "
                           "parent=excluded.parent,kind=excluded.kind,record=excluded.record,"
                           "inventory_revision=excluded.inventory_revision,observed_at=excluded.observed_at,present=1",
                           (row["id"], row["parent"], row["kind"], canonical(row), record["revision"], now))
            db.execute("INSERT INTO meta VALUES('inventory',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (canonical(record),))
        return record

    def inventory(self):
        with self.authority():
            return self._inventory()

    def status(self):
        from .availability import project
        with self.store.connection() as db:
            # One read snapshot: a concurrent reserve/release must not mix its
            # leases with another version of the resource hierarchy.
            db.execute("BEGIN")
            raw = db.execute("SELECT value FROM meta WHERE key='inventory'").fetchone()
            leases = [Store.decode(r) for r in db.execute("SELECT * FROM leases ORDER BY generation")]
            policy = db.execute("SELECT * FROM bridge_policy WHERE singleton=1").fetchone()
            records = [dict(row) for row in db.execute("SELECT id,parent,present,observed_at FROM resources")]
            last = float(db.execute("SELECT value FROM meta WHERE key='last_wall_time'").fetchone()[0])
            inventory = json.loads(raw[0]) if raw else None
            availability = project(inventory, leases, records,
                                   authority=getattr(self.backend, "allocation_authority", "observe"),
                                   now=self.clock(), last_wall_time=last)
            return {"api_version": API_VERSION, "inventory": inventory, "availability": availability,
                    "leases": leases, "bridge_policy": dict(policy) if policy else None,
                    "hardware_qualified": False}

    def get(self, lease_id):
        with self.store.connection() as db:
            return Store.lease(db, lease_id)

    def bridge_policy_state(self):
        with self.store.connection() as db:
            row = db.execute("SELECT policy_revision,enabled,authorization_id,consent_reference,expires_at "
                             "FROM bridge_policy WHERE singleton=1").fetchone()
            return dict(row) if row else {"policy_revision": 0, "enabled": False, "authorization_id": None,
                                         "consent_reference": None, "expires_at": 0}

    @staticmethod
    def _native_handoff(lease):
        return (lease.get("runtime") or {}).get("execution_kind") == "native_handoff"

    def record_connection_attempt(self, credential_binding=None, *, participation=None, fresh_record=False):
        """Persist before any remote Accept/connect; serialize against native handoff."""
        with self.authority(), self.store.transaction(self.clock()) as db:
            for row in db.execute("SELECT * FROM leases WHERE state!='released'"):
                if self._native_handoff(Store.decode(row)):
                    raise Error("native_handoff_active", "native handoff requires an out-of-band return fence before platform participation", 409)
            prior = db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()
            if participation == "disabled":
                recorded = db.execute("SELECT value FROM meta WHERE key='participation_history'").fetchone()
                if not recorded:
                    pristine = (fresh_record and not prior
                        and not db.execute("SELECT 1 FROM meta WHERE key='connected_mode_seen'").fetchone()
                        and not db.execute("SELECT 1 FROM bridge_policy").fetchone()
                        and not db.execute("SELECT 1 FROM platform_claims").fetchone()
                        and not db.execute("SELECT 1 FROM leases WHERE owner='external'").fetchone())
                    db.execute("INSERT INTO meta VALUES('participation_history',?)",
                               ("never_enabled" if pristine else "unknown",))
                db.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
            seen = db.execute("SELECT 1 FROM meta WHERE key='connected_mode_seen'").fetchone()
            history = json.loads(prior[0]) if prior else {
                "eligible": credential_binding is not None and not seen, "binding": credential_binding,
                "reason": "tracked_first_connection" if credential_binding is not None and not seen else "unknown_prior_credentials"}
            if credential_binding is None or history["binding"] != credential_binding:
                history.update(eligible=False, reason="credential_or_connection_changed")
            db.execute("INSERT OR REPLACE INTO meta VALUES('native_credential_history',?)", (canonical(history),))
            # Old binaries refuse this authority state rather than silently omit
            # credential-history checks after a package rollback.
            db.execute("UPDATE meta SET value='2' WHERE key='schema_version' AND value='1'")
            db.execute("INSERT OR REPLACE INTO meta VALUES('connected_mode_seen','1')")

    @staticmethod
    def _fence(lease, generation):
        if type(generation) is not int or generation != lease["generation"]:
            raise Error("stale_generation", "lease generation does not match current authority")

    def _operation(self, db, lease, generation, action, request_key, payload):
        self._fence(lease, generation)
        key(request_key, "request_key")
        request_hash = digest({"lease": lease["id"], "generation": generation,
                               "action": action, "payload": payload})
        prior = db.execute("SELECT request_hash FROM operations WHERE request_key=?", (request_key,)).fetchone()
        if prior:
            if prior[0] != request_hash:
                raise Error("idempotency_conflict", "request key was used with different inputs")
            return True
        db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)",
                   (request_key, lease["id"], generation, action, request_hash, self.clock()))
        return False

    def _expires(self, expires_at):
        expires_at = finite_time(expires_at, "expires_at")
        if not self.clock() < expires_at <= self.clock() + 86400:
            raise Error("invalid_expiry", "lease must expire within the next 24 hours", 400)
        return expires_at

    def _check_bridge_authorization(self, **workload):
        if self.bridge_authorization_check is None:
            return
        try:
            valid = self.bridge_authorization_check(**workload)
        except Error:
            raise
        except Exception:
            raise Error("bridge_identity_unverified", "enrolled host authorization could not be verified", 403) from None
        if valid is not True:
            raise Error("bridge_identity_unverified", "enrolled host authorization could not be verified", 403)

    def _policy(self, db, *, expected_revision=None):
        self._check_bridge_authorization()
        if self.bridge_health_error:
            raise Error("bridge_unhealthy", "connected authorization health could not be verified", 403)
        row = db.execute("SELECT * FROM bridge_policy WHERE singleton=1").fetchone()
        if (not self.bridge_enabled or row is None or not row["enabled"]
                or row["expires_at"] <= self.clock()):
            raise Error("external_not_authorized", "external execution has no current operator authorization", 403)
        if expected_revision is not None and row["policy_revision"] != expected_revision:
            raise Error("stale_policy", "operator policy revision changed")
        return dict(row)

    def _reserve(self, resources, mode, expires_at, request_key, *, owner="local", authorization=None):
        if not isinstance(resources, list) or not resources or any(not isinstance(r, str) for r in resources):
            raise Error("invalid_request", "resources must be a nonempty list of identifiers", 400)
        if len(set(resources)) != len(resources):
            raise Error("invalid_request", "resource identifiers must be unique", 400)
        resources = sorted(resources)
        key(request_key, "request_key")
        expires_at = finite_time(expires_at, "expires_at")
        if mode not in LOCAL_MODES:
            raise Error("unsupported_mode", "allocation mode is unsupported; weaker isolation will not be substituted", 400)
        payload = {"resources": resources, "mode": mode, "expires_at": expires_at,
                   "owner": owner, "authorization": authorization}
        request_hash = digest(payload)
        now = self.clock()
        with self.store.transaction(now) as db:
            prior = db.execute("SELECT * FROM leases WHERE request_key=?", (request_key,)).fetchone()
            if prior:
                if prior["request_hash"] != request_hash:
                    raise Error("idempotency_conflict", "request key was used with different inputs")
                return Store.decode(prior)
            self._expires(expires_at)
            if owner == "external":
                policy = self._policy(db, expected_revision=authorization["policy_revision"])
                for field in ("authorization_id", "consent_reference"):
                    if authorization.get(field) != policy[field]:
                        raise Error("stale_authorization", "lease authorization does not match operator consent")
                if expires_at > policy["expires_at"]:
                    raise Error("invalid_expiry", "lease exceeds the operator authorization window", 400)
                existing = db.execute("SELECT * FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?",
                                      (authorization["platform_lease_id"], authorization["platform_epoch"])).fetchone()
                if existing:
                    raise Error("platform_claim_exists", "platform tuple is already claimed or retired")
            records = {r["id"]: dict(r) for r in db.execute("SELECT * FROM resources")}
            parents = {r: record["parent"] for r, record in records.items()}
            for r in resources:
                row = records.get(r)
                if not row or not row["present"] or now - row["observed_at"] > 30:
                    raise Error("resource_unavailable", f"resource {r} has no current inventory")
                spec = json.loads(row["record"])
                if mode not in spec["modes"]:
                    raise Error("unsupported_mode", f"{r} does not support {mode}")
                if not spec["healthy"] or spec["busy"]:
                    raise Error("resource_unavailable", f"resource {r} is unhealthy or has existing activity")
            if any(overlap({a}, {b}, parents) for i, a in enumerate(resources) for b in resources[i+1:]):
                raise Error("overlapping_request", "one request cannot select a resource and its descendant", 400)
            live = [Store.decode(r) for r in db.execute("SELECT * FROM leases WHERE state != 'released'")]
            for other in live:
                if overlap(set(resources), set(other["resources"]), parents):
                    raise Error("allocation_conflict", f"resource remains held by lease {other['id']}")
            lease_id = str(uuid.uuid4())
            generation = Store.generation(db)
            baseline = [json.loads(row["record"]) for r, row in records.items()
                        if row["present"] and overlap(set(resources), {r}, parents)]
            db.execute("INSERT INTO leases(id,generation,owner,mode,state,resources,created_at,updated_at,expires_at,"
                       "request_key,request_hash,authorization,baseline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (lease_id, generation, owner, mode, "reserved", canonical(resources), now, now, expires_at,
                        request_key, request_hash, canonical(authorization) if authorization else None, canonical(baseline)))
            lease = Store.lease(db, lease_id)
            if owner == "external":
                db.execute("INSERT INTO platform_claims VALUES(?,?,?,?,?,0,?,?)",
                           (authorization["platform_lease_id"], authorization["platform_epoch"], lease_id,
                            generation, authorization["policy_revision"], now, now))
            Store.event(db, now, lease, "reserve", payload)
            return lease

    def reserve(self, *, resources, mode, expires_at, request_key):
        with self.authority():
            self._inventory()
            return self._reserve(resources, mode, expires_at, request_key)

    def start(self, lease_id, *, generation, request_key, workload):
        if not isinstance(workload, dict):
            raise Error("invalid_request", "workload must be an object", 400)
        with self.authority():
            now = self.clock()
            with self.store.transaction(now) as db:
                lease = Store.lease(db, lease_id)
                if self._operation(db, lease, generation, "start", request_key, workload):
                    return lease
                if lease["owner"] != "local":
                    raise Error("external_execution_delegated", "external work must run through the trusted platform bridge", 403)
                if lease["state"] != "reserved" or lease["expires_at"] <= now:
                    raise Error("lease_not_startable", "lease is expired or no longer reserved")
                self.backend.validate_workload(workload, lease)
                lease = Store.update(db, lease, now, state="starting", workload=workload)
                Store.event(db, now, lease, "start_intent", {"workload": workload})
            try:
                runtime = self.backend.start(lease)
                if not isinstance(runtime, dict) or runtime.get("lease_id") != lease_id or runtime.get("generation") != generation:
                    raise Error("invalid_backend_evidence", "runtime identity does not match the lease", 503)
            except Exception as exc:
                with self.store.transaction(self.clock()) as db:
                    current = Store.lease(db, lease_id)
                    current = Store.update(db, current, self.clock(), state="quarantined", error="start outcome uncertain: " + str(exc))
                    Store.event(db, self.clock(), current, "start_failed", {"error": str(exc)})
                raise Error("start_uncertain", "workload start did not complete; resource remains quarantined", 503) from exc
            with self.store.transaction(self.clock()) as db:
                current = Store.lease(db, lease_id)
                current = Store.update(db, current, self.clock(), state="active", runtime=runtime)
                Store.event(db, self.clock(), current, "started", runtime)
                return current

    def native_handoff(self, lease_id, *, generation, request_key, provisioner_reference):
        """Sticky intent guard only: does not provision SSH or prove native return."""
        key(provisioner_reference, "provisioner_reference")
        with self.authority():
            with self.store.transaction(self.clock()) as db:
                lease = Store.lease(db, lease_id)
                if self._operation(db, lease, generation, "native_handoff", request_key,
                                   {"provisioner_reference": provisioner_reference}):
                    return lease
                if (self.bridge_enabled or (Path(self.store.path).parent/"connection.json").exists()
                        or Path("/var/lib/nodus/node.json").exists()
                        or db.execute("SELECT 1 FROM meta WHERE key='connected_mode_seen'").fetchone()
                        or db.execute("SELECT 1 FROM bridge_policy LIMIT 1").fetchone()
                        or db.execute("SELECT 1 FROM platform_claims LIMIT 1").fetchone()):
                    raise Error("native_platform_fence_unsupported", "connected/enrolled hosts need a durable out-of-band platform revocation fence; local native handoff is unsupported", 409)
                if (lease["owner"] != "local" or lease["mode"] != "exclusive_host" or lease["state"] != "reserved"
                        or lease["expires_at"] <= self.clock() or lease["runtime"] or lease["workload"]):
                    raise Error("native_handoff_requires_host", "native intent requires a current unused local exclusive-host lease", 409)
                runtime = {"lease_id": lease_id, "generation": generation, "execution_kind": "native_handoff",
                           "provisioner_reference": provisioner_reference, "handed_off_at": self.clock(),
                           "return_supported": False}
                lease = Store.update(db, lease, self.clock(), state="active", runtime=runtime)
                Store.event(db, self.clock(), lease, "native_handoff_intent", runtime)
                return lease

    def configure(self, lease_id, *, generation, request_key, plan):
        from .partitioning import validate_plan
        validate_plan(plan)
        with self.authority():
            with self.store.transaction(self.clock()) as db:
                lease = Store.lease(db, lease_id)
                if self._operation(db, lease, generation, "configure", request_key, plan):
                    return lease
                if (lease["owner"] != "local" or lease["mode"] != "gpu_configuration"
                        or len(lease["resources"]) != 1 or lease["state"] != "reserved"
                        or lease["expires_at"] <= self.clock()):
                    raise Error("configuration_lease_required", "configuration needs a current reserved GPU maintenance lease")
                lease = Store.update(db, lease, self.clock(), state="starting", workload={"mig_plan": plan}, runtime=None)
                Store.event(db, self.clock(), lease, "configuration_intent", plan)
            try:
                snapshot = self.backend.configure_mig(lease, plan)
                rows = [r.record() for r in snapshot.resources]
                parents = {r["id"]: r["parent"] for r in rows}
                baseline = [r for r in rows if overlap(set(lease["resources"]), {r["id"]}, parents)]
                self._inventory()
            except Exception as exc:
                with self.store.transaction(self.clock()) as db:
                    lease = Store.update(db, Store.lease(db, lease_id), self.clock(), state="quarantined", error=str(exc))
                    Store.event(db, self.clock(), lease, "configuration_failed", {"error": str(exc)})
                raise Error("configuration_uncertain", "MIG change needs recovery; GPU remains held", 503) from exc
            with self.store.transaction(self.clock()) as db:
                lease = Store.update(db, Store.lease(db, lease_id), self.clock(), state="reserved", baseline=baseline,
                                     workload=None, runtime={"lease_id": lease_id, "generation": generation,
                                     "configuration": plan}, error=None)
                Store.event(db, self.clock(), lease, "configuration_verified", {"plan": plan, "baseline": baseline})
                return lease

    def recover(self, lease_id, *, generation, request_key):
        """Fence uncertain old commands by a verified host boot transition.

        No arbitrary operator 'clean' assertion is accepted. Docker restart
        policies are disabled by this runtime; exact owned containers are still
        removed and independently checked before capacity returns.
        """
        with self.authority():
            with self.store.transaction(self.clock()) as db:
                lease = Store.lease(db, lease_id)
                self._fence(lease, generation)
                if lease["owner"] != "local":
                    raise Error("recovery_not_applicable", "only uncertain local leases can be recovered")
                if self._native_handoff(lease):
                    raise Error("native_return_unsupported", "a boot change cannot prove native credential revocation; out-of-band reprovisioning is required", 409)
                original = next((r for r in lease["baseline"] if r["kind"] == "host"), None)
                old_boot = original["details"].get("boot_id") if original else None
                new_boot = self.backend.boot_id()
                if not old_boot or not new_boot or old_boot == new_boot:
                    raise Error("execution_fence_required", "uncertain commands require a verified host reboot before recovery")
                replay = self._operation(db, lease, generation, "recover", request_key, {"boot_id": new_boot})
                if replay and lease["state"] == "released":
                    return lease
                recovering_partition = (lease["mode"] == "hardware_partition" and lease["state"] == "verifying"
                                        and (lease.get("runtime") or {}).get("retired_partition_recovery") is True)
                if lease["state"] not in {"starting", "quarantined", "draining"} and not recovering_partition:
                    raise Error("recovery_not_applicable", "only uncertain local leases can be recovered")
                if lease["mode"] == "hardware_partition":
                    baseline = {r["id"]: r for r in lease["baseline"]}
                    partitions = [baseline.get(r) for r in lease["resources"]]
                    if (not partitions or any(r is None or r["kind"] != "partition"
                                              or baseline.get(r["parent"], {}).get("kind") != "gpu"
                                              for r in partitions)):
                        raise Error("recovery_parent_unknown", "original physical parent identities are missing", 503)
                    physical = {r["parent"] for r in partitions}
                    parents = {r["id"]: r["parent"] for r in db.execute("SELECT id,parent FROM resources")}
                    for row in db.execute("SELECT * FROM leases WHERE state!='released' AND id!=?", (lease_id,)):
                        other = Store.decode(row)
                        baseline_parents = {r["id"] for r in other["baseline"] if r["kind"] == "gpu"}
                        if (physical & baseline_parents
                                or overlap(physical, set(other["resources"]), parents)):
                            raise Error("recovery_parent_busy", "release every other allocation on the original physical GPU before partition recovery")
            if lease["mode"] == "hardware_partition":
                # A disappeared MIG UUID is not clean evidence by itself. The
                # original identity stays in the lease and cleanup proof; a new
                # boot plus exact idle physical-parent evidence retires it.
                with self.store.transaction(self.clock()) as db:
                    lease = Store.update(db, Store.lease(db, lease_id), self.clock(), state="verifying",
                                         runtime={"lease_id": lease_id, "generation": generation,
                                                  "recovery_boot_id": new_boot, "retired_partition_recovery": True})
                    Store.event(db, self.clock(), lease, "partition_recovery_execution_fenced",
                                {"previous_boot_id": old_boot, "boot_id": new_boot})
                try:
                    proof = self.backend.recover_partition(lease, old_boot, new_boot)
                except Exception as exc:
                    proof = CleanupProof(False, self.clock(), lease_id, generation, tuple(lease["resources"]),
                                         {"error": str(exc), "scope": "partition recovery failed; capacity held"})
                return self._apply_cleanup(lease, proof)
            if lease["mode"] == "gpu_configuration":
                # Reapply the journaled desired plan after fencing old commands.
                plan = (lease["workload"] or {}).get("mig_plan")
                if plan is None:
                    raise Error("missing_recovery_plan", "no journaled MIG recovery plan exists")
                snapshot = self.backend.configure_mig(lease, plan)
                rows = [r.record() for r in snapshot.resources]
                parents = {r["id"]: r["parent"] for r in rows}
                baseline = [r for r in rows if overlap(set(lease["resources"]), {r["id"]}, parents)]
            else:
                baseline = lease["baseline"]
            with self.store.transaction(self.clock()) as db:
                lease = Store.update(db, Store.lease(db, lease_id), self.clock(), state="draining", baseline=baseline,
                                     runtime={"lease_id": lease_id, "generation": generation, "recovery_boot_id": new_boot})
                Store.event(db, self.clock(), lease, "recovery_execution_fenced", {"previous_boot_id": old_boot, "boot_id": new_boot})
            return self._finish_local(lease)

    def _drain(self, lease_id, generation, request_key, reason):
        with self.store.transaction(self.clock()) as db:
            lease = Store.lease(db, lease_id)
            if self._operation(db, lease, generation, "drain", request_key, {"reason": reason}):
                return lease
            if lease["state"] == "released":
                return lease
            lease = Store.update(db, lease, self.clock(), state="quarantined" if self._native_handoff(lease) else "draining", error=reason)
            Store.event(db, self.clock(), lease, "drain_requested", {"reason": reason})
            return lease

    def drain(self, lease_id, *, generation, request_key, reason="operator_reclaim"):
        with self.authority():
            return self._drain(lease_id, generation, request_key, reason)

    def _finish_local(self, lease):
        if lease["owner"] != "local":
            raise Error("bridge_cleanup_required", "external allocation requires exact platform cleanup evidence", 403)
        if lease["state"] == "released":
            return lease
        if self._native_handoff(lease):
            raise Error("native_return_unsupported", "native ownership cannot be returned by process inventory, TTL or a local cleanup assertion", 409)
        # An interrupted launch can leave a daemon request in flight. A clean
        # process listing alone cannot prove that request will never execute.
        if lease["state"] == "starting" or (not lease["runtime"] and lease["workload"]):
            raise Error("uncertain_launch", "interrupted launch needs explicit backend recovery evidence; resource remains held")
        with self.store.transaction(self.clock()) as db:
            lease = Store.update(db, Store.lease(db, lease["id"]), self.clock(), state="verifying")
        try:
            proof = self.backend.cleanup(lease)
        except Exception as exc:
            proof = CleanupProof(False, self.clock(), lease["id"], lease["generation"], tuple(lease["resources"]), {"error": str(exc)})
        return self._apply_cleanup(lease, proof)

    def _apply_cleanup(self, lease, proof, additional=None):
        valid = (isinstance(proof, CleanupProof) and proof.lease_id == lease["id"]
                 and proof.generation == lease["generation"]
                 and set(proof.resource_ids) == set(lease["resources"])
                 and math.isfinite(proof.observed_at) and abs(self.clock() - proof.observed_at) <= 30)
        clean = valid and proof.clean is True
        detail = proof.record() if isinstance(proof, CleanupProof) else {"error": "invalid backend cleanup proof"}
        if additional:
            detail["bridge"] = additional
        with self.store.transaction(self.clock()) as db:
            current = Store.lease(db, lease["id"])
            self._fence(current, lease["generation"])
            current = Store.update(db, current, self.clock(), state="released" if clean else "quarantined",
                                   cleanup=detail, error=None if clean else "clean handback has not been verified")
            Store.event(db, self.clock(), current, "released" if clean else "cleanup_failed", detail)
            return current

    def release(self, lease_id, *, generation, request_key):
        with self.authority():
            with self.store.transaction(self.clock()) as db:
                lease = Store.lease(db, lease_id)
                self._fence(lease, generation)
                if self._native_handoff(lease):
                    raise Error("native_return_unsupported", "native handoff stays held until a supported out-of-band return fence exists", 409)
                if self._operation(db, lease, generation, "release", request_key, {}):
                    return lease
                if lease["owner"] != "local":
                    raise Error("bridge_cleanup_required", "external handback belongs to the bridge", 403)
            return self._finish_local(lease)

    def reconcile(self):
        """No timeout ever establishes clean ownership. Unknown execution stays held."""
        with self.authority():
            self._inventory()
            return self._reconcile_leases()

    def maintain_leases(self):
        """Keep expiry/recovery fencing independent of optional inventory refresh.

        Admission and cleanup obtain their own fresh hardware evidence. Status
        retains the last explicitly observed inventory and its original time.
        """
        with self.authority():
            # Keep the periodic durable clock-regression fence formerly supplied
            # by the inventory transaction, even when no lease changes state.
            with self.store.transaction(self.clock()):
                pass
            return self._reconcile_leases()

    def _reconcile_leases(self):
        # Both callers hold the same host authority lock throughout this loop.
        with self.store.connection() as db:
            leases = [Store.decode(r) for r in db.execute("SELECT * FROM leases WHERE state!='released'")]
        outcomes = []
        for lease in leases:
            if lease["state"] == "starting":
                with self.store.transaction(self.clock()) as db:
                    lease = Store.update(db, Store.lease(db, lease["id"]), self.clock(), state="quarantined",
                                         error="interrupted launch requires backend recovery evidence")
                    Store.event(db, self.clock(), lease, "recovery_quarantine", {})
            elif lease["expires_at"] <= self.clock() and lease["state"] not in {"draining", "verifying", "quarantined"}:
                lease = self._drain(lease["id"], lease["generation"], f"expiry:{lease['generation']}", "lease_expired")
            if lease["owner"] == "local" and lease["state"] in {"draining", "verifying"}:
                try:
                    lease = self._finish_local(lease)
                except Error as exc:
                    with self.store.transaction(self.clock()) as db:
                        lease = Store.update(db, Store.lease(db, lease["id"]), self.clock(), state="quarantined", error=str(exc))
                        Store.event(db, self.clock(), lease, "reconciliation_held", {"error": str(exc)})
            outcomes.append(lease)
        return {"leases": outcomes}

    def bridge_policy(self, *, enabled, policy_revision, consent_reference, authorization_id, expires_at):
        if not self.bridge_enabled:
            raise Error("bridge_disabled", "trusted platform bridge is not configured", 403)
        if type(enabled) is not bool or type(policy_revision) is not int or policy_revision < 1:
            raise Error("invalid_request", "enabled and policy_revision have invalid types", 400)
        key(authorization_id, "authorization_id")
        if not isinstance(consent_reference, str) or not 1 <= len(consent_reference) <= 512:
            raise Error("invalid_request", "a verified consent reference is required", 400)
        expires_at = finite_time(expires_at, "expires_at")
        if enabled and expires_at <= self.clock():
            raise Error("invalid_expiry", "authorization is already expired", 400)
        with self.authority(), self.store.transaction(self.clock()) as db:
            if enabled:
                for row in db.execute("SELECT * FROM leases WHERE state!='released'"):
                    if self._native_handoff(Store.decode(row)):
                        raise Error("native_handoff_active", "native handoff needs an out-of-band return fence before participation", 409)
            if enabled:
                # The same commit records exposure before publishing any enabled policy.
                # Disabled/current state can never prove absence of past participation.
                db.execute("INSERT OR REPLACE INTO meta VALUES('participation_history','ever_enabled')")
                db.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
            old = db.execute("SELECT * FROM bridge_policy WHERE singleton=1").fetchone()
            values = (int(enabled), policy_revision, consent_reference, authorization_id, expires_at)
            if old and policy_revision <= old["policy_revision"]:
                if tuple(old[k] for k in ("enabled", "policy_revision", "consent_reference", "authorization_id", "expires_at")) == values:
                    return dict(old)
                raise Error("stale_policy", "policy revision must increase monotonically")
            db.execute("INSERT INTO bridge_policy VALUES(1,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET "
                       "enabled=excluded.enabled,policy_revision=excluded.policy_revision,consent_reference=excluded.consent_reference,"
                       "authorization_id=excluded.authorization_id,expires_at=excluded.expires_at,updated_at=excluded.updated_at",
                       (*values, self.clock()))
            db.execute("INSERT OR REPLACE INTO meta VALUES('connected_mode_seen','1')")
            # Policy changes stop all current external admissions until explicitly renewed.
            for row in db.execute("SELECT * FROM leases WHERE owner='external' AND state!='released'").fetchall():
                lease = Store.update(db, Store.decode(row), self.clock(), state="draining", error="operator_policy_changed")
                Store.event(db, self.clock(), lease, "bridge_policy_changed", {"policy_revision": policy_revision})
            return dict(db.execute("SELECT * FROM bridge_policy WHERE singleton=1").fetchone())

    def bridge_admit(self, lease_id, *, generation, platform_lease_id, policy_revision):
        """Check immediately before every nodusd external admission, not only at claim."""
        if not self.bridge_enabled:
            raise Error("bridge_disabled", "trusted platform bridge is not configured", 403)
        with self.authority(), self.store.transaction(self.clock()) as db:
            lease = Store.lease(db, lease_id)
            self._fence(lease, generation)
            self._policy(db, expected_revision=policy_revision)
            if (lease["owner"] != "external" or lease["mode"] != "exclusive_host"
                    or lease["authorization"]["platform_lease_id"] != platform_lease_id
                    or lease["authorization"]["policy_revision"] != policy_revision
                    or lease["expires_at"] <= self.clock() or lease["state"] not in {"reserved", "active"}):
                raise Error("external_admission_denied", "external lease is expired, draining, stale or mismatched", 403)
            if lease["state"] == "reserved":
                lease = Store.update(db, lease, self.clock(), state="active")
                Store.event(db, self.clock(), lease, "bridge_admitted", {"platform_lease_id": platform_lease_id})
            return lease

    @staticmethod
    def _platform_key(platform_lease_id, platform_epoch):
        key(platform_lease_id, "platform_lease_id")
        if type(platform_epoch) is not int or platform_epoch < 1:
            raise Error("invalid_request", "platform_epoch must be a positive integer", 400)
        return platform_lease_id, platform_epoch

    @staticmethod
    def _claim_response(row, lease=None):
        return {"lease_id": row["lease_id"], "generation": row["generation"] or 0,
                "platform_lease_id": row["platform_lease_id"], "platform_epoch": row["platform_epoch"],
                "policy_revision": row["policy_revision"],
                "retired": bool(row["retired"]),
                "held": lease is not None and lease["state"] != "released",
                "state": lease["state"] if lease else "retired"}

    def bridge_status(self):
        if not self.bridge_enabled:
            return {"available": False, "policy_revision": 0, "reason": "bridge_disabled"}
        if self.bridge_health_error:
            return {"available": False, "policy_revision": self.bridge_policy_state()["policy_revision"], "reason": "bridge_unhealthy"}
        try:
            self._check_bridge_authorization()
        except Error as exc:
            return {"available": False, "policy_revision": self.bridge_policy_state()["policy_revision"], "reason": exc.code}
        with self.authority():
            self._inventory()
            with self.store.connection() as db:
                policy = db.execute("SELECT * FROM bridge_policy WHERE singleton=1").fetchone()
                revision = policy["policy_revision"] if policy else 0
                if not policy or not policy["enabled"] or policy["expires_at"] <= self.clock():
                    return {"available": False, "policy_revision": revision, "reason": "operator_authorization_required"}
                if db.execute("SELECT 1 FROM leases WHERE state!='released' LIMIT 1").fetchone():
                    return {"available": False, "policy_revision": revision, "reason": "host_allocation_held"}
            ready = self.backend.host_ready_for_external()
            return {"available": ready, "policy_revision": revision, "reason": "ready" if ready else "host_not_clean"}

    def bridge_inspect(self, *, platform_lease_id, platform_epoch):
        identity = self._platform_key(platform_lease_id, platform_epoch)
        if not self.bridge_enabled:
            raise Error("bridge_disabled", "trusted platform bridge is not configured", 403)
        with self.store.connection() as db:
            row = db.execute("SELECT * FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?", identity).fetchone()
            if row is None:
                return {"held": False, "generation": 0, "retired": False, "platform_lease_id": identity[0],
                        "platform_epoch": identity[1], "lease_id": None}
            lease = Store.lease(db, row["lease_id"]) if row["lease_id"] else None
            return self._claim_response(row, lease)

    def bridge_claim(self, *, platform_lease_id, platform_epoch, policy_revision,
                     idempotency_key, expires_at=None, workload_image="", workload_kind=""):
        identity = self._platform_key(platform_lease_id, platform_epoch)
        key(idempotency_key, "idempotency_key")
        if (not isinstance(workload_image, str) or len(workload_image) > 1024 or "\0" in workload_image
                or not isinstance(workload_kind, str) or len(workload_kind) > 64 or "\0" in workload_kind):
            raise Error("invalid_workload_metadata", "workload image/kind must be bounded strings", 400)
        if type(policy_revision) is not int or policy_revision < 1:
            raise Error("invalid_request", "policy_revision must be a positive integer", 400)
        if not self.bridge_enabled:
            raise Error("bridge_disabled", "trusted platform bridge is not configured", 403)
        with self.authority():
            with self.store.connection() as db:
                row = db.execute("SELECT * FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?", identity).fetchone()
                if row:
                    if row["policy_revision"] is not None and row["policy_revision"] != policy_revision:
                        raise Error("idempotency_conflict", "platform tuple was used with a different policy")
                    lease = Store.lease(db, row["lease_id"]) if row["lease_id"] else None
                    if lease and (lease["authorization"].get("idempotency_key") != idempotency_key
                                  or expires_at is not None and expires_at != lease["expires_at"]
                                  or lease["authorization"].get("workload_image", "") != workload_image
                                  or lease["authorization"].get("workload_kind", "") != workload_kind):
                        raise Error("idempotency_conflict", "platform tuple was used with different claim inputs")
                    return self._claim_response(row, lease)
                self._check_bridge_authorization(workload_image=workload_image, workload_kind=workload_kind)
                policy = self._policy(db, expected_revision=policy_revision)
            snapshot = self._inventory()
            if not self.backend.host_ready_for_external():
                raise Error("host_not_clean", "host has activity or configuration incompatible with exclusive lending")
            authorization = {"platform_lease_id": platform_lease_id, "platform_epoch": platform_epoch,
                             "policy_revision": policy_revision, "authorization_id": policy["authorization_id"],
                             "consent_reference": policy["consent_reference"], "idempotency_key": idempotency_key,
                             "workload_image": workload_image, "workload_kind": workload_kind}
            expiry = min(policy["expires_at"], self.clock() + 86400) if expires_at is None else expires_at
            lease = self._reserve([snapshot["host_id"]], "exclusive_host", expiry,
                                  "bridge:" + digest(identity), owner="external", authorization=authorization)
            return {"lease_id": lease["id"], "generation": lease["generation"], "platform_lease_id": platform_lease_id,
                    "platform_epoch": platform_epoch, "policy_revision": policy_revision,
                    "held": True, "retired": False, "state": lease["state"]}

    def bridge_check(self, *, platform_lease_id, platform_epoch, generation):
        identity = self._platform_key(platform_lease_id, platform_epoch)
        if not self.bridge_enabled:
            raise Error("bridge_disabled", "trusted platform bridge is not configured", 403)
        with self.store.connection() as db:
            row = db.execute("SELECT * FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?", identity).fetchone()
        if row is None or row["retired"] or not row["lease_id"]:
            return {"authorized": False, "reason": "claim_absent_or_retired"}
        try:
            lease = self.bridge_admit(row["lease_id"], generation=generation,
                                      platform_lease_id=platform_lease_id, policy_revision=row["policy_revision"])
        except Error as exc:
            if exc.code == "clock_regression":
                raise
            return {"authorized": False, "reason": exc.code}
        return {"authorized": True, "generation": lease["generation"], "lease_id": lease["id"],
                "expires_at": lease["expires_at"], "policy_revision": row["policy_revision"]}

    def bridge_reclaim(self, *, platform_lease_id, platform_epoch, generation=None):
        identity = self._platform_key(platform_lease_id, platform_epoch)
        if generation is not None and (type(generation) is not int or generation < 0):
            raise Error("invalid_request", "generation must be a nonnegative integer when supplied", 400)
        if not self.bridge_enabled:
            raise Error("bridge_disabled", "trusted platform bridge is not configured", 403)
        with self.authority(), self.store.transaction(self.clock()) as db:
            row = db.execute("SELECT * FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?", identity).fetchone()
            if row is None:
                db.execute("INSERT INTO platform_claims VALUES(?,?,NULL,NULL,NULL,1,?,?)", (*identity, self.clock(), self.clock()))
                return {"held": False, "retired": True, "generation": 0}
            lease = Store.lease(db, row["lease_id"]) if row["lease_id"] else None
            if lease and generation not in {None, 0}:
                self._fence(lease, generation)
            db.execute("UPDATE platform_claims SET retired=1,updated_at=? WHERE platform_lease_id=? AND platform_epoch=?",
                       (self.clock(), *identity))
            if lease and lease["state"] != "released":
                lease = Store.update(db, lease, self.clock(), state="draining", error="platform_reclaim")
                Store.event(db, self.clock(), lease, "bridge_reclaim", {"platform_epoch": platform_epoch})
            return {"held": lease is not None and lease["state"] != "released", "retired": True,
                    "generation": lease["generation"] if lease else 0}

    def bridge_complete(self, *, platform_lease_id, platform_epoch, cleanup_verified, generation=None):
        identity = self._platform_key(platform_lease_id, platform_epoch)
        if generation is not None and (type(generation) is not int or generation < 0):
            raise Error("invalid_request", "generation must be a nonnegative integer when supplied", 400)
        if not self.bridge_enabled:
            raise Error("bridge_disabled", "trusted platform bridge is not configured", 403)
        if cleanup_verified is not True:
            raise Error("incomplete_cleanup", "bridge did not confirm exact workload termination and cleanup")
        with self.authority():
            with self.store.transaction(self.clock()) as db:
                row = db.execute("SELECT * FROM platform_claims WHERE platform_lease_id=? AND platform_epoch=?", identity).fetchone()
                if row is None:
                    db.execute("INSERT INTO platform_claims VALUES(?,?,NULL,NULL,NULL,1,?,?)", (*identity, self.clock(), self.clock()))
                    return {"released": True, "held": False, "retired": True, "generation": 0}
                if not row["lease_id"]:
                    return {"released": True, "held": False, "retired": True, "generation": 0}
                lease = Store.lease(db, row["lease_id"])
                if generation not in {None, 0}:
                    self._fence(lease, generation)
                if lease["state"] == "released":
                    return {"released": True, "held": False, "retired": True, "generation": lease["generation"]}
                if not row["retired"] or lease["state"] not in {"draining", "quarantined", "verifying"}:
                    raise Error("reclaim_required", "retire the platform claim before confirming handback")
                lease = Store.update(db, lease, self.clock(), state="verifying")
            try:
                proof = self.backend.verify_clean(lease)
            except Exception as exc:
                proof = CleanupProof(False, self.clock(), lease["id"], lease["generation"], tuple(lease["resources"]), {"error": str(exc)})
            lease = self._apply_cleanup(lease, proof, additional={"platform_lease_id": platform_lease_id,
                                        "platform_epoch": platform_epoch, "cleanup_verified": True})
            return {"released": lease["state"] == "released", "held": lease["state"] != "released",
                    "retired": True, "generation": lease["generation"], "state": lease["state"]}
