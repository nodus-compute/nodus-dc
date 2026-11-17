"""Explicit partition permission delivered over the existing private bridge.

This provider is not installed by the production service. Positive permission is
process-local; SQLite and the independent registry retain only replay/retirement
authority. Neither a persisted grant nor whole-host consent can enable execution.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import time
import uuid
from urllib.parse import urlsplit

from .errors import Error
from .model import canonical
from .partitions import MAX, _PolicyExpiry, fields, guid, integer, sha
from .store import Store

MAX_VALID_NS = 30_000_000_000
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}")


def _deny(code="partition_policy_unavailable", message="current independent partition permission is required", status=403):
    raise Error(code, message, status)


def _object(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise ValueError("duplicate field")
        out[key] = value
    return out


def _text(value, maximum):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        _deny("invalid_request", "partition terms text is invalid", 400)


def images(value):
    if value is None: return None
    if (not isinstance(value, list) or len(value) > 16 or any(not isinstance(v, str)
            or len(v.encode("utf-8")) > 512 or not IMAGE.fullmatch(v) for v in value)
            or len(set(value)) != len(value)):
        _deny("invalid_request", "partition image restriction is invalid", 400)
    return value


def agreement(value):
    fields(value, "node_id consent_id generation terms_sha256")
    if not isinstance(value["node_id"], str) or not re.fullmatch(r"bnod_[0-7][0-9a-hjkmnp-tv-z]{25}", value["node_id"]):
        _deny("invalid_request", "partition node identity is invalid", 400)
    guid(value["consent_id"]); integer(value["generation"], 1); sha(value["terms_sha256"])
    return value


def terms(raw, expected_sha):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 24*1024:
        _deny("invalid_request", "partition terms exceed the bounded delivery contract", 400)
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != expected_sha:
        _deny("invalid_request", "partition terms digest differs", 400)
    try:
        value = json.loads(raw, object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (ValueError, TypeError):
        _deny("invalid_request", "partition terms JSON is invalid", 400)
    fields(value, "contract revision partitionPricing compensation ownerShareBasisPoints reclaimNoticeSeconds agreementURL")
    if value["contract"] != "MIGPartitionV1" or value["compensation"] not in ("Credits", "CashUSD"):
        _deny("invalid_request", "partition terms contract is invalid", 400)
    _text(value["revision"], 128)
    integer(value["ownerShareBasisPoints"], 1, 10000); integer(value["reclaimNoticeSeconds"], 0, 120)
    try:
        url = urlsplit(value["agreementURL"])
        if url.scheme != "https" or not url.netloc or url.username is not None or url.password is not None: raise ValueError()
    except (TypeError, ValueError, AttributeError):
        _deny("invalid_request", "partition agreement URL is invalid", 400)
    pricing = value["partitionPricing"]; fields(pricing, "version shapes"); _text(pricing["version"], 128)
    if not isinstance(pricing["shapes"], list) or not 1 <= len(pricing["shapes"]) <= 128:
        _deny("invalid_request", "partition price shapes are invalid", 400)
    seen = set()
    for row in pricing["shapes"]:
        fields(row, "shape hourlyUSD"); shape = row["shape"]
        fields(shape, "accelerator profile gpuMemoryBytes cpuMillis memoryBytes scratchBytes")
        _text(shape["accelerator"], 128)
        if shape["accelerator"].strip() != shape["accelerator"]: _deny("invalid_request", "accelerator contains whitespace", 400)
        _text(shape["profile"], 32)
        if not re.fullmatch(r"[1-9][0-9]*g\.[1-9][0-9]*gb", shape["profile"]): _deny("invalid_request", "MIG profile is invalid", 400)
        for name in ("gpuMemoryBytes", "cpuMillis", "memoryBytes"): integer(shape[name], 1)
        integer(shape["scratchBytes"], 0, shape["memoryBytes"])
        key = canonical(shape)
        if key in seen: _deny("invalid_request", "partition price shape is duplicated", 400)
        seen.add(key)
        price = row["hourlyUSD"]
        if not isinstance(price, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,6})?", price):
            _deny("invalid_request", "partition price is invalid", 400)
        whole, _, fraction = price.partition(".")
        if len(whole.lstrip("0")) > 13: _deny("invalid_request", "partition price overflows", 400)
        micros = int(whole.lstrip("0") or "0")*1_000_000 + int(fraction.ljust(6, "0") or "0")
        integer(micros, 1)
    return value


class PartitionPolicy:
    """Explicitly installed seam; identity and local restrictions are trusted callbacks.

    identity() returns exactly node_id and host_epoch from verified enrollment.
    local_images() returns the operator's independent partition image restriction.
    Neither callback may perform network calls while the host authority is locked.
    """
    def __init__(self, service, *, identity, local_images, boot_id, boottime_ns=None):
        guid(boot_id)
        self.service, self.identity, self.local_images = service, identity, local_images
        self.context = {"nonce": str(uuid.uuid4()), "boot_id": boot_id}
        self.boottime_ns = boottime_ns or (lambda: time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        self.live = None
        self.closed_sessions = set()

    @staticmethod
    def _session_key(scope):
        return scope["node_id"],scope["host_epoch"],scope["stream_epoch"],scope["nonce"]

    def _expire(self, db, scope):
        self.live = None
        self.closed_sessions.add(self._session_key(scope))
        closed = {**scope, "closed":True}
        self._retire(db, self.service.clock(), revision=scope["revision"])
        db.execute("UPDATE meta SET value=? WHERE key='partition_policy_scope'", (canonical(closed),))
        def persist():
            # Caller still holds host authority, but its failed request has
            # rolled back. A real commit failure leaves the registry fenced.
            with self.service.store.transaction(self.service.clock()) as current:
                row=current.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()
                if row and json.loads(row[0]) in (scope,closed):
                    self._retire(current,self.service.clock(),revision=scope["revision"])
                    current.execute("UPDATE meta SET value=? WHERE key='partition_policy_scope'", (canonical(closed),))
        raise _PolicyExpiry(persist)

    def read_context(self, **request):
        fields(request, "")
        now = self.boottime_ns(); integer(now)
        return {"context": dict(self.context), "boottime_ns": now}

    def _identity(self, node, epoch):
        integer(epoch)
        try:
            observed = self.identity()
            fields(observed, "node_id host_epoch"); integer(observed["host_epoch"])
        except Exception: _deny()
        if observed != {"node_id": node, "host_epoch": epoch}: _deny("partition_identity_changed", "verified enrollment differs")

    def _scope(self, db, request):
        self._identity(request["node_id"], request["host_epoch"])
        fields(request["context"], "nonce boot_id")
        if request["context"] != self.context: _deny("stale_partition_context", "partition daemon context changed", 409)
        integer(request["stream_epoch"], 1)
        key=(request["node_id"],request["host_epoch"],request["stream_epoch"],self.context["nonce"])
        if key in self.closed_sessions and request["action"] != "session_revoke":
            _deny("stale_partition_session", "partition stream was locally closed", 409)
        raw = db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()
        old = json.loads(raw[0]) if raw else None
        if old:
            if old["node_id"] != request["node_id"] or request["host_epoch"] < old["host_epoch"]:
                _deny("partition_identity_changed", "partition enrollment cannot move backwards", 409)
            if request["host_epoch"] == old["host_epoch"]:
                if request["stream_epoch"] < old["stream_epoch"] or (request["stream_epoch"] == old["stream_epoch"]
                        and ((old["closed"] and request["action"] != "session_revoke") or old["nonce"] != self.context["nonce"])):
                    _deny("stale_partition_session", "partition stream was replaced or closed", 409)
        return old

    @staticmethod
    def _revision(db):
        row = db.execute("SELECT value FROM meta WHERE key='partition_policy_revision'").fetchone()
        revision = int(row[0]) + 1 if row else 1
        integer(revision, 1)
        db.execute("INSERT INTO meta VALUES('partition_policy_revision',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(revision),))
        return revision

    @staticmethod
    def _retire(db, now, *, agreement_value=None, revision=None):
        for row in db.execute("SELECT * FROM partition_claims WHERE retired=0").fetchall():
            request = json.loads(row["request"])
            if (agreement_value is not None and request["offer"]["agreement"] != agreement_value
                    or revision is not None and request["offer"]["policy_revision"] != revision): continue
            db.execute("UPDATE partition_claims SET retired=1,updated_at=? WHERE platform_lease_id=? AND platform_epoch=?", (now,row["platform_lease_id"],row["platform_epoch"]))
            if row["lease_id"]:
                from .partition_binding import retire
                retire(db, row["lease_id"])
                lease = Store.lease(db, row["lease_id"])
                if lease["state"] != "released": Store.update(db, lease, now, state="draining", error="partition_permission_retired")

    def update(self, **request):
        action = request.get("action")
        common = "action context node_id host_epoch stream_epoch"
        extra = {"grant":" grant freshness", "withdraw":" agreement", "session_revoke":""}.get(action)
        if extra is None: _deny("invalid_request", "partition policy action is invalid", 400)
        fields(request, common+extra)
        grant = parsed = consent = local = None; deadline = 0
        if action == "grant":
            grant = request["grant"]; fields(grant, "agreement terms_json allowed_images")
            consent = agreement(grant["agreement"]); images(grant["allowed_images"])
            parsed = terms(grant["terms_json"], consent["terms_sha256"])
            try: local = copy.deepcopy(images(self.local_images()))
            except Exception: _deny()
            fresh = request["freshness"]; fields(fresh, "echoed_boottime_ns valid_for_ns available_until_unix_millis")
            integer(fresh["echoed_boottime_ns"]); integer(fresh["valid_for_ns"], 1, MAX_VALID_NS)
            integer(fresh["available_until_unix_millis"], 1)
            deadline = fresh["echoed_boottime_ns"] + fresh["valid_for_ns"]; integer(deadline)
        elif action == "withdraw": consent = agreement(request["agreement"])
        if consent and consent["node_id"] != request["node_id"]: _deny("invalid_request", "agreement node differs", 400)
        # Match Handler.send_json exactly before any durable mutation. Unicode
        # escaping can expand otherwise valid terms beyond the response bound.
        preview = {"context":request["context"], **{k:request[k] for k in ("node_id","host_epoch","stream_epoch")},
            "state":"session_revoked", "policy_revision":MAX, "grant":grant, "agreement":consent,
            "valid_until_boottime_ns":MAX}
        if len(json.dumps(preview,sort_keys=True,allow_nan=False).encode()) > 65536:
            _deny("invalid_request", "partition update echo exceeds the response bound", 400)
        if not self.service.bridge_enabled: _deny("bridge_disabled", "partition bridge is not configured")
        with self.service.authority():
            self.service.partitions.ensure_durable()
            with self.service.partitions._admission_transaction() as db:
                old = self._scope(db, request)
                scope = {name: request[name] for name in ("node_id", "host_epoch", "stream_epoch")}
                same_session = bool(old and all(old[k] == v for k,v in scope.items()) and old["nonce"] == self.context["nonce"])
                if same_session: scope = dict(old)
                revision = old["revision"] if same_session else self._revision(db)
                if old and not same_session: self._retire(db, self.service.clock(), revision=old["revision"])
                scope.update(nonce=self.context["nonce"], closed=action=="session_revoke", revision=revision)
                key = (request["node_id"], request["host_epoch"], consent["generation"]) if consent else None
                if consent:
                    prior = db.execute("SELECT * FROM partition_policy_grants WHERE node_id=? AND host_epoch=? AND generation=?", key).fetchone()
                    if prior and json.loads(prior["agreement"]) != consent: _deny("partition_policy_conflict", "generation has different agreement", 409)
                    if action == "grant":
                        now = self.boottime_ns(); integer(now)
                        if fresh["echoed_boottime_ns"] > now or deadline <= now or fresh["available_until_unix_millis"] <= self.service.clock()*1000:
                            _deny("partition_policy_expired", "partition freshness is expired or from the future")
                        if same_session and fresh["echoed_boottime_ns"] < old.get("last_echo_ns",0):
                            _deny("stale_partition_freshness", "partition heartbeat moved backwards", 409)
                        high = db.execute("SELECT MAX(generation) FROM partition_policy_grants WHERE node_id=? AND host_epoch=?", key[:2]).fetchone()[0]
                        if high is not None and consent["generation"] < high: _deny("stale_partition_agreement", "older partition generation cannot revive", 409)
                        if prior and prior["retired"]: _deny("partition_policy_retired", "partition agreement was withdrawn", 409)
                        if prior and prior["grant_payload"] != canonical(grant): _deny("partition_policy_conflict", "generation has different immutable grant", 409)
                        # EXPIRY_FENCE: negative deadlines outlive positive memory.
                        if same_session and (old.get("valid_until_boottime_ns",MAX) <= now
                                or old.get("available_until_unix_millis",MAX) <= self.service.clock()*1000):
                            self._expire(db, old)
                        if prior and same_session and (self.live is None or self.live["local_images"] != local):
                            self._retire(db, self.service.clock(), revision=revision)
                            scope["revision"] = self._revision(db)
                        if not prior:
                            if same_session:
                                self._retire(db, self.service.clock(), revision=revision)
                                scope["revision"] = self._revision(db)
                            db.execute("INSERT INTO partition_policy_grants VALUES(?,?,?,?,?,0)", (*key,canonical(consent),canonical(grant)))
                        scope["last_echo_ns"] = fresh["echoed_boottime_ns"]
                        scope["valid_until_boottime_ns"] = deadline
                        scope["available_until_unix_millis"] = fresh["available_until_unix_millis"]
                    else:
                        db.execute("INSERT INTO partition_policy_grants VALUES(?,?,?,?,NULL,1) ON CONFLICT(node_id,host_epoch,generation) DO UPDATE SET retired=1", (*key,canonical(consent)))
                        self._retire(db, self.service.clock(), agreement_value=consent)
                        if self.live and consent["generation"] >= self.live["grant"]["agreement"]["generation"]:
                            # One agreement per enrolled node: a later withdrawn
                            # generation also supersedes an earlier missed grant.
                            self._retire(db, self.service.clock(), revision=self.live["scope"]["revision"])
                else:
                    if old: self._retire(db, self.service.clock(), revision=old["revision"])
                db.execute("INSERT INTO meta VALUES('partition_policy_scope',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (canonical(scope),))
                db.execute("UPDATE meta SET value='5' WHERE key='schema_version' AND CAST(value AS INTEGER)<5")
            # A failed registry/SQLite commit never installs positive permission.
            if action == "grant":
                self.live = {"scope": scope, "grant": copy.deepcopy(grant), "terms": parsed, "deadline": deadline,
                    "available_until": fresh["available_until_unix_millis"], "echo": fresh["echoed_boottime_ns"], "local_images":local}
            elif not same_session or action == "session_revoke" or self.live and consent["generation"] >= self.live["grant"]["agreement"]["generation"]:
                self.live = None
            if action == "session_revoke": self.closed_sessions.add(self._session_key(scope))
            return {"context":dict(self.context), **{k:request[k] for k in ("node_id","host_epoch","stream_epoch")},
                "state":{"grant":"active","withdraw":"withdrawn","session_revoke":"session_revoked"}[action],
                "policy_revision":scope["revision"], "grant":copy.deepcopy(grant), "agreement":copy.deepcopy(consent),
                "valid_until_boottime_ns":deadline}

    def current(self, db, *, expected_revision=None, workload=None):
        live = self.live
        if live is None: _deny()
        self._identity(live["scope"]["node_id"], live["scope"]["host_epoch"])
        now = self.boottime_ns()
        integer(now)
        if (now < live["echo"] or now >= live["deadline"] or self.service.clock()*1000 >= live["available_until"]):
            self._expire(db, live["scope"])
        row = db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()
        if not row or json.loads(row[0]) != live["scope"]: _deny()
        a = live["grant"]["agreement"]
        row = db.execute("SELECT retired FROM partition_policy_grants WHERE node_id=? AND host_epoch=? AND generation=?", (a["node_id"],live["scope"]["host_epoch"],a["generation"])).fetchone()
        if not row or row[0]: _deny()
        high = db.execute("SELECT MAX(generation) FROM partition_policy_grants WHERE node_id=? AND host_epoch=?", (a["node_id"],live["scope"]["host_epoch"])).fetchone()[0]
        if high != a["generation"]: _deny()
        if expected_revision is not None and live["scope"]["revision"] != expected_revision: _deny("stale_policy", "partition policy revision changed", 409)
        try: local = images(self.local_images())
        except Exception: _deny()
        if local != live["local_images"]:
            self.live = None
            _deny("partition_policy_unavailable", "local partition restrictions changed; fresh permission is required")
        if workload:
            image = workload["workload_image"]
            if workload["workload_kind"] != "Job" or not IMAGE.fullmatch(image): _deny("workload_not_permitted", "partition workload is not permitted")
            for allowed in (local, live["grant"]["allowed_images"]):
                if allowed is not None and image not in allowed: _deny("workload_not_permitted", "partition image is outside current restrictions")
        return {"policy_revision":live["scope"]["revision"], "agreement":copy.deepcopy(a),
            "available_until_unix_millis":live["available_until"], "shapes":copy.deepcopy(live["terms"]["partitionPricing"]["shapes"])}
