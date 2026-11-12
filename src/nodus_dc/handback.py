"""One-way native owner return after authoritative platform credential retirement.

The operator controls this host until ready. This is not a provisioning or
post-native-root attestation system. A ready installation can never lend again.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

from .api import token_file
from .connection import Connection, _NoRedirect, _node_uuid
from .errors import Error
from .model import CleanupProof, Snapshot, canonical, key
from .store import Store

# APIKey revocation's documented authentication cache bound is 30 seconds.
# Wait longer, using this process's monotonic clock; no wall-clock restart credit.
REVOCATION_WAIT_SECONDS = 31
SCOPES = frozenset({"pools:read", "nodes:read", "nodes:write", "apikeys:read", "apikeys:write"})
JOURNAL_KEY = "terminal_native_handback"


def exact_effective_scopes(value, stored):
    """WhoAmI includes authz.Effective's implicit reads; APIKey metadata does not."""
    return (isinstance(value, list) and all(isinstance(scope, str) for scope in value)
            and len(value) == len(set(value))
            and set(value) == set(stored) | {"models:read", "offerings:read"})


def api_key_metadata(value):
    """Project a GET APIKey object without retaining status or accepting flat aliases."""
    if (not isinstance(value, dict) or set(value) != {"apiVersion", "kind", "metadata", "spec", "status"}
            or value.get("apiVersion") != "nodus.dev/v1" or value.get("kind") != "APIKey"):
        return None
    metadata, spec, status = (value[field] for field in ("metadata", "spec", "status"))
    if not all(isinstance(item, dict) for item in (metadata, spec, status)):
        return None
    if (set(metadata) - {"name", "uid", "creationTimestamp", "labels", "annotations", "resourceVersion",
                         "namespace", "generation", "deletionTimestamp", "finalizers"}
            or set(spec) - {"description", "serviceAccountName", "scopes", "projects", "expirationTime"}
            or set(status) - {"owner", "prefix", "lastUsedTime"}):
        return None
    scopes, projects = spec.get("scopes"), spec.get("projects")
    if (not all(isinstance(metadata.get(field), str) and metadata[field] for field in ("uid", "name"))
            or not isinstance(scopes, list) or not all(isinstance(scope, str) and scope for scope in scopes)
            or len(scopes) != len(set(scopes)) or not isinstance(projects, list)
            or not all(isinstance(project, str) for project in projects)
            or not isinstance(spec.get("serviceAccountName", ""), str)
            or not isinstance(status.get("owner", ""), str)
            or (status.get("owner", "").startswith("sa/") and not spec.get("serviceAccountName"))):
        return None
    return {"uid": metadata["uid"], "name": metadata["name"], "scopes": scopes, "projects": projects,
            "serviceAccountName": spec.get("serviceAccountName", "")}


def node_retirement_proof(journal, status, proof):
    """Affirmative same-org tombstone proof, never absence or DELETE acknowledgement."""
    try:
        timestamp = datetime.fromisoformat(proof.get("nodeIdentityRevokedTime", "").replace("Z", "+00:00"))
        valid_time = timestamp.tzinfo is not None
    except (AttributeError, ValueError, TypeError):
        valid_time = False
    if (status != 200 or not isinstance(proof, dict) or proof.get("apiVersion") != "nodus.dev/v1"
            or proof.get("kind") != "NodeRetirement" or proof.get("retired") is not True
            or proof.get("node") != journal["settings"]["node"] or proof.get("uid") != journal["node_uid"]
            or proof.get("organizationUID") != journal["org_uid"]
            or type(proof.get("credentialGeneration")) is not int or proof["credentialGeneration"] <= 0 or not valid_time):
        raise Error("node_retirement_unverified", "no affirmative retirement proof for the frozen Node identity; keep host quarantined", 409)
    return {name: proof[name] for name in ("apiVersion", "kind", "retired", "node", "uid", "organizationUID",
                                         "credentialGeneration", "nodeIdentityRevokedTime")}


def terminal_retirement(service, lease_id):
    """Read retained handback evidence; this neither grants access nor attests native use.

    Local-only native_handoff and older journals without an affirmative saved
    NodeRetirement are deliberately ineligible. No remote requests or state writes.
    """
    def refuse():
        raise Error("terminal_retirement_unverified", "no matching ready terminal handback proof for this host lease", 409)

    key(lease_id, "lease_id")
    with service.store.connection() as db:
        db.execute("BEGIN")
        row = db.execute("SELECT value FROM meta WHERE key=?", (JOURNAL_KEY,)).fetchone()
        journal = json.loads(row[0]) if row else None
        lease = Store.lease(db, lease_id)
        now = service.clock()
        last = float(db.execute("SELECT value FROM meta WHERE key='last_wall_time'").fetchone()[0])
        if (not isinstance(journal, dict) or journal.get("stage") != "ready"
                or journal.get("lease_id") != lease_id or type(journal.get("generation")) is not int
                or journal["generation"] != lease["generation"] or lease["owner"] != "local"
                or lease["mode"] != "exclusive_host" or lease["state"] != "active" or lease["workload"]
                or not math.isfinite(now) or now + 1 < last or lease["expires_at"] <= now):
            refuse()
        runtime = lease["runtime"]
        expected = {"execution_kind": "native_handoff", "lease_id": lease_id, "generation": journal["generation"],
                    "handback_stage": "ready", "native_access_ready": True, "return_supported": False,
                    "node_uid": journal.get("node_uid"), "credential_uid": journal.get("credential_uid")}
        if (runtime != expected or type(runtime.get("generation")) is not int
                or runtime.get("native_access_ready") is not True or runtime.get("return_supported") is not False
                or not all(isinstance(journal.get(name), str) and journal[name]
                                          for name in ("node_uid", "credential_uid", "org_uid"))
                or not isinstance(journal.get("settings"), dict)):
            refuse()
        evidence = journal.get("evidence", {})
        if not isinstance(evidence, dict):
            refuse()
        retirement = node_retirement_proof(journal, 200, evidence.get("node_retirement_proof"))
        rejection = evidence.get("rejection", {})
        cleanup = evidence.get("final_device_cleanup", {})
        if (not isinstance(rejection, dict) or not isinstance(cleanup, dict)
                or not isinstance(evidence.get("agent"), dict)
                or evidence.get("key_delete") != {"http_status": 204, "uid": journal["credential_uid"]}
                or rejection.get("http_status") != 401
                or type(rejection.get("monotonic_wait_seconds")) not in {int, float}
                or not math.isfinite(rejection["monotonic_wait_seconds"])
                or rejection["monotonic_wait_seconds"] < REVOCATION_WAIT_SECONDS
                or evidence.get("agent", {}).get("stopped") is not True
                or evidence.get("agent", {}).get("disabled") is not True
                or any(item.get("state") != "rejected" for item in journal.get("recovery_keys", []))
                or cleanup.get("clean") is not True or cleanup.get("lease_id") != lease_id
                or type(cleanup.get("generation")) is not int or cleanup["generation"] != lease["generation"]
                or cleanup.get("resource_ids") != lease["resources"]):
            refuse()
        host = db.execute("SELECT value FROM meta WHERE key='host_id'").fetchone()
        snapshot = service.backend.inventory()
        observed_now = service.clock()
        if (not host or not isinstance(snapshot, Snapshot) or snapshot.host_id != host[0]
                or lease["resources"] != [snapshot.host_id] or not math.isfinite(snapshot.observed_at)
                or not math.isfinite(observed_now) or observed_now < now
                or lease["expires_at"] <= observed_now or abs(observed_now - snapshot.observed_at) > 30):
            refuse()
        hosts = [resource for resource in snapshot.resources if resource.kind == "host"]
        if (len(hosts) != 1 or hosts[0].id != snapshot.host_id or hosts[0].parent is not None
                or not isinstance(hosts[0].details.get("boot_id"), str) or not hosts[0].details["boot_id"]):
            refuse()
        return {"schema": "nodus-terminal-retirement-v1", "lease_id": lease_id, "generation": lease["generation"],
                "stage": "ready", "native_access_ready": True, "reconnect_supported": False,
                "node_uid": journal["node_uid"], "credential_uid": journal["credential_uid"],
                "retirement": retirement, "host_id": snapshot.host_id, "boot_id": hosts[0].details["boot_id"]}


def _unique_object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate response field")
        value[name] = item
    return value


def request(method, url, token, body=None):
    """Status-preserving HTTPS, without redirects, proxies or credential logging."""
    data = None if body is None else canonical(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(req, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    except (OSError, urllib.error.URLError):
        raise Error("retirement_unavailable", "platform retirement acknowledgement unavailable", 503) from None
    try:
        with response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("response limit")
            result = json.loads(raw, object_pairs_hook=_unique_object) if raw else None
            return response.code, result
    except (OSError, ValueError):
        raise Error("retirement_protocol", "invalid platform retirement response", 503) from None


def private_file(path, *, missing=False):
    """Bind a known credential file, never discover/copy arbitrary host secrets."""
    path = Path(path)
    if not path.is_absolute() or path != Path(os.path.abspath(path)):
        raise Error("credential_path", "credential path must be canonical and absolute", 409)
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
            raise Error("credential_path", "credential path ancestors must be owned and not writable by others", 409)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing:
            return None
        raise Error("credential_missing", "required managed credential file is missing", 409) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Error("credential_permissions", "credential files must be private and owned by the operator", 409)
        raw = os.read(fd, 1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Error("credential_limit", "credential file exceeds limit", 409)
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "device": info.st_dev, "inode": info.st_ino}
    finally:
        os.close(fd)


def observed_binding(settings):
    value = private_file(settings["token_file"])
    return {**{name: settings[name] for name in ("platform_url", "namespace", "pool", "token_file", "node_identity_file")},
            "node_uuid": str(_node_uuid(settings["node"])), "token_sha256": value["sha256"]}


def credential_binding(settings, transport):
    before = observed_binding(settings)
    who = transport("GET", settings["platform_url"] + "/auth/whoami", token_file(settings["token_file"]), None)
    if (not isinstance(who, dict) or who.get("kind") != "APIKey" or who.get("serviceAccount")
            or not exact_effective_scopes(who.get("scopes"), SCOPES) or who.get("projects") not in ([], None)
            or observed_binding(settings) != before):
        raise Error("retirement_credential", "terminal return requires a stable dedicated API key with the exact documented scopes", 409)
    return {**before, "credential_uid": Handback._uuid(who.get("credentialUID")), "org_uid": Handback._uuid(who.get("org"))}


class LinuxAgent:
    """Only the existing official nodusd service; no SSH/account/container changes."""
    def prepare(self, record):
        if os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
            raise Error("native_return_platform", "native return requires root on the installed Linux systemd host", 409)
        if record["node_identity_file"] != "/var/lib/nodus/node.json":
            raise Error("agent_layout_unsupported", "native return currently supports the official nodusd state path only", 409)
        # Enrollment must already have consumed and removed its single-use token.
        if os.path.lexists("/etc/nodus/bootstrap-token"):
            raise Error("bootstrap_credential_present", "resolve the remaining enrollment credential before native return", 409)

    @staticmethod
    def _command(argv):
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=45, check=True, text=True)
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            raise Error("agent_stop_unverified", "nodusd service stop/disable could not be verified", 503) from None

    def stop(self):
        self._command(["systemctl", "disable", "--now", "nodusd.service"])
        state = self._command(["systemctl", "show", "nodusd.service", "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,UnitFileState,Job,KillMode,SendSIGKILL"])
        values = dict(line.split("=", 1) for line in state.splitlines() if "=" in line)
        if (values.get("LoadState") != "loaded" or values.get("ActiveState") != "inactive"
                or values.get("SubState") != "dead" or values.get("MainPID") != "0"
                or values.get("ControlPID") != "0" or values.get("UnitFileState") != "disabled"
                or values.get("Job") not in {"", "0"} or values.get("KillMode") != "control-group"
                or values.get("SendSIGKILL") != "yes"):
            raise Error("agent_stop_unverified", "nodusd is not verified stopped and disabled", 503)
        return {"unit": "nodusd.service", "stopped": True, "disabled": True}


class Handback:
    def __init__(self, service, state_dir, *, transport=None, agent=None, monotonic=time.monotonic, sleep=time.sleep):
        self.service = service
        self.connection = Connection(service, state_dir)
        self.transport = transport or request
        self.agent = agent or LinuxAgent()
        self.monotonic = monotonic
        self.sleep = sleep

    def _load(self):
        with self.service.store.connection() as db:
            row = db.execute("SELECT value FROM meta WHERE key=?", (JOURNAL_KEY,)).fetchone()
            return json.loads(row[0]) if row else None

    def _save(self, journal, stage, **evidence):
        journal = {**journal, "stage": stage, "evidence": {**journal.get("evidence", {}), **evidence}}
        now = self.service.clock()
        with self.service.store.transaction(now) as db:
            lease = Store.lease(db, journal["lease_id"])
            self.service._fence(lease, journal["generation"])
            runtime = {"execution_kind": "native_handoff", "lease_id": lease["id"], "generation": lease["generation"],
                       "handback_stage": stage, "native_access_ready": stage == "ready", "return_supported": False,
                       "node_uid": journal["node_uid"], "credential_uid": journal["credential_uid"]}
            lease = Store.update(db, lease, now, state="active" if stage == "ready" else "quarantined", runtime=runtime,
                                 error=None if stage == "ready" else "terminal native return incomplete; keep native customer access closed")
            db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (JOURNAL_KEY, canonical(journal)))
            Store.event(db, now, lease, "terminal_native_" + stage, runtime)
        return journal

    def _call(self, journal, method, path, body=None, *, token=None):
        # Token remains in memory only; file reference and its digest live in private state.
        if token is None:
            current = private_file(journal["settings"]["token_file"])
            if current != journal["files"][0]:
                raise Error("credential_changed", "the bound connection credential changed", 409)
            token = token_file(current["path"])
        return self.transport(method, journal["settings"]["platform_url"] + path, token, body)

    @staticmethod
    def _uuid(value):
        try:
            return str(uuid.UUID(value))
        except (ValueError, TypeError, AttributeError):
            raise Error("retirement_identity", "platform identity is not a UUID", 409) from None

    def _prepare(self, lease_id, generation, request_key, api_key_name):
        service = self.service
        if hasattr(service.backend, "require_management"):
            service.backend.require_management()
        lease = service.get(lease_id)
        service._fence(lease, generation)
        if (lease["owner"] != "local" or lease["mode"] != "exclusive_host" or lease["state"] != "reserved"
                or lease["expires_at"] <= service.clock() or lease["runtime"] or lease["workload"]):
            raise Error("native_handoff_requires_host", "native return requires a current unused local exclusive-host lease", 409)
        with service.store.connection() as db:
            if db.execute("SELECT 1 FROM leases WHERE state!='released' AND id!=?", (lease_id,)).fetchone():
                raise Error("native_return_busy", "every other local/external allocation must be released", 409)
        record = self.connection._load()
        if not record or record.get("connected") is not False or record.get("active") is not False or service.bridge_policy_state()["enabled"]:
            raise Error("disconnect_required", "disconnect local participation after reclaim before terminal native return", 409)
        self.connection._verify_identity(record)
        Connection._settings(**{name: record[name] for name in ("platform_url", "namespace", "pool", "node", "token_file")})
        self.agent.prepare(record)
        files = [private_file(record[name]) for name in ("token_file", "node_identity_file")]
        if files[0]["path"] == files[1]["path"]:
            raise Error("credential_path", "connection and node credentials must be distinct", 409)
        settings = {name: record[name] for name in ("platform_url", "namespace", "pool", "node", "token_file", "node_identity_file")}
        journal = {"lease_id": lease_id, "generation": generation, "request_key": request_key,
                   "api_key_name": api_key_name, "settings": settings, "files": files}
        status, who = self._call(journal, "GET", "/auth/whoami")
        if (status != 200 or not isinstance(who, dict) or who.get("kind") != "APIKey" or who.get("serviceAccount")
                or not exact_effective_scopes(who.get("scopes"), SCOPES) or who.get("projects") not in ([], None)):
            raise Error("retirement_credential", "use the current dedicated API key with exactly the documented retirement scopes; User/SA credentials are unsupported", 409)
        journal["credential_uid"] = self._uuid(who.get("credentialUID"))
        journal["org_uid"] = self._uuid(who.get("org"))
        journal["key_path"] = "/apis/nodus.dev/v1/apikeys/" + urllib.parse.quote(api_key_name, safe="")
        self._verify_key(journal)
        with service.store.connection() as db:
            row = db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()
            participation = db.execute("SELECT value FROM meta WHERE key='participation_history'").fetchone()
            prior_external = (db.execute("SELECT 1 FROM platform_claims").fetchone()
                              or db.execute("SELECT 1 FROM leases WHERE owner='external'").fetchone())
        history = json.loads(row[0]) if row else None
        current_binding = {**observed_binding(settings), "credential_uid": journal["credential_uid"], "org_uid": journal["org_uid"]}
        if not history or history.get("eligible") is not True or history.get("binding") != current_binding:
            raise Error("native_credential_history_unqualified", "automatic terminal return requires a fresh dev2 connection with one continuously tracked dedicated key; legacy/rotated credentials need external retirement", 409)
        journal["credential_binding"] = current_binding
        quote = lambda value: urllib.parse.quote(value, safe="")
        path = "/apis/nodus.dev/v1/namespaces/" + quote(record["namespace"]) + "/pools/" + quote(record["pool"]) + "/sharing?node=" + quote(record["node"])
        status, sharing = self._call(journal, "GET", path)
        consent = sharing.get("consent") if isinstance(sharing, dict) else None
        if (status != 200 or not isinstance(sharing, dict) or sharing.get("accepting") is not False
                or record["node"] not in sharing.get("nodes", []) or type(sharing.get("generation")) is not int):
            raise Error("remote_revocation_required", "this exact enrolled host must not be accepting capacity work", 409)
        never_enabled = (participation is not None and participation[0] == "never_enabled"
                         and not prior_external and record.get("participation") == "disabled")
        if never_enabled:
            if consent is not None and (not isinstance(consent, dict) or not consent.get("revokedTime")):
                raise Error("remote_revocation_required", "existing accepted consent must be revoked before terminal return", 409)
            journal["retirement_basis"] = "never_enabled"
            journal["participation_history"] = "never_enabled"
        else:
            if (not isinstance(consent, dict) or not record.get("consent_id") or not record.get("terms_digest")
                    or consent.get("id") != record["consent_id"] or consent.get("termsDigest") != record["terms_digest"]
                    or not consent.get("revokedTime")):
                raise Error("remote_revocation_required", "revoke this exact host's accepted consent in the console and complete reclaim first", 409)
            journal["consent"] = {"id": consent["id"], "terms_digest": consent["termsDigest"], "generation": sharing["generation"], "revoked_time": consent["revokedTime"]}
        # Inventory can take time. Read the CAS resourceVersion after it, as close
        # as possible to the durable DELETE intent.
        self._verify_clean(lease)
        journal["node_path"] = "/apis/nodus.dev/v1/nodes/" + quote(record["node"])
        status, node = self._call(journal, "GET", journal["node_path"])
        metadata = node.get("metadata", {}) if isinstance(node, dict) else {}
        if (status != 200 or metadata.get("name") != record["node"]
                or _node_uuid(metadata.get("uid")) != _node_uuid(record["node"])
                or not isinstance(metadata.get("resourceVersion"), str) or not metadata["resourceVersion"]):
            raise Error("retirement_identity", "current Node UID/resourceVersion did not match the enrolled host", 409)
        journal["node_uid"] = metadata["uid"]
        journal["node_uuid"] = str(_node_uuid(metadata["uid"]))
        journal["node_resource_version"] = metadata["resourceVersion"]
        return self._save(journal, "prepared")

    def _verify_key(self, journal):
        status, value = self._call(journal, "GET", journal["key_path"])
        metadata = api_key_metadata(value)
        if (status != 200 or not isinstance(metadata, dict) or metadata.get("name") != journal["api_key_name"]
                or metadata.get("uid") != journal["credential_uid"] or metadata.get("serviceAccountName")
                or set(metadata.get("scopes", [])) != SCOPES or metadata.get("projects") not in ([], None)):
            raise Error("retirement_identity", "exact current API key UID, name and scopes could not be verified", 409)

    def _verify_clean(self, lease):
        proof = self.service.backend.verify_clean(lease)
        if (not isinstance(proof, CleanupProof) or proof.clean is not True or proof.lease_id != lease["id"]
                or type(proof.generation) is not int or proof.generation != lease["generation"] or set(proof.resource_ids) != set(lease["resources"])
                or type(proof.observed_at) not in {int, float} or not math.isfinite(proof.observed_at)
                or abs(self.service.clock() - proof.observed_at) > 30):
            raise Error("native_cleanup_unverified", "device and workload cleanup has not been verified; host remains held", 409)
        return proof.record()

    def run(self, lease_id, *, generation, request_key, api_key_name, recover=False,
            recovery_token_file=None, recovery_api_key_name=None):
        key(request_key, "request_key")
        key(api_key_name, "api_key_name")
        if recovery_api_key_name:
            key(recovery_api_key_name, "recovery_api_key_name")
        if (recovery_token_file or recovery_api_key_name) and not recover:
            raise Error("recovery_explicit", "recovery credentials require --recover", 409)
        # Same order as Connection.sync: connection lock before the host authority.
        # Admission and local starts remain serialized during verification/retirement.
        with self.connection._locked(), self.service.authority():
            journal = self._load()
            if journal:
                if any(journal[name] != value for name, value in (("lease_id", lease_id), ("generation", generation),
                            ("request_key", request_key), ("api_key_name", api_key_name))):
                    raise Error("handback_conflict", "terminal handback is bound to a different immutable request", 409)
                self.service._fence(self.service.get(lease_id), generation)
            else:
                if recover:
                    raise Error("recovery_journal_required", "recovery requires an existing frozen handback journal", 409)
                journal = self._prepare(lease_id, generation, request_key, api_key_name)
            if recover and journal["stage"] in {"prepared", "node_delete_pending", "node_retired", "key_delete_pending", "key_revoked", "key_rejected"}:
                from .recovery import Recovery
                journal = Recovery(self).run(journal, recovery_token_file, recovery_api_key_name)
            elif recover and (recovery_token_file or recovery_api_key_name):
                raise Error("recovery_stage", "no new recovery credential may be introduced after agent shutdown", 409)
            elif any(item["state"] != "rejected" for item in journal.get("recovery_keys", [])):
                raise Error("recovery_required", "tracked recovery keys remain retirement obligations; resume with --recover", 409)
            if journal["stage"] in {"node_delete_pending", "key_delete_pending"}:
                raise Error("retirement_uncertain", "remote deletion outcome is uncertain; keep host quarantined for external operator API reconciliation", 409)
            if journal["stage"] == "prepared":
                journal = self._save(journal, "node_delete_pending")
                status, ack = self._call(journal, "DELETE", journal["node_path"] + "?propagationPolicy=Background",
                    {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background",
                     "preconditions": {"uid": journal["node_uid"], "resourceVersion": journal["node_resource_version"]}})
                details = ack.get("details", {}) if isinstance(ack, dict) else {}
                if (status != 200 or not isinstance(ack, dict) or ack.get("kind") != "Status" or ack.get("status") != "Success"
                        or details.get("uid") != journal["node_uid"] or details.get("name") != journal["settings"]["node"]
                        or details.get("kind") != "nodes" or details.get("group") != "nodus.dev"):
                    raise Error("node_retirement_unverified", "exact Node retirement acknowledgement missing; host remains quarantined", 409)
                journal = self._save(journal, "node_delete_pending", node_delete=ack)
                status, proof = self._call(journal, "GET", journal["node_path"] + "/retirement?uid="
                                           + urllib.parse.quote(journal["node_uid"], safe=""))
                journal = self._save(journal, "node_retired", node_retirement_proof=node_retirement_proof(journal, status, proof))
            if journal["stage"] == "node_retired":
                # Older ever-enabled journals retained only the DELETE ACK.
                # Fetch affirmative proof while their dedicated key still exists.
                evidence = journal.get("evidence", {})
                if "node_retirement_proof" not in evidence:
                    status, proof = self._call(journal, "GET", journal["node_path"] + "/retirement?uid="
                                               + urllib.parse.quote(journal["node_uid"], safe=""))
                    journal = self._save(journal, "node_retired", node_retirement_proof=node_retirement_proof(journal, status, proof))
                else:
                    node_retirement_proof(journal, 200, evidence["node_retirement_proof"])
                self._verify_key(journal)
                journal = self._save(journal, "key_delete_pending")
                status, _ = self._call(journal, "DELETE", journal["key_path"])
                if status != 204:
                    raise Error("key_retirement_unverified", "exact API key retirement acknowledgement missing; host remains quarantined", 409)
                journal = self._save(journal, "key_revoked", key_delete={"http_status": 204, "uid": journal["credential_uid"]})
            if journal["stage"] == "key_revoked":
                started = self.monotonic()
                while (remaining := REVOCATION_WAIT_SECONDS - (self.monotonic() - started)) > 0:
                    self.sleep(min(remaining, 1))
                status, _ = self._call(journal, "GET", "/auth/whoami")
                if status != 401:
                    raise Error("key_still_authorized", "revoked API key did not return authenticated HTTP401 after the full cache bound", 409)
                journal = self._save(journal, "key_rejected", rejection={"http_status": 401, "monotonic_wait_seconds": self.monotonic() - started})
            if journal["stage"] == "key_rejected":
                self.agent.prepare(journal["settings"])
                stopped = self.agent.stop()
                if stopped.get("stopped") is not True or stopped.get("disabled") is not True:
                    raise Error("agent_stop_unverified", "agent stop proof was not affirmative", 409)
                journal = self._save(journal, "agent_stopped", agent=stopped)
            if journal["stage"] == "agent_stopped":
                # Recheck on every resumed removal attempt; no new agent may hold credentials.
                self.agent.stop()
                for expected in journal["files"]:
                    current = private_file(expected["path"], missing=True)
                    if current is not None:
                        if current != expected:
                            raise Error("credential_changed", "managed credential changed after retirement; do not remove a different credential", 409)
                        Path(expected["path"]).unlink()
                        fd = os.open(Path(expected["path"]).parent, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                journal = self._save(journal, "credentials_removed")
            if journal["stage"] == "credentials_removed":
                self.agent.prepare(journal["settings"])
                self.agent.stop()
                if any(os.path.lexists(item["path"]) for item in journal["files"]):
                    raise Error("credential_reappeared", "a managed credential reappeared; native grant remains blocked", 409)
                proof = self._verify_clean(self.service.get(lease_id))
                journal = self._save(journal, "ready", final_device_cleanup=proof)
            return {"lease_id": lease_id, "generation": generation, "stage": journal["stage"],
                    "native_access_ready": journal["stage"] == "ready", "reconnect_supported": False,
                    "node_uid": journal["node_uid"], "credential_uid": journal["credential_uid"]}
