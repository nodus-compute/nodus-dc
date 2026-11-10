"""Bounded normal-API recovery of a frozen terminal handback journal."""
from datetime import datetime
import urllib.parse

from .api import token_file
from .errors import Error
from .handback import node_retirement_proof, SCOPES, REVOCATION_WAIT_SECONDS, private_file, api_key_metadata, exact_effective_scopes

RECOVERY_SCOPES = SCOPES | {"auditevents:read"}
MAX_RECOVERY_KEYS = 4
MAX_AUDIT_PAGES = 20


class Recovery:
    def __init__(self, handback):
        self.h = handback
        self.j = None

    def save(self, stage=None, **evidence):
        self.j = self.h._save(self.j, stage or self.j["stage"], **evidence)

    def call(self, actor, method, path, body=None):
        if private_file(actor["file"]["path"]) != actor["file"]:
            raise Error("credential_changed", "a tracked recovery credential changed", 409)
        return self.h._call(self.j, method, path, body, token=token_file(actor["file"]["path"]))

    def original(self):
        return {"uid": self.j["credential_uid"], "name": self.j["api_key_name"],
                "file": self.j["files"][0], "path": self.j["key_path"], "scopes": sorted(SCOPES)}

    def identity(self, actor):
        status, who = self.call(actor, "GET", "/auth/whoami")
        if status != 200:
            return False
        if (not isinstance(who, dict) or who.get("kind") != "APIKey" or who.get("serviceAccount")
                or who.get("credentialUID") != actor["uid"] or who.get("org") != self.j["org_uid"]
                or not exact_effective_scopes(who.get("scopes"), actor["scopes"]) or who.get("projects") not in ([], None)):
            raise Error("recovery_identity", "recovery credential no longer matches its exact org, UID and scope binding", 409)
        return True

    def introduce(self, path, name):
        if not path and not name:
            return
        if not path or not name:
            raise Error("recovery_credential", "provide both recovery token file and API key name", 409)
        bound = private_file(path)
        keys = self.j.setdefault("recovery_keys", [])
        for item in keys:
            if item["name"] == name or item["file"]["path"] == path:
                if item["name"] != name or item["file"] != bound:
                    raise Error("recovery_credential_changed", "recovery key name and file binding are immutable", 409)
                self.resolve_identity(item)
                return
        if len(keys) >= MAX_RECOVERY_KEYS or any(item["path"] == path for item in self.j["files"]):
            raise Error("recovery_key_limit", "at most four distinct recovery keys may be tracked; host remains quarantined", 409)
        actor = {"file": bound, "uid": None, "name": name,
                 "path": "/apis/nodus.dev/v1/apikeys/" + urllib.parse.quote(name, safe=""),
                 "scopes": sorted(RECOVERY_SCOPES), "state": "identity_pending"}
        keys.append(actor)
        self.j["files"].append(bound)
        # An authenticated read can expose a live credential too. Persist the
        # unresolved obligation before the first request, even if identity fails.
        self.save(recovery_credentials_tracked=True)
        self.resolve_identity(actor)

    def resolve_identity(self, actor):
        if actor["state"] != "identity_pending":
            return
        status, who = self.call(actor, "GET", "/auth/whoami")
        if status != 200:
            return
        if (status != 200 or not isinstance(who, dict) or who.get("kind") != "APIKey" or who.get("serviceAccount")
                or who.get("org") != self.j["org_uid"] or not exact_effective_scopes(who.get("scopes"), RECOVERY_SCOPES)
                or who.get("projects") not in ([], None)):
            raise Error("recovery_credential", "use a same-org dedicated recovery API key with exactly the documented scopes", 409)
        uid = self.h._uuid(who.get("credentialUID"))
        if (uid == self.j["credential_uid"] or actor["uid"] not in {None, uid}
                or any(item is not actor and item["uid"] == uid for item in self.j["recovery_keys"])):
            raise Error("recovery_credential_changed", "a tracked key cannot be introduced under another file or name", 409)
        actor["uid"] = uid
        self.save(recovery_identity_observed=True)
        status, meta = self.call(actor, "GET", actor["path"])
        self.verify_metadata(actor, status, meta)
        actor["state"] = "active"
        self.save(recovery_identity_verified=True)

    @staticmethod
    def verify_metadata(target, status, meta):
        meta = api_key_metadata(meta)
        if (status != 200 or not isinstance(meta, dict) or meta.get("uid") != target["uid"]
                or meta.get("name") != target["name"] or meta.get("serviceAccountName")
                or set(meta.get("scopes", [])) != set(target["scopes"]) or meta.get("projects") not in ([], None)):
            raise Error("recovery_identity", "exact API key identity could not be verified", 409)

    def actor(self):
        for candidate in [*reversed(self.j.get("recovery_keys", [])), self.original()]:
            if candidate.get("state", "active") == "active" and self.identity(candidate):
                return candidate
        raise Error("recovery_authority_required", "an active same-org recovery key is required to establish retirement; 401 is not proof", 409)

    def node(self, actor):
        status, proof = self.call(actor, "GET", self.j["node_path"] + "/retirement?uid=" + urllib.parse.quote(self.j["node_uid"], safe=""))
        if status == 200:
            self.save("node_retired", node_retirement_proof=node_retirement_proof(self.j, status, proof))
            return
        if status != 409:
            raise Error("node_retirement_unverified", "no affirmative retained Node retirement proof; keep host quarantined", 409)
        status, live = self.call(actor, "GET", self.j["node_path"])
        meta = live.get("metadata", {}) if isinstance(live, dict) else {}
        if (status != 200 or meta.get("uid") != self.j["node_uid"] or meta.get("name") != self.j["settings"]["node"]
                or not isinstance(meta.get("resourceVersion"), str) or not meta["resourceVersion"]):
            raise Error("node_retirement_unverified", "the same live Node cannot be conditionally retired", 409)
        self.j["node_resource_version"] = meta["resourceVersion"]
        self.save("node_delete_pending")
        status, ack = self.call(actor, "DELETE", self.j["node_path"] + "?propagationPolicy=Background",
            {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background",
             "preconditions": {"uid": self.j["node_uid"], "resourceVersion": meta["resourceVersion"]}})
        detail = ack.get("details", {}) if isinstance(ack, dict) else {}
        if (status != 200 or not isinstance(ack, dict) or ack.get("kind") != "Status" or ack.get("status") != "Success"
                or detail.get("uid") != self.j["node_uid"] or detail.get("name") != self.j["settings"]["node"]
                or detail.get("kind") != "nodes" or detail.get("group") != "nodus.dev"):
            raise Error("node_retirement_unverified", "conditional Node retirement acknowledgement is uncertain", 409)
        if self.j.get("retirement_basis") == "never_enabled":
            self.save("node_delete_pending", node_delete=ack)
            status, proof = self.call(actor, "GET", self.j["node_path"] + "/retirement?uid=" + urllib.parse.quote(self.j["node_uid"], safe=""))
            self.save("node_retired", node_retirement_proof=node_retirement_proof(self.j, status, proof))
        else:
            self.save("node_retired", node_delete=ack)

    @staticmethod
    def timestamp(value):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.tzinfo is not None
        except (AttributeError, ValueError, TypeError):
            return False

    def audit(self, actor, target):
        if "auditevents:read" not in actor["scopes"]:
            raise Error("recovery_audit_required", "exact key retirement needs a same-org recovery key with auditevents:read", 409)
        # Query retained history, never infer anything from an absent/expired event.
        query = {"action": "apikeys.delete", "since": "1970-01-01T00:00:00Z", "limit": "1000"}
        seen = set()
        for _ in range(MAX_AUDIT_PAGES):
            status, page = self.call(actor, "GET", "/apis/nodus.dev/v1/auditevents?" + urllib.parse.urlencode(query))
            if status != 200 or not isinstance(page, dict) or not isinstance(page.get("items"), list):
                break
            for event in page["items"]:
                if not isinstance(event, dict) or not isinstance(event.get("target"), dict):
                    continue
                ref = event["target"]
                if (event.get("action") == "apikeys.delete" and event.get("result") == "Success"
                        and ref.get("kind") == "APIKey" and ref.get("uid") == target["uid"] and ref.get("name") == target["name"]
                        and self.timestamp(event.get("time"))):
                    return {"event_uid": self.h._uuid(event.get("uid")), "time": event["time"], "target": ref,
                            "action": "apikeys.delete", "organization_uid": self.j["org_uid"]}
            continuation = page.get("metadata", {}).get("continue")
            if not isinstance(continuation, str) or not continuation or continuation in seen:
                break
            seen.add(continuation)
            query["continue"] = continuation
        raise Error("key_retirement_unverified", "no exact retained key retirement event within the bounded audit scan", 409)

    def retire(self, actor, target, original=False):
        status, meta = self.call(actor, "GET", target["path"])
        if status == 200:
            self.verify_metadata(target, status, meta)
            if original:
                self.save("key_delete_pending")
            else:
                target["state"] = "delete_pending"
                self.save()
            status, _ = self.call(actor, "DELETE", target["path"])
            if status != 204:
                raise Error("key_retirement_unverified", "key deletion remains uncertain; retain the credential obligation", 409)
            proof = {"http_status": 204, "uid": target["uid"]}
        elif status == 404:
            proof = self.audit(actor, target)
        else:
            raise Error("key_retirement_unverified", "exact key state unavailable; retain the credential obligation", 409)
        if original:
            self.save("key_revoked", key_delete=proof)
        else:
            target["state"], target["proof"] = "revoked", proof
            self.save()

    def run(self, journal, token_path=None, key_name=None):
        self.j = journal
        if self.j["stage"] not in {"prepared", "node_delete_pending", "node_retired", "key_delete_pending", "key_revoked", "key_rejected"}:
            raise Error("recovery_stage", "recovery is only available before local credential removal", 409)
        self.introduce(token_path, key_name)
        for item in self.j.get("recovery_keys", []):
            self.resolve_identity(item)
            if item["state"] == "identity_pending":
                if not item["uid"]:
                    raise Error("recovery_identity_unresolved", "introduced credential identity is unresolved; keep host quarantined", 409)
                item["proof"] = self.audit(self.actor(), item)
                item["state"] = "revoked"
                self.save()
        if self.j["stage"] in {"prepared", "node_delete_pending"}:
            self.node(self.actor())
        if self.j["stage"] in {"node_retired", "key_delete_pending"}:
            self.retire(self.actor(), self.original(), original=True)
        if self.j["stage"] not in {"key_revoked", "key_rejected"}:
            raise Error("recovery_stage", "recovery is only available before local credential removal", 409)
        pending = [item for item in self.j.get("recovery_keys", []) if item["state"] not in {"revoked", "rejected"}]
        if pending:
            actor = self.actor()
            # Retire the credential doing reconciliation last.
            for item in sorted(pending, key=lambda item: item["uid"] == actor["uid"]):
                self.retire(actor, item)
        started = self.h.monotonic()
        while (remaining := REVOCATION_WAIT_SECONDS - (self.h.monotonic() - started)) > 0:
            self.h.sleep(min(remaining, 1))
        for item in [self.original(), *self.j.get("recovery_keys", [])]:
            status, _ = self.call(item, "GET", "/auth/whoami")
            if status != 401:
                raise Error("key_still_authorized", "every retired key must return HTTP401 after the full fresh cache wait", 409)
        for item in self.j.get("recovery_keys", []):
            item["state"] = "rejected"
        self.save("key_rejected", rejection={"http_status": 401, "monotonic_wait_seconds": self.h.monotonic() - started},
                  recovery_all_keys_rejected=True)
        return self.j
