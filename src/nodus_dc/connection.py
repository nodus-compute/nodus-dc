"""Explicit, node-bound platform participation. Ordinary local operations never call this module."""
from __future__ import annotations

import contextlib
import fcntl
import json
import math
import os
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from .api import token_file
from .errors import Error
from .model import finite_time, key


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def platform_request(method, url, token, body=None):
    """Verified TLS, no ambient proxy, redirects, response logging or credential forwarding."""
    data = None if body is None else json.dumps(body, allow_nan=False).encode()
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    if method == "POST":
        request.add_header("Idempotency-Key", str(uuid.uuid4()))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=5) as response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise Error("platform_response_limit", "platform response exceeded the supported limit", 503)
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("object required")
            return result
    except urllib.error.HTTPError as exc:
        raise Error("platform_rejected", f"platform request was rejected (HTTP {exc.code})", 503) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise Error("platform_unavailable", "platform connection could not be verified", 503) from None


def _read_private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise Error("insecure_connection_file", "connection files must be private and owned by this user", 503)
        raw = os.read(fd, 1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Error("invalid_connection_file", "connection file is too large", 503)
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise Error("invalid_connection_file", "connection record must be an object", 503)
        return result
    finally:
        os.close(fd)


def _node_uuid(value):
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        if not isinstance(value, str) or not re.fullmatch(r"(?:bnod|nod)_[0-7][0-9abcdefghjkmnpqrstvwxyz]{25}", value):
            raise Error("node_identity_mismatch", "node identity is not a supported Nodus identifier", 409) from None
        alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
        number = 0
        for character in value.split("_", 1)[1]:
            number = number * 32 + alphabet.index(character)
        return uuid.UUID(int=number)


class Connection:
    def __init__(self, service, state_dir, *, transport=None, clock=time.time):
        self.service = service
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.state_dir / "connection.json"
        self.transport = transport or platform_request
        self.clock = clock
        self.service.bridge_authorization_check = self._authorization_current

    @staticmethod
    def _verify_identity(record):
        try:
            identity = _read_private_json(record["node_identity_file"])
            matches = _node_uuid(identity.get("nodeId")) == _node_uuid(record["node"])
        except (Error, OSError, ValueError, KeyError, TypeError):
            matches = False
        if not matches:
            raise Error("node_identity_mismatch", "this host's enrolled identity could not be verified", 409)

    def _authorization_current(self, *, workload_image=None, workload_kind=None):
        # Runs inside allocation checks without taking connection.lock or making network calls.
        # A stalled platform response cannot extend the last verified permission indefinitely.
        record = self._load()
        if (not record or record.get("participation") == "disabled"
                or not record.get("connected") or not record.get("active")):
            return False
        self._verify_identity(record)
        verified = record.get("permission_verified_at")
        fresh = (type(verified) in {int, float} and math.isfinite(verified)
                 and 0 <= self.clock() - verified <= 20 and self.clock() < record["available_until"])
        if not fresh:
            return False
        if workload_image is None and workload_kind is None:
            return True
        if workload_kind == "maintenance" and workload_image == "":
            return True
        allowed = record.get("allowed_images", [])
        if (workload_kind != "Job" or not self._pinned_image(workload_image)
                or allowed is not None and workload_image not in allowed):
            raise Error("workload_not_permitted", "workload kind or pinned image is outside this host's accepted policy", 403)
        return True

    @staticmethod
    def _pinned_image(image):
        return (isinstance(image, str) and len(image) <= 512
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", image) is not None)

    @contextlib.contextmanager
    def _locked(self):
        fd = os.open(self.state_dir / "connection.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _load(self):
        try:
            return _read_private_json(self.path)
        except FileNotFoundError:
            return None

    def _save(self, record):
        temp = self.state_dir / ("connection-" + uuid.uuid4().hex + ".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as out:
                json.dump(record, out, sort_keys=True, allow_nan=False)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp, self.path)
            directory = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temp.unlink(missing_ok=True)

    @staticmethod
    def _settings(platform_url, namespace, pool, node, token_file):
        parsed = urllib.parse.urlsplit(platform_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
            raise Error("invalid_platform_url", "platform URL must be an HTTPS origin without credentials", 400)
        for name, value in (("namespace", namespace), ("pool", pool), ("node", node)):
            key(value, name)
        _node_uuid(node)
        return {"platform_url": platform_url.rstrip("/"), "namespace": namespace, "pool": pool,
                "node": node, "token_file": str(Path(token_file).resolve())}

    def _request(self, settings, method="GET", body=None, *, audit_history=True):
        if audit_history:
            self._audit_credential_history(settings)
        token = token_file(settings["token_file"])
        quote = lambda value: urllib.parse.quote(value, safe="")
        path = "/apis/nodus.dev/v1/namespaces/" + quote(settings["namespace"]) + "/pools/" + quote(settings["pool"]) + "/sharing"
        if method == "GET":
            path += "?node=" + quote(settings["node"])
        response = self.transport(method, settings["platform_url"] + path, token, body)
        if not isinstance(response, dict) or settings["node"] not in response.get("nodes", []):
            raise Error("node_identity_mismatch", "platform did not confirm the selected enrolled node", 409)
        return response

    def _audit_credential_history(self, settings):
        from .handback import observed_binding
        with self.service.store.connection() as db:
            row = db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()
        history = json.loads(row[0]) if row else None
        if history and history.get("eligible"):
            try:
                observed = observed_binding(settings)
                unchanged = all(history["binding"].get(k) == v for k, v in observed.items())
            except (Error, OSError):
                unchanged = False
            if not unchanged:
                self.service.record_connection_attempt(None)

    @staticmethod
    def _accepted(response, node, compensation):
        consent = response.get("consent") or {}
        terms = consent.get("terms") or {}
        digest = consent.get("termsDigest", "")
        try:
            uuid.UUID(consent.get("id", ""))
        except (ValueError, TypeError, AttributeError):
            raise Error("consent_required", "accept published terms for this host in the Nodus console", 409) from None
        if (response.get("accepting") is not True or consent.get("revokedTime")
                or not (node in consent.get("nodes", []) or consent.get("allHosts") is True)
                or not consent.get("acceptedBy") or not consent.get("acceptedTime")
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise Error("consent_required", "current accepted consent must cover this exact host", 409)
        if terms.get("compensation") != compensation:
            raise Error("compensation_mismatch", "accepted compensation does not match the requested payment mode", 409)
        return consent

    def review(self, *, platform_url, namespace, pool, node, token_file, node_identity_file=None):
        settings = self._settings(platform_url, namespace, pool, node, token_file)
        # Review is read-only and does not enroll/configure this host or change
        # its managed connection history; it may run off-host without node.json.
        response = self._request(settings, audit_history=False)
        return {"node": node, "generation": response.get("generation"), "accepting": response.get("accepting"),
                "terms": response.get("terms"), "terms_digest": response.get("termsDigest"),
                "accepted_consent": response.get("consent"), "hosts": response.get("hosts", [])}

    def _apply(self, record, enabled, reason):
        policy = self.service.bridge_policy_state()
        revision = policy["policy_revision"] + 1
        self.service.bridge_policy(enabled=enabled, policy_revision=revision,
                                   consent_reference=record["consent_id"] + ":" + record["terms_digest"],
                                   authorization_id=record["authorization_id"], expires_at=record["available_until"])
        record.update(active=enabled, local_revision=revision, reason=reason)

    def _disable(self, record, reason):
        # Disable a real policy using its existing identity; observation creates no consent.
        policy = self.service.bridge_policy_state()
        if policy["enabled"]:
            policy = self.service.bridge_policy(enabled=False, policy_revision=policy["policy_revision"] + 1,
                consent_reference=policy["consent_reference"], authorization_id=policy["authorization_id"],
                expires_at=policy["expires_at"])
        record.update(active=False, local_revision=policy["policy_revision"], reason=reason)

    @staticmethod
    def _public(record):
        if record is None:
            return {"connected": False, "active": False}
        names = ("connected", "active", "platform_url", "namespace", "pool", "node", "consent_id", "terms_digest",
                 "compensation", "available_until", "local_revision", "reason", "allowed_images", "participation")
        return {name: record[name] for name in names if name in record}

    def connect(self, *, platform_url, namespace, pool, node, token_file, available_until=None,
                accept_terms_digest=None, required_compensation="CashUSD", node_identity_file="/var/lib/nodus/node.json",
                allowed_images=(), terminal_native_return=False, participation="enabled"):
        if participation not in {"enabled", "disabled"}:
            raise Error("invalid_participation", "select enabled or disabled participation", 400)
        if participation == "disabled" and (accept_terms_digest is not None or available_until is not None
                or allowed_images not in ((), [])):
            raise Error("observation_policy", "observation does not accept terms, availability or workload permissions", 400)
        if required_compensation not in {"CashUSD", "Credits"}:
            raise Error("invalid_compensation", "select CashUSD or Credits explicitly", 400)
        if participation == "enabled" and allowed_images is not None:
            if (not isinstance(allowed_images, list) or not 1 <= len(allowed_images) <= 128
                    or any(not self._pinned_image(image) for image in allowed_images)):
                raise Error("invalid_workload_policy", "explicitly permit qualified Jobs or supply 1–128 pinned image references", 400)
            allowed_images = sorted(set(allowed_images))
        settings = self._settings(platform_url, namespace, pool, node, token_file)
        until = None
        if participation == "enabled":
            until = finite_time(available_until, "available_until")
            if not self.clock() < until <= self.clock() + 86400:
                raise Error("invalid_availability", "v1 availability must end within the next 24 hours", 400)
        settings["node_identity_file"] = str(Path(node_identity_file).absolute())
        self._verify_identity(settings)
        # Ordinary connections remain usable with read-only keys/older servers.
        # Terminal return requires a dedicated, identifiable key from day one.
        binding = None
        if terminal_native_return:
            from .handback import credential_binding
            binding = credential_binding(settings, self.transport)
        else:
            # Reapplying identical settings does not need a new opt-in and must
            # not erase the original verified identity. No missing history is inferred.
            from .handback import observed_binding
            with self.service.store.connection() as db:
                row = db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()
            history = json.loads(row[0]) if row else None
            if history and history.get("eligible"):
                observed = observed_binding(settings)
                if all(history["binding"].get(k) == v for k, v in observed.items()):
                    binding = history["binding"]
        with self._locked():
            previous = self._load()
            self.service.record_connection_attempt(binding, participation=participation, fresh_record=previous is None)
            response = self._request(settings)
            if participation == "disabled":
                self._verify_identity(settings)
                record = {**(previous or {}), **settings, "connected": True, "active": False,
                          "participation": "disabled", "permission_verified_at": self.clock(),
                          "authorization_id": (previous or {}).get("authorization_id", "connection-" + uuid.uuid4().hex)}
                self._save(record)  # Claims fail closed before any existing enabled policy is drained.
                self._disable(record, "observation")
                self._save(record)
                return self._public(record)
            if accept_terms_digest is not None:
                if response.get("termsDigest") != accept_terms_digest:
                    raise Error("terms_changed", "published terms differ from the reviewed digest", 409)
                if (response.get("terms") or {}).get("compensation") != required_compensation:
                    raise Error("compensation_mismatch", "published terms differ from the requested compensation", 409)
                try:
                    existing = self._accepted(response, node, required_compensation)
                except Error:
                    existing = {}
                if existing.get("termsDigest") != accept_terms_digest:
                    response = self._request(settings, "POST", {"action": "Accept", "generation": response["generation"],
                                              "node": node, "termsDigest": accept_terms_digest, "agreed": True})
            consent = self._accepted(response, node, required_compensation)
            if accept_terms_digest is not None and consent["termsDigest"] != accept_terms_digest:
                raise Error("terms_changed", "accepted terms differ from the explicitly reviewed digest", 409)
            self._verify_identity(settings)
            record = {**settings, "connected": True, "active": False, "reason": "connecting", "participation": "enabled",
                      "consent_id": consent["id"], "terms_digest": consent["termsDigest"],
                      "compensation": required_compensation, "available_until": until,
                      "allowed_images": allowed_images,
                      "authorization_id": "connection-" + uuid.uuid4().hex,
                      "permission_verified_at": self.clock(),
                      "local_revision": self.service.bridge_policy_state()["policy_revision"]}
            self._save(record)
            self._apply(record, True, "authorized")
            self._save(record)
            return self._public(record)

    def sync(self):
        with self._locked():
            record = self._load()
            if record is None:
                return self._public(None)
            if record.get("participation") == "disabled":
                self._disable(record, "observation" if record["connected"] else "disconnected")
                if record["connected"]:
                    try:
                        self._verify_identity(record)
                        self._request(record)
                        self._verify_identity(record)
                        record["permission_verified_at"] = self.clock()
                    except (Error, OSError) as exc:
                        record["reason"] = exc.code if isinstance(exc, Error) else "platform_unavailable"
                        if record["reason"] == "node_identity_mismatch":
                            record["connected"] = False
                self._save(record)
                return self._public(record)
            if not record["connected"]:
                policy = self.service.bridge_policy_state()
                if record.get("active") or (policy.get("enabled") and policy.get("authorization_id") == record["authorization_id"]):
                    self._apply(record, False, "disconnected")
                    self._save(record)
                return self._public(record)
            policy = self.service.bridge_policy_state()
            if policy["policy_revision"] != record["local_revision"]:
                record["connected"] = False
                self._save(record)
                self._apply(record, False, "local_policy_changed")
                self._save(record)
                return self._public(record)
            enabled, reason = False, "availability_ended"
            if self.clock() < record["available_until"]:
                try:
                    self._verify_identity(record)
                    response = self._request(record)
                    consent = self._accepted(response, record["node"], record["compensation"])
                    if consent["id"] != record["consent_id"] or consent["termsDigest"] != record["terms_digest"]:
                        raise Error("terms_changed", "new consent requires another explicit connection", 409)
                    self._verify_identity(record)
                    record["permission_verified_at"] = self.clock()
                    enabled, reason = True, "authorized"
                except (Error, OSError) as exc:
                    reason = exc.code if isinstance(exc, Error) else "platform_unavailable"
                    if reason in {"consent_required", "terms_changed", "compensation_mismatch", "node_identity_mismatch"}:
                        record["connected"] = False
                        self._save(record)
            if enabled != record["active"]:
                self._apply(record, enabled, reason)
            record["reason"] = reason
            self._save(record)
            return self._public(record)

    def disconnect(self):
        with self._locked():
            record = self._load()
            if record is None:
                return self._public(None)
            record["connected"] = False
            self._save(record)
            self._disable(record, "disconnected")
            self._save(record)
            return self._public(record)
