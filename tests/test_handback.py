"""CPU-only durable protocol tests, synthetic GPU/agent and simulated platform.

Real SQLite and filesystem transitions; no GPU, systemd or platform retirement
is qualified by these tests. Platform Node/APIKey handlers have their own tests.
"""
import json
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from nodus_dc.connection import Connection
from nodus_dc.errors import Error
from nodus_dc.handback import Handback, LinuxAgent, SCOPES, JOURNAL_KEY, observed_binding, request
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock


class Agent:
    def __init__(self):
        self.stops = 0
        self.fail = False

    def prepare(self, record):
        pass  # Deliberately synthetic; production requires the official Linux service.

    def stop(self):
        if self.fail:
            raise Error("agent_stop_unverified", "synthetic failed service stop")
        self.stops += 1
        return {"unit": "nodusd.service", "stopped": True, "disabled": True, "synthetic": True}


def api_key_object(uid, name, scopes, projects=None):
    """Normal API object shape; whoami and audit events have separate contracts."""
    return {"apiVersion": "nodus.dev/v1", "kind": "APIKey",
            "metadata": {"uid": uid, "name": name, "labels": {"qualification": "synthetic"}},
            "spec": {"scopes": sorted(scopes), "projects": [] if projects is None else projects},
            "status": {"owner": "usr_synthetic", "prefix": "synthetic-display-prefix"}}


def invalid_api_key_objects(value):
    cases = [("flat", {**value["metadata"], **value["spec"]})]
    for section in ("metadata", "spec", "status"):
        missing = copy.deepcopy(value)
        del missing[section]
        cases.append(("missing-"+section, missing))
    for section, field, replacement in (
        (None, "apiVersion", "other/v1"), (None, "kind", "APIKeyList"),
        (None, "uid", value["metadata"]["uid"]), (None, "metadata", []), (None, "spec", []), (None, "status", []),
        ("metadata", "uid", str(uuid.uuid4())), ("metadata", "name", "other-key"),
        ("metadata", "scopes", value["spec"]["scopes"]), ("spec", "uid", value["metadata"]["uid"]),
        ("status", "uid", value["metadata"]["uid"]), ("status", "scopes", value["spec"]["scopes"]),
        ("status", "token", "synthetic-unexpected-token-never-retained"),
        ("spec", "scopes", "*"), ("spec", "scopes", [False]),
        ("spec", "scopes", value["spec"]["scopes"]*2), ("spec", "scopes", [*value["spec"]["scopes"], "*"]),
        ("spec", "projects", None), ("spec", "projects", ["other-project"]),
        ("spec", "serviceAccountName", "lab/other"), ("status", "owner", "sa/lab/other"),
    ):
        candidate = copy.deepcopy(value)
        target = candidate if section is None else candidate[section]
        target[field] = replacement
        cases.append((str(section)+"."+field, candidate))
    return cases


class HandbackTests(unittest.TestCase):
    def setUp(self):
        # Exercise real private-path validation; /tmp is intentionally ineligible.
        self.temp = tempfile.TemporaryDirectory(prefix=".nodus-handback-test-", dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()
        self.clock = Clock()
        self.service = Service(Store(self.path / "authority.sqlite3"), Backend(self.clock), clock=self.clock, bridge_enabled=True)
        self.node_uuid = str(uuid.uuid4())
        number = uuid.UUID(self.node_uuid).int
        alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
        encoded = ""
        for _ in range(26):
            encoded = alphabet[number & 31] + encoded
            number >>= 5
        self.node = "nod_" + encoded
        self.node_uid = "bnod_" + encoded
        self.key_uid = str(uuid.uuid4())
        self.org = str(uuid.uuid4())
        self.token_path = self.path / "platform.token"
        self.node_path = self.path / "node.json"
        self.token_path.write_text("synthetic-test-connection-token-1234567890")
        self.node_path.write_text(json.dumps({"nodeId": self.node, "nodeIdentityToken": "synthetic-only"}))
        self.token_path.chmod(0o600)
        self.node_path.chmod(0o600)
        self.record = {"connected": False, "active": False, "node": self.node, "namespace": "lab", "pool": "pool",
            "platform_url": "https://api.invalid", "token_file": str(self.token_path), "node_identity_file": str(self.node_path),
            "consent_id": str(uuid.uuid4()), "terms_digest": "a" * 64, "authorization_id": "old", "available_until": 2000,
            "local_revision": 1}
        Connection(self.service, self.path)._save(self.record)
        self.service.record_connection_attempt({**observed_binding(self.record), "credential_uid": self.key_uid, "org_uid": self.org})
        self.service.bridge_policy(enabled=False, policy_revision=1, authorization_id="old",
                                   consent_reference=self.record["consent_id"] + ":" + "a"*64, expires_at=2000)
        self.lease = self.service.reserve(resources=["host-a"], mode="exclusive_host", expires_at=1100, request_key="owner")
        self.agent = Agent()
        self.tick = 0.0
        self.waits = []
        self.calls = []
        self.node_deleted = False
        self.key_deleted = False
        self.mutate = lambda method, path, response: response
        self.h = self.new_handback()

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.tick += seconds

    def new_handback(self):
        return Handback(self.service, self.path, transport=self.transport, agent=self.agent,
                        monotonic=lambda: self.tick, sleep=self.sleep)

    def transport(self, method, url, token, body):
        path = url.removeprefix("https://api.invalid")
        self.calls.append((method, path, body))
        if path == "/auth/whoami":
            result = (401, {"reason": "Unauthorized"}) if self.key_deleted else (200,
                {"kind": "APIKey", "credentialUID": self.key_uid, "org": self.org, "projects": [], "scopes": sorted(SCOPES)})
        elif path.startswith("/apis/nodus.dev/v1/apikeys/"):
            if method == "GET":
                result = (200, api_key_object(self.key_uid, "host-retirement", SCOPES))
            else:
                self.assertTrue(self.node_deleted)
                self.assertEqual(self.h._load()["stage"], "key_delete_pending")
                self.assertIn("node_delete", self.h._load()["evidence"])
                self.key_deleted = True
                result = (204, None)
        elif "/sharing?" in path:
            result = (200, {"accepting": False, "nodes": [self.node], "generation": 2,
                "consent": {"id": self.record["consent_id"], "termsDigest": "a"*64, "revokedTime": "2026-11-10T00:00:00Z"}})
        elif method == "GET":
            result = (200, {"metadata": {"name": self.node, "uid": self.node_uid, "resourceVersion": "123"}})
        else:
            self.assertEqual(self.h._load()["stage"], "node_delete_pending")
            self.assertEqual(body["preconditions"], {"uid": self.node_uid, "resourceVersion": "123"})
            self.assertIn("propagationPolicy=Background", path)
            self.node_deleted = True
            result = (200, {"kind": "Status", "status": "Success", "details": {"name": self.node,
                         "uid": self.node_uid, "kind": "nodes", "group": "nodus.dev"}})
        return self.mutate(method, path, result)

    def run_handback(self, **overrides):
        args = dict(generation=self.lease["generation"], request_key="return-owner", api_key_name="host-retirement")
        args.update(overrides)
        return self.h.run(self.lease["id"], **args)

    def test_exact_retirement_ready_removes_credentials_and_never_reconnects_or_releases(self):
        result = self.run_handback()
        self.assertTrue(result["native_access_ready"])
        self.assertFalse(result["reconnect_supported"])
        self.assertGreaterEqual(sum(self.waits), 31)
        self.assertFalse(self.token_path.exists())
        self.assertFalse(self.node_path.exists())
        self.assertGreaterEqual(self.agent.stops, 1)
        before = len(self.calls)
        self.assertEqual(result, self.run_handback())
        self.assertEqual(before, len(self.calls))
        self.clock.now = 1200
        self.service.reconcile()
        self.assertEqual("quarantined", self.service.get(self.lease["id"])["state"])
        self.service = Service(Store(self.service.store.path), self.service.backend, clock=self.clock, bridge_enabled=True)
        for action in (
            lambda: self.service.record_connection_attempt(),
            lambda: self.service.bridge_policy(enabled=True, policy_revision=2, authorization_id="new", consent_reference="new", expires_at=2000),
            lambda: self.service.release(self.lease["id"], generation=self.lease["generation"], request_key="release"),
            lambda: self.service.recover(self.lease["id"], generation=self.lease["generation"], request_key="recover"),
            lambda: self.service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1300, request_key="overlap")):
            with self.assertRaises(Error):
                action()

    def test_api_key_object_identity_rejects_flat_ambiguous_and_malformed_fields(self):
        for name, value in invalid_api_key_objects(api_key_object(self.key_uid, "host-retirement", SCOPES)):
            with self.subTest(case=name):
                self.mutate = lambda method, path, result: (200, value) if method == "GET" and "/apikeys/" in path else result
                with self.assertRaises(Error):
                    self.run_handback()
                self.assertFalse(self.node_deleted)
                self.assertFalse(self.key_deleted)
                self.assertIsNone(self.h._load())
        self.mutate = lambda method, path, result: result
        self.assertTrue(self.run_handback()["native_access_ready"])
        self.assertNotIn("synthetic-unexpected-token-never-retained", json.dumps(self.h._load()))

    def test_retirement_http_rejects_duplicate_json_fields(self):
        class Response(io.BytesIO):
            code = 200
        class Opener:
            def open(self, *_args, **_kwargs):
                return Response(raw)
        value = api_key_object(self.key_uid, "host-retirement", SCOPES)
        valid = json.dumps(value).encode()
        with patch("nodus_dc.handback.urllib.request.build_opener", return_value=Opener()):
            raw = valid
            self.assertEqual((200, value), request("GET", "https://api.invalid/apis/nodus.dev/v1/apikeys/host-retirement", "synthetic-only"))
            for field, conflicting in ((b'"uid":', b'"uid":"wrong",'), (b'"kind":', b'"kind":"Other",'),
                                       (b'"scopes":', b'"scopes":["*"],')):
                raw = valid.replace(field, conflicting + field, 1)
                with self.assertRaises(Error) as exc:
                    request("GET", "https://api.invalid/apis/nodus.dev/v1/apikeys/host-retirement", "synthetic-only")
                self.assertEqual("retirement_protocol", exc.exception.code)

    def test_wrong_generation_or_replayed_request_fails(self):
        with self.assertRaises(Error):
            self.run_handback(generation=self.lease["generation"] + 1)
        self.assertEqual([], self.calls)
        self.run_handback()
        for change in ({"generation": self.lease["generation"] + 1}, {"request_key": "other"}, {"api_key_name": "other"}):
            with self.assertRaises(Error):
                self.run_handback(**change)

    def test_active_workload_blocks_before_any_remote_calls(self):
        self.service.start(self.lease["id"], generation=self.lease["generation"], request_key="start", workload={"test_workload": True})
        with self.assertRaises(Error):
            self.run_handback()
        self.assertEqual([], self.calls)

    def test_current_permission_and_credential_identity_fail_closed(self):
        cases = [
            ("/auth/whoami", {"kind": "User"}),
            ("/auth/whoami", {"credentialUID": None}),
            ("/auth/whoami", {"serviceAccount": "sa/other"}),
            ("/auth/whoami", {"scopes": ["*"]}),
            ("/apikeys/", {"uid": str(uuid.uuid4())}),
            ("/sharing?", {"accepting": True}),
            ("/sharing?", {"consent": {"id": self.record["consent_id"], "termsDigest": "a"*64}}),
            ("/nodes/", {"metadata": {"name": self.node, "uid": str(uuid.uuid4()), "resourceVersion": "123"}}),
        ]
        for route, values in cases:
            with self.subTest(route=route, values=values):
                self.mutate = lambda method, path, result: (result[0], {**result[1], **values}) if route in path else result
                with self.assertRaises(Error):
                    self.run_handback()
                self.assertFalse(self.node_deleted)
                self.assertIsNone(self.h._load())
        self.mutate = lambda method, path, result: result

    def test_crash_after_each_durable_stage_resumes_or_stays_uncertain(self):
        # Fresh real SQLite/credential fixture for every injected process interruption.
        for target in ("prepared", "node_delete_pending", "node_retired", "key_delete_pending", "key_revoked",
                       "key_rejected", "agent_stopped", "credentials_removed", "ready"):
            with self.subTest(stage=target):
                child = HandbackTests()
                child.setUp()
                try:
                    original = child.h._save
                    def save(journal, stage, **evidence):
                        result = original(journal, stage, **evidence)
                        if stage == target:
                            raise SystemExit("simulated crash")
                        return result
                    with patch.object(child.h, "_save", side_effect=save), self.assertRaises(SystemExit):
                        child.run_handback()
                    self.assertNotEqual("released", child.service.get(child.lease["id"])["state"])
                    child.h = child.new_handback()
                    if target in {"node_delete_pending", "key_delete_pending"}:
                        with self.assertRaises(Error) as exc:
                            child.run_handback()
                        self.assertEqual("retirement_uncertain", exc.exception.code)
                    else:
                        self.assertTrue(child.run_handback()["native_access_ready"])
                finally:
                    child.doCleanups()

    def test_node_ack_loss_never_revokes_key_or_grants_on_404(self):
        self.mutate = lambda method, path, result: (404, {}) if method == "DELETE" and "/nodes/" in path else result
        with self.assertRaises(Error):
            self.run_handback()
        self.assertTrue(self.node_deleted)
        self.assertFalse(self.key_deleted)
        self.h = self.new_handback()
        before = len(self.calls)
        with self.assertRaises(Error) as exc:
            self.run_handback()
        self.assertEqual("retirement_uncertain", exc.exception.code)
        self.assertEqual(before, len(self.calls))
        self.assertTrue(self.token_path.exists())

    def test_lost_key_delete_response_never_grants_or_retries(self):
        def response_lost(method, path, result):
            if method == "DELETE" and "/apikeys/" in path:
                raise Error("retirement_unavailable", "simulated lost acknowledgement")
            return result
        self.mutate = response_lost
        with self.assertRaises(Error):
            self.run_handback()
        self.assertTrue(self.node_deleted)
        self.assertTrue(self.key_deleted)
        self.assertEqual("key_delete_pending", self.h._load()["stage"])
        self.assertTrue(self.token_path.exists())
        self.assertEqual(0, self.agent.stops)
        count = len(self.calls)
        self.h = self.new_handback()
        with self.assertRaises(Error):
            self.run_handback()
        self.assertEqual(count, len(self.calls))

    def test_replaced_credential_after_retirement_is_not_deleted_or_granted(self):
        self.agent.fail = True
        with self.assertRaises(Error):
            self.run_handback()
        self.agent.fail = False
        self.token_path.write_text("different-potentially-live-secret-1234567890")
        with self.assertRaises(Error) as result:
            self.run_handback()
        self.assertEqual("credential_changed", result.exception.code)
        self.assertTrue(self.token_path.exists())
        self.assertEqual("agent_stopped", self.h._load()["stage"])

    def test_restart_repeats_entire_monotonic_wait_and_requires_401(self):
        self.mutate = lambda method, path, result: (403, {}) if self.key_deleted and path == "/auth/whoami" else result
        with self.assertRaises(Error):
            self.run_handback()
        self.assertEqual("key_revoked", self.h._load()["stage"])
        self.assertEqual(31, sum(self.waits))
        self.h = self.new_handback()
        self.tick = 900000  # A reboot/wall clock cannot earn any waiting credit.
        self.mutate = lambda method, path, result: result
        self.assertTrue(self.run_handback()["native_access_ready"])
        self.assertEqual(62, sum(self.waits))

    def test_stop_failure_or_dirty_gpu_keeps_held_and_preserves_credentials(self):
        self.agent.fail = True
        with self.assertRaises(Error):
            self.run_handback()
        self.assertEqual("key_rejected", self.h._load()["stage"])
        self.assertTrue(self.token_path.exists())
        self.agent.fail = False
        self.service.backend.clean = False
        with self.assertRaises(Error):
            self.run_handback()
        self.assertEqual("credentials_removed", self.h._load()["stage"])
        self.assertNotEqual("released", self.service.get(self.lease["id"])["state"])
        self.service.backend.clean = True
        self.assertTrue(self.run_handback()["native_access_ready"])

    def test_legacy_or_rotated_credential_history_cannot_be_requalified(self):
        for change in ("unknown", "new_path", "new_bytes", "new_node"):
            with self.subTest(change=change):
                child = HandbackTests()
                child.setUp()
                try:
                    if change == "unknown":
                        with child.service.store.transaction(child.clock()) as db:
                            db.execute("DELETE FROM meta WHERE key='native_credential_history'")
                    else:
                        binding = {**observed_binding(child.record), "credential_uid": child.key_uid, "org_uid": child.org}
                        changed = dict(binding)
                        field = {"new_path": "token_file", "new_bytes": "token_sha256", "new_node": "node_uuid"}[change]
                        changed[field] = "changed"
                        child.service.record_connection_attempt(changed)
                        child.service.record_connection_attempt(binding)  # Restoring old settings does not repair history.
                    with self.assertRaises(Error) as exc:
                        child.run_handback()
                    self.assertEqual("native_credential_history_unqualified", exc.exception.code)
                    self.assertFalse(child.node_deleted)
                    self.assertFalse(child.key_deleted)
                finally:
                    child.doCleanups()

    def test_normal_connection_persists_initial_identity_and_observed_rotation(self):
        # Exercise actual Connection.connect rather than seeding its journal.
        with self.service.store.transaction(self.clock()) as db:
            db.execute("DELETE FROM meta WHERE key IN ('native_credential_history','connected_mode_seen')")
        self.service.release(self.lease["id"], generation=self.lease["generation"], request_key="allow-connection")
        def api(method, url, token, body):
            if url.endswith("/auth/whoami"):
                return self.transport(method, url, token, body)[1]
            return {"generation": 1, "nodes": [self.node], "accepting": True,
                "consent": {"id": self.record["consent_id"], "termsDigest": "a"*64, "nodes": [self.node],
                    "acceptedBy": "synthetic-owner", "acceptedTime": "2026-11-10T00:00:00Z", "terms": {"compensation": "CashUSD"}}}
        connection = Connection(self.service, self.path, transport=api, clock=self.clock)
        args = {key: self.record[key] for key in ("platform_url", "namespace", "pool", "node", "token_file", "node_identity_file")}
        connection.connect(**args, available_until=2000, allowed_images=None, terminal_native_return=True)
        with self.service.store.connection() as db:
            initial = json.loads(db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()[0])
            self.assertEqual("2", db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0])
        self.assertTrue(initial["eligible"])
        self.assertEqual(self.org, initial["binding"]["org_uid"])
        review_args = {key: value for key, value in args.items() if key != "node_identity_file"}
        self.assertEqual(self.node, connection.review(**review_args)["node"])
        with self.service.store.connection() as db:
            after_review = json.loads(db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()[0])
        self.assertEqual(initial, after_review)
        connection.connect(**args, available_until=2000, allowed_images=None)  # Identical reapply needs no flag.
        connection = Connection(self.service, self.path, transport=api, clock=self.clock)
        connection.sync()  # Daemon restart and ordinary healthy polling preserve history.
        with self.service.store.connection() as db:
            unchanged = json.loads(db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()[0])
        self.assertEqual(initial, unchanged)
        original = self.token_path.read_text()
        self.token_path.write_text("synthetic-replacement-token-1234567890")
        connection.sync()
        self.token_path.write_text(original)
        connection.connect(**args, available_until=2000, allowed_images=None, terminal_native_return=True)
        with self.service.store.connection() as db:
            current = json.loads(db.execute("SELECT value FROM meta WHERE key='native_credential_history'").fetchone()[0])
        self.assertFalse(current["eligible"])

    def test_agent_inspection_requires_inactive_disabled_no_pids_or_jobs(self):
        agent = LinuxAgent()
        good = "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nUnitFileState=disabled\nJob=\nKillMode=control-group\nSendSIGKILL=yes\n"
        with patch.object(agent, "_command", side_effect=["", good]) as command:
            self.assertTrue(agent.stop()["stopped"])
            self.assertEqual(["systemctl", "disable", "--now", "nodusd.service"], command.call_args_list[0].args[0])
        for old, new in (("MainPID=0", "MainPID=42"), ("ControlPID=0", "ControlPID=1"), ("Job=\n", "Job=12\n"),
                         ("ActiveState=inactive", "ActiveState=active"), ("UnitFileState=disabled", "UnitFileState=enabled"),
                         ("KillMode=control-group", "KillMode=process"), ("SendSIGKILL=yes", "SendSIGKILL=no")):
            with patch.object(agent, "_command", side_effect=["", good.replace(old, new)]), self.assertRaises(Error):
                agent.stop()


if __name__ == "__main__":
    unittest.main()
