"""Real SQLite/CLI policy and terminal-return protocol; remote/GPU seams are synthetic."""
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import unittest

from nodus_dc.connection import Connection
from nodus_dc.errors import Error
from nodus_dc.handback import SCOPES
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests import test_handback


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.f = test_handback.HandbackTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.h.connection.path.unlink()
        with self.f.service.store.transaction(self.f.clock()) as db:
            db.execute("DELETE FROM meta WHERE key IN ('native_credential_history','connected_mode_seen','participation_history')")
            db.execute("DELETE FROM bridge_policy")
        self.sharing = {"accepting": False, "nodes": [self.f.node], "generation": 1, "consent": None}
        self.proof_override = None
        self.calls = []
        self.f.h.transport = self.transport
        self.c = Connection(self.f.service, self.f.path, transport=self.connection_transport, clock=self.f.clock)
        self.args = {name: self.f.record[name] for name in
                     ("platform_url", "namespace", "pool", "node", "token_file", "node_identity_file")}

    def transport(self, method, url, token, body):
        self.calls.append((method, url))
        if "/sharing?" in url:
            return 200, copy.deepcopy(self.sharing)
        if "/retirement?" in url:
            if self.proof_override is not None:
                return self.proof_override
            return (200, {"apiVersion": "nodus.dev/v1", "kind": "NodeRetirement", "node": self.f.node,
                "uid": self.f.node_uid, "organizationUID": self.f.org, "credentialGeneration": 4,
                "nodeIdentityRevokedTime": "2026-11-10T00:00:00Z", "retired": True}) if self.f.node_deleted else (409, {})
        return self.f.transport(method, url, token, body)

    def connection_transport(self, *args):
        status, value = self.transport(*args)
        if status != 200:
            raise Error("platform_unavailable", "synthetic unavailable response")
        return value

    def observe(self):
        return self.c.connect(**self.args, participation="disabled", terminal_native_return=True)

    def history(self):
        with self.f.service.store.connection() as db:
            return dict(db.execute("SELECT key,value FROM meta"))

    def enable(self):
        self.sharing.update(accepting=True, consent={"id": self.f.record["consent_id"], "termsDigest": "a"*64,
            "nodes": [self.f.node], "acceptedBy": "synthetic", "acceptedTime": "2026-11-10T00:00:00Z",
            "terms": {"compensation": "CashUSD"}})
        return self.c.connect(**self.args, participation="enabled", available_until=2000, allowed_images=None,
                              terminal_native_return=True)

    def test_observe_reconnect_sync_restart_without_acceptance_or_policy(self):
        result = self.observe()
        self.assertTrue(result["connected"])
        self.assertFalse(result["active"])
        self.assertNotIn("consent_id", result)
        for _ in range(2):
            self.c = Connection(Service(Store(self.f.service.store.path), self.f.service.backend,
                clock=self.f.clock, bridge_enabled=True), self.f.path, transport=self.connection_transport, clock=self.f.clock)
            self.assertFalse(self.c.sync()["active"])
            self.c.connect(**self.args, participation="disabled")
        self.assertEqual("never_enabled", self.history().get("participation_history"))
        self.assertEqual("3", self.history()["schema_version"])
        self.assertTrue(json.loads(self.history()["native_credential_history"])["eligible"])
        self.assertEqual(0, self.f.service.bridge_policy_state()["policy_revision"])
        self.assertTrue(all(method == "GET" for method, _ in self.calls))
        # An inconsistent mutable record still cannot authorize a claim.
        record = self.c._load(); record["active"] = True; self.c._save(record)
        self.assertFalse(self.c._authorization_current())
        self.c.disconnect()
        self.assertFalse(self.c.sync()["connected"])

    def test_disabled_rejects_acceptance_and_workload_flags_before_remote_calls(self):
        for extra in ({"accept_terms_digest": "a"*64}, {"available_until": 2000}, {"allowed_images": None},
                      {"allowed_images": ["fixture/image@sha256:" + "a"*64]}):
            with self.subTest(extra=extra), self.assertRaises(Error) as caught:
                self.c.connect(**self.args, participation="disabled", **extra)
            self.assertEqual("observation_policy", caught.exception.code)
        self.assertEqual([], self.calls)
        self.assertNotIn("participation_history", self.history())

    def test_explicit_enable_retains_gates_and_observation_preserves_consent(self):
        self.observe()
        with self.assertRaises(Error) as caught:
            self.c.connect(**self.args, participation="enabled", available_until=2000, allowed_images=None)
        self.assertEqual("consent_required", caught.exception.code)
        self.assertEqual("never_enabled", self.history().get("participation_history"))
        consent = self.enable()["consent_id"]
        self.assertEqual("ever_enabled", self.history().get("participation_history"))
        result = self.observe()
        self.assertEqual(consent, result["consent_id"])
        self.assertFalse(self.f.service.bridge_policy_state()["enabled"])
        self.c.disconnect()
        with self.assertRaises(Error) as caught:
            self.f.run_handback()
        self.assertEqual("remote_revocation_required", caught.exception.code)
        self.sharing.update(accepting=False)
        self.sharing["consent"]["revokedTime"] = "2026-11-10T00:00:00Z"
        self.assertTrue(self.f.run_handback()["native_access_ready"])
        self.assertIn("consent", self.f.h._load())

    def test_direct_enable_is_sticky_even_when_replayed_then_disabled(self):
        self.observe()
        policy = dict(enabled=True, policy_revision=1, authorization_id="direct", consent_reference="actual-consent", expires_at=2000)
        self.f.service.bridge_policy(**policy)
        # An idempotent replay of a legacy enabled row still records exposure.
        with self.f.service.store.transaction(self.f.clock()) as db:
            db.execute("DELETE FROM meta WHERE key='participation_history'")
            db.execute("UPDATE meta SET value='2' WHERE key='schema_version'")
        self.f.service.bridge_policy(**policy)
        self.assertEqual("3", self.history()["schema_version"])
        self.c.sync()
        self.assertFalse(self.f.service.bridge_policy_state()["enabled"])
        self.assertEqual("ever_enabled", self.history().get("participation_history"))
        self.observe(); self.c.disconnect()
        with self.assertRaises(Error):
            self.f.run_handback()
        self.assertFalse(self.f.node_deleted)

    def test_legacy_or_malformed_history_never_becomes_never_enabled(self):
        cases = [("connected_mode_seen", "1"), ("participation_history", "unknown"),
                 ("participation_history", "false"), ("participation_history", "ever_enabled")]
        for name, value in cases:
            with self.subTest(name=name, value=value):
                child = ObservationTests(); child.setUp()
                try:
                    with child.f.service.store.transaction(child.f.clock()) as db:
                        db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (name, value))
                    child.observe(); child.c.disconnect()
                    self.assertNotEqual("never_enabled", child.history()["participation_history"])
                    with self.assertRaises(Error):
                        child.f.run_handback()
                    self.assertFalse(child.f.node_deleted)
                finally:
                    child.doCleanups()

    def test_prior_policy_claim_or_external_lease_excludes_fresh_observation_history(self):
        statements = ["INSERT INTO bridge_policy VALUES(1,0,1,'prior-consent','prior',2000,1000)",
                      "INSERT INTO platform_claims VALUES('prior',1,NULL,NULL,1,1,1000,1000)",
                      "UPDATE leases SET owner='external',state='released'"]
        for statement in statements:
            with self.subTest(statement=statement):
                child = ObservationTests(); child.setUp()
                try:
                    with child.f.service.store.transaction(child.f.clock()) as db:
                        db.execute(statement)
                    child.observe()
                    self.assertEqual("unknown", child.history()["participation_history"])
                finally:
                    child.doCleanups()

    def test_concurrent_explicit_enable_and_observe_never_erase_exposure(self):
        self.observe()
        barrier = Barrier(2)
        def enabled():
            barrier.wait(); return self.enable()
        def disabled():
            barrier.wait(); return self.observe()
        with ThreadPoolExecutor(max_workers=2) as workers:
            a, b = workers.submit(enabled), workers.submit(disabled)
            a.result(); b.result()
        self.assertEqual("ever_enabled", self.history().get("participation_history"))
        self.observe(); self.c.disconnect()
        self.assertFalse(self.f.service.bridge_policy_state()["enabled"])
        self.assertEqual("ever_enabled", self.history().get("participation_history"))

    def test_never_enabled_requires_positive_remote_proof_then_original_cleanup(self):
        self.observe(); self.c.disconnect()
        self.assertTrue(self.f.run_handback()["native_access_ready"])
        journal = self.f.h._load()
        self.assertEqual("never_enabled", journal["retirement_basis"])
        self.assertNotIn("consent", journal)
        self.assertEqual(self.f.node_uid, journal["evidence"]["node_retirement_proof"]["uid"])
        self.assertGreaterEqual(sum(self.f.waits), 31)
        self.assertFalse(self.f.token_path.exists())
        self.assertFalse(self.f.node_path.exists())
        self.assertGreater(self.f.agent.stops, 0)
        proof_index = next(i for i, (_, url) in enumerate(self.calls) if "/retirement?" in url)
        key_delete = next(i for i, (method, url) in enumerate(self.calls) if method == "DELETE" and "/apikeys/" in url)
        self.assertLess(proof_index, key_delete)

    def test_missing_or_contradictory_proof_quarantines_before_key_revocation(self):
        mutations = [("apiVersion", "other/v1"), ("kind", "Node"), ("node", "wrong"), ("uid", "wrong"),
                     ("organizationUID", "wrong"), ("retired", False), ("credentialGeneration", True),
                     ("credentialGeneration", 0), ("nodeIdentityRevokedTime", "2026-11-10T00:00:00")]
        cases = [(404, None), (409, None), (200, None), *[(200, change) for change in mutations]]
        for status, mutation in cases:
            with self.subTest(status=status, mutation=mutation):
                child = ObservationTests(); child.setUp()
                try:
                    child.observe(); child.c.disconnect()
                    # Mutate one field of otherwise valid proof bound to this exact fixture.
                    child.f.node_deleted = True
                    proof = child.transport("GET", "https://api.invalid/retirement?uid=x", "", None)[1]
                    child.f.node_deleted = False
                    child.proof_override = (status, {**proof, mutation[0]: mutation[1]} if mutation else {})
                    with self.assertRaises(Error) as caught:
                        child.f.run_handback()
                    self.assertEqual("node_retirement_unverified", caught.exception.code)
                    self.assertEqual("node_delete_pending", child.f.h._load()["stage"])
                    self.assertFalse(child.f.key_deleted)
                    self.assertEqual("quarantined", child.f.service.get(child.f.lease["id"])["state"])
                    child.proof_override = None
                    self.assertTrue(child.f.run_handback(recover=True)["native_access_ready"])
                finally:
                    child.doCleanups()

    def test_current_remote_acceptance_refuses_observation_native_return(self):
        self.observe(); self.c.disconnect()
        for update in ({"accepting": True}, {"nodes": []}, {"consent": {"id": "current"}}):
            with self.subTest(update=update):
                original = copy.deepcopy(self.sharing)
                self.sharing.update(update)
                with self.assertRaises(Error):
                    self.f.run_handback()
                self.assertFalse(self.f.node_deleted)
                self.sharing = original
