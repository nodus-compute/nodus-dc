"""Actual local policy/SQLite behavior with an explicitly synthetic platform transport."""
import copy
import json
import os
import tempfile
import unittest
from urllib.parse import urlsplit
from pathlib import Path

from nodus_dc.connection import Connection
from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock

NODE = "bnod_00000000000000000000000001"
DIGEST = "a" * 64
IMAGE = "fixture/job@sha256:" + "c" * 64


class Platform:
    def __init__(self):
        self.calls = []
        self.error = None
        self.response = {"generation": 1, "nodes": [NODE], "accepting": True,
                         "termsDigest": DIGEST, "terms": {"compensation": "CashUSD"},
                         "consent": {"id": "00000000-0000-0000-0000-000000000010", "nodes": [NODE],
                                     "termsDigest": DIGEST, "terms": {"compensation": "CashUSD"},
                                     "acceptedBy": "fixture-owner", "acceptedTime": "2026-11-10T00:00:00Z"}}

    def __call__(self, method, url, token, body):
        self.calls.append((method, url, body))
        if method == "POST" and urlsplit(url).query:
            raise Error("platform_rejected", "put node in the request body", 400)
        if self.error:
            raise self.error
        return copy.deepcopy(self.response)


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock()
        self.service = Service(Store(self.root / "authority.db"), Backend(self.clock), clock=self.clock, bridge_enabled=True)
        self.platform = Platform()
        self.connection = Connection(self.service, self.root, transport=self.platform, clock=self.clock)
        self.token = self.root / "platform.token"
        self.token.write_text("fixture-" + "x" * 40)
        self.token.chmod(0o600)
        self.identity = self.root / "node.json"
        self.identity.write_text(json.dumps({"nodeId": "00000000-0000-0000-0000-000000000001"}))
        self.identity.chmod(0o600)
        self.settings = dict(platform_url="https://api.fixture.invalid", namespace="project", pool="pool", node=NODE,
                             token_file=str(self.token), available_until=2000, node_identity_file=str(self.identity),
                             allowed_images=[IMAGE])

    def assert_error(self, code, call):
        with self.assertRaises(Error) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_connect_binds_actual_node_and_accepted_cash_terms(self):
        result = self.connection.connect(**self.settings)
        self.assertTrue(result["active"])
        self.assertEqual(result["terms_digest"], DIGEST)
        self.assertNotIn("token_file", result)
        self.assertNotIn(self.token.read_text(), self.connection.path.read_text())
        self.assertEqual(os.stat(self.connection.path).st_mode & 0o777, 0o600)
        self.assertIn("?node=" + NODE, self.platform.calls[0][1])
        self.identity.write_text('{"nodeId":"00000000-0000-0000-0000-000000000099"}')
        self.assert_error("node_identity_mismatch", lambda: self.connection.connect(**self.settings))

    def test_unchanged_poll_does_not_drain_active_lease(self):
        result = self.connection.connect(**self.settings)
        claim = self.service.bridge_claim(platform_lease_id="platform-one", platform_epoch=1,
                                          policy_revision=result["local_revision"], idempotency_key="platform-one",
                                          workload_image=IMAGE, workload_kind="Job")
        first = result["local_revision"]
        for _ in range(3):
            self.assertEqual(self.connection.sync()["local_revision"], first)
        self.assertTrue(self.service.bridge_check(platform_lease_id="platform-one", platform_epoch=1,
                                                  generation=claim["generation"])["authorized"])

    def test_platform_outage_fences_external_but_not_local_management(self):
        self.connection.connect(**self.settings)
        self.platform.error = Error("platform_unavailable", "fixture")
        self.assertFalse(self.connection.sync()["active"])
        own = self.service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1500, request_key="offline-owner")
        self.assertEqual(own["owner"], "local")
        self.platform.error = None
        self.assertTrue(self.connection.sync()["active"])
        self.assertFalse(self.service.bridge_status()["available"])

    def test_changed_or_revoked_terms_cannot_reenable_old_permission(self):
        self.connection.connect(**self.settings)
        self.platform.response["consent"]["termsDigest"] = "b" * 64
        self.assertFalse(self.connection.sync()["active"])
        self.platform.response["consent"]["termsDigest"] = DIGEST
        self.assertFalse(self.connection.sync()["connected"])
        self.connection.connect(**self.settings)
        self.platform.response["consent"]["revokedTime"] = "2026-11-10T01:00:00Z"
        self.assertFalse(self.connection.sync()["active"])
        self.platform.response["consent"].pop("revokedTime")
        self.assertFalse(self.connection.sync()["connected"])

    def test_disconnect_is_durable_and_never_contacts_platform(self):
        self.connection.connect(**self.settings)
        self.platform.error = Error("platform_unavailable", "fixture")
        count = len(self.platform.calls)
        self.assertFalse(self.connection.disconnect()["active"])
        self.assertFalse(self.connection.sync()["connected"])
        self.assertEqual(count, len(self.platform.calls))

    def test_manual_local_revocation_is_not_overridden(self):
        result = self.connection.connect(**self.settings)
        current = self.service.bridge_policy_state()
        current.update(enabled=False, policy_revision=result["local_revision"] + 1)
        self.service.bridge_policy(**current)
        self.assertFalse(self.connection.sync()["connected"])

    def test_crash_between_policy_and_record_update_fails_closed(self):
        self.connection.connect(**self.settings)
        record = json.loads(self.connection.path.read_text())
        record.update(local_revision=0, active=False)
        self.connection._save(record)
        restarted = Connection(self.service, self.root, transport=self.platform, clock=self.clock)
        self.assertFalse(restarted.sync()["active"])
        self.assertFalse(self.service.bridge_policy_state()["enabled"])

    def test_accept_requires_exact_reviewed_digest_and_compensation(self):
        self.assert_error("terms_changed", lambda: self.connection.connect(**self.settings, accept_terms_digest="b" * 64))
        self.assertEqual([x[0] for x in self.platform.calls], ["GET"])
        self.platform.response["terms"]["compensation"] = "Credits"
        self.assert_error("compensation_mismatch", lambda: self.connection.connect(**self.settings, accept_terms_digest=DIGEST))
        self.assertFalse(self.service.bridge_policy_state()["enabled"])
        self.platform.response["terms"]["compensation"] = "CashUSD"
        accepted = copy.deepcopy(self.platform.response)
        self.platform.response.pop("consent")
        def accept(method, url, token, body):
            response = self.platform(method, url, token, body)
            return accepted if method == "POST" else response
        self.connection.transport = accept
        self.assertTrue(self.connection.connect(**self.settings, accept_terms_digest=DIGEST)["active"])
        method, url, body = self.platform.calls[-1]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://api.fixture.invalid/apis/nodus.dev/v1/namespaces/project/pools/pool/sharing")
        self.assertEqual(body, {"action": "Accept", "node": NODE, "generation": 1, "termsDigest": DIGEST, "agreed": True})

    def test_expiry_and_unconfigured_state_do_not_make_network_calls(self):
        self.assertFalse(self.connection.sync()["connected"])
        self.assertEqual(self.platform.calls, [])
        self.connection.connect(**self.settings)
        count = len(self.platform.calls)
        self.clock.now = 2001
        self.assertFalse(self.connection.sync()["active"])
        self.assertEqual(count, len(self.platform.calls))

    def test_accept_response_cannot_substitute_unreviewed_terms(self):
        accepted = copy.deepcopy(self.platform.response)
        self.platform.response.pop("consent")
        accepted["consent"]["termsDigest"] = "b" * 64
        def changed(method, url, token, body):
            return copy.deepcopy(accepted if method == "POST" else self.platform.response)
        self.connection.transport = changed
        self.assert_error("terms_changed", lambda: self.connection.connect(**self.settings, accept_terms_digest=DIGEST))
        self.assertFalse(self.service.bridge_policy_state()["enabled"])

    def test_enrollment_change_immediately_fences_and_stickily_disconnects(self):
        result = self.connection.connect(**self.settings)
        claim = self.service.bridge_claim(platform_lease_id="bound-node", platform_epoch=1,
                                          policy_revision=result["local_revision"], idempotency_key="bound-node",
                                          workload_image=IMAGE, workload_kind="Job")
        original = self.identity.read_text()
        self.identity.write_text('{"nodeId":"00000000-0000-0000-0000-000000000099"}')
        self.assertFalse(self.service.bridge_check(platform_lease_id="bound-node", platform_epoch=1,
                                                  generation=claim["generation"])["authorized"])
        self.assertFalse(self.connection.sync()["connected"])
        self.identity.write_text(original)
        self.assertFalse(self.connection.sync()["connected"])

    def test_stalled_sync_cannot_extend_permission_heartbeat(self):
        result = self.connection.connect(**self.settings)
        claim = self.service.bridge_claim(platform_lease_id="heartbeat", platform_epoch=1,
                                          policy_revision=result["local_revision"], idempotency_key="heartbeat",
                                          workload_image=IMAGE, workload_kind="Job")
        self.clock.now += 21
        count = len(self.platform.calls)
        self.assertFalse(self.service.bridge_check(platform_lease_id="heartbeat", platform_epoch=1,
                                                  generation=claim["generation"])["authorized"])
        self.assertEqual(count, len(self.platform.calls))

    def test_completed_delayed_response_does_not_renew_stale_permission(self):
        result = self.connection.connect(**self.settings)
        claim = self.service.bridge_claim(platform_lease_id="delayed", platform_epoch=1,
                                          policy_revision=result["local_revision"], idempotency_key="delayed",
                                          workload_image=IMAGE, workload_kind="Job")

        def delayed(seconds):
            def transport(*args):
                response = self.platform(*args)
                self.clock.now += seconds
                return response
            return transport

        self.connection.transport = delayed(19)
        self.assertTrue(self.connection.sync()["active"])
        self.clock.now += 2
        self.assertFalse(self.service.bridge_check(platform_lease_id="delayed", platform_epoch=1,
                                                   generation=claim["generation"])["authorized"])
        self.connection.transport = self.platform
        self.assertTrue(self.connection.sync()["active"])
        self.assertTrue(self.service.bridge_check(platform_lease_id="delayed", platform_epoch=1,
                                                  generation=claim["generation"])["authorized"])
        self.connection.transport = delayed(21)
        self.assertFalse(self.connection.sync()["active"])
        self.assertFalse(self.service.bridge_check(platform_lease_id="delayed", platform_epoch=1,
                                                   generation=claim["generation"])["authorized"])

    def test_workload_policy_denies_unlisted_images_and_nonjob_execution(self):
        result = self.connection.connect(**self.settings)
        claim = dict(platform_lease_id="policy", platform_epoch=1,
                     policy_revision=result["local_revision"], idempotency_key="policy")
        for image, kind in [("other/image@sha256:" + "d"*64,"Job"), (IMAGE,"Sandbox"), ("", "Job")]:
            self.assert_error("workload_not_permitted", lambda: self.service.bridge_claim(
                **claim, workload_image=image, workload_kind=kind))
        self.assertFalse(self.service.status()["leases"])
        self.service.bridge_claim(**claim, workload_image=IMAGE, workload_kind="Job")
        self.assert_error("idempotency_conflict", lambda: self.service.bridge_claim(
            **claim, workload_image=IMAGE, workload_kind="maintenance"))


if __name__ == "__main__":
    unittest.main()
