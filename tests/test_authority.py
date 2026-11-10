"""Implementation controls for the allocation and connected bridge invariants.

These tests use a declared synthetic backend. They do not qualify any GPU.
"""
import tempfile
import multiprocessing
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from nodus_dc.errors import Error
from nodus_dc.model import CleanupProof, Resource, Snapshot
from nodus_dc.service import Service
from nodus_dc.store import Store


def race_reserve(args):
    path, request = args
    clock = Clock()
    service = Service(Store(path), Backend(clock), clock=clock)
    try:
        return service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key=request)["id"]
    except Error as exc:
        return exc.code


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Backend:
    def __init__(self, clock):
        self.clock = clock
        self.clean = True
        self.running = {}
        self.start_error = None
        self.cleanup_calls = 0
        self.verify_calls = 0
        self.wrong_proof = False

    def inventory(self):
        return Snapshot("host-a", self.clock(), (
            Resource("host-a", "host", None, modes=("exclusive_host",), healthy=True, busy=not self.clean),
            Resource("GPU-aaaa", "gpu", "host-a", "GPU-aaaa", memory_bytes=80 * 1024**3,
                     modes=("exclusive_gpu",), healthy=True),
            Resource("GPU-bbbb", "gpu", "host-a", "GPU-bbbb", memory_bytes=80 * 1024**3,
                     modes=(), healthy=True),
            Resource("MIG-aaaa", "partition", "GPU-bbbb", "MIG-aaaa", memory_bytes=40 * 1024**3,
                     modes=("hardware_partition",), healthy=True),
            Resource("MIG-bbbb", "partition", "GPU-bbbb", "MIG-bbbb", memory_bytes=40 * 1024**3,
                     modes=("hardware_partition",), healthy=True),
        ))

    def host_ready_for_external(self):
        return self.clean

    def validate_workload(self, workload, lease):
        if workload != {"test_workload": True}:
            raise Error("invalid_workload", "test workload required", 400)

    def start(self, lease):
        if self.start_error:
            raise self.start_error
        self.running[lease["id"]] = lease["generation"]
        return {"lease_id": lease["id"], "generation": lease["generation"], "container_id": "test"}

    def cleanup(self, lease):
        self.cleanup_calls += 1
        if self.clean:
            self.running.pop(lease["id"], None)
        return self.verify_clean(lease)

    def verify_clean(self, lease):
        self.verify_calls += 1
        return CleanupProof(self.clean, self.clock(), lease["id"], lease["generation"] + int(self.wrong_proof),
                            tuple(lease["resources"]), {"synthetic": True})


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.backend = Backend(self.clock)
        self.path = Path(self.tmp.name) / "authority.sqlite3"
        self.service = Service(Store(self.path), self.backend, clock=self.clock, bridge_enabled=True)
        self.counter = 0

    def tearDown(self):
        self.tmp.cleanup()

    def reserve(self, resource="GPU-aaaa", mode="exclusive_gpu", request_key=None):
        self.counter += 1
        return self.service.reserve(resources=[resource], mode=mode, expires_at=self.clock() + 100,
                                    request_key=request_key or f"r{self.counter}")

    def policy(self, enabled=True, revision=1):
        return self.service.bridge_policy(enabled=enabled, policy_revision=revision,
                                          authorization_id="auth-1", consent_reference="accepted-terms-1",
                                          expires_at=self.clock() + 1000)

    def claim(self, epoch=1, policy_revision=1):
        return self.service.bridge_claim(platform_lease_id="platform-1", platform_epoch=epoch,
                                         policy_revision=policy_revision, idempotency_key="platform-1")

    def check(self, claim):
        return self.service.bridge_check(platform_lease_id="platform-1", platform_epoch=claim["platform_epoch"],
                                         generation=claim["generation"])

    def assert_error(self, code, callback):
        with self.assertRaises(Error) as context:
            callback()
        self.assertEqual(context.exception.code, code)

    def test_exclusive_gpu_cannot_be_double_allocated(self):
        self.reserve()
        self.assert_error("allocation_conflict", self.reserve)

    def unavailable_inventory(self):
        raise Error("inventory_unavailable", "declared failed hardware observer", 503)

    def test_maintenance_expiry_requires_independent_cleanup_even_without_inventory(self):
        lease = self.reserve()
        self.service.start(lease["id"], generation=lease["generation"], request_key="start", workload={"test_workload": True})
        self.backend.inventory = self.unavailable_inventory
        self.backend.clean = False
        self.clock.now += 101
        self.service.maintain_leases()
        self.assertEqual(self.service.get(lease["id"])["state"], "quarantined")
        self.assertEqual((self.backend.cleanup_calls, self.backend.verify_calls), (1, 1))
        self.backend.clean = True
        self.service.maintain_leases()
        self.assertEqual(self.service.get(lease["id"])["state"], "quarantined")
        self.assertEqual(self.backend.cleanup_calls, 1)
        released = self.service.release(lease["id"], generation=lease["generation"], request_key="retry-cleanup")
        self.assertEqual(released["state"], "released")
        self.assertEqual(self.backend.verify_calls, 2)

    def test_maintenance_restart_holds_unknown_launch_without_inventory(self):
        lease = self.reserve()
        with self.service.store.transaction(self.clock()) as db:
            Store.update(db, lease, self.clock(), state="starting", workload={"test_workload": True})
        self.backend.inventory = self.unavailable_inventory
        resumed = Service(Store(self.path), self.backend, clock=self.clock)
        resumed.maintain_leases()
        self.assertEqual(resumed.get(lease["id"])["state"], "quarantined")
        self.assertEqual(self.backend.cleanup_calls, 0)
        self.assert_error("uncertain_launch", lambda: resumed.release(lease["id"], generation=lease["generation"], request_key="unsafe-release"))
        self.assert_error("inventory_unavailable", self.reserve)

    def test_maintenance_preserves_cached_timestamp_and_explicit_refresh(self):
        self.reserve()
        original = self.service.status()["inventory"]
        available = self.backend.inventory
        self.backend.inventory = self.unavailable_inventory
        self.clock.now += 1
        self.service.maintain_leases()
        self.assertEqual(self.service.status()["inventory"], original)
        self.assert_error("inventory_unavailable", self.service.reconcile)
        self.backend.inventory = available
        self.service.reconcile()
        self.assertEqual(self.service.status()["inventory"]["observed_at"], self.clock.now)

    def test_maintenance_external_expiry_never_local_releases(self):
        self.policy()
        claim = self.claim()
        self.backend.inventory = self.unavailable_inventory
        self.clock.now += 1001
        self.service.maintain_leases()
        self.assertEqual(self.service.get(claim["lease_id"])["state"], "draining")
        self.assertFalse(self.check(claim)["authorized"])
        self.assertEqual(self.backend.cleanup_calls, 0)

    def test_maintenance_keeps_durable_clock_fence_without_inventory(self):
        self.reserve()
        self.backend.inventory = self.unavailable_inventory
        self.clock.now = 1005
        self.service.maintain_leases()
        self.clock.now = 1003
        resumed = Service(Store(self.path), self.backend, clock=self.clock)
        self.assert_error("clock_regression", resumed.maintain_leases)

    def test_bridge_claim_workload_policy_and_replay_metadata_are_fenced(self):
        self.policy()
        allowed_image = "fixture/image@sha256:" + "a"*64
        observed = []
        def authorize(**workload):
            if workload:
                observed.append(workload)
                return workload == {"workload_image": allowed_image, "workload_kind": "Job"}
            return True
        self.service.bridge_authorization_check = authorize
        request = {"platform_lease_id": "qualified-job", "platform_epoch": 1, "policy_revision": 1,
                   "idempotency_key": "qualified-job", "workload_image": allowed_image, "workload_kind": "Job"}
        self.assert_error("bridge_identity_unverified", lambda: self.service.bridge_claim(**dict(request, workload_image="other")))
        self.assertEqual(self.service.status()["leases"], [])
        claim = self.service.bridge_claim(**request)
        lease = self.service.get(claim["lease_id"])
        self.assertEqual(lease["authorization"]["workload_image"], allowed_image)
        self.assert_error("idempotency_conflict", lambda: self.service.bridge_claim(**dict(request, workload_kind="maintenance")))
        self.service.bridge_authorization_check = lambda **_: False
        self.assertEqual(self.service.bridge_claim(**request)["generation"], claim["generation"])
        self.assertFalse(self.service.bridge_check(platform_lease_id="qualified-job", platform_epoch=1,
                                                   generation=claim["generation"])["authorized"])

    def test_whole_host_excludes_local_gpu_and_partitions(self):
        self.reserve("host-a", "exclusive_host")
        self.assert_error("allocation_conflict", self.reserve)
        self.assert_error("allocation_conflict", lambda: self.reserve("MIG-aaaa", "hardware_partition"))

    def test_partition_leases_exclude_host_but_allow_disjoint_instances(self):
        self.reserve("MIG-aaaa", "hardware_partition")
        self.reserve("MIG-bbbb", "hardware_partition")
        self.assert_error("allocation_conflict", lambda: self.reserve("host-a", "exclusive_host"))

    def test_unqualified_sharing_is_never_substituted(self):
        self.assert_error("unsupported_mode", lambda: self.reserve(mode="trusted_mps"))
        self.assert_error("unsupported_mode", lambda: self.reserve("GPU-bbbb", "exclusive_gpu"))

    def test_concurrent_thread_authorities_admit_only_one_gpu_lease(self):
        other = Service(Store(self.path), Backend(self.clock), clock=self.clock)
        def reserve(service, request):
            try:
                return service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key=request)["id"]
            except Error as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: reserve(*args), [(self.service, "one"), (other, "two")]))
        self.assertEqual(results.count("allocation_conflict"), 1)
        self.assertEqual(len(self.service.status()["leases"]), 1)

    def test_independent_processes_share_one_durable_authority(self):
        with multiprocessing.get_context("spawn").Pool(4) as pool:
            results = pool.map(race_reserve, [(str(self.path), "process-"+str(i)) for i in range(4)])
        self.assertEqual(results.count("allocation_conflict"), 3)
        self.assertEqual(len(self.service.status()["leases"]), 1)

    def test_reserve_replay_is_stable_and_changed_input_rejected(self):
        first = self.reserve(request_key="same")
        self.assertEqual(first["id"], self.reserve(request_key="same")["id"])
        self.assert_error("idempotency_conflict", lambda: self.reserve("MIG-aaaa", "hardware_partition", "same"))
        self.clock.now = 1200
        replay = self.service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key="same")
        self.assertEqual(first["id"], replay["id"])

    def test_released_generation_cannot_restart_or_release_successor(self):
        first = self.reserve()
        self.service.release(first["id"], generation=first["generation"], request_key="release")
        second = self.reserve()
        self.assertGreater(second["generation"], first["generation"])
        self.assert_error("stale_generation", lambda: self.service.release(second["id"], generation=first["generation"], request_key="stale"))
        self.assert_error("lease_not_startable", lambda: self.service.start(first["id"], generation=first["generation"], request_key="late", workload={"test_workload": True}))

    def test_started_work_is_cleaned_before_reallocation(self):
        lease = self.reserve()
        started = self.service.start(lease["id"], generation=lease["generation"], request_key="start", workload={"test_workload": True})
        self.assertEqual(started["state"], "active")
        self.assert_error("allocation_conflict", self.reserve)
        released = self.service.release(lease["id"], generation=lease["generation"], request_key="release")
        self.assertEqual(released["state"], "released")
        self.assertEqual(self.backend.running, {})
        self.reserve()

    def test_failed_cleanup_quarantines_and_retains_capacity(self):
        lease = self.reserve()
        self.backend.clean = False
        result = self.service.release(lease["id"], generation=lease["generation"], request_key="release")
        self.assertEqual(result["state"], "quarantined")
        self.backend.clean = True
        self.assert_error("allocation_conflict", self.reserve)
        result = self.service.release(lease["id"], generation=lease["generation"], request_key="retry-cleanup")
        self.assertEqual(result["state"], "released")

    def test_wrong_generation_cleanup_proof_cannot_free_resource(self):
        lease = self.reserve()
        self.backend.wrong_proof = True
        result = self.service.release(lease["id"], generation=lease["generation"], request_key="release")
        self.assertEqual(result["state"], "quarantined")

    def test_start_crash_survives_restart_and_drain_cannot_bypass_uncertainty(self):
        lease = self.reserve()
        self.backend.start_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.service.start(lease["id"], generation=lease["generation"], request_key="start", workload={"test_workload": True})
        resumed = Service(Store(self.path), self.backend, clock=self.clock)
        resumed.reconcile()
        self.assertEqual(resumed.get(lease["id"])["state"], "quarantined")
        resumed.drain(lease["id"], generation=lease["generation"], request_key="drain")
        self.assert_error("uncertain_launch", lambda: resumed.release(lease["id"], generation=lease["generation"], request_key="release"))
        self.assertEqual(self.backend.cleanup_calls, 0)

    def test_expiry_does_not_mean_handback(self):
        self.policy()
        claim = self.claim()
        self.clock.now = 2100
        self.service.reconcile()
        self.assertFalse(self.check(claim)["authorized"])
        self.assertTrue(self.service.bridge_inspect(platform_lease_id="platform-1", platform_epoch=1)["held"])
        self.assert_error("allocation_conflict", self.reserve)

    def test_external_requires_live_explicit_permission(self):
        self.assert_error("external_not_authorized", self.claim)
        self.policy()
        claim = self.claim()
        self.assertTrue(self.check(claim)["authorized"])
        self.policy(False, 2)
        self.assertFalse(self.check(claim)["authorized"])
        self.assertTrue(self.service.bridge_inspect(platform_lease_id="platform-1", platform_epoch=1)["held"])

    def test_local_allocation_blocks_external_even_if_gpu_idle(self):
        self.policy()
        self.reserve()
        self.assert_error("allocation_conflict", self.claim)
        self.assertFalse(self.service.bridge_status()["available"])

    def test_claim_replay_recovers_same_generation_after_revocation(self):
        self.policy()
        claim = self.claim()
        self.policy(False, 2)
        recovered = self.claim()
        self.assertEqual(recovered["generation"], claim["generation"])
        self.assertFalse(self.check(recovered)["authorized"])

    def test_claim_reclaim_complete_keeps_owner_blocked_until_independent_clean(self):
        self.policy()
        claim = self.claim()
        self.service.bridge_reclaim(platform_lease_id="platform-1", platform_epoch=1, generation=claim["generation"])
        self.assertFalse(self.check(claim)["authorized"])
        self.backend.clean = False
        result = self.service.bridge_complete(platform_lease_id="platform-1", platform_epoch=1,
                                              generation=claim["generation"], cleanup_verified=True)
        self.assertFalse(result["released"])
        self.backend.clean = True
        self.assert_error("allocation_conflict", self.reserve)
        result = self.service.bridge_complete(platform_lease_id="platform-1", platform_epoch=1,
                                              generation=claim["generation"], cleanup_verified=True)
        self.assertTrue(result["released"])
        self.reserve()

    def test_unknown_reclaim_tombstone_prevents_delayed_claim_without_cleaning_local_owner(self):
        self.policy()
        local = self.reserve()
        self.service.bridge_reclaim(platform_lease_id="platform-1", platform_epoch=1)
        info = self.service.bridge_inspect(platform_lease_id="platform-1", platform_epoch=1)
        self.assertFalse(info["held"])
        self.assertTrue(info["retired"])
        result = self.service.bridge_complete(platform_lease_id="platform-1", platform_epoch=1, cleanup_verified=True)
        self.assertTrue(result["released"])
        delayed = self.claim()
        self.assertTrue(delayed["retired"])
        self.assertFalse(self.check(delayed)["authorized"])
        self.assertEqual(self.backend.verify_calls, 0)
        self.assertEqual(self.service.get(local["id"])["state"], "reserved")

    def test_complete_needs_reclaim_and_does_not_accept_wrong_generation(self):
        self.policy()
        claim = self.claim()
        self.assert_error("reclaim_required", lambda: self.service.bridge_complete(platform_lease_id="platform-1", platform_epoch=1,
                                                                                  cleanup_verified=True, generation=claim["generation"]))
        self.assert_error("stale_generation", lambda: self.service.bridge_reclaim(platform_lease_id="platform-1", platform_epoch=1,
                                                                                generation=claim["generation"]+1))

    def test_local_release_cannot_free_external_claim(self):
        self.policy()
        claim = self.claim()
        self.assert_error("bridge_cleanup_required", lambda: self.service.release(claim["lease_id"], generation=claim["generation"], request_key="bypass"))

    def test_policy_and_clock_cannot_roll_back(self):
        self.policy()
        self.assert_error("stale_policy", lambda: self.policy(False, 1))
        self.clock.now = 900
        self.assert_error("clock_regression", self.reserve)

    def test_bridge_disabled_keeps_local_management_available(self):
        service = Service(Store(self.path), self.backend, clock=self.clock, bridge_enabled=False)
        self.assertFalse(service.bridge_status()["available"])
        lease = service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key="local")
        self.assertEqual(lease["owner"], "local")


if __name__ == "__main__":
    unittest.main()
