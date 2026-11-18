"""SQLite/Service seam with declared synthetic devices and enforcement, never GPU proof."""
import copy
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from dataclasses import replace
from pathlib import Path

from nodus_dc.errors import Error
from nodus_dc.api import BridgeUnixServer
from nodus_dc.model import CleanupProof
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend as BaseBackend, Clock
from tests.test_mig_binding import Devices, inventory
from tests.test_api import UnixHTTPConnection

GPU = "GPU-11111111-1111-4111-8111-111111111111"
A = "MIG-22222222-2222-4222-8222-222222222222"
B = "MIG-33333333-3333-4333-8333-333333333333"
IMAGE = "example/model@sha256:" + "a"*64


class Backend(BaseBackend):
    def __init__(self, clock, root):
        super().__init__(clock); self.root=root
        mapping={"GPU-aaaa":GPU,"MIG-aaaa":A,"MIG-bbbb":B}
        self.rows=tuple(replace(r,id=mapping.get(r.id,r.id),parent=mapping.get(r.parent,r.parent),
            device_uuid=mapping.get(r.device_uuid,r.device_uuid),busy=False,
            modes=("exclusive_host",) if r.kind=="host" else (("gpu_configuration",) if r.kind=="gpu" else ("hardware_partition",))) for r in inventory().resources)
    def partition_fence_path(self): return self.root/"registry"/"fence.json"
    def inventory(self): return replace(inventory(),observed_at=self.clock(),resources=self.rows)
    def configure_mig(self, lease, plan):
        with Store(self.root/"state.db").connection() as db:
            row=db.execute("SELECT state,generation FROM partition_configurations WHERE parent_uuid=?",(GPU,)).fetchone()
            assert row["state"]=="changing" and row["generation"]>0
        if getattr(self,"fail_configuration",False): raise RuntimeError("synthetic partial mutation")
        return self.inventory()


class Executor:
    """Declared fake at the runtime/enforcement seam; it qualifies no real tuple."""
    def __init__(self, clock):
        self.clock=clock; self.continuous=True; self.clean=True; self.verified=[]
        self.accounted=True; self.accounting=[]
    def qualification(self, binding):
        return {"qualified":True,"continuous_configuration_authority":self.continuous,"runtime_sha256":"b"*64,"accelerator":"a100-40gb"}
    def host_capacity(self): return {"cpu_millis":4000,"memory_bytes":8*1024**3,"scratch_bytes":8*1024**3}
    def verify_host_accounting(self, capacity, held, scope):
        self.accounting.append((capacity, held, scope))
        return self.accounted
    def prepare_reservation(self, lease, resources): return {"enforcement_ready":True,"synthetic":True}
    def verify_reservation(self, lease, reservation): return True
    def check_execution(self, lease, request): return True
    def verify_clean(self, lease, request):
        self.verified.append(tuple(lease["resources"]))
        return CleanupProof(self.clean,self.clock(),lease["id"],lease["generation"],tuple(lease["resources"]),{"synthetic":True})


class Partitions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix=".nodus-partition-",dir=Path.home().resolve())
        self.root=Path(self.tmp.name); self.clock=Clock(); self.backend=Backend(self.clock,self.root)
        self.service=Service(Store(self.root/"state.db"),self.backend,clock=self.clock,bridge_enabled=True)
        self.p=self.service.partitions; self.p.devices=Devices()
        self.p.devices.files["/proc/driver/nvidia/gpus/0000:07:00.0/information"] = f"GPU UUID: {GPU}\nDevice Minor: 3\n"
        for suffix,minor in (("access",69),("ci0/access",70)):
            self.p.devices.files["/proc/driver/nvidia/capabilities/gpu3/mig/gi8/"+suffix]=f"DeviceFileMinor: {minor}\n"
            self.p.devices.nodes[f"/dev/nvidia-caps/nvidia-cap{minor}"]=(508,minor)
        self.executor=Executor(self.clock); self.p.executor=self.executor
        self.agreement={"node_id":"node-1","consent_id":"partition-consent-1","generation":7,"terms_sha256":"c"*64}
        # Independent declared synthetic policy; whole-host policy remains absent.
        self.p.policy_provider=self.synthetic_policy
        self.adopt("initial")
    def tearDown(self): self.tmp.cleanup()
    def synthetic_policy(self, db, *, expected_revision=None, workload=None):
        return {"policy_revision":1,"available_until_unix_millis":2000000,"agreement":dict(self.agreement),"shapes":[{"shape":{
            "accelerator":"a100-40gb","profile":"3g.20gb","gpuMemoryBytes":21072183296,
            "cpuMillis":2000,"memoryBytes":3*1024**3,"scratchBytes":128*1024**2},"hourlyUSD":"1.00"}]}
    def adopt(self, key, parent=GPU):
        lease=self.service.reserve(resources=[parent],mode="gpu_configuration",expires_at=1500,request_key="maintenance-"+key)
        self.service.adopt_partitions(lease["id"],generation=lease["generation"],request_key="adopt-"+key)
        self.service.release(lease["id"],generation=lease["generation"],request_key="release-"+key)
    def request(self, resource=B, name="borrowed"):
        offer=next(o for o in self.p.offers()["offers"] if o["partition"]["resource_id"]==resource)
        return {"platform_lease_id":name,"platform_epoch":1,"generation":0,"offer":offer,"workload":{"workload_image":IMAGE,"workload_kind":"Job"},
                "resources":{"cpu_millis":2000,"memory_bytes":3*1024**3,"scratch_bytes":128*1024**2},"expires_at_unix_millis":1100000}
    def assert_error(self,code,callback):
        with self.assertRaises(Error) as exc: callback()
        self.assertEqual(exc.exception.code,code)

    def test_shared_host_budget_report_and_atomic_claim_refuse_unaccounted_work(self):
        resources = {"cpu_millis":1000,"memory_bytes":2*1024**3,"scratch_bytes":128*1024**2}
        local = self.service.reserve(resources=[A], mode="hardware_partition", expires_at=1400,
                                     request_key="budget-local", host_resources=resources)
        server = BridgeUnixServer(str(self.root/"budget.sock"), self.service, "fixture-"+"x"*40, owner_uid=os.geteuid())
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def request(body):
            connection = UnixHTTPConnection(server.path)
            try:
                connection.request("POST", "/v2/bridge/partitions/offers", json.dumps(body).encode(),
                                   {"Authorization":"Bearer "+server.bridge_token})
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally: connection.close()
        try:
            status, report = request({"include_host_budget":True})
            self.assertEqual(status, 200)
            self.assertEqual(report["host_budget"], {"capacity":self.executor.host_capacity(), "local_reserved":resources})
            self.assertEqual([o["partition"]["resource_id"] for o in report["offers"]], [B])
            self.assertEqual(set(request({})[1]), {"offers"})
            self.assertEqual(request({"include_host_budget":False})[0], 400)
            capacity, held, scope = self.executor.accounting[-1]
            self.assertEqual((capacity, [(r["lease"]["id"],r["resources"]) for r in held]),
                             (self.executor.host_capacity(), [(local["id"],resources)]))
            self.assertEqual(scope["authority_incarnation"], report["offers"][0]["partition"]["authority_incarnation"])
            self.assertEqual(scope["configurations"][0]["generation"], report["offers"][0]["partition"]["configuration_generation"])
            frozen = self.request()
            self.executor.accounted = False  # unmanaged work or lost enforced ownership boundary
            self.assertEqual(request({"include_host_budget":True}), (200,{"offers":[],"host_budget":None}))
            self.assert_error("host_resources_unaccounted", lambda:self.p.claim(**frozen))
            self.assertFalse(self.p.inspect(**frozen)["held"])
            self.executor.accounted = True
            with patch.object(self.executor, "verify_host_accounting", None):
                self.assertEqual(request({"include_host_budget":True}), (200,{"offers":[],"host_budget":None}))
                self.assertEqual(request({}), (200,{"offers":[]}))
                self.assert_error("host_resources_unaccounted", lambda:self.p.claim(**frozen))
            borrowed = self.p.claim(**frozen)["lease"]
            self.assertEqual(request({"include_host_budget":True})[1]["host_budget"]["local_reserved"], resources)
            self.assertEqual(sorted((r["lease"]["owner"],r["resources"]) for r in self.executor.accounting[-1][1]),
                             [("external",borrowed["resources"]),("local",resources)])
            self.executor.accounted = False
            self.assertFalse(self.p.check(**borrowed)["authorized"])
            self.assertTrue(self.p.inspect(**borrowed)["held"])
            self.assertEqual(self.p.reclaim(**borrowed)["lease"], borrowed)
            self.assertTrue(self.p.complete(lease=borrowed,cleanup_verified=True)["released"])
            self.assertEqual(self.service.get(local["id"])["state"], "reserved")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

    def test_disjoint_external_claims_share_budget_and_cleanup_preserves_local_and_borrowed_siblings(self):
        # Four declared 1g instances; only three fit the enforced host CPU budget concurrently.
        host, parent, child = self.backend.rows[:3]
        identities = [A, B, "MIG-44444444-4444-4444-8444-444444444444", "MIG-55555555-5555-4555-8555-555555555555"]
        rows, mapping = [host, parent], ["config 1\n", "monitor 2\n"]
        for index, identity in enumerate(identities):
            gi, minor = 7+index, 67+index*2
            rows.append(replace(child, id=identity, device_uuid=identity, details={**child.details,
                "gpu_instance_id":gi, "profile":"1g.5gb", "memory_capacity_bytes":5268045824}))
            for suffix, number in (("access",minor),("ci0/access",minor+1)):
                mapping.append(f"gpu3/gi{gi}/{suffix} {number}\n")
                self.p.devices.files[f"/proc/driver/nvidia/capabilities/gpu3/mig/gi{gi}/{suffix}"] = f"DeviceFileMinor: {number}\n"
                self.p.devices.nodes[f"/dev/nvidia-caps/nvidia-cap{number}"] = (508,number)
        self.backend.rows = tuple(rows)
        self.p.devices.files["/proc/driver/nvidia-caps/mig-minors"] = "".join(mapping)
        policy = self.synthetic_policy(None)
        policy["shapes"][0]["shape"].update(profile="1g.5gb",gpuMemoryBytes=5268045824,cpuMillis=1500,memoryBytes=2*1024**3)
        self.p.policy_provider = lambda db, **kwargs: policy
        self.adopt("four-disjoint")
        local_resources = {"cpu_millis":1000,"memory_bytes":1024**3,"scratch_bytes":128*1024**2}
        local = self.service.reserve(resources=[A],mode="hardware_partition",expires_at=1400,
            request_key="multi-local",host_resources=local_resources)
        self.service.start(local["id"],generation=local["generation"],request_key="multi-start",workload={"test_workload":True})
        baseline_cleanup = self.backend.cleanup_calls
        server = BridgeUnixServer(str(self.root/"multi.sock"), self.service, "fixture-"+"x"*40, owner_uid=os.geteuid())
        thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        workers = []
        def call(op, body):
            connection = UnixHTTPConnection(server.path)
            try:
                connection.request("POST","/v2/bridge/partitions/"+op,json.dumps(body).encode(),
                    {"Authorization":"Bearer "+server.bridge_token})
                response = connection.getresponse()
                return response.status,json.loads(response.read())
            finally: connection.close()
        def request(offer, name):
            return {"platform_lease_id":name,"platform_epoch":1,"generation":0,"offer":offer,
                "workload":{"workload_image":IMAGE,"workload_kind":"Job"},"resources":dict(offer["capacity"]),
                "expires_at_unix_millis":1100000}
        try:
            status, observed = call("offers",{"include_host_budget":True})
            self.assertEqual(status,200)
            self.assertEqual(observed["host_budget"]["local_reserved"],local_resources)
            offers = {o["partition"]["resource_id"]:o for o in observed["offers"]}
            self.assertEqual(set(offers),set(identities[1:]))
            first = request(offers[B],"multi-b")
            status, response = call("claim",first); self.assertEqual(status,200)
            held_b = response["lease"]
            self.assertEqual(call("claim",first),(200,{"lease":held_b}))
            forged = request(copy.deepcopy(offers[identities[2]]),"same-gi")
            forged["offer"]["partition"]["gpu_instance"] = held_b["offer"]["partition"]["gpu_instance"]
            refused, detail = call("claim",forged)
            self.assertEqual((refused,detail["error"]["code"]),(409,"stale_partition_offer"))
            contenders = [request(offers[identity],"multi-"+str(index)) for index,identity in enumerate(identities[2:])]
            barrier = threading.Barrier(3,timeout=5)
            outcomes, failures = [], []
            def acquire(candidate):
                try:
                    barrier.wait()
                    outcomes.append((candidate,call("claim",candidate)))
                except Exception as exc: failures.append(exc)
            workers = [threading.Thread(target=acquire,args=(r,),daemon=True) for r in contenders]
            for worker in workers: worker.start()
            barrier.wait()
            for worker in workers: worker.join(5)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(failures,[])
            self.assertEqual(sorted(result[0] for _,result in outcomes),[200,409])
            winner = next(result[1]["lease"] for _,result in outcomes if result[0]==200)
            loser = next(candidate for candidate,result in outcomes if result[0]==409)
            self.assertEqual(call("offers",{})[1],{"offers":[]})
            with self.service.store.connection() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM leases WHERE owner='external' AND state!='released'").fetchone()[0],2)
                self.assertEqual(db.execute("SELECT sum(cpu_millis) FROM host_reservations r JOIN leases l ON l.id=r.lease_id WHERE l.state!='released'").fetchone()[0],4000)
            self.assertTrue(call("check",held_b)[1]["authorized"])
            self.assertTrue(call("check",winner)[1]["authorized"])
            self.executor.clean = False
            self.assertEqual(call("reclaim",winner)[1]["lease"],winner)
            self.assertFalse(call("complete",{"lease":winner,"cleanup_verified":True})[1]["released"])
            self.assertTrue(call("inspect",winner)[1]["held"])
            self.assertEqual(call("claim",loser)[0],409)
            self.assertTrue(call("check",held_b)[1]["authorized"])
            self.executor.clean = True
            self.assertTrue(call("complete",{"lease":winner,"cleanup_verified":True})[1]["released"])
            self.assertTrue(call("check",held_b)[1]["authorized"])
            self.assertEqual(call("inspect",held_b),(200,{"lease":held_b,"held":True}))
            self.assertEqual(self.executor.verified[-2:],[(winner["offer"]["partition"]["resource_id"],)]*2)
            self.assertEqual(self.service.get(local["id"])["state"],"active")
            status, response = call("claim",loser); self.assertEqual(status,200)
            for held in (held_b,response["lease"]):
                self.assertTrue(call("reclaim",held)[1]["retired"])
                self.assertTrue(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
            self.assertEqual(self.backend.cleanup_calls,baseline_cleanup)
            self.assertEqual(call("offers",{"include_host_budget":True})[1]["host_budget"]["local_reserved"],local_resources)
            self.assertEqual(self.service.get(local["id"])["state"],"active")
        finally:
            for worker in workers: worker.join(5)
            server.shutdown(); server.server_close(); thread.join(5)
            self.assertFalse(thread.is_alive())

    def test_complete_multi_gpu_offer_report_is_bounded_without_truncation(self):
        host, parent, child = self.backend.rows[:3]
        policy = self.synthetic_policy(None)
        policy["shapes"][0]["shape"].update(profile="1g.5gb", gpuMemoryBytes=5268045824, cpuMillis=1000, memoryBytes=1024**3)
        self.agreement.update(node_id="bnod_"+"a"*26, consent_id="bpcs_"+"b"*26)
        policy["agreement"] = self.agreement
        self.p.policy_provider = lambda db, **kwargs: policy

        def fleet(counts):
            rows, mapping, parents = [host], ["config 1\n", "monitor 2\n"], []
            for index, count in enumerate(counts):
                gpu = f"GPU-00000000-0000-4000-8000-{index+1:012x}"
                pci = f"0000:{index+1:02x}:00.0"
                parents.append(gpu)
                rows.append(replace(parent, id=gpu, device_uuid=gpu, details={**parent.details, "pci_bus_id":pci}))
                self.p.devices.files[f"/proc/driver/nvidia/gpus/{pci}/information"] = f"GPU UUID: {gpu}\nDevice Minor: {index}\n"
                self.p.devices.nodes[f"/dev/nvidia{index}"] = (195,index)
                for part in range(count):
                    mig = f"MIG-00000000-0000-4000-8000-{index*7+part+1:012x}"
                    gi = 7+part
                    rows.append(replace(child, id=mig, device_uuid=mig, parent=gpu, details={**child.details,
                        "gpu_instance_id":gi, "profile":"1g.5gb", "memory_capacity_bytes":5268045824}))
                    for suffix, minor in (("access",3+index*135+gi*9),("ci0/access",4+index*135+gi*9)):
                        mapping.append(f"gpu{index}/gi{gi}/{suffix} {minor}\n")
                        self.p.devices.files[f"/proc/driver/nvidia/capabilities/gpu{index}/mig/gi{gi}/{suffix}"] = f"DeviceFileMinor: {minor}\n"
                        self.p.devices.nodes[f"/dev/nvidia-caps/nvidia-cap{minor}"] = (508,minor)
            self.backend.rows = tuple(rows)
            self.p.devices.files["/proc/driver/nvidia-caps/mig-minors"] = "".join(mapping)
            for index, gpu in enumerate(parents): self.adopt(f"fleet-{sum(counts)}-{index}", gpu)
            return {r.id for r in rows if r.kind == "partition"}

        expected = fleet([7]*8)
        server = BridgeUnixServer(str(self.root/"offers.sock"), self.service, "fixture-"+"x"*40, owner_uid=os.geteuid())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request():
            connection = UnixHTTPConnection(server.path)
            try:
                connection.request("POST", "/v2/bridge/partitions/offers", b"{}", {"Authorization":"Bearer "+server.bridge_token})
                response = connection.getresponse()
                return response.status, response.read(65537)
            finally: connection.close()
        try:
            status, raw = request()
            self.assertEqual(status, 200); self.assertLessEqual(len(raw), 65536)
            offers = json.loads(raw)["offers"]
            self.assertEqual(len(offers), 56)
            self.assertEqual({o["partition"]["resource_id"] for o in offers}, expected)
            self.assertEqual(len({(o["partition"]["parent_uuid"],o["partition"]["gpu_instance"]) for o in offers}), 56)

            # Individually valid identifier lengths can still overflow the complete response.
            self.agreement.update(node_id="n"*128, consent_id="c"*128)
            self.assertGreater(len(json.dumps({"offers":[{**o,"agreement":self.agreement} for o in offers]},sort_keys=True,allow_nan=False).encode()),65536)
            status, raw = request()
            self.assertEqual(status,503)
            self.assertEqual(json.loads(raw)["error"]["code"],"partition_offer_report_too_large")
            self.assertNotIn("offers",json.loads(raw))
            self.agreement.update(node_id="bnod_"+"a"*26, consent_id="bpcs_"+"b"*26)
            self.assertEqual(len(json.loads(request()[1])["offers"]),56)

            fleet([7]*9+[2])
            status, raw = request()
            self.assertEqual(status,503)
            self.assertEqual(json.loads(raw)["error"]["code"],"partition_offer_report_too_large")
            with self.service.store.connection() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM partition_claims").fetchone()[0],0)
                self.assertEqual(db.execute("SELECT count(*) FROM leases WHERE state!='released'").fetchone()[0],0)
        finally:
            server.shutdown(); server.server_close(); thread.join(5)
            self.assertFalse(thread.is_alive())

    def test_invalid_driver_preflight_does_not_mutate_configuration(self):
        lease = self.service.reserve(resources=[GPU], mode="gpu_configuration", expires_at=1500, request_key="preflight")
        self.p.devices.files["/sys/module/nvidia/srcversion"] = "malformed"
        with self.service.store.connection() as db:
            original = tuple(db.execute("SELECT * FROM partition_configurations WHERE parent_uuid=?", (GPU,)).fetchone())
        with patch.object(self.backend, "configure_mig", wraps=self.backend.configure_mig) as mutate:
            self.assert_error("partition_binding_unavailable", lambda: self.service.configure(
                lease["id"], generation=lease["generation"], request_key="bad-driver", plan={"enabled":True,"profiles":["3g.20gb"]}))
            mutate.assert_not_called()
        current = self.service.get(lease["id"])
        self.assertEqual((current["state"], current["runtime"], current["workload"]), ("reserved", None, None))
        self.assertEqual(current["baseline"], lease["baseline"])
        with self.service.store.connection() as db:
            self.assertEqual(tuple(db.execute("SELECT * FROM partition_configurations WHERE parent_uuid=?", (GPU,)).fetchone()), original)

    def test_final_observation_failure_quarantines_without_releasing_uncertain_change(self):
        lease = self.service.reserve(resources=[GPU], mode="gpu_configuration", expires_at=1500, request_key="post-observation")
        prior_cleanup_calls = self.backend.cleanup_calls
        configure = self.backend.configure_mig
        def change_then_lose_identity(held, plan):
            result = configure(held, plan)
            self.p.devices.files["/sys/module/nvidia/srcversion"] = "malformed"
            return result
        plan = {"enabled":True,"profiles":["3g.20gb"]}
        with patch.object(self.backend, "configure_mig", side_effect=change_then_lose_identity) as mutate:
            self.assert_error("configuration_uncertain", lambda: self.service.configure(
                lease["id"], generation=lease["generation"], request_key="post-driver", plan=plan))
            self.assertEqual(mutate.call_count, 1)
        restarted = Service(Store(self.root/"state.db"), self.backend, clock=self.clock)
        current = restarted.get(lease["id"])
        self.assertEqual((current["state"], current["runtime"], current["workload"]), ("quarantined", None, {"mig_plan":plan}))
        self.assertEqual(current["baseline"], lease["baseline"])
        with restarted.store.connection() as db:
            self.assertEqual(db.execute("SELECT state FROM partition_configurations WHERE parent_uuid=?", (GPU,)).fetchone()[0], "quarantined")
        self.assert_error("uncertain_launch", lambda: restarted.release(lease["id"], generation=lease["generation"], request_key="no-reset"))
        self.assertEqual(self.backend.cleanup_calls, prior_cleanup_calls)

    def test_bad_registration_preflight_never_mutates_configuration(self):
        lease = self.service.reserve(resources=[GPU], mode="gpu_configuration", expires_at=1500, request_key="registration-preflight")
        valid = "195 nvidia\n195 nvidiactl\n511 nvidia-uvm\n508 nvidia-caps\n"
        malformed = [
            valid.replace("195 nvidiactl\n", ""),
            valid.replace("195 nvidiactl", "196 nvidiactl"),
            valid + "195 nvidia-frontend\n",
            valid + "195 nvidia\n",
            valid + "511 nvidia-uvm\n",
            valid.replace("511 nvidia-uvm\n", ""),
            valid.replace("508 nvidia-caps\n", ""),
            valid.replace("195 nvidia\n", "195 unknown-nvidia\n"),
            "195 nvidia-frontend\n195 nvidia-frontend\n511 nvidia-uvm\n508 nvidia-caps\n",
            "195 nvidia-frontend\n195 nvidiactl\n511 nvidia-uvm\n508 nvidia-caps\n",
        ]
        with self.service.store.connection() as db:
            original = tuple(db.execute("SELECT * FROM partition_configurations WHERE parent_uuid=?", (GPU,)).fetchone())
            event_count = db.execute("SELECT count(*) FROM events").fetchone()[0]
        for index, content in enumerate(malformed):
            with self.subTest(layout=index):
                self.p.devices.files["/proc/devices"] = "Character devices:\n" + content + "\nBlock devices:\n8 sd\n"
                with patch.object(self.backend, "configure_mig", wraps=self.backend.configure_mig) as mutate:
                    self.assert_error("partition_binding_unavailable", lambda: self.service.configure(
                        lease["id"], generation=lease["generation"], request_key=f"bad-registration-{index}", plan={"enabled":True,"profiles":["3g.20gb"]}))
                    mutate.assert_not_called()
                current = self.service.get(lease["id"])
                self.assertEqual((current["state"], current["runtime"], current["workload"]), ("reserved", None, None))
                self.assertEqual(current["baseline"], lease["baseline"])
                with self.service.store.connection() as db:
                    self.assertEqual(tuple(db.execute("SELECT * FROM partition_configurations WHERE parent_uuid=?", (GPU,)).fetchone()), original)
                    self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], event_count)

    def test_configuration_expiry_during_driver_preflight_never_mutates(self):
        lease = self.service.reserve(resources=[GPU], mode="gpu_configuration", expires_at=1001, request_key="preflight-expiry")
        read = self.p.devices.text
        def expire(path):
            if path == "/sys/module/nvidia/srcversion": self.clock.now = 1002
            return read(path)
        with patch.object(self.p.devices, "text", side_effect=expire), patch.object(self.backend, "configure_mig") as mutate:
            self.assert_error("lease_expired", lambda: self.service.configure(
                lease["id"], generation=lease["generation"], request_key="expired", plan={"enabled":True,"profiles":["3g.20gb"]}))
            mutate.assert_not_called()
        current = self.service.get(lease["id"])
        self.assertEqual((current["state"], current["runtime"], current["workload"]), ("reserved", None, None))

    def test_captured_driver_configures_from_no_children_and_disable_skips_preflight(self):
        configured = self.backend.rows
        def disabled_rows():
            return tuple(replace(r, details={**r.details,"mig_mode":"Disabled"}) if r.kind=="gpu" else r
                         for r in configured if r.kind != "partition")
        self.backend.rows = disabled_rows()
        lease = self.service.reserve(resources=[GPU], mode="gpu_configuration", expires_at=1500, request_key="captured-driver")
        self.p.devices.files["/sys/module/nvidia/srcversion"] = "12B00758E1DCB3540DF2F3A"
        self.p.devices.files["/proc/devices"] = "Character devices:\n195 nvidia\n195 nvidiactl\n511 nvidia-uvm\n508 nvidia-caps\n\nBlock devices:\n8 sd\n"
        configure = self.backend.configure_mig
        def change(held, plan):
            self.backend.rows = configured if plan["enabled"] else disabled_rows()
            return configure(held, plan)
        with patch.object(self.backend, "configure_mig", side_effect=change) as mutate:
            enabled = self.service.configure(lease["id"], generation=lease["generation"], request_key="enabled",
                                             plan={"enabled":True,"profiles":["3g.20gb","3g.20gb"]})
            self.assertEqual(enabled["state"], "reserved")
            with self.service.store.connection() as db:
                binding = json.loads(db.execute("SELECT binding FROM partition_configurations WHERE parent_uuid=?", (GPU,)).fetchone()[0])
            self.assertEqual([b["driver_source_version"] for b in binding["bindings"]], ["12B00758E1DCB3540DF2F3A"] * 2)
            self.p.devices.files["/sys/module/nvidia/srcversion"] = "malformed"
            disabled = self.service.configure(lease["id"], generation=lease["generation"], request_key="disabled",
                                              plan={"enabled":False,"profiles":[]})
            self.assertEqual(disabled["state"], "reserved")
            self.assertFalse(any(r["kind"] == "partition" for r in disabled["baseline"]))
            self.assertEqual(mutate.call_count, 2)

    def test_claim_sibling_budget_cleanup_and_payload_tombstone(self):
        local=self.service.reserve(resources=[A],mode="hardware_partition",expires_at=1400,request_key="local",
            host_resources={"cpu_millis":1000,"memory_bytes":2*1024**3,"scratch_bytes":128*1024**2})
        self.service.start(local["id"],generation=local["generation"],request_key="start-local",workload={"test_workload":True})
        request=self.request(); held=self.p.claim(**request)["lease"]
        self.assertTrue(self.p.check(**held)["authorized"])
        for operation, extra in ((self.service.bridge_reclaim, {}), (self.service.bridge_complete, {"cleanup_verified":True}),
                                 (self.service.bridge_inspect, {}), (self.service.bridge_check, {"generation":held["generation"]})):
            self.assert_error("platform_protocol_conflict",lambda op=operation,kw=extra:op(platform_lease_id="borrowed",platform_epoch=1,**kw))
        self.assertTrue(self.p.check(**held)["authorized"])
        self.assertEqual(self.p.claim(**request)["lease"],held)
        changed=copy.deepcopy(request); changed["resources"]["cpu_millis"]-=1
        self.assert_error("idempotency_conflict",lambda:self.p.reclaim(**changed))
        self.assertEqual(self.p.offers(),{"offers":[]})  # Both observed instances remain held.
        self.assert_error("allocation_conflict",lambda:self.service.reserve(resources=["host-a"],mode="exclusive_host",expires_at=1500,request_key="host"))
        retired=self.p.reclaim(**request)["lease"]; self.assertEqual(retired,held)
        self.assertTrue(self.p.inspect(**request)["held"])
        self.assert_error("stale_generation",lambda:self.p.complete(lease=request,cleanup_verified=True))
        self.executor.clean=False
        self.assertFalse(self.p.complete(lease=held,cleanup_verified=True)["released"])
        self.assertEqual(self.service.get(local["id"])["state"],"active")
        self.executor.clean=True
        self.assertTrue(self.p.complete(lease=held,cleanup_verified=True)["released"])
        self.assertEqual(self.executor.verified,[(B,),(B,)])
        self.assertEqual(self.service.get(local["id"])["state"],"active")
        self.assertTrue(self.p.offers()["offers"])

    def test_reverse_unbudgeted_sibling_admission_is_refused(self):
        held=self.p.claim(**self.request())["lease"]
        self.assert_error("host_resources_required",lambda:self.service.reserve(resources=[A],mode="hardware_partition",expires_at=1400,request_key="unbudgeted-after-b"))
        self.assertTrue(self.p.check(**held)["authorized"])
        self.assertEqual(self.backend.running,{})
        self.assertTrue(self.p.inspect(**held)["held"])

    def test_unknown_reclaim_is_exact_and_prevents_delayed_or_v1_claim(self):
        request=self.request(); self.assertEqual(self.p.reclaim(**request)["lease"],request)
        self.assertFalse(self.p.inspect(**request)["held"])
        self.assert_error("platform_claim_retired",lambda:self.p.claim(**request))
        changed=copy.deepcopy(request); changed["workload"]["workload_image"]="example/other@sha256:"+"d"*64
        self.assert_error("idempotency_conflict",lambda:self.p.complete(lease=changed,cleanup_verified=True))
        self.assertTrue(self.p.complete(lease=request,cleanup_verified=True)["released"])
        self.assert_error("platform_protocol_conflict",lambda:self.service.bridge_claim(platform_lease_id="borrowed",platform_epoch=1,policy_revision=1,idempotency_key="v1"))
        self.assertEqual(self.executor.verified,[])

    def test_expiry_consent_generation_and_unqualified_gate(self):
        request=self.request(); held=self.p.claim(**request)["lease"]
        self.agreement["generation"]+=1
        self.assertFalse(self.p.check(**held)["authorized"])
        self.agreement["generation"]-=1; self.clock.now=1101
        self.assertFalse(self.p.check(**held)["authorized"])
        self.clock.now=1102; self.p.executor=None
        self.assertEqual(self.p.offers(),{"offers":[]})

    def test_runtime_check_cannot_outlive_lease_expiry(self):
        held=self.p.claim(**self.request())["lease"]
        def slow_check(*_):
            self.clock.now=1101
            return True
        self.executor.check_execution=slow_check
        self.assertFalse(self.p.check(**held)["authorized"])
        self.assertTrue(self.p.inspect(**held)["held"])

    def test_unaccounted_sibling_and_changed_configuration_stay_fenced(self):
        local=self.service.reserve(resources=[A],mode="hardware_partition",expires_at=1400,request_key="unbudgeted")
        self.assertEqual(self.p.offers(),{"offers":[]})
        self.service.release(local["id"],generation=local["generation"],request_key="release-unbudgeted")
        old=self.request(); rows=self.backend.rows
        self.backend.rows=tuple(replace(r,details={**r.details,"profile":"2g.10gb"}) if r.id==B else r for r in rows)
        self.service.inventory(); self.backend.rows=rows
        self.assertEqual(self.p.offers(),{"offers":[]})
        self.adopt("readopt")
        new=self.request()
        self.assertGreater(new["offer"]["partition"]["configuration_generation"],old["offer"]["partition"]["configuration_generation"])
        self.assert_error("stale_partition_offer",lambda:self.p.claim(**old))

    def test_database_rollback_fails_closed_with_live_claim(self):
        backup=self.root/"older.db"
        import sqlite3
        with self.service.store.connection() as db, sqlite3.connect(backup) as target: db.backup(target)
        held=self.p.claim(**self.request())["lease"]
        os.replace(backup,self.root/"state.db")
        for suffix in ("-wal","-shm"): Path(str(self.root/"state.db")+suffix).unlink(missing_ok=True)
        self.assert_error("authority_continuity_lost",lambda:self.p.check(**held))

    def test_monitor_gap_invalidates_generation_and_tombstone_survives_restart(self):
        request=self.request(); self.p.reclaim(**request)
        restarted=Service(Store(self.root/"state.db"),self.backend,clock=self.clock,bridge_enabled=True)
        self.assertFalse(restarted.partitions.inspect(**request)["held"])
        self.executor.continuous=False; self.service.inventory(); self.executor.continuous=True
        self.assertEqual(self.p.offers(),{"offers":[]})

    def test_initial_rejection_does_not_poison_independent_registry(self):
        fresh=self.root/"fresh"; fresh.mkdir(mode=0o700)
        backend=Backend(self.clock,fresh)
        service=Service(Store(fresh/"state.db"),backend,clock=self.clock,bridge_enabled=True)
        service.bridge_policy(enabled=True,policy_revision=1,consent_reference="v1-only",authorization_id="fresh",expires_at=2000)
        self.assert_error("partition_policy_unavailable",lambda:service.partitions.claim(**self.request()))
        self.assert_error("partition_executor_unqualified",lambda:service.reserve(resources=[A],mode="hardware_partition",expires_at=1400,request_key="budgeted",host_resources={"cpu_millis":1,"memory_bytes":1024,"scratch_bytes":0}))
        local=service.reserve(resources=[A],mode="hardware_partition",expires_at=1400,request_key="ordinary")
        self.assertEqual(local["state"],"reserved")

    def test_activation_crash_and_observation_failure_cannot_revive_authority(self):
        fresh=self.root/"crashed"; fresh.mkdir(mode=0o700)
        service=Service(Store(fresh/"state.db"),Backend(self.clock,fresh),clock=self.clock)
        with self.assertRaises(RuntimeError):
            with service.store.transaction(self.clock()) as db:
                service.store.fence.activate(db)
                raise RuntimeError("synthetic crash before SQLite commit")
        self.assert_error("authority_continuity_lost",service.inventory)
        old=self.request(); original=self.backend.inventory
        self.backend.inventory=lambda:(_ for _ in ()).throw(Error("observation_failed","synthetic failure",503))
        self.assert_error("observation_failed",self.service.inventory)
        self.backend.inventory=original
        self.assertEqual(self.p.offers(),{"offers":[]})
        self.assert_error("stale_partition_offer",lambda:self.p.claim(**old))
        self.adopt("observation-return")
        original_qualification=self.executor.qualification
        self.executor.qualification=lambda _:(_ for _ in ()).throw(RuntimeError("monitor unavailable"))
        self.service.inventory()
        self.executor.qualification=original_qualification
        self.assertEqual(self.p.offers(),{"offers":[]})

    def test_repeated_qualification_failure_cannot_revive_offer_or_claim(self):
        original=self.executor.qualification
        for operation in ("offers", "claim", "check"):
            with self.subTest(operation=operation):
                request=self.request(name="repeat-"+operation)
                held=self.p.claim(**request)["lease"] if operation=="check" else None
                calls={}
                def lose_after_observation(binding):
                    key=binding["partition_uuid"]; calls[key]=calls.get(key,0)+1
                    if calls[key]>1: raise RuntimeError("monitor lost after inventory transaction")
                    return original(binding)
                self.executor.qualification=lose_after_observation
                action=(self.p.offers if operation=="offers" else
                        lambda:self.p.claim(**request)) if operation!="check" else lambda:self.p.check(**held)
                self.assert_error("partition_continuity_lost",action)
                self.assertTrue(any(count==2 for count in calls.values()))
                self.executor.qualification=original
                self.assertEqual(self.p.offers(),{"offers":[]})
                if held:
                    self.assertFalse(self.p.check(**held)["authorized"])
                    self.assertTrue(self.p.inspect(**held)["held"])
                else:
                    self.assert_error("stale_partition_offer",lambda:self.p.claim(**request))
                    self.adopt("after-"+operation)

    def test_managed_change_journals_generation_before_driver_mutation(self):
        lease=self.service.reserve(resources=[GPU],mode="gpu_configuration",expires_at=1500,request_key="configure")
        self.backend.fail_configuration=True
        self.assert_error("configuration_uncertain",lambda:self.service.configure(lease["id"],generation=lease["generation"],request_key="change",plan={"enabled":True,"profiles":["3g.20gb","3g.20gb"]}))
        with self.service.store.connection() as db:
            row=db.execute("SELECT state,generation FROM partition_configurations").fetchone()
            self.assertEqual(row["state"],"quarantined"); self.assertGreater(row["generation"],1)

if __name__ == "__main__": unittest.main()
