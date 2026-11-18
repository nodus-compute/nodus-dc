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
        return {"qualified":True,"continuous_configuration_authority":self.continuous,"runtime_sha256":"b"*64,"accelerator":"a100-40gb",
                "execution_identity": {**{key:"b"*64 for key in (
                    "manifest_sha256","qualification_sha256","runsc_sha256","sentry_sha256",
                    "scoped_shim_sha256","containerd_shim_sha256","cdi_sha256","libraries_sha256","hooks_sha256")},
                    "cdi_path":"/owned/synthetic/cdi.json"}}
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

    def enable_ephemeral_profile(self, task=None, capacity=None):
        """Explicit synthetic aggregate provider shared with the Go/private Unix fixture."""
        from nodus_dc import ephemeral
        task = task or {"cpu_millis":2000,"memory_bytes":3*1024**3,"scratch_bytes":64*1024**2}
        capacity = capacity or {"cpu_millis":8000,"memory_bytes":8*1024**3,"scratch_bytes":128*1024**2}
        policy = self.synthetic_policy(None)
        policy["shapes"][0]["shape"].update(cpuMillis=task["cpu_millis"],memoryBytes=task["memory_bytes"],scratchBytes=task["scratch_bytes"])
        self.p.policy_provider = lambda db, **kwargs: policy
        original_capacity = self.executor.host_capacity
        self.executor.host_capacity = lambda *, accounting_version=None: original_capacity() if accounting_version is None else {
            "accounting_version":ephemeral.ACCOUNTING,"capacity":dict(capacity)}
        self.executor.prepare_reservation = lambda lease, resources: {
            "enforcement_ready":True,"synthetic":True,"accounting_version":ephemeral.ACCOUNTING}
        return dict(task)

    def enable_trusted_profile(self):
        """Protocol fixture: real Linux socket peers, explicitly synthetic host/GPU evidence."""
        from nodus_dc import ephemeral
        from nodus_dc.partition_execution import PROVIDER
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.backend.rows = tuple(replace(row, details={**row.details,"boot_id":boot})
                                  if row.kind == "host" else row for row in self.backend.rows)
        self.p.devices.files["/proc/sys/kernel/random/boot_id"] = boot
        self.adopt("kernel-peer-boot")
        task = self.enable_ephemeral_profile()
        self.executor.published = False
        self.executor.prepares = 0
        self.executor.contexts = []
        image = {"version":1,"reference":IMAGE,"manifest_sha256":"a"*64,"config_sha256":"e"*64,
                 "rootfs_chain_sha256":"f"*64,"os":"linux","architecture":"amd64","user":"0:0",
                 "workdir":"/","namespace":"nodus-fixture","snapshotter":"overlayfs","spec_sha256":"d"*64}
        def prepare(local, resources, *, context):
            self.executor.prepares += 1
            self.assertEqual(resources, context["lease"]["ephemeral"]["charge"]["aggregate"])
            capacity = self.executor.host_capacity(accounting_version=ephemeral.ACCOUNTING)["capacity"]
            host = {"version":1,"accounting_version":ephemeral.ACCOUNTING,"boot_id":boot,
                    "authority_incarnation":context["authority_scope"]["authority_incarnation"],
                    **{name+"_namespace":os.readlink("/proc/self/ns/"+name) for name in ("pid","user","cgroup")},
                    "root":{"path":"/sys/fs/cgroup/synthetic","device":31,"inode":32,
                            "cpu_millis":capacity["cpu_millis"]+1000,"memory_bytes":capacity["memory_bytes"]+1024**3,"pids":2048},
                    "shared":{"path":"/sys/fs/cgroup/synthetic/shared","device":31,"inode":33,
                              "cpu_millis":1000,"memory_bytes":1024**3,"pids":512},
                    "capacity":capacity,"max_claims":2}
            return {"contract":PROVIDER,"accounting_version":ephemeral.ACCOUNTING,"enforcement_ready":True,
                    "synthetic":True,"qualified_image":context["qualified_image"],"host_budget":host}
        def check(local, request, *, context):
            self.executor.contexts.append(copy.deepcopy(context))
            state = context["binding_state"]
            if context["purpose"] == "publish" or (state and state["phase"] == "host-published"):
                return self.executor.published
            return True
        self.executor.prepare_reservation = prepare
        self.executor.verify_reservation = lambda local, row, *, context: True
        self.executor.check_execution = check
        original_clean = self.executor.verify_clean
        self.executor.verify_clean = lambda local, request, *, context: original_clean(local, request)
        descriptor = {"contract":ephemeral.CONTRACT,"spec_sha256":"d"*64,"charge":ephemeral.charge(task),
            "features":{"continuity":"ephemeral","restore_manifest":False,"checkpoint_policy":False,
                "snapshot_inputs":False,"lazy_inputs":False,"outside_outputs":False,
                "input_count":0,"input_bytes":0,"output_count":0}}
        return task, descriptor, image

    def test_qualified_creator_cas_replay_loss_and_retirement(self):
        from nodus_dc import ephemeral
        from nodus_dc.partition_binding import split_reservation
        from nodus_dc.api import Handler
        from http.client import RemoteDisconnected
        import subprocess
        import sys
        task, descriptor, image = self.enable_trusted_profile()
        server = BridgeUnixServer(str(self.root/"creator.sock"), self.service, "fixture-"+"x"*40, owner_uid=os.geteuid())
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def call(op, body):
            connection = UnixHTTPConnection(server.path)
            try:
                connection.request("POST", "/v2/bridge/partitions/"+op, json.dumps(body).encode(),
                                   {"Authorization":"Bearer "+server.bridge_token})
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally: connection.close()
        def saved(held):
            with self.service.store.connection() as db:
                row = db.execute("SELECT r.* FROM host_reservations r JOIN partition_claims c ON c.lease_id=r.lease_id WHERE c.platform_lease_id=?",(held["platform_lease_id"],)).fetchone()
                return split_reservation(row)[1], row["memory_bytes"], list(db.iterdump())
        def acquire(name, *, bind=True):
            status, report = call("offers", {"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})
            self.assertEqual(status,200,report)
            request = {"platform_lease_id":name,"platform_epoch":1,"generation":0,"offer":report["offers"][0],
                       "resources":task,"workload":{"workload_image":IMAGE,"workload_kind":"Job"},
                       "expires_at_unix_millis":1100000,"ephemeral":descriptor}
            status, response = call("claim", {**request,"qualified_image":image})
            self.assertEqual(status,200,response); held = response["lease"]
            ref = {"attempt_id":"att_"+str(self.executor.prepares).zfill(26),"epoch":1}
            if not bind: return held, {"lease":held,"ref":ref}
            status, state = call("bind", {"lease":held,"ref":ref})
            self.assertEqual(status,200,state)
            return held, {"lease":held,"ref":ref,"binding_sha256":state["binding_sha256"]}
        def begin(base, operation, **kw):
            return {**base,"operation":operation,"expected_phase_revision":{"issue":1,"consume":2,"publish":3}[operation],**kw}
        def retirement(held, ref):
            prepares, contexts = self.executor.prepares, len(self.executor.contexts)
            with patch.object(self.service,"_inventory",side_effect=AssertionError("retirement must not observe inventory")), \
                    patch.object(self.p,"_checked",side_effect=AssertionError("retirement must not admit")):
                result = call("bind",{"lease":held,"ref":ref,"purpose":"retirement"})
            self.assertEqual((self.executor.prepares,len(self.executor.contexts)),(prepares,contexts))
            return result
        def strict_retired_accounting(held, retired):
            # Exercise the production reservation routing through actual offers/SQLite.
            # Artifact/image/kernel evidence remains explicitly synthetic in this fixture.
            from nodus_dc.partition_host import LinuxPartitionProvider, refused
            reader = object.__new__(LinuxPartitionProvider); reader.sha256 = "7"*64
            roots = tuple(self.root/("held-retired-"+name) for name in ("guard","owner","host"))
            reader._paths = lambda c, ref: ("key",roots[0],roots[1],roots[1]/"epoch",roots[1]/"guardian",roots[2])
            reader._image = lambda *args: None
            observations = []
            def owner(e, c, state, *, clean=False):
                observations.append((state["binding"]["ref"],clean))
                self.assertTrue(clean)
                if not clean_ready[0]: raise refused()
            clean_ready = [False]; reader._owner = owner
            original = self.executor.verify_reservation
            def verify(local, row, *, context):
                if context["binding_state"] and context["binding_state"]["phase"]=="retired":
                    proof = json.loads(row["enforcement"])
                    proof["provider_config_sha256"] = reader.sha256
                    reader._reservation(None,{"host_budget":proof["host_budget"]},local,
                                        {**row,"enforcement":json.dumps(proof)},context)
                return original(local,row,context=context)
            def report():
                status, value = call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})
                self.assertEqual(status,200,value)
                return value
            self.executor.verify_reservation = verify
            try:
                if retired["phase_revision"]<=3:
                    for root in roots:
                        root.mkdir()
                        try: self.assertEqual(report(),{"offers":[],"host_budget":None})
                        finally: root.rmdir()
                    self.assertEqual(observations,[])
                else:
                    self.assertEqual(report(),{"offers":[],"host_budget":None})
                    self.assertEqual(observations,[(retired["binding"]["ref"],True)])
                clean_ready[0] = True
                self.assertIsNotNone(report()["host_budget"])
                self.assertTrue(call("inspect",held)[1]["held"])
                self.assertEqual(saved(held)[1],descriptor["charge"]["aggregate"]["memory_bytes"])
            finally:
                self.executor.verify_reservation = original
        def published_renewal(held, base):
            # Real HTTP/SQLite and provider routing; finite/live kernel observations are synthetic.
            from nodus_dc.partition_host import LinuxPartitionProvider, refused
            other, other_base = acquire("renewal-sibling")
            status, issued = call("begin",begin(other_base,"issue")); self.assertEqual(status,200)
            status, consumed = call("begin",begin(other_base,"consume",creation_token=issued["creation_token"])); self.assertEqual(status,200)
            def sibling_snapshot():
                # Check advances the global authority fence, but must not change this held sibling.
                with self.service.store.connection() as db:
                    claim = db.execute("SELECT * FROM partition_claims WHERE platform_lease_id=? AND platform_epoch=?",
                                       (other["platform_lease_id"],other["platform_epoch"])).fetchone()
                    lease = db.execute("SELECT * FROM leases WHERE id=?",(claim["lease_id"],)).fetchone()
                    reservation = db.execute("SELECT * FROM host_reservations WHERE lease_id=?",(claim["lease_id"],)).fetchone()
                    return dict(claim), dict(lease), dict(reservation)
            reader=object.__new__(LinuxPartitionProvider); reader.sha256="7"*64; reader._immutable_hashes={}
            kernel=self.root/"renewal-kernel"; fifo=self.root/"renewal-fifo"
            for parent in (kernel/"nodus-scoped-owners",kernel/"nodus-scoped-host",fifo/"guardians"):
                parent.mkdir(parents=True)
            def paths(c,ref):
                key=ref["attempt_id"]; owner=kernel/"nodus-scoped-owners"/key
                return key,fifo/"guardians"/key,owner,owner/"epoch",owner/"guardian",kernel/"nodus-scoped-host"/key
            reader._paths=paths;reader._image=lambda *args:None
            for ref in (base["ref"],other_base["ref"]):
                for directory in (paths(None,ref)[1],paths(None,ref)[2],paths(None,ref)[5]): directory.mkdir()
            observed=[]; live=[True]; finite=[True]; cleaned=[False]
            def owner(e,c,state,*,clean=False):
                observed.append(("strict",state["binding"]["ref"],clean))
                if state["binding"]["ref"]==other_base["ref"]:
                    if not clean or not cleaned[0]: raise refused()
                elif not live[0]: raise refused()
            def accounted(e,c,state):
                observed.append(("finite",state["binding"]["ref"],False))
                self.assertEqual(state["binding"]["ref"],other_base["ref"])
                if not finite[0]: raise refused()
            reader._owner=owner;reader._accounted_owner=accounted
            state=saved(held)[0]; budget=copy.deepcopy(state["binding"]["host_budget"])
            budget["root"]["path"]=str(kernel)
            config={"host_budget":budget,"fifo_dir":str(fifo)}
            reader._configuration=lambda e:config;reader._envelope=lambda e,c:budget
            original_verify=self.executor.verify_reservation;original_account=self.executor.verify_host_accounting
            def verify(local,row,*,context):
                proof=json.loads(row["enforcement"]);proof["provider_config_sha256"]=reader.sha256
                reader._reservation(None,{"host_budget":proof["host_budget"]},local,{**row,"enforcement":json.dumps(proof)},context)
                return True
            def account(capacity,rows,scope):
                reader.verify_host_accounting(capacity,rows,scope)
                return original_account(capacity,rows,scope)
            self.executor.verify_reservation=verify;self.executor.verify_host_accounting=account
            request={**held,"published_ref":base["ref"]}
            try:
                for bad in (None,{**base["ref"],"epoch":2},{**base["ref"],"extra":True}):
                    self.assertNotEqual(call("check",{**held,"published_ref":bad})[0],200)
                self.assertNotEqual(call("check",{**request,"creation_token":None})[0],200)
                self.assertFalse(call("check",{**held,"published_ref":other_base["ref"]})[1]["authorized"])
                self.assertFalse(call("check",{**other,"published_ref":other_base["ref"]})[1]["authorized"])
                self.assertFalse(call("check",held)[1]["authorized"])
                self.assertFalse(call("check",{**other,"creation_token":consumed["creation_token"]})[1]["authorized"])
                self.assertEqual(call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})[1],{"offers":[],"host_budget":None})
                before=sibling_snapshot(); prepares=self.executor.prepares
                self.assertTrue(call("check",request)[1]["authorized"])
                self.assertIn(("finite",other_base["ref"],False),observed)
                self.assertNotIn(("finite",base["ref"],False),observed)
                self.assertEqual(sibling_snapshot(),before);self.assertEqual(self.executor.prepares,prepares)
                target=self.executor.accounting[-1][2]["renewal_target"]
                self.assertEqual(target,{"local_lease_id":state["binding"]["local_lease_id"],"binding_sha256":state["binding_sha256"],"ref":base["ref"],"phase_revision":4})
                finite[0]=False;self.assertFalse(call("check",request)[1]["authorized"]);finite[0]=True
                live[0]=False;self.assertFalse(call("check",request)[1]["authorized"]);live[0]=True
                self.assertTrue(call("reclaim",other)[1]["retired"])
                self.assertTrue(call("check",request)[1]["authorized"])
                self.executor.clean=False
                self.assertFalse(call("complete",{"lease":other,"cleanup_verified":True})[1]["released"])
                self.assertTrue(call("inspect",other)[1]["held"])
                self.assertEqual(saved(other)[1],descriptor["charge"]["aggregate"]["memory_bytes"])
                self.executor.clean=True;cleaned[0]=True
                self.assertTrue(call("complete",{"lease":other,"cleanup_verified":True})[1]["released"])
                cleaned[0]=False
                self.assertFalse(call("check",request)[1]["authorized"])  # Released history never uses finite-only evidence.
                cleaned[0]=True;self.assertTrue(call("check",request)[1]["authorized"])
            finally:
                self.executor.verify_reservation=original_verify;self.executor.verify_host_accounting=original_account
        def original_abort(held, consumed):
            # Actual protected files/flock and HTTP/SQLite; historical kernel slots/envelope are synthetic.
            import fcntl
            import hashlib
            from nodus_dc import partition_host as host
            from nodus_dc.model import digest
            b=consumed["binding"];budget=b["host_budget"];charge=held["ephemeral"]["charge"]
            reader=object.__new__(host.LinuxPartitionProvider);reader.sha256="7"*64;reader.clock=self.clock;reader._immutable_hashes={}
            root=self.root/"original-abort";fifo=root/"fifo";owners=root/"owners";hosts=root/"hosts"
            for parent in (fifo/"guardians",owners,hosts): parent.mkdir(parents=True,mode=0o700)
            config={"host_budget":budget,"namespace":b["image"]["namespace"],"fifo_dir":str(fifo),
                    "runtime_identity":b["runtime_identity"],"creator_sha256":consumed["creator"]["executable_sha256"]}
            def paths(c,ref):
                key=host.LinuxPartitionProvider._paths(c,ref)[0];owner=owners/key
                return key,fifo/"guardians"/key,owner,owner/"nodus-epochs"/key,owner/"nodus-guardians"/key,hosts/key
            reader._paths=paths;reader._configuration=lambda e,**kw:config;reader._envelope=lambda e,c:budget;reader._image=lambda *args:None
            key,directory,owner,epoch,guardian,group=paths(config,b["ref"])
            # Deterministic verifier→census interleaving: the actual held row is still consumed.
            with self.service.store.connection() as db:
                local=Store.lease(db,b["local_lease_id"])
                row=db.execute("SELECT * FROM host_reservations WHERE lease_id=?",(local["id"],)).fetchone()
                provider,current=split_reservation(row,local)
            self.assertEqual(current,consumed)
            proof=json.loads(provider["enforcement"]);proof["provider_config_sha256"]=reader.sha256
            provider={**provider,"enforcement":json.dumps(proof)}
            reader._reservation(host.Evidence(),config,local,provider,{"lease":held,"binding_state":current})
            directory.mkdir(mode=0o700)  # A late first mkdir must not become an accepted per-root shape.
            with self.assertRaises(Error):
                reader.verify_host_accounting(budget["capacity"],
                    [{"lease":local,"provider_row":provider,"binding_state":current,"resources":charge["aggregate"]}],
                    {"accounting_version":ephemeral.ACCOUNTING,"authority_incarnation":budget["authority_incarnation"],"retired":[]})
            directory.rmdir()
            self.assertTrue(call("inspect",held)[1]["held"])
            self.assertEqual(saved(held)[1],charge["aggregate"]["memory_bytes"])
            self.assertTrue(call("reclaim",held)[1]["retired"]);retired=saved(held)[0]
            directory.mkdir(mode=0o700);lock=directory/"bootstrap.lock";lock.touch(mode=0o600)
            ident=lambda p:host.identity(p.stat())
            topology={"Owner":str(owner),"EpochParent":str(epoch.parent),"Epoch":str(epoch),"GuardianParent":str(guardian.parent),
                      "Guardian":str(guardian),"Host":str(group),"Worker":str(group/"worker"),"GuardDirectory":str(directory),"HostDirectory":str(directory/"host"),
                      **{k:str(directory/"host"/k.lower()) for k in ("Visible","Stage","Internal")}}
            plan={"Version":2,"SpecSHA256":held["ephemeral"]["spec_sha256"],"DeviceSHA256":reader._grant_digest(b),
                  "VisibleBytes":task["scratch_bytes"],"StageBytes":charge["stage_bytes"]}
            limits={"Version":1,"BindingSHA256":retired["binding_sha256"],"HostBudgetSHA256":digest(budget),
                    "Task":{"CPUMillis":task["cpu_millis"],"MemoryBytes":task["memory_bytes"],"PIDs":512},
                    "HostScratchBytes":charge["host_memory_bytes"],"OwnerOverheadBytes":charge["owner_overhead_bytes"],"OwnerOverheadCPUMillis":charge["owner_cpu_millis"]}
            intent={"Version":2,"Ref":{"AttemptID":b["ref"]["attempt_id"],"Epoch":b["ref"]["epoch"]},"Namespace":config["namespace"],"Executor":2,
                    "BindingSHA256":retired["binding_sha256"],"LocalLeaseID":b["local_lease_id"],"QualificationSHA256":b["runtime_identity"]["qualification_sha256"],
                    "RunscSHA256":b["runtime_identity"]["runsc_sha256"],"Creator":retired["creator"],"IssueSHA256":retired["issue_sha256"],
                    "StartSHA256":retired["start_sha256"],"ConsumedRevision":3,"HostBudgetSHA256":digest(budget),
                    "HostScope":{"BootID":budget["boot_id"],"CgroupNamespace":budget["cgroup_namespace"],"UserNamespace":budget["user_namespace"],
                    "PIDNamespace":budget["pid_namespace"],"AllocationRoot":budget["root"]["path"],"AllocationDevice":budget["root"]["device"],"AllocationInode":budget["root"]["inode"]},
                    "TimeNamespace":os.readlink("/proc/self/ns/time"),"Shared":{"Path":budget["shared"]["path"],"Device":budget["shared"]["device"],"Inode":budget["shared"]["inode"]},
                    "SharedBudget":budget["shared"],"Limits":limits,"Plan":plan,"DeadlineBootNS":1,"Directory":ident(directory),"BootstrapLock":ident(lock),"Topology":topology}
            proof={k:copy.deepcopy(intent[k]) for k in ("Version","Ref","BindingSHA256","LocalLeaseID","Creator","IssueSHA256","StartSHA256","QualificationSHA256")}
            proof.update(Version=3,IntentSHA256="",RetiredRevision=4,ProofContract="scoped-host-original-abort.v3",Drain=None,
                         Cgroups=dict.fromkeys(("Owner","EpochParent","Epoch","GuardianParent","Guardian","Host","Worker")),
                         Mounts=dict.fromkeys(("Visible","Stage","Internal")),OwnedDirectories=dict.fromkeys(("Host","Visible","Stage","Internal")))
            def put(name,value):
                raw=value if isinstance(value,bytes) else json.dumps(value,separators=(",",":")).encode()
                p=directory/name;p.write_bytes(raw);p.chmod(0o600);return raw
            def install(a=intent,z=proof):
                raw=put("creation-intent.json",a);value=copy.deepcopy(z);value["IntentSHA256"]=hashlib.sha256(raw).hexdigest()
                put("creation-retired.json",value)
            class Files(host.Evidence):
                def mounts(self): return []  # No kernel/mount qualification in this protocol journey.
            def worker_records():
                # Actual protected record parsing and unchanged SQL hold; cgroup files/daemon facts are synthetic.
                fixture=root/"worker-proof";record_dir=fixture/"records";parent=fixture/"H";worker=parent/"worker"
                shared=fixture/"node";leaf=shared/"agent"
                for p in (record_dir,parent,worker,shared,leaf): p.mkdir(parents=True,mode=0o700,exist_ok=True)
                def write(p,value):
                    p.write_text(value);p.chmod(0o600)
                def record(name,value):
                    raw=json.dumps(value,separators=(",",":")).encode();p=record_dir/name
                    p.write_bytes(raw);p.chmod(0o600);return hashlib.sha256(raw).hexdigest()
                controls={"cgroup.type":"domain","memory.max":str(charge["host_memory_bytes"]),"memory.swap.max":"0",
                          "memory.oom.group":"1","pids.max":"64","cpu.max.burst":"0","cpu.max":"25000 100000",
                          "memory.high":"max","cgroup.subtree_control":"cpu memory pids","memory.events.local":"oom 0\noom_kill 0\noom_group_kill 0"}
                for p,values in ((parent,controls),(worker,{**controls,"memory.max":"max","memory.oom.group":"0","cgroup.subtree_control":""})):
                    for name,value in {**values,"cgroup.freeze":"0","cgroup.kill":"","cgroup.procs":"","memory.current":"0","cgroup.events":"populated 0\nfrozen 0"}.items(): write(p/name,value)
                scope={"CreationIntentSHA256":"a"*64,"Group":ident(parent),"WorkerPath":str(worker),"Worker":ident(worker),
                       "Freeze":ident(parent/"cgroup.freeze"),"Kill":ident(parent/"cgroup.kill"),"CreatorLock":ident(lock),
                       "Controls":{k:ident(parent/k) for k in controls},"WorkerControls":{k:ident(worker/k) for k in (*controls,"cgroup.freeze")}}
                for index,title in enumerate(("Visible","Stage","Internal")):
                    scope[title]={"Path":str(fixture/title.lower()),"MountID":9000+index,"Device":"0:"+str(9100+index)}
                guard={"Version":5,"Ref":intent["Ref"],"HostSHA256":"b"*64};owner_limits={"Plan":limits,"Guardian":{"Device":1,"Inode":91}}
                records=(record_dir,owner,epoch,guardian,parent,guard,owner_limits,scope,"b"*64)
                config2={**config,"host_budget":copy.deepcopy(budget)}
                config2["host_budget"]["root"].update(path=str(fixture),device=ident(fixture)["Device"],inode=ident(fixture)["Inode"])
                allocation=config2["host_budget"]["root"]
                for k,v in {"cgroup.type":"domain","memory.max":str(allocation["memory_bytes"]),"memory.swap.max":"0",
                            "cpu.max":f'{allocation["cpu_millis"]*100} 100000',"cpu.max.burst":"0","pids.max":str(allocation["pids"]),"memory.oom.group":"1"}.items(): write(fixture/k,v)
                sb=config2["host_budget"]["shared"];sb.update(path=str(shared),device=ident(shared)["Device"],inode=ident(shared)["Inode"])
                parser=copy.copy(reader);parser._metadata=lambda *args:None
                check=lambda mode:parser._host_progress(Files(),config2,retired,records,mode=mode)
                parser._host_identities(scope,ident(parent)["Device"])
                self.assertEqual(check("active"),(None,None,None))
                write(worker/"memory.max",controls["memory.max"])
                with self.assertRaises(Error): check("active")  # A narrower child OOM domain is forbidden.
                write(worker/"memory.max","max");write(parent/"memory.events.local","oom 1\noom_kill 1\noom_group_kill 1")
                with self.assertRaises(Error): check("active")
                self.assertEqual(check("held"),(None,None,None))  # Historical OOM cannot veto finite retirement.
                write(parent/"cgroup.freeze","1");write(parent/"cgroup.events","populated 0\nfrozen 1")
                offline={"Version":1,"Guard":guard,"ScopeSHA256":"b"*64,"CreationIntentSHA256":"a"*64,
                         "ParentPath":str(parent),"Parent":ident(parent),"WorkerPath":str(worker),"Worker":ident(worker),
                         "CreatorLock":ident(lock),"WorkerPopulated":0,"WorkerMemoryCurrent":4096}
                ohash=record("host-worker-offline.json",offline)
                with self.assertRaises((Error,OSError)): check("held")  # Missing predecessor joins.
                for name,value in (("revoked.json",guard),("intent.json",guard),
                                   ("retired.json",{"Guard":guard,"Group":owner_limits["Guardian"]}),
                                   ("guardian.json",{"Guard":guard,"Group":owner_limits["Guardian"]})):
                    record(name,value)
                for title in ("Visible","Stage","Internal"): record("host-unmount-"+title.lower()+".json",scope[title])
                self.assertEqual(check("held")[0],offline)
                with self.assertRaises(Error): check("clean")  # Original worker still exists.
                worker.rename(parent/"replacement")
                with self.assertRaises(Error): check("held")
                (parent/"replacement").rename(worker)
                for p in worker.iterdir(): p.unlink()
                worker.rmdir()
                (record_dir/"host-worker-offline.json").unlink()
                with self.assertRaises(Error): check("held")  # Missing worker is not evidence of offlining.
                record("host-worker-offline.json",offline);write(parent/"memory.current","4096")
                self.assertEqual(check("held")[0],offline)
                with self.assertRaises(Error): check("clean")
                shared_values={"cgroup.type":"domain","memory.max":str(sb["memory_bytes"]),"memory.swap.max":"0",
                               "cpu.max":f'{sb["cpu_millis"]*100} 100000',"cpu.max.burst":"0","pids.max":str(sb["pids"]),
                               "cgroup.freeze":"0","memory.high":"max","memory.oom.group":"0","cgroup.subtree_control":"cpu memory pids"}
                vector=[]
                for p,values in ((shared,shared_values),(leaf,{**shared_values,"memory.max":"max","pids.max":"max","cgroup.subtree_control":""})):
                    for k,v in {**values,"cgroup.events":"populated 0\nfrozen 0","cgroup.procs":""}.items(): write(p/k,v)
                    vector.append({"Path":str(p),"Identity":ident(p),"Controls":{k:{"Identity":ident(p/k),"Value":values[k]} for k in sorted(values)}})
                high={"Version":1,"Guard":guard,"ScopeSHA256":"b"*64,"CreationIntentSHA256":"a"*64,"WorkerOfflineSHA256":ohash,
                      "DeadlineBootNS":1,"ParentPath":str(parent),"Parent":ident(parent),"High":scope["Controls"]["memory.high"],
                      "CreatorLock":ident(lock),"SharedBudget":sb,"SharedControls":{k:ident(shared/k) for k in ("cgroup.type","memory.max","memory.swap.max","cpu.max","cpu.max.burst","pids.max","cgroup.freeze")},
                      "SharedLeafPath":str(leaf),"SharedLeaf":ident(leaf),"SharedAncestryCount":2,
                      "SharedAncestrySHA256":hashlib.sha256(json.dumps(vector,separators=(",",":"),ensure_ascii=False).encode()).hexdigest(),"Value":0}
                hhash=record("host-high-intent.json",high);write(parent/"memory.high","0")
                self.assertEqual(check("held")[1],high)
                for key,value in (("DeadlineBootNS",None),("DeadlineBootNS",2**63),("SharedAncestryCount",None),
                                  ("SharedBudget",{**sb,"memory_bytes":sb["memory_bytes"]+4096}),("Value",1)):
                    record("host-high-intent.json",{**high,key:value})
                    with self.assertRaises(Error): check("held")
                record("host-high-intent.json",high)
                with self.assertRaises(Error): check("clean")  # No joined outcome, even if parent reaches zero.
                write(parent/"memory.current","0")
                with self.assertRaises(Error): check("clean")
                for wrong in ({"Version":1,"IntentSHA256":hhash,"WaitStatus":9},
                              {"Version":1,"IntentSHA256":"f"*64,"WaitStatus":0}):
                    record("host-high-outcome.json",wrong)
                    with self.assertRaises(Error): check("clean")
                outcome={"Version":1,"IntentSHA256":hhash,"WaitStatus":0};record("host-high-outcome.json",outcome)
                self.assertEqual(check("clean"),(offline,high,outcome))
                write(leaf/"pids.max","1")
                with self.assertRaises(Error): check("clean")  # Even tighter changed ancestry cannot replay.
                write(leaf/"pids.max","max");write(parent/"memory.current","4096")
                with self.assertRaises(Error): check("clean")
                self.assertTrue(call("inspect",held)[1]["held"])
                self.assertEqual(saved(held)[1],charge["aggregate"]["memory_bytes"])
                return config2,high
            def consumed_clean_guards():
                # Actual Complete/verify_clean/record-pair path; current envelope and later kernel facts are synthetic.
                (directory/"creation-retired.json").unlink()  # Exercise normal consumed cleanup, with no high intent.
                owner_calls=[]
                def otherwise_clean(e,c,state,*,clean=False):
                    owner_calls.append(clean);self.assertTrue(clean)
                class EnvelopeFiles(Files):
                    drift=""
                    def mounts(self): return [{"path":"/sys/fs/cgroup","type":"cgroup2"}]
                    def controls(self,p,expected,identities=None):
                        role="root" if str(p)==budget["root"]["path"] else "shared"
                        item=budget[role]
                        self_value={"Device":item["device"],"Inode":item["inode"]}
                        if role==self.drift: self_value["Inode"]+=1
                        return self_value
                try:
                    with patch.object(reader,"_envelope",host.LinuxPartitionProvider._envelope.__get__(reader)), \
                            patch.object(reader,"_owner",otherwise_clean),patch.object(host,"Evidence",EnvelopeFiles):
                        for role in ("root","shared"):
                            EnvelopeFiles.drift=role
                            self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                            self.assertTrue(call("inspect",held)[1]["held"])
                            self.assertEqual(saved(held)[1],charge["aggregate"]["memory_bytes"])
                        self.assertEqual(owner_calls,[])  # Missing envelope check would release through this positive owner.
                    limit_record={"Version":1,"Root":str(owner.parent.parent),"Plan":limits,
                                  "Owner":{"Device":31,"Inode":101},"Epoch":{"Device":31,"Inode":102},
                                  "Guardian":{"Device":31,"Inode":103},"Controls":{}}
                    lhash=hashlib.sha256(put("scoped-limits.json",limit_record)).hexdigest()
                    guard={"Version":4,"Executor":2,"Ref":intent["Ref"],"Namespace":config["namespace"],
                           "BootID":budget["boot_id"],"TimeNamespace":intent["TimeNamespace"],"HostScope":intent["HostScope"],
                           "CgroupPath":str(epoch),"Freeze":{"Device":31,"Inode":104},"Kill":{"Device":31,"Inode":105},"ScopeSHA256":lhash}
                    scope={"Version":3,"Guard":guard,"Plan":plan,"Root":limit_record["Root"],"GroupPath":str(group),
                           "GuardianPath":str(guardian),"Group":{"Device":31,"Inode":106},"Freeze":{"Device":31,"Inode":107},
                           "Kill":{"Device":31,"Inode":108},"CreatorLock":ident(lock),"Controls":{},
                           "CreationIntentSHA256":hashlib.sha256((directory/"creation-intent.json").read_bytes()).hexdigest(),
                           "WorkerPath":str(group/"worker"),"Worker":{"Device":31,"Inode":109},"WorkerControls":{}}
                    for index,role in enumerate(("Visible","Stage","Internal")):
                        scope[role]={"Path":topology[role],"Bytes":{"Visible":plan["VisibleBytes"],"Stage":plan["StageBytes"],"Internal":8192}[role],
                                     "Inodes":8 if role=="Internal" else 256,"MountID":3000+index,"Device":"0:"+str(4000+index),
                                     "Identity":{"Device":os.makedev(0,4000+index),"Inode":1}}
                    boundary=[]
                    class MountFiles(Files):
                        def protected(self,p,*,directory=False):
                            if str(p)==str(owner):
                                boundary.append("after-all-mounts")
                                raise OSError("synthetic kernel boundary after complete historical mount validation")
                            return super().protected(p,directory=directory)
                    with patch.object(host,"Evidence",MountFiles):
                        put("host-scope.json",scope)
                        self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                        self.assertEqual(boundary,["after-all-mounts"]);boundary.clear()
                        for name in host.ORIGINAL_HIGH_FILES:
                            put(name,{})
                            self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                            self.assertEqual(boundary,[])  # Original-only progress cannot mix with a v5 scope.
                            self.assertTrue(call("inspect",held)[1]["held"])
                            (directory/name).unlink()
                        bad=[("MountID",0),("MountID",2**31),("Device","00:4000"),("Device","0:4294967296"),
                             ("Device","0:4001"),("Identity",None),("Identity",{"Device":0,"Inode":1}),
                             ("Identity",{"Device":os.makedev(0,4000),"Inode":2**64})]
                        for key,value in bad:
                            altered=copy.deepcopy(scope);altered["Visible"][key]=value;put("host-scope.json",altered)
                            self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                            self.assertEqual(boundary,[])  # Rejection must precede the synthetic later kernel boundary.
                            self.assertTrue(call("inspect",held)[1]["held"])
                            self.assertEqual(saved(held)[1],charge["aggregate"]["memory_bytes"])
                        for keys in (("MountID",),("Device","Identity")):
                            altered=copy.deepcopy(scope)
                            for key in keys: altered["Stage"][key]=copy.deepcopy(scope["Visible"][key])
                            put("host-scope.json",altered)
                            self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                            self.assertEqual(boundary,[])
                            self.assertTrue(call("inspect",held)[1]["held"])
                            self.assertEqual(saved(held)[1],charge["aggregate"]["memory_bytes"])
                finally:
                    for name in ("host-scope.json","scoped-limits.json"):
                        (directory/name).unlink(missing_ok=True)
                    install()
            def drain_records(present,partial,shared_config,shared_high):
                # Real protected pair/Complete/census; the existing file-backed Shared fixture maps synthetic host paths.
                high={"Version":1,"CreationIntentSHA256":hashlib.sha256((directory/"creation-intent.json").read_bytes()).hexdigest(),
                      "RetiredRevision":4,"RetirementStartedBootNS":1,"DeadlineBootNS":10_000_000_001,
                      "CreatorLock":ident(lock),"Targets":{},"SharedBudget":budget["shared"],"Value":0,
                      **{k:copy.deepcopy(shared_high[k]) for k in ("SharedControls","SharedLeafPath","SharedLeaf","SharedAncestryCount","SharedAncestrySHA256")}}
                for i,role in enumerate(("Host","Owner")):
                    memory=limits["HostScratchBytes"] if role=="Host" else task["memory_bytes"]+limits["OwnerOverheadBytes"]
                    cpu=25000 if role=="Host" else (task["cpu_millis"]+limits["OwnerOverheadCPUMillis"])*100
                    values={"cgroup.type":"domain","cgroup.freeze":"0","cgroup.subtree_control":"cpu memory pids",
                            "memory.max":str(memory),"memory.swap.max":"0","memory.oom.group":"1","memory.high":"max",
                            "pids.max":"64" if role=="Host" else "512","cpu.max":f"{cpu} 100000","cpu.max.burst":"0"}
                    high["Targets"][role]={"Path":topology[role],"Identity":present["Cgroups"][role]["Identity"],
                        "Controls":{k:{"Identity":{"Device":budget["root"]["device"],"Inode":6000+i*10+j},"Value":v} for j,(k,v) in enumerate(values.items())}}
                for name,control in high["Targets"]["Owner"]["Controls"].items():
                    if name in partial["Controls"]: control["Identity"]=copy.deepcopy(partial["Controls"][name])
                outcome={"Version":1,"IntentSHA256":"","WaitStatus":0}
                def install_drain(h=high,o=outcome,z=present):
                    a=hashlib.sha256(put(host.ORIGINAL_HIGH_FILES[0],h)).hexdigest()
                    result=copy.deepcopy(o);result["IntentSHA256"]=a
                    b=hashlib.sha256(put(host.ORIGINAL_HIGH_FILES[1],result)).hexdigest()
                    value=copy.deepcopy(z);value["Drain"]={"IntentSHA256":a,"OutcomeSHA256":b};install(z=value)
                def ancestry(e,c,value):
                    self.assertEqual(c,config);self.assertEqual(value["SharedBudget"],budget["shared"])
                    return host.LinuxPartitionProvider._shared_ancestry(reader,e,shared_config,
                        {**value,"SharedBudget":shared_config["host_budget"]["shared"]})
                def refused_held():
                    self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                    self.assertTrue(call("inspect",held)[1]["held"])
                    self.assertEqual(saved(held)[1],charge["aggregate"]["memory_bytes"])
                    self.assertIsNone(call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})[1]["host_budget"])
                with patch.object(reader,"_shared_ancestry",ancestry):
                    install_drain()
                    self.assertEqual(reader._creation_retired(Files(),config,retired),high["CreationIntentSHA256"])
                    self.assertEqual(reader._creation_retired(Files(),config,retired),high["CreationIntentSHA256"])
                    self.assertTrue(call("inspect",held)[1]["held"])
                    for role in ("Host","Owner"):
                        only=copy.deepcopy(high);only["Targets"][role]=None;install_drain(only)
                        self.assertEqual(reader._creation_retired(Files(),config,retired),high["CreationIntentSHA256"])
                    for key,value in (("Version",2),("RetiredRevision",5),("CreationIntentSHA256","f"*64),
                                      ("RetirementStartedBootNS",0),("DeadlineBootNS",1),("DeadlineBootNS",10_000_000_002),
                                      ("DeadlineBootNS",2**63),("Value",1),("SharedAncestryCount",1),
                                      ("SharedAncestrySHA256","f"*64),("Targets",{"Host":None,"Owner":None})):
                        install_drain({**high,key:value});refused_held()
                    for key,value in (("Path",topology["Owner"]),("Identity",present["Cgroups"]["Worker"]["Identity"]),
                                      ("Controls",{})):
                        bad=copy.deepcopy(high);bad["Targets"]["Host"][key]=value;install_drain(bad);refused_held()
                    for key,value in (("Value","0"),("Identity",{"Device":0,"Inode":6000}),
                                      ("Identity",present["Cgroups"]["Host"]["Identity"]),
                                      ("Identity",high["Targets"]["Owner"]["Controls"]["memory.high"]["Identity"])):
                        bad=copy.deepcopy(high);bad["Targets"]["Host"]["Controls"]["memory.high"][key]=value
                        install_drain(bad);refused_held()
                    for status in (9,2**32): install_drain(o={**outcome,"WaitStatus":status});refused_held()
                    bad=copy.deepcopy(high);bad["Targets"]["Owner"]["Controls"]["memory.max"]["Identity"]["Inode"]=7000
                    install_drain(bad);refused_held()  # The same captured Owner file cannot change identity across records.
                    for role,name,null_owner in (("Host","memory.events.local",False),
                                                 ("Host","memory.max",True),("Owner","memory.events.local",False)):
                        bad=copy.deepcopy(high)
                        if null_owner: bad["Targets"]["Owner"]=None
                        bad["Targets"][role]["Controls"]["memory.high"]["Identity"]=copy.deepcopy(partial["Controls"][name])
                        install_drain(bad);refused_held()  # Distinct objects cannot alias even when Owner was not selected.
                    for role in ("Host","Owner"):
                        bad=copy.deepcopy(present);bad["Cgroups"][role]["MemoryCurrent"]=4096
                        install_drain(z=bad);refused_held()
                    for names in (host.ORIGINAL_HIGH_FILES[:1],host.ORIGINAL_HIGH_FILES[1:2],host.ORIGINAL_HIGH_FILES[:2]):
                        install_drain()
                        for name in names: (directory/name).unlink()
                        refused_held()  # Losing both sidecars cannot become the no-drain path.
                    for name in host.ORIGINAL_HIGH_FILES[2:]:
                        install_drain();put(name,{});refused_held();(directory/name).unlink()
                    install_drain();install(z=present);refused_held()  # Null Drain with sidecars refuses.
                    install_drain();bad=json.loads((directory/"creation-retired.json").read_text());bad["Drain"]["OutcomeSHA256"]="f"*64
                    put("creation-retired.json",bad);refused_held()
                    leaf=Path(high["SharedLeafPath"])
                    install_drain();leaf.rename(leaf.with_name("replacement"));refused_held();leaf.with_name("replacement").rename(leaf)
                    # Even tighter changed ancestry is not an interchangeable replay context.
                    (leaf/"pids.max").write_text("1");refused_held();(leaf/"pids.max").write_text("max")
                    install_drain()
                    self.assertIsNotNone(call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})[1]["host_budget"])
                    self.assertEqual(saved(held)[1],charge["aggregate"]["memory_bytes"])
                    self.assertTrue(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
                    self.assertFalse(call("inspect",held)[1]["held"])
                    self.assertTrue(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
                    self.assertFalse(call("check",held)[1]["authorized"])
                    self.assertIsNotNone(call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})[1]["host_budget"])
                    (directory/host.ORIGINAL_HIGH_FILES[1]).unlink()
                    self.assertIsNone(call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})[1]["host_budget"])
                    install_drain()
            old_clean=self.executor.verify_clean;old_account=self.executor.verify_host_accounting;old_verify=self.executor.verify_reservation
            def clean(local,request,*,context):
                p=json.loads(context["provider_row"]["enforcement"]);p["provider_config_sha256"]=reader.sha256
                return reader.verify_clean(local,request,context={**context,"provider_row":{**context["provider_row"],"enforcement":json.dumps(p)}})
            def verify(local,row,*,context):
                p=json.loads(row["enforcement"]);p["provider_config_sha256"]=reader.sha256
                reader._reservation(Files(),config,local,{**row,"enforcement":json.dumps(p)},context)
                return True
            def account(capacity,rows,scope):
                reader.verify_host_accounting(capacity,rows,scope)
                return old_account(capacity,rows,scope)
            self.executor.verify_clean=clean;self.executor.verify_host_accounting=account;self.executor.verify_reservation=verify
            try:
                with patch.object(host,"Evidence",Files):
                    self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                    self.assertTrue(call("inspect",held)[1]["held"])
                    install()
                    shared_config,shared_high=worker_records()
                    consumed_clean_guards()
                    for which,key,value in (("intent","DeadlineBootNS",0),("intent","DeadlineBootNS",2**63),
                            ("intent","Version",True),("intent","Version",1),
                            ("intent","SharedBudget",{**budget["shared"],"memory_bytes":budget["shared"]["memory_bytes"]+4096}),("intent","Creator",{**retired["creator"],"pid":retired["creator"]["pid"]+1}),
                            ("intent","Topology",{**topology,"Host":str(root/"foreign")}),
                            ("proof","StartSHA256","8"*64),("proof","RetiredRevision",5),("proof","Version",2),("proof","Creators",[]),
                            ("proof","Cgroups",{"Owner":None}),
                            ("proof","Cgroups",{k:v for k,v in proof["Cgroups"].items() if k!="Worker"})):
                        a=copy.deepcopy(intent);z=copy.deepcopy(proof);(a if which=="intent" else z)[key]=value;install(a,z)
                        self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                        self.assertTrue(call("inspect",held)[1]["held"])
                        self.assertEqual(saved(held)[1],descriptor["charge"]["aggregate"]["memory_bytes"])
                    for raw in (b'{"Version":1,"Version":1}',json.dumps(intent).replace('"DeadlineBootNS": 1','"DeadlineBootNS": 1e0').encode()):
                        install();put("creation-intent.json",raw)
                        with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                    install()
                    missing=copy.deepcopy(proof);del missing["Drain"];install(z=missing)
                    self.assertNotEqual(call("complete",{"lease":held,"cleanup_verified":True})[0],200)
                    install()
                    for filename in ("host-scope.json","metadata-intent.json","guardian.json","removed.json","creation-intent.json.tmp"):
                        put(filename,{})
                        with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                        (directory/filename).unlink()
                    for p in (owner,group,directory/"host"):
                        p.mkdir(mode=0o700)
                        with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                        p.rmdir()
                    with lock.open('rb') as owned:
                        fcntl.flock(owned,fcntl.LOCK_SH|fcntl.LOCK_NB)
                        with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                    # A source-qualified all-null proof is never inferred from absent files.
                    self.assertEqual(reader._creation_retired(Files(),config,retired),hashlib.sha256((directory/"creation-intent.json").read_bytes()).hexdigest())
                    # Successful v5 publication retains and strictly joins this same predecessor.
                    self.assertEqual(reader._creation_intent(Files(),config,{**retired,"phase":"host-published","phase_revision":4})[0],intent)
                    self.assertNotEqual(call("begin",begin({"lease":held,"ref":b["ref"],"binding_sha256":retired["binding_sha256"]},"issue"))[0],200)
                    self.assertFalse(call("check",held)[1]["authorized"])
                    status,report=call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})
                    self.assertEqual(status,200,report);self.assertIsNotNone(report["host_budget"])
                    self.assertTrue(call("inspect",held)[1]["held"])
                    self.assertEqual(saved(held)[1],descriptor["charge"]["aggregate"]["memory_bytes"])
                    target=[r for r in self.executor.accounting[-1][1] if r["lease"]["id"]==b["local_lease_id"]]
                    self.assertEqual([r["resources"] for r in target],[descriptor["charge"]["aggregate"]])
                    unknown=fifo/"guardians"/"unaccounted";unknown.mkdir(mode=0o700)
                    self.assertIsNone(call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING})[1]["host_budget"])
                    unknown.rmdir()
                    # Present original slots prove prior empty teardown, not current live permission.
                    present=copy.deepcopy(proof)
                    for index,role in enumerate(present["Cgroups"]):
                        present["Cgroups"][role]={"Identity":{"Device":budget["root"]["device"],"Inode":1000+index},"Populated":0,"MemoryCurrent":0}
                    for index,role in enumerate(present["OwnedDirectories"]): present["OwnedDirectories"][role]={"Device":ident(directory)["Device"],"Inode":2000+index}
                    for index,role in enumerate(present["Mounts"]):
                        size={"Visible":task["scratch_bytes"],"Stage":charge["stage_bytes"],"Internal":8192}[role]
                        present["Mounts"][role]={"Path":topology[role],"Bytes":size,"Inodes":8 if role=="Internal" else 256,
                                                "MountID":3000+index,"Device":"0:"+str(4000+index),"Identity":{"Device":os.makedev(0,4000+index),"Inode":1}}
                    install(z=present)
                    partial={"Version":1,"Root":budget["root"]["path"],"Plan":limits,
                             **{k:present["Cgroups"][k]["Identity"] for k in ("Owner","Epoch","Guardian")},
                             "Controls":{k:{"Device":budget["root"]["device"],"Inode":5000+i} for i,k in enumerate(("cgroup.type","cpu.max","cpu.max.burst","memory.max","memory.swap.max","memory.oom.group","pids.max","memory.events.local"))}}
                    put("scoped-limits.json",partial)
                    with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,{**retired,"phase_revision":5})
                    wrong=copy.deepcopy(present);wrong["Cgroups"]["Host"]["MemoryCurrent"]=4096;install(z=wrong)
                    with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                    wrong=copy.deepcopy(present);wrong["Cgroups"]["Worker"]["MemoryCurrent"]=4096;install(z=wrong)
                    with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                    wrong=copy.deepcopy(present);wrong["Cgroups"]["Host"]=None;install(z=wrong)
                    with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                    install(z=present)
                    wrong=copy.deepcopy(partial);wrong["Plan"]["HostScratchBytes"]+=4096;put("scoped-limits.json",wrong)
                    with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Files(),config,retired)
                    put("scoped-limits.json",partial)
                    class Mounted(Files):
                        def mounts(self):
                            m=present["Mounts"]["Visible"]
                            return [{"id":m["MountID"],"device":m["Device"],"path":str(root/"moved")}]
                    with self.assertRaises((Error,OSError,ValueError)): reader._creation_retired(Mounted(),config,retired)
                    self.assertEqual(reader._creation_retired(Files(),config,retired),hashlib.sha256((directory/"creation-intent.json").read_bytes()).hexdigest())
                    drain_records(present,partial,shared_config,shared_high)
            finally:
                self.executor.verify_clean=old_clean;self.executor.verify_host_accounting=old_account;self.executor.verify_reservation=old_verify
        def finish(held):
            prior = saved(held)[0]
            self.assertTrue(call("reclaim",held)[1]["retired"])
            status, retired = call("bind",{"lease":held,"ref":prior["binding"]["ref"]})
            self.assertEqual(status,200,retired)
            self.assertEqual(retired,{**prior,"phase":"retired","phase_revision":prior["phase_revision"]+1})
            self.assertEqual(call("bind",{"lease":held,"ref":prior["binding"]["ref"]}),(200,retired))
            expected = {"contract":"partition-retirement.v1","lease":held,"state":retired,
                        "disposition":"never-consumed" if retired["phase_revision"]<=3 else "scope-required"}
            self.assertEqual(retirement(held,prior["binding"]["ref"]),(200,expected))
            self.assertEqual(retirement(held,prior["binding"]["ref"]),(200,expected))
            wrong={**prior["binding"]["ref"],"attempt_id":"att_00000000000000000000000099"}
            self.assertNotEqual(call("bind",{"lease":held,"ref":wrong})[0],200)
            self.assertNotEqual(retirement(held,wrong)[0],200)
            self.assertNotEqual(retirement({**held,"generation":held["generation"]+1},prior["binding"]["ref"])[0],200)
            self.assertNotEqual(call("begin",begin({"lease":held,"ref":prior["binding"]["ref"],
                "binding_sha256":prior["binding_sha256"]},"issue"))[0],200)
            self.assertFalse(call("check",held)[1]["authorized"])
            self.assertFalse(call("check",{**held,"published_ref":prior["binding"]["ref"]})[1]["authorized"])
            strict_retired_accounting(held,retired)
            self.executor.clean = False
            self.assertFalse(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
            self.assertTrue(call("inspect",held)[1]["held"])
            self.assertEqual(saved(held)[1],descriptor["charge"]["aggregate"]["memory_bytes"])
            self.executor.clean = True
            self.assertTrue(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
            prepares = self.executor.prepares
            self.assertEqual(call("claim",{**held,"qualified_image":image})[1]["lease"],held)
            self.assertEqual(self.executor.prepares,prepares)
            self.assertFalse(call("inspect",held)[1]["held"])
            self.assertEqual(retirement(held,prior["binding"]["ref"]),(200,expected))
        try:
            held, base = acquire("never-bound",bind=False)
            self.assertIsNone(saved(held)[0])
            self.assertNotEqual(retirement(held,base["ref"])[0],200)
            for purpose in (None,"create"):
                self.assertNotEqual(call("bind",{**base,"purpose":purpose})[0],200)
            self.assertTrue(call("reclaim",held)[1]["retired"])
            unbound = {"contract":"partition-retirement.v1","lease":held,"disposition":"never-bound","state":None}
            self.assertEqual(retirement(held,base["ref"]),(200,unbound))
            # An unbound row asserts no Ref at all, rather than adopting the caller's Ref.
            another = {**base["ref"],"attempt_id":"att_00000000000000000000000099"}
            self.assertEqual(retirement(held,another),(200,unbound))
            self.assertNotEqual(call("bind",base)[0],200)
            self.assertFalse(call("check",held)[1]["authorized"])
            self.executor.clean = False
            self.assertFalse(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
            self.assertTrue(call("inspect",held)[1]["held"])
            self.assertEqual(saved(held)[1],descriptor["charge"]["aggregate"]["memory_bytes"])
            self.executor.clean = True
            self.assertTrue(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
            prepares = self.executor.prepares
            self.assertEqual(call("claim",{**held,"qualified_image":image})[1]["lease"],held)
            self.assertEqual(self.executor.prepares,prepares)
            self.assertFalse(call("inspect",held)[1]["held"])
            self.assertEqual(retirement(held,base["ref"]),(200,unbound))
            held,base=acquire("original-abort")
            status,issued=call("begin",begin(base,"issue"));self.assertEqual(status,200)
            status,consumed=call("begin",begin(base,"consume",creation_token=issued["creation_token"]));self.assertEqual(status,200)
            original_abort(held,consumed["state"])
            held, base = acquire("creator-full")
            self.assertNotEqual(retirement(held,base["ref"])[0],200)
            self.assertEqual(self.service.store.fence.read()["reader_schema"],8)
            self.assertTrue(call("check",held)[1]["authorized"])  # reservation, never creation
            status, issued = call("begin",begin(base,"issue")); self.assertEqual(status,200,"creator transition failed")
            a = issued["creation_token"]
            self.assertEqual(issued["state"]["creator"]["pid"],os.getpid())
            self.assertNotEqual(call("begin",begin(base,"issue"))[0],200)
            self.assertFalse(call("check",held)[1]["authorized"])
            # A distinct real process cannot use the original process's capability.
            probe = """import json,sys
from tests.test_api import UnixHTTPConnection
v=json.load(sys.stdin);c=UnixHTTPConnection(v['socket'])
c.request('POST','/v2/bridge/partitions/begin',json.dumps(v['body']).encode(),{'Authorization':'Bearer '+v['token']})
r=c.getresponse();r.read();print(r.status);c.close()
"""
            child = subprocess.run([sys.executable,"-c",probe],input=json.dumps({"socket":str(server.path),"token":server.bridge_token,
                "body":begin(base,"consume",creation_token=a)}),text=True,capture_output=True,timeout=15)
            self.assertEqual(child.returncode,0,child.stderr); self.assertNotEqual(child.stdout.strip(),"200")
            status, consumed = call("begin",begin(base,"consume",creation_token=a)); self.assertEqual(status,200,"creator transition failed")
            b = consumed["creation_token"]; self.assertTrue(a != b,"creation capability did not rotate")
            self.assertNotEqual(call("begin",begin(base,"consume",creation_token=a))[0],200)
            self.assertFalse(call("check",held)[1]["authorized"])
            self.assertFalse(call("check",{**held,"creation_token":a})[1]["authorized"])
            self.assertTrue(call("check",{**held,"creation_token":b})[1]["authorized"])
            state, _, dump = saved(held)
            self.assertEqual(state["phase"],"creation-consumed")
            self.assertTrue(a not in "\n".join(dump) and b not in "\n".join(dump),"plaintext capability persisted")
            publish = begin(base,"publish",creation_token=b,host_scope_sha256="9"*64)
            self.assertNotEqual(call("begin",publish)[0],200)  # positive owner evidence required
            self.executor.published = True
            status, published = call("begin",publish); self.assertEqual(status,200,"creator transition failed")
            self.assertTrue(published["creation_token"] == "","publish returned a creation capability")
            self.assertTrue(call("check",held)[1]["authorized"])
            self.assertFalse(call("check",{**held,"creation_token":b})[1]["authorized"])
            self.assertNotEqual(call("begin",publish)[0],200)
            published_renewal(held,base)
            self.executor.published = False
            self.assertFalse(call("check",held)[1]["authorized"])
            finish(held)
            # A committed transition followed by transport loss must not return its token on replay.
            for phase in ("committed","creation-issued","creation-consumed","host-published"):
                held, base = acquire("lost-"+phase)
                if phase == "committed": finish(held); continue
                body = begin(base,"issue")
                if phase in {"creation-consumed","host-published"}:
                    status, issued = call("begin",body); self.assertEqual(status,200,"creator transition failed")
                    body = begin(base,"consume",creation_token=issued["creation_token"])
                if phase == "host-published":
                    status, consumed = call("begin",body); self.assertEqual(status,200,"creator transition failed")
                    self.executor.published = True
                    body = begin(base,"publish",creation_token=consumed["creation_token"],host_scope_sha256="9"*64)
                original = Handler.send_json
                def lost(handler, status, value):
                    if status == 200 and isinstance(value,dict) and "creation_token" in value:
                        handler.close_connection = True
                        handler.connection.shutdown(2)
                        return
                    return original(handler,status,value)
                with patch.object(Handler,"send_json",lost):
                    with self.assertRaises(RemoteDisconnected): call("begin",body)
                self.assertEqual(saved(held)[0]["phase"],phase)
                self.assertNotEqual(call("begin",body)[0],200)
                self.assertEqual(call("check",held)[1]["authorized"],phase == "host-published")
                if phase == "host-published":
                    self.assertFalse(call("check",{**held,"creation_token":consumed["creation_token"]})[1]["authorized"])
                    self.clock.now += 101
                    self.assertFalse(call("check",held)[1]["authorized"])
                finish(held)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

    def test_qualified_floor8_write_ahead_loss_cannot_reopen_admission(self):
        from nodus_dc import ephemeral
        task, descriptor, image = self.enable_trusted_profile()
        offer = self.p.offers(include_host_budget=True,accounting_version=ephemeral.ACCOUNTING)["offers"][0]
        request = {"platform_lease_id":"floor8-loss","platform_epoch":1,"generation":0,"offer":offer,
                   "resources":task,"workload":{"workload_image":IMAGE,"workload_kind":"Job"},
                   "expires_at_unix_millis":1100000,"ephemeral":descriptor,"qualified_image":image}
        with self.service.store.connection() as db:
            generation = db.execute("SELECT value FROM meta WHERE key='next_generation'").fetchone()[0]
            schema = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        advance = self.service.store.fence.advance
        def interrupted(db):
            advance(db)
            if db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "8":
                raise RuntimeError("synthetic loss after durable reader floor")
        self.service.store.fence.advance = interrupted
        try:
            with self.assertRaises(RuntimeError): self.p.claim(**request)
        finally: self.service.store.fence.advance = advance
        self.assertEqual(self.service.store.fence.read()["reader_schema"],8)
        with self.service.store.connection() as db:
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],schema)
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key='next_generation'").fetchone()[0],generation)
            self.assertEqual(db.execute("SELECT count(*) FROM partition_claims").fetchone()[0],0)
            self.assertEqual(db.execute("SELECT count(*) FROM host_reservations").fetchone()[0],0)
        self.assert_error("authority_continuity_lost",lambda:self.p.claim(**request))

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
            prepare = self.executor.prepare_reservation
            for reserved in ("nodus.execution_binding", "nodus.future_authority"):
                self.executor.prepare_reservation = lambda lease, resources: {"enforcement_ready":True,reserved:None}
                self.assert_error("invalid_execution_binding",lambda:self.p.claim(**frozen))
                self.assertFalse(self.p.inspect(**frozen)["held"])
            self.executor.prepare_reservation = prepare
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

    def test_ephemeral_aggregate_claim_is_atomic_and_cannot_authorize_execution(self):
        from nodus_dc import ephemeral
        from nodus_dc.partition_binding import provider_reservation
        task = {"cpu_millis":2000,"memory_bytes":64*1024**2,"scratch_bytes":4*1024**2}
        charge = ephemeral.charge(task)
        descriptor = {"contract":ephemeral.CONTRACT,"spec_sha256":"d"*64,"charge":charge,
            "features":{"continuity":"ephemeral","restore_manifest":False,"checkpoint_policy":False,
                "snapshot_inputs":False,"lazy_inputs":False,"outside_outputs":False,
                "input_count":1,"input_bytes":17,"output_count":1}}
        policy = self.synthetic_policy(None)
        policy["shapes"][0]["shape"].update(cpuMillis=task["cpu_millis"],memoryBytes=task["memory_bytes"],scratchBytes=task["scratch_bytes"])
        self.p.policy_provider = lambda db, **kwargs: policy
        capacity = {"cpu_millis":10000,"memory_bytes":2*charge["aggregate"]["memory_bytes"]-4096,"scratch_bytes":2*task["scratch_bytes"]}
        original_prepare = self.executor.prepare_reservation
        server = BridgeUnixServer(str(self.root/"aggregate.sock"), self.service, "fixture-"+"x"*40, owner_uid=os.geteuid())
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
        report_request = {"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING}
        def floor():
            with self.service.store.connection() as db:
                return db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        try:
            self.assertEqual(call("offers",report_request),(200,{"offers":[],"host_budget":None}))
            self.enable_ephemeral_profile(task,capacity)
            aggregate_prepare = self.executor.prepare_reservation
            self.executor.prepare_reservation = original_prepare
            status, report = call("offers",report_request); self.assertEqual(status,200,report)
            self.assertEqual(report["host_budget"],{"accounting_version":ephemeral.ACCOUNTING,"capacity":capacity,
                "local_reserved":{k:0 for k in task}})
            self.assertEqual(len(report["offers"]),2)
            requests = [{"platform_lease_id":"aggregate-"+str(i),"platform_epoch":1,"generation":0,
                "offer":offer,"workload":{"workload_image":IMAGE,"workload_kind":"Job"},
                "resources":dict(task),"ephemeral":copy.deepcopy(descriptor),"expires_at_unix_millis":1100000}
                for i,offer in enumerate(report["offers"])]
            previous_floor = floor()
            for invalid in (None,{}, {**descriptor,"extra":1},
                    {**descriptor,"charge":{**charge,"host_memory_bytes":False}},
                    {**descriptor,"features":{**descriptor["features"],"input_bytes":0}},
                    {**descriptor,"features":{**descriptor["features"],"lazy_inputs":True}},
                    {**descriptor,"charge":{**charge,"aggregate":task}}):
                self.assertEqual(call("claim",{**requests[0],"ephemeral":invalid})[0],400)
            # A provider that only knows raw task accounting cannot commit the new floor.
            self.assertEqual(call("claim",requests[0])[0],503)
            self.assertEqual(floor(),previous_floor)
            self.assertNotIn("reader_schema",self.service.store.fence.read())
            self.assertFalse(call("inspect",requests[0])[1]["held"])
            def aggregate_reservation(lease,resources):
                self.assertEqual(resources,charge["aggregate"])
                return aggregate_prepare(lease,resources)
            self.executor.prepare_reservation = aggregate_reservation
            barrier = threading.Barrier(3,timeout=5); outcomes=[]; failures=[]
            def acquire(request):
                try:
                    barrier.wait(); outcomes.append((request,call("claim",request)))
                except Exception as exc: failures.append(exc)
            workers=[threading.Thread(target=acquire,args=(r,),daemon=True) for r in requests]
            for worker in workers: worker.start()
            barrier.wait()
            for worker in workers: worker.join(5)
            self.assertTrue(all(not worker.is_alive() for worker in workers)); self.assertEqual(failures,[])
            self.assertEqual(sorted(response[0] for _,response in outcomes),[200,409])
            requested,response=next(pair for pair in outcomes if pair[1][0]==200)
            held=response[1]["lease"]
            self.assertEqual(held["resources"],task)
            self.assertEqual(held["ephemeral"],descriptor)
            self.assertEqual(call("claim",requested),(200,{"lease":held}))
            self.assertEqual(call("claim",{**requested,"ephemeral":{**descriptor,"spec_sha256":"e"*64}})[0],409)
            self.assertEqual((floor(),self.service.store.fence.read()["reader_schema"]),("7",7))
            with self.service.store.connection() as db:
                row=db.execute("SELECT r.* FROM host_reservations r JOIN leases l ON l.id=r.lease_id WHERE l.owner='external'").fetchone()
                local=Store.lease(db,row["lease_id"])
                self.assertEqual({k:row[k] for k in task},charge["aggregate"])
                original=row["enforcement"]
                self.assertEqual(json.loads(provider_reservation(row,local)["enforcement"]),
                    {"enforcement_ready":True,"synthetic":True,"accounting_version":ephemeral.ACCOUNTING})
            self.assertFalse(call("check",held)[1]["authorized"])
            ref={"attempt_id":"att_00000000000000000000000001","epoch":1}
            self.assertEqual(call("bind",{"lease":held,"ref":ref})[1]["error"]["code"],"ephemeral_enforcement_unavailable")
            self.assertEqual(call("begin",{"lease":held,"ref":ref,"binding_sha256":"a"*64,"expected_phase_revision":1})[0],503)
            self.assertEqual(call("offers",{})[1],{"offers":[]})  # No legacy reinterpretation.
            self.assertEqual(call("offers",report_request)[1]["offers"],[])
            self.assertEqual(self.executor.accounting[-1][2]["accounting_version"],ephemeral.ACCOUNTING)
            self.assertEqual(self.executor.accounting[-1][1][0]["resources"],charge["aggregate"])
            # Reserved data cannot be dropped or altered to masquerade as legacy provider proof.
            for changed in (None,{**json.loads(original)[ephemeral.MEMBER],"provider_proof_sha256":"0"*64}):
                with self.service.store.transaction(self.clock()) as db:
                    proof=json.loads(original)
                    if changed is None: proof.pop(ephemeral.MEMBER)
                    else: proof[ephemeral.MEMBER]=changed
                    db.execute("UPDATE host_reservations SET enforcement=? WHERE lease_id=?",(json.dumps(proof),local["id"]))
                self.assertEqual(call("offers",report_request)[1]["error"]["code"],"invalid_execution_binding")
                self.assertEqual(call("reclaim",held)[1]["error"]["code"],"invalid_execution_binding")
                with self.service.store.transaction(self.clock()) as db:
                    db.execute("UPDATE host_reservations SET enforcement=? WHERE lease_id=?",(original,local["id"]))
            self.assertTrue(call("reclaim",held)[1]["retired"])
            self.executor.clean=False
            self.assertFalse(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
            self.assertTrue(call("inspect",held)[1]["held"])
            self.assertEqual(call("offers",report_request)[1]["offers"],[])
            self.executor.clean=True
            self.assertTrue(call("complete",{"lease":held,"cleanup_verified":True})[1]["released"])
            with self.service.store.connection() as db:
                self.assertEqual(db.execute("SELECT enforcement FROM host_reservations WHERE lease_id=?",(local["id"],)).fetchone()[0],original)
            self.assertEqual(len(call("offers",report_request)[1]["offers"]),2)
        finally:
            for worker in workers: worker.join(5)
            server.shutdown(); server.server_close(); thread.join(5)
            self.assertFalse(thread.is_alive())

        # A crash after the registry write must not repair itself into a second admission.
        crash = Partitions(); crash.setUp()
        try:
            crash.enable_ephemeral_profile(task,capacity)
            offer=crash.p.offers(**report_request)["offers"][0]
            request={**requests[0],"offer":offer}
            with crash.service.store.connection() as db:
                old_floor=db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
            advance=crash.service.store.fence.advance
            def interrupted(db):
                advance(db)
                if db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]=="7":
                    raise RuntimeError("synthetic interruption after aggregate registry write")
            crash.service.store.fence.advance=interrupted
            with self.assertRaisesRegex(RuntimeError,"after aggregate registry write"):
                crash.p.claim(**request)
            crash.service.store.fence.advance=advance
            with crash.service.store.connection() as db:
                self.assertEqual(db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],old_floor)
                self.assertEqual(db.execute("SELECT count(*) FROM partition_claims").fetchone()[0],0)
            self.assertEqual(crash.service.store.fence.read()["reader_schema"],7)
            crash.assert_error("authority_continuity_lost",lambda:crash.p.claim(**request))
        finally: crash.tearDown()

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
