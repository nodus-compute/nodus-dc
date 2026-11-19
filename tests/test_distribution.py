"""An actual offline wheel install, activation and safe uninstall in temp dirs."""
import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import select
import tarfile
import sqlite3
import sys
import tempfile
import time
import unittest

from nodus_dc import __version__
from nodus_dc.authority_fence import AuthorityFence
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock

ROOT = Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
    def test_schema4_refuses_published_dev14_without_changing_ownership(self):
        self.schema_downgrade("NODUS_PARTITION_LEGACY_WHEEL",
            "8ef7558a94a52f9ecb1319fa18431b727c7f9021e5d9134b99edb0f520efc625", "4")

    def test_schema5_refuses_published_dev15_without_changing_policy_or_ownership(self):
        self.schema_downgrade("NODUS_POLICY_LEGACY_WHEEL",
            "ea5d0929d5039cac947a2f28d90c038b9720fb978e07b985a880fd2d3ccdda05", "5")

    def test_schema6_fences_already_open_dev16_and_d9_before_provider_hooks(self):
        self.binding_reader_floor()

    def test_schema7_fences_already_open_ecfa_before_provider_hooks(self):
        self.binding_reader_floor(aggregate=True)

    def test_schema8_fences_already_open_b18_before_provider_hooks(self):
        self.binding_reader_floor(aggregate=True, qualified=True)

    def binding_reader_floor(self, aggregate=False, qualified=False):
        # Actual frozen old code, not a reimplementation of the old reader.
        pins = (("NODUS_TRUSTED_B18_ARCHIVE","2eccbf8981dc0f488f006044bd0650a6e49bd6b7212df23bf282ea573d8ec05e"),) if qualified else (("NODUS_AGGREGATE_ECFA_ARCHIVE","828e7d0dfab05640972f572d1785a7f1fca135e7fd535b931fd2f5944db2fb22"),) if aggregate else (
                ("NODUS_BINDING_DEV16_WHEEL","4a9153d982bad3f34db4792ad80649a054e12ead8573d6639f54ba25eaf19870"),
                ("NODUS_BINDING_D9_ARCHIVE","c9150aa8a107616056d968bf36e8dd664a4123a64b34f0c7cd69726b92989a29"))
        for name, expected in pins:
            if not os.environ.get(name): self.skipTest("offline binding reader fixture required: "+name)
            self.assertEqual(hashlib.sha256(Path(os.environ[name]).read_bytes()).hexdigest(),expected)
        from tests.test_partition_policy import PartitionPolicyJourney
        journey=PartitionPolicyJourney();journey.setUp()
        children=[]
        try:
            self.assertEqual(journey.update()[0],200)
            local,request,held=journey.claimed()
            old_source=journey.case.root/"old-d9";old_source.mkdir()
            with tarfile.open(os.environ[pins[-1][0]]) as archive:
                for member in archive.getmembers():
                    prefix="nodus-dc/src/"
                    if member.isfile() and member.name.startswith(prefix) and member.name.endswith(".py"):
                        relative=Path(member.name[len(prefix):])
                        self.assertNotIn("..",relative.parts)
                        target=old_source/relative;target.parent.mkdir(parents=True,exist_ok=True)
                        target.write_bytes(archive.extractfile(member).read())
            probe = r"""
import json, sys
from pathlib import Path
import nodus_dc
assert str(nodus_dc.__file__).startswith(sys.argv[2]+'/'), 'wrong old-reader import'
from nodus_dc.service import Service
from nodus_dc.store import Store
from nodus_dc.errors import Error
from tests.test_partition_authority import Backend, Clock
root=Path(sys.argv[1]);clock=Clock();backend=Backend(clock,root)
service=Service(Store(root/'state.db'),backend,clock=clock,bridge_enabled=True)
calls=[]
def forbidden(*args,**kwargs):
    calls.append('provider');raise AssertionError('old reader reached provider')
class Executor:
    def __getattr__(self,name): return forbidden
service.partitions.executor=Executor()
for name in ('start','cleanup','validate_workload','configure_mig','recover_partition'):
    setattr(backend,name,forbidden)
print(json.dumps({'opened':True}),flush=True)
body=json.loads(sys.stdin.readline());held=body['held'];local=body['local']
out={}
for name,operation in (
    ('check',lambda:service.partitions.check(**held)),
    ('claim',lambda:service.partitions.claim(**body['request'])),
    ('reclaim',lambda:service.partitions.reclaim(**held)),
    ('complete',lambda:service.partitions.complete(lease=held,cleanup_verified=True)),
    ('start',lambda:service.start(local['id'],generation=local['generation'],request_key='old-start',workload={'test_workload':True})),
    ('release',lambda:service.release(local['id'],generation=local['generation'],request_key='old-release'))):
    try: operation();out[name]='ALLOWED'
    except Error as error: out[name]=error.code
try: Store(root/'state.db');out['reopen']='ALLOWED'
except Error as error: out['reopen']=error.code
out['provider_calls']=calls
print(json.dumps(out),flush=True)
"""
            sources = (old_source,) if aggregate else (Path(os.environ[pins[0][0]]).resolve(),old_source)
            for source in sources:
                environment={k:v for k,v in os.environ.items() if k not in {"PYTHONPATH","PYTHONHOME"}}
                environment["PYTHONPATH"]=os.pathsep.join((str(source),str(ROOT)))
                child=subprocess.Popen([sys.executable,"-c",probe,str(journey.case.root),str(source)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                    env=environment,cwd=journey.case.root)
                children.append(child)
                self.assertTrue(select.select([child.stdout],[],[],15)[0],"old reader did not open before binding")
                self.assertEqual(json.loads(child.stdout.readline()),{"opened":True})
            if aggregate:
                from nodus_dc import ephemeral
                # Retire legacy owners normally; the first profile deliberately refuses mixed contracts.
                self.assertEqual(journey.call("reclaim",held,partitions=True)[0],200)
                self.assertTrue(journey.call("complete",{"lease":held,"cleanup_verified":True},partitions=True)[1]["released"])
                journey.s.release(local["id"],generation=local["generation"],request_key="release-before-aggregate")
                task, descriptor, image = journey.case.enable_trusted_profile() if qualified else (journey.case.enable_ephemeral_profile(),None,None)
                status,offers=journey.call("offers",{"include_host_budget":True,"accounting_version":ephemeral.ACCOUNTING},partitions=True)
                self.assertEqual(status,200,offers)
                profile={"contract":ephemeral.CONTRACT,"spec_sha256":"d"*64,"charge":ephemeral.charge(task),
                    "features":{"continuity":"ephemeral","restore_manifest":False,"checkpoint_policy":False,
                        "snapshot_inputs":False,"lazy_inputs":False,"outside_outputs":False,
                        "input_count":0,"input_bytes":0,"output_count":0}}
                candidate={**request,"platform_lease_id":"aggregate-floor","generation":0,"offer":offers["offers"][0],
                    "resources":task,"ephemeral":profile}
                if qualified: candidate.update(ephemeral=descriptor, qualified_image=image)
                status,committed=journey.call("claim",candidate,partitions=True)
                self.assertEqual(status,200,committed)
                self.assertEqual(journey.s.store.fence.read()["reader_schema"],8 if qualified else 7)
            else:
                ref={"attempt_id":"att_00000000000000000000000001","epoch":held["platform_epoch"]}
                status,committed=journey.call("bind",{"lease":held,"ref":ref},partitions=True)
                self.assertEqual(status,200,committed)
            with journey.s.store.connection() as db: before=list(db.iterdump())
            registry=journey.s.store.fence.path.read_bytes()
            for child in children:
                stdout,stderr=child.communicate(json.dumps({"held":held,"request":request,"local":local})+"\n",timeout=30)
                self.assertEqual(child.returncode,0,stderr)
                result=json.loads(stdout)
                self.assertEqual(result.pop("provider_calls"),[])
                self.assertEqual(result.pop("reopen"),"schema_version")
                self.assertEqual(result,{key:"authority_fence_unavailable" for key in ("check","claim","reclaim","complete","start","release")})
                with journey.s.store.connection() as db: self.assertEqual(list(db.iterdump()),before)
                self.assertEqual(journey.s.store.fence.path.read_bytes(),registry)
            if aggregate:
                self.assertEqual(journey.call("check",committed["lease"],partitions=True)[1]["authorized"],qualified)
                self.assertEqual(journey.s.get(local["id"])["state"],"released")
            else:
                self.assertTrue(journey.call("check",held,partitions=True)[1]["authorized"])
                self.assertEqual(journey.s.get(local["id"])["state"],"active")
        finally:
            for child in children:
                if child.poll() is None: child.kill()
                child.communicate(timeout=5)
            journey.tearDown()

    def schema_downgrade(self, variable, legacy_sha, schema):
        legacy_path = os.environ.get(variable)
        if not legacy_path:
            self.skipTest("offline published wheel required for schema"+schema+" downgrade verification: "+variable)
        legacy = Path(legacy_path).resolve()
        self.assertEqual(hashlib.sha256(legacy.read_bytes()).hexdigest(), legacy_sha)
        spec = importlib.util.spec_from_file_location("build_partition_compatibility", ROOT / "build_backend.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        # The real registry requires private, non-writable ancestry, unlike /tmp.
        with tempfile.TemporaryDirectory(prefix=".nodus-downgrade-", dir=Path.home().resolve()) as folder:
            base = Path(folder)
            wheel = base / "wheels" / builder.build_wheel(base / "wheels")
            prefix, state = base / "install", base / "state"
            command = [sys.executable, str(ROOT / "tools/install.py")]
            common = ["--prefix", str(prefix), "--state-dir", str(state)]
            for candidate in (legacy, wheel):
                installed = subprocess.run([*command, "install", *common, "--wheel", str(candidate)],
                                           capture_output=True, text=True, timeout=90)
                self.assertEqual(installed.returncode, 0, installed.stderr)
            clock = Clock()
            service = Service(Store(state / "authority.sqlite3"), Backend(clock), clock=clock)
            registry = base / "registry" / "fence.json"
            service.store.fence = AuthorityFence(registry, service.store.path)
            keeper = sqlite3.connect(service.store.path)
            try:
                keeper.execute("PRAGMA journal_mode=WAL")
                keeper.execute("PRAGMA wal_autocheckpoint=0")
                service.partitions.ensure_durable()
                held = service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu",
                                       expires_at=1100, request_key="schema4-held")
                if schema == "5":
                    from nodus_dc.partition_policy import PartitionPolicy
                    from tests.test_partition_policy import grant, NODE
                    from tests.test_mig_binding import BOOT
                    policy=PartitionPolicy(service,identity=lambda:{"node_id":NODE,"host_epoch":0},
                        local_images=lambda:None,boot_id=BOOT,boottime_ns=lambda:10_000_000_000)
                    service.bridge_enabled=True
                    policy.update(action="grant",context=policy.context,node_id=NODE,host_epoch=0,stream_epoch=1,
                        grant=grant(),freshness={"echoed_boottime_ns":10_000_000_000,"valid_for_ns":30_000_000_000,
                                                 "available_until_unix_millis":2000000})
                self.assertEqual(keeper.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0], schema)
                self.assertGreater((state / "authority.sqlite3-wal").stat().st_size, 32)
                before = list(keeper.iterdump())
                fence = registry.read_bytes()
                current = os.readlink(prefix / "current")
                manifest = (prefix / "installation.json").read_bytes()
                attempts = [
                    ["activate", *common, "--release", legacy_sha[:20]],
                    ["install", *common, "--wheel", str(legacy)],
                    ["install", "--prefix", str(base / "new-install"), "--state-dir", str(state),
                     "--wheel", str(legacy)],
                ]
                for args in attempts:
                    with self.subTest(action=args[:2]):
                        refused = subprocess.run([*command, *args], capture_output=True, text=True, timeout=90)
                        self.assertNotEqual(refused.returncode, 0)
                        self.assertIn("candidate cannot open the current authority state", refused.stderr)
                        self.assertEqual(os.readlink(prefix / "current"), current)
                        self.assertEqual((prefix / "installation.json").read_bytes(), manifest)
                        self.assertEqual(list(keeper.iterdump()), before)
                        self.assertEqual(registry.read_bytes(), fence)
                        self.assertEqual(service.get(held["id"])["state"], "reserved")
                self.assertFalse((base / "new-install").exists())
            finally:
                keeper.close()

    def test_locked_sqlite_compatibility_snapshot_has_deadline(self):
        spec = importlib.util.spec_from_file_location("installer_deadline", ROOT / "tools/install.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            database = state / "authority.sqlite3"
            owner = sqlite3.connect(database)
            try:
                owner.execute("CREATE TABLE history(value TEXT)")
                owner.execute("INSERT INTO history VALUES ('retained')")
                owner.commit()
                before = database.read_bytes()
                owner.execute("BEGIN EXCLUSIVE")
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "state snapshot timed out; activation refused"):
                    installer.state_compatible(sys.executable, state, snapshot_timeout=0.15)
                self.assertLess(time.monotonic() - started, 1.5)
                self.assertTrue(owner.in_transaction)
                self.assertEqual(database.read_bytes(), before)
                self.assertEqual(owner.execute("SELECT value FROM history").fetchone(), ("retained",))
            finally:
                owner.close()

    def test_schema2_refuses_published_dev1_before_daemon_stop(self):
        # Supply the public immutable wheel offline. No test downloads and no
        # synthetic older implementation may stand in for this compatibility gate.
        legacy_path = os.environ.get("NODUS_DISTRIBUTION_LEGACY_WHEEL")
        if not legacy_path:
            self.skipTest("offline published dev1 wheel required for artifact compatibility qualification")
        legacy = Path(legacy_path).resolve()
        legacy_sha = "af84d890e652c6a62ae7b1672703691db8eb99df1f65920a2a5d3a34c49e67f9"
        self.assertEqual(hashlib.sha256(legacy.read_bytes()).hexdigest(), legacy_sha)
        spec = importlib.util.spec_from_file_location("build_compatibility", ROOT / "build_backend.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            wheel = base / "wheels" / builder.build_wheel(base / "wheels")
            prefix, state = base / "install", base / "state"
            common = [sys.executable, str(ROOT / "tools/install.py")]
            def install(action, *extra):
                return subprocess.run([*common, action, "--prefix", str(prefix), "--state-dir", str(state), *extra],
                                      capture_output=True, text=True, timeout=90)
            for candidate in (legacy, wheel):
                result = install("install", "--wheel", str(candidate))
                self.assertEqual(result.returncode, 0, result.stderr)
            current = json.loads(result.stdout)["release"]
            environment = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"}}
            def status():
                return subprocess.run([str(prefix / "current/bin/nodus-dc"), "--state-dir", str(state), "status"],
                                      capture_output=True, text=True, env=environment, cwd=base)
            self.assertEqual(status().returncode, 0)
            self.assertEqual(install("activate", "--release", legacy_sha[:20]).returncode, 0)
            self.assertEqual(status().returncode, 0)  # Real schema1 rollback remains supported.
            self.assertEqual(install("activate", "--release", current).returncode, 0)
            # Keep the schema2 update in WAL: copying only the main database must
            # never incorrectly admit the older schema1 implementation.
            keeper = sqlite3.connect(state / "authority.sqlite3")
            try:
                keeper.execute("PRAGMA journal_mode=WAL")
                keeper.execute("PRAGMA wal_autocheckpoint=0")
                Service(Store(state / "authority.sqlite3"), object()).record_connection_attempt({"synthetic_fixture": True})
                self.assertTrue((state / "authority.sqlite3-wal").stat().st_size > 32)
                before = dict(keeper.execute("SELECT key,value FROM meta"))
                self.assertEqual(before["schema_version"], "2")
                active = os.readlink(prefix / "current")
                manifest = (prefix / "installation.json").read_bytes()
                with (state / "daemon.lock").open("a") as daemon:
                    fcntl.flock(daemon.fileno(), fcntl.LOCK_EX)
                    for action, extra in (("activate", ["--release", legacy_sha[:20]]),
                                          ("install", ["--wheel", str(legacy)])):
                        refused = install(action, *extra)
                        self.assertNotEqual(refused.returncode, 0)
                        self.assertIn("candidate cannot open the current authority state", refused.stderr)
                        self.assertNotIn("stop the daemon", refused.stderr)
                    # Also exercise a not-yet-installed wheel's temporary probe.
                    other_prefix = base / "new-prefix"
                    refused = subprocess.run([*common, "install", "--prefix", str(other_prefix), "--state-dir", str(state),
                                              "--wheel", str(legacy)], capture_output=True, text=True, timeout=90)
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertIn("candidate cannot open the current authority state", refused.stderr)
                    self.assertFalse(other_prefix.exists())
                self.assertEqual(os.readlink(prefix / "current"), active)
                self.assertEqual((prefix / "installation.json").read_bytes(), manifest)
                self.assertEqual(dict(keeper.execute("SELECT key,value FROM meta")), before)
                self.assertEqual(status().returncode, 0)
            finally:
                keeper.close()

    def test_reproducible_build_offline_install_and_owned_uninstall(self):
        spec = importlib.util.spec_from_file_location("build_backend", ROOT / "build_backend.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            name = builder.build_wheel(base / "one")
            other = builder.build_wheel(base / "two")
            self.assertEqual((base / "one" / name).read_bytes(), (base / "two" / other).read_bytes())
            wheel = base / "one" / name
            if os.environ.get("NODUS_MANAGED_COMPONENT_INPUT"):
                from tests.managed_distribution_components import measure
                measure(ROOT, wheel)
            prefix, state = base / "install", base / "state"
            environment = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"}}
            def installed_version():
                return subprocess.check_output([str(prefix / "current/bin/nodus-dc"), "--version"],
                                               text=True, env=environment, cwd=base).strip()
            command = [sys.executable, str(ROOT / "tools/install.py")]
            common = ["--prefix", str(prefix), "--state-dir", str(state)]
            result = subprocess.run([*command, "install", *common, "--wheel", str(wheel)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            release = json.loads(result.stdout)["release"]
            version = installed_version()
            self.assertEqual(version, __version__)
            clock = Clock()
            service = Service(Store(state / "authority.sqlite3"), Backend(clock), clock=clock)
            lease = service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key="install-test")
            refused = subprocess.run([*command, "uninstall", *common], capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertTrue((prefix / "current/bin/nodus-dc").exists())
            service.release(lease["id"], generation=lease["generation"], request_key="clean")
            # Build a declared test-only successor and verify actual executable
            # upgrade followed by rollback to the original installed release.
            successor = base / "successor-source"
            shutil.copytree(ROOT / "src", successor / "src", ignore=shutil.ignore_patterns("__pycache__"))
            for name in ("LICENSE", "PROVENANCE.json"):
                shutil.copy2(ROOT / name, successor / name)
            init = successor / "src/nodus_dc/__init__.py"
            init.write_text(init.read_text().replace(__version__, "0.1.0.dev999"))
            builder.ROOT = successor
            builder.VERSION = "0.1.0.dev999"
            builder.DIST = "nodus_datacenter-0.1.0.dev999.dist-info"
            builder.METADATA = builder.METADATA.replace(__version__, "0.1.0.dev999")
            next_name = builder.build_wheel(base / "next")
            upgraded = subprocess.run([*command, "install", *common, "--wheel", str(base/"next"/next_name)], capture_output=True, text=True)
            self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
            self.assertEqual(installed_version(), "0.1.0.dev999")
            activated = subprocess.run([*command, "activate", *common, "--release", release], capture_output=True, text=True)
            self.assertEqual(activated.returncode, 0, activated.stderr)
            self.assertEqual(installed_version(), __version__)
            foreign = prefix / "releases" / release / "operator-data.txt"
            foreign.write_text("preserve this")
            removed = subprocess.run([*command, "uninstall", *common], capture_output=True, text=True)
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertTrue((state / "authority.sqlite3").exists())
            self.assertEqual(foreign.read_text(), "preserve this")
            self.assertFalse((prefix / "current").exists())


if __name__ == "__main__":
    unittest.main()
