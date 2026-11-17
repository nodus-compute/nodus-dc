"""Real private socket + SQLite policy journey; all devices/enforcement synthetic."""
import copy
import hashlib
import json
import os
import threading
import unittest

from nodus_dc.api import BridgeUnixServer
from nodus_dc.partition_policy import PartitionPolicy
from tests.test_api import UnixHTTPConnection
from tests.test_mig_binding import BOOT
from tests import test_partition_authority as fixture
from tests.test_partition_authority import A, B, IMAGE

NODE = "bnod_00000000000000000000000001"
CONSENT = "12345678-1234-4234-8234-123456789abc"
TOKEN = "synthetic-partition-policy-bridge-token-00000001"


def grant():
    # This insertion order is the Go PoolPartitionSharingTerms struct order.
    terms = {"contract":"MIGPartitionV1", "revision":"1", "partitionPricing":{"version":"1", "shapes":[{
        "shape":{"accelerator":"a100-40gb", "profile":"3g.20gb", "gpuMemoryBytes":21072183296,
            "cpuMillis":2000, "memoryBytes":3*1024**3, "scratchBytes":128*1024**2}, "hourlyUSD":"1.00"}]},
        "compensation":"Credits", "ownerShareBasisPoints":8000, "reclaimNoticeSeconds":0,
        "agreementURL":"https://example.test/partition-terms"}
    raw = json.dumps(terms,separators=(",",":"),ensure_ascii=False)
    return {"agreement":{"node_id":NODE,"consent_id":CONSENT,"generation":7,
        "terms_sha256":hashlib.sha256(raw.encode()).hexdigest()}, "terms_json":raw, "allowed_images":[IMAGE]}


class PartitionPolicyJourney(unittest.TestCase):
    def setUp(self):
        self.case = fixture.Partitions(); self.case.setUp()
        self.s, self.p = self.case.service, self.case.p
        self.ns = 10_000_000_000
        self.identity = {"node_id":NODE,"host_epoch":0}
        self.local_images = [IMAGE]
        self.install()
        self.server = BridgeUnixServer(self.case.root/"policy.sock",self.s,TOKEN,owner_uid=os.geteuid())
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.ctx = self.call("context",{})[1]["context"]
        self.g = grant()
        # Any accidental v1 authorization call fails this journey.
        self.s.bridge_authorization_check = lambda **_: False

    def install(self):
        self.policy = PartitionPolicy(self.s,identity=lambda:dict(self.identity),local_images=lambda:self.local_images,
                                      boot_id=BOOT,boottime_ns=lambda:self.ns)
        self.s.partition_policy = self.policy
        self.p.policy_provider = self.policy.current

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)
        self.case.tearDown()

    def call(self, operation, body, *, token=TOKEN, partitions=False):
        connection = UnixHTTPConnection(self.server.path)
        path = "/v2/bridge/"+("partitions/" if partitions else "partition-policy/")+operation
        try:
            try:
                connection.request("POST",path,json.dumps(body,ensure_ascii=False).encode("utf-8"),{"Authorization":"Bearer "+token,"Content-Type":"application/json"})
            except BrokenPipeError:
                # Authentication may reject before reading the request body.
                pass
            response = connection.getresponse(); data=response.read()
            self.assertLessEqual(len(data),65536)
            return response.status,json.loads(data)
        finally:
            connection.close()

    def update(self, action="grant", *, epoch=1, **changes):
        body = {"action":action,"context":self.ctx,"node_id":NODE,"host_epoch":0,"stream_epoch":epoch}
        if action == "grant":
            body.update(grant=copy.deepcopy(self.g),freshness={"echoed_boottime_ns":self.ns,
                "valid_for_ns":30_000_000_000,"available_until_unix_millis":2000000})
        if action == "withdraw": body["agreement"]=copy.deepcopy(self.g["agreement"])
        body.update(changes)
        return self.call("update",body)

    def claimed(self, name="borrowed"):
        local=self.s.reserve(resources=[A],mode="hardware_partition",expires_at=1400,request_key="local-"+name,
            host_resources={"cpu_millis":1000,"memory_bytes":2*1024**3,"scratch_bytes":128*1024**2})
        self.s.start(local["id"],generation=local["generation"],request_key="start-"+name,workload={"test_workload":True})
        status,offers=self.call("offers",{},partitions=True); self.assertEqual(status,200)
        offer=next(o for o in offers["offers"] if o["partition"]["resource_id"]==B)
        request={"platform_lease_id":name,"platform_epoch":1,"generation":0,"offer":offer,
            "workload":{"workload_image":IMAGE,"workload_kind":"Job"},"resources":offer["capacity"],"expires_at_unix_millis":1100000}
        status,result=self.call("claim",request,partitions=True);self.assertEqual(status,200,result)
        return local,request,result["lease"]

    def test_socket_renewal_withdraw_and_cleanup_preserve_sibling(self):
        self.assertEqual(self.call("context",{},token="wrong")[0],401)
        status,first=self.update(); self.assertEqual(status,200,first)
        self.assertEqual(first["grant"],self.g); self.assertEqual(first["agreement"],self.g["agreement"])
        local,request,held=self.claimed()
        ref={"attempt_id":"att_00000000000000000000000001","epoch":held["platform_epoch"]}
        def binding_state():
            from nodus_dc.partition_binding import split_reservation
            with self.s.store.connection() as db:
                row=db.execute("SELECT r.* FROM host_reservations r JOIN partition_claims c ON c.lease_id=r.lease_id WHERE c.platform_lease_id=?",(held["platform_lease_id"],)).fetchone()
                return split_reservation(row)[1]
        # Failed first binding commits neither identity nor the reader floor.
        qualify=self.case.executor.qualification
        self.case.executor.qualification=lambda device:{**qualify(device),"execution_identity":None}
        self.assertNotEqual(self.call("bind",{"lease":held,"ref":ref},partitions=True)[0],200)
        self.case.executor.qualification=qualify
        self.assertIsNone(binding_state())
        with self.s.store.connection() as db:
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],"5")
        self.assertNotIn("reader_schema",self.s.store.fence.read())
        status,committed=self.call("bind",{"lease":held,"ref":ref},partitions=True)
        self.assertEqual(status,200,committed)
        self.assertEqual((committed["phase"],committed["phase_revision"]),("committed",1))
        self.assertEqual(committed["binding"]["requested_resources"],held["resources"])
        self.assertEqual(self.s.store.fence.read()["reader_schema"],6)
        original_verify=self.case.executor.verify_reservation
        def exact_provider(lease,reservation):
            self.assertEqual(json.loads(reservation["enforcement"]),{"enforcement_ready":True,"synthetic":True})
            return original_verify(lease,reservation)
        self.case.executor.verify_reservation=exact_provider
        begin={"lease":held,"ref":ref,"binding_sha256":committed["binding_sha256"],"expected_phase_revision":1}
        for changed in ({**begin,"binding_sha256":"0"*64},{**begin,"expected_phase_revision":2},
                        {**begin,"phase":"runnable"},{**begin,"ref":{**ref,"epoch":2}}):
            self.assertNotEqual(self.call("begin",changed,partitions=True)[0],200)
            self.assertEqual(binding_state(),committed)
        status,begun=self.call("begin",begin,partitions=True);self.assertEqual(status,200,begun)
        self.assertEqual((begun["phase"],begun["phase_revision"]),("materialization-begun",2))
        self.assertEqual(begun["binding"],committed["binding"])
        self.assertEqual(self.call("begin",begin,partitions=True),(200,begun))
        self.assertEqual(self.call("bind",{"lease":held,"ref":ref},partitions=True),(200,begun))
        self.assertNotEqual(self.call("bind",{"lease":held,"ref":{**ref,"attempt_id":CONSENT}},partitions=True)[0],200)
        self.assertEqual(binding_state(),begun)
        with self.s.store.connection() as db:
            row=db.execute("SELECT lease_id,enforcement FROM host_reservations WHERE lease_id IN (SELECT lease_id FROM partition_claims)").fetchone()
            local_id,original=row[0],row[1]
        for malformed in (None,{**begun,"phase":"runnable"}):
            with self.s.store.transaction(self.case.clock()) as db:
                proof=json.loads(original);proof["nodus.execution_binding"]=malformed
                db.execute("UPDATE host_reservations SET enforcement=? WHERE lease_id=?",(json.dumps(proof),local_id))
            self.assertFalse(self.call("check",held,partitions=True)[1]["authorized"])
            self.assertNotEqual(self.call("begin",begin,partitions=True)[0],200)
            with self.s.store.transaction(self.case.clock()) as db:
                db.execute("UPDATE host_reservations SET enforcement=? WHERE lease_id=?",(original,local_id))
        self.assertTrue(self.call("check",held,partitions=True)[1]["authorized"])
        self.ns += 5_000_000_000
        status,renewed=self.update(freshness={"echoed_boottime_ns":self.ns,"valid_for_ns":30_000_000_000,"available_until_unix_millis":2100000})
        self.assertEqual(status,200,renewed);self.assertEqual(first["policy_revision"],renewed["policy_revision"])
        replay=self.call("claim",request,partitions=True)[1]["lease"]
        self.assertEqual(replay,held);self.assertEqual(replay["expires_at_unix_millis"],1100000)
        self.assertTrue(self.call("check",held,partitions=True)[1]["authorized"])
        with self.s.store.connection() as db:
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],"6")
        self.assertEqual(self.update("withdraw")[0],200)
        retired=binding_state()
        self.assertEqual((retired["phase"],retired["phase_revision"]),("retired",3))
        self.assertEqual(retired["binding"],committed["binding"])
        self.assertNotEqual(self.call("begin",begin,partitions=True)[0],200)
        self.assertFalse(self.call("check",held,partitions=True)[1]["authorized"])
        self.assertTrue(self.call("inspect",held,partitions=True)[1]["held"])
        self.assertEqual(self.call("reclaim",request,partitions=True)[1]["lease"],held)
        self.case.executor.clean=False
        self.assertFalse(self.call("complete",{"lease":held,"cleanup_verified":True},partitions=True)[1]["released"])
        self.assertEqual(self.s.get(local["id"])["state"],"active")
        self.case.executor.clean=True
        self.assertTrue(self.call("complete",{"lease":held,"cleanup_verified":True},partitions=True)[1]["released"])
        self.assertEqual(self.case.executor.verified,[(B,),(B,)])
        self.assertEqual(self.s.get(local["id"])["state"],"active")
        self.assertEqual(binding_state(),retired)  # Completion retains provenance with the released claim.
        self.assertEqual(self.call("reclaim",request,partitions=True)[0],200)
        self.assertEqual(binding_state(),retired)
        self.assertEqual(self.update()[1]["error"]["code"],"partition_policy_retired")

    def test_binding_commit_crash_retains_the_write_ahead_reader_fence(self):
        self.assertEqual(self.update()[0],200)
        local,_,held=self.claimed()
        advance=self.s.store.fence.advance
        def interrupted(db):
            advance(db)
            raise RuntimeError("synthetic interruption after registry write before binding commit")
        self.s.store.fence.advance=interrupted
        # Avoid interrupting the earlier read-only inventory transaction; only
        # the binding's schema6 transaction crosses this deliberate boundary.
        def binding_only(db):
            if db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]=="6": interrupted(db)
            else: advance(db)
        self.s.store.fence.advance=binding_only
        ref={"attempt_id":"att_00000000000000000000000001","epoch":held["platform_epoch"]}
        self.assertEqual(self.call("bind",{"lease":held,"ref":ref},partitions=True)[0],500)
        self.s.store.fence.advance=advance
        with self.s.store.connection() as db:
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],"5")
            self.assertNotIn("nodus.execution_binding",db.execute("SELECT enforcement FROM host_reservations WHERE lease_id IN (SELECT lease_id FROM partition_claims)").fetchone()[0])
        self.assertEqual(self.s.store.fence.read()["reader_schema"],6)
        self.assertEqual(self.call("check",held,partitions=True)[1]["error"]["code"],"authority_continuity_lost")
        self.assertEqual(self.s.get(local["id"])["state"],"active")

    def test_restart_expiry_and_session_revoke_cannot_revive_held_execution(self):
        self.assertEqual(self.update()[0],200)
        _,_,held=self.claimed()
        self.ns += 31_000_000_000
        self.assertFalse(self.call("check",held,partitions=True)[1]["authorized"])
        self.assertEqual(self.call("offers",{},partitions=True)[1],{"offers":[]})
        self.assertEqual(self.update()[1]["error"]["code"],"stale_partition_session")
        self.assertEqual(self.call("offers",{},partitions=True)[1],{"offers":[]})
        status,new=self.update(epoch=2); self.assertEqual(status,200,new)
        self.assertGreater(new["policy_revision"],held["offer"]["policy_revision"])
        self.assertFalse(self.call("check",held,partitions=True)[1]["authorized"])
        old_context=self.ctx;self.install()
        self.assertFalse(self.call("check",held,partitions=True)[1]["authorized"])
        self.ctx=self.call("context",{})[1]["context"];self.assertNotEqual(self.ctx,old_context)
        self.assertEqual(self.update(context=old_context)[1]["error"]["code"],"stale_partition_context")
        self.assertEqual(self.update()[1]["error"]["code"],"stale_partition_session")
        self.assertEqual(self.update(epoch=3)[0],200)
        self.assertEqual(self.update("session_revoke",epoch=3)[0],200)
        self.assertEqual(self.update("session_revoke",epoch=3)[0],200)  # lost acknowledgement
        self.assertEqual(self.update(epoch=3)[1]["error"]["code"],"stale_partition_session")
        self.assertTrue(self.call("inspect",held,partitions=True)[1]["held"])
        self.assertTrue(self.call("complete",{"lease":held,"cleanup_verified":True},partitions=True)[1]["released"])

    def test_conflicts_identity_clock_and_response_bound_refuse_before_mutation(self):
        self.assertEqual(self.update()[0],200)
        with self.s.store.connection() as db: before=db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()[0]
        changed=copy.deepcopy(self.g);changed["allowed_images"]=None
        self.assertEqual(self.update(grant=changed)[1]["error"]["code"],"partition_policy_conflict")
        self.assertEqual(self.update(host_epoch=1)[1]["error"]["code"],"partition_identity_changed")
        self.assertEqual(self.update(freshness={"echoed_boottime_ns":self.ns+1,"valid_for_ns":30_000_000_000,"available_until_unix_millis":2000000})[1]["error"]["code"],"partition_policy_expired")
        self.assertEqual(self.update(freshness={"echoed_boottime_ns":self.ns,"valid_for_ns":30_000_000_001,"available_until_unix_millis":2000000})[0],400)
        changed=copy.deepcopy(self.g);t=json.loads(changed["terms_json"]);t["agreementURL"]="https://example.test/"+"é"*11000
        changed["terms_json"]=json.dumps(t,separators=(",",":"),ensure_ascii=False)
        changed["agreement"]["terms_sha256"]=hashlib.sha256(changed["terms_json"].encode()).hexdigest()
        status,error=self.update(grant=changed);self.assertEqual(status,400,error)
        self.assertIn("response bound",error["error"]["message"])
        with self.s.store.connection() as db: self.assertEqual(db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()[0],before)

    def test_local_image_restrictions_and_exact_bundle_are_not_broadened(self):
        self.g["allowed_images"]=None;self.assertEqual(self.update()[0],200)
        request=self.case.request()
        changed=copy.deepcopy(request);changed["resources"]["cpu_millis"]-=1
        self.assertEqual(self.call("claim",changed,partitions=True)[1]["error"]["code"],"partition_shape_mismatch")
        self.local_images=[]
        self.assertEqual(self.call("claim",request,partitions=True)[1]["error"]["code"],"partition_policy_unavailable")
        self.assertEqual(self.update()[0],200)
        # Refresh changes local revision; obtain an offer at that revision.
        request=self.case.request()
        self.assertEqual(self.call("claim",request,partitions=True)[1]["error"]["code"],"workload_not_permitted")
        self.assertEqual(self.case.backend.running,{})

    def test_higher_generation_supersedes_missing_withdrawal_and_persists(self):
        self.assertEqual(self.update()[0],200)
        local,_,held=self.claimed()
        old=copy.deepcopy(self.g)
        self.g["agreement"]["generation"]+=2
        self.g["agreement"]["consent_id"]="22345678-1234-4234-8234-123456789abc"
        self.assertEqual(self.update()[0],200)
        self.assertFalse(self.call("check",held,partitions=True)[1]["authorized"])
        self.assertTrue(self.call("inspect",held,partitions=True)[1]["held"])
        self.assertEqual(self.s.get(local["id"])["state"],"active")
        self.install();self.ctx=self.call("context",{})[1]["context"]
        self.assertEqual(self.update(epoch=2,grant=old)[1]["error"]["code"],"stale_partition_agreement")
        self.assertEqual(self.update(epoch=2)[0],200)
        changed=copy.deepcopy(self.g);changed["agreement"]["consent_id"]=CONSENT
        self.assertEqual(self.update(epoch=2,grant=changed)[1]["error"]["code"],"partition_policy_conflict")
        self.assertTrue(self.call("complete",{"lease":held,"cleanup_verified":True},partitions=True)[1]["released"])
        self.assertEqual(self.case.executor.verified,[(B,)])

    def test_later_unknown_withdrawal_fences_prior_generation_without_freeing_it(self):
        self.assertEqual(self.update()[0],200)
        local,_,held=self.claimed()
        self.g["agreement"]["generation"]+=2
        self.g["agreement"]["consent_id"]="22345678-1234-4234-8234-123456789abc"
        self.assertEqual(self.update("withdraw")[0],200)
        self.assertFalse(self.call("check",held,partitions=True)[1]["authorized"])
        self.assertTrue(self.call("inspect",held,partitions=True)[1]["held"])
        self.assertEqual(self.case.executor.verified,[])
        self.assertEqual(self.s.get(local["id"])["state"],"active")

    def test_update_expiry_rollback_commits_closure_and_failed_commit_installs_nothing(self):
        self.assertEqual(self.update()[0],200)
        self.ns+=31_000_000_000
        self.assertEqual(self.update()[1]["error"]["code"],"partition_policy_expired")
        with self.s.store.connection() as db:
            self.assertTrue(json.loads(db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()[0])["closed"])
        self.assertEqual(self.update()[1]["error"]["code"],"stale_partition_session")
        self.assertEqual(self.call("offers",{},partitions=True)[1],{"offers":[]})
        advance=self.s.store.fence.advance
        def interrupted(db):
            advance(db)
            row=db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()
            if row and json.loads(row[0])["stream_epoch"]==2:
                raise RuntimeError("synthetic policy write after registry advance before SQLite commit")
        self.s.store.fence.advance=interrupted
        self.assertEqual(self.update(epoch=2)[0],500)
        self.assertIsNone(self.policy.live)
        self.s.store.fence.advance=advance
        self.assertEqual(self.call("offers",{},partitions=True)[1]["error"]["code"],"authority_continuity_lost")

    def test_discarded_positive_state_cannot_reopen_expired_stream(self):
        self.assertEqual(self.update()[0],200)
        self.local_images=[]
        self.assertEqual(self.call("offers",{},partitions=True)[1],{"offers":[]})
        self.assertIsNone(self.policy.live)
        self.ns+=31_000_000_000
        # Owning negative control removes EXPIRY_FENCE only. Then this fresh
        # update wrongly returns200 despite no current session permission.
        status,result=self.update()
        self.assertEqual((status,result.get("error",{}).get("code")),(403,"partition_policy_expired"))
        self.assertEqual(self.call("offers",{},partitions=True)[1],{"offers":[]})
        self.assertEqual(self.update()[1]["error"]["code"],"stale_partition_session")
        self.assertEqual(self.update(epoch=2)[0],200)
        self.assertEqual(self.call("claim",self.case.request(),partitions=True)[1]["error"]["code"],"workload_not_permitted")

    def test_failed_expiry_commit_cannot_reopen_same_stream(self):
        self.assertEqual(self.update()[0],200)
        self.ns+=31_000_000_000
        advance=self.s.store.fence.advance
        def refuse_closure_before_registry(db):
            row=db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()
            if row and json.loads(row[0])["closed"]:
                raise RuntimeError("synthetic failure before registry advance")
            advance(db)
        self.s.store.fence.advance=refuse_closure_before_registry
        self.assertEqual(self.update()[0],500)
        self.s.store.fence.advance=advance
        with self.s.store.connection() as db:
            self.assertFalse(json.loads(db.execute("SELECT value FROM meta WHERE key='partition_policy_scope'").fetchone()[0])["closed"])
        self.assertIsNone(self.policy.live)
        self.assertEqual(self.update()[1]["error"]["code"],"stale_partition_session")
        self.assertEqual(self.call("offers",{},partitions=True)[1],{"offers":[]})
        self.assertEqual(self.update(epoch=2)[0],200)


if __name__ == "__main__": unittest.main()
