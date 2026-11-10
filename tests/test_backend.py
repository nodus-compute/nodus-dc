"""Hardware adapter command/parse tests; no simulated result qualifies hardware."""
import json
import unittest
from dataclasses import replace

from nodus_dc.backend import LABEL, NvidiaDockerBackend
from nodus_dc.errors import Error
from nodus_dc.model import Resource, Snapshot, canonical
from nodus_dc.partitioning import configure_mig
from nodus_dc.sharing import validate_pool, remove_pool_volume

IMAGE = "example.invalid/model@sha256:" + "a" * 64
XML = """<nvidia_smi_log><driver_version>580.test</driver_version><gpu>
<uuid>GPU-aaaa</uuid><product_name>Fixture GPU</product_name>
<fb_memory_usage><total>81920 MiB</total></fb_memory_usage>
<mig_mode><current_mig>Disabled</current_mig></mig_mode>
<gpu_recovery_action>None</gpu_recovery_action><processes></processes>
</gpu></nvidia_smi_log>"""


class Commands:
    def __init__(self):
        self.calls = []
        self.containers = []
        self.xml = XML
        self.listing = "GPU 0: Fixture GPU (UUID: GPU-aaaa)"
        self.fail_docker = False
        self.volume_labels = {}

    def __call__(self, args, **kw):
        self.calls.append(args)
        if args == ["nvidia-smi", "-q", "-x"]:
            return self.xml
        if args == ["nvidia-smi", "-L"]:
            return self.listing
        if args[:2] == ["nvidia-smi", "--query-gpu=uuid,compute_cap"]:
            return "GPU-aaaa, 8.0"
        if args[:2] == ["docker", "ps"]:
            if self.fail_docker:
                raise Error("fixture_unavailable", "docker unavailable")
            return "\n".join(c["Id"] for c in self.containers)
        if args[:2] == ["docker", "inspect"]:
            return json.dumps(self.containers)
        if args[:3] == ["docker", "image", "inspect"]:
            return "[]"
        if args[:3] == ["docker", "volume", "ls"]:
            return "nodus-dc-1-mps"
        if args[:3] == ["docker", "volume", "inspect"]:
            return json.dumps([{"Labels": self.volume_labels}])
        if args[:2] == ["docker", "create"]:
            labels = {args[i+1].split("=", 1)[0]: args[i+1].split("=", 1)[1]
                      for i, a in enumerate(args) if a == "--label"}
            self.containers = [{"Id": "b"*64, "Config": {"Labels": labels}, "State": {"Running": True},
                                "HostConfig": {"DeviceRequests": []}}]
            return "b" * 64
        if args[:2] in [["docker", "start"], ["docker", "stop"]]:
            return ""
        if args[:2] == ["docker", "rm"]:
            self.containers = []
            return ""
        raise AssertionError("unhandled fixture command: " + repr(args))


class PoolCommands(Commands):
    def __init__(self):
        super().__init__()
        self.volume = None
        self.sequence = 0

    def __call__(self, args, **kw):
        if args[:2] == ["docker", "create"]:
            self.calls.append(args)
            labels = {args[i+1].split("=", 1)[0]: args[i+1].split("=", 1)[1]
                      for i, a in enumerate(args) if a == "--label"}
            self.sequence += 1
            identity = format(self.sequence, "064x")
            self.containers.append({"Id": identity, "Name": args[args.index("--name")+1], "Config": {"Labels": labels},
                                    "State": {"Running": True}, "HostConfig": {"DeviceRequests": []}})
            return identity
        if args[:2] == ["docker", "exec"]:
            self.calls.append(args)
            return ""
        if args[:2] == ["docker", "rm"]:
            self.calls.append(args)
            self.containers = [c for c in self.containers if c["Id"] != args[-1]]
            return ""
        if args[:3] == ["docker", "volume", "ls"]:
            self.calls.append(args)
            return self.volume or ""
        if args[:3] == ["docker", "volume", "create"]:
            self.calls.append(args)
            self.volume = args[-1]
            self.volume_labels = {args[i+1].split("=", 1)[0]: args[i+1].split("=", 1)[1]
                                  for i, a in enumerate(args) if a == "--label"}
            return self.volume
        if args[:3] == ["docker", "volume", "rm"]:
            self.calls.append(args)
            if self.containers:
                raise AssertionError("volume cleanup attempted before client/controller removal")
            self.volume = None
            return ""
        return super().__call__(args, **kw)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.cmd = Commands()
        self.backend = NvidiaDockerBackend(command=self.cmd, clock=lambda: 1000, host_id="host-a", allocation_authority="standalone")

    def lease(self, mode="exclusive_gpu"):
        return {"id": "lease-a", "generation": 1, "mode": mode, "resources": ["GPU-aaaa"],
                "baseline": [r.record() for r in self.backend.inventory().resources],
                "workload": {"image": IMAGE, "command": ["python", "model.py"], "entrypoint": "/usr/bin/env"}}

    def test_observe_mode_cannot_allocate_even_empty_hardware(self):
        self.backend.allocation_authority = "observe"
        self.assertTrue(all(not r.modes for r in self.backend.inventory().resources))

    def test_unobservable_processes_and_docker_fail_closed(self):
        self.cmd.xml = XML.replace("<processes></processes>", "<processes>N/A</processes>")
        self.assertFalse(self.backend.inventory().resources[1].healthy)
        self.cmd.xml = XML
        self.cmd.fail_docker = True
        self.assertTrue(self.backend.inventory().resources[1].busy)

    def test_idle_container_assignment_still_blocks_gpu(self):
        self.cmd.containers = [{"Id": "c", "HostConfig": {"DeviceRequests": [{"Driver": "nvidia",
            "Capabilities": [["gpu"]], "DeviceIDs": ["GPU-aaaa"]}]}}]
        gpu = self.backend.inventory().resources[1]
        self.assertTrue(gpu.busy)
        self.assertFalse(self.backend.host_ready_for_external())

    def test_existing_mig_exposes_whole_instances_and_no_whole_gpu_launch(self):
        self.cmd.xml = XML.replace("Disabled", "Enabled")
        self.cmd.listing += "\n  MIG 1g.10gb Device 0: (UUID: MIG-aaaa)"
        snapshot = self.backend.inventory()
        self.assertNotIn("exclusive_gpu", snapshot.resources[1].modes)
        self.assertEqual(snapshot.resources[2].modes, ("hardware_partition",))
        self.assertEqual(snapshot.resources[2].memory_bytes, 0)
        self.assertFalse(self.backend.host_ready_for_external())

    def test_launch_honors_entrypoint_and_exact_gpu_without_shell_or_pull(self):
        lease = self.lease()
        runtime = self.backend.start(lease)
        create = next(c for c in self.cmd.calls if c[:2] == ["docker", "create"])
        self.assertEqual(create[create.index("--entrypoint") + 1], "/usr/bin/env")
        self.assertEqual(create[create.index("--gpus") + 1], '"device=GPU-aaaa"')
        self.assertFalse(any("pull" in c for c in self.cmd.calls))
        lease["runtime"] = runtime
        self.assertTrue(self.backend.cleanup(lease).clean)

    def test_forged_container_generation_is_not_deleted(self):
        lease = self.lease()
        self.cmd.containers = [{"Id": "other", "Config": {"Labels": {LABEL+".lease": lease["id"],
            LABEL+".generation": "2", LABEL+".resources": canonical(lease["resources"])}}}]
        with self.assertRaises(Error):
            self.backend.cleanup(lease)
        self.assertFalse(any(c[:2] == ["docker", "rm"] for c in self.cmd.calls))

    def test_mps_capacity_and_explicit_trust_are_required(self):
        self.backend.enable_trusted_mps = True
        lease = self.lease("trusted_mps")
        client = {"workload": {"image": IMAGE, "command": ["model"]}, "active_thread_percent": 50, "memory_mib": 30000}
        pool = {"trust_domain": "team-a", "controller_image": IMAGE, "clients": [client, dict(client)]}
        validate_pool(self.backend, pool, lease)
        pool["clients"][1]["active_thread_percent"] = 51
        with self.assertRaises(Error):
            validate_pool(self.backend, pool, lease)
        self.backend.enable_trusted_mps = False
        with self.assertRaises(Error):
            validate_pool(self.backend, pool, lease)

    def test_mps_foreign_volume_never_deleted(self):
        with self.assertRaises(Error):
            remove_pool_volume(self.backend, self.lease())
        self.assertFalse(any(c[:3] == ["docker", "volume", "rm"] for c in self.cmd.calls))

    def test_mps_pool_starts_all_clients_and_cleans_clients_before_controller(self):
        commands = PoolCommands()
        self.backend.command = commands
        self.backend.enable_trusted_mps = True
        lease = self.lease("trusted_mps")
        client = {"workload": {"image": IMAGE, "command": ["model"]}, "active_thread_percent": 50, "memory_mib": 30000}
        lease["workload"] = {"trust_domain": "team-a", "controller_image": IMAGE, "clients": [client, dict(client)]}
        runtime = self.backend.start(lease)
        self.assertEqual(len(runtime["client_ids"]), 2)
        self.assertEqual(runtime["isolation"], "trusted_cooperative_only")
        self.assertFalse(runtime["hardware_qualified"])
        creates = [c for c in commands.calls if c[:2] == ["docker", "create"]]
        for create in creates[1:]:
            self.assertIn("CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=50", create)
            self.assertIn("CUDA_MPS_PINNED_DEVICE_MEM_LIMIT=0=30000M", create)
            self.assertIn("container:"+runtime["controller_id"], create)
        lease["runtime"] = runtime
        self.assertTrue(self.backend.cleanup(lease).clean)
        stops = [c[-1] for c in commands.calls if c[:2] == ["docker", "stop"]]
        self.assertEqual(stops, [*runtime["client_ids"], runtime["controller_id"]])
        self.assertIsNone(commands.volume)

    def test_mig_configuration_never_targets_other_gpu_or_uses_reset(self):
        gpu = Resource("GPU-aaaa", "gpu", "host-a", "GPU-aaaa", modes=("gpu_configuration",), healthy=True,
                       details={"mig_mode": "Disabled"})
        after_gpu = replace(gpu, details={"mig_mode": "Enabled"})
        child = Resource("MIG-aaaa", "partition", "GPU-aaaa", "MIG-aaaa", healthy=True, details={"profile": "1g.10gb"})
        snapshots = iter([Snapshot("host-a", 1000, (gpu,)), Snapshot("host-a", 1000, (after_gpu, child))])
        self.backend.inventory = lambda: next(snapshots)
        calls = []
        self.backend.command = lambda args, **kw: calls.append(args) or ""
        configure_mig(self.backend, {"mode": "gpu_configuration", "resources": ["GPU-aaaa"]},
                      {"enabled": True, "profiles": ["1g.10gb"]})
        self.assertEqual(calls, [["nvidia-smi", "-i", "GPU-aaaa", "-mig", "1"],
                                ["nvidia-smi", "mig", "-i", "GPU-aaaa", "-cgi", "1g.10gb", "-C"]])

    def test_unverified_mig_configuration_is_not_success(self):
        lease = self.lease("gpu_configuration")
        self.backend.command = lambda args, **kw: ""
        original = self.backend.inventory
        self.backend.inventory = lambda: Snapshot("host-a", 1000, (Resource("GPU-aaaa", "gpu", "host-a",
            modes=("gpu_configuration",), healthy=True, details={"mig_mode": "Disabled"}),))
        with self.assertRaises(Error) as ctx:
            configure_mig(self.backend, lease, {"enabled": True, "profiles": ["1g.10gb"]})
        self.assertEqual(ctx.exception.code, "mig_configuration_unverified")


if __name__ == "__main__":
    unittest.main()
