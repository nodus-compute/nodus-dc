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

# Shape captured from a real H100/580.105.08; identifiers are synthetic.
MIG_DEVICES = """<mig_devices>
<mig_device><index>0</index><gpu_instance_id>1</gpu_instance_id><compute_instance_id>0</compute_instance_id>
<fb_memory_usage><total>40448 MiB</total><used>376 MiB</used></fb_memory_usage></mig_device>
<mig_device><index>1</index><gpu_instance_id>2</gpu_instance_id><compute_instance_id>0</compute_instance_id>
<fb_memory_usage><total>40448 MiB</total><used>44 MiB</used></fb_memory_usage></mig_device>
</mig_devices>"""
MIG_PROCESS = """<process_info><gpu_instance_id>1</gpu_instance_id><compute_instance_id>0</compute_instance_id>
<pid>4174</pid><type>C</type><process_name>/probe/cuda_probe</process_name></process_info>"""


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
        for content in ("N/A", "Not Supported", "Unknown", "<unknown_process/>"):
            self.cmd.xml = XML.replace("<processes></processes>", "<processes>" + content + "</processes>")
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

    def mig_fixture(self, *, process=True):
        self.cmd.xml = XML.replace("Disabled", "Enabled").replace("</gpu>", MIG_DEVICES + "</gpu>")
        if process:
            self.cmd.xml = self.cmd.xml.replace("<processes></processes>", "<processes>" + MIG_PROCESS + "</processes>")
        self.cmd.listing += "\n  MIG 3g.40gb Device 0: (UUID: MIG-first)\n  MIG 3g.40gb Device 1: (UUID: MIG-second)"

    def assign(self, device):
        self.cmd.containers = [{"Id": "foreign-first", "HostConfig": {"DeviceRequests": [{"Driver": "nvidia",
            "Capabilities": [["gpu"]], "DeviceIDs": [device] if device else []}]}}]

    def test_mig_process_and_container_do_not_block_distinct_gpu_instance(self):
        self.mig_fixture()
        self.assign("MIG-first")
        rows = {r.id: r for r in self.backend.inventory().resources}
        self.assertTrue(rows["GPU-aaaa"].busy)
        self.assertTrue(rows["MIG-first"].busy)
        self.assertFalse(rows["MIG-second"].busy)
        self.assertEqual(rows["MIG-first"].details["process_ids"], ["4174"])
        self.assertEqual(rows["MIG-second"].details["gpu_instance_id"], 2)
        self.assertEqual(rows["MIG-second"].details["memory_capacity_bytes"], 40448 * 2**20)
        lease = self.lease("hardware_partition")
        lease["resources"] = ["MIG-second"]
        self.backend.start(lease)
        create = next(c for c in self.cmd.calls if c[:2] == ["docker", "create"])
        self.assertEqual(create[create.index("--gpus") + 1], '\"device=MIG-second\"')

    def test_idle_assigned_partition_still_excludes_itself_and_parent(self):
        self.mig_fixture(process=False)
        self.assign("MIG-first")
        rows = {r.id: r for r in self.backend.inventory().resources}
        self.assertTrue(rows["GPU-aaaa"].busy)
        self.assertTrue(rows["MIG-first"].busy)
        self.assertFalse(rows["MIG-second"].busy)

    def test_mig_unknown_process_or_ambiguous_mapping_retains_parent_scope(self):
        self.mig_fixture()
        original = self.cmd.xml
        mutations = [
            ("<gpu_instance_id>1</gpu_instance_id><compute_instance_id>0</compute_instance_id>\n<pid>",
             "<gpu_instance_id>N/A</gpu_instance_id><compute_instance_id>0</compute_instance_id>\n<pid>"),
            ("<index>1</index>", "<index>0</index>"),
            ("<gpu_instance_id>2</gpu_instance_id>", "<gpu_instance_id>1</gpu_instance_id>"),
            ("<index>1</index>", "<index>9</index>"),
        ]
        for before, after in mutations:
            with self.subTest(after=after):
                self.cmd.xml = original.replace(before, after)
                rows = {r.id: r for r in self.backend.inventory().resources}
                self.assertTrue(rows["MIG-second"].busy)
                self.assertEqual(rows["MIG-second"].details["process_inventory_scope"], "conservative_parent_gpu")

    def test_shared_gpu_instance_container_cannot_open_an_idle_sibling(self):
        self.mig_fixture(process=False)
        self.cmd.xml = self.cmd.xml.replace(
            "<gpu_instance_id>2</gpu_instance_id><compute_instance_id>0</compute_instance_id>",
            "<gpu_instance_id>1</gpu_instance_id><compute_instance_id>1</compute_instance_id>")
        self.assign("MIG-first")
        self.assertTrue(next(r for r in self.backend.inventory().resources if r.id == "MIG-second").busy)

    def test_whole_gpu_and_unknown_assignments_block_all_mig_children(self):
        self.mig_fixture(process=False)
        for device in ("GPU-aaaa", "0", "MIG-unknown", None):
            with self.subTest(device=device):
                self.assign(device)
                self.assertTrue(all(r.busy for r in self.backend.inventory().resources))

    def test_numeric_docker_gpu_uses_driver_index_not_xml_order(self):
        self.cmd.listing = "GPU 7: Fixture GPU (UUID: GPU-aaaa)"
        self.assign("7")
        self.assertTrue(self.backend.inventory().resources[1].busy)

    def test_missing_or_unrecognized_listing_cannot_report_clean_geometry(self):
        self.mig_fixture(process=False)
        original = self.cmd.listing
        for listing in ("", original.splitlines()[0], original.replace("Device 1:", "Unknown 1:"),
                        "\n".join(original.splitlines()[:-1])):
            with self.subTest(listing=listing):
                self.cmd.listing = listing
                snapshot = self.backend.inventory()
                self.assertTrue(snapshot.warnings)
                self.assertFalse(snapshot.resources[0].healthy)
                self.assertTrue(all(not r.healthy for r in snapshot.resources if r.kind == "gpu"))

    def test_legacy_nvidia_runtime_blocks_idle_gpu_even_without_device_requests(self):
        self.mig_fixture(process=False)
        self.cmd.containers = [{"Id": "legacy", "HostConfig": {"Runtime": "nvidia", "DeviceRequests": []},
                                "Config": {"Env": ["NVIDIA_VISIBLE_DEVICES=MIG-first"]}}]
        self.assertTrue(all(r.busy for r in self.backend.inventory().resources))
        self.assign("MIG-first")
        self.cmd.containers[0]["HostConfig"]["Runtime"] = "nvidia"
        self.assertFalse(next(r for r in self.backend.inventory().resources if r.id == "MIG-second").busy)

    def partition_recovery_fixture(self):
        self.backend.boot_id = lambda: "old-boot"
        self.mig_fixture(process=False)
        self.cmd.xml = self.cmd.xml.replace("</gpu>", "<pci><pci_bus_id>0000:01:00.0</pci_bus_id></pci></gpu>")
        lease = self.lease("hardware_partition")
        lease.update(owner="local", resources=["MIG-second"])
        self.backend.boot_id = lambda: "new-boot"
        # Hopper's pre-reboot MIG UUIDs no longer exist.
        self.cmd.xml = XML.replace("</gpu>", "<pci><pci_bus_id>0000:01:00.0</pci_bus_id></pci></gpu>")
        self.cmd.listing = "GPU 0: Fixture GPU (UUID: GPU-aaaa)"
        return lease

    def test_reboot_recovery_retires_missing_partition_without_rewriting_baseline(self):
        lease = self.partition_recovery_fixture()
        original = canonical(lease)
        proof = self.backend.recover_partition(lease, "old-boot", "new-boot")
        self.assertTrue(proof.clean)
        self.assertEqual(proof.resource_ids, ("MIG-second",))
        self.assertEqual(proof.evidence["retired_partition_leases"], ["MIG-second"])
        self.assertEqual(canonical(lease), original)
        self.assertFalse(any(c[0] == "nvidia-smi" and "-mig" in c for c in self.cmd.calls))

    def test_partition_recovery_requires_actual_distinct_boot_and_original_host(self):
        lease = self.partition_recovery_fixture()
        for previous, current in (("new-boot", "new-boot"), ("old-boot", "pretend-boot"), ("wrong-old", "new-boot")):
            with self.subTest(previous=previous, current=current), self.assertRaises(Error):
                self.backend.recover_partition(lease, previous, current)
        lease["baseline"] = [r for r in lease["baseline"] if r["kind"] != "host"]
        with self.assertRaises(Error):
            self.backend.recover_partition(lease, "old-boot", "new-boot")

    def test_partition_recovery_refuses_changed_or_busy_physical_gpu(self):
        lease = self.partition_recovery_fixture()
        xml = self.cmd.xml
        for before, after in (("580.test", "581.changed"), ("0000:01:00.0", "0000:02:00.0"),
                              ("81920 MiB", "40960 MiB"), ("<processes></processes>", "<processes>N/A</processes>"),
                              ("<processes></processes>", "<processes>" + MIG_PROCESS + "</processes>")):
            with self.subTest(after=after):
                self.cmd.xml = xml.replace(before, after)
                self.assertFalse(self.backend.recover_partition(lease, "old-boot", "new-boot").clean)
        self.cmd.xml = xml
        self.assign("GPU-aaaa")
        self.assertFalse(self.backend.recover_partition(lease, "old-boot", "new-boot").clean)
        self.assertFalse(any(c[:2] == ["docker", "rm"] for c in self.cmd.calls))

    def test_unknown_mig_mode_or_empty_geometry_shape_cannot_authorize_recovery(self):
        lease = self.partition_recovery_fixture()
        original = self.cmd.xml
        for mode, content in (("Unknown", "None"), ("Enabled", "Unknown"),
                              ("Enabled", "<unexpected_device/>"), ("N/A", "None")):
            with self.subTest(mode=mode, content=content):
                self.cmd.xml = original.replace("Disabled", mode).replace("</gpu>", "<mig_devices>" + content + "</mig_devices></gpu>")
                self.assertFalse(self.backend.recover_partition(lease, "old-boot", "new-boot").clean)
        # Exact driver spellings for empty geometry are supported.
        for mode in ("Enabled", "Disabled"):
            self.cmd.xml = original.replace("Disabled", mode).replace("</gpu>", "<mig_devices>None</mig_devices></gpu>")
            self.assertTrue(self.backend.recover_partition(lease, "old-boot", "new-boot").clean)

    def test_partition_recovery_removes_only_exact_generation_owned_container(self):
        lease = self.partition_recovery_fixture()
        self.cmd.containers = [{"Id": "owned", "Config": {"Labels": {LABEL+".lease": lease["id"],
            LABEL+".generation": "1", LABEL+".resources": canonical(lease["resources"])}}, "State": {"Running": False}}]
        self.assertTrue(self.backend.recover_partition(lease, "old-boot", "new-boot").clean)
        self.assertIn(["docker", "rm", "owned"], self.cmd.calls)
        self.cmd.containers = [{"Id": "forged", "Config": {"Labels": {LABEL+".lease": lease["id"],
            LABEL+".generation": "2", LABEL+".resources": canonical(lease["resources"])}}}]
        with self.assertRaises(Error):
            self.backend.recover_partition(lease, "old-boot", "new-boot")
        self.assertNotIn(["docker", "rm", "forged"], self.cmd.calls)

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
