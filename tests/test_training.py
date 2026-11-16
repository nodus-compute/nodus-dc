"""Checkpoint storage/admission controls. Synthetic GPUs; no hardware claim."""
from concurrent.futures import ThreadPoolExecutor
import copy
from pathlib import Path
import tempfile
import unittest

from nodus_dc.backend import NvidiaDockerBackend
from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from nodus_dc.training import build_workload
from nodus_dc.workload_io import output_directory
from tests.test_authority import Backend, Clock
from tests.test_backend import Commands, IMAGE


class TrainingBackend(Backend):
    def validate_workload(self, workload, lease):
        NvidiaDockerBackend(host_id="fixture").validate_workload(workload, lease)


class TrainingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.code = self.root / "code"
        self.code.mkdir(mode=0o700)
        (self.code / "train.py").write_text("print('fixture')\n")
        self.output = self.root / "output"
        self.output.mkdir(mode=0o700)

    def workload(self, output=None):
        return build_workload(IMAGE, self.code, "train.py", output or self.output,
                              arguments=["--run-name", "spaces; $() stay one argument"])

    def test_descriptor_launch_and_cleanup_preserve_checkpoint(self):
        commands = Commands()
        backend = NvidiaDockerBackend(command=commands, clock=lambda: 1000,
                                      host_id="host-a", allocation_authority="standalone")
        workload = self.workload()
        lease = {"id": "lease-a", "generation": 1, "mode": "exclusive_gpu", "resources": ["GPU-aaaa"],
                 "baseline": [r.record() for r in backend.inventory().resources], "workload": workload}
        lease["runtime"] = backend.start(lease)
        create = next(args for args in commands.calls if args[:2] == ["docker", "create"])
        self.assertIn(f"type=bind,src={self.code},dst=/code,readonly", create)
        self.assertIn(f"type=bind,src={self.output},dst=/outputs", create)
        self.assertEqual(create[create.index("--network") + 1], "none")
        self.assertEqual(create[-len(workload["command"]):], workload["command"])
        checkpoint = self.output / "checkpoint.pt"
        checkpoint.write_bytes(b"retained operator checkpoint fixture")
        self.assertTrue(backend.cleanup(lease).clean)
        self.assertEqual(checkpoint.read_bytes(), b"retained operator checkpoint fixture")
        self.assertFalse(any("pull" in args for args in commands.calls))

    def test_private_canonical_output_and_input_separation(self):
        alias = self.root / "alias"
        alias.symlink_to(self.output, target_is_directory=True)
        self.output.chmod(0o755)
        for path in (self.output, alias, self.root / "missing", "/", "relative", self.code / "train.py"):
            with self.subTest(path=path), self.assertRaises(Error):
                output_directory(str(path))
        self.output.chmod(0o700)
        self.assertEqual(output_directory(str(self.output)), self.output)
        with self.assertRaises(Error):
            self.workload(output=self.code)
        self.root.chmod(0o777)
        try:
            with self.assertRaises(Error):
                self.workload()
        finally:
            self.root.chmod(0o700)
        external = self.root / "outside.py"
        external.write_text("not part of the code directory")
        (self.code / "escape.py").symlink_to(external)
        with self.assertRaises(Error):
            build_workload(IMAGE, self.code, "escape.py", self.output)

    def test_output_revalidated_after_descriptor_before_docker_create(self):
        workload = self.workload()
        self.output.rename(self.root / "original")
        self.output.symlink_to(self.root / "original", target_is_directory=True)
        commands = Commands()
        backend = NvidiaDockerBackend(command=commands, host_id="fixture")
        with self.assertRaises(Error):
            backend._launch_container({"id": "lease", "generation": 1, "resources": ["GPU-a"]}, workload, ["GPU-a"])
        self.assertEqual(commands.calls, [])

    def test_concurrent_jobs_cannot_share_checkpoints_and_quarantine_keeps_claim(self):
        clock = Clock()
        backend = TrainingBackend(clock)
        state = self.root / "state" / "authority.sqlite3"
        service = Service(Store(state), backend, clock=clock)
        first = service.reserve(resources=["MIG-aaaa"], mode="hardware_partition", expires_at=1100, request_key="first")
        second = service.reserve(resources=["MIG-bbbb"], mode="hardware_partition", expires_at=1100, request_key="second")
        def start(lease):
            try:
                service.start(lease["id"], generation=lease["generation"], request_key="start-" + lease["id"], workload=self.workload())
                return "started"
            except Error as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(start, [first, second]))
        self.assertEqual(sorted(results), ["output_directory_conflict", "started"])
        winner, loser = (first, second) if results[0] == "started" else (second, first)
        with service.store.transaction(clock()) as db:
            Store.update(db, Store.lease(db, winner["id"]), clock(), state="quarantined")
        self.assertEqual(start(loser), "output_directory_conflict")
        # Even an idle GPU cannot turn an unverified output owner into a free directory.
        self.assertEqual(len(backend.running), 1)

    def test_custom_authority_state_cannot_be_mounted_writable(self):
        clock = Clock()
        service = Service(Store(self.output / "authority.sqlite3"), TrainingBackend(clock), clock=clock)
        lease = service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key="lease")
        with self.assertRaises(Error) as raised:
            service.start(lease["id"], generation=lease["generation"], request_key="start", workload=self.workload())
        self.assertEqual(raised.exception.code, "output_directory_conflict")
        with service.store.connection() as db:
            self.assertEqual(Store.lease(db, lease["id"])["state"], "reserved")

    def test_writer_reader_conflict_in_both_orders_and_reuse_after_release(self):
        writer = self.workload()
        reader = self.workload()
        del reader["output_directory"]
        reader["mounts"].append({"source": str(self.output), "target": "/data"})
        for index, workloads in enumerate(((writer, reader), (reader, writer))):
            with self.subTest(writer_first=index == 0):
                clock, backend = Clock(), TrainingBackend(Clock())
                service = Service(Store(self.root / f"state-{index}" / "authority.sqlite3"), backend, clock=clock)
                leases = [service.reserve(resources=[resource], mode="hardware_partition",
                          expires_at=1100, request_key=resource) for resource in ("MIG-aaaa", "MIG-bbbb")]
                for lease, workload in zip(leases[:1], workloads[:1]):
                    service.start(lease["id"], generation=lease["generation"], request_key="start-first", workload=workload)
                second = leases[1]
                with self.assertRaises(Error) as raised:
                    service.start(second["id"], generation=second["generation"], request_key="start-second", workload=workloads[1])
                self.assertEqual(raised.exception.code, "output_directory_conflict")
                self.assertEqual(len(backend.running), 1)
                first = leases[0]
                service.release(first["id"], generation=first["generation"], request_key="release-first")
                service.start(second["id"], generation=second["generation"], request_key="start-second", workload=workloads[1])
                self.assertEqual(set(backend.running), {second["id"]})

    def test_mps_clients_need_disjoint_output_directories(self):
        backend = NvidiaDockerBackend(host_id="fixture", enable_trusted_mps=True)
        client = {"workload": self.workload(), "active_thread_percent": 50, "memory_mib": 1024}
        workload = {"controller_image": IMAGE, "trust_domain": "owner-team", "clients": [client, copy.deepcopy(client)]}
        lease = {"mode": "trusted_mps", "resources": ["GPU-a"], "baseline": [
            {"id": "GPU-a", "kind": "gpu", "modes": ["trusted_mps"], "memory_bytes": 40 * 1024**3}]}
        with self.assertRaises(Error) as raised:
            backend.validate_workload(workload, lease)
        self.assertEqual(raised.exception.code, "output_directory_conflict")
        second = self.root / "output-2"
        second.mkdir(mode=0o700)
        workload["clients"][1]["workload"] = self.workload(second)
        backend.validate_workload(workload, lease)


if __name__ == "__main__":
    unittest.main()
