"""Explicit recovery installation keeps real SQLite ownership unchanged."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery_installer", ROOT / "tools/install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class RecoveryInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.clock = Clock()
        self.backend = Backend(self.clock)
        self.service = Service(Store(self.state / "authority.sqlite3"), self.backend, clock=self.clock)

    def tearDown(self):
        self.tmp.cleanup()

    def quarantine(self):
        lease = self.service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=1100, request_key="lease")
        self.backend.start_error = RuntimeError("synthetic unknown start")
        with self.assertRaises(Error):
            self.service.start(lease["id"], generation=lease["generation"], request_key="start", workload={"test_workload": True})
        return self.service.get(lease["id"])

    def snapshot(self):
        with sqlite3.connect(self.state / "authority.sqlite3") as db:
            return list(db.iterdump())

    def test_optin_preserves_quarantine_and_existing_normal_install_remains_strict(self):
        lease = self.quarantine()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "must be cleanly released"):
            installer.lock_state(self.state)
        handles = installer.lock_state(self.state, recovery_upgrade=True)
        try:
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.service.get(lease["id"])["state"], "quarantined")
        finally:
            for handle in handles:
                handle.close()

    def test_active_external_native_terminal_and_empty_states_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, "requires a quarantined allocation"):
            installer.lock_state(self.state, recovery_upgrade=True)
        lease = self.quarantine()
        # Deliberately malformed/other-owner fixtures, never a production repair.
        cases = [("UPDATE leases SET state='active'",),
                 ("UPDATE leases SET state='reserved'",),
                 ("UPDATE leases SET owner='external'",),
                 ("UPDATE leases SET runtime=?", json.dumps({"execution_kind": "native_handoff"})),
                 ("INSERT INTO meta VALUES('terminal_native_handback','{}')",)]
        for statement in cases:
            with self.subTest(statement=statement[0]):
                with sqlite3.connect(self.state / "authority.sqlite3") as db:
                    db.execute("UPDATE leases SET state='quarantined', owner='local', runtime=NULL")
                    db.execute("DELETE FROM meta WHERE key='terminal_native_handback'")
                    db.execute(statement[0], statement[1:])
                before = self.snapshot()
                with self.assertRaisesRegex(RuntimeError, "only quarantined local non-native"):
                    installer.lock_state(self.state, recovery_upgrade=True)
                self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.service.get(lease["id"])["generation"], lease["generation"])

    def test_daemon_lock_and_uninstall_or_activate_abuse_are_refused(self):
        self.quarantine()
        with (self.state / "daemon.lock").open("a") as daemon:
            fcntl.flock(daemon, fcntl.LOCK_EX)
            with self.assertRaisesRegex(RuntimeError, "stop the daemon"):
                installer.lock_state(self.state, recovery_upgrade=True)
        for action in ("activate", "uninstall"):
            with self.assertRaisesRegex(RuntimeError, "available only for install"):
                installer.main([action, "--prefix", str(self.root / "install"), "--state-dir", str(self.state), "--recovery-upgrade"])

    def test_actual_offline_wheel_protocol_and_interrupted_activation(self):
        old_path = os.environ.get("NODUS_RECOVERY_LEGACY_WHEEL")
        if not old_path:
            self.skipTest("provide immutable published dev3 wheel offline for recovery-upgrade artifact verification")
        old = Path(old_path).resolve()
        self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(), "0237fca79edb80250c7ca17f5a9fd90cb4cba92d9b89f4d92dd0b79b73ae7ec2")
        buildspec = importlib.util.spec_from_file_location("recovery_build", ROOT / "build_backend.py")
        builder = importlib.util.module_from_spec(buildspec)
        buildspec.loader.exec_module(builder)
        wheel = self.root / "wheels" / builder.build_wheel(self.root / "wheels")
        prefix = self.root / "install"
        common = ["install", "--prefix", str(prefix), "--state-dir", str(self.state)]
        self.assertEqual(installer.main([*common, "--wheel", str(old)]), 0)
        lease = self.quarantine()
        before = self.snapshot()
        link = os.readlink(prefix / "current")
        manifest = (prefix / "installation.json").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "required recovery protocol"):
            installer.main([*common, "--wheel", str(old), "--recovery-upgrade"])
        self.assertEqual(os.readlink(prefix / "current"), link)
        self.assertEqual((prefix / "installation.json").read_bytes(), manifest)
        self.assertEqual(self.snapshot(), before)
        with patch.object(installer, "finish_activation", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                installer.main([*common, "--wheel", str(wheel), "--recovery-upgrade"])
        pending = json.loads((prefix / "installation.json").read_text())["pending"]
        self.assertTrue(pending["recovery_upgrade"])
        self.assertEqual(os.readlink(prefix / "current"), link)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(installer.main([*common, "--wheel", str(wheel), "--recovery-upgrade"]), 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.service.get(lease["id"])["state"], "quarantined")
        env = {k:v for k,v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"}}
        check = subprocess.run([str(prefix / "current/bin/python"), "-I", "-c",
                                "from nodus_dc.service import RECOVERY_UPGRADE_PROTOCOL; assert RECOVERY_UPGRADE_PROTOCOL == 1"], env=env)
        self.assertEqual(check.returncode, 0)


if __name__ == "__main__":
    unittest.main()
