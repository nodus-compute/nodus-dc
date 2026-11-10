"""An actual offline wheel install, activation and safe uninstall in temp dirs."""
import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest

from nodus_dc import __version__
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock

ROOT = Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
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
