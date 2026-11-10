"""An actual offline wheel install, activation and safe uninstall in temp dirs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

from nodus_dc import __version__
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend, Clock

ROOT = Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
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
