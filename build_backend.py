"""Small deterministic PEP 517 build backend using only the Python stdlib."""
import base64
import csv
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
NAME = "nodus_datacenter"
VERSION = "0.1.0.dev5"
DIST = f"{NAME}-{VERSION}.dist-info"
METADATA = f"""Metadata-Version: 2.1
Name: nodus-datacenter
Version: {VERSION}
Summary: Local GPU allocation and explicit capacity lending
Requires-Python: >=3.11
License: Apache-2.0
"""


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    files = {str(p.relative_to(ROOT / "src")): p.read_bytes()
             for p in sorted((ROOT / "src").rglob("*.py"))}
    files.update({f"{DIST}/METADATA": METADATA.encode(),
                  f"{DIST}/WHEEL": b"Wheel-Version: 1.0\nGenerator: nodus-stdlib-build\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                  f"{DIST}/entry_points.txt": b"[console_scripts]\nnodus-dc = nodus_dc.cli:main\n",
                  f"{DIST}/LICENSE": (ROOT / "LICENSE").read_bytes(),
                  f"{DIST}/PROVENANCE.json": (ROOT / "PROVENANCE.json").read_bytes()})
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for path, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow((path, "sha256=" + digest, len(content)))
    writer.writerow((f"{DIST}/RECORD", "", ""))
    files[f"{DIST}/RECORD"] = record.getvalue().encode()
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    target = Path(wheel_directory)
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target / filename, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path, content in sorted(files.items()):
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, content)
    return filename


def build_sdist(sdist_directory, config_settings=None):
    filename = f"{NAME}-{VERSION}.tar.gz"
    target = Path(sdist_directory)
    target.mkdir(parents=True, exist_ok=True)
    paths = [ROOT / n for n in ("pyproject.toml", "build_backend.py", "LICENSE", "README.md", "PROVENANCE.json")]
    paths += [p for folder in ("src", "tools", "docs", "examples", "tests", "kubernetes")
              for p in (ROOT / folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    models = ROOT / "verification" / "models"
    paths += [models / n for n in ("README.md", "mapping.md", "source-mapping.json", "checker.py",
              "allocation.py", "reclaim.py", "financial.py", "integrated.py", "native_handback.py",
              "native_handback_recovery.py", "run_models.py", "run_native_recovery.py")]
    # Only checked reference runs ship; local operator results may contain private paths.
    paths += [p for run in ("core-v1", "native-return-v1")
              for p in (models / "reference-results" / run).rglob("*")
              if p.is_file() and "__pycache__" not in p.parts]
    with open(target / filename, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for path in sorted(set(paths)):
                content = path.read_bytes()
                info = tarfile.TarInfo(f"{NAME}-{VERSION}/" + str(path.relative_to(ROOT)))
                info.size, info.mode, info.mtime = len(content), 0o644, 0
                tar.addfile(info, io.BytesIO(content))
    return filename


if __name__ == "__main__":
    print(build_wheel(str(ROOT / "dist")))
    print(build_sdist(str(ROOT / "dist")))
