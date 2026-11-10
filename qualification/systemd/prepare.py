#!/usr/bin/env python3
"""Build only the frozen public candidate and compare exact reviewed artifacts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import shutil

from verify_agent import fetch
import zipfile


def legacy_inputs(output, bindings, local_assets=None):
    legacy = bindings["legacy"]
    observed = {}
    for key in ("wheel", "sdist"):
        path = output / legacy[key]
        if local_assets:
            shutil.copyfile(local_assets / legacy[key], path)
        else:
            fetch(legacy["release_url"] + legacy[key], path, 4 << 20)
        observed[key] = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed[key] != legacy[key + "_sha256"]:
            raise RuntimeError("public legacy artifact differs from frozen bytes")
    with tarfile.open(output / legacy["sdist"], "r:gz") as archive:
        member = archive.getmember("nodus_datacenter-0.1.0.dev1/tools/install.py")
        if not member.isfile() or member.size > 128 << 10:
            raise RuntimeError("unexpected legacy installer archive member")
        raw = archive.extractfile(member).read()
    observed["installer"] = hashlib.sha256(raw).hexdigest()
    if observed["installer"] != legacy["installer_sha256"]:
        raise RuntimeError("legacy installer differs from reviewed bytes")
    (output / "legacy-install.py").write_bytes(raw)
    return observed


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--legacy-assets", type=Path, help="optional local exact public artifacts for offline preparation checks")
    args = p.parse_args()
    bindings = json.loads(Path(__file__).with_name("bindings.json").read_text())
    revision = subprocess.check_output(["git", "-C", str(args.candidate), "rev-parse", "HEAD"], text=True).strip()
    if revision != bindings["source_commit"]:
        raise SystemExit("candidate checkout differs from reviewed source")
    if hashlib.sha256((args.candidate / "tools/install.py").read_bytes()).hexdigest() != bindings["candidate_installer_sha256"]:
        raise SystemExit("candidate installer differs from reviewed compatibility fix")
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("frozen_nodus_build", args.candidate / "build_backend.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build_wheel(str(args.output))
    module.build_sdist(str(args.output))
    for name, expected in bindings["artifacts"].items():
        if hashlib.sha256((args.output / name).read_bytes()).hexdigest() != expected:
            raise SystemExit("built artifact differs from reviewed bytes: " + name)
    with zipfile.ZipFile(args.output / bindings["wheel"]) as wheel:
        for source, expected in bindings["module_sha256"].items():
            if hashlib.sha256(wheel.read(source)).hexdigest() != expected:
                raise SystemExit("packaged module differs from independent review")
    legacy = legacy_inputs(args.output, bindings, args.legacy_assets)
    result = {"legacy_inputs_sha256": legacy, "candidate_installer_sha256": bindings["candidate_installer_sha256"],
              "source_commit": revision, "artifacts": bindings["artifacts"], "built_equal_reviewed": True,
              "systemd_executed": False, "gpu_qualified": False}
    (args.output / "artifact-rebuild.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
