#!/usr/bin/env python3
"""Validate the probe's public build inputs and anonymous-pull descriptor; no network or credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/nodus-compute/nodus-dc-probe"
SOURCE = "https://github.com/nodus-compute/nodus-dc"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs():
    value = json.loads((ROOT / "probe/build-inputs.json").read_text())
    assert value["schemaVersion"] == 1 and value["platform"] == "linux/amd64"
    assert value["image"] == IMAGE and value["release"] == "cuda-probe-v1"
    assert value["license"] == "Apache-2.0" and value["sourceSHA256"] == sha(ROOT / "probe/probe.c")
    dockerfile = (ROOT / "probe/Dockerfile").read_text()
    for field, suffix in (("builder", " AS build"), ("runtime", "")):
        assert re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", value[field])
        assert "FROM " + value[field] + suffix in dockerfile.splitlines()
    return value


def descriptor(revision, metadata, inspection):
    value = inputs()
    assert re.fullmatch(r"[0-9a-f]{40}", revision)
    digest = metadata["containerimage.digest"]
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    assert len(inspection) == 1
    image = inspection[0]
    assert IMAGE + "@" + digest in image["RepoDigests"]
    assert image["Os"] == "linux" and image["Architecture"] == "amd64"
    config = image["Config"]
    assert config["User"] == "65534:65534" and config["Entrypoint"] == ["/usr/local/bin/nodus-probe"]
    assert config.get("Cmd") in (None, [])
    labels = config["Labels"]
    assert labels["org.opencontainers.image.source"] == SOURCE
    assert labels["org.opencontainers.image.revision"] == revision
    assert labels["org.opencontainers.image.licenses"] == "Apache-2.0"
    return {"schemaVersion": 1, "image": IMAGE, "digest": digest, "platform": value["platform"],
            "sourceRepository": SOURCE, "sourceCommit": revision, "sourceSHA256": value["sourceSHA256"],
            "dockerfileSHA256": sha(ROOT / "probe/Dockerfile"),
            "buildInputsSHA256": sha(ROOT / "probe/build-inputs.json"),
            "builder": value["builder"], "runtime": value["runtime"], "license": value["license"],
            "anonymousPullVerified": True, "gpuExecutionQualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inputs", "descriptor"))
    parser.add_argument("--source")
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--inspection", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.mode == "inputs":
        inputs()
        return
    result = descriptor(args.source, json.loads(args.metadata.read_text()), json.loads(args.inspection.read_text()))
    with args.out.open("x") as output:
        output.write(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
