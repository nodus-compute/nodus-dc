#!/usr/bin/env python3
"""Public signed-release byte/protocol check; never start or enroll nodusd."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import urllib.parse


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("non-HTTPS redirect refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, path, limit):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSRedirect())
    started, size = time.monotonic(), 0
    with opener.open(url, timeout=15) as response, path.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > limit or time.monotonic() - started > 90:
                raise RuntimeError("public artifact download exceeded bound")
            output.write(chunk)
    return {"url": url, "bytes": size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    bindings = json.loads(Path(__file__).with_name("bindings.json").read_text())["published_nodusd"]
    result = {"signature_verified": False, "protocol_executable_verified": False,
              "nodusd_daemon_started": False, "enrollment_qualified": False,
              "current_local_authority_release_qualified": False,
              "release_source": bindings["source_commit"], "negative_checks": []}
    receipt = args.output / "receipt.json"
    try:
        binary, bundle = args.output / "nodusd", args.output / "nodusd.bundle"
        result["binary"] = fetch(bindings["binary_url"], binary, 128 << 20)
        result["bundle"] = fetch(bindings["bundle_url"], bundle, 2 << 20)
        if result["binary"]["sha256"] != bindings["sha256"]:
            raise RuntimeError("public binary differs from successful release job digest")
        common = ["cosign", "verify-blob", "--bundle", str(bundle), "--certificate-oidc-issuer", bindings["issuer"]]
        def verify(name, target, identity, expected):
            argv = common + ["--certificate-identity-regexp", identity, str(target)]
            with (args.output / (name + ".log")).open("wb") as log:
                done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=75)
            if (done.returncode == 0) != expected:
                raise RuntimeError("unexpected signature result for " + name)
            return {"case": name, "returncode": done.returncode, "expected_success": expected}
        verify("signed-published-binary", binary, bindings["identity_regex"], True)
        result["signature_verified"] = True
        altered = args.output / "nodusd.altered"
        shutil.copyfile(binary, altered)
        with altered.open("r+b") as f:
            byte = f.read(1)
            f.seek(0)
            f.write(bytes([byte[0] ^ 1]))
        result["negative_checks"].append(verify("changed-byte-rejected", altered, bindings["identity_regex"], False))
        result["negative_checks"].append(verify("wrong-workflow-rejected", binary,
                    r"^https://github\.com/nodus-compute/nodus-platform/\.github/workflows/not-the-release\.yml@refs/heads/main$", False))
        altered.unlink()
        binary.chmod(0o700)
        # --version is not a supported nodusd flag. This is only its documented
        # credential-free port protocol version command, not daemon execution.
        with (args.output / "port-version.log").open("wb") as log:
            done = subprocess.run([str(binary.resolve()), "port-version"], stdin=subprocess.DEVNULL,
                                  stdout=log, stderr=subprocess.STDOUT, timeout=10,
                                  env={"PATH": "/usr/bin:/bin"})
        if done.returncode != 0 or not (args.output / "port-version.log").stat().st_size:
            raise RuntimeError("signed nodusd port-version command failed")
        result["protocol_executable_verified"] = True
        go = shutil.which("go")
        if go:
            with (args.output / "go-build-metadata.log").open("wb") as log:
                subprocess.run([go, "version", "-m", str(binary)], stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT, timeout=10, check=True)
        result["go_build_metadata_available"] = go is not None
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
        raise
    finally:
        receipt.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
