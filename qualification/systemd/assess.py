#!/usr/bin/env python3
"""Require actual receipts; workflow transport success alone is never evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED = {"active_descendants", "restart_then_stop", "already_stopped", "refuse_killmode_process",
            "refuse_no_sigkill", "stop_command_timeout", "refuse_stale_stopped_receipt",
            "schema2_rollback_refusal_and_restoration"}


def assess(root):
    result = {"passed_scoped_systemd_and_artifact_checks": False,
              "native_customer_return_qualified": False, "gpu_qualified": False,
              "actual_nodusd_daemon_qualified": False, "errors": []}
    try:
        bindings = json.loads(Path(__file__).with_name("bindings.json").read_text())
        systemd = json.loads((root / "systemd/receipt.json").read_text())
        cleanup = json.loads((root / "systemd/outer-cleanup.json").read_text())
        artifact = json.loads((root / "prepared/artifact-rebuild.json").read_text())
        agent = json.loads((root / "signed-agent/receipt.json").read_text())
        assert all(value.get("synthetic_fixture") is not True for value in (systemd, cleanup, artifact, agent))
        assert re.fullmatch(r"[0-9a-f]{40}", systemd["workflow_sha"])
        assert systemd["fixture_sha256"] == hashlib.sha256(Path(__file__).with_name("systemd_fixture.py").read_bytes()).hexdigest()
        assert systemd["bindings_sha256"] == hashlib.sha256(Path(__file__).with_name("bindings.json").read_bytes()).hexdigest()
        assert systemd["handback_sha256"] == bindings["handback_sha256"]
        assert systemd["installed_module_sha256"] == bindings["module_sha256"]
        assert artifact["source_commit"] == bindings["source_commit"]
        assert artifact["artifacts"] == bindings["artifacts"]
        for name, expected in bindings["artifacts"].items():
            assert hashlib.sha256((root / "prepared" / name).read_bytes()).hexdigest() == expected
        assert agent["binary"]["sha256"] == bindings["published_nodusd"]["sha256"]
        cases = systemd["cases"]
        assert len(cases) == len(EXPECTED) and {c["name"] for c in cases} == EXPECTED
        assert all(c["status"] == "passed" for c in cases)
        legacy = bindings["legacy"]
        assert artifact["candidate_installer_sha256"] == bindings["candidate_installer_sha256"]
        assert artifact["legacy_inputs_sha256"] == {"wheel": legacy["wheel_sha256"], "sdist": legacy["sdist_sha256"], "installer": legacy["installer_sha256"]}
        assert systemd["installer_input_sha256"] == {"install.py": bindings["candidate_installer_sha256"], "legacy-install.py": legacy["installer_sha256"], legacy["wheel"]: legacy["wheel_sha256"]}
        for name, sha in ((legacy["wheel"], legacy["wheel_sha256"]), (legacy["sdist"], legacy["sdist_sha256"]), ("legacy-install.py", legacy["installer_sha256"])):
            assert hashlib.sha256((root / "prepared" / name).read_bytes()).hexdigest() == sha
        rollback = next(c for c in cases if c["name"] == "schema2_rollback_refusal_and_restoration")
        assert all(rollback.get(key) is True for key in ("incompatible_refused_while_service_active", "active_pid_link_manifest_history_preserved",
                   "legacy_break_and_current_restoration_preserved_history", "service_restarted_after_restoration", "synthetic_history_only"))
        assert len(rollback["installer_attempts"]) == 2 and all(item["returncode"] != 0 for item in rollback["installer_attempts"])

        assert systemd["systemd_qualified"] is True and systemd["cleanup"] is True
        assert cleanup["owned_unit_absent"] is True and cleanup["owned_processes_gone"] is True
        assert artifact["built_equal_reviewed"] is True
        assert agent["signature_verified"] is True and agent["protocol_executable_verified"] is True
        assert len(agent["negative_checks"]) == 2 and all(x["returncode"] != 0 for x in agent["negative_checks"])
        assert not any(systemd.get(k) is True for k in ("gpu_qualified", "platform_retirement_qualified", "actual_nodusd_daemon_qualified", "native_customer_return_qualified"))
        assert (root / "nodus-dc-version.txt").read_text().strip() == "0.1.0.dev2"
        assert "--api-key-name" in (root / "native-return-help.txt").read_text()
        assert (root / "systemd/commands.jsonl").stat().st_size > 0
        result["passed_scoped_systemd_and_artifact_checks"] = True
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        result["errors"].append({"type": type(error).__name__, "message": str(error)})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    result = assess(args.evidence)
    (args.evidence / "assessment.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["passed_scoped_systemd_and_artifact_checks"] else 1


if __name__ == "__main__":
    sys.exit(main())
