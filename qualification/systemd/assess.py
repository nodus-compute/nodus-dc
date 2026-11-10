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
            "schema2_rollback_refusal_and_restoration", "stubborn_descendants_operator_recovery"}


def process_ids(rows):
    assert isinstance(rows, list) and rows
    ids = []
    for row in rows:
        assert type(row["pid"]) is int and row["pid"] > 1
        assert isinstance(row["start_ticks"], str) and row["start_ticks"].isdigit()
        assert row["case"] in EXPECTED
        ids.append((row["case"], row["pid"], row["start_ticks"]))
    assert len(set(ids)) == len(ids)
    return set(ids)


def stopped_snapshot(value, records, *, failed=False, removed=False):
    assert type(value["observed_ns"]) is int and value["observed_ns"] > 0
    assert process_ids(value["processes"]) == process_ids(records)
    assert all(row.get("alive") is False for row in value["processes"])
    unit = value["unit"]
    assert unit["LoadState"] == ("not-found" if removed else "loaded")
    assert (unit["ActiveState"], unit["SubState"]) == (("failed", "failed") if failed else ("inactive", "dead"))
    assert unit["MainPID"] == unit["ControlPID"] == "0" and unit["Job"] in ("", "0")
    assert unit["ControlGroup"] in ("", "/system.slice/nodusd.service")
    assert value["owned_unit"] is (not removed)
    if not removed:
        assert unit["UnitFileState"] == "disabled" and unit["KillMode"] == "control-group" and unit["SendSIGKILL"] == "yes"
    group = value["cgroup"]
    assert group["path"] == "/sys/fs/cgroup/system.slice/nodusd.service/cgroup.procs"
    assert type(group["exists"]) is bool and group["pids"] == [] and isinstance(group["raw"], str) and not group["raw"].strip()
    assert group["events_path"] == "/sys/fs/cgroup/system.slice/nodusd.service/cgroup.events"
    assert type(group["populated"]) is int and group["populated"] == 0
    if group["exists"]:
        assert dict(line.split() for line in group["events_raw"].splitlines()).get("populated") == "0"
        assert type(group["identity"]["device"]) is int and type(group["identity"]["inode"]) is int
    else:
        assert group["events_raw"] == "" and group["identity"] is None


def service_evidence(root, cases, cleanup):
    rows = [json.loads(line) for line in (root / "systemd/processes.jsonl").read_text().splitlines()]
    snapshots = [json.loads(line) for line in (root / "systemd/snapshots.jsonl").read_text().splitlines()]
    attempts = [json.loads(line) for line in (root / "systemd/agent-attempts.jsonl").read_text().splitlines()]
    commands = [json.loads(line) for line in (root / "systemd/commands.jsonl").read_text().splitlines()]
    process_ids(rows)
    assert snapshots and attempts and commands
    for case in cases:
        observed = [row for row in rows if row["case"] == case["name"]]
        assert process_ids(case["processes"]) == process_ids(observed)
        minimum = 1 if case["name"] in {"refuse_killmode_process", "refuse_no_sigkill", "stop_command_timeout"} else 3
        if case["name"] in {"restart_then_stop", "refuse_stale_stopped_receipt", "schema2_rollback_refusal_and_restoration"}:
            minimum = 6
        assert len(observed) >= minimum
        assert case["before_observation"] in snapshots and case["final_observation"] in snapshots
        assert len(case["before_observation"]["processes"]) == (1 if case["name"] in {"refuse_killmode_process", "refuse_no_sigkill", "stop_command_timeout"} else 3)
        assert process_ids(case["before_observation"]["processes"]).issubset(process_ids(observed))
        assert isinstance(case["agent_attempts"], list) and case["agent_attempts"]
        assert all(row["alive"] is True for row in case["before_observation"]["processes"])
        before_unit = case["before_observation"]["unit"]
        assert case["before"] == before_unit and case["before_observation"]["owned_unit"] is True
        assert before_unit["LoadState"] == "loaded" and before_unit["ActiveState"] == "active" and before_unit["SubState"] == "running"
        assert before_unit["ControlGroup"] == "/system.slice/nodusd.service" and before_unit["FragmentPath"] == "/etc/systemd/system/nodusd.service" and before_unit["DropInPaths"] == ""
        assert before_unit["MainPID"] in {str(row["pid"]) for row in case["before_observation"]["processes"]}
        assert before_unit["KillMode"] == ("process" if case["name"] == "refuse_killmode_process" else "control-group")
        assert before_unit["SendSIGKILL"] == ("no" if case["name"] == "refuse_no_sigkill" else "yes")

        for attempt in case["agent_attempts"]:
            assert {"case": case["name"], **attempt} in attempts and attempt["snapshot"] in snapshots
            assert 0 < attempt["started_ns"] <= attempt["completed_ns"] <= attempt["snapshot"]["observed_ns"]
        if case["name"] in {"refuse_killmode_process", "refuse_no_sigkill", "stop_command_timeout"}:
            assert len(case["agent_attempts"]) == 1
            assert case["expected_refusal"] == "agent_stop_unverified"
            assert case["agent_attempts"][-1]["error_code"] == "agent_stop_unverified"
            attempt = case["agent_attempts"][-1]
            if case["name"] == "stop_command_timeout":
                assert attempt["completed_ns"] - attempt["started_ns"] >= 45_000_000_000
                assert attempt["error"] == "nodusd service stop/disable could not be verified"
            else:
                assert attempt["error"] == "nodusd is not verified stopped and disabled"
        else:
            stopped_snapshot(case["final_observation"], observed)
            assert case["agent_attempts"][-1]["result"] == {"unit": "nodusd.service", "stopped": True, "disabled": True}
            if case["name"] != "stubborn_descendants_operator_recovery":
                assert all("error_code" not in attempt and attempt["result"] == {"unit": "nodusd.service", "stopped": True, "disabled": True} for attempt in case["agent_attempts"])
    recovery = next(case for case in cases if case["name"] == "stubborn_descendants_operator_recovery")
    records = [row for row in rows if row["case"] == recovery["name"]]
    assert len(records) == 3 and len(recovery["agent_attempts"]) == 2
    first, second = recovery["agent_attempts"]
    assert first["error_code"] == recovery["expected_refusal"] == "agent_stop_unverified" and "result" not in first
    assert first["error"] == "nodusd is not verified stopped and disabled"
    assert first["label"] == "stubborn_initial_stop" and second["label"] == "after_operator_reset"
    before, after, reset = recovery["before_operator_reset"], recovery["after_operator_retry"], recovery["operator_reset"]
    assert before in snapshots and after in snapshots
    stopped_snapshot(before, records, failed=True)
    stopped_snapshot(after, records)
    assert before["unit"]["Result"] == "timeout" and before["unit"]["ExecMainCode"] == "2" and before["unit"]["ExecMainStatus"] == "9"
    assert recovery["operator_recovery_is_explicit"] is True
    assert reset["argv"] == ["systemctl", "reset-failed", "nodusd.service"] and reset["returncode"] == 0
    assert any(all(command.get(key) == value for key, value in reset.items()) for command in commands)
    assert (first["completed_ns"] <= before["observed_ns"] < reset["started_ns"] <= reset["completed_ns"]
            < second["started_ns"] <= second["completed_ns"] <= after["observed_ns"])
    journal = (root / "systemd/stubborn-forced-stop-journal.log").read_text()
    assert all(re.search(rf"Killing process {row['pid']} \([^)]*\) with signal SIGKILL\.", journal) for row in records)
    assert cleanup["observation"] in snapshots
    stopped_snapshot(cleanup["observation"], rows, removed=True)


def published_evidence(root, artifact, bindings):
    """Require downloaded release provenance and identical rebuilt artifact bytes."""
    release = bindings["published_release"]
    assert artifact["published_downloads"] == {
        "tag": release["tag"], "source_commit": bindings["source_commit"],
        "assets": {name: {"url": release["url"] + name, "bytes": release["sizes"][name], "sha256": sha}
                   for name, sha in bindings["artifacts"].items()}}
    for name, expected in bindings["artifacts"].items():
        downloaded = root / "prepared" / name
        assert downloaded.stat().st_size == release["sizes"][name]
        assert hashlib.sha256(downloaded.read_bytes()).hexdigest() == expected
        assert hashlib.sha256((root / "prepared/rebuilt" / name).read_bytes()).hexdigest() == expected


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
        published_evidence(root, artifact, bindings)
        assert agent["binary"]["sha256"] == bindings["published_nodusd"]["sha256"]
        cases = systemd["cases"]
        assert len(cases) == len(EXPECTED) and {c["name"] for c in cases} == EXPECTED
        assert all(c["status"] == "passed" for c in cases)
        service_evidence(root, cases, cleanup)
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
        assert (root / "nodus-dc-version.txt").read_text().strip() == bindings["version"]
        assert "--api-key-name" in (root / "native-return-help.txt").read_text()
        assert (root / "systemd/commands.jsonl").stat().st_size > 0
        result["passed_scoped_systemd_and_artifact_checks"] = True
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, AssertionError) as error:
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
