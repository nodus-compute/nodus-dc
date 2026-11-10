#!/usr/bin/env python3
"""Manual hosted-VM fixture. Real systemd, explicitly representative worker.

No platform credential, node enrollment, GPU, Docker or shared-VM operation.
Run only through the reviewed workflow. This file is preparation, not evidence
that any of its systemd cases have executed.
"""
import argparse
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import signal
import stat
import sqlite3
import subprocess
import sys
import time

UNIT = "nodusd.service"
UNIT_FILE = Path("/etc/systemd/system/nodusd.service")
PROPERTIES = "LoadState,ActiveState,SubState,MainPID,ControlPID,UnitFileState,Job,KillMode,SendSIGKILL,ControlGroup,NRestarts,FragmentPath,DropInPaths,Result,ExecMainCode,ExecMainStatus"
CASES = ("active_descendants", "restart_then_stop", "already_stopped", "refuse_killmode_process",
         "refuse_no_sigkill", "stop_command_timeout", "refuse_stale_stopped_receipt",
         "schema2_rollback_refusal_and_restoration", "stubborn_descendants_operator_recovery")
WORKER = '''import json,os,signal,sys,time
from pathlib import Path
root,case,mode=sys.argv[1:]
def record():
    raw=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()
    row={'pid':os.getpid(),'start_ticks':raw[19],'case':case}
    fd=os.open(str(Path(root)/'processes.jsonl'),os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
    os.write(fd,(json.dumps(row)+'\\n').encode());os.fsync(fd);os.close(fd)
record()
if mode.endswith('descendants'):
    if mode=='stubborn_descendants':
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
    for _ in range(2):
        if os.fork()==0:
            record()
            break
while True:time.sleep(1)
'''


def atomic(path, value):
    raw = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def guard(root):
    if (os.geteuid() != 0 or sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise RuntimeError("only a disposable native GitHub-hosted manual Linux VM is supported")
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[0-9]+", run) or not re.fullmatch(r"[0-9]+", attempt):
        raise RuntimeError("missing numeric workflow identity")
    if root != Path(f"/var/lib/nodus-dc-systemd-qualification-{run}-{attempt}"):
        raise RuntimeError("unexpected fixture root")
    info = root.lstat()
    if root.is_symlink() or not root.is_dir() or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError("fixture root must be a new private root-owned directory")


class Fixture:
    def __init__(self, root):
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir(mode=0o700, exist_ok=True)
        self.marker = root / "unit-owner.json"
        self.result = {"scope": "real systemd control of an explicitly representative worker using installed LinuxAgent",
                       "systemd_qualified": False, "gpu_qualified": False, "platform_retirement_qualified": False,
                       "actual_nodusd_daemon_qualified": False, "native_customer_return_qualified": False,
                       "cases": [], "cleanup": False}
        self.result["workflow_sha"] = os.environ.get("GITHUB_SHA")
        self.result["workflow_run_id"] = os.environ.get("GITHUB_RUN_ID")
        self.result["fixture_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.result["bindings_sha256"] = hashlib.sha256((root / "bindings.json").read_bytes()).hexdigest()

    def command_result(self, argv, *, timeout=15, check=True):
        started_ns = time.monotonic_ns()
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, text=True, check=False)
        result.started_ns, result.completed_ns = started_ns, time.monotonic_ns()
        with (self.evidence / "commands.jsonl").open("a") as out:
            out.write(json.dumps({"argv": argv, "returncode": result.returncode, "output": result.stdout[-65536:],
                                  "started_ns": result.started_ns, "completed_ns": result.completed_ns}) + "\n")
        if check and result.returncode:
            raise RuntimeError(f"fixture command failed ({result.returncode}): {argv[0:3]}")
        return result

    def command(self, argv, *, timeout=15, check=True):
        return self.command_result(argv, timeout=timeout, check=check).stdout

    def inspect(self):
        raw = self.command(["systemctl", "show", UNIT, "--property=" + PROPERTIES])
        return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)

    def processes(self, case=None):
        path = self.root / "processes.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [r for r in rows if case is None or r["case"] == case]

    @staticmethod
    def alive(row):
        try:
            raw = Path(f"/proc/{row['pid']}/stat").read_text().rsplit(")", 1)[1].split()
            return raw[19] == row["start_ticks"]
        except FileNotFoundError:
            return False

    @staticmethod
    def eventually(fn, seconds=10):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if fn():
                return
            time.sleep(0.1)
        raise RuntimeError("bounded observation did not become true")

    def own_unit(self):
        if not self.marker.exists():
            return False
        owned = json.loads(self.marker.read_text())
        return (owned["root"] == str(self.root) and UNIT_FILE.is_file() and not UNIT_FILE.is_symlink()
                and hashlib.sha256(UNIT_FILE.read_bytes()).hexdigest() in owned["allowed_sha256"])

    def cleanup_unit(self):
        if not os.path.lexists(UNIT_FILE):
            if any(self.alive(r) for r in self.processes()):
                raise RuntimeError("owned worker survived without its unit")
            return
        if not self.own_unit():
            raise RuntimeError("refuse cleanup of an unowned or modified unit")
        # Scope every command to our exact unit; never stop a shared container daemon.
        self.command(["systemctl", "disable", "--no-reload", UNIT], check=False)
        self.command(["systemctl", "stop", "--no-block", UNIT], check=False)
        self.command(["systemctl", "kill", "--kill-whom=all", "--signal=SIGKILL", UNIT], check=False)
        self.eventually(lambda: not any(self.alive(r) for r in self.processes()), 12)
        self.eventually(lambda: self.inspect().get("ActiveState") in {"inactive", "failed"}, 12)
        self.command(["journalctl", "--no-pager", "-u", UNIT, "-n", "250"], check=False)
        self.command(["systemctl", "reset-failed", UNIT], check=False)
        if not self.own_unit():
            raise RuntimeError("owned unit changed during cleanup")
        UNIT_FILE.unlink()
        self.command(["systemctl", "daemon-reload"])
        if self.inspect().get("LoadState") != "not-found":
            raise RuntimeError("owned unit remained loaded after removal")

    def unit(self, case, *, killmode="control-group", sigkill="yes", slow_stop=False, descendants=True, stubborn=False):
        self.cleanup_unit()
        worker = self.root / "worker.py"
        worker.write_text(WORKER)
        worker.chmod(0o600)
        mode = ("stubborn_descendants" if stubborn else "cooperative_descendants") if descendants else "cooperative"
        text = (f"[Unit]\nDescription=Disposable Nodus systemd qualification {self.root.name}\n"
                f"[Service]\nType=simple\nExecStart={sys.executable} -I {worker} {self.root} {case} {mode}\n"
                f"Restart=always\nRestartSec=0.5\nKillMode={killmode}\nSendSIGKILL={sigkill}\n"
                f"TimeoutStopSec={'80' if slow_stop else '2'}\n"
                + ("ExecStop=/bin/sleep 70\n" if slow_stop else "")
                + f"PrivateNetwork=yes\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths={self.root}\n"
                "[Install]\nWantedBy=multi-user.target\n")
        digest = hashlib.sha256(text.encode()).hexdigest()
        owned = json.loads(self.marker.read_text()) if self.marker.exists() else {"root": str(self.root), "allowed_sha256": []}
        owned["allowed_sha256"].append(digest)
        atomic(self.marker, owned)  # Record exact cleanup ownership before publishing the unit.
        fd = os.open(UNIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, text.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        (self.evidence / (case + ".service")).write_text(text)
        self.command(["systemctl", "daemon-reload"])
        self.command(["systemctl", "enable", "--now", UNIT])
        self.eventually(lambda: self.inspect().get("ActiveState") == "active" and len(self.processes(case)) >= (3 if descendants else 1))

    def retain_process_journal(self):
        path = self.root / "processes.jsonl"
        raw = path.read_bytes() if path.exists() else b""
        (self.evidence / "processes.jsonl").write_bytes(raw)

    @staticmethod
    def cgroup_snapshot():
        group = Path("/sys/fs/cgroup/system.slice/nodusd.service")
        expected = {"path": str(group / "cgroup.procs"), "events_path": str(group / "cgroup.events")}
        if any(parent.is_symlink() for parent in (group, *group.parents)):
            raise RuntimeError("owned cgroup path contains a symlink")
        try:
            directory = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return {**expected, "exists": False, "identity": None, "raw": "", "pids": [], "events_raw": "", "populated": 0}
        try:
            before = os.fstat(directory)
            if before.st_uid != 0 or not stat.S_ISDIR(before.st_mode):
                raise RuntimeError("owned cgroup directory identity is invalid")
            def read(name):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise RuntimeError("owned cgroup observation is not a regular control file")
                    raw = os.read(fd, 65537)
                    if len(raw) > 65536:
                        raise RuntimeError("owned cgroup observation exceeded bound")
                    return raw.decode()
                finally:
                    os.close(fd)
            raw, events_raw = read("cgroup.procs"), read("cgroup.events")
            after = group.lstat()
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or not stat.S_ISDIR(after.st_mode):
                raise RuntimeError("owned cgroup path changed during observation")
            events = dict(line.split() for line in events_raw.splitlines())
            if events.get("populated") not in {"0", "1"}:
                raise RuntimeError("subtree cgroup population is unavailable")
            return {**expected, "exists": True, "identity": {"device": before.st_dev, "inode": before.st_ino},
                    "raw": raw, "pids": [int(pid) for pid in raw.split()], "events_raw": events_raw,
                    "populated": int(events["populated"])}
        finally:
            os.close(directory)

    def observe(self, label, case):
        value = self.inspect()
        group = self.cgroup_snapshot()
        rows = [{**row, "alive": self.alive(row)} for row in self.processes(case)]
        observation = {"label": label, "case": case, "observed_ns": time.monotonic_ns(), "unit": value,
                       "owned_unit": self.own_unit(), "processes": rows,
                       "cgroup": group}
        with (self.evidence / "snapshots.jsonl").open("a") as output:
            output.write(json.dumps(observation) + "\n")
        self.retain_process_journal()
        return observation

    @staticmethod
    def quiescent(observation, *, failed=False):
        unit = observation["unit"]
        state, substate = ("failed", "failed") if failed else ("inactive", "dead")
        return (observation["owned_unit"] is True and unit.get("LoadState") == "loaded"
                and unit.get("ActiveState") == state and unit.get("SubState") == substate
                and unit.get("MainPID") == "0" and unit.get("ControlPID") == "0"
                and unit.get("UnitFileState") == "disabled" and unit.get("Job") in {"", "0"}
                and unit.get("KillMode") == "control-group" and unit.get("SendSIGKILL") == "yes"
                and unit.get("ControlGroup") in {"", "/system.slice/nodusd.service"}
                and observation["cgroup"]["path"] == "/sys/fs/cgroup/system.slice/nodusd.service/cgroup.procs"
                and observation["cgroup"]["events_path"] == "/sys/fs/cgroup/system.slice/nodusd.service/cgroup.events"
                and observation["cgroup"]["populated"] == 0
                and not observation["cgroup"]["pids"] and not observation["cgroup"]["raw"].strip()
                and bool(observation["processes"]) and not any(row["alive"] for row in observation["processes"]))

    def fresh_stopped(self, case):
        return self.quiescent(self.observe("check_stopped", case))

    def stop(self, agent, row, label):
        attempt = {"label": label, "started_ns": time.monotonic_ns()}
        row.setdefault("agent_attempts", []).append(attempt)
        try:
            attempt["result"] = agent.stop()
            return attempt["result"]
        except Exception as error:
            attempt.update(error_code=getattr(error, "code", None), error_type=type(error).__name__, error=str(error))
            raise
        finally:
            attempt["completed_ns"] = time.monotonic_ns()
            attempt["snapshot"] = self.observe(label + "_after", row["name"])
            with (self.evidence / "agent-attempts.jsonl").open("a") as output:
                output.write(json.dumps({"case": row["name"], **attempt}) + "\n")

    def stubborn_case(self, row, agent, error_type):
        try:
            self.stop(agent, row, "stubborn_initial_stop")
        except error_type as error:
            if error.code != "agent_stop_unverified":
                raise
            row["expected_refusal"] = error.code
        else:
            raise RuntimeError("failed forced stop was unexpectedly accepted")
        before = self.observe("stubborn_before_operator_reset", row["name"])
        if (not self.quiescent(before, failed=True) or len(before["processes"]) != 3
                or before["unit"].get("Result") != "timeout" or before["unit"].get("ExecMainCode") != "2"
                or before["unit"].get("ExecMainStatus") != "9"):
            raise RuntimeError("forced stop lacks exact independent failed-state and process/cgroup cleanup evidence")
        journal = self.command(["journalctl", "--no-pager", "-u", UNIT, "-n", "250"])
        if not all(re.search(rf"Killing process {process['pid']} \([^)]*\) with signal SIGKILL\.", journal) for process in before["processes"]):
            raise RuntimeError("kernel journal does not corroborate every stubborn process kill")
        (self.evidence / "stubborn-forced-stop-journal.log").write_text(journal)
        row["before_operator_reset"] = before
        # Explicit fixture operator action after independent quiescence proof.
        # LinuxAgent and the production native-return acceptance remain unchanged.
        reset = self.command_result(["systemctl", "reset-failed", UNIT])
        row["operator_reset"] = {"argv": reset.args, "returncode": reset.returncode,
                                 "started_ns": reset.started_ns, "completed_ns": reset.completed_ns}
        row["operator_recovery_is_explicit"] = True
        row["retry_stop_result"] = self.stop(agent, row, "after_operator_reset")
        after = self.observe("stubborn_after_retry", row["name"])
        if not self.quiescent(after):
            raise RuntimeError("ordinary strict stop retry did not independently verify inactive/dead quiescence")
        row["after_operator_retry"] = after
        time.sleep(2)
        if not self.fresh_stopped(row["name"]):
            raise RuntimeError("explicit recovery did not remain stopped")

    def rollback_case(self, row, agent):
        # Real installer and wheel bytes; the credential-history entry is an
        # explicit local synthetic fence, never hosted retirement evidence.
        from nodus_dc.service import Service
        from nodus_dc.store import Store
        prefix, state = self.root / "install", self.root / "state"
        expected = self.bindings
        old = expected["legacy"]["wheel_sha256"][:20]
        current = expected["artifacts"][expected["wheel"]][:20]
        common = ["/usr/bin/python3", "-I", str(self.root / "install.py")]
        options = ["--prefix", str(prefix), "--state-dir", str(state)]
        cli = [str(prefix / "current/bin/nodus-dc"), "--state-dir", str(state), "status"]
        self.command(cli)
        Service(Store(state / "authority.sqlite3"), object()).record_connection_attempt({"synthetic_fixture": True})
        def history():
            with sqlite3.connect("file:" + str(state / "authority.sqlite3") + "?mode=ro", uri=True) as db:
                return dict(db.execute("SELECT key,value FROM meta"))
        before = history()
        if before.get("schema_version") != "2":
            raise RuntimeError("compatibility fixture did not establish schema2")
        active, manifest = os.readlink(prefix / "current"), (prefix / "installation.json").read_bytes()
        pid = self.inspect()["MainPID"]
        row["installer_attempts"] = []
        with (state / "daemon.lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            for action, extra in (("activate", ["--release", old]),
                                  ("install", ["--wheel", str(self.root / expected["legacy"]["wheel"])])):
                done = self.command_result(common + [action] + options + extra, timeout=75, check=False)
                row["installer_attempts"].append({"action": action, "returncode": done.returncode, "output": done.stdout})
                if done.returncode == 0 or "candidate cannot open the current authority state" not in done.stdout or "stop the daemon" in done.stdout:
                    raise RuntimeError("incompatible rollback was not refused before daemon-lock checks")
            if (self.inspect().get("ActiveState") != "active" or self.inspect().get("MainPID") != pid
                    or os.readlink(prefix / "current") != active
                    or (prefix / "installation.json").read_bytes() != manifest or history() != before):
                raise RuntimeError("refused rollback changed active service, installation, or history")
        row["incompatible_refused_while_service_active"] = True
        row["active_pid_link_manifest_history_preserved"] = True
        self.command(cli)
        self.stop(agent, row, "rollback_stop")
        self.eventually(lambda: self.fresh_stopped(row["name"]))
        # Reproduce the actual old installer's unsafe activation only after our
        # owned stand-in is stopped. Restore using the reviewed current installer.
        legacy = ["/usr/bin/python3", "-I", str(self.root / "legacy-install.py")]
        self.command(legacy + ["activate"] + options + ["--release", old], timeout=75)
        broken = self.command_result(cli, check=False)
        if broken.returncode == 0 or "unsupported state schema 2" not in broken.stdout:
            raise RuntimeError("legacy artifact did not exhibit the expected compatibility refusal")
        self.command(common + ["activate"] + options + ["--release", current], timeout=75)
        self.command(cli)
        if os.readlink(prefix / "current") != active or history() != before:
            raise RuntimeError("manual restoration changed authority history or selected the wrong release")
        row["legacy_break_and_current_restoration_preserved_history"] = True
        self.command(["systemctl", "start", UNIT])
        self.eventually(lambda: self.inspect().get("ActiveState") == "active" and len(self.processes(row["name"])) >= 6)
        row["service_restarted_after_restoration"] = True
        self.stop(agent, row, "rollback_stop")
        self.eventually(lambda: self.fresh_stopped(row["name"]))
        row["synthetic_history_only"] = True

    def run_case(self, name, agent, error_type):
        start = time.monotonic()
        row = {"name": name, "status": "running"}
        self.result["cases"].append(row)
        atomic(self.evidence / "receipt.json", self.result)
        try:
            self.unit(name, killmode="process" if name == "refuse_killmode_process" else "control-group",
                      sigkill="no" if name == "refuse_no_sigkill" else "yes",
                      slow_stop=name == "stop_command_timeout", stubborn=name == "stubborn_descendants_operator_recovery",
                      descendants=name not in {"refuse_killmode_process", "refuse_no_sigkill", "stop_command_timeout"})
            row["before_observation"] = self.observe("case_started", name)
            row["before"] = row["before_observation"]["unit"]
            if not all(process["alive"] for process in row["before_observation"]["processes"]):
                raise RuntimeError("expected owned workers were not alive at case start")
            if row["before"].get("ControlGroup") != "/system.slice/nodusd.service":
                raise RuntimeError("unit did not use its expected isolated cgroup")
            if name == "schema2_rollback_refusal_and_restoration":
                self.rollback_case(row, agent)
            if name == "restart_then_stop":
                first = int(row["before"]["MainPID"])
                if not any(r["pid"] == first and self.alive(r) for r in self.processes(name)):
                    raise RuntimeError("cannot bind restart signal to owned worker")
                os.kill(first, signal.SIGKILL)
                self.eventually(lambda: self.inspect().get("MainPID") not in {"0", str(first)} and len(self.processes(name)) >= 6)
                row["restarted"] = self.inspect()
            if name == "stubborn_descendants_operator_recovery":
                self.stubborn_case(row, agent, error_type)
            elif name in {"refuse_killmode_process", "refuse_no_sigkill", "stop_command_timeout"}:
                try:
                    self.stop(agent, row, "expected_refusal_stop")
                except error_type as error:
                    if error.code != "agent_stop_unverified":
                        raise
                    row["expected_refusal"] = error.code
                else:
                    raise RuntimeError("invalid/unverified stop was accepted")
            else:
                row["stop_result"] = self.stop(agent, row, "ordinary_stop")
                self.eventually(lambda: self.fresh_stopped(name))
                if name == "already_stopped":
                    row["repeated_stop_result"] = self.stop(agent, row, "repeat_stopped")
                if name == "refuse_stale_stopped_receipt":
                    self.command(["systemctl", "start", UNIT])
                    self.eventually(lambda: self.inspect().get("ActiveState") == "active" and len(self.processes(name)) >= 6)
                    if self.fresh_stopped(name):
                        raise RuntimeError("old stop result accepted after actual service restart")
                    row["stale_receipt_rejected_by_independent_observation"] = True
                    row["historical_ready_is_not_reattestation"] = True
                    self.stop(agent, row, "after_stale_receipt_restart")
                    self.eventually(lambda: self.fresh_stopped(name))
                # A stopped Restart=always unit must remain stopped during this bounded observation.
                time.sleep(2)
                if not self.fresh_stopped(name):
                    raise RuntimeError("service or descendants restarted after stop")
            row["after"] = self.inspect()
            row["processes"] = self.processes(name)
            row["status"] = "passed"
        except Exception as error:
            row.update(status="failed", error_type=type(error).__name__, error=str(error))
            raise
        finally:
            row["elapsed_seconds"] = time.monotonic() - start
            try:
                row["final_observation"] = self.observe("case_final", name)
            finally:
                self.retain_process_journal()
                atomic(self.evidence / "receipt.json", self.result)
                self.cleanup_unit()

    def run(self):
        from nodus_dc.handback import LinuxAgent
        from nodus_dc.errors import Error
        import nodus_dc.handback as module
        expected = json.loads((self.root / "bindings.json").read_text())
        self.bindings = expected
        files = {"install.py": expected["candidate_installer_sha256"],
                 "legacy-install.py": expected["legacy"]["installer_sha256"],
                 expected["legacy"]["wheel"]: expected["legacy"]["wheel_sha256"]}
        self.result["installer_input_sha256"] = {name: hashlib.sha256((self.root / name).read_bytes()).hexdigest() for name in files}
        if self.result["installer_input_sha256"] != files:
            raise RuntimeError("installer fixture inputs differ from reviewed artifacts")
        self.result["package_version"] = importlib.metadata.version("nodus-datacenter")
        self.result["handback_sha256"] = hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
        if self.result["package_version"] != expected["version"] or self.result["handback_sha256"] != expected["handback_sha256"]:
            raise RuntimeError("installed package does not match reviewed handback source")
        installed_root = Path(module.__file__).parent.parent
        self.result["installed_module_sha256"] = {name: hashlib.sha256((installed_root / name).read_bytes()).hexdigest()
                                                for name in expected["module_sha256"]}
        if self.result["installed_module_sha256"] != expected["module_sha256"]:
            raise RuntimeError("installed runtime module differs from independent review")
        self.result["kernel"] = self.command(["uname", "-a"])
        self.result["systemd"] = self.command(["systemctl", "--version"])
        if os.path.lexists(UNIT_FILE) or self.inspect().get("LoadState") != "not-found":
            raise RuntimeError("fixture requires absent nodusd unit; it will never replace an existing service")
        self.result["unit_absent_before"] = True
        try:
            for name in CASES:
                self.run_case(name, LinuxAgent(), Error)
            self.result["systemd_qualified"] = True
        finally:
            self.cleanup_unit()
            self.result["cleanup"] = True
            atomic(self.evidence / "receipt.json", self.result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    guard(args.root)  # Must run before any systemctl invocation or file mutation.
    def cancelled(_signal, _frame):
        raise RuntimeError("fixture cancelled; run owned-unit cleanup")
    signal.signal(signal.SIGTERM, cancelled)
    fixture = Fixture(args.root)
    if args.cleanup:
        fixture.cleanup_unit()
        fixture.retain_process_journal()
        observation = fixture.observe("outer_cleanup", None)
        atomic(fixture.evidence / "outer-cleanup.json", {"owned_unit_absent": not os.path.lexists(UNIT_FILE),
               "owned_processes_gone": not any(fixture.alive(r) for r in fixture.processes()), "observation": observation})
        return
    fixture.run()


if __name__ == "__main__":
    main()
