#!/usr/bin/env python3
"""Offline versioned installation, upgrade/rollback, and owned-file uninstall.

No driver/package downloads, system configuration changes, service starts,
database removal, or automatic lending. Run installed daemon as host operator.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import uuid
import venv
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


COMPATIBILITY_PROBE = """
import json, sys
try:
    from nodus_dc.store import Store
    Store(sys.argv[1])
    if sys.argv[2] == 'recovery':
        from nodus_dc import service
        protocol = getattr(service, 'RECOVERY_UPGRADE_PROTOCOL', None)
        if type(protocol) is not int or protocol != 1:
            raise RuntimeError('candidate lacks recovery-upgrade protocol')
except Exception as error:
    print(json.dumps({'supported': False, 'error_type': type(error).__name__, 'code': getattr(error, 'code', None)}))
    sys.exit(1)
print(json.dumps({'supported': True}))
"""


def state_compatible(python, state, *, snapshot_timeout=10, require_recovery=False):
    """Open a consistent private copy with the actual candidate's Store code.

    The authoritative database is opened mode=ro, including its current WAL.
    Old releases need no new CLI command or inferred compatibility metadata.
    Any initialization/migration by candidate code affects only the disposable
    copy. Repeat this check after acquiring the ordinary installer locks.
    """
    database = state / "authority.sqlite3"
    if not database.exists():
        return
    with tempfile.TemporaryDirectory(prefix="nodus-state-compatibility-") as folder:
        snapshot = Path(folder) / "authority.sqlite3"
        deadline = time.monotonic() + snapshot_timeout
        def bounded_backup(_status, _remaining, _total):
            if time.monotonic() >= deadline:
                raise RuntimeError("current authority state snapshot timed out; activation refused")
        try:
            source = sqlite3.connect("file:" + urllib.parse.quote(str(database), safe="/") + "?mode=ro", uri=True, timeout=0.05)
            try:
                target = sqlite3.connect(snapshot)
                try:
                    source.execute("PRAGMA query_only=ON")
                    source.backup(target, pages=128, progress=bounded_backup, sleep=0.05)
                finally:
                    target.close()
            finally:
                source.close()
        except sqlite3.Error:
            raise RuntimeError("current authority state could not be read for compatibility; activation refused") from None
        try:
            result = subprocess.run([str(python), "-I", "-c", COMPATIBILITY_PROBE, str(snapshot),
                                     "recovery" if require_recovery else "normal"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=30, check=False)
            supported = result.returncode == 0 and json.loads(result.stdout).get("supported") is True
        except (OSError, subprocess.TimeoutExpired, ValueError, AttributeError):
            supported = False
        if not supported:
            raise RuntimeError("candidate cannot open the current authority state or provide the required recovery protocol; active installation and state were not changed")


def validate_wheel(wheel):
    if not wheel.is_file() or wheel.suffix != ".whl":
        raise RuntimeError("supply the local wheel with --wheel")
    with zipfile.ZipFile(wheel) as archive:
        metadata = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or "Name: nodus-datacenter\n" not in archive.read(metadata[0]).decode():
            raise RuntimeError("wheel is not the expected product")


def read_manifest(prefix, state):
    marker = prefix / "installation.json"
    if not marker.exists():
        return None
    manifest = json.loads(marker.read_text())
    if manifest.get("product") != "nodus-datacenter" or manifest.get("state_dir") != str(state):
        raise RuntimeError("installation ownership or state directory does not match")
    return manifest


def release_python(prefix, manifest, release):
    if release not in manifest["releases"]:
        raise RuntimeError("requested release is not owned by this installation")
    return owned_path(prefix, "releases/" + release + "/bin/python")


def preflight_candidate(args, prefix, state):
    """Reject incompatible targets before asking an operator to stop a daemon.

    Existing release interpreters are probed directly. A new wheel is installed
    offline into a private temporary venv, without altering the active prefix.
    This early read is advisory until rechecked under installer locks.
    """
    if args.action == "uninstall":
        return
    manifest = read_manifest(prefix, state)
    recovery = getattr(args, "recovery_upgrade", False)
    if recovery and (args.action != "install" or manifest is None):
        raise RuntimeError("recovery upgrade requires install into an existing owned installation")
    if args.action == "activate":
        if manifest is None:
            raise RuntimeError("a new install requires an empty dedicated prefix")
        state_compatible(release_python(prefix, manifest, args.release), state)
        return
    wheel = Path(args.wheel or "").resolve()
    validate_wheel(wheel)
    if not (state / "authority.sqlite3").exists():
        return
    release = digest(wheel)[:20]
    if manifest and release in manifest["releases"]:
        state_compatible(release_python(prefix, manifest, release), state, require_recovery=recovery)
        return
    with tempfile.TemporaryDirectory(prefix="nodus-wheel-compatibility-") as folder:
        probe = Path(folder) / "candidate"
        venv.EnvBuilder(with_pip=True).create(probe)
        python = probe / "bin/python"
        subprocess.run([str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps",
                        "--disable-pip-version-check", str(wheel)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=60)
        state_compatible(python, state, require_recovery=recovery)


def lock_state(state, *, recovery_upgrade=False):
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    handles = []
    try:
        for name in ("daemon.lock", "host.lock"):
            handle = open(state / name, "a")
            handles.append(handle)
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("stop the daemon and active local commands before changing installation") from None
        database = state / "authority.sqlite3"
        held = []
        if database.exists():
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
                db.row_factory = sqlite3.Row
                held = list(db.execute("SELECT * FROM leases WHERE state != 'released'"))
                if held and not recovery_upgrade:
                    raise RuntimeError("held, draining or quarantined leases must be cleanly released first")
                if recovery_upgrade:
                    # Recovery installation cannot authorize native ownership or
                    # external work. This is the actual runtime predicate, plus its
                    # durable terminal-return journal, not a mode-only guess.
                    terminal = db.execute("SELECT 1 FROM meta WHERE key='terminal_native_handback'").fetchone()
                    for row in held:
                        runtime = json.loads(row["runtime"]) if row["runtime"] else {}
                        if (row["owner"] != "local" or row["state"] != "quarantined"
                                or row["mode"] not in {"exclusive_gpu", "exclusive_host", "hardware_partition", "gpu_configuration", "trusted_mps"}
                                or not isinstance(runtime, dict) or runtime.get("execution_kind") == "native_handoff" or terminal):
                            raise RuntimeError("recovery upgrade permits only quarantined local non-native allocations")
        if recovery_upgrade and not held:
            raise RuntimeError("recovery upgrade requires a quarantined allocation; use ordinary install")
    except BaseException:
        for handle in handles:
            handle.close()
        raise
    return handles


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_manifest(prefix, manifest):
    """Atomic durable state, never a shared fixed temporary filename."""
    temporary = prefix / (".installation-" + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(manifest, stream, sort_keys=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, prefix / "installation.json")
        sync_directory(prefix)
    finally:
        temporary.unlink(missing_ok=True)


def initialize_prefix(prefix, state):
    """The first visible nonempty prefix already contains its ownership marker."""
    if prefix.exists() and any(prefix.iterdir()):
        raise RuntimeError("a new install requires an empty dedicated prefix")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="."+prefix.name+".bootstrap-", dir=prefix.parent))
    manifest = {"product": "nodus-datacenter", "installation_id": str(uuid.uuid4()),
                "state_dir": str(state), "releases": {}, "retired_releases": {},
                "preserved_directories": [], "pending": None}
    save_manifest(stage, manifest)
    # Atomic directory publication prevents a killed first install from leaving
    # an unowned nonempty prefix. An interrupted unpublished bootstrap is kept.
    os.replace(stage, prefix)
    sync_directory(prefix.parent)
    return manifest


def owned_path(prefix, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise RuntimeError("invalid ownership manifest path")
    result = prefix / path
    if not result.parent.resolve().is_relative_to(prefix):
        raise RuntimeError("owned path parent escaped the installation directory")
    return result


def preserve_pending(prefix, manifest):
    pending = manifest["pending"]
    source = owned_path(prefix, pending["source"])
    target = owned_path(prefix, pending["destination"])
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.exists() or source.is_symlink():
        if source.is_symlink() or not source.is_dir() or target.exists() or target.is_symlink():
            raise RuntimeError("cannot safely preserve an interrupted release directory")
        os.replace(source, target)
        sync_directory(source.parent)
        sync_directory(target.parent)
    elif not target.is_dir() or target.is_symlink():
        raise RuntimeError("interrupted release preservation has no verifiable source or target")
    preserved = manifest.setdefault("preserved_directories", [])
    if pending["destination"] not in preserved:
        preserved.append(pending["destination"])
    manifest.setdefault("retired_releases", {}).pop(pending.get("release"), None)
    manifest["pending"] = None
    save_manifest(prefix, manifest)


def preserve_release(prefix, manifest, release, reason):
    manifest["pending"] = {"kind": "preserve", "release": release, "source": "releases/"+release,
                           "destination": "preserved/"+reason+"-"+release+"-"+uuid.uuid4().hex}
    save_manifest(prefix, manifest)
    preserve_pending(prefix, manifest)


def finish_activation(prefix, manifest, *, compatibility_checked=False):
    pending = manifest["pending"]
    release = pending["release"]
    if release not in manifest["releases"] or not (prefix/"releases"/release).is_dir():
        raise RuntimeError("activation journal does not identify an installed release")
    if not compatibility_checked:
        state_compatible(release_python(prefix, manifest, release), Path(manifest["state_dir"]),
                         require_recovery=pending.get("recovery_upgrade") is True)
    expected = str(Path("releases") / release)
    current = prefix / "current"
    if current.exists() or current.is_symlink():
        if not current.is_symlink() or os.readlink(current) not in {str(Path("releases")/r) for r in manifest["releases"]}:
            raise RuntimeError("current is not an owned release link")
    temporary = owned_path(prefix, pending["temporary"])
    if temporary.exists() or temporary.is_symlink():
        if not temporary.is_symlink() or os.readlink(temporary) != expected:
            raise RuntimeError("activation staging path has unexpected contents")
    else:
        temporary.symlink_to(expected)
        sync_directory(prefix)
    os.replace(temporary, current)
    sync_directory(prefix)
    manifest["active_release"] = release
    manifest["pending"] = None
    save_manifest(prefix, manifest)


def activate(prefix, manifest, release, *, recovery_upgrade=False):
    # Installer locks are held: an earlier schema1 snapshot cannot authorize a
    # schema2 downgrade after an intervening connection opt-in.
    state_compatible(release_python(prefix, manifest, release), Path(manifest["state_dir"]),
                     require_recovery=recovery_upgrade)
    manifest["pending"] = {"kind": "activate", "release": release,
                           "temporary": ".current-" + uuid.uuid4().hex,
                           "previous_release": manifest.get("active_release"),
                           "recovery_upgrade": recovery_upgrade}
    save_manifest(prefix, manifest)
    finish_activation(prefix, manifest, compatibility_checked=True)


def finish_uninstall(prefix, manifest):
    # Remove exact manifest-owned files, never recursively delete unknown data.
    owned_directories = set()
    for release, entry in manifest["releases"].items():
        release_root = prefix / "releases" / release
        for relative in entry["files"]:
            path = owned_path(prefix, relative)
            parent = path.parent
            while parent.is_relative_to(release_root):
                owned_directories.add(parent)
                parent = parent.parent
            path.unlink(missing_ok=True)
    current = prefix / "current"
    if current.is_symlink() and os.readlink(current) in {str(Path("releases")/r) for r in manifest["releases"]}:
        current.unlink()
    directories = sorted(owned_directories, key=lambda p: len(p.parts), reverse=True)
    for directory in directories:
        if directory.is_symlink():
            continue
        try:
            directory.rmdir()
        except OSError:
            pass
    manifest.setdefault("retired_releases", {}).update({r: entry["wheel_sha256"] for r, entry in manifest["releases"].items()})
    manifest.update(releases={}, active_release=None, pending=None)
    # Keep ownership metadata so another install can preserve old untracked
    # leftovers before reusing a release path. State and unrelated files stay.
    save_manifest(prefix, manifest)


def recover_pending(prefix, manifest):
    pending = manifest.get("pending")
    if not pending:
        return
    kind = pending.get("kind")
    if kind == "install":
        release = pending["release"]
        destination = prefix / "releases" / release
        if destination.exists() or destination.is_symlink():
            preserve_release(prefix, manifest, release, "interrupted")
        else:
            manifest["pending"] = None
            save_manifest(prefix, manifest)
    elif kind == "preserve":
        preserve_pending(prefix, manifest)
    elif kind == "activate":
        finish_activation(prefix, manifest)
    elif kind == "uninstall":
        finish_uninstall(prefix, manifest)
    else:
        raise RuntimeError("unknown installation journal state")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["install", "activate", "uninstall"])
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--wheel")
    parser.add_argument("--release")
    parser.add_argument("--recovery-upgrade", action="store_true",
                        help="install a compatible recovery-capable wheel while only quarantined local non-native leases remain; never releases them")
    args = parser.parse_args(argv)
    if args.recovery_upgrade and args.action != "install":
        raise RuntimeError("--recovery-upgrade is available only for install")
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required")
    prefix, state = Path(args.prefix).resolve(), Path(args.state_dir).resolve()
    if prefix in {Path("/"), Path.home(), Path("/usr"), Path("/opt"), state} or prefix in state.parents or state in prefix.parents:
        raise RuntimeError("use dedicated, disjoint installation and persistent state directories")
    preflight_candidate(args, prefix, state)
    locks = lock_state(state, recovery_upgrade=args.recovery_upgrade)
    try:
        return install_locked(args, prefix, state)
    finally:
        for handle in locks:
            handle.close()


def install_locked(args, prefix, state):
    # Recheck the requested target before pending-install recovery or any prefix
    # mutation. A CLI connection opt-in may have committed after the early read.
    preflight_candidate(args, prefix, state)
    # Another installer may have completed between the early probe and locks.
    manifest = read_manifest(prefix, state)
    if manifest is None:
        if args.action != "install":
            raise RuntimeError("a new install requires an empty dedicated prefix")
        manifest = initialize_prefix(prefix, state)
    pending = manifest.get("pending") or {}
    if args.recovery_upgrade and pending.get("kind") == "uninstall":
        raise RuntimeError("recovery upgrade cannot resume an interrupted uninstall")
    if args.recovery_upgrade and pending.get("kind") == "activate" and not pending.get("recovery_upgrade"):
        raise RuntimeError("an earlier ordinary activation must be resolved after clean release")
    recover_pending(prefix, manifest)
    if args.action == "install":
        wheel = Path(args.wheel or "").resolve()
        validate_wheel(wheel)
        release = digest(wheel)[:20]
        destination = prefix / "releases" / release
        if release not in manifest["releases"]:
            if destination.exists() or destination.is_symlink():
                if release in manifest.get("retired_releases", {}):
                    preserve_release(prefix, manifest, release, "uninstalled")
                else:
                    raise RuntimeError("untracked release directory exists; it will not be deleted")
            manifest["pending"] = {"kind": "install", "release": release, "wheel_sha256": digest(wheel),
                                   "recovery_upgrade": args.recovery_upgrade}
            save_manifest(prefix, manifest)
            venv.EnvBuilder(with_pip=True).create(destination)
            subprocess.run([str(destination / "bin/python"), "-I", "-m", "pip", "install", "--no-index", "--no-deps",
                            "--disable-pip-version-check", str(wheel)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([str(destination / "bin/python"), "-I", "-m", "nodus_dc", "--version"], check=True, stdout=subprocess.DEVNULL)
            owned = [str(p.relative_to(prefix)) for p in destination.rglob("*") if p.is_file() or p.is_symlink()]
            manifest["releases"][release] = {"wheel_sha256": digest(wheel), "files": sorted(owned)}
            manifest["pending"] = None
            save_manifest(prefix, manifest)
    elif args.action == "activate":
        release = args.release
        if release not in manifest["releases"]:
            raise RuntimeError("requested release is not owned by this installation")
    else:
        manifest["pending"] = {"kind": "uninstall"}
        save_manifest(prefix, manifest)
        finish_uninstall(prefix, manifest)
        print(json.dumps({"uninstalled": True, "state_preserved": str(state), "untracked_files_preserved": str(prefix)}))
        return 0
    activate(prefix, manifest, release, recovery_upgrade=args.recovery_upgrade)
    print(json.dumps({"installed": True, "release": release, "executable": str(prefix / "current/bin/nodus-dc"),
                      "state_dir": str(state), "service_started": False,
                      "recovery_upgrade": args.recovery_upgrade,
                      "preserved_directories": manifest.get("preserved_directories", [])}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
