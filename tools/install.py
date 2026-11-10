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
import uuid
import venv
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lock_state(state):
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    handles = []
    for name in ("daemon.lock", "host.lock"):
        handle = open(state / name, "a")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("stop the daemon and active local commands before changing installation") from None
        handles.append(handle)
    database = state / "authority.sqlite3"
    if database.exists():
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
            if db.execute("SELECT 1 FROM leases WHERE state != 'released' LIMIT 1").fetchone():
                raise RuntimeError("held, draining or quarantined leases must be cleanly released first")
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


def finish_activation(prefix, manifest):
    pending = manifest["pending"]
    release = pending["release"]
    if release not in manifest["releases"] or not (prefix/"releases"/release).is_dir():
        raise RuntimeError("activation journal does not identify an installed release")
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


def activate(prefix, manifest, release):
    manifest["pending"] = {"kind": "activate", "release": release,
                           "temporary": ".current-" + uuid.uuid4().hex,
                           "previous_release": manifest.get("active_release")}
    save_manifest(prefix, manifest)
    finish_activation(prefix, manifest)


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
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required")
    prefix, state = Path(args.prefix).resolve(), Path(args.state_dir).resolve()
    if prefix in {Path("/"), Path.home(), Path("/usr"), Path("/opt"), state} or prefix in state.parents or state in prefix.parents:
        raise RuntimeError("use dedicated, disjoint installation and persistent state directories")
    locks = lock_state(state)
    marker = prefix / "installation.json"
    if marker.exists():
        manifest = json.loads(marker.read_text())
        if manifest.get("product") != "nodus-datacenter" or manifest.get("state_dir") != str(state):
            raise RuntimeError("installation ownership or state directory does not match")
    else:
        if args.action != "install":
            raise RuntimeError("a new install requires an empty dedicated prefix")
        manifest = initialize_prefix(prefix, state)
    recover_pending(prefix, manifest)
    if args.action == "install":
        wheel = Path(args.wheel or "").resolve()
        if not wheel.is_file() or wheel.suffix != ".whl":
            raise RuntimeError("supply the local wheel with --wheel")
        with zipfile.ZipFile(wheel) as archive:
            metadata = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
            if len(metadata) != 1 or "Name: nodus-datacenter\n" not in archive.read(metadata[0]).decode():
                raise RuntimeError("wheel is not the expected product")
        release = digest(wheel)[:20]
        destination = prefix / "releases" / release
        if release not in manifest["releases"]:
            if destination.exists() or destination.is_symlink():
                if release in manifest.get("retired_releases", {}):
                    preserve_release(prefix, manifest, release, "uninstalled")
                else:
                    raise RuntimeError("untracked release directory exists; it will not be deleted")
            manifest["pending"] = {"kind": "install", "release": release, "wheel_sha256": digest(wheel)}
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
    activate(prefix, manifest, release)
    print(json.dumps({"installed": True, "release": release, "executable": str(prefix / "current/bin/nodus-dc"),
                      "state_dir": str(state), "service_started": False,
                      "preserved_directories": manifest.get("preserved_directories", [])}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
