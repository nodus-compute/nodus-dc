#!/usr/bin/env python3
"""Offline versioned installation, upgrade/rollback, and owned-file uninstall.

Explicit managed installation bootstraps its independently pinned signature verifier.
No driver/package downloads, system configuration changes, service starts,
database removal, or automatic lending. Run installed daemon as host operator.
"""
import argparse
import contextlib
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


# Independently reviewed cosign-installer 6f9f1778 action.yml, not release.json.
MANAGED_VERIFIER = Path('/opt/nodus/managed-local/verifier/v3.0.6/cosign-linux-amd64')
MANAGED_VERIFIER_SHA256 = 'c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74'
MANAGED_VERIFIER_URL = 'https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64'
MANAGED_VERIFIER_LIMIT = 256 << 20
MANAGED_VERIFIER_DOWNLOAD = r'''
import os, sys, urllib.parse, urllib.request
class Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections, max_repeats = 3, 1
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if (url.scheme != 'https' or url.hostname not in {'github.com', 'release-assets.githubusercontent.com'}
                or url.port not in {None, 443} or url.username or url.password or url.fragment):
            raise RuntimeError('verifier redirect refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
with opener.open(sys.argv[2], timeout=float(sys.argv[4])) as response, os.fdopen(int(sys.argv[1]), 'wb') as out:
    if response.status != 200:
        raise RuntimeError('verifier download refused')
    limit, count = int(sys.argv[3]), 0
    while True:
        block = response.read(65536)
        if not block: break
        count += len(block)
        if count > limit: raise RuntimeError('verifier size refused')
        out.write(block)
    out.flush(); os.fsync(out.fileno())
'''


def managed_verifier(deadline, *, allow_download=False):
    import platform
    import stat
    if os.geteuid() != 0 or sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise RuntimeError('managed verifier requires Linux amd64 root')
    end = min(deadline, time.monotonic() + 30)
    def remaining():
        left = end - time.monotonic()
        if left <= 0:
            raise RuntimeError('managed verifier deadline')
        return left
    def directory(path):
        for item in (path, *path.parents):
            st = item.lstat()
            if st.st_uid != 0 or st.st_gid != 0 or not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
                raise RuntimeError('managed verifier directory refused')
    def exact():
        directory(MANAGED_VERIFIER.parent)
        fd = os.open(MANAGED_VERIFIER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or st.st_nlink != 1
                    or stat.S_IMODE(st.st_mode) != 0o555 or not 0 < st.st_size <= MANAGED_VERIFIER_LIMIT):
                raise RuntimeError('managed verifier file refused')
            digest, count = hashlib.sha256(), 0
            while True:
                remaining()
                block = stream.read(65536)
                if not block: break
                count += len(block); digest.update(block)
                if count > MANAGED_VERIFIER_LIMIT:
                    raise RuntimeError('managed verifier size refused')
            after = os.fstat(fd); named = MANAGED_VERIFIER.lstat()
            if (count != st.st_size or digest.hexdigest() != MANAGED_VERIFIER_SHA256
                    or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or (named.st_dev, named.st_ino) != (st.st_dev, st.st_ino)):
                raise RuntimeError('managed verifier bytes changed')
        return str(MANAGED_VERIFIER)
    if MANAGED_VERIFIER.exists() or MANAGED_VERIFIER.is_symlink():
        return exact()
    if not allow_download:
        raise RuntimeError('managed verifier missing; existing host state cannot be changed')
    # Only the explicit fresh managed install can publish this immutable prerequisite.
    directory(MANAGED_VERIFIER.parents[2])
    for path in (MANAGED_VERIFIER.parents[1], MANAGED_VERIFIER.parent):
        try: path.mkdir(mode=0o755)
        except FileExistsError: pass
        directory(path)
    dfd = os.open(MANAGED_VERIFIER.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.download-' + uuid.uuid4().hex
    fd = None
    try:
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        child = subprocess.Popen(['/usr/bin/python3.12', '-I', '-S', '-B', '-c', MANAGED_VERIFIER_DOWNLOAD,
                                  str(fd), MANAGED_VERIFIER_URL, str(MANAGED_VERIFIER_LIMIT), str(remaining())],
                                 pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env={'PATH':'/usr/bin:/bin', 'HOME':'/nonexistent', 'LC_ALL':'C'})
        try:
            code = child.wait(timeout=remaining())  # Recompute after process creation.
        except BaseException:
            child.kill(); child.wait()
            raise
        if code != 0:
            raise RuntimeError('managed verifier download failed')
        os.lseek(fd, 0, os.SEEK_SET)
        digest, count = hashlib.sha256(), 0
        while True:
            remaining()
            block = os.read(fd, 65536)
            if not block: break
            count += len(block); digest.update(block)
            if count > MANAGED_VERIFIER_LIMIT:
                raise RuntimeError('managed verifier size refused')
        if count == 0 or digest.hexdigest() != MANAGED_VERIFIER_SHA256:
            raise RuntimeError('managed verifier digest mismatch')
        os.fchmod(fd, 0o555); os.fsync(fd)
        directory(MANAGED_VERIFIER.parent)
        if not os.path.samestat(os.fstat(dfd), MANAGED_VERIFIER.parent.lstat()):
            raise RuntimeError('managed verifier directory changed')
        try:
            os.link(temporary, MANAGED_VERIFIER.name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        except FileExistsError:
            pass  # A concurrent exact publication is checked below; no replacement or retry.
        os.unlink(temporary, dir_fd=dfd); os.fsync(dfd)
        return exact()
    finally:
        if fd is not None:
            try:
                if os.path.samestat(os.fstat(fd), os.stat(temporary, dir_fd=dfd, follow_symlinks=False)):
                    os.unlink(temporary, dir_fd=dfd); os.fsync(dfd)
            except FileNotFoundError:
                pass
            os.close(fd)
        os.close(dfd)


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
            result = subprocess.run([str(python), "-I", *(["-B"] if str(python).startswith("/opt/nodus/managed-local/python/releases/") else []), "-c", COMPATIBILITY_PROBE, str(snapshot),
                                     "recovery" if require_recovery else "normal"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=30, check=False,
                                    env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "HOME":"/root"}
                                    if str(python).startswith("/opt/nodus/managed-local/python/releases/") else None)
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


# Managed installation accepts only the release owner's qualified CPython 3.12 host tuple.
# This does not generate qualification or change the ordinary wheel installation path.
def managed_source_reason(parts):
    if any(p in {'sitecustomize', 'usercustomize'} or p.startswith(('sitecustomize.', 'usercustomize.')) for p in parts):
        return 'startup-customization'
    if any(p == '__pycache__' or p.endswith(('.pyc', '.pyo')) for p in parts):
        return 'bytecode'
    if any(p in {'site-packages', 'dist-packages'} for p in parts):
        return 'foreign-packages'
    if any(p in {'pyvenv.cfg', 'pybuilddir.txt'} or p.endswith(('._pth', '.pth')) for p in parts):
        return 'path-configuration'
    return 'source'


def managed_source_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid)


@contextlib.contextmanager
def managed_sysconfig_target(path, deadline, identities):
    """Open only the distro's exact compatibility pair; never resolve an alias."""
    import stat
    parent = Path('/usr/lib/python3.12')
    name = '_sysconfigdata__linux_x86_64-linux-gnu.py'
    literal = '_sysconfigdata__x86_64-linux-gnu.py'
    if path != parent/name or time.monotonic() >= deadline:
        raise RuntimeError('managed sysconfig source/deadline refused')
    for ancestor in (parent, *parent.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('managed sysconfig ancestry refused')
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_info = os.fstat(directory)
        if (managed_source_identity(parent_info) != managed_source_identity(parent.lstat())
                or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or parent_info.st_mode & 0o022):
            raise RuntimeError('managed sysconfig opened ancestry refused')
        link = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISLNK(link.st_mode) or link.st_uid != 0 or link.st_gid != 0:
            raise RuntimeError('managed sysconfig link identity refused')
        actual = os.readlink(name, dir_fd=directory)
        if actual != literal or link.st_size != len(actual.encode('utf-8')):
            raise RuntimeError('managed sysconfig literal refused')
        # Only after validating the actual literal may the fixed target be opened.
        target = parent/literal
        info = os.stat(literal, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not 0 <= info.st_size <= 64 << 20 or managed_source_reason((literal,)) != 'source'):
            raise RuntimeError('managed sysconfig target refused')
        snapshot = {str(parent):managed_source_identity(parent_info),
                    str(path):managed_source_identity(link), str(target):managed_source_identity(info)}
        if identities and identities != snapshot:
            raise RuntimeError('managed sysconfig acquisition identity changed')
        identities.update(snapshot)
        with os.fdopen(os.open(literal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory), 'rb') as stream:
            if managed_source_identity(os.fstat(stream.fileno())) != snapshot[str(target)]:
                raise RuntimeError('managed sysconfig target changed before read')
            yield stream, link, info, target, actual
            if (time.monotonic() >= deadline
                    or managed_source_identity(os.fstat(stream.fileno())) != snapshot[str(target)]
                    or managed_source_identity(os.stat(literal, dir_fd=directory, follow_symlinks=False)) != snapshot[str(target)]
                    or managed_source_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != snapshot[str(path)]
                    or os.readlink(name, dir_fd=directory) != actual
                    or managed_source_identity(parent.lstat()) != snapshot[str(parent)]):
                raise RuntimeError('managed sysconfig source changed during read')
    finally:
        os.close(directory)


def managed_source_census(destination, deadline, *, identities=None):
    """Observe source bytes/exclusions, with one explicit regular-copy exception."""
    import stat
    source = Path('/usr/lib/python3.12')
    entries, total = [], 0
    identities = {} if identities is None else identities
    def visit(path):
        nonlocal total
        if time.monotonic() >= deadline:
            raise RuntimeError('managed installation acquisition deadline')
        info = path.lstat()
        parts = path.relative_to(source).parts if path != Path('/usr/bin/python3.12') else ()
        reason = managed_source_reason(parts)
        kind = ('directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode)
                else 'symlink' if stat.S_ISLNK(info.st_mode) else None)
        flattened = kind == 'symlink' and path == source/'_sysconfigdata__linux_x86_64-linux-gnu.py'
        if not flattened and (kind is None or (reason == 'source' and (kind == 'symlink' or info.st_uid != 0 or info.st_mode & 0o022))):
            requested = str(path)
            detail = {'path':requested[:512], 'path_truncated':len(requested) > 512,
                      'kind':kind, 'reason':reason, 'uid':info.st_uid, 'gid':info.st_gid,
                      'mode':stat.S_IMODE(info.st_mode), 'file_type':stat.S_IFMT(info.st_mode),
                      'device':info.st_dev, 'inode':info.st_ino,
                      'flags':{'unsupported_type':kind is None,
                               'source_alias':reason == 'source' and kind == 'symlink',
                               'source_uid_not_root':reason == 'source' and info.st_uid != 0,
                               'source_writable':reason == 'source' and bool(info.st_mode & 0o022)}}
            raise RuntimeError('managed Python acquisition alias/type/ownership refused: '
                               + json.dumps(detail, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False))
        target = destination/'lib/python3.12'/Path(*parts) if path != Path('/usr/bin/python3.12') else destination/'bin/python'
        row = {'source':str(path), 'destination':str(target) if reason == 'source' else None,
               'kind':kind, 'disposition':'copied' if reason == 'source' else 'excluded', 'reason':reason,
               'bytes':0 if kind == 'directory' else info.st_size, 'mode':stat.S_IMODE(info.st_mode),
               'uid':info.st_uid, 'gid':info.st_gid, 'sha256':None}
        if reason == 'source' and (kind == 'file' or flattened):
            with contextlib.ExitStack() as stack:
                file_info, file_path = info, path
                if flattened:
                    stream, link, file_info, file_path, literal = stack.enter_context(managed_sysconfig_target(path, deadline, identities))
                    if managed_source_identity(link) != managed_source_identity(info):
                        raise RuntimeError('managed sysconfig link changed before read')
                    row['disposition'] = 'flattened'
                    row['alias'] = {'link_target':literal, 'target':{
                        'path':str(file_path), 'kind':'file', 'bytes':file_info.st_size,
                        'mode':stat.S_IMODE(file_info.st_mode), 'uid':file_info.st_uid,
                        'gid':file_info.st_gid, 'sha256':None}}
                else:
                    stream = stack.enter_context(os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb'))
                if not 0 <= file_info.st_size <= 64 << 20:
                    raise RuntimeError('managed Python acquisition member limit')
                h = hashlib.sha256()
                before = os.fstat(stream.fileno())
                count = 0
                while True:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('managed installation acquisition deadline')
                    block = stream.read(65536)
                    if not block: break
                    count += len(block); h.update(block)
                    if count > file_info.st_size:
                        raise RuntimeError('managed Python source changed')
                after = os.fstat(stream.fileno())
                observed = [managed_source_identity(s) for s in (file_info,before,after,file_path.lstat())]
                if count != file_info.st_size or len(set(observed)) != 1:
                    raise RuntimeError('managed Python source changed')
                total += count  # Includes the second destination's bytes, not only unique targets.
                (row['alias']['target'] if flattened else row)['sha256'] = h.hexdigest()
        entries.append(row)
        if len(entries) > 8192 or total > 512 << 20:
            raise RuntimeError('managed Python acquisition census limit')
        if kind == 'directory':
            for child in sorted(path.iterdir()): visit(child)
    # Ancestors are protected independently of the selectively excluded descendants.
    for path in (source, Path('/usr/bin/python3.12')):
        for parent in path.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError('managed Python acquisition ancestry')
        visit(path)
    by_source = {row['source']:row for row in entries}
    for row in entries:
        if row['disposition'] != 'flattened': continue
        target = row['alias']['target']; ordinary = by_source.get(target['path'], {})
        if (ordinary.get('disposition') != 'copied' or ordinary.get('reason') != 'source'
                or any(ordinary.get(key) != target[key] for key in ('kind','bytes','mode','uid','gid','sha256'))
                or managed_source_identity(Path(target['path']).lstat()) != identities[target['path']]):
            raise RuntimeError('managed sysconfig independent target census mismatch')
        with managed_sysconfig_target(Path(row['source']), deadline, identities):
            pass
    result = {'schema':'managed-python-acquisition.v2', 'source_interpreter':'/usr/bin/python3.12',
              'source_stdlib':str(source), 'private_prefix':str(destination),
              'entries':sorted(entries,key=lambda row:row['source'])}
    if len(json.dumps(result,sort_keys=True,separators=(',',':')).encode()) > 2 << 20:
        raise RuntimeError('managed Python acquisition output limit')
    return result


def managed_installation(prefix, wheel, *, deadline=None, allow_verifier_download=False):
    import stat
    deadline = time.monotonic() + 120 if deadline is None else deadline
    if os.geteuid() != 0:
        raise RuntimeError("managed installation requires root")
    if (prefix != Path('/opt/nodus/managed-local/python') or sys.version_info[:2] != (3,12)
            or Path(sys.executable).resolve() != Path('/usr/bin/python3.12')):
        raise RuntimeError('unqualified managed Python installation tuple')
    release_path = Path('/opt/nodus/managed-local/release.json')
    def protected(path):
        path = Path(path)
        if not path.is_absolute() or str(path) != os.path.normpath(path):
            raise RuntimeError('managed installation path is not canonical')
        for item in (path, *path.parents):
            st = item.lstat()
            if st.st_uid != 0 or stat.S_ISLNK(st.st_mode) or st.st_mode & 0o022:
                raise RuntimeError('managed installation requires protected canonical paths')
        return path
    def read(path, limit):
        path = protected(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                raise RuntimeError('managed installation file limit')
            body = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(body) != st.st_size or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise RuntimeError('managed installation file changed')
            return body
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError('duplicate managed installation key')
            result[key] = value
        return result
    raw = read(release_path, 256 << 10)
    bundle = read(str(release_path) + '.bundle', 1 << 20)
    verifier = managed_verifier(deadline, allow_download=allow_verifier_download)
    verification_time = min(30, deadline - time.monotonic())
    if verification_time <= 0:
        raise RuntimeError('managed installation verification deadline')
    with tempfile.TemporaryDirectory(prefix='nodus-managed-verify-') as folder:
        signed, signature = Path(folder)/'release.json', Path(folder)/'release.bundle'
        signed.write_bytes(raw); signature.write_bytes(bundle)
        subprocess.run([str(verifier), 'verify-blob', '--bundle', str(signature),
                        '--certificate-identity-regexp', r'^https://github\.com/nodus-compute/nodus-platform/\.github/workflows/release\.yml@refs/heads/main$',
                        '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com', str(signed)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env={'PATH':'/usr/bin:/bin', 'HOME':folder, 'TMPDIR':folder, 'LC_ALL':'C'},
                       timeout=verification_time, check=True)
    release = json.loads(raw, object_pairs_hook=unique)
    keys = {'version','policy','files','python_installation','guardian','image_reference','shared','pids','max_claims'}
    if type(release) is not dict or set(release) != keys or type(release['version']) is not int or release['version'] != 2:
        raise RuntimeError('qualified managed release unavailable')
    pin = release['python_installation']
    if type(pin) is not dict or set(pin) != {'path','sha256'}:
        raise RuntimeError('managed installation pin invalid')
    body = read(pin['path'], 2 << 20)
    if hashlib.sha256(body).hexdigest() != pin['sha256']:
        raise RuntimeError('managed installation pin mismatch')
    m = json.loads(body, object_pairs_hook=unique)
    if (type(m) is not dict or set(m) != {'version','wheel_sha256','base_prefix','python_version','qualification_sha256','files','directories','native_links'}
            or type(m['version']) is not int or m['version'] != 2
            or m['python_version'] != '.'.join(map(str, sys.version_info[:3])) or sys.version_info[:2] != (3,12)
            or Path(sys.executable).resolve() != Path('/usr/bin/python3.12')
            or m['wheel_sha256'] != digest(wheel) or prefix != Path('/opt/nodus/managed-local/python')):
        raise RuntimeError('unqualified managed Python installation tuple')
    def sha(value):
        return type(value) is str and len(value) == 64 and value != '0'*64 and all(c in '0123456789abcdef' for c in value)
    if not sha(m['wheel_sha256']) or not sha(m['qualification_sha256']):
        raise RuntimeError('managed installation qualification missing')
    if not (6 <= len(m['files']) <= 8192 and len(m['directories']) <= 2048 and len(m['native_links']) <= 64):
        raise RuntimeError('managed installation census limit')
    venv_root = prefix/'releases'/m['wheel_sha256'][:20]
    if m['base_prefix'] != str(venv_root):
        raise RuntimeError('managed Python private prefix mismatch')
    stdlib, site = venv_root/'lib/python3.12', venv_root/'lib/python3/dist-packages'
    def inside(path):
        return path == venv_root or venv_root in path.parents
    if any(type(m[key]) is not list for key in ('files','directories','native_links')):
        raise RuntimeError('managed installation census invalid')
    rows, links = {}, {}
    previous, total = '', 0
    for row in m['files']:
        if (type(row) is not dict or set(row) != {'path','sha256','bytes'} or row['path'] <= previous
                or not Path(row['path']).is_absolute() or os.path.normpath(row['path']) != row['path']
                or not sha(row['sha256']) or type(row['bytes']) is not int or not 0 <= row['bytes'] <= 64 << 20):
            raise RuntimeError('managed installation file set invalid')
        previous = row['path']; total += row['bytes']; rows[row['path']] = row
    if total > 512 << 20:
        raise RuntimeError('managed installation byte limit')
    previous = ''
    for link in m['native_links']:
        if (type(link) is not dict or set(link) != {'path','target'} or link['path'] <= previous
                or not Path(link['path']).is_absolute() or os.path.normpath(link['path']) != link['path']
                or not link['target'] or inside(Path(link['path'])) or str(link['path']).startswith(str(prefix)+'/')):
            raise RuntimeError('managed native link invalid')
        previous = link['path']; links[link['path']] = link['target']
    def native_path(path):
        path = Path(path)
        for _ in range(41):
            parts, at = path.parts[1:], Path('/')
            for index, part in enumerate(parts):
                at = at/part; st = at.lstat()
                if st.st_uid != 0:
                    raise RuntimeError('managed native dependency owner')
                if stat.S_ISLNK(st.st_mode):
                    target = os.readlink(at)
                    if links.get(str(at)) != target:
                        raise RuntimeError('unlisted managed native alias')
                    target = Path(target) if target.startswith('/') else at.parent/target
                    path = Path(os.path.normpath(target.joinpath(*parts[index+1:])))
                    break
                if st.st_mode & 0o022:
                    raise RuntimeError('managed native dependency mode')
            else:
                return path
        raise RuntimeError('managed native alias cycle')
    def check(final):
        physical = set()
        for name, row in rows.items():
            if time.monotonic() >= deadline:
                raise RuntimeError('managed installation verification deadline')
            path = Path(name)
            if not final and (path == venv_root or venv_root in path.parents):
                continue
            if inside(path):
                if managed_source_reason(path.relative_to(venv_root).parts) != 'source' and not (site in path.parents and managed_source_reason(path.relative_to(site).parts) == 'source'):
                    raise RuntimeError('managed Python startup injection')
            elif path != Path('/usr/bin/python3.12'):
                path = native_path(path)
            if path in physical:
                raise RuntimeError('duplicate managed native file')
            physical.add(path)
            body = read(path, 64 << 20)
            if len(body) != row['bytes'] or hashlib.sha256(body).hexdigest() != row['sha256']:
                raise RuntimeError('managed Python file mismatch')
        for name in links:
            target = native_path(name)
            if not target.is_dir() and target not in physical:
                raise RuntimeError('unbound managed native alias')
        for absent in (venv_root/'lib/python312.zip', stdlib/'site-packages', stdlib/'dist-packages', venv_root/'local', Path('/etc/ld.so.preload')):
            if absent.exists() or absent.is_symlink():
                raise RuntimeError('unlisted managed Python startup path')
        roots = (venv_root,) if final else ()
        expected_dirs = m['directories']
        if expected_dirs != sorted(set(expected_dirs)) or any(not inside(Path(p)) for p in expected_dirs):
            raise RuntimeError('managed Python directory set invalid')
        for root in roots:
            actual_files, actual_dirs = set(), {str(root)}
            protected(root)
            def walk_failed(_error):
                raise RuntimeError('managed Python directory unavailable')
            for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_failed):
                if time.monotonic() >= deadline:
                    raise RuntimeError('managed installation verification deadline')
                for name in dirs + files:
                    path = protected(Path(directory)/name)
                    relative = path.relative_to(site).parts if path == site or site in path.parents else path.relative_to(venv_root).parts
                    if managed_source_reason(relative) != 'source':
                        raise RuntimeError('managed Python startup injection')
                    (actual_dirs if path.is_dir() else actual_files).add(str(path))
            if actual_dirs != {p for p in expected_dirs if p == str(root) or p.startswith(str(root)+'/')} or actual_files != {p for p in rows if p.startswith(str(root)+'/')}:
                raise RuntimeError('managed Python import tree mismatch')
        required = (venv_root/'bin/python', venv_root/'bin/nodus-dc', Path('/usr/bin/python3.12'), site/'nodus_dc/__main__.py', site/'nodus_dc/__init__.py', stdlib/'site.py', stdlib/'os.py', stdlib/'encodings/__init__.py', Path('/etc/ld.so.cache'))
        if any(str(p) not in rows for p in required):
            raise RuntimeError('managed Python required file missing')
        interpreter = release['files'].get('python')
        if interpreter != {'path':str(venv_root/'bin/python'),'sha256':rows[str(venv_root/'bin/python')]['sha256']} or interpreter['sha256'] != rows['/usr/bin/python3.12']['sha256']:
            raise RuntimeError('managed Python interpreter mismatch')
    source_identities = {}
    acquisition = managed_source_census(venv_root, deadline, identities=source_identities)
    copied = {}
    for row in acquisition['entries']:
        value = row['alias']['target'] if row['disposition'] == 'flattened' else row
        if row['disposition'] in {'copied','flattened'} and value['kind'] == 'file':
            copied[row['destination']] = {'path':row['destination'],'sha256':value['sha256'],'bytes':value['bytes']}
    expected_source = {path:row for path,row in rows.items() if path == str(venv_root/'bin/python') or path.startswith(str(stdlib)+'/')}
    if copied != expected_source:
        raise RuntimeError('managed Python source differs from qualified copy')
    check(False)
    return {'root':venv_root,'site':site,'rows':rows,'check':check,'pin':pin,'acquisition':acquisition,'source_identities':source_identities,'deadline':deadline}


def install_managed_wheel(wheel, prepared):
    destination, site = prepared['root'], prepared['site']
    # This wheel has no dependencies or install-time hooks. Every file comes from its signed byte map.
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 256:
            raise RuntimeError('managed wheel member set invalid')
        expected = {str(Path(n).relative_to(site)): row for n, row in prepared['rows'].items() if Path(n).is_relative_to(site)}
        if set(names) != set(expected):
            raise RuntimeError('managed wheel differs from qualified package set')
        bodies = {}
        for item in archive.infolist():
            name = item.filename
            if (name.startswith('/') or '..' in Path(name).parts or item.is_dir()
                    or item.file_size > 1 << 20 or (item.external_attr >> 16) & 0o170000 not in {0,0o100000}):
                raise RuntimeError('managed wheel unsafe member')
            body = archive.read(name)
            bodies[name] = body
            if sum(map(len, bodies.values())) > 4 << 20:
                raise RuntimeError('managed wheel total byte limit')
            row = expected[name]
            if len(body) != row['bytes'] or hashlib.sha256(body).hexdigest() != row['sha256']:
                raise RuntimeError('managed wheel byte mismatch')
        # The prefix is independent from host site initialization, not a venv pointing back to /usr.
        deadline = prepared['deadline']
        source_identities = {}
        acquisition = managed_source_census(destination, deadline, identities=source_identities)
        if acquisition != prepared['acquisition'] or source_identities != prepared['source_identities']:
            raise RuntimeError('managed Python acquisition changed before copy')
        destination.mkdir(parents=True, mode=0o755)
        (destination/'bin').mkdir(mode=0o755)
        for row in acquisition['entries']:
            if row['disposition'] not in {'copied','flattened'}: continue
            if time.monotonic() >= deadline:
                raise RuntimeError('managed installation copy deadline')
            path = Path(row['destination'])
            if row['kind'] == 'directory':
                path.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with contextlib.ExitStack() as stack:
                expected = row
                if row['disposition'] == 'flattened':
                    source, _, _, _, _ = stack.enter_context(managed_sysconfig_target(Path(row['source']), deadline, source_identities))
                    expected = row['alias']['target']
                else:
                    source = stack.enter_context(os.fdopen(os.open(row['source'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb'))
                info = os.fstat(source.fileno())
                import stat
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size != expected['bytes']:
                    raise RuntimeError('managed Python copy source changed')
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if path == destination/'bin/python' else 0o644)
                with os.fdopen(fd,'wb') as stream:
                    h, count = hashlib.sha256(), 0
                    while True:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('managed installation copy deadline')
                        block = source.read(65536)
                        if not block: break
                        count += len(block); h.update(block)
                        if count > expected['bytes']: raise RuntimeError('managed Python copy exceeded census')
                        stream.write(block)
                    stream.flush(); os.fsync(stream.fileno())
                if count != expected['bytes'] or h.hexdigest() != expected['sha256']:
                    raise RuntimeError('managed Python copy bytes changed')
                if managed_source_identity(os.fstat(source.fileno())) != managed_source_identity(info):
                    raise RuntimeError('managed Python copy identity changed')
                source_name = expected['path'] if row['disposition'] == 'flattened' else row['source']
                if source_name in source_identities and managed_source_identity(info) != source_identities[source_name]:
                    raise RuntimeError('managed sysconfig copied target identity changed')
        if managed_source_census(destination, deadline, identities=dict(source_identities)) != acquisition:
            raise RuntimeError('managed Python source changed before publication')
        for name in names:
            path = site/name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd,'wb') as stream:
                stream.write(bodies[name]); stream.flush(); os.fsync(stream.fileno())
    # Same public console entry point; managed runtime itself uses the pinned interpreter with -m.
    script = destination/'bin/nodus-dc'
    with script.open('x') as stream:
        stream.write('#!'+str(destination/'bin/python')+' -IB\nfrom nodus_dc.cli import main\nraise SystemExit(main())\n')
        stream.flush(); os.fsync(stream.fileno())
    script.chmod(0o755)
    prepared['check'](True)


def lock_managed_installation(prefix, state):
    import stat
    handles = []
    def acquire(path, create=False):
        for parent in path.parents:
            st = parent.lstat()
            if st.st_uid != 0 or not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
                raise RuntimeError("managed installation lock ancestry")
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_CREAT if create else 0), 0o600)
        stream = os.fdopen(fd, 'r+b'); handles.append(stream)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise RuntimeError("managed installation lock identity")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("stop the managed host session before changing installation") from None
    try:
        if prefix != Path('/opt/nodus/managed-local/python') or state.name != 'authority':
            raise RuntimeError("managed installation state must be its host directory/authority")
        acquire(prefix.parent/'python-install.lock', True)
        if state.parent.exists() or state.parent.is_symlink():
            acquire(state.parent/'owner.lock')
            if state.exists() or state.is_symlink():
                for name in ('daemon.lock','host.lock'):
                    acquire(state/name)
        return handles
    except BaseException:
        for stream in handles:
            stream.close()
        raise

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["install", "activate", "uninstall"])
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--wheel")
    parser.add_argument("--release")
    parser.add_argument("--managed", action="store_true", help="install the same wheel against the installed signed managed-runtime qualification; missing qualification refuses")
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
    existing = read_manifest(prefix, state)
    if existing and existing.get('managed') and not args.managed:
        raise RuntimeError("use --managed for this paired installation")
    if args.managed and not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise RuntimeError("start managed installation with /usr/bin/python3.12 -I -S -B install.py")
    if args.managed and (args.action not in {"install", "uninstall"} or args.recovery_upgrade):
        raise RuntimeError("managed activation requires install with the qualified wheel")
    deadline = time.monotonic() + 120
    if not args.managed:
        preflight_candidate(args, prefix, state)
    locks = lock_managed_installation(prefix, state) if args.managed else lock_state(state, recovery_upgrade=args.recovery_upgrade)
    try:
        try:
            args.managed_install = managed_installation(prefix, Path(args.wheel or "").resolve(), deadline=deadline,
                allow_verifier_download=not (state.parent.exists() or state.parent.is_symlink())) if args.managed and args.action == "install" else None
        except (KeyError, TypeError, AttributeError):
            raise RuntimeError("invalid qualified managed installation contract") from None
        return install_locked(args, prefix, state)
    finally:
        for handle in locks:
            handle.close()


def install_locked(args, prefix, state):
    # Recheck the requested target before pending-install recovery or any prefix
    # mutation. A CLI connection opt-in may have committed after the early read.
    if not getattr(args, "managed_install", None):
        preflight_candidate(args, prefix, state)
    # Another installer may have completed between the early probe and locks.
    manifest = read_manifest(prefix, state)
    if getattr(args, "managed", False) and state.parent.exists():
        prepared = getattr(args, "managed_install", None)
        release = prepared['root'].name if prepared else None
        if (args.action != "install" or not manifest or not manifest.get('managed')
                or manifest.get('pending') is not None or manifest.get('active_release') != release
                or manifest.get('releases', {}).get(release, {}).get('wheel_sha256') != digest(Path(args.wheel))
                or not (prefix/'current').is_symlink() or os.readlink(prefix/'current') != 'releases/'+release):
            raise RuntimeError("managed host state exists; replacement or removal requires separately qualified migration")
        prepared['check'](True)
        print(json.dumps({'installed':True, 'unchanged':True, 'release':release,
                          'state_preserved':str(state), 'service_started':False}))
        return 0
    if manifest is None:
        if args.action != "install":
            raise RuntimeError("a new install requires an empty dedicated prefix")
        manifest = initialize_prefix(prefix, state)
    if getattr(args, "managed", False):
        manifest['managed'] = True
        save_manifest(prefix, manifest)
    pending = manifest.get("pending") or {}
    if args.recovery_upgrade and pending.get("kind") == "uninstall":
        raise RuntimeError("recovery upgrade cannot resume an interrupted uninstall")
    if args.recovery_upgrade and pending.get("kind") == "activate" and not pending.get("recovery_upgrade"):
        raise RuntimeError("an earlier ordinary activation must be resolved after clean release")
    if getattr(args, "managed_install", None) and pending.get("kind") == "activate":
        if pending.get("release") != args.managed_install['root'].name:
            raise RuntimeError("managed activation belongs to another release")
        args.managed_install['check'](True)
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
            if getattr(args, "managed_install", None):
                install_managed_wheel(wheel, args.managed_install)
            else:
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
    if getattr(args, "managed_install", None):
        args.managed_install['check'](True)
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
