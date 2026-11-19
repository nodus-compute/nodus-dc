"""Opt-in Linux component arm of the existing distribution journey.

This measures one actual OS/Python/wheel tuple in private mount/PID namespaces.
The installer signature subprocess is an explicit seam, never a fake verifier
executable. A PASS is neither a signature nor managed-provider qualification.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile


PYTHON = "/usr/bin/python3.12"
PREFIX = Path("/opt/nodus/managed-local/python")
STDLIB = Path("/usr/lib/python3.12")
OUTPUTS = ("receipt.json", "python-installation.json", "import-closure.json", "package.whl",
           "source-manifest.json", "census.json", "refusals.json", "closure.json",
           "raw/console.json", "raw/serve.json", "raw/status.json", "raw/native.json")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
       "PYTHONDONTWRITEBYTECODE": "1"}
MAX_OUTPUT = 16 << 20


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def put(path, value):
    body = value if isinstance(value, bytes) else canonical(value)
    require(len(body) <= 4 << 20, "component individual output bound")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())


def read(path, limit=64 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "component regular file bound")
        body = stream.read(limit + 1); after = os.fstat(fd)
    require(len(body) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "component file changed")
    return body


def protected(path, *, private=False, stage="component-path"):
    require(path.is_absolute() and str(path) == os.path.normpath(path), "noncanonical component path")
    for item in (path, *path.parents):
        info = item.lstat()
        try:
            require(info.st_uid == 0 and info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                    and not info.st_mode & 0o022, "unprotected component path")
        except RuntimeError:
            detail = {"stage": stage, "requested_path": str(path)[:512],
                      "requested_path_truncated": len(str(path)) > 512,
                      "offending_ancestor": str(item)[:512],
                      "ancestor_path_truncated": len(str(item)) > 512,
                      "uid": info.st_uid, "gid": info.st_gid,
                      "mode": stat.S_IMODE(info.st_mode), "file_type": stat.S_IFMT(info.st_mode),
                      "inode": info.st_ino,
                      "conditions": {"root_uid": info.st_uid == 0, "root_gid": info.st_gid == 0,
                                     "not_symlink": not stat.S_ISLNK(info.st_mode),
                                     "not_group_or_world_writable": not info.st_mode & 0o022}}
            raise RuntimeError("unprotected component path: " + json.dumps(detail, sort_keys=True)) from None
    if private:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                "component input ownership")


def input_record(path, expected):
    protected(path, private=True, stage="component-input"); body = read(path, 16 << 10)
    require(sha(body) == expected, "component input hash")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate component input key"); result[key] = value
        return result
    value = json.loads(body, object_pairs_hook=unique)
    require(set(value) == {"schema", "platform_head", "python_head", "python_tree", "source_manifest_sha256",
                          "target_kind", "target_identity", "expected_os_release_sha256",
                          "expected_package_census_sha256", "output_directory"}, "component input fields")
    require(value["schema"] == "managed-python-component-input.v1", "component input schema")
    for key in ("platform_head", "python_head", "python_tree", "source_manifest_sha256"):
        require(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{" + ("64" if key.endswith("sha256") else "40") + "}", value[key]), "component source pin")
    for key in ("expected_os_release_sha256", "expected_package_census_sha256"):
        require(value[key] is None or isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{64}", value[key]), "component expected tuple")
    require(value["target_kind"] in {"hosted-runner", "provider-image"}
            and isinstance(value["target_identity"], str) and re.fullmatch(r"[ -~]{1,160}", value["target_identity"]), "component target provenance")
    out = Path(value["output_directory"])
    require(out.parent == Path("/run") and re.fullmatch(r"nodus-managed-components-[a-z0-9-]{8,80}", out.name), "component output scope")
    require(len(str(out/"work/local.sock").encode()) < 108, "component Unix socket path bound")
    return value


def start_ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def namespaces():
    return {name: os.readlink("/proc/self/ns/" + name) for name in ("mnt", "pid")}


class Commands:
    """Every child shares one deadline; forced termination is always negative."""
    def __init__(self, work, end):
        self.work, self.end, self.children, self.records = work, end, [], []
        work.mkdir(mode=0o700)
        temporary = work.parent/"tmp"; temporary.mkdir(mode=0o700, exist_ok=True)
        self.environment = {**ENV, "TMPDIR": str(temporary)}

    def left(self, cap=15):
        value = min(cap, (self.end - time.monotonic_ns()) / 1e9)
        require(value > 0, "original component deadline expired")
        return value

    def run(self, argv, *, cwd=None, ready=False, cap=15):
        self.left(cap)
        index = len(self.children); out = self.work/f"command-{index}.out"; err = self.work/f"command-{index}.err"
        with out.open("xb") as stdout, err.open("xb") as stderr:
            proc = subprocess.Popen(argv, cwd=cwd, env=self.environment, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, start_new_session=True)
            row = {"pid": proc.pid, "start_ticks": start_ticks(proc.pid), "argv_sha256": sha(canonical(argv)),
                   "returncode": None, "waited": False}
            self.children.append(row); natural = True; observed = None; maps = None
            end = min(self.end, time.monotonic_ns() + int(cap * 1e9))
            try:
                if ready:
                    while True:
                        self.left()
                        require(time.monotonic_ns() < end and proc.poll() is None, "observe serve did not become ready")
                        try:
                            with out.open("rb") as stream:
                                snapshot = stream.read((64 << 10) + 1)
                            require(len(snapshot) <= 64 << 10, "component serve output bound")
                            observed = json.loads(snapshot)
                            break
                        except json.JSONDecodeError:
                            time.sleep(0.02)
                    require(observed.get("bridge_enabled") is False and "prepared_provider" not in observed,
                            "component serve exposed managed authority")
                    maps = Path(f"/proc/{proc.pid}/maps").read_text()
                    proc.send_signal(signal.SIGINT)
                else:
                    maps = None
                proc.wait(timeout=max(0.001, (end - time.monotonic_ns()) / 1e9))
            except (subprocess.TimeoutExpired, RuntimeError):
                natural = False
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait(timeout=10)
            finally:
                row.update(returncode=proc.returncode, waited=proc.returncode is not None)
                # Persist partial process custody even if a later assertion fails.
                (self.work/"children.json").write_bytes(canonical(self.children))
        body, errors = read(out, 4 << 20), read(err, 4 << 20)
        record = {"argv": argv, "returncode": proc.returncode, "natural": natural,
                  "stdout": body.decode(), "stderr": errors.decode(), "observed_ready": observed, "maps": maps}
        self.records.append(record)
        try: os.killpg(proc.pid, 0)
        except ProcessLookupError: pass
        else: raise RuntimeError("component child left a process group")
        require(natural, "component child required forced termination")
        require(sum(p.stat().st_size for p in self.work.glob("command-*.*")) <= MAX_OUTPUT, "component command output total")
        return record


def source_manifest(root, commands):
    def git(*args):
        result = commands.run(["/usr/bin/git", "-C", str(root), *args])
        require(result["returncode"] == 0, "component Git custody"); return result["stdout"]
    head, tree = git("rev-parse", "HEAD").strip(), git("rev-parse", "HEAD^{tree}").strip()
    rows = []
    for entry in git("ls-tree", "-rz", "HEAD").split("\0"):
        if not entry: continue
        metadata, name = entry.split("\t", 1); mode, kind, obj = metadata.split()
        require(mode in {"100644", "100755"} and kind == "blob" and ".." not in Path(name).parts,
                "component source member")
        file = root/name; info = file.lstat(); body = read(file)
        require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111) == (mode == "100755"), "component source mode")
        require(hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == obj, "component source Git bytes")
        rows.append({"path": name, "mode": mode, "git_object": obj, "sha256": sha(body), "bytes": len(body)})
    require(not git("status", "--porcelain", "--untracked-files=no"), "component tracked source dirty")
    rows.sort(key=lambda row: row["path"])
    return {"schema": "managed-python-source-manifest.v1", "head": head, "tree": tree,
            "files": rows, "total_bytes": sum(row["bytes"] for row in rows)}


def pointer(root, relative):
    return {"path": "components/" + relative, "sha256": sha(read(root/relative, MAX_OUTPUT))}


def installer(root):
    spec = importlib.util.spec_from_file_location("component_installer", root/"tools/install.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def signature_seam(module, release_body):
    """Only verify-blob is intercepted, in this isolated test process.

    The real parser/census/refusal code and canonical verifier hash run unchanged.
    The owner supplies the official pinned executable; no substitute executable,
    valid signature bundle or production-qualified release leaves this namespace.
    """
    real_run = module.subprocess.run
    def verify(argv, **kwargs):
        require(len(argv) == 9 and argv[0] == str(module.MANAGED_VERIFIER) and argv[1:3] == ["verify-blob", "--bundle"]
                and argv[4:8] == ["--certificate-identity-regexp", r"^https://github\.com/nodus-compute/nodus-platform/\.github/workflows/release\.yml@refs/heads/main$",
                                  "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"]
                and read(Path(argv[8])) == release_body and read(Path(argv[3])) == b"component-signature-seam\n",
                "unexpected installer signature boundary")
        return subprocess.CompletedProcess(argv, 0)
    module.subprocess.run = verify
    return real_run


def verify_install(root, wheel):
    module = installer(root); body = read(Path("/opt/nodus/managed-local/release.json"))
    real_run = signature_seam(module, body)
    try:
        prepared = module.managed_installation(PREFIX, wheel)
        prepared["check"](True)
    finally:
        module.subprocess.run = real_run


def import_probe():
    """Companion census; actual -m console/serve/status are separate commands."""
    import importlib
    import nodus_dc
    package = Path(nodus_dc.__file__).parent
    for file in sorted(package.rglob("*.py")):
        relative = file.relative_to(package).with_suffix("")
        if relative.name == "__main__": continue  # Actual -m probes own this entry.
        parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
        importlib.import_module(".".join(("nodus_dc", *parts)))
    origins = {}
    for name, module in sorted(sys.modules.items()):
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if isinstance(origin, str) and origin.startswith("/"):
            origins[name] = origin
    print(json.dumps({"python_executable": sys.executable, "prefix": sys.prefix, "base_prefix": sys.base_prefix,
                      "sys_path": sys.path, "module_origins": origins,
                      "maps": Path("/proc/self/maps").read_text()}, sort_keys=True), flush=True)


def tree_census(roots, commands):
    files, dirs = {}, set()
    for root in roots:
        stage = "stdlib-census" if root == STDLIB else "site-census"
        protected(root, stage=stage); dirs.add(str(root))
        for directory, children, leaves in os.walk(root, followlinks=False):
            commands.left()
            for name in children + leaves:
                file = Path(directory)/name; protected(file, stage=stage)
                info = file.lstat()
                if stat.S_ISDIR(info.st_mode): dirs.add(str(file))
                else:
                    body = read(file); files[str(file)] = {"path": str(file), "sha256": sha(body), "bytes": len(body)}
            require(len(files) <= 8192 and len(dirs) <= 2048, "component import census bound")
    return files, dirs


def native_census(seeds, commands):
    """Resolve every DT_NEEDED and ELF interpreter, including all stdlib .so files."""
    files, links, dependencies, pending, seen = {}, {}, [], list(sorted(seeds)), set()
    cache = commands.run(["/sbin/ldconfig", "-p"])
    require(cache["returncode"] == 0, "native loader cache unavailable")
    candidates = {}
    for line in cache["stdout"].splitlines():
        match = re.fullmatch(r"\s*(\S+) \(([^)]+)\) => (/\S+)", line)
        if match and "x86-64" in match[2]: candidates.setdefault(match[1], []).append(match[3])
    def resolve(name):
        path = Path(name)
        for _ in range(41):
            at = Path("/"); parts = path.parts[1:]
            for index, part in enumerate(parts):
                at /= part; info = at.lstat()
                require(info.st_uid == 0 and not (info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode)), "native path protection")
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(at); links[str(at)] = target
                    joined = Path(target) if target.startswith("/") else at.parent/target
                    path = Path(os.path.normpath(joined.joinpath(*parts[index+1:])))
                    break
            else: return path
        raise RuntimeError("native alias cycle")
    while pending:
        commands.left(); name = pending.pop(); path = resolve(name)
        if str(path) in seen: continue
        seen.add(str(path)); body = read(path)
        files[str(path)] = {"path": str(path), "sha256": sha(body), "bytes": len(body)}
        if body[:4] != b"\x7fELF": continue
        require(body[4:6] == b"\x02\x01" and int.from_bytes(body[18:20], "little") == 62, "native ELF ABI")
        result = commands.run(["/usr/bin/readelf", "-W", "-l", "-d", str(path)])
        require(result["returncode"] == 0, "native ELF metadata")
        text = result["stdout"]
        search = []
        for raw in re.findall(r"\((?:RUNPATH|RPATH)\).*?\[([^]]*)\]", text):
            for value in raw.split(":"):
                value = value.replace("${ORIGIN}", str(path.parent)).replace("$ORIGIN", str(path.parent))
                require(value.startswith("/") and "$" not in value, "unqualified native search path")
                search.append(value)
        required = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", text)
        loader = re.findall(r"Requesting program interpreter: ([^]]+)\]", text)
        for dependency in required + loader:
            options = ([dependency] if dependency.startswith("/") else
                       [str(Path(directory)/dependency) for directory in search if (Path(directory)/dependency).exists()]
                       or candidates.get(dependency, []))
            require(options, "unresolved native dependency")
            # Retain loader search order and exact selected physical byte identity.
            resolved = {str(resolve(option)) for option in options}
            require(len(resolved) == 1, "ambiguous native loader-cache candidates")
            target = Path(next(iter(resolved)))
            dependencies.append({"source": str(path), "name": dependency, "path": str(target)})
            pending.append(str(target))
        require(len(links) <= 64 and len(files) <= 8192, "native census bound")
    return files, [{"path": p, "target": t} for p, t in sorted(links.items())], dependencies


def mapped_paths(text):
    result = set()
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith("/"):
            require(not fields[5].endswith(" (deleted)"), "deleted mapped component")
            result.add(fields[5])
    return result


def namespace_measure(root, value, end, parent_ns):
    os.umask(0o077)
    out = Path(value["output_directory"]); components, work = out/"components", out/"work"
    commands = Commands(work/"child", end)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
    def expired(_signum, _frame):
        raise TimeoutError("original component deadline expired")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, commands.left(240))
    require(os.geteuid() == 0 and platform.machine() == "x86_64" and sys.version_info[:2] == (3, 12), "component Linux root/Python tuple")
    require(all(namespaces()[key] != parent_ns[key] for key in parent_ns), "component namespace isolation")
    require(commands.run(["/usr/bin/mount", "--make-rprivate", "/"])["returncode"] == 0, "private mount propagation")
    mounts = []
    for index, target in enumerate(("/usr", "/etc", "/opt", "/var/lib")):
        upper, scratch = work/f"upper-{index}", work/f"overlay-{index}"
        upper.mkdir(mode=0o700); scratch.mkdir(mode=0o700)
        result = commands.run(["/usr/bin/mount", "-t", "overlay", "overlay", "-o",
                               f"lowerdir={target},upperdir={upper},workdir={scratch}", target])
        require(result["returncode"] == 0, "component overlay unavailable")
        mounts.append(target)
    mountinfo = Path("/proc/self/mountinfo").read_text()
    require(all(any(line.split()[4] == target and " - overlay " in line for line in mountinfo.splitlines())
                for target in mounts), "component overlay observation")
    wheel = components/"package.whl"; wheel_sha = sha(read(wheel, 4 << 20))
    destination = PREFIX/"releases"/wheel_sha[:20]; site = destination/"lib/python3.12/site-packages"
    require(not PREFIX.exists(), "component canonical installation already exists")
    require(not Path("/var/lib/nodus-dc-authority/fence.json").exists()
            and not Path("/var/lib/nodus-dc/authority-path.json").exists(), "existing physical authority is outside component scope")
    # Controlled assembly calls the actual copy/no-pip installer. Its measured
    # qualification does not exist yet, so only the wheel-byte check is supplied
    # at this internal assembly seam. The unchanged full checker runs below.
    with zipfile.ZipFile(wheel) as archive:
        require(len(archive.infolist()) <= 256, "component wheel count")
        wheel_rows = {}
        for item in archive.infolist():
            require(not item.filename.startswith("/") and ".." not in Path(item.filename).parts
                    and not item.is_dir() and item.file_size <= 1 << 20, "component wheel member")
            body = archive.read(item)
            wheel_rows[str(site/item.filename)] = {"path": str(site/item.filename), "sha256": sha(body), "bytes": len(body)}
        require(len(wheel_rows) == len(archive.infolist()) and sum(row["bytes"] for row in wheel_rows.values()) <= 4 << 20,
                "component wheel total")
    def assembled(final):
        require(final and read(destination/"bin/python") == read(Path(PYTHON)), "component interpreter copy")
        for name, row in wheel_rows.items():
            body = read(Path(name)); require(len(body) == row["bytes"] and sha(body) == row["sha256"], "component assembled wheel")
    installer(root).install_managed_wheel(wheel, {"root": destination, "site": site, "rows": wheel_rows, "check": assembled})
    commands.left()
    python = str(destination/"bin/python")
    console = commands.run([str(destination/"bin/nodus-dc"), "--version"])
    module_console = commands.run([python, "-I", "-B", "-v", "-m", "nodus_dc", "--version"])
    require(console["returncode"] == module_console["returncode"] == 0
            and console["stdout"] == module_console["stdout"], "component public console")
    state = work/"observe-state"; state.mkdir(mode=0o700)
    serve = commands.run([python, "-I", "-B", "-v", "-m", "nodus_dc", "--state-dir", str(state),
                          "--allocation-authority", "observe", "serve", "--port", "0", "--local-socket", str(work/"local.sock")], ready=True)
    require(serve["returncode"] == 0, "component observe serve natural stop")
    status = commands.run([python, "-I", "-B", "-v", "-m", "nodus_dc", "--state-dir", str(state), "status"])
    require(status["returncode"] == 0, "component observe status")
    status_body = json.loads(status["stdout"])
    require(status_body["leases"] == [] and status_body["hardware_qualified"] is False
            and not (status_body.get("bridge_policy") or {}).get("enabled"), "component status created authority")
    require(not Path("/var/lib/nodus-dc-authority/fence.json").exists()
            and not Path("/var/lib/nodus-dc/authority-path.json").exists(), "component authority absence")
    probe = commands.run([python, "-I", "-B", str(Path(__file__).resolve()), "probe"])
    require(probe["returncode"] == 0, "component complete package import")
    imports = json.loads(probe["stdout"])
    require(imports["python_executable"] == python and imports["prefix"] == str(destination)
            and imports["base_prefix"] == "/usr", "component actual interpreter roots")
    allowed_path = {"/usr/lib/python312.zip", str(STDLIB), str(STDLIB/"lib-dynload"), str(site)}
    require(set(imports["sys_path"]) == allowed_path and len(imports["sys_path"]) == len(allowed_path), "component isolated sys.path")
    files, dirs = tree_census((STDLIB, site), commands)
    for name in (destination/"bin/python", destination/"bin/nodus-dc", destination/"pyvenv.cfg", Path(PYTHON), Path("/etc/ld.so.cache")):
        protected(name, stage="interpreter-and-cache"); body = read(name); files[str(name)] = {"path": str(name), "sha256": sha(body), "bytes": len(body)}
    # Python's verbose importer supplies origins for the real -m paths. The
    # companion imports all shipped modules; neither alone is a dynamic-path proof.
    trace_origins = set()
    for record in (module_console, serve, status):
        trace_origins.update(re.findall(r"^# (/[\S ]+?)(?: matches | has bad |$)", record["stderr"], re.M))
        trace_origins.update(re.findall(r"^# code object from '?(/[^\n']+)'?$", record["stderr"], re.M))
        trace_origins.update(re.findall(r"extension module '[^']+' loaded from '(/[^']+)'", record["stderr"]))
    origins = set(imports["module_origins"].values()) | trace_origins
    require(origins and all(path in files for path in origins), "component import origin escaped complete census")
    mapped = mapped_paths(imports["maps"]) | mapped_paths(serve["maps"])
    seeds = {name for name in files if name.endswith(".so") or ".so." in name} | mapped | {PYTHON, python, "/etc/ld.so.cache"}
    native, links, dependencies = native_census(seeds, commands)
    files.update(native)
    require(all(str(Path(name).resolve()) in files for name in mapped), "mapped native file outside census")
    require(len(files) <= 8192 and len(dirs) <= 2048 and sum(row["bytes"] for row in files.values()) <= 512 << 20, "component complete closure bound")
    packages = commands.run(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"])
    require(packages["returncode"] == 0, "component package census")
    target = {"kind": value["target_kind"], "identity": value["target_identity"], "machine": platform.machine(),
              "kernel_release": platform.release(), "python_version": platform.python_version(),
              "base_python_sha256": files[PYTHON]["sha256"], "native_census_sha256": sha(canonical({"files": sorted(native.values(), key=lambda r:r["path"]), "native_links": links})),
              "os_release_sha256": sha(read(Path("/etc/os-release").resolve())), "package_census_sha256": sha(packages["stdout"].encode()),
              "stdlib_census_sha256": sha(canonical({"files": [files[p] for p in sorted(files) if p.startswith(str(STDLIB)+"/")],
                                                       "directories": sorted(p for p in dirs if p == str(STDLIB) or p.startswith(str(STDLIB)+"/"))}))}
    for key in ("os_release_sha256", "package_census_sha256"):
        expected = value["expected_" + key]
        require(expected is None or expected == target[key], "component target byte mismatch")
    put(components/"raw/console.json", {"console": console, "module": module_console})
    put(components/"raw/serve.json", serve); put(components/"raw/status.json", status)
    put(components/"raw/native.json", {"companion_import_probe": probe, "readelf_and_cache": [r for r in commands.records if r["argv"][0] in {"/usr/bin/readelf", "/sbin/ldconfig"}],
                                       "packages": packages, "parent_namespaces": parent_ns, "child_namespaces": namespaces(),
                                       "mountinfo": mountinfo, "os_release": read(Path("/etc/os-release").resolve()).decode(),
                                       "actual_entry_import_origins": sorted(trace_origins)})
    raw_refs = [pointer(components, "raw/" + name + ".json") for name in ("console", "serve", "status", "native")]
    measured = {"schema": "managed-python-import-closure.v1", "python_head": value["python_head"], "python_tree": value["python_tree"],
                "wheel_sha256": wheel_sha, "target_tuple": target, **{key: imports[key] for key in ("python_executable", "prefix", "base_prefix", "sys_path", "module_origins")},
                "elf_dependencies": dependencies, "mapped_libraries": sorted(mapped), "raw_refs": raw_refs,
                "all_resolved_within_census": True, "scope": "python-os-import-native-components",
                "managed_provider_execution": False, "host_lifecycle_qualified": False}
    put(components/"import-closure.json", measured)
    manifest = {"version": 1, "wheel_sha256": wheel_sha, "base_prefix": "/usr", "python_version": target["python_version"],
                "qualification_sha256": sha(canonical(measured)), "files": [files[p] for p in sorted(files)],
                "directories": sorted(dirs), "native_links": links}
    require(len(canonical(manifest)) <= 2 << 20, "component installation manifest bound")
    put(components/"python-installation.json", manifest)
    installation_path = Path("/opt/nodus/managed-local/python-installation.json")
    put(installation_path, manifest)
    release = {"version": 2, "policy": None, "files": {"python": {"path": python, "sha256": files[python]["sha256"]}},
               "python_installation": {"path": str(installation_path), "sha256": sha(canonical(manifest))},
               "guardian": None, "image_reference": None, "shared": None, "pids": None, "max_claims": None}
    put(Path("/opt/nodus/managed-local/release.json"), release)
    put(Path("/opt/nodus/managed-local/release.json.bundle"), b"component-signature-seam\n")
    verification = commands.run([PYTHON, "-I", "-B", str(Path(__file__).resolve()), "verify", str(root), str(wheel)])
    require(verification["returncode"] == 0, "actual installer component verifier refused measured tuple")
    cases = []
    native_alias = next((Path(row["path"]) for row in links if row["path"].startswith("/usr/") and Path(row["path"]).is_file()), None)
    require(native_alias is not None, "component native alias refusal witness unavailable")
    for name, path in (("member-tamper", site/"nodus_dc/__init__.py"), ("extra-startup-file", site/"component-extra.pth"),
                       ("pyvenv-drift", destination/"pyvenv.cfg"), ("interpreter-alias", Path(python)),
                       ("native-alias-drift", native_alias), ("missing-pin", installation_path)):
        existed = path.exists() or path.is_symlink(); info = path.lstat() if existed else None
        old_link = os.readlink(path) if existed and path.is_symlink() else None
        body = read(path) if existed and old_link is None else None
        try:
            if name == "native-alias-drift":
                target_path = str(path.resolve()); path.unlink()
                replacement = target_path if old_link != target_path else os.path.relpath(target_path, path.parent)
                require(replacement != old_link, "native alias counterexample unchanged"); path.symlink_to(replacement)
            elif name == "interpreter-alias": path.unlink(); path.symlink_to(PYTHON)
            elif name == "missing-pin": path.unlink()
            else: path.write_bytes((body or b"") + b"\n# component refusal\n")
            refused = commands.run([PYTHON, "-I", "-B", str(Path(__file__).resolve()), "verify", str(root), str(wheel)])
            require(refused["returncode"] == 23 and refused["stdout"] == "component-installation-refused\n", "component expected typed refusal")
        finally:
            path.unlink(missing_ok=True)
            if existed:
                if old_link is not None: path.symlink_to(old_link)
                else: path.write_bytes(body); path.chmod(stat.S_IMODE(info.st_mode))
        restored = (os.readlink(path) == old_link if old_link is not None else read(path) == body) if existed else not path.exists()
        require(restored, "component counterexample not restored")
        cases.append({"name": name, "returncode": refused["returncode"], "refused": True,
                      "authority_absent": not Path("/var/lib/nodus-dc-authority/fence.json").exists(), "restored_exact": restored})
    require(commands.run([PYTHON, "-I", "-B", str(Path(__file__).resolve()), "verify", str(root), str(wheel)])["returncode"] == 0,
            "component restored tuple verification")
    put(components/"refusals.json", {"schema": "managed-python-component-refusals.v1", "cases": cases, "signature_seam": True})
    put(components/"census.json", {"schema": "managed-python-component-census.v1", **{k: manifest[k] for k in ("files", "directories", "native_links")},
                                  "source_members": len(json.loads(read(components/"source-manifest.json"))["files"]),
                                  "wheel_members": len(wheel_rows), "output_members": ["components/" + p for p in OUTPUTS],
                                  "total_bytes": sum(row["bytes"] for row in files.values())})
    put(work/"namespace-result.json", {"target_tuple": target, "wheel_sha256": wheel_sha,
                                      "wheel_bytes": wheel.stat().st_size, "raw_refs": raw_refs,
                                      "authority_absent": True, "children": commands.children})


def measure(root, wheel):
    start = time.monotonic_ns(); end = start + 240_000_000_000
    require(sys.platform == "linux" and os.geteuid() == 0 and sys.version_info[:2] == (3, 12)
            and Path(sys.executable).resolve() == Path(PYTHON), "component requires actual root Linux CPython 3.12")
    input_path = Path(os.environ["NODUS_MANAGED_COMPONENT_INPUT"])
    input_sha = os.environ.get("NODUS_MANAGED_COMPONENT_INPUT_SHA256", "")
    value = input_record(input_path, input_sha)
    out = Path(value["output_directory"]); protected(out.parent, stage="component-output-parent")
    out.mkdir(mode=0o700); work = out/"work"; work.mkdir(mode=0o700)
    components = out/"components"; components.mkdir(mode=0o700)
    commands = Commands(work/"parent", end + 10_000_000_000)
    manifest = source_manifest(root, commands)
    require((manifest["head"], manifest["tree"]) == (value["python_head"], value["python_tree"])
            and sha(canonical(manifest)) == value["source_manifest_sha256"], "component exact source manifest")
    put(components/"source-manifest.json", manifest); put(components/"package.whl", read(wheel, 4 << 20))
    before_mounts = Path("/proc/self/mountinfo").read_bytes(); parent_ns = namespaces()
    result = commands.run(["/usr/bin/unshare", "--mount", "--pid", "--fork", "--mount-proc", "--kill-child=KILL",
                           PYTHON, "-I", "-B", str(Path(__file__).resolve()), "namespace", str(root), str(input_path), input_sha,
                           str(end), json.dumps(parent_ns, sort_keys=True)], cap=max(0.001, (end-time.monotonic_ns())/1e9))
    namespace_children = json.loads(read(work/"child/children.json", 1 << 20)) if (work/"child/children.json").exists() else []
    source_clean = source_manifest(root, commands) == manifest
    namespace_row = next(row for row in commands.children if row["argv_sha256"] == sha(canonical(result["argv"])))
    try: os.killpg(namespace_row["pid"], 0)
    except ProcessLookupError: group_absent = True
    else: group_absent = False
    owned_mounts_absent = Path("/proc/self/mountinfo").read_bytes() == before_mounts
    partial = json.loads(read(work/"namespace-result.json")) if (work/"namespace-result.json").exists() else None
    closure = {"schema": "managed-python-component-closure.v1", "original_start_monotonic_ns": start,
               "original_end_monotonic_ns": end, "elapsed_ns": time.monotonic_ns() - start,
               "children": commands.children + namespace_children, "namespace_exit_returncode": result["returncode"],
               "group_absent": group_absent, "owned_mounts_absent": owned_mounts_absent,
               "authority_absent": bool(partial and partial["authority_absent"]), "source_clean": source_clean,
               "raw_output_total_bytes": sum(p.stat().st_size for p in (components/"raw").glob("*.json"))}
    put(components/"closure.json", closure)
    require(result["returncode"] == 0 and partial and group_absent and owned_mounts_absent and source_clean,
            "component namespace/measurement failed; retain partial owned evidence")
    receipt = {"schema": "managed-python-components.v1", "scope": "python-os-import-native-components", "outcome": "PASS",
               **{k: value[k] for k in ("platform_head", "python_head", "python_tree", "source_manifest_sha256")},
               "target_tuple": partial["target_tuple"], "wheel": {"path": "components/package.whl", "sha256": partial["wheel_sha256"], "bytes": partial["wheel_bytes"]},
               "raw": partial["raw_refs"], "source_clean": True, "entry_signature_verified": False,
               "host_lifecycle_qualified": False, "production_ready": False}
    for key, name in (("python_installation", "python-installation.json"), ("import_closure", "import-closure.json"),
                      ("census", "census.json"), ("refusals", "refusals.json"), ("process_closure", "closure.json")):
        receipt[key] = pointer(components, name)
    require(sorted(str(p.relative_to(out)) for p in components.rglob("*") if p.is_file())
            == sorted("components/" + name for name in OUTPUTS if name != "receipt.json"), "component exact output census")
    require(sum(p.stat().st_size for p in components.rglob("*") if p.is_file()) + len(canonical(receipt)) <= MAX_OUTPUT,
            "component final output total")
    # Namespace exit already destroyed the mounts. Only this fresh output's
    # private scratch is removed; failed measurements retain it for diagnosis.
    shutil.rmtree(work)
    put(components/"receipt.json", receipt)


if __name__ == "__main__":
    if sys.argv[1:] == ["probe"]:
        import_probe()
    elif len(sys.argv) == 4 and sys.argv[1] == "verify":
        try: verify_install(Path(sys.argv[2]), Path(sys.argv[3]))
        except (RuntimeError, OSError, ValueError, KeyError):
            print("component-installation-refused", flush=True); raise SystemExit(23)
    elif len(sys.argv) == 7 and sys.argv[1] == "namespace":
        try:
            namespace_measure(Path(sys.argv[2]), input_record(Path(sys.argv[3]), sys.argv[4]), int(sys.argv[5]), json.loads(sys.argv[6]))
        except Exception as exc:
            print(json.dumps({"component_failure_type": type(exc).__name__,
                              "component_failure": str(exc) if type(exc) is RuntimeError else "component-step-failed"}), flush=True)
            raise SystemExit(1)
    else:
        raise SystemExit("closed component helper invocation required")
