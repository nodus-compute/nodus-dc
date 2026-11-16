"""Explicit local checkpoint storage; never a grant of GPU capacity."""
import os
from pathlib import Path
import stat

from .errors import Error


def paths_overlap(left, right):
    left, right = Path(left), Path(right)
    return left == right or left in right.parents or right in left.parents


def output_directory(value):
    """Require an existing, canonical, private operator-owned directory.

    Host administrators remain trusted, including during path validation and
    Docker's later bind. This is not protection from a malicious host operator.
    """
    if not isinstance(value, str) or not value or any(c in value for c in ("\0", ",")):
        raise Error("invalid_output_directory", "output_directory must be an absolute dedicated directory", 400)
    path = Path(value)
    try:
        info = path.lstat()
        valid = (path.is_absolute() and str(path.resolve(strict=True)) == value
                 and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o700)
    except (OSError, ValueError, RuntimeError):
        valid = False
    if not valid:
        raise Error("invalid_output_directory", "output_directory must exist, have mode 0700, belong to the operator and have no symlink components", 400)
    for parent in path.parents:
        info = parent.stat()
        # Root-owned sticky temporary roots permit private children without
        # permitting another UID to rename this operator's child directory.
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not sticky_root):
            raise Error("invalid_output_directory", "output_directory ancestors must not be replaceable by another user", 400)
    protected = ("/etc", "/run", "/dev", "/proc", "/sys", "/boot", "/usr", "/bin",
                 "/sbin", "/lib", "/lib64", "/opt/nodus-dc", "/var/lib/nodus-dc", "/var/lib/nodus",
                 "/var/lib/docker", "/var/lib/containerd")
    if any(paths_overlap(path, root) for root in protected):
        raise Error("invalid_output_directory", "system and Nodus runtime directories cannot be checkpoint output", 400)
    return path


def outputs(workload, mode):
    """Validated workload output paths, including each cooperating MPS client."""
    if not workload:
        return []
    if mode == "trusted_mps":
        return [Path(client["workload"]["output_directory"]) for client in workload["clients"]
                if "output_directory" in client["workload"]]
    return [Path(workload["output_directory"])] if "output_directory" in workload else []


def inputs(workload, mode):
    if not workload:
        return []
    if mode == "trusted_mps":
        return [path for client in workload["clients"] for path in inputs(client["workload"], "exclusive_gpu")]
    return [Path(mount["source"]).resolve() for mount in workload.get("mounts", [])]


def require_disjoint_outputs(directories, *, protected=()):
    for index, path in enumerate(directories):
        if any(paths_overlap(path, other) for other in (*directories[:index], *protected)):
            raise Error("output_directory_conflict", "checkpoint output overlaps another held job or protected path", 409)
