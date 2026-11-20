"""Kernel-observed creator identity for the private Linux partition socket."""
from __future__ import annotations

import hashlib
import os
import select
import socket
import stat
import struct
import sys

from .errors import Error


def _refuse():
    return Error("partition_creator_unavailable", "the original live creator cannot be verified", 403)


def _read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        value = os.read(fd, limit + 1)
        if len(value) > limit: raise _refuse()
        return value.decode("ascii").strip()
    finally:
        os.close(fd)


class SocketCreator:
    """A pidfd pins the observed peer; request JSON never supplies this object."""

    def __init__(self, connection):
        self.pidfd = -1
        self.executable_key = None
        self.executable_digest = None
        if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
            raise _refuse()
        try:
            self.pid, self.uid, self.gid = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if self.pid <= 0: raise _refuse()
            self.pidfd = os.pidfd_open(self.pid, 0)
            self.identity = self._observe()
        except (OSError, ValueError, UnicodeError):
            self.close()
            raise _refuse() from None
        except BaseException:
            self.close()
            raise

    def _observe(self):
        if self.pidfd < 0: raise _refuse()
        poll = select.poll()
        poll.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poll.poll(0): raise _refuse()
        root = f"/proc/{self.pid}"
        # comm may itself contain parentheses; the fields after its last ')' are stable.
        raw = _read(root + "/stat", 4096)
        tail = raw[raw.rindex(")") + 2:].split()
        ticks = int(tail[19])
        if ticks <= 0 or tail[0] == "Z": raise _refuse()
        status = _read(root + "/status", 16384)
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        # Reject credential-changing executables rather than infer their old authority.
        if ([int(v) for v in fields["Uid"].split()] != [self.uid] * 4
                or [int(v) for v in fields["Gid"].split()] != [self.gid] * 4):
            raise _refuse()
        executable = os.open(root + "/exe", os.O_RDONLY | os.O_CLOEXEC)
        try:
            before = os.fstat(executable)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 512 * 1024**2:
                raise _refuse()
            key = (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            if self.executable_key is not None and key != self.executable_key: raise _refuse()
            if self.executable_key is None:
                digest = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    block = os.read(executable, min(1024**2, remaining))
                    if not block: raise _refuse()
                    digest.update(block)
                    remaining -= len(block)
                self.executable_digest = digest.hexdigest()
            after = os.fstat(executable)
            if key != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise _refuse()
            self.executable_key = key
        finally:
            os.close(executable)
        result = {"boot_id": _read("/proc/sys/kernel/random/boot_id", 64),
                  "pid": self.pid, "start_ticks": ticks, "uid": self.uid, "gid": self.gid,
                  "executable_sha256": self.executable_digest}
        for name in ("pid", "user", "cgroup"):
            value = os.readlink(root + "/ns/" + name)
            if not value.startswith(name + ":[") or not value.endswith("]"):
                raise _refuse()
            result[name + "_namespace"] = value
        if poll.poll(0): raise _refuse()
        return result

    def verify(self, expected=None):
        try:
            observed = self._observe()
            if observed != self.identity or (expected is not None and observed != expected):
                raise _refuse()
            return dict(observed)
        except (OSError, ValueError, KeyError, IndexError, UnicodeError):
            raise _refuse() from None

    def close(self):
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
