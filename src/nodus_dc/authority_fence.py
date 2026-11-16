"""An independent write-ahead sequence prevents database rollback from reviving ownership.

The trusted host operator owns the registry. A crash between registry and SQLite
commits fences admission; it never guesses that a missing write was harmless.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path

from .errors import Error
from .model import canonical


class AuthorityFence:
    def __init__(self, path, database):
        self.path = Path(path)
        self.database = str(Path(database).resolve())

    def _parent(self):
        path = self.path
        if not path.is_absolute() or path != path.resolve():
            raise Error("authority_fence_unavailable", "authority registry must be canonical", 503)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (path.parent, *path.parent.parents):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
                raise Error("authority_fence_unavailable", "authority registry ancestry is not protected", 503)
        if path.parent.stat().st_uid != os.geteuid() or path.parent.stat().st_mode & 0o077:
            raise Error("authority_fence_unavailable", "authority registry directory must be private", 503)

    def read(self):
        self._parent()
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise Error("authority_fence_unavailable", "authority registry must be a private owned file", 503)
            raw = os.read(fd, 4097)
            value = json.loads(raw)
            if (len(raw) > 4096 or set(value) != {"database", "incarnation", "sequence"}
                    or value["database"] != self.database or type(value["sequence"]) is not int
                    or value["sequence"] < 0 or str(uuid.UUID(value["incarnation"])) != value["incarnation"]):
                raise ValueError("invalid registry identity")
            return value
        except (ValueError, TypeError, KeyError):
            raise Error("authority_fence_unavailable", "authority registry cannot be verified", 503) from None
        finally:
            os.close(fd)

    def write(self, value):
        self._parent()
        temp = self.path.with_name(self.path.name + "." + uuid.uuid4().hex)
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            temp.unlink(missing_ok=True)

    def verify(self, db):
        row = db.execute("SELECT value FROM meta WHERE key='authority_fence'").fetchone()
        saved = json.loads(row[0]) if row else None
        current = self.read()
        if saved != current:
            raise Error("authority_continuity_lost", "database and independent authority registry disagree; drained recovery required", 503)
        return saved

    def activate(self, db):
        current = self.verify(db)
        if current is None:
            current = {"database": self.database, "incarnation": str(uuid.uuid4()), "sequence": 0}
            self.write(current)
            db.execute("INSERT INTO meta VALUES('authority_fence',?)", (canonical(current),))
            db.execute("UPDATE meta SET value='4' WHERE key='schema_version'")
        return current

    def advance(self, db):
        current = self.verify(db)
        if current is not None:
            current = {**current, "sequence": current["sequence"] + 1}
            self.write(current)
            db.execute("UPDATE meta SET value=? WHERE key='authority_fence'", (canonical(current),))
