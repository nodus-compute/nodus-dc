"""SQLite is the single host allocation authority, shared by local and connected paths."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .errors import Error
from .model import canonical

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO meta VALUES('schema_version','1');
INSERT OR IGNORE INTO meta VALUES('next_generation','0');
INSERT OR IGNORE INTO meta VALUES('last_wall_time','0');
CREATE TABLE IF NOT EXISTS resources(
 id TEXT PRIMARY KEY, parent TEXT, kind TEXT NOT NULL, record TEXT NOT NULL,
 inventory_revision TEXT NOT NULL, observed_at REAL NOT NULL, present INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS leases(
 id TEXT PRIMARY KEY, generation INTEGER NOT NULL UNIQUE, owner TEXT NOT NULL,
 mode TEXT NOT NULL, state TEXT NOT NULL, resources TEXT NOT NULL,
 created_at REAL NOT NULL, updated_at REAL NOT NULL, expires_at REAL NOT NULL,
 request_key TEXT NOT NULL UNIQUE, request_hash TEXT NOT NULL,
 authorization TEXT, workload TEXT, runtime TEXT, cleanup TEXT, error TEXT, baseline TEXT,
 lease_revision INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS operations(
 request_key TEXT PRIMARY KEY, lease_id TEXT NOT NULL, generation INTEGER NOT NULL,
 action TEXT NOT NULL, request_hash TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at REAL NOT NULL,
 lease_id TEXT, generation INTEGER, action TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bridge_policy(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), enabled INTEGER NOT NULL,
 policy_revision INTEGER NOT NULL, consent_reference TEXT NOT NULL,
 authorization_id TEXT NOT NULL, expires_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS platform_claims(
 platform_lease_id TEXT NOT NULL, platform_epoch INTEGER NOT NULL,
 lease_id TEXT, generation INTEGER, policy_revision INTEGER,
 retired INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, updated_at REAL NOT NULL,
 PRIMARY KEY(platform_lease_id,platform_epoch));
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(Path(path).expanduser().resolve())
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A second process cannot observe partially initialized schema.
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
            version = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
            if version != "1":
                raise Error("schema_version", f"unsupported state schema {version}", 503)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self, now: float):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                last = float(db.execute("SELECT value FROM meta WHERE key='last_wall_time'").fetchone()[0])
                # Regressed clocks must not revive expired authorization or leases.
                if now + 1 < last:
                    raise Error("clock_regression", "host clock moved backwards; admissions are held", 503)
                db.execute("UPDATE meta SET value=? WHERE key='last_wall_time'", (str(max(now, last)),))
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @staticmethod
    def generation(db):
        current = int(db.execute("SELECT value FROM meta WHERE key='next_generation'").fetchone()[0]) + 1
        db.execute("UPDATE meta SET value=? WHERE key='next_generation'", (str(current),))
        return current

    @staticmethod
    def event(db, now, lease, action, detail):
        db.execute("INSERT INTO events(occurred_at,lease_id,generation,action,detail) VALUES(?,?,?,?,?)",
                   (now, lease.get("id"), lease.get("generation"), action, canonical(detail)))

    @staticmethod
    def lease(db, lease_id):
        row = db.execute("SELECT * FROM leases WHERE id=?", (lease_id,)).fetchone()
        if row is None:
            raise Error("lease_not_found", "lease does not exist", 404)
        return Store.decode(row)

    @staticmethod
    def decode(row):
        result = dict(row)
        for name in ("resources", "authorization", "workload", "runtime", "cleanup", "baseline"):
            if name in result and result[name] is not None:
                result[name] = json.loads(result[name])
        return result

    @staticmethod
    def update(db, lease, now, **fields):
        allowed = {"state", "expires_at", "authorization", "workload", "runtime", "cleanup", "error", "baseline"}
        if not set(fields) <= allowed:
            raise ValueError("unsupported lease field")
        values = {}
        for field, value in fields.items():
            values[field] = canonical(value) if field in {"authorization", "workload", "runtime", "cleanup", "baseline"} and value is not None else value
        values["updated_at"] = now
        sql = ",".join(f"{field}=?" for field in values)
        changed = db.execute(f"UPDATE leases SET {sql},lease_revision=lease_revision+1 WHERE id=? AND generation=? AND lease_revision=?",
                             (*values.values(), lease["id"], lease["generation"], lease["lease_revision"])).rowcount
        if changed != 1:
            raise Error("stale_revision", "lease changed concurrently")
        return Store.lease(db, lease["id"])
