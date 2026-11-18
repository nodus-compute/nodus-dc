"""Explicit real-host setup for the existing private Agent bridge fixture.

Importing this module does no work. The owning prepared-host journey supplies the
finite envelope and immutable qualification; no production entry imports it.
"""
from __future__ import annotations

import copy
import hashlib
import math
import os
import time
from pathlib import Path

from nodus_dc import ephemeral
from nodus_dc.backend import NvidiaDockerBackend
from nodus_dc.errors import Error
from nodus_dc.model import canonical
from nodus_dc.partition_host import Evidence, LinuxPartitionProvider, path
from nodus_dc.service import Service
from nodus_dc.store import Store


def prepare_trusted_partition_fixture(private_dir, template_path, template_sha256, *, expires_at):
    """Return the real Service and safe metadata; the existing caller owns its socket and policy."""
    def refuse():
        return Error("trusted_fixture_unavailable", "the exact prepared host fixture is unavailable", 503)

    def live():
        if time.time() >= expires_at:
            raise refuse()

    now = time.time()
    if (os.geteuid() != 0 or type(expires_at) not in {int, float}
            or not math.isfinite(expires_at) or not now < expires_at <= now + 300):
        raise refuse()
    root = path(private_dir)
    evidence = Evidence()
    owner = evidence.protected(root, directory=True)
    if owner.st_gid != 0 or owner.st_mode & 0o077:
        raise refuse()
    template, observed = evidence.record(path(template_path))
    if observed != template_sha256 or template.get("host_budget", {}).get("authority_incarnation", "missing") is not None:
        raise refuse()
    store_path, config_path = root / "authority.sqlite3", root / "provider-config.json"
    if any(os.path.lexists(p) for p in (store_path, Path(str(store_path) + "-wal"),
                                       Path(str(store_path) + "-shm"), config_path)):
        raise refuse()  # This is one original setup; retained or uncertain state is never reset.

    backend = NvidiaDockerBackend(allocation_authority="standalone", clock=time.time)
    service = Service(Store(store_path), backend, clock=time.time, bridge_enabled=True)
    # The existing physical-host registry refuses a competing database. It is not redirected.
    with service.authority():
        live()
        service.partitions.ensure_durable()
        with service.store.connection() as db:
            anchor = service.store.fence.verify(db)
    config = copy.deepcopy(template)
    config["host_budget"]["authority_incarnation"] = anchor["incarnation"]
    if config["host_budget"]["boot_id"] != backend.boot_id():
        raise refuse()
    raw = canonical(config).encode()
    fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    config_sha256 = hashlib.sha256(raw).hexdigest()
    service.partitions.executor = LinuxPartitionProvider(str(config_path), config_sha256, clock=time.time)
    # None selects actual LinuxDevices; no synthetic command, inventory or enforcement adapter is installed.
    if service.partitions.devices is not None:
        raise refuse()
    with service.authority(), service.store.transaction(time.time()) as db:
        service.partitions._host_account(db, accounting_version=ephemeral.ACCOUNTING)

    parents = {item["device"]["parent_uuid"] for item in config["devices"]}
    if len(parents) != 1:
        raise refuse()
    parent = next(iter(parents))
    live()
    held = service.reserve(resources=[parent], mode="gpu_configuration", expires_at=expires_at,
                           request_key="trusted-fixture-adopt-parent")
    live()
    service.adopt_partitions(held["id"], generation=held["generation"], request_key="trusted-fixture-adopt")
    released = service.release(held["id"], generation=held["generation"], request_key="trusted-fixture-parent-release")
    if released["state"] != "released":
        raise refuse()
    live()
    return service, {"config_path": str(config_path), "config_sha256": config_sha256,
                     "host_budget": copy.deepcopy(config["host_budget"]),
                     "runtime_identity": copy.deepcopy(config["runtime_identity"]),
                     "parent_uuid": parent}
