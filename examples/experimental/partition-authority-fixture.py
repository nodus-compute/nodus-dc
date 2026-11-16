#!/usr/bin/env python3
"""Manual cross-component fixture: real Store/private socket, synthetic hardware only.

Run from an unpacked source checkout with PYTHONPATH=src:. . The caller starts
its real Go authority client against the readiness record and must terminate this
process afterward. This starts no container, GPU operation, provider call or offer
on a production daemon. It is deliberately not an installed CLI command.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import threading

from nodus_dc.api import BridgeUnixServer
from tests.test_partition_authority import Partitions, A

TOKEN = "synthetic-partition-contract-fixture-token-00000001"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    case = Partitions()
    case.setUp()
    server = None
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_:stopped.set())
    signal.signal(signal.SIGINT, lambda *_:stopped.set())
    try:
        local = case.service.reserve(resources=[A], mode="hardware_partition", expires_at=1400,
            request_key="cross-component-local-sibling", host_resources={
                "cpu_millis":1000, "memory_bytes":2*1024**3, "scratch_bytes":128*1024**2})
        case.service.start(local["id"], generation=local["generation"], request_key="start-local-sibling",
                           workload={"test_workload":True})
        server = BridgeUnixServer(case.root/"bridge.sock", case.service, TOKEN, owner_uid=os.geteuid())
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        with args.ready.open("x") as out:
            json.dump({"socket":str(server.path), "token":TOKEN, "synthetic":True,
                       "clock_unix_seconds":case.clock(), "claim_expires_at_unix_millis":1100000,
                       "local_sibling":A, "hardware_qualified":False}, out)
            out.write("\n"); out.flush(); os.fsync(out.fileno())
        stopped.wait()
        return 0
    finally:
        if server:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
        case.tearDown()


if __name__ == "__main__": raise SystemExit(main())
