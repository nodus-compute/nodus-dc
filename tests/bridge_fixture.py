"""Real HTTP local API + private UDS bridge, SYNTHETIC GPU backend.

PYTHONPATH=src python -m tests.bridge_fixture --state-dir /tmp/unique-state
Prints bound URL and credential FILE PATHS only. Explicit synthetic consent is
set by this test harness. Do not use this fixture to execute real work.
"""
import argparse
import json
import os
import signal
import tempfile
import threading
import time
from pathlib import Path

from nodus_dc.api import BridgeUnixServer, LocalUnixServer, Server, token_file
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_authority import Backend


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--state-dir", required=True)
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--dirty", action="store_true")
    p.add_argument("--local-lease", action="store_true")
    p.add_argument("--bridge-socket")
    args = p.parse_args()
    state = Path(args.state_dir).resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    backend = Backend(time.time)
    backend.clean = not args.dirty
    service = Service(Store(state / "authority.sqlite3"), backend, bridge_enabled=True)
    # Deliberately fixture-only: no policy is enabled by the real CLI/installer.
    service.bridge_policy(enabled=True, policy_revision=1, authorization_id="cpu-fixture-authorization",
                          consent_reference="cpu-fixture-explicit-consent", expires_at=time.time() + 3600)
    if args.local_lease:
        service.reserve(resources=["GPU-aaaa"], mode="exclusive_gpu", expires_at=time.time()+3600, request_key="cpu-fixture-local")
    local = state / "local.token"
    bridge = state / "bridge.token"
    # A world-writable /tmp ancestor is never accepted as a bridge identity.
    socket_directory = tempfile.TemporaryDirectory(prefix=".nodus-bridge-", dir=Path.home().resolve()) if not args.bridge_socket else None
    socket_path = args.bridge_socket or str(Path(socket_directory.name)/"bridge.sock")
    server = Server(("127.0.0.1", args.port), service, token_file(local, create=True))
    bridge_server = BridgeUnixServer(socket_path, service, token_file(bridge, create=True), owner_uid=os.geteuid())
    local_server = LocalUnixServer(str(Path(socket_path).with_name("local.sock")), service,
                                   server.local_token, owner_uid=os.geteuid())
    bridge_server.stop_event = server.stop_event
    local_server.stop_event = server.stop_event
    bridge_thread = threading.Thread(target=bridge_server.serve_forever, daemon=True)
    bridge_thread.start()
    local_thread = threading.Thread(target=local_server.serve_forever, daemon=True)
    local_thread.start()
    threading.Thread(target=server.maintain, daemon=True).start()
    print(json.dumps({"url": f"http://127.0.0.1:{server.server_port}", "local_token_file": str(local),
                      "bridge_url": "unix://" + str(bridge_server.path), "local_api_url": "unix://" + str(local_server.path),
                      "bridge_token_file": str(bridge), "synthetic": True}), flush=True)
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop_event.set()
        bridge_server.shutdown()
        bridge_server.server_close()
        bridge_thread.join()
        local_server.shutdown()
        local_server.server_close()
        local_thread.join()
        server.server_close()
        if socket_directory:
            socket_directory.cleanup()


if __name__ == "__main__":
    main()
