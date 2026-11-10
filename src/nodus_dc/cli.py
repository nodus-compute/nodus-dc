"""Local commands do not contact the Nodus platform."""
from __future__ import annotations

import argparse
import fcntl
import hmac
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

from . import __version__
from .api import BridgeUnixServer, LocalUnixServer, Server, token_file
from .backend import NvidiaDockerBackend
from .errors import Error
from .service import Service
from .store import Store


def parser():
    p = argparse.ArgumentParser(prog="nodus-dc")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--state-dir", default=str(Path.home() / ".local/state/nodus-dc"))
    p.add_argument("--allocation-authority", choices=["observe", "standalone", "kubernetes"], default="observe",
                   help="standalone explicitly makes this service allocation owner; observe is read-only")
    p.add_argument("--enable-trusted-mps", action="store_true", help="allow cooperative MPS pools (no tenant isolation)")
    sub = p.add_subparsers(dest="command", required=True)
    for command in ("inventory", "status", "reconcile"):
        sub.add_parser(command)
    connection = sub.add_parser("connection")
    actions = connection.add_subparsers(dest="connection_action", required=True)
    for action in ("review", "connect", "sync", "disconnect"):
        q = actions.add_parser(action)
        if action in {"review", "connect"}:
            for name in ("platform-url", "namespace", "pool", "node", "token-file"):
                q.add_argument("--" + name, required=True)
            q.add_argument("--node-identity-file", default="/var/lib/nodus/node.json")
        if action in {"connect", "sync"}:
            q.add_argument("--bridge-token-file", required=True)
        if action == "connect":
            q.add_argument("--available-until", type=float, required=True)
            q.add_argument("--accept-terms-digest")
            q.add_argument("--required-compensation", choices=["CashUSD", "Credits"], default="CashUSD")
            allowed = q.add_mutually_exclusive_group(required=True)
            allowed.add_argument("--allow-qualified-jobs", action="store_true")
            allowed.add_argument("--allow-image", action="append", help="permit only these exact digest-pinned job images")
    reserve = sub.add_parser("reserve")
    reserve.add_argument("--resource", action="append", required=True)
    reserve.add_argument("--mode", choices=["exclusive_host", "exclusive_gpu", "hardware_partition", "gpu_configuration", "trusted_mps"], required=True)
    reserve.add_argument("--ttl-seconds", type=int, required=True)
    reserve.add_argument("--request-key", default=None)
    for command in ("start", "drain", "release", "configure", "recover", "native-handoff"):
        q = sub.add_parser(command)
        q.add_argument("lease_id")
        q.add_argument("--generation", type=int, required=True)
        q.add_argument("--request-key", default=None)
        if command == "start":
            q.add_argument("--workload", required=True, help="JSON file, or - for stdin")
        if command == "configure":
            q.add_argument("--plan", required=True, help="MIG JSON plan file")
        if command == "native-handoff":
            q.add_argument("--provisioner-reference", required=True, help="sticky local-only intent; native return is unsupported")
    server = sub.add_parser("serve")
    server.add_argument("--port", type=int, default=7441)
    server.add_argument("--local-token-file")
    server.add_argument("--bridge-token-file")
    server.add_argument("--bridge-socket", default="/run/nodus-dc/bridge.sock")
    server.add_argument("--local-socket", default="/run/nodus-dc/local.sock")
    return p


def sync_connection(service, connection):
    try:
        result = connection.sync()
        service.bridge_health_error = None
        return result
    except Exception as exc:
        # Includes malformed local state/protocol failures. Runtime checks deny
        # external launch while local workloads and management remain available.
        service.bridge_health_error = getattr(exc, "code", "connection_sync_failed")
        try:
            policy = service.bridge_policy_state()
            if policy["enabled"]:
                service.bridge_policy(enabled=False, policy_revision=policy["policy_revision"]+1,
                                      authorization_id=policy["authorization_id"], consent_reference=policy["consent_reference"],
                                      expires_at=policy["expires_at"])
        except Exception:
            pass  # In-memory denial remains until durable state can be verified.
        return {"connected": False, "active": False, "reason": service.bridge_health_error}


def connection_worker(server, connection):
    while not server.stop_event.is_set():
        sync_connection(server.service, connection)
        if server.stop_event.wait(5):
            break


def main(argv=None):
    args = parser().parse_args(argv)
    state = Path(args.state_dir).expanduser().resolve()
    try:
        bridge_token = token_file(args.bridge_token_file) if getattr(args, "bridge_token_file", None) else None
        if args.command == "serve" and (bridge_token or args.allocation_authority == "standalone") and os.geteuid() != 0:
            raise Error("bridge_owner_required", "production allocation/bridge listeners must run as root", 403)
        service = Service(Store(state / "authority.sqlite3"),
                          NvidiaDockerBackend(allocation_authority=args.allocation_authority, enable_trusted_mps=args.enable_trusted_mps),
                          bridge_enabled=bridge_token is not None or
                              args.command == "connection" and args.connection_action == "disconnect")
        request_key = getattr(args, "request_key", None) or str(uuid.uuid4())
        if args.command in {"inventory", "status", "reconcile"}:
            result = getattr(service, args.command)()
        elif args.command == "reserve":
            result = service.reserve(resources=args.resource, mode=args.mode,
                                     expires_at=time.time() + args.ttl_seconds, request_key=request_key)
        elif args.command == "start":
            workload = json.load(sys.stdin) if args.workload == "-" else json.loads(Path(args.workload).read_text())
            result = service.start(args.lease_id, generation=args.generation, request_key=request_key, workload=workload)
        elif args.command == "configure":
            result = service.configure(args.lease_id, generation=args.generation, request_key=request_key,
                                       plan=json.loads(Path(args.plan).read_text()))
        elif args.command in {"drain", "release", "recover"}:
            result = getattr(service, args.command)(args.lease_id, generation=args.generation, request_key=request_key)
        elif args.command == "native-handoff":
            result = service.native_handoff(args.lease_id, generation=args.generation, request_key=request_key,
                                            provisioner_reference=args.provisioner_reference)
        elif args.command == "connection":
            from .connection import Connection
            connection = Connection(service, state)
            parameters = {}
            if args.connection_action in {"review", "connect"}:
                parameters = {field: getattr(args, field) for field in
                              ("platform_url", "namespace", "pool", "node", "token_file", "node_identity_file")}
            if args.connection_action == "connect":
                parameters.update(available_until=args.available_until, accept_terms_digest=args.accept_terms_digest,
                                  required_compensation=args.required_compensation,
                                  allowed_images=None if args.allow_qualified_jobs else args.allow_image)
            result = getattr(connection, args.connection_action)(**parameters)
        else:
            daemon_file = open(state / "daemon.lock", "a")
            try:
                fcntl.flock(daemon_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("daemon_running", "another daemon already owns this state directory") from None
            server = bridge_server = bridge_thread = local_server = local_thread = None
            try:
                local_path = Path(args.local_token_file) if args.local_token_file else state / "local.token"
                local_token = token_file(local_path, create=True)
                if bridge_token and hmac.compare_digest(local_token, bridge_token):
                    raise Error("shared_token", "bridge and local API credentials must differ", 400)
                server = Server(("127.0.0.1", args.port), service, local_token)
                if os.geteuid() == 0:
                    local_server = LocalUnixServer(args.local_socket, service, local_token)
                    local_server.stop_event = server.stop_event
                    local_thread = threading.Thread(target=local_server.serve_forever, daemon=True)
                    local_thread.start()
                if bridge_token:
                    from .connection import Connection
                    bridge_server = BridgeUnixServer(args.bridge_socket, service, bridge_token)
                    bridge_server.stop_event = server.stop_event
                    connection = Connection(service, state)
                    service.bridge_health_error = "connection_verification_pending"
                    bridge_thread = threading.Thread(target=bridge_server.serve_forever, daemon=True)
                    bridge_thread.start()
                    threading.Thread(target=connection_worker, args=(server, connection), daemon=True).start()
                threading.Thread(target=server.maintain, daemon=True).start()
                print(json.dumps({"listening": f"http://127.0.0.1:{server.server_port}",
                                  "bridge_url": "unix://" + str(bridge_server.path) if bridge_server else None,
                                  "local_api_url": "unix://" + str(local_server.path) if local_server else None,
                                  "local_token_file": str(local_path), "bridge_enabled": bridge_server is not None}), flush=True)
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                if server:
                    server.stop_event.set()
                if bridge_server:
                    if bridge_thread:
                        bridge_server.shutdown()
                        bridge_thread.join()
                    bridge_server.server_close()
                if local_server:
                    if local_thread:
                        local_server.shutdown()
                        local_thread.join()
                    local_server.server_close()
                if server:
                    server.server_close()
                daemon_file.close()
            return 0
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (Error, ValueError, OSError) as exc:
        error = exc.as_dict() if isinstance(exc, Error) else {"error": {"code": "local_failure", "message": str(exc)}}
        print(json.dumps(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
