"""Local commands do not contact the Nodus platform."""
from __future__ import annotations

import argparse
import fcntl
import hmac
import json
import math
import os
import stat
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
from .privacy import REQUIREMENTS


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
    managed = sub.add_parser("managed", help="use the prepared host's local scoped execution owner")
    managed.add_argument("--local-socket",default="/run/nodus-dc/local.sock")
    managed.add_argument("--local-token-file")
    actions = managed.add_subparsers(dest="managed_action",required=True)
    q = actions.add_parser("reserve",help="reserve immutable local work and its full host budget")
    q.add_argument("--resource",required=True); q.add_argument("--workload",required=True)
    for name in ("cpu-millis","memory-bytes","scratch-bytes","expires-at-unix-millis"):
        q.add_argument("--"+name,type=int,required=True)
    q.add_argument("--request-key",required=True)
    for action in ("run","reclaim","inspect"):
        q = actions.add_parser(action); q.add_argument("--lease",required=True)
        if action == "run": q.add_argument("--request-key",required=True)
    actions.add_parser("status",help="observe all held local rows, including cleanup pending")
    doctor = sub.add_parser("doctor", help="read live daemon health and capacity without changing state")
    doctor.add_argument("--port", type=int, default=7441)
    doctor.add_argument("--local-token-file", help="daemon's local read token; defaults to STATE_DIR/local.token")
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
            q.add_argument("--terminal-native-return", action="store_true", help="track a fresh dedicated API key for irreversible native return")
            q.add_argument("--participation", choices=["enabled", "disabled"], default="enabled")
            q.add_argument("--available-until", type=float)
            q.add_argument("--accept-terms-digest")
            q.add_argument("--required-compensation", choices=["CashUSD", "Credits"], default="CashUSD")
            allowed = q.add_mutually_exclusive_group()
            allowed.add_argument("--allow-qualified-jobs", action="store_true")
            allowed.add_argument("--allow-image", action="append", help="permit only these exact digest-pinned job images")
    reserve = sub.add_parser("reserve")
    reserve.add_argument("--resource", action="append", required=True)
    reserve.add_argument("--mode", choices=["exclusive_host", "exclusive_gpu", "hardware_partition", "gpu_configuration", "trusted_mps"], required=True)
    reserve.add_argument("--ttl-seconds", type=int, required=True)
    reserve.add_argument("--request-key", default=None)
    reserve.add_argument("--cpu-millis", type=int, help="experimental enforced host CPU reservation")
    reserve.add_argument("--memory-bytes", type=int, help="experimental enforced host RAM limit")
    reserve.add_argument("--scratch-bytes", type=int, help="memory-backed scratch within the RAM limit")
    reserve.add_argument("--required-privacy", choices=REQUIREMENTS, default="trusted_host",
                         help="host_confidential refuses admission without an attested execution backend")
    for command in ("start", "drain", "release", "configure", "adopt-partitions", "recover", "native-handoff", "native-return"):
        q = sub.add_parser(command)
        q.add_argument("lease_id")
        q.add_argument("--generation", type=int, required=True)
        q.add_argument("--request-key", required=command == "native-return", default=None)
        if command == "native-return":
            q.add_argument("--api-key-name", required=True, help="exact current connection API key to irreversibly retire")
            q.add_argument("--recover", action="store_true", help="reconcile an existing frozen journal through exact normal API retirement evidence")
            q.add_argument("--recovery-token-file", help="private file for a temporary same-org recovery key; it must also be retired")
            q.add_argument("--recovery-api-key-name", help="exact temporary recovery key name")
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
    server.add_argument("--partition-provider-config",help="existing protected prepared-host provider configuration")
    server.add_argument("--partition-provider-sha256",help="exact SHA256 of that protected configuration")
    server.add_argument("--prepare-local-template", help="initialize fresh local-only authority from an observed protected host template")
    server.add_argument("--prepare-local-sha256", help="exact template SHA256; never a qualification override")
    server.add_argument("--prepare-until", type=float, help="original absolute setup deadline, at most 300 seconds away")
    server.add_argument("--require-clean-start", action="store_true", help="require retained local ownership history to be positively clean before listening")
    server.add_argument("--partition-enrollment", help=argparse.SUPPRESS)
    server.add_argument("--partition-enrollment-sha256", help=argparse.SUPPRESS)
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
    prepared_daemon = None
    prepare_end = None
    try:
        if args.command == "connection" and os.path.lexists(state.parent / "enrollment.json"):
            raise Error("partition_connection_managed", "prepared enrollment is owned by nodusd; the whole-host connection command is unavailable", 403)
        if args.command == "managed":
            from .partition_local_cli import run
            result=run(args,state)
            print(json.dumps(result,indent=2,sort_keys=True,allow_nan=False))
            return 0
        if args.command == "doctor":
            from .diagnostics import inspect_daemon
            result = inspect_daemon(port=args.port, token_path=args.local_token_file or state / "local.token")
            print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
            return 0 if result["ok"] else 1
        preparing = args.command == "serve" and any((args.prepare_local_template is not None,
                    args.prepare_local_sha256 is not None, args.prepare_until is not None))
        clean_start = args.command == "serve" and args.require_clean_start
        partition_enrollment = args.command == "serve" and any((args.partition_enrollment, args.partition_enrollment_sha256))
        if partition_enrollment and (preparing or not clean_start or not args.partition_enrollment
                or not args.partition_enrollment_sha256 or not args.bridge_token_file
                or args.bridge_socket != str(state / "partition.sock")
                or args.bridge_token_file != str(state / "partition.token")):
            raise Error("local_preparation_unavailable", "partition enrollment requires the exact prepared owner", 403)
        if clean_start:
            if (preparing or args.allocation_authority != "standalone" or args.enable_trusted_mps or os.geteuid() != 0
                    or not partition_enrollment and (args.bridge_token_file is not None or args.bridge_socket != "/run/nodus-dc/bridge.sock")
                    or not args.partition_provider_config or not args.partition_provider_sha256):
                raise Error("local_preparation_unavailable", "clean start requires the same protected local-only standalone provider", 403)
            from .partition_host import Evidence, path
            if str(path(args.state_dir)) != str(state):
                raise Error("local_preparation_unavailable", "clean start requires the original canonical state directory", 403)
            owner = Evidence().protected(state, directory=True)
            lock = Evidence().protected(state / "daemon.lock")
            if (owner.st_gid != 0 or owner.st_mode & 0o077 or lock.st_gid != 0
                    or not stat.S_ISREG(lock.st_mode) or stat.S_IMODE(lock.st_mode) != 0o600):
                raise Error("local_preparation_unavailable", "clean start requires the original private daemon lock", 403)
            prepared_daemon = os.fdopen(os.open(state / "daemon.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC), "r+")
            fcntl.flock(prepared_daemon.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            current_lock = os.fstat(prepared_daemon.fileno())
            if (not os.path.samestat(owner, os.lstat(state)) or not os.path.samestat(lock, current_lock)
                    or current_lock.st_mode != lock.st_mode or current_lock.st_uid != lock.st_uid or current_lock.st_gid != lock.st_gid
                    or not os.path.samestat(lock, os.lstat(state / "daemon.lock"))):
                raise Error("local_preparation_unavailable", "clean start daemon lock changed", 503)
        if preparing:
            # Reject incompatible modes before reading credentials, opening a Store or creating a lock.
            now = time.time()
            if (not args.prepare_local_template or not args.prepare_local_sha256
                    or args.prepare_until is None or not math.isfinite(args.prepare_until)
                    or not now < args.prepare_until <= now + 300
                    or args.allocation_authority != "standalone" or args.enable_trusted_mps
                    or args.bridge_token_file is not None or args.bridge_socket != "/run/nodus-dc/bridge.sock"
                    or args.partition_provider_config is not None or args.partition_provider_sha256 is not None
                    or os.geteuid() != 0):
                raise Error("local_preparation_unavailable", "preparation requires a finite protected local-only standalone owner", 403)
            prepare_end = time.monotonic() + args.prepare_until - now
        bridge_token = token_file(args.bridge_token_file) if getattr(args, "bridge_token_file", None) else None
        if args.command == "serve" and (bridge_token or args.allocation_authority == "standalone") and os.geteuid() != 0:
            raise Error("bridge_owner_required", "production allocation/bridge listeners must run as root", 403)
        prepared = None
        if preparing:
            from .partition_host import Evidence, path
            from .partition_prepare import daemon_lock, prepare_local_host
            if str(path(args.state_dir)) != str(state):
                raise Error("local_preparation_unavailable", "preparation requires the same protected local-only standalone owner", 403)
            owner = Evidence().protected(state, directory=True)
            if owner.st_gid != 0 or owner.st_mode & 0o077:
                raise Error("local_preparation_unavailable", "preparation directory must be private", 403)
            if time.time() >= args.prepare_until or time.monotonic() >= prepare_end:
                raise Error("local_preparation_unavailable", "local preparation deadline expired", 503)
            prepared_daemon = daemon_lock(state)
            service, prepared = prepare_local_host(state, args.prepare_local_template, args.prepare_local_sha256, expires_at=args.prepare_until)
        else:
            service = Service(Store(state / "authority.sqlite3"),
                              NvidiaDockerBackend(allocation_authority=args.allocation_authority, enable_trusted_mps=args.enable_trusted_mps),
                              bridge_enabled=bridge_token is not None or
                                  args.command == "connection" and args.connection_action == "disconnect")
        if args.command == "serve" and (args.partition_provider_config or args.partition_provider_sha256):
            if not args.partition_provider_config or not args.partition_provider_sha256 or os.geteuid()!=0 or args.allocation_authority!="standalone":
                raise Error("local_partition_unavailable", "prepared local execution requires root standalone ownership and both exact provider pins", 403)
            from .partition_host import LinuxPartitionProvider
            service.partitions.executor=LinuxPartitionProvider(args.partition_provider_config,args.partition_provider_sha256)
            if partition_enrollment:
                from .partition_policy import enrolled_partition_policy, partition_clean_start
                service.partition_policy = enrolled_partition_policy(service, state, args.partition_enrollment,
                    args.partition_enrollment_sha256, args.partition_provider_sha256)
                service.partitions.policy_provider = service.partition_policy.current
            # Installation never invents a registry/configuration or moves this initialized process.
            # The existing prepared host must already place this service inside its Shared envelope.
            with service.authority(),service.store.transaction(service.clock()) as db:
                anchor=service.partitions._durable(db)
                if service.partitions.executor.verify_startup(anchor["incarnation"]) is not True:
                    raise Error("local_partition_unavailable", "prepared local envelope differs from the durable authority", 503)
                if clean_start:
                    if partition_enrollment:
                        partition_clean_start(service, db, service.partition_policy.identity)
                    elif (db.execute("SELECT 1 FROM leases WHERE state!='released' LIMIT 1").fetchone()
                            or db.execute("SELECT 1 FROM bridge_policy WHERE enabled!=0 LIMIT 1").fetchone()
                            or any(db.execute("SELECT 1 FROM " + table + " WHERE retired=0 LIMIT 1").fetchone()
                                   for table in ("platform_claims", "partition_claims", "partition_policy_grants"))):
                        raise Error("local_preparation_unavailable", "clean start retains outstanding authority state", 503)
                    from . import ephemeral
                    service.partitions._host_account(db, accounting_version=ephemeral.ACCOUNTING)
        request_key = getattr(args, "request_key", None) or str(uuid.uuid4())
        if args.command in {"inventory", "status", "reconcile"}:
            result = getattr(service, args.command.replace("-", "_"))()
        elif args.command == "reserve":
            host_resources = None
            if any(v is not None for v in (args.cpu_millis,args.memory_bytes,args.scratch_bytes)):
                if any(v is None for v in (args.cpu_millis,args.memory_bytes,args.scratch_bytes)):
                    raise Error("invalid_request", "host budget requires CPU, memory and scratch values together", 400)
                host_resources = {"cpu_millis":args.cpu_millis,"memory_bytes":args.memory_bytes,"scratch_bytes":args.scratch_bytes}
            result = service.reserve(resources=args.resource, mode=args.mode,
                                     expires_at=time.time() + args.ttl_seconds, request_key=request_key,
                                     required_privacy=args.required_privacy, host_resources=host_resources)
        elif args.command == "start":
            workload = json.load(sys.stdin) if args.workload == "-" else json.loads(Path(args.workload).read_text())
            result = service.start(args.lease_id, generation=args.generation, request_key=request_key, workload=workload)
        elif args.command == "configure":
            result = service.configure(args.lease_id, generation=args.generation, request_key=request_key,
                                       plan=json.loads(Path(args.plan).read_text()))
        elif args.command in {"drain", "release", "recover", "adopt-partitions"}:
            result = getattr(service, args.command.replace("-", "_"))(args.lease_id, generation=args.generation, request_key=request_key)
        elif args.command == "native-return":
            if args.allocation_authority != "standalone":
                raise Error("observe_only", "native return requires standalone allocation authority", 403)
            from .handback import Handback
            result = Handback(service, state).run(args.lease_id, generation=args.generation,
                                                 request_key=request_key, api_key_name=args.api_key_name, recover=args.recover,
                                                 recovery_token_file=args.recovery_token_file,
                                                 recovery_api_key_name=args.recovery_api_key_name)
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
                if args.participation == "enabled" and not bridge_token:
                    raise Error("bridge_disabled", "enabled participation requires --bridge-token-file", 403)
                parameters.update(participation=args.participation, available_until=args.available_until, accept_terms_digest=args.accept_terms_digest,
                                  required_compensation=args.required_compensation, terminal_native_return=args.terminal_native_return,
                                  allowed_images=None if args.allow_qualified_jobs else (args.allow_image or ()))
            result = getattr(connection, args.connection_action)(**parameters)
        else:
            daemon_file = prepared_daemon or open(state / "daemon.lock", "a")
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
                    bridge_server = BridgeUnixServer(args.bridge_socket, service, bridge_token, partition_only=partition_enrollment)
                    bridge_server.stop_event = server.stop_event
                    if not partition_enrollment:
                        from .connection import Connection
                        connection = Connection(service, state)
                        service.bridge_health_error = "connection_verification_pending"
                    bridge_thread = threading.Thread(target=bridge_server.serve_forever, daemon=True)
                    bridge_thread.start()
                    if not partition_enrollment:
                        threading.Thread(target=connection_worker, args=(server, connection), daemon=True).start()
                threading.Thread(target=server.maintain, daemon=True).start()
                ready = {"listening": f"http://127.0.0.1:{server.server_port}",
                                  "bridge_url": "unix://" + str(bridge_server.path) if bridge_server else None,
                                  "local_api_url": "unix://" + str(local_server.path) if local_server else None,
                                  "local_token_file": str(local_path), "bridge_enabled": bridge_server is not None}
                if prepared is not None:
                    ready["prepared_provider"] = prepared
                    if time.time() >= args.prepare_until or time.monotonic() >= prepare_end:
                        raise Error("local_preparation_unavailable", "local preparation deadline expired before readiness", 503)
                print(json.dumps(ready), flush=True)
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
                if partition_enrollment:
                    with service.authority(), service.store.connection() as db:
                        partition_clean_start(service, db, service.partition_policy.identity)
                daemon_file.close()
            return 0
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (Error, ValueError, OSError) as exc:
        error = exc.as_dict() if isinstance(exc, Error) else {"error": {"code": "local_failure", "message": str(exc)}}
        print(json.dumps(error), file=sys.stderr)
        return 1
    finally:
        if prepared_daemon is not None:
            prepared_daemon.close()


if __name__ == "__main__":
    raise SystemExit(main())
