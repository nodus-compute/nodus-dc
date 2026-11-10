"""Authenticated loopback API. Bridge authority is separate from local control."""
from __future__ import annotations

import hmac
import ctypes
import errno
import fcntl
import json
import os
import secrets
import stat
import socket
import socketserver
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .errors import Error


def token_file(path, *, create=False):
    path = Path(path)
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w") as file:
                file.write(secrets.token_urlsafe(48) + "\n")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
            raise Error("insecure_token_file", "token file must be an owned regular file with mode 0600", 503)
        raw = os.read(fd, 4097)
        token = raw.decode().strip()
        if len(raw) > 4096 or len(token) < 32 or any(c.isspace() for c in token):
            raise Error("invalid_token_file", "token file must hold one sufficiently long token", 503)
        return token
    finally:
        os.close(fd)


def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


class _BoundedServer:
    daemon_threads = True
    allow_reuse_address = False

    def initialize(self, service, local_token=None, bridge_token=None, *, scope="local_http"):
        self.service = service
        self.local_token = local_token
        self.bridge_token = bridge_token
        self.scope = scope
        self.bridge_only = scope == "bridge"
        self.slots = threading.BoundedSemaphore(32)
        self.stop_event = threading.Event()
        self.maintenance_error = None

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def maintain(self, interval=5):
        while not self.stop_event.wait(interval):
            try:
                self.service.maintain_leases()
                self.maintenance_error = None
            except Exception as exc:
                # Status is honest. A failure never releases any resource.
                self.maintenance_error = str(exc)

    def server_close(self):
        self.stop_event.set()
        super().server_close()


class Server(_BoundedServer, ThreadingHTTPServer):
    """Loopback dashboard/local API only. Never accepts bridge authority calls."""

    def __init__(self, address, service, local_token, bridge_token=None):
        if address[0] != "127.0.0.1":
            raise Error("nonlocal_bind", "local control API binds only to 127.0.0.1", 400)
        if bridge_token is not None:
            raise Error("bridge_transport_required", "bridge authority requires a private Unix socket", 400)
        self.initialize(service, local_token)
        super().__init__(address, Handler)


def _peer_uid(connection):
    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", credentials)[1]
    if sys.platform == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        function = library.getpeereid
        function.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        function.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if function(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise OSError(ctypes.get_errno(), "peer identity could not be verified")
        return uid.value
    raise Error("unsupported_peer_credentials", "bridge requires OS peer credential support", 503)


def _secure_socket_path(value, owner_uid):
    raw = os.fspath(value)
    path = Path(raw)
    if (not path.is_absolute() or raw.startswith("//") or str(path) != raw
            or os.path.normpath(raw) != raw or "\0" in raw or len(os.fsencode(raw)) > 103):
        raise Error("insecure_bridge_path", "bridge socket needs a canonical absolute path of at most 103 bytes", 400)
    components = list(reversed(path.parent.parents)) + [path.parent]
    for directory in components:
        try:
            info = directory.lstat()
        except FileNotFoundError:
            directory.mkdir(mode=0o700)
            info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner_uid}
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise Error("insecure_bridge_path", "bridge ancestors must be owned directories without symlinks or group/world write", 503)
    parent = path.parent.lstat()
    if parent.st_uid != owner_uid or stat.S_IMODE(parent.st_mode) != 0o700:
        raise Error("insecure_bridge_path", "bridge socket parent must be owned with mode 0700", 503)
    return path


class _PrivateUnixServer(_BoundedServer, socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Private bridge listener with filesystem and OS peer authentication.

    Production CLI fixes owner_uid=0. An explicit current-UID override is used
    only by unprivileged CPU fixtures; it does not bypass path or peer checks.
    """
    def __init__(self, path, service, token, *, owner_uid=0, scope):
        if os.geteuid() != owner_uid:
            raise Error("bridge_owner_required", "bridge listener must run as its configured owner", 503)
        if not isinstance(token, str) or len(token) < 32:
            raise Error("invalid_bridge_token", "bridge requires its separate bearer credential", 503)
        self.path = _secure_socket_path(path, owner_uid)
        self.owner_uid = owner_uid
        self.lock_fd = None
        self.socket_identity = None
        self.initialize(service, local_token=token if scope == "local_unix" else None,
                        bridge_token=token if scope == "bridge" else None, scope=scope)
        lock_path = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.lock_fd = fd
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o600:
                raise Error("insecure_bridge_lock", "bridge lock must be an owned private regular file", 503)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("bridge_already_running", "another listener owns the bridge socket") from None
            if self.path.exists() or self.path.is_symlink():
                info = self.path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o600:
                    raise Error("insecure_bridge_socket", "existing bridge path is not an owned private socket", 503)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.25)
                    try:
                        probe.connect(str(self.path))
                    except OSError as exc:
                        if exc.errno != errno.ECONNREFUSED:
                            raise Error("uncertain_bridge_socket", "existing bridge endpoint could not be safely classified", 503) from None
                    else:
                        raise Error("bridge_already_running", "existing socket has a live listener")
                self.path.unlink()
            old_mask = os.umask(0o077)
            try:
                super().__init__(str(self.path), Handler)
            finally:
                os.umask(old_mask)
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner_uid:
                raise Error("insecure_bridge_socket", "created bridge socket has unexpected identity", 503)
            self.socket_identity = (info.st_dev, info.st_ino)
            os.chmod(self.path, 0o600)
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o600:
                raise Error("insecure_bridge_socket", "created bridge socket has unexpected ownership or mode", 503)
        except BaseException:
            self.server_close()
            raise

    def verify_request(self, request, client_address):
        try:
            return _peer_uid(request) == self.owner_uid
        except (Error, OSError, ValueError, AttributeError):
            return False

    def server_close(self):
        if hasattr(self, "socket"):
            super().server_close()
        if self.socket_identity is not None:
            try:
                info = self.path.lstat()
                if (info.st_dev, info.st_ino) == self.socket_identity and stat.S_ISSOCK(info.st_mode):
                    self.path.unlink()
            except FileNotFoundError:
                pass
            self.socket_identity = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None


class BridgeUnixServer(_PrivateUnixServer):
    def __init__(self, path, service, bridge_token, *, owner_uid=0):
        super().__init__(path, service, bridge_token, owner_uid=owner_uid, scope="bridge")


class LocalUnixServer(_PrivateUnixServer):
    def __init__(self, path, service, local_token, *, owner_uid=0):
        super().__init__(path, service, local_token, owner_uid=owner_uid, scope="local_unix")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        pass

    def send_json(self, status, value):
        data = json.dumps(value, sort_keys=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def authorize(self, bridge):
        expected = self.server.bridge_token if bridge else self.server.local_token
        supplied = self.headers.get("Authorization", "")
        if not expected or not hmac.compare_digest(supplied, "Bearer " + expected):
            raise Error("unauthorized", "a valid scoped bearer credential is required", 401)

    def body(self):
        if self.headers.get("Transfer-Encoding"):
            raise Error("invalid_body", "transfer encoding is unsupported", 400)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise Error("invalid_body", "invalid content length", 400) from None
        if not 0 <= length <= 1024 * 1024:
            raise Error("invalid_body", "request body exceeds the limit", 413)
        try:
            value = json.loads(self.rfile.read(length) or b"{}", object_pairs_hook=_object,
                               parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite number")))
        except (ValueError, UnicodeError):
            raise Error("invalid_json", "request must be finite JSON without duplicate keys", 400) from None
        if not isinstance(value, dict):
            raise Error("invalid_json", "request must be an object", 400)
        return value

    def route(self, method):
        path = urlsplit(self.path).path
        bridge = path.startswith("/v1/bridge/")
        if self.server.bridge_only and not bridge:
            raise Error("not_found", "the bridge socket exposes only bridge authority routes", 404)
        if bridge and not self.server.bridge_only:
            raise Error("bridge_transport_required", "bridge authority is unavailable over HTTP", 403)
        if path == "/health" and method == "GET":
            return {"ok": self.server.maintenance_error is None and self.server.service.bridge_health_error is None,
                    "maintenance_error": self.server.maintenance_error,
                    "connection_error": self.server.service.bridge_health_error}
        self.authorize(bridge)
        service = self.server.service
        if method == "GET":
            if path == "/v1/status":
                return service.status()
            if path == "/v1/inventory":
                return service.inventory()
            if path.startswith("/v1/leases/") and len(path.split("/")) == 4:
                return service.get(path.split("/")[-1])
        if method == "POST":
            body = self.body()
            direct = {"/v1/reserve": service.reserve, "/v1/reconcile": service.reconcile,
                      "/v1/bridge/status": service.bridge_status,
                      "/v1/bridge/policy": service.bridge_policy,
                      "/v1/bridge/claim": service.bridge_claim,
                      "/v1/bridge/check": service.bridge_check,
                      "/v1/bridge/inspect": service.bridge_inspect,
                      "/v1/bridge/reclaim": service.bridge_reclaim,
                      "/v1/bridge/complete": service.bridge_complete}
            if path in direct:
                return direct[path](**body)
            parts = path.split("/")
            if len(parts) == 5 and parts[1:3] == ["v1", "leases"]:
                operations = {"start": service.start, "drain": service.drain, "release": service.release,
                              "configure": service.configure, "recover": service.recover, "native-handoff": service.native_handoff}
                if parts[4] in operations:
                    return operations[parts[4]](parts[3], **body)
        raise Error("not_found", "API route does not exist", 404)

    def dispatch(self, method):
        try:
            self.send_json(200, self.route(method))
        except Error as exc:
            self.close_connection = True
            self.send_json(exc.status, exc.as_dict())
        except TypeError:
            self.close_connection = True
            self.send_json(400, Error("invalid_request", "missing, unknown or incorrectly typed request fields", 400).as_dict())
        except Exception:
            self.close_connection = True
            self.send_json(500, Error("internal_error", "operation failed; allocation remains held until reconciled", 500).as_dict())

    def do_GET(self):
        if self.path == "/" and self.server.scope == "local_http":
            from .dashboard import HTML
            data = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)
            return
        self.dispatch("GET")

    def do_POST(self):
        if self.server.scope == "local_http":
            self.close_connection = True
            self.send_json(403, Error("private_transport_required", "mutating local APIs require the private Unix socket", 403).as_dict())
            return
        self.dispatch("POST")
