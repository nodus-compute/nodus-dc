"""Read live daemon health and saved capacity without changing allocation state."""
from __future__ import annotations

from collections import Counter
import http.client
import json
import math
import socket
import threading
import time

from .api import _object, token_file
from .errors import Error


def inspect_daemon(*, port, token_path, timeout=5):
    """Inspect loopback only; never follow redirects or send a bridge credential.

    A successful read is not a reservation, hardware qualification, permission
    to lend, or evidence that a previous workload has been cleaned up.
    """
    if type(port) is not int or not 1 <= port <= 65535:
        raise Error("invalid_port", "doctor port must be between 1 and 65535", 400)
    token = token_file(token_path)

    def read(path, *, authenticated=False):
        started = time.monotonic()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        timer = None
        response = None
        try:
            connection.connect()
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError()
            transport = connection.sock
            transport.settimeout(remaining)

            def expire():
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            # Retain the actual socket: getresponse may detach it from the
            # connection while a response file still owns the open descriptor.
            timer = threading.Timer(remaining, expire)
            timer.daemon = True
            timer.start()
            headers = {"Authorization": "Bearer " + token} if authenticated else {}
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status in (401, 403):
                raise Error("diagnostic_unauthorized", "use this daemon's local token file, not its bridge or platform token", 401)
            if response.status != 200:
                raise Error("diagnostic_response", "daemon diagnostic endpoint did not return HTTP 200", 503)
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise Error("diagnostic_response", "daemon diagnostic response exceeds 4 MiB", 503)
            value = json.loads(raw, object_pairs_hook=_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            elapsed = time.monotonic() - started
            if elapsed >= timeout:
                raise TimeoutError()
            return value, elapsed
        except (OSError, http.client.HTTPException):
            raise Error("daemon_unreachable", "cannot read the local daemon; check its port, service state and logs", 503) from None
        except (ValueError, UnicodeError):
            raise Error("diagnostic_response", "daemon diagnostic response is not valid finite JSON", 503) from None
        finally:
            if timer:
                timer.cancel()
                timer.join()
            if response:
                response.close()
            connection.close()

    health, _ = read("/health")
    status, elapsed = read("/v1/status", authenticated=True)
    if (not isinstance(health, dict)
            or set(health) != {"ok", "maintenance_error", "connection_error"}
            or type(health["ok"]) is not bool
            or any(health[k] is not None and not isinstance(health[k], str)
                   for k in ("maintenance_error", "connection_error"))):
        raise Error("diagnostic_response", "daemon health schema is not supported", 503)
    availability = status.get("availability") if isinstance(status, dict) else None
    if (not isinstance(availability, dict)
            or availability.get("scope") != "local_snapshot_only"
            or availability.get("state") not in {"fresh", "stale", "missing", "clock_uncertain"}
            or availability.get("allocation_authority") not in {"observe", "standalone", "kubernetes"}
            or not isinstance(availability.get("resources"), list)
            or type(availability.get("fresh_for_seconds")) not in (int, float)
            or not math.isfinite(availability["fresh_for_seconds"])
            or not 0 <= availability["fresh_for_seconds"] <= 30
            or any(type(availability.get(k)) is not int or availability[k] < 0
                   for k in ("available_gpus", "available_partitions"))
            or any(not isinstance(row, dict) or not isinstance(row.get("reason"), str)
                   for row in availability["resources"])):
        raise Error("diagnostic_response", "daemon availability schema is not supported", 503)

    healthy = health["ok"] and health["maintenance_error"] is None and health["connection_error"] is None
    fresh = availability["state"] == "fresh" and availability["fresh_for_seconds"] > elapsed
    inventory_state = "stale" if availability["state"] == "fresh" and not fresh else availability["state"]
    reasons = dict(sorted(Counter(row["reason"] for row in availability["resources"]).items()))
    steps = []
    if not healthy:
        steps.append("Inspect the service logs for maintenance or connection errors. Local allocations remain held until verified cleanup.")
    if not fresh:
        steps.append("Inventory is not fresh. Inspect the service logs and read inventory using the daemon's existing state directory and authority settings.")
    if availability["allocation_authority"] == "observe":
        steps.append("Observe mode does not allocate GPUs. Select one allocation authority before running workloads.")
    elif availability["allocation_authority"] == "kubernetes":
        steps.append("Kubernetes owns allocation. Schedule workloads through the configured GPU device plugin.")
    if reasons.get("held"):
        steps.append("Held resources need their existing lease's normal lifecycle; a restart or expired lease does not make them available.")
    if fresh and availability["allocation_authority"] == "standalone":
        steps.append("Reserve an available GPU or partition before starting a workload.")
    return {"ok": healthy and fresh, "daemon_healthy": healthy,
            "inventory_state": inventory_state,
            "allocation_authority": availability["allocation_authority"],
            "available_gpus": availability["available_gpus"] if fresh else 0,
            "available_partitions": availability["available_partitions"] if fresh else 0,
            "resource_reasons": reasons, "reservation_required": True,
            "external_capacity_evaluated": False,
            "next_steps": steps}
