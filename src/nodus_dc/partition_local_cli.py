"""Ordinary local CLI requests to the already-running protected host authority."""
from __future__ import annotations

import http.client
import json
import os
import socket
import stat
import threading
import time
from pathlib import Path

from .api import _object, _peer_uid, token_file
from .errors import Error
from . import partition_local as local, partition_origin as origin


def request(socket_path, token_path, operation, payload, *, timeout=10):
    path = Path(socket_path)
    if not path.is_absolute() or path != path.resolve() or os.geteuid() != 0:
        raise Error("local_owner_required", "managed local commands require root and a canonical private socket", 403)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Error("local_socket_unprotected", "local authority socket ancestry is not protected", 403)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise Error("local_socket_unprotected", "local authority socket is not private", 403)
    raw = json.dumps(payload,sort_keys=True,allow_nan=False).encode()
    if len(raw) > 65536: raise Error("local_wire_bound", "local request exceeds64KiB", 400)
    token = token_file(token_path)
    connection = http.client.HTTPConnection("localhost",timeout=timeout)
    transport = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    timer = response = None
    started = time.monotonic()
    try:
        transport.settimeout(timeout); transport.connect(str(path))
        if _peer_uid(transport) != 0: raise Error("local_owner_required", "local authority peer is not root", 403)
        def expire():
            try: transport.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        remaining = timeout - (time.monotonic()-started)
        if remaining <= 0: raise TimeoutError()
        transport.settimeout(remaining)
        timer = threading.Timer(remaining,expire); timer.daemon = True; timer.start()
        connection.sock = transport
        target="/v2/local/partitions/"+operation
        if operation=="inspect": target="/v1/leases/"+local.reference(payload["ref"])["lease_id"]
        connection.request("GET" if operation=="inspect" else "POST",target,body=None if operation=="inspect" else raw,
            headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
        response = connection.getresponse(); raw = response.read(65537)
        if len(raw)>65536 or time.monotonic()-started>=timeout: raise TimeoutError()
        value = json.loads(raw,object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if response.status != 200:
            if (isinstance(value,dict) and set(value)=={"error"} and isinstance(value["error"],dict)
                    and set(value["error"])=={"code","message"} and all(isinstance(v,str) for v in value["error"].values())):
                raise Error(value["error"]["code"],value["error"]["message"],response.status)
            raise Error("local_authority_response", "local authority refused the request", response.status)
        return value
    except (OSError,http.client.HTTPException,ValueError,UnicodeError):
        # A lost mutation response is uncertain. The CLI never automatically retries it.
        raise Error("local_authority_unavailable", "local response unavailable; inspect retained ownership before retrying", 503) from None
    finally:
        if timer: timer.cancel(); timer.join()
        if response: response.close()
        connection.close(); transport.close()


def read_object(name):
    with open(name,"rb") as source: raw=source.read(65537)
    if len(raw)>65536: raise Error("local_wire_bound", "local input exceeds64KiB", 400)
    return json.loads(raw,object_pairs_hook=_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def run(args, state):
    token = args.local_token_file or state/"local.token"
    call = lambda operation,payload: request(args.local_socket,token,operation,payload)
    if args.managed_action == "reserve":
        return call("reserve",{"resource_id":args.resource,"workload":read_object(args.workload),
            "resources":{"cpu_millis":args.cpu_millis,"memory_bytes":args.memory_bytes,"scratch_bytes":args.scratch_bytes},
            "expires_at_unix_millis":args.expires_at_unix_millis,"request_key":args.request_key})
    if args.managed_action == "status":
        cursor = 0; result = []
        for _ in range(64):
            page = call("pending",{"after_generation":cursor})
            if (not isinstance(page,dict) or set(page)!={"leases","has_more"} or type(page["has_more"]) is not bool
                    or not isinstance(page["leases"],list) or len(page["leases"])>1):
                raise Error("local_authority_response", "local inventory shape differs", 503)
            for row in page["leases"]:
                if not isinstance(row,dict) or set(row)!={"lease","dispatched","retired"} or any(type(row[k]) is not bool for k in ("dispatched","retired")):
                    raise Error("local_authority_response", "local inventory row differs", 503)
                lease=local.validate_lease(row["lease"])
                if lease["ref"]["generation"]<=cursor: raise Error("local_authority_response", "local inventory cursor did not advance", 503)
                cursor=lease["ref"]["generation"]; result.append(row)
            if not page["has_more"]: return {"leases":result,"scope":"ordered_observation_not_permission"}
            if not page["leases"]: raise Error("local_authority_response", "local inventory cursor is missing", 503)
        raise Error("local_authority_response", "local inventory exceeds its bounded traversal", 503)
    saved=read_object(args.lease)
    if isinstance(saved,dict) and set(saved)=={"lease"}: saved=saved["lease"]
    lease=local.validate_lease(saved)
    if args.managed_action == "run":
        return call("dispatch",{"contract":local.DISPATCH,"ref":lease["ref"],"request_key":args.request_key})
    if args.managed_action == "inspect":
        row=call("inspect",{"ref":lease["ref"]})
        if not origin.matches_row(lease,row): raise Error("local_authority_response", "retained local row differs from the saved lease", 503)
        return row
    return call("reclaim",{"lease":lease})
