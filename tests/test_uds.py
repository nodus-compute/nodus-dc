"""Private socket path/ownership/lifetime tests; actual OS peer ID for success."""
import os
import http.client
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from nodus_dc.api import BridgeUnixServer, Server
from nodus_dc.errors import Error
from nodus_dc.service import Service
from nodus_dc.store import Store
from tests.test_api import UnixHTTPConnection
from tests.test_authority import Backend, Clock


class PrivateSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix=".nodus-uds-", dir=Path.home().resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        clock = Clock()
        self.service = Service(Store(self.root/"state.db"), Backend(clock), clock=clock, bridge_enabled=True)
        self.token = "fixture-private-" + "x"*40

    def server(self, path=None):
        return BridgeUnixServer(str(path or self.root/"bridge.sock"), self.service, self.token, owner_uid=os.geteuid())

    def test_insecure_parent_and_symlink_parent_are_rejected(self):
        parent = self.root/"public"
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        with self.assertRaises(Error):
            self.server(parent/"bridge.sock")
        parent.chmod(0o700)
        alias = self.root/"alias"
        alias.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(Error):
            self.server(alias/"bridge.sock")

    def test_existing_file_is_not_replaced_and_socket_mode_is_private(self):
        path = self.root/"bridge.sock"
        path.write_text("operator file")
        path.chmod(0o600)
        with self.assertRaises(Error):
            self.server(path)
        self.assertEqual(path.read_text(), "operator file")
        path.unlink()
        server = self.server(path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        server.server_close()
        self.assertFalse(path.exists())

    def test_second_listener_cannot_unlink_live_socket(self):
        server = self.server()
        try:
            identity = server.path.stat().st_ino
            with self.assertRaises(Error) as error:
                self.server()
            self.assertEqual(error.exception.code, "bridge_already_running")
            self.assertEqual(server.path.stat().st_ino, identity)
        finally:
            server.server_close()

    def test_only_owned_refused_stale_socket_can_be_replaced(self):
        path = self.root/"bridge.sock"
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(path))
        path.chmod(0o600)
        stale.close()
        server = self.server(path)
        server.server_close()
        self.assertFalse(path.exists())

    def test_close_does_not_remove_replacement_socket(self):
        server = self.server()
        path = server.path
        path.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(path))
        path.chmod(0o600)
        inode = path.stat().st_ino
        server.server_close()
        self.assertEqual(path.stat().st_ino, inode)
        replacement.close()
        path.unlink()

    def test_peer_identity_rejection_precedes_http_authorization(self):
        server = self.server()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch("nodus_dc.api._peer_uid", return_value=os.geteuid()+1):
                connection = UnixHTTPConnection(server.path)
                with self.assertRaises((ConnectionError, OSError, http.client.HTTPException)):
                    connection.request("POST", "/v1/bridge/status", "{}", {"Authorization": "Bearer "+self.token})
                    connection.getresponse()
                connection.close()
            self.assertEqual(self.service.status()["leases"], [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_tcp_server_refuses_bridge_credential_configuration(self):
        with self.assertRaises(Error) as caught:
            Server(("127.0.0.1", 0), self.service, "local-"+"y"*40, self.token)
        self.assertEqual(caught.exception.code, "bridge_transport_required")


if __name__ == "__main__":
    unittest.main()
