from __future__ import annotations

import json
import socket
import struct
import sys
import unittest
import urllib.error
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke  # noqa: E402


def server_frame(opcode: int, payload: bytes, *, final: bool = True) -> bytes:
    first = opcode | (0x80 if final else 0)
    if len(payload) < 126:
        return bytes((first, len(payload))) + payload
    if len(payload) <= 0xFFFF:
        return bytes((first, 126)) + struct.pack("!H", len(payload)) + payload
    return bytes((first, 127)) + struct.pack("!Q", len(payload)) + payload


class FailingOpener:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def open(self, request: object, timeout: float) -> object:
        del request, timeout
        raise urllib.error.URLError(f"upstream rejected {self.secret}")


class FakeAPI:
    def __init__(self) -> None:
        self.roles: list[str] = []
        self.current_role = ""
        self.attempts: dict[str, int] = {}

    def raw(self, method: str, path: str, **kwargs: object) -> smoke.HTTPResult:
        del kwargs
        if method != "DELETE" or path != "/v1/me":
            raise AssertionError("unexpected fake request")
        role = self.current_role
        self.roles.append(role)
        count = self.attempts.get(role, 0)
        self.attempts[role] = count + 1
        return smoke.HTTPResult(
            status=401 if count == 0 else 204,
            headers={},
            body=b"",
        )


class ValidationTests(unittest.TestCase):
    def test_https_origin_validation(self) -> None:
        self.assertEqual(
            smoke.validate_origin("https://API.Example.com/", "test"),
            "https://api.example.com",
        )
        for invalid in (
            "http://api.example.com",
            "https://user@api.example.com",
            "https://api.example.com:8443",
            "https://api.example.com/path",
            "https://api.example.com?secret=yes",
            "https://api.example.com/#fragment",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(smoke.SmokeFailure):
                smoke.validate_origin(invalid, "test")

    def test_par_url_is_pinned_to_expected_https_host(self) -> None:
        valid = "https://objectstorage.us-phoenix-1.oraclecloud.com/p/opaque/n/x"
        smoke.validate_par_url(
            valid, "objectstorage.us-phoenix-1.oraclecloud.com"
        )
        for invalid in (
            "http://objectstorage.us-phoenix-1.oraclecloud.com/p/opaque/n/x",
            "https://evil.example/p/opaque/n/x",
            "https://user@objectstorage.us-phoenix-1.oraclecloud.com/p/opaque/n/x",
            "https://objectstorage.us-phoenix-1.oraclecloud.com/not-a-par/x",
            "https://objectstorage.us-phoenix-1.oraclecloud.com/p/x?redirect=evil",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(smoke.SmokeFailure):
                smoke.validate_par_url(
                    invalid, "objectstorage.us-phoenix-1.oraclecloud.com"
                )

    def test_transport_error_redacts_par_url_and_secret(self) -> None:
        secret = "PAR-SECRET-MUST-NOT-LEAK"
        transport = smoke.HTTPTransport(opener=FailingOpener(secret))
        with self.assertRaises(smoke.SmokeFailure) as caught:
            smoke.download_par(
                transport,
                f"https://objectstorage.example/p/{secret}/n/namespace/b/bucket/o/object",
            )
        message = str(caught.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn("objectstorage.example", message)

    def test_confirmation_is_mandatory(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            smoke.parse_args(
                [
                    "--base-url",
                    "https://api.example.com",
                    "--legal-base-url",
                    "https://legal.example.com",
                    "--expected-media-host",
                    "objectstorage.example.com",
                    "--confirm-disposable-writes",
                    "NO",
                ]
            )


class WebSocketTests(unittest.TestCase):
    def test_fragmented_json_and_ping_are_supported(self) -> None:
        client_socket, server_socket = socket.socketpair()
        self.addCleanup(client_socket.close)
        self.addCleanup(server_socket.close)
        client = smoke.WebSocketClient._from_connected_socket(client_socket)
        payload = json.dumps({"type": "session.ready", "payload": {"ok": True}}).encode()
        server_socket.sendall(
            server_frame(0x9, b"heartbeat")
            + server_frame(0x1, payload[:8], final=False)
            + server_frame(0x0, payload[8:], final=True)
        )
        self.assertEqual(client.receive_json(1.0)["type"], "session.ready")

        pong = server_socket.recv(128)
        self.assertEqual(pong[0] & 0x0F, 0xA)
        self.assertTrue(pong[1] & 0x80)
        length = pong[1] & 0x7F
        self.assertEqual(length, len(b"heartbeat"))
        mask = pong[2:6]
        masked_payload = pong[6 : 6 + length]
        unmasked = bytes(
            value ^ mask[index % 4] for index, value in enumerate(masked_payload)
        )
        self.assertEqual(unmasked, b"heartbeat")


class CleanupTests(unittest.TestCase):
    def test_cleanup_uses_all_sessions_and_preserves_account_order(self) -> None:
        suite = smoke.SmokeSuite(
            "https://api.example.com",
            "https://legal.example.com",
            "objectstorage.example.com",
        )
        fake = FakeAPI()
        suite.api = fake  # type: ignore[assignment]
        for role in ("owner", "member"):
            account = smoke.DisposableAccount(
                role=role,
                email=f"test-{role}@example.com",
                password="not-printed-password",
                sessions=[
                    smoke.Session("expired-access", "expired-refresh"),
                    smoke.Session("active-access", "active-refresh"),
                ],
            )
            suite.accounts.append(account)

        failures: list[str] = []
        for account in suite.accounts:
            fake.current_role = account.role
            failure = suite._delete_account(account)
            if failure:
                failures.append(failure)
        self.assertEqual(failures, [])
        self.assertEqual(fake.roles, ["owner", "owner", "member", "member"])
        self.assertTrue(all(account.deleted for account in suite.accounts))


if __name__ == "__main__":
    unittest.main()
