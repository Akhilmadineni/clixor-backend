#!/usr/bin/env python3
"""Destructive, disposable smoke test for the public Clixor OCI deployment.

The runner deliberately uses only the Python standard library. Credentials and
OCI pre-authenticated-request URLs stay in memory and are never printed. Every
created account is removed in ``finally`` and the final group member is deleted
last so the backend can enqueue deletion of the group's media objects.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


MAX_BODY_BYTES = 2 << 20
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CONFIRMATION = "DELETE-ALL-SMOKE-DATA"
SAFE_ERROR_CODE = re.compile(r"^[a-z0-9_.-]{1,80}$")


class SmokeFailure(RuntimeError):
    """A failure whose message is safe to print without leaking credentials."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class HTTPTransport:
    """Bounded HTTP transport which never follows redirects or logs URLs."""

    def __init__(self, timeout: float = 30.0, opener: Any | None = None) -> None:
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        label: str = "HTTP request",
    ) -> HTTPResult:
        request_headers = {
            "Accept": "application/json",
            "Connection": "close",
            "User-Agent": "clixor-oci-smoke/1",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            url, data=body, headers=request_headers, method=method
        )
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError) as error:
            raise SmokeFailure(
                f"{label} transport failed ({type(error).__name__})"
            ) from None

        try:
            payload = response.read(MAX_BODY_BYTES + 1)
            status = int(getattr(response, "status", getattr(response, "code", 0)))
            response_headers = {
                str(name).lower(): str(value)
                for name, value in response.headers.items()
            }
        except OSError as error:
            raise SmokeFailure(
                f"{label} response failed ({type(error).__name__})"
            ) from None
        finally:
            response.close()
        if len(payload) > MAX_BODY_BYTES:
            raise SmokeFailure(f"{label} response exceeded the safe size limit")
        return HTTPResult(status=status, headers=response_headers, body=payload)


def validate_origin(value: str, label: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or (parsed.port is not None and parsed.port != 443)
    ):
        raise SmokeFailure(f"{label} must be an HTTPS origin on port 443")
    return f"https://{parsed.hostname.lower()}"


def validate_media_host(value: str) -> str:
    candidate = value.strip().lower()
    parsed = urllib.parse.urlsplit("https://" + candidate)
    if (
        not candidate
        or parsed.hostname != candidate
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise SmokeFailure("expected media host must be a bare DNS hostname")
    return candidate


def validate_par_url(url: str, expected_host: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.hostname.lower() != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.port is not None and parsed.port != 443)
        or not parsed.path.startswith("/p/")
        or parsed.query
        or parsed.fragment
    ):
        raise SmokeFailure("OCI media URL did not match the approved PAR endpoint")


def json_object(result: HTTPResult, label: str) -> dict[str, Any]:
    if "application/json" not in result.header("content-type").lower():
        raise SmokeFailure(f"{label} did not return JSON")
    try:
        value = json.loads(result.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SmokeFailure(f"{label} returned malformed JSON") from None
    if not isinstance(value, dict):
        raise SmokeFailure(f"{label} returned an unexpected JSON shape")
    return value


def error_code(result: HTTPResult) -> str:
    try:
        value = json.loads(result.body)
        code = value["error"]["code"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return "unknown"
    if isinstance(code, str) and SAFE_ERROR_CODE.fullmatch(code):
        return code
    return "unknown"


def required_dict(value: Mapping[str, Any], field_name: str, label: str) -> dict[str, Any]:
    field_value = value.get(field_name)
    if not isinstance(field_value, dict):
        raise SmokeFailure(f"{label} omitted {field_name}")
    return field_value


def required_string(value: Mapping[str, Any], field_name: str, label: str) -> str:
    field_value = value.get(field_name)
    if not isinstance(field_value, str) or not field_value:
        raise SmokeFailure(f"{label} omitted {field_name}")
    return field_value


def required_uuid(value: Mapping[str, Any], field_name: str, label: str) -> str:
    candidate = required_string(value, field_name, label)
    try:
        parsed = uuid.UUID(candidate)
    except ValueError:
        raise SmokeFailure(f"{label} returned an invalid {field_name}") from None
    return str(parsed)


def assert_security_headers(result: HTTPResult, *, public_cache: bool = False) -> None:
    if not result.header("x-request-id"):
        raise SmokeFailure("response omitted X-Request-ID")
    if result.header("x-content-type-options").lower() != "nosniff":
        raise SmokeFailure("response omitted X-Content-Type-Options")
    if result.header("x-frame-options").upper() != "DENY":
        raise SmokeFailure("response omitted X-Frame-Options")
    if result.header("referrer-policy").lower() != "no-referrer":
        raise SmokeFailure("response omitted Referrer-Policy")
    if "max-age=" not in result.header("strict-transport-security").lower():
        raise SmokeFailure("response omitted HSTS")
    cache_control = result.header("cache-control").lower()
    if public_cache:
        if "public" not in cache_control:
            raise SmokeFailure("public document did not use an explicit cache policy")
    elif "no-store" not in cache_control:
        raise SmokeFailure("API response was not marked no-store")


def assert_cloudflare(result: HTTPResult) -> None:
    if "cloudflare" not in result.header("server").lower() or not result.header("cf-ray"):
        raise SmokeFailure("public response did not traverse the Cloudflare edge")


class APIClient:
    def __init__(self, origin: str, transport: HTTPTransport) -> None:
        self.origin = origin
        self.transport = transport

    def raw(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: object | None = None,
    ) -> HTTPResult:
        if not path.startswith("/") or path.startswith("//"):
            raise SmokeFailure("internal smoke path is invalid")
        headers: dict[str, str] = {}
        payload = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        result = self.transport.request(
            method,
            self.origin + path,
            body=payload,
            headers=headers,
            label=f"{method} {path.split('?', 1)[0]}",
        )
        assert_security_headers(result)
        return result

    def expect(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: object | None = None,
        statuses: Iterable[int] = (200,),
        expected_error: str | None = None,
    ) -> HTTPResult:
        result = self.raw(method, path, token=token, body=body)
        allowed = tuple(statuses)
        if result.status not in allowed:
            raise SmokeFailure(
                f"{method} {path.split('?', 1)[0]} returned {result.status} "
                f"(error={error_code(result)})"
            )
        if expected_error is not None and error_code(result) != expected_error:
            raise SmokeFailure(
                f"{method} {path.split('?', 1)[0]} returned the wrong error contract"
            )
        return result


@dataclass(frozen=True)
class Session:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)


@dataclass
class DisposableAccount:
    role: str
    email: str
    password: str = field(repr=False)
    user_id: str = ""
    device_id: str = ""
    sessions: list[Session] = field(default_factory=list, repr=False)
    identity_key: bytes = field(default=b"", repr=False)
    deleted: bool = False

    def add_session(self, auth: Mapping[str, Any], label: str) -> Session:
        user = required_dict(auth, "user", label)
        device = required_dict(auth, "device", label)
        tokens = required_dict(auth, "tokens", label)
        user_id = required_uuid(user, "id", label)
        device_id = required_uuid(device, "id", label)
        if self.user_id and self.user_id != user_id:
            raise SmokeFailure(f"{label} changed the account identity")
        self.user_id = user_id
        self.device_id = device_id
        session = Session(
            access_token=required_string(tokens, "access_token", label),
            refresh_token=required_string(tokens, "refresh_token", label),
        )
        self.sessions.append(session)
        return session


def parse_token_pair(value: Mapping[str, Any], label: str) -> Session:
    return Session(
        access_token=required_string(value, "access_token", label),
        refresh_token=required_string(value, "refresh_token", label),
    )


class WebSocketClient:
    """Minimal RFC 6455 client sufficient for authenticated JSON smoke tests."""

    def __init__(self, origin: str, token: str, timeout: float = 20.0) -> None:
        parsed = urllib.parse.urlsplit(origin)
        host = parsed.hostname
        if parsed.scheme != "https" or host is None:
            raise SmokeFailure("realtime origin is invalid")
        connection: socket.socket | ssl.SSLSocket | None = None
        try:
            connection = socket.create_connection((host, 443), timeout=timeout)
            context = ssl.create_default_context()
            connection = context.wrap_socket(connection, server_hostname=host)
            connection.settimeout(timeout)
            websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
            request = (
                "GET /v1/realtime HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Key: {websocket_key}\r\n"
                f"Authorization: Bearer {token}\r\n"
                "User-Agent: clixor-oci-smoke/1\r\n"
                "\r\n"
            ).encode("ascii")
            connection.sendall(request)
            response = bytearray()
            while b"\r\n\r\n" not in response:
                if len(response) > 32 << 10:
                    raise SmokeFailure("realtime upgrade headers were too large")
                chunk = connection.recv(4096)
                if not chunk:
                    raise SmokeFailure("realtime upgrade ended before its response")
                response.extend(chunk)
            header_bytes, remainder = bytes(response).split(b"\r\n\r\n", 1)
            lines = header_bytes.split(b"\r\n")
            fields = lines[0].split(b" ", 2)
            if len(fields) < 2 or fields[1] != b"101":
                raise SmokeFailure("realtime upgrade did not return HTTP 101")
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if b":" not in line:
                    raise SmokeFailure("realtime upgrade returned malformed headers")
                name, value = line.split(b":", 1)
                headers[name.decode("ascii").lower()] = value.decode(
                    "iso-8859-1"
                ).strip()
            expected_accept = base64.b64encode(
                hashlib.sha1((websocket_key + WEBSOCKET_GUID).encode("ascii")).digest()
            ).decode("ascii")
            if (
                "upgrade" not in headers.get("connection", "").lower()
                or headers.get("upgrade", "").lower() != "websocket"
                or not hmac.compare_digest(
                    headers.get("sec-websocket-accept", ""), expected_accept
                )
            ):
                raise SmokeFailure("realtime upgrade validation failed")
            if (
                "cloudflare" not in headers.get("server", "").lower()
                or not headers.get("cf-ray")
            ):
                raise SmokeFailure("realtime connection bypassed the Cloudflare edge")
            self.sock = connection
            self.buffer = bytearray(remainder)
            self.closed = False
            connection = None
        except SmokeFailure:
            raise
        except OSError as error:
            raise SmokeFailure(
                f"realtime transport failed ({type(error).__name__})"
            ) from None
        finally:
            if connection is not None:
                connection.close()

    @classmethod
    def _from_connected_socket(cls, connection: socket.socket) -> "WebSocketClient":
        client = cls.__new__(cls)
        client.sock = connection
        client.buffer = bytearray()
        client.closed = False
        return client

    def _recv_exact(self, length: int) -> bytes:
        while len(self.buffer) < length:
            chunk = self.sock.recv(max(4096, length - len(self.buffer)))
            if not chunk:
                raise SmokeFailure("realtime connection closed unexpectedly")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    def _read_frame(self) -> tuple[bool, int, bytes]:
        first, second = self._recv_exact(2)
        final = bool(first & 0x80)
        opcode = first & 0x0F
        if first & 0x70:
            raise SmokeFailure("realtime frame used unsupported extensions")
        if second & 0x80:
            raise SmokeFailure("realtime server sent a masked frame")
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        if length > MAX_BODY_BYTES:
            raise SmokeFailure("realtime frame exceeded the safe size limit")
        if opcode >= 0x8 and (not final or length > 125):
            raise SmokeFailure("realtime control frame was invalid")
        return final, opcode, self._recv_exact(length)

    def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
        first = 0x80 | opcode
        length = len(payload)
        if length < 126:
            header = bytes((first, 0x80 | length))
        elif length <= 0xFFFF:
            header = bytes((first, 0x80 | 126)) + struct.pack("!H", length)
        else:
            header = bytes((first, 0x80 | 127)) + struct.pack("!Q", length)
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def receive_json(self, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        fragments = bytearray()
        fragmented = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeFailure("realtime event timed out")
            self.sock.settimeout(remaining)
            try:
                final, opcode, payload = self._read_frame()
            except (OSError, TimeoutError) as error:
                raise SmokeFailure(
                    f"realtime receive failed ({type(error).__name__})"
                ) from None
            if opcode == 0x8:
                if not self.closed:
                    self._send_frame(0x8, payload[:125])
                    self.closed = True
                raise SmokeFailure("realtime server closed before the expected event")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x2:
                raise SmokeFailure("realtime server sent an unexpected binary frame")
            if opcode == 0x1:
                if fragmented:
                    raise SmokeFailure("realtime server interleaved data messages")
                fragments.extend(payload)
                fragmented = not final
            elif opcode == 0x0:
                if not fragmented:
                    raise SmokeFailure("realtime continuation had no initial frame")
                fragments.extend(payload)
                fragmented = not final
            else:
                raise SmokeFailure("realtime server sent an unsupported frame")
            if fragmented:
                continue
            try:
                value = json.loads(fragments.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise SmokeFailure("realtime event was not valid JSON") from None
            if not isinstance(value, dict):
                raise SmokeFailure("realtime event had an unexpected JSON shape")
            return value

    def close(self) -> None:
        if getattr(self, "closed", True):
            return
        try:
            self._send_frame(0x8, struct.pack("!H", 1000))
        except OSError:
            pass
        self.closed = True
        self.sock.close()


def upload_par(
    transport: HTTPTransport,
    url: str,
    content: bytes,
    headers: Mapping[str, str],
) -> None:
    result = transport.request(
        "PUT", url, body=content, headers=headers, label="OCI media upload"
    )
    if not 200 <= result.status < 300:
        raise SmokeFailure(f"OCI media upload returned {result.status}")


def download_par(transport: HTTPTransport, url: str) -> HTTPResult:
    return transport.request("GET", url, label="OCI media download")


class SmokeSuite:
    def __init__(
        self,
        api_origin: str,
        legal_origin: str,
        media_host: str,
        *,
        cleanup_timeout: float = 45.0,
        verify_legal_documents: bool = True,
        transport: HTTPTransport | None = None,
    ) -> None:
        self.transport = transport or HTTPTransport()
        self.api = APIClient(api_origin, self.transport)
        self.api_origin = api_origin
        self.legal_origin = legal_origin
        self.media_host = media_host
        self.cleanup_timeout = cleanup_timeout
        self.verify_legal_documents = verify_legal_documents
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.prefix = f"clixor-smoke-{stamp}-{uuid.uuid4().hex[:8]}"
        self.accounts: list[DisposableAccount] = []
        self.websocket: WebSocketClient | None = None
        self.media_probe_url: str | None = None
        self.checks = 0

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            raise SmokeFailure(message)
        self.checks += 1

    def account(self, role: str) -> DisposableAccount:
        account = DisposableAccount(
            role=role,
            email=f"{self.prefix}-{role}@example.com",
            password=secrets.token_urlsafe(32),
        )
        self.accounts.append(account)
        return account

    def register(self, account: DisposableAccount) -> Session:
        result = self.api.expect(
            "POST",
            "/v1/auth/register",
            body={
                "email": account.email,
                "password": account.password,
                "display_name": f"OCI smoke {account.role}",
                "device_name": "OCI smoke iPhone",
                "platform": "ios",
            },
            statuses=(201,),
        )
        auth = json_object(result, "register")
        session = account.add_session(auth, "register")
        self.check(
            required_dict(auth, "user", "register").get("email") == account.email,
            "register returned the wrong email",
        )
        return session

    def login(self, account: DisposableAccount) -> Session:
        result = self.api.expect(
            "POST",
            "/v1/auth/login",
            body={
                "email": account.email,
                "password": account.password,
                "device_name": "OCI smoke iPhone",
                "platform": "ios",
            },
        )
        return account.add_session(json_object(result, "login"), "login")

    def assure_adult(self, account: DisposableAccount, session: Session) -> None:
        result = self.api.expect(
            "PUT",
            "/v1/me/age-assurance",
            token=session.access_token,
            body={
                "source": "self_attested_date_of_birth",
                "declaration": "self_declared",
                "date_of_birth": "1990-01-01",
            },
        )
        assurance = json_object(result, "age assurance")
        self.check(
            assurance.get("status") == "adult"
            and assurance.get("minimum_age") == 18,
            "adult age assurance did not persist",
        )

    def publish_identity(self, account: DisposableAccount, session: Session) -> None:
        account.identity_key = secrets.token_bytes(32)
        result = self.api.expect(
            "PUT",
            f"/v1/devices/{account.device_id}",
            token=session.access_token,
            body={
                "name": "OCI smoke iPhone",
                "platform": "ios",
                "identity_key": base64.b64encode(account.identity_key).decode("ascii"),
                "signed_prekey": {
                    "key_id": 1,
                    "public_key": base64.b64encode(
                        secrets.token_bytes(32)
                    ).decode("ascii"),
                    "signature": base64.b64encode(
                        secrets.token_bytes(64)
                    ).decode("ascii"),
                },
            },
        )
        device = json_object(result, "device identity")
        self.check(
            device.get("identity_key")
            == base64.b64encode(account.identity_key).decode("ascii"),
            "device identity did not round-trip",
        )

    def verify_edge_and_legal(self) -> None:
        live = self.api.expect("GET", "/health/live")
        assert_cloudflare(live)
        self.check(json_object(live, "liveness") == {"status": "ok"}, "liveness failed")
        ready = self.api.expect("GET", "/health/ready")
        assert_cloudflare(ready)
        self.check(
            json_object(ready, "readiness") == {"status": "ready"},
            "readiness failed",
        )
        for path in ("/", "/privacy", "/legal", "/terms"):
            redirect = self.transport.request(
                "GET", self.api_origin + path, label=f"legal redirect {path}"
            )
            if redirect.status != 308:
                raise SmokeFailure(f"legal redirect {path} returned {redirect.status}")
            assert_cloudflare(redirect)
            assert_security_headers(redirect, public_cache=True)
            self.check(
                redirect.header("location") == self.legal_origin + path,
                f"legal redirect {path} targeted the wrong origin",
            )
            if not self.verify_legal_documents:
                continue
            document = self.transport.request(
                "GET", self.legal_origin + path, label=f"legal document {path}"
            )
            if document.status != 200:
                raise SmokeFailure(f"legal document {path} returned {document.status}")
            assert_cloudflare(document)
            assert_security_headers(document, public_cache=True)
            self.check(
                "text/html" in document.header("content-type").lower()
                and b"Privacy Policy &amp; Terms of Use" in document.body,
                f"legal document {path} had unexpected content",
            )

    def verify_unauthenticated_contract(self) -> None:
        self.api.expect(
            "GET", "/v1/me", statuses=(401,), expected_error="unauthenticated"
        )
        metrics = self.api.expect(
            "GET", "/metrics", statuses=(401,), expected_error="unauthenticated"
        )
        self.check(
            metrics.status == 401,
            "metrics authentication contract failed",
        )

    def verify_auth_lifecycle_and_rate_limit(self) -> None:
        account = self.account("lifecycle")
        registration = self.register(account)
        self.api.expect(
            "POST",
            "/v1/auth/register",
            body={
                "email": account.email,
                "password": account.password,
                "display_name": "duplicate",
                "device_name": "OCI smoke iPhone",
                "platform": "ios",
            },
            statuses=(409,),
            expected_error="conflict",
        )
        self.api.expect(
            "POST",
            "/v1/auth/login",
            body={
                "email": account.email,
                "password": secrets.token_urlsafe(32),
                "device_name": "OCI smoke iPhone",
                "platform": "ios",
            },
            statuses=(401,),
            expected_error="invalid_credentials",
        )

        # Exercise a narrow, disposable identity quota rather than exhausting
        # the shared public auth/IP budget needed for deterministic cleanup.
        for _ in range(10):
            self.api.expect(
                "PUT",
                "/v1/me/age-assurance",
                token=registration.access_token,
                body={"source": "invalid"},
                statuses=(422,),
                expected_error="invalid_age_assurance",
            )
        limited = self.api.expect(
            "PUT",
            "/v1/me/age-assurance",
            token=registration.access_token,
            body={"source": "invalid"},
            statuses=(429,),
            expected_error="rate_limited",
        )
        self.check(bool(limited.header("retry-after")), "rate limit omitted Retry-After")

        login_session = self.login(account)
        refreshed_result = self.api.expect(
            "POST",
            "/v1/auth/refresh",
            body={"refresh_token": login_session.refresh_token},
        )
        refreshed = parse_token_pair(json_object(refreshed_result, "refresh"), "refresh")
        account.sessions.append(refreshed)
        self.check(
            refreshed.refresh_token != login_session.refresh_token,
            "refresh token did not rotate",
        )
        self.api.expect(
            "POST",
            "/v1/auth/refresh",
            body={"refresh_token": login_session.refresh_token},
            statuses=(401,),
            expected_error="unauthenticated",
        )
        self.api.expect(
            "GET",
            "/v1/me",
            token=refreshed.access_token,
            statuses=(401,),
            expected_error="unauthenticated",
        )
        self.api.expect(
            "POST",
            "/v1/auth/refresh",
            body={"refresh_token": refreshed.refresh_token},
            statuses=(401,),
            expected_error="unauthenticated",
        )

        logout_session = self.login(account)
        self.api.expect(
            "POST",
            "/v1/auth/logout",
            token=logout_session.access_token,
            statuses=(204,),
        )
        self.api.expect(
            "GET",
            "/v1/me",
            token=logout_session.access_token,
            statuses=(401,),
            expected_error="unauthenticated",
        )
        self.api.expect(
            "POST",
            "/v1/auth/refresh",
            body={"refresh_token": logout_session.refresh_token},
            statuses=(401,),
            expected_error="unauthenticated",
        )

        self.api.expect(
            "DELETE", "/v1/me", token=registration.access_token, statuses=(204,)
        )
        account.deleted = True
        self.api.expect(
            "GET",
            "/v1/me",
            token=registration.access_token,
            statuses=(401,),
            expected_error="unauthenticated",
        )
        self.api.expect(
            "POST",
            "/v1/auth/refresh",
            body={"refresh_token": registration.refresh_token},
            statuses=(401,),
            expected_error="unauthenticated",
        )
        self.api.expect(
            "POST",
            "/v1/auth/login",
            body={
                "email": account.email,
                "password": account.password,
                "device_name": "OCI smoke iPhone",
                "platform": "ios",
            },
            statuses=(401,),
            expected_error="invalid_credentials",
        )

    def verify_group_realtime_and_media(self) -> None:
        owner = self.account("owner")
        member = self.account("member")
        outsider = self.account("outsider")
        owner_session = self.register(owner)
        member_session = self.register(member)
        outsider_session = self.register(outsider)
        for account, session in (
            (owner, owner_session),
            (member, member_session),
            (outsider, outsider_session),
        ):
            self.assure_adult(account, session)
            self.publish_identity(account, session)

        conversation_result = self.api.expect(
            "POST",
            "/v1/conversations/",
            token=owner_session.access_token,
            body={
                "kind": "group",
                "title": f"OCI smoke {self.prefix[-8:]}",
                "member_ids": [member.user_id],
            },
            statuses=(201,),
        )
        conversation = json_object(conversation_result, "group creation")
        conversation_id = required_uuid(conversation, "id", "group creation")
        self.check(conversation.get("kind") == "group", "group kind did not persist")
        self.api.expect(
            "GET",
            f"/v1/conversations/{conversation_id}",
            token=outsider_session.access_token,
            statuses=(404,),
            expected_error="not_found",
        )

        self.websocket = WebSocketClient(self.api_origin, member_session.access_token)
        ready = self.websocket.receive_json(15.0)
        ready_payload = ready.get("payload")
        self.check(
            ready.get("type") == "session.ready"
            and isinstance(ready_payload, dict)
            and ready_payload.get("user_id") == member.user_id
            and ready_payload.get("device_id") == member.device_id
            and isinstance(ready_payload.get("heartbeat_seconds"), (int, float)),
            "realtime session.ready identity was incorrect",
        )

        ciphertext = secrets.token_bytes(96)
        client_message_id = str(uuid.uuid4())
        envelope = {
            "protocol": "clixor-e2ee-v1",
            "version": 1,
            "sender_identity_key": base64.b64encode(owner.identity_key).decode("ascii"),
            "sender_ephemeral_key": base64.b64encode(
                secrets.token_bytes(32)
            ).decode("ascii"),
            "recipients": [
                {
                    "device_id": account.device_id,
                    "key_id": 1,
                    "wrapped_key": base64.b64encode(
                        secrets.token_bytes(60)
                    ).decode("ascii"),
                }
                for account in (owner, member)
            ],
            "signature": base64.b64encode(secrets.token_bytes(64)).decode("ascii"),
        }
        message_body = {
            "client_message_id": client_message_id,
            "content_type": "text",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "envelope": envelope,
        }
        message_result = self.api.expect(
            "POST",
            f"/v1/conversations/{conversation_id}/messages",
            token=owner_session.access_token,
            body=message_body,
            statuses=(201,),
        )
        message = json_object(message_result, "message creation")
        message_id = required_uuid(message, "id", "message creation")
        message_seq = message.get("seq")
        self.check(
            isinstance(message_seq, int)
            and message_seq == 1
            and message.get("ciphertext") == message_body["ciphertext"]
            and message.get("envelope") == envelope,
            "E2EE message did not round-trip",
        )
        replay = json_object(
            self.api.expect(
                "POST",
                f"/v1/conversations/{conversation_id}/messages",
                token=owner_session.access_token,
                body=message_body,
                statuses=(201,),
            ),
            "message retry",
        )
        self.check(
            replay.get("id") == message_id and replay.get("seq") == message_seq,
            "message retry was not idempotent",
        )

        deadline = time.monotonic() + 20.0
        delivered = False
        while time.monotonic() < deadline:
            event = self.websocket.receive_json(max(0.1, deadline - time.monotonic()))
            if event.get("type") != "message.created":
                continue
            payload = event.get("payload")
            if (
                event.get("id") == message_id
                and event.get("conversation_id") == conversation_id
                and event.get("seq") == message_seq
                and isinstance(payload, dict)
                and payload.get("id") == message_id
            ):
                delivered = True
                break
        self.check(
            delivered,
            "cross-replica realtime delivery did not publish message.created",
        )

        # A successful first upgrade is insufficient: exercise the mobile
        # reconnect path through Cloudflare and require a second authenticated
        # RFC 6455 upgrade before accepting the canary.
        self.websocket.close()
        self.websocket = WebSocketClient(self.api_origin, member_session.access_token)
        reconnected = self.websocket.receive_json(15.0)
        reconnect_payload = reconnected.get("payload")
        self.check(
            reconnected.get("type") == "session.ready"
            and isinstance(reconnect_payload, dict)
            and reconnect_payload.get("user_id") == member.user_id
            and reconnect_payload.get("device_id") == member.device_id,
            "realtime reconnect did not restore the authenticated identity",
        )

        listed = json_object(
            self.api.expect(
                "GET",
                f"/v1/conversations/{conversation_id}/messages?after_seq=0",
                token=member_session.access_token,
            ),
            "message listing",
        )
        items = listed.get("items")
        self.check(
            isinstance(items, list)
            and len(items) == 1
            and isinstance(items[0], dict)
            and items[0].get("id") == message_id
            and items[0].get("ciphertext") == message_body["ciphertext"]
            and items[0].get("envelope") == envelope,
            "member message history did not match the E2EE write",
        )

        media_bytes = b"clixor-oci-public-smoke\n" + secrets.token_bytes(128)
        media_hash = hashlib.sha256(media_bytes).hexdigest()
        slot = json_object(
            self.api.expect(
                "POST",
                f"/v1/conversations/{conversation_id}/media",
                token=owner_session.access_token,
                body={
                    "byte_size": len(media_bytes),
                    "ciphertext_sha256": media_hash,
                },
                statuses=(201,),
            ),
            "media slot",
        )
        media = required_dict(slot, "media", "media slot")
        upload = required_dict(slot, "upload", "media slot")
        media_id = required_uuid(media, "id", "media slot")
        upload_url = required_string(upload, "url", "media slot")
        self.check(upload.get("method") == "PUT", "media slot used the wrong method")
        validate_par_url(upload_url, self.media_host)
        upload_headers = upload.get("headers")
        if not isinstance(upload_headers, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in upload_headers.items()
        ):
            raise SmokeFailure("media slot returned invalid upload headers")
        normalized_headers = {key.lower(): value for key, value in upload_headers.items()}
        self.check(
            normalized_headers == {"content-type": "application/octet-stream"},
            "media slot returned unexpected upload headers",
        )
        upload_par(self.transport, upload_url, media_bytes, upload_headers)
        completed = json_object(
            self.api.expect(
                "POST",
                f"/v1/media/{media_id}/complete",
                token=owner_session.access_token,
                body={},
            ),
            "media completion",
        )
        self.check(
            completed.get("status") == "ready"
            and completed.get("ciphertext_sha256") == media_hash,
            "media completion did not preserve metadata",
        )
        self.api.expect(
            "GET",
            f"/v1/media/{media_id}/download",
            token=outsider_session.access_token,
            statuses=(404,),
            expected_error="not_found",
        )
        download = json_object(
            self.api.expect(
                "GET",
                f"/v1/media/{media_id}/download",
                token=member_session.access_token,
            ),
            "media download slot",
        )
        download_url = required_string(download, "url", "media download slot")
        validate_par_url(download_url, self.media_host)
        downloaded = download_par(self.transport, download_url)
        if downloaded.status != 200:
            raise SmokeFailure(f"OCI media download returned {downloaded.status}")
        self.check(
            len(downloaded.body) == len(media_bytes)
            and hmac.compare_digest(hashlib.sha256(downloaded.body).hexdigest(), media_hash)
            and hmac.compare_digest(downloaded.body, media_bytes),
            "OCI media bytes or ciphertext hash did not match",
        )
        self.media_probe_url = download_url

    def execute(self) -> None:
        self.verify_edge_and_legal()
        self.verify_unauthenticated_contract()
        self.verify_auth_lifecycle_and_rate_limit()
        self.verify_group_realtime_and_media()

    def _delete_account(self, account: DisposableAccount) -> str | None:
        if account.deleted:
            return None
        for session in account.sessions:
            result = self.api.raw(
                "DELETE", "/v1/me", token=session.access_token
            )
            if result.status == 204:
                account.deleted = True
                return None
            if result.status == 401:
                continue
            return f"{account.role}:delete_status_{result.status}"

        login = self.api.raw(
            "POST",
            "/v1/auth/login",
            body={
                "email": account.email,
                "password": account.password,
                "device_name": "OCI smoke cleanup",
                "platform": "ios",
            },
        )
        if login.status == 401:
            account.deleted = True
            return None
        if login.status != 200:
            return f"{account.role}:cleanup_login_status_{login.status}"
        try:
            session = account.add_session(json_object(login, "cleanup login"), "cleanup login")
        except SmokeFailure:
            return f"{account.role}:cleanup_login_contract"
        deleted = self.api.raw("DELETE", "/v1/me", token=session.access_token)
        if deleted.status == 204:
            account.deleted = True
            return None
        return f"{account.role}:cleanup_delete_status_{deleted.status}"

    def _wait_for_media_deletion(self) -> str | None:
        if self.media_probe_url is None:
            return None
        deadline = time.monotonic() + self.cleanup_timeout
        last_status = 0
        while time.monotonic() < deadline:
            try:
                result = download_par(self.transport, self.media_probe_url)
            except SmokeFailure:
                return "media:cleanup_probe_transport"
            last_status = result.status
            if result.status in {401, 403, 404, 410}:
                return None
            if 200 <= result.status < 300 or result.status >= 500:
                time.sleep(1.0)
                continue
            return f"media:cleanup_probe_status_{result.status}"
        return f"media:still_accessible_status_{last_status}"

    def cleanup(self) -> list[str]:
        failures: list[str] = []
        if self.websocket is not None:
            self.websocket.close()
            self.websocket = None
        # Creation order is lifecycle, owner, member, outsider. Deleting owner
        # before the final member preserves shared history briefly; deleting the
        # member then removes the group and enqueues every OCI object for removal.
        for account in self.accounts:
            try:
                failure = self._delete_account(account)
            except SmokeFailure:
                failure = f"{account.role}:cleanup_transport_or_contract"
            if failure:
                failures.append(failure)
        try:
            media_failure = self._wait_for_media_deletion()
        except SmokeFailure:
            media_failure = "media:cleanup_verification"
        if media_failure:
            failures.append(media_failure)
        return failures


def run(
    api_origin: str,
    legal_origin: str,
    media_host: str,
    *,
    cleanup_timeout: float = 45.0,
    verify_legal_documents: bool = True,
) -> tuple[str, int]:
    suite = SmokeSuite(
        api_origin,
        legal_origin,
        media_host,
        cleanup_timeout=cleanup_timeout,
        verify_legal_documents=verify_legal_documents,
    )
    primary: BaseException | None = None
    cleanup_failures: list[str] = []
    try:
        suite.execute()
    except BaseException as error:
        primary = error
    finally:
        # Account and media cleanup also runs for Ctrl-C and other interruptions.
        try:
            cleanup_failures = suite.cleanup()
        except BaseException as error:
            cleanup_failures = [f"suite:internal_{type(error).__name__}"]
    if primary is not None:
        if isinstance(primary, SmokeFailure):
            primary_detail = str(primary)
        else:
            primary_detail = f"internal failure ({type(primary).__name__})"
        if cleanup_failures:
            raise SmokeFailure(
                primary_detail + "; cleanup failed: " + ",".join(cleanup_failures)
            ) from None
        raise primary
    if cleanup_failures:
        raise SmokeFailure("cleanup failed: " + ",".join(cleanup_failures))
    return suite.prefix, suite.checks


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the destructive disposable smoke suite against public OCI."
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--legal-base-url", required=True)
    parser.add_argument("--expected-media-host", required=True)
    parser.add_argument(
        "--confirm-disposable-writes",
        required=True,
        metavar=CONFIRMATION,
        help=f"must equal {CONFIRMATION}",
    )
    parser.add_argument("--cleanup-timeout", type=float, default=45.0)
    parser.add_argument(
        "--canary-api-only",
        action="store_true",
        help="verify legal redirect targets but defer old production legal documents",
    )
    args = parser.parse_args(argv)
    if args.confirm_disposable_writes != CONFIRMATION:
        parser.error(f"--confirm-disposable-writes must equal {CONFIRMATION}")
    if not 5.0 <= args.cleanup_timeout <= 120.0:
        parser.error("--cleanup-timeout must be between 5 and 120 seconds")
    try:
        args.base_url = validate_origin(args.base_url, "base URL")
        args.legal_base_url = validate_origin(args.legal_base_url, "legal base URL")
        args.expected_media_host = validate_media_host(args.expected_media_host)
    except SmokeFailure as error:
        parser.error(str(error))
    if args.base_url == args.legal_base_url:
        parser.error("API and legal origins must be different")
    if args.canary_api_only and args.base_url != "https://clixor-oci-canary.atlanteanz.com":
        parser.error("--canary-api-only may target only the reviewed OCI canary")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        prefix, checks = run(
            args.base_url,
            args.legal_base_url,
            args.expected_media_host,
            cleanup_timeout=args.cleanup_timeout,
            verify_legal_documents=not args.canary_api_only,
        )
    except SmokeFailure as error:
        print(f"smoke=failed reason={error}", file=sys.stderr)
        return 1
    except Exception as error:
        print(
            f"smoke=failed reason=internal_failure_{type(error).__name__}",
            file=sys.stderr,
        )
        return 1
    print(f"smoke=passed prefix={prefix} checks={checks} cleanup=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
