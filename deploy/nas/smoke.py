#!/usr/bin/env python3
"""End-to-end Clustr API smoke test using only the Python standard library."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class SmokeFailure(RuntimeError):
    pass


def request(
    base_url: str,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: object | None = None,
    expected: tuple[int, ...] = (200,),
) -> object | None:
    headers = {"Accept": "application/json", "User-Agent": "clustr-smoke/1"}
    payload = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        payload = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
        data=payload,
        headers=headers,
        method=method,
    )
    try:
        response = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        response_payload = response.read()
        if response.status not in expected:
            detail = response_payload.decode(errors="replace")[:500]
            raise SmokeFailure(
                f"{method} {path}: expected {expected}, got {response.status}: {detail}"
            )
        if not response_payload:
            return None
        return json.loads(response_payload)


def register(base_url: str, email: str) -> dict[str, object]:
    result = request(
        base_url,
        "POST",
        "/v1/auth/register",
        body={
            "email": email,
            "password": "clustr-smoke-password-2026",
            "display_name": email,
            "device_name": "Smoke iPhone",
            "platform": "ios",
        },
        expected=(201,),
    )
    assert isinstance(result, dict)
    return result


def assure_adult(base_url: str, auth: dict[str, object]) -> None:
    tokens = auth["tokens"]
    assert isinstance(tokens, dict)
    result = request(
        base_url,
        "PUT",
        "/v1/me/age-assurance",
        token=str(tokens["access_token"]),
        body={
            "source": "self_attested_date_of_birth",
            "declaration": "self_declared",
            "date_of_birth": "1990-01-01",
        },
    )
    if not isinstance(result, dict) or result.get("status") != "adult":
        raise SmokeFailure(f"adult age assurance failed: {result!r}")


def publish_encryption_identity(base_url: str, auth: dict[str, object], marker: bytes) -> None:
    tokens = auth["tokens"]
    device = auth["device"]
    assert isinstance(tokens, dict) and isinstance(device, dict)
    request(
        base_url,
        "PUT",
        f"/v1/devices/{device['id']}",
        token=str(tokens["access_token"]),
        body={
            "name": "Smoke iPhone",
            "platform": "ios",
            "identity_key": base64.b64encode(marker * 32).decode(),
            "signed_prekey": {
                "key_id": 1,
                "public_key": base64.b64encode(b"p" * 32).decode(),
                "signature": base64.b64encode(b"s" * 64).decode(),
            },
        },
    )


def upload_bytes(url: str, content: bytes, headers: dict[str, str]) -> None:
    request_headers = {"User-Agent": "clustr-smoke/1", **headers}
    req = urllib.request.Request(
        url, data=content, headers=request_headers, method="PUT"
    )
    try:
        response = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:500]
        raise SmokeFailure(f"media PUT returned {error.code}: {detail}") from error
    with response:
        if response.status < 200 or response.status >= 300:
            raise SmokeFailure(f"media PUT returned {response.status}")


def download_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "clustr-smoke/1"})
    with urllib.request.urlopen(req, timeout=60) as response:
        if response.status != 200:
            raise SmokeFailure(f"media download returned {response.status}")
        return response.read()


def websocket_handshake(base_url: str, token: str) -> None:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SmokeFailure(f"invalid base URL for realtime test: {base_url}")
    tls = parsed.scheme == "https"
    port = parsed.port or (443 if tls else 80)
    connection = socket.create_connection((parsed.hostname, port), timeout=20)
    if tls:
        context = ssl.create_default_context()
        connection = context.wrap_socket(connection, server_hostname=parsed.hostname)
    connection.settimeout(20)
    websocket_key = base64.b64encode(os.urandom(16)).decode()
    host = parsed.hostname if parsed.port is None else f"{parsed.hostname}:{port}"
    handshake = (
        "GET /v1/realtime HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {websocket_key}\r\n"
        f"Authorization: Bearer {token}\r\n"
        "\r\n"
    ).encode()
    connection.sendall(handshake)
    response = b""
    while b"\r\n\r\n" not in response and len(response) < 16384:
        chunk = connection.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0]
    if b" 101 " not in status_line:
        connection.close()
        raise SmokeFailure(
            f"realtime upgrade failed: {status_line.decode(errors='replace')}"
        )
    mask = os.urandom(4)
    close_payload = struct.pack("!H", 1000)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(close_payload))
    connection.sendall(bytes([0x88, 0x80 | len(close_payload)]) + mask + masked)
    connection.close()


def run(base_url: str, expected_media_host: str | None) -> str:
    ready = request(base_url, "GET", "/health/ready")
    if ready != {"status": "ready"}:
        raise SmokeFailure(f"unexpected readiness response: {ready!r}")
    request(base_url, "GET", "/v1/me", expected=(401,))
    reset_probe = request(
        base_url,
        "POST",
        "/v1/auth/password/reset/start",
        body={"email": f"clustr-smoke-missing-{uuid.uuid4().hex}@example.com"},
        expected=(202, 503),
    )
    reset_disabled = (
        isinstance(reset_probe, dict)
        and isinstance(reset_probe.get("error"), dict)
        and reset_probe["error"].get("code") == "password_reset_unavailable"
    )
    reset_enabled = (
        isinstance(reset_probe, dict)
        and bool(reset_probe.get("challenge_id"))
        and reset_probe.get("expires_in_seconds") == 600
    )
    if not reset_disabled and not reset_enabled:
        raise SmokeFailure(f"password reset start contract failed: {reset_probe!r}")

    suffix = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
    prefix = f"clustr-smoke-public-{suffix}"
    alice = register(base_url, f"{prefix}-alice@example.com")
    bob = register(base_url, f"{prefix}-bob@example.com")
    eve = register(base_url, f"{prefix}-eve@example.com")
    assure_adult(base_url, alice)
    assure_adult(base_url, bob)
    assure_adult(base_url, eve)
    publish_encryption_identity(base_url, alice, b"i")
    publish_encryption_identity(base_url, bob, b"b")
    publish_encryption_identity(base_url, eve, b"v")

    alice_tokens = alice["tokens"]
    bob_tokens = bob["tokens"]
    eve_tokens = eve["tokens"]
    assert isinstance(alice_tokens, dict)
    assert isinstance(bob_tokens, dict)
    assert isinstance(eve_tokens, dict)
    old_refresh = str(alice_tokens["refresh_token"])
    refreshed = request(
        base_url,
        "POST",
        "/v1/auth/refresh",
        body={"refresh_token": old_refresh},
    )
    assert isinstance(refreshed, dict)
    if refreshed["refresh_token"] == old_refresh:
        raise SmokeFailure("refresh token was not rotated")
    alice_token = str(refreshed["access_token"])
    bob_token = str(bob_tokens["access_token"])
    eve_token = str(eve_tokens["access_token"])

    conversation = request(
        base_url,
        "POST",
        "/v1/conversations/",
        token=alice_token,
        body={"kind": "direct", "member_ids": [bob["user"]["id"]]},
        expected=(201,),
    )
    assert isinstance(conversation, dict)
    conversation_id = str(conversation["id"])
    request(
        base_url,
        "GET",
        f"/v1/conversations/{conversation_id}",
        token=eve_token,
        expected=(403, 404),
    )

    message_body = {
        "client_message_id": str(uuid.uuid4()),
        "content_type": "text",
        "ciphertext": base64.b64encode(b"opaque smoke envelope").decode(),
        "envelope": {
            "protocol": "clixor-e2ee-v1",
            "version": 1,
            "sender_identity_key": base64.b64encode(b"i" * 32).decode(),
            "sender_ephemeral_key": base64.b64encode(b"e" * 32).decode(),
            "recipients": [{
                "device_id": alice["device"]["id"],
                "key_id": 1,
                "wrapped_key": base64.b64encode(b"w" * 60).decode(),
            }],
            "signature": base64.b64encode(b"s" * 64).decode(),
        },
    }
    message = request(
        base_url,
        "POST",
        f"/v1/conversations/{conversation_id}/messages",
        token=alice_token,
        body=message_body,
        expected=(201,),
    )
    replay = request(
        base_url,
        "POST",
        f"/v1/conversations/{conversation_id}/messages",
        token=alice_token,
        body=message_body,
        expected=(201,),
    )
    assert isinstance(message, dict) and isinstance(replay, dict)
    if message["id"] != replay["id"] or message["seq"] != replay["seq"]:
        raise SmokeFailure("message retry was not idempotent")

    listed = request(
        base_url,
        "GET",
        f"/v1/conversations/{conversation_id}/messages?after_seq=0",
        token=bob_token,
    )
    assert isinstance(listed, dict)
    if len(listed["items"]) != 1:
        raise SmokeFailure("message replay returned an unexpected item count")
    request(
        base_url,
        "PUT",
        f"/v1/conversations/{conversation_id}/receipt",
        token=bob_token,
        body={"delivered_seq": 1, "read_seq": 1},
    )

    entity_id = str(uuid.uuid4())
    entity = request(
        base_url,
        "PUT",
        f"/v1/conversations/{conversation_id}/entities/task/{entity_id}?expected_version=0",
        token=alice_token,
        body={"title": "Public smoke entity"},
    )
    assert isinstance(entity, dict)
    if entity["version"] != 1:
        raise SmokeFailure("entity version did not advance to 1")

    media_content = b"clustr public media smoke\n"
    slot = request(
        base_url,
        "POST",
        f"/v1/conversations/{conversation_id}/media",
        token=alice_token,
        body={
            "byte_size": len(media_content),
            "ciphertext_sha256": hashlib.sha256(media_content).hexdigest(),
        },
        expected=(201,),
    )
    assert isinstance(slot, dict)
    upload = slot["upload"]
    assert isinstance(upload, dict)
    upload_url = str(upload["url"])
    actual_media_host = urllib.parse.urlparse(upload_url).hostname
    if expected_media_host and actual_media_host != expected_media_host:
        raise SmokeFailure(
            f"presigned upload host {actual_media_host!r} != {expected_media_host!r}"
        )
    upload_bytes(upload_url, media_content, dict(upload["headers"]))
    media = slot["media"]
    assert isinstance(media, dict)
    media_id = str(media["id"])
    request(
        base_url,
        "POST",
        f"/v1/media/{media_id}/complete",
        token=alice_token,
        body={},
    )
    download = request(
        base_url,
        "GET",
        f"/v1/media/{media_id}/download",
        token=bob_token,
    )
    assert isinstance(download, dict)
    if download_bytes(str(download["url"])) != media_content:
        raise SmokeFailure("downloaded media bytes did not match the upload")

    websocket_handshake(base_url, alice_token)
    # A replayed refresh secret revokes the session, so verify that defense only
    # after the access token has completed the authenticated smoke workflow.
    request(
        base_url,
        "POST",
        "/v1/auth/refresh",
        body={"refresh_token": old_refresh},
        expected=(401,),
    )
    return prefix


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-url", default="https://clustr-api.atlanteanz.com"
    )
    parser.add_argument("--expected-media-host", default=None)
    args = parser.parse_args()
    prefix = run(args.base_url, args.expected_media_host)
    print(
        "smoke=passed auth refresh authorization conversation message replay "
        "password-reset-safe-state receipt entity media-upload "
        "media-download websocket "
        f"test_prefix={prefix}"
    )


if __name__ == "__main__":
    main()
