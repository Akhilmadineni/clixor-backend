#!/usr/bin/env python3
"""Prove that the OCI canary does not own the production API hostname.

The release-bound connector controller separately verifies the exact candidate
tunnel, account, configuration version, canary-only ingress rule, and terminal
404.  This helper completes the proof through public DNS and authenticated TLS:
the production hostname must either identify a different healthy Clixor
revision or return the exact reviewed Cloudflare Tunnel outage response.  It
never follows redirects and treats every other HTTP or transport outcome as
ambiguous.
"""

from __future__ import annotations

import argparse
import http.client
import os
import re
import ssl
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Sequence


PRODUCTION_HOST = "clustr-api.atlanteanz.com"
PRODUCTION_PATH = "/health/ready"
EXPECTED_CLOUDFLARE_OUTAGE_BODY = b"error code: 1033\n"
MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 64 * 1024
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
CF_RAY_RE = re.compile(r"^[0-9A-Fa-f]{16,32}-[0-9A-Za-z]{3,8}$")


class NegativeProofError(RuntimeError):
    """The public response cannot prove that production is not the canary."""


class Proof:
    __slots__ = ("status", "headers", "body", "outcome")

    def __init__(
        self,
        status: int,
        headers: tuple[tuple[str, str], ...],
        body: bytes,
        outcome: str,
    ) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.outcome = outcome


ConnectionFactory = Callable[..., http.client.HTTPSConnection]


def _normalized_headers(
    raw_headers: Sequence[tuple[str, str]],
) -> tuple[tuple[tuple[str, str], ...], dict[str, list[str]]]:
    normalized: list[tuple[str, str]] = []
    grouped: dict[str, list[str]] = {}
    encoded_size = 0
    for raw_name, raw_value in raw_headers:
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise NegativeProofError("production response headers are invalid")
        try:
            raw_name.encode("ascii")
            raw_value.encode("ascii")
        except UnicodeError:
            raise NegativeProofError("production response headers are not ASCII") from None
        if (
            HEADER_NAME_RE.fullmatch(raw_name) is None
            or "\r" in raw_value
            or "\n" in raw_value
        ):
            raise NegativeProofError("production response header syntax is invalid")
        name = raw_name.lower()
        value = raw_value.strip()
        encoded_size += len(raw_name) + len(raw_value) + 4
        if encoded_size > MAX_HEADER_BYTES:
            raise NegativeProofError("production response headers are too large")
        normalized.append((raw_name, value))
        grouped.setdefault(name, []).append(value)
    return tuple(normalized), grouped


def _one_header(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name, [])
    if len(values) != 1 or not values[0]:
        raise NegativeProofError(f"production response has invalid {name} header")
    return values[0]


def validate_response(
    status: int,
    raw_headers: Sequence[tuple[str, str]],
    body: bytes,
    expected_revision: str,
) -> Proof:
    if REVISION_RE.fullmatch(expected_revision) is None:
        raise NegativeProofError("candidate revision is invalid")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise NegativeProofError("production response status is invalid")
    if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES:
        raise NegativeProofError("production response body is too large")

    normalized, headers = _normalized_headers(raw_headers)
    if _one_header(headers, "server").lower() != "cloudflare":
        raise NegativeProofError("production response did not traverse Cloudflare")
    if CF_RAY_RE.fullmatch(_one_header(headers, "cf-ray")) is None:
        raise NegativeProofError("production response has invalid cf-ray header")

    revisions = headers.get("x-clixor-revision", [])
    if len(revisions) > 1:
        raise NegativeProofError("production response has duplicate revision headers")
    if revisions:
        revision = revisions[0]
        if REVISION_RE.fullmatch(revision) is None:
            raise NegativeProofError("production response revision is invalid")
        if revision == expected_revision:
            raise NegativeProofError("candidate connector owns the production hostname")

    if 200 <= status <= 299:
        if len(revisions) != 1:
            raise NegativeProofError("healthy production response did not identify its revision")
        return Proof(status, normalized, body, "different-revision")
    if status == 530:
        if revisions:
            raise NegativeProofError("Cloudflare outage response carried a Clixor revision")
        if body != EXPECTED_CLOUDFLARE_OUTAGE_BODY:
            raise NegativeProofError("Cloudflare outage response is not the reviewed 1033 shape")
        return Proof(status, normalized, body, "cloudflare-1033")
    raise NegativeProofError("production response is ambiguous")


def fetch_proof(
    expected_revision: str,
    *,
    attempts: int = 3,
    retry_delay: float = 2.0,
    connection_factory: ConnectionFactory = http.client.HTTPSConnection,
    sleep: Callable[[float], None] = time.sleep,
) -> Proof:
    if attempts <= 0:
        raise NegativeProofError("production proof attempt count is invalid")
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    request_path = f"{PRODUCTION_PATH}?candidate-negative={expected_revision}"
    for attempt in range(attempts):
        connection: http.client.HTTPSConnection | None = None
        try:
            connection = connection_factory(
                PRODUCTION_HOST,
                443,
                timeout=10,
                context=context,
            )
            connection.request(
                "GET",
                request_path,
                headers={
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "User-Agent": "clixor-oci-negative-proof/1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            body = response.read(MAX_BODY_BYTES + 1)
            return validate_response(
                response.status,
                response.getheaders(),
                body,
                expected_revision,
            )
        except NegativeProofError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError):
            if attempt + 1 >= attempts:
                break
            sleep(retry_delay)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except (OSError, http.client.HTTPException):
                    pass
    raise NegativeProofError("production DNS/TLS/HTTP transport did not complete")


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_evidence(root: Path, proof: Proof) -> None:
    try:
        metadata = root.lstat()
    except OSError:
        raise NegativeProofError("production evidence directory is unavailable") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (os.geteuid(), os.getegid())
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise NegativeProofError("production evidence directory is unsafe")
    header_lines = [f"HTTP/1.1 {proof.status}\r\n"]
    header_lines.extend(f"{name}: {value}\r\n" for name, value in proof.headers)
    header_lines.append("\r\n")
    _atomic_write(root / "production-negative.headers", "".join(header_lines).encode("ascii"))
    _atomic_write(root / "production-negative.status", f"{proof.status}\n".encode("ascii"))
    _atomic_write(root / "production-negative.body", proof.body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--evidence-root", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise NegativeProofError("production negative proof must run as root")
        proof = fetch_proof(arguments.expected_revision)
        write_evidence(arguments.evidence_root, proof)
    except (NegativeProofError, OSError) as error:
        print(f"Clixor production negative proof refused: {error}", file=sys.stderr)
        return 1
    print(f"production-negative={proof.outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
