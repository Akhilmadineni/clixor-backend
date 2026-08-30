#!/usr/bin/env python3
"""Validate that public Cloudflare responses came from one exact OCI release."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any


EXPECTED_APP_ID = "H9S3BAQ9U8.com.Clustr.Clustr.Clustr"
EXPECTED_ASSOCIATION = {
    "applinks": {
        "apps": [],
        "details": [
            {
                "appIDs": [EXPECTED_APP_ID],
                "components": [
                    {
                        "/": "/join",
                        "comment": "Matches only the fixed Clixor invite landing path.",
                    }
                ],
            }
        ],
    }
}
REVISION_RE = re.compile(r"[0-9a-f]{40}")


class SmokeValidationError(Exception):
    pass


def _read_regular(path: Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError:
        raise SmokeValidationError(f"public smoke artifact is unavailable: {path.name}") from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SmokeValidationError(f"public smoke artifact is unsafe: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise SmokeValidationError(f"public smoke artifact has invalid size: {path.name}")
    try:
        return path.read_bytes()
    except OSError:
        raise SmokeValidationError(f"public smoke artifact cannot be read: {path.name}") from None


def _parse_headers(path: Path) -> dict[str, list[str]]:
    raw = _read_regular(path, 64 * 1024)
    blocks = [block for block in raw.replace(b"\r\n", b"\n").split(b"\n\n") if block]
    if not blocks:
        raise SmokeValidationError(f"HTTP headers are empty: {path.name}")
    lines = blocks[-1].splitlines()
    try:
        status = lines[0].decode("ascii").split()
    except (UnicodeDecodeError, IndexError):
        raise SmokeValidationError(f"HTTP status is invalid: {path.name}") from None
    if len(status) < 2 or not status[0].startswith("HTTP/") or status[1] != "200":
        raise SmokeValidationError(f"HTTP status is not 200: {path.name}")
    headers: dict[str, list[str]] = {}
    for raw_line in lines[1:]:
        if raw_line.startswith((b" ", b"\t")) or b":" not in raw_line:
            raise SmokeValidationError(f"HTTP header syntax is invalid: {path.name}")
        raw_name, raw_value = raw_line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").strip().lower()
            value = raw_value.decode("ascii").strip()
        except UnicodeDecodeError:
            raise SmokeValidationError(f"HTTP header encoding is invalid: {path.name}") from None
        if not name:
            raise SmokeValidationError(f"HTTP header name is invalid: {path.name}")
        headers.setdefault(name, []).append(value)
    return headers


def _one_header(headers: dict[str, list[str]], name: str, artifact: str) -> str:
    values = headers.get(name, [])
    if len(values) != 1 or not values[0]:
        raise SmokeValidationError(f"{artifact} has invalid {name} header")
    return values[0]


def _json_no_duplicates(raw: bytes, artifact: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SmokeValidationError(f"{artifact} JSON contains a duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs)
    except SmokeValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SmokeValidationError(f"{artifact} body is not canonical JSON") from None


def validate(
    api_headers_path: Path,
    api_body_path: Path,
    association_headers_path: Path,
    association_body_path: Path,
    expected_revision: str,
) -> None:
    if REVISION_RE.fullmatch(expected_revision) is None:
        raise SmokeValidationError("expected revision is invalid")

    api_headers = _parse_headers(api_headers_path)
    if _one_header(api_headers, "x-clixor-revision", "readiness") != expected_revision:
        raise SmokeValidationError("public readiness came from a different release")
    api_content_type = _one_header(api_headers, "content-type", "readiness")
    if api_content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise SmokeValidationError("public readiness content type is invalid")
    api = _json_no_duplicates(_read_regular(api_body_path, 64 * 1024), "readiness")
    if api != {"status": "ready", "revision": expected_revision}:
        raise SmokeValidationError("public readiness payload does not identify the release")

    association_headers = _parse_headers(association_headers_path)
    if (
        _one_header(association_headers, "x-clixor-revision", "association")
        != expected_revision
    ):
        raise SmokeValidationError("public association document came from a different release")
    association_content_type = _one_header(
        association_headers, "content-type", "association"
    )
    if association_content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise SmokeValidationError("association document content type is invalid")
    association = _json_no_duplicates(
        _read_regular(association_body_path, 1024 * 1024), "association"
    )
    if association != EXPECTED_ASSOCIATION:
        raise SmokeValidationError("association document is not the reviewed exact policy")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-headers", type=Path, required=True)
    parser.add_argument("--api-body", type=Path, required=True)
    parser.add_argument("--association-headers", type=Path, required=True)
    parser.add_argument("--association-body", type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    args = parser.parse_args(argv)
    try:
        validate(
            args.api_headers,
            args.api_body,
            args.association_headers,
            args.association_body,
            args.expected_revision,
        )
    except SmokeValidationError as exc:
        print(f"Public ingress validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
