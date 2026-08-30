#!/usr/bin/env python3
"""Validate immutable Clixor backup manifests without handling credentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
MIGRATION_PATTERN = re.compile(r"^(\d{6})_[A-Za-z0-9][A-Za-z0-9_-]*\.sql$")


class BackupManifestError(ValueError):
    """A backup listing or checksum manifest violated the expected contract."""


@dataclass(frozen=True)
class BackupObject:
    name: str
    size: int
    created_at: datetime


def validate_prefix(prefix: str) -> str:
    if not PREFIX_PATTERN.fullmatch(prefix):
        raise BackupManifestError("backup prefix contains unsupported characters")
    return prefix


def select_latest_complete_backup(
    document: dict[str, Any],
    prefix: str,
    max_age_minutes: int,
    *,
    now: datetime | None = None,
) -> BackupObject:
    validate_prefix(prefix)
    if max_age_minutes <= 0:
        raise BackupManifestError("maximum backup age must be positive")
    entries = document.get("data")
    if not isinstance(entries, list):
        raise BackupManifestError("OCI object listing has no data array")

    object_names: set[str] = set()
    object_sizes: dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise BackupManifestError("OCI object listing contains a non-object entry")
        name = entry.get("name")
        size = entry.get("size")
        if not isinstance(name, str) or not isinstance(size, int) or size < 0:
            raise BackupManifestError("OCI object listing contains an invalid name or size")
        object_names.add(name)
        object_sizes[name] = size

    pattern = re.compile(
        rf"^{re.escape(prefix)}/postgres/clixor-(\d{{8}}T\d{{6}}Z)\.dump$"
    )
    candidates: list[BackupObject] = []
    for name in object_names:
        match = pattern.fullmatch(name)
        if match is None or f"{name}.sha256" not in object_names:
            continue
        if object_sizes[name] <= 0 or object_sizes[f"{name}.sha256"] <= 0:
            continue
        try:
            created_at = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError as exc:
            raise BackupManifestError("backup object has an invalid timestamp") from exc
        candidates.append(BackupObject(name, object_sizes[name], created_at))

    if not candidates:
        raise BackupManifestError("no complete dump and checksum pair exists")
    latest = max(candidates, key=lambda candidate: candidate.created_at)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise BackupManifestError("current time must be timezone-aware")
    if latest.created_at > current + timedelta(minutes=5):
        raise BackupManifestError("latest backup timestamp is unexpectedly in the future")
    if current - latest.created_at > timedelta(minutes=max_age_minutes):
        raise BackupManifestError("latest complete offsite backup is stale")
    return latest


def verify_checksum(dump_path: Path, checksum_path: Path) -> None:
    if not dump_path.is_file() or dump_path.stat().st_size <= 0:
        raise BackupManifestError("downloaded dump is missing or empty")
    if not checksum_path.is_file() or checksum_path.stat().st_size > 512:
        raise BackupManifestError("checksum sidecar is missing or oversized")
    try:
        manifest = checksum_path.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise BackupManifestError("checksum sidecar is not ASCII") from exc
    lines = manifest.splitlines()
    if len(lines) != 1:
        raise BackupManifestError("checksum sidecar must contain exactly one record")
    match = re.fullmatch(r"([0-9a-f]{64})  (clixor-\d{8}T\d{6}Z\.dump)", lines[0])
    if match is None or match.group(2) != dump_path.name:
        raise BackupManifestError("checksum sidecar names an unexpected dump")

    digest = hashlib.sha256()
    with dump_path.open("rb") as dump_file:
        for chunk in iter(lambda: dump_file.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != match.group(1):
        raise BackupManifestError("downloaded dump checksum does not match")


def required_migration_versions(directory: Path) -> list[int]:
    if not directory.is_dir():
        raise BackupManifestError("migration directory is missing")
    versions: list[int] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.suffix != ".sql":
            continue
        match = MIGRATION_PATTERN.fullmatch(path.name)
        if match is None:
            raise BackupManifestError(f"invalid migration filename: {path.name}")
        versions.append(int(match.group(1)))
    if not versions or len(versions) != len(set(versions)):
        raise BackupManifestError("migration versions are empty or duplicated")
    if versions[0] != 1 or versions != list(range(1, versions[-1] + 1)):
        raise BackupManifestError("migration versions are not contiguous")
    return versions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    select = subparsers.add_parser("select")
    select.add_argument("--prefix", required=True)
    select.add_argument("--max-age-minutes", type=int, required=True)
    select.add_argument("--field", choices=("name", "size"), required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--dump", type=Path, required=True)
    verify.add_argument("--checksum", type=Path, required=True)

    migrations = subparsers.add_parser("migrations")
    migrations.add_argument("--directory", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "select":
            selected = select_latest_complete_backup(
                json.load(sys.stdin), args.prefix, args.max_age_minutes
            )
            print(selected.name if args.field == "name" else selected.size)
        elif args.command == "verify":
            verify_checksum(args.dump, args.checksum)
        else:
            print(
                ",".join(
                    str(version)
                    for version in required_migration_versions(args.directory)
                )
            )
    except (BackupManifestError, json.JSONDecodeError, OSError) as exc:
        print(f"backup manifest validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
