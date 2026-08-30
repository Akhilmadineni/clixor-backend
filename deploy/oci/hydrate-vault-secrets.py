#!/usr/bin/python3
"""Materialize one release-approved Clixor OCI Vault secret cohort."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import resource
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote, urlparse


DEFAULT_MAPPING = Path("/etc/clixor/vault-secrets.map")
DEFAULT_SECRET_ROOT = Path("/run/clixor/secrets")
DEFAULT_OCI_BINARY = Path("/usr/local/bin/oci")
DEFAULT_OPENSSL_BINARY = Path("/usr/bin/openssl")
APPROVED_MANIFEST_NAME = "vault-approved-cohort.json"
APPROVED_MAPPING_NAME = "vault-secrets.map"
BOOT_SECRET_DIRECTORY_NAME = "boot-secrets"
BOOT_CHECKSUM_NAME = "SHA256SUMS"
BOOT_FILE_MODES = {
    "hydrate-vault-secrets.py": 0o500,
    "prepare-runtime-secrets.sh": 0o500,
}
MANIFEST_SCHEMA = 1
GENERATION_ROOT_NAME = "vault-generations"
ACTIVE_NAME = "active"
MARKER_NAME = ".vault-hydrated"
MATERIALIZED_MANIFEST_NAME = ".secret-integrity.json"
MATERIALIZED_MANIFEST_SCHEMA = 1
MAX_ENV_BYTES = 256 * 1024
MAX_APNS_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 8 * 1024
MAX_ENCODED_BYTES = 384 * 1024
MAX_OCI_RESPONSE_BYTES = MAX_ENCODED_BYTES + 64 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_OCI_VERSION_NUMBER = (1 << 63) - 1

REQUIRED_MAPPING_NAMES = frozenset(
    {
        "api_env",
        "postgres_env",
        "redis_env",
        "nats_env",
        "grafana_env",
        "apns_production_p8",
        "cloudflare_token",
    }
)
OPTIONAL_MAPPING_NAMES = frozenset({"apns_sandbox_p8"})
ALL_MAPPING_NAMES = REQUIRED_MAPPING_NAMES | OPTIONAL_MAPPING_NAMES

OCI_SECRET_RE = re.compile(
    r"^ocid1\.vaultsecret\.oc[1-9]\.[a-z0-9-]+\.[A-Za-z0-9._-]{10,255}$"
)
MAPPING_LINE_RE = re.compile(r"^([a-z][a-z0-9_]*)=(\S+)$")
ENV_LINE_RE = re.compile(rb"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
TOKEN_RE = re.compile(rb"^[A-Za-z0-9._=-]{40,8192}$")
OPAQUE_SECRET_RE = re.compile(rb"^[^\x00-\x20\x7f]{32,8192}$")
SERVICE_SECRET_RE = re.compile(rb"^[A-Za-z0-9._~-]{32,256}$")
SERVICE_NAME_RE = re.compile(rb"^[A-Za-z0-9._-]{1,64}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
RELEASE_COHORT_RE = re.compile(r"^oci-[a-f0-9]{12}-[A-Za-z0-9._-]{1,160}$")

API_ALLOWED_KEYS = frozenset(
    {
        "CLUSTER_ACCESS_TTL",
        "CLUSTER_APNS_BUNDLE_ID",
        "CLUSTER_APNS_ENVIRONMENT",
        "CLUSTER_APNS_KEY_ID",
        "CLUSTER_APNS_PRIVATE_KEY_FILE",
        "CLUSTER_APNS_SANDBOX_BUNDLE_ID",
        "CLUSTER_APNS_SANDBOX_KEY_ID",
        "CLUSTER_APNS_SANDBOX_PRIVATE_KEY_FILE",
        "CLUSTER_APNS_SANDBOX_TEAM_ID",
        "CLUSTER_APNS_TEAM_ID",
        "CLUSTER_APPLE_CLIENT_ID",
        "CLUSTER_AUTO_MIGRATE",
        "CLUSTER_DATABASE_MAX_CONNS",
        "CLUSTER_DATABASE_MIN_CONNS",
        "CLUSTER_DATABASE_URL",
        "CLUSTER_ENV",
        "CLUSTER_HTTP_ADDR",
        "CLUSTER_JWT_ACCESS_SECRET",
        "CLUSTER_JWT_ISSUER",
        "CLUSTER_MAIL_FROM",
        "CLUSTER_MAIL_PROVIDER",
        "CLUSTER_MAIL_QUEUE_BATCH_SIZE",
        "CLUSTER_MAIL_QUEUE_DEAD_LETTER_RETENTION",
        "CLUSTER_MAIL_QUEUE_DELIVERED_RETENTION",
        "CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY",
        "CLUSTER_MAIL_QUEUE_MAX_ATTEMPTS",
        "CLUSTER_MAIL_QUEUE_RETRY_BASE_DELAY",
        "CLUSTER_MAIL_QUEUE_RETRY_MAX_DELAY",
        "CLUSTER_MAIL_QUEUE_WORKER_CONCURRENCY",
        "CLUSTER_MEDIA_PROVIDER",
        "CLUSTER_METRICS_TOKEN",
        "CLUSTER_NATS_URL",
        "CLUSTER_OCI_OBJECT_STORAGE_BUCKET",
        "CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE",
        "CLUSTER_OCI_OBJECT_STORAGE_REGION",
        "CLUSTER_OTP_ALLOWED_PREFIXES",
        "CLUSTER_OTP_CHALLENGE_TTL",
        "CLUSTER_OTP_CODE_LENGTH",
        "CLUSTER_OTP_GLOBAL_SEND_DAILY",
        "CLUSTER_OTP_GLOBAL_SEND_MINUTE",
        "CLUSTER_OTP_HMAC_SECRET",
        "CLUSTER_OTP_LOCKOUT_TTL",
        "CLUSTER_OTP_MAX_ATTEMPTS",
        "CLUSTER_OTP_PHONE_SEND_DAILY",
        "CLUSTER_OTP_PHONE_SEND_HOURLY",
        "CLUSTER_OTP_RESEND_COOLDOWN",
        "CLUSTER_PASSWORD_RESET_CODE_LENGTH",
        "CLUSTER_PASSWORD_RESET_HMAC_SECRET",
        "CLUSTER_PASSWORD_RESET_MAX_ATTEMPTS",
        "CLUSTER_PASSWORD_RESET_TTL",
        "CLUSTER_PUBLIC_BASE_URL",
        "CLUSTER_PUSH_DEAD_LETTER_RETENTION",
        "CLUSTER_PUSH_DELIVERED_RETENTION",
        "CLUSTER_PUSH_DELIVERY_BATCH_SIZE",
        "CLUSTER_PUSH_MAX_ATTEMPTS",
        "CLUSTER_PUSH_RETRY_BASE_DELAY",
        "CLUSTER_PUSH_RETRY_MAX_DELAY",
        "CLUSTER_PUSH_WORKER_CONCURRENCY",
        "CLUSTER_REDIS_URL",
        "CLUSTER_REFRESH_TTL",
        "CLUSTER_SMTP_ADDRESS",
        "CLUSTER_SMTP_CA_FILE",
        "CLUSTER_SMTP_PASSWORD",
        "CLUSTER_SMTP_SERVER_NAME",
        "CLUSTER_SMTP_TRANSPORT",
        "CLUSTER_SMTP_USERNAME",
        "CLUSTER_STORE",
        "CLUSTER_TELNYX_API_KEY",
        "CLUSTER_TELNYX_FROM_NUMBER",
        "CLUSTER_TELNYX_MESSAGING_PROFILE_ID",
        "CLUSTER_TELNYX_PUBLIC_KEY",
        "CLUSTER_TLS_CA_FILE",
        "CLUSTER_VERIFICATION_PROVIDER",
    }
)

API_REQUIRED_KEYS = frozenset(
    {
        "CLUSTER_ENV",
        "CLUSTER_HTTP_ADDR",
        "CLUSTER_PUBLIC_BASE_URL",
        "CLUSTER_TLS_CA_FILE",
        "CLUSTER_STORE",
        "CLUSTER_AUTO_MIGRATE",
        "CLUSTER_DATABASE_URL",
        "CLUSTER_DATABASE_MAX_CONNS",
        "CLUSTER_DATABASE_MIN_CONNS",
        "CLUSTER_REDIS_URL",
        "CLUSTER_NATS_URL",
        "CLUSTER_JWT_ACCESS_SECRET",
        "CLUSTER_METRICS_TOKEN",
        "CLUSTER_APPLE_CLIENT_ID",
        "CLUSTER_MEDIA_PROVIDER",
        "CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE",
        "CLUSTER_OCI_OBJECT_STORAGE_BUCKET",
        "CLUSTER_OCI_OBJECT_STORAGE_REGION",
        "CLUSTER_VERIFICATION_PROVIDER",
        "CLUSTER_OTP_HMAC_SECRET",
        "CLUSTER_TELNYX_API_KEY",
        "CLUSTER_TELNYX_FROM_NUMBER",
        "CLUSTER_TELNYX_MESSAGING_PROFILE_ID",
        "CLUSTER_TELNYX_PUBLIC_KEY",
        "CLUSTER_MAIL_PROVIDER",
        "CLUSTER_SMTP_TRANSPORT",
        "CLUSTER_SMTP_ADDRESS",
        "CLUSTER_SMTP_USERNAME",
        "CLUSTER_SMTP_PASSWORD",
        "CLUSTER_SMTP_SERVER_NAME",
        "CLUSTER_MAIL_FROM",
        "CLUSTER_PASSWORD_RESET_HMAC_SECRET",
        "CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY",
        "CLUSTER_APNS_TEAM_ID",
        "CLUSTER_APNS_KEY_ID",
        "CLUSTER_APNS_BUNDLE_ID",
        "CLUSTER_APNS_PRIVATE_KEY_FILE",
        "CLUSTER_APNS_ENVIRONMENT",
    }
)


class HydrationError(Exception):
    """A sanitized operator-facing hydration failure."""


def _safe_lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise HydrationError(f"required path is unavailable: {path}") from None


def _validate_no_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise HydrationError(f"cannot validate path: {path}") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise HydrationError(f"symbolic links are not allowed in path: {path}")


def _validate_mapping_file(
    path: Path,
    expected_uid: int,
    expected_gid: int,
    *,
    expected_mode: int,
) -> bytes:
    _validate_no_symlink_components(path)
    parent_metadata = _safe_lstat(path.parent)
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise HydrationError("mapping parent must be a directory")
    if (parent_metadata.st_uid, parent_metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("mapping parent has the wrong owner")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o077:
        raise HydrationError("mapping parent must be root-only")

    metadata = _safe_lstat(path)
    if not stat.S_ISREG(metadata.st_mode):
        raise HydrationError("mapping must be a regular file")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("mapping has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise HydrationError(f"mapping must have mode {expected_mode:04o}")
    if metadata.st_size <= 0 or metadata.st_size > 64 * 1024:
        raise HydrationError("mapping size is invalid")
    try:
        return path.read_bytes()
    except OSError:
        raise HydrationError("mapping cannot be read") from None


def _parse_mapping(content: bytes) -> dict[str, str]:
    if b"\x00" in content or b"\r" in content:
        raise HydrationError("mapping contains unsupported bytes")
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError:
        raise HydrationError("mapping must be ASCII") from None

    parsed: dict[str, str] = {}
    seen_ocids: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = MAPPING_LINE_RE.fullmatch(line)
        if match is None:
            raise HydrationError("mapping contains an invalid assignment")
        name, ocid = match.groups()
        if name not in ALL_MAPPING_NAMES:
            raise HydrationError(f"mapping contains unknown artifact: {name}")
        if name in parsed:
            raise HydrationError(f"mapping contains duplicate artifact: {name}")
        if not OCI_SECRET_RE.fullmatch(ocid):
            raise HydrationError(f"mapping has an invalid secret OCID for {name}")
        if ocid in seen_ocids:
            raise HydrationError("mapping reuses a secret OCID")
        parsed[name] = ocid
        seen_ocids.add(ocid)

    missing = sorted(REQUIRED_MAPPING_NAMES - parsed.keys())
    if missing:
        raise HydrationError(f"mapping is missing required artifact: {missing[0]}")
    return parsed


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise HydrationError(f"JSON object contains a duplicate key: {key}")
        parsed[key] = value
    return parsed


def _load_strict_json(content: bytes, description: str) -> object:
    if not content or len(content) > MAX_MANIFEST_BYTES or b"\x00" in content:
        raise HydrationError(f"{description} size is invalid")
    try:
        return json.loads(content.decode("ascii"), object_pairs_hook=_strict_json_object)
    except HydrationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HydrationError(f"{description} is invalid JSON") from None


def _cohort_payload(
    release_cohort: str,
    mapping_sha256: str,
    artifacts: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "schema": MANIFEST_SCHEMA,
        "release_cohort": release_cohort,
        "mapping_sha256": mapping_sha256,
        "artifacts": artifacts,
    }


def _cohort_digest(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _build_manifest(
    release_cohort: str,
    mapping_content: bytes,
    mapping: Mapping[str, str],
    versions: Mapping[str, int],
) -> bytes:
    if RELEASE_COHORT_RE.fullmatch(release_cohort) is None:
        raise HydrationError("release cohort is invalid")
    if set(versions) != set(mapping):
        raise HydrationError("candidate cohort is incomplete")
    artifacts: list[dict[str, object]] = []
    for name in sorted(mapping):
        version_number = versions[name]
        if (
            isinstance(version_number, bool)
            or not isinstance(version_number, int)
            or version_number < 1
            or version_number > MAX_OCI_VERSION_NUMBER
        ):
            raise HydrationError(f"candidate version is invalid for {name}")
        artifacts.append(
            {
                "name": name,
                "secret_id": mapping[name],
                "version_number": version_number,
            }
        )
    payload = _cohort_payload(
        release_cohort, hashlib.sha256(mapping_content).hexdigest(), artifacts
    )
    document = dict(payload)
    document["cohort_sha256"] = _cohort_digest(payload)
    return (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")


def _parse_manifest(
    content: bytes,
    mapping_content: bytes,
    mapping: Mapping[str, str],
    expected_release_cohort: str,
) -> tuple[dict[str, int], str]:
    loaded = _load_strict_json(content, "approved cohort manifest")
    if not isinstance(loaded, dict):
        raise HydrationError("approved cohort manifest must be an object")
    expected_keys = {
        "schema",
        "release_cohort",
        "mapping_sha256",
        "cohort_sha256",
        "artifacts",
    }
    if set(loaded) != expected_keys:
        raise HydrationError("approved cohort manifest has unsupported or missing fields")
    if loaded["schema"] != MANIFEST_SCHEMA or isinstance(loaded["schema"], bool):
        raise HydrationError("approved cohort manifest schema is invalid")
    release_cohort = loaded["release_cohort"]
    if (
        not isinstance(release_cohort, str)
        or RELEASE_COHORT_RE.fullmatch(release_cohort) is None
        or release_cohort != expected_release_cohort
    ):
        raise HydrationError("approved cohort is bound to a different release")
    mapping_sha256 = loaded["mapping_sha256"]
    if not isinstance(mapping_sha256, str) or SHA256_RE.fullmatch(mapping_sha256) is None:
        raise HydrationError("approved cohort mapping hash is invalid")
    if mapping_sha256 != hashlib.sha256(mapping_content).hexdigest():
        raise HydrationError("approved cohort mapping hash does not match its snapshot")
    cohort_sha256 = loaded["cohort_sha256"]
    if not isinstance(cohort_sha256, str) or SHA256_RE.fullmatch(cohort_sha256) is None:
        raise HydrationError("approved cohort digest is invalid")
    artifact_records = loaded["artifacts"]
    if not isinstance(artifact_records, list):
        raise HydrationError("approved cohort artifacts must be a list")
    versions: dict[str, int] = {}
    seen_secret_ids: set[str] = set()
    normalized_records: list[dict[str, object]] = []
    previous_name = ""
    for record in artifact_records:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "secret_id",
            "version_number",
        }:
            raise HydrationError("approved cohort artifact record is invalid")
        name = record["name"]
        secret_id = record["secret_id"]
        version_number = record["version_number"]
        if not isinstance(name, str) or name not in ALL_MAPPING_NAMES:
            raise HydrationError("approved cohort contains an unknown artifact")
        if name in versions or name <= previous_name:
            raise HydrationError("approved cohort artifacts are duplicated or unsorted")
        if not isinstance(secret_id, str) or secret_id != mapping.get(name):
            raise HydrationError(f"approved cohort secret ID does not match mapping: {name}")
        if secret_id in seen_secret_ids:
            raise HydrationError("approved cohort reuses a secret ID")
        if (
            isinstance(version_number, bool)
            or not isinstance(version_number, int)
            or version_number < 1
            or version_number > MAX_OCI_VERSION_NUMBER
        ):
            raise HydrationError(f"approved cohort version is invalid for {name}")
        versions[name] = version_number
        seen_secret_ids.add(secret_id)
        previous_name = name
        normalized_records.append(
            {
                "name": name,
                "secret_id": secret_id,
                "version_number": version_number,
            }
        )
    if set(versions) != set(mapping):
        raise HydrationError("approved cohort is incomplete or mixed with another mapping")
    payload = _cohort_payload(release_cohort, mapping_sha256, normalized_records)
    if cohort_sha256 != _cohort_digest(payload):
        raise HydrationError("approved cohort digest does not match its contents")
    return versions, cohort_sha256


def _validate_release_directory(
    path: Path, expected_uid: int, expected_gid: int, release_cohort: str
) -> None:
    _validate_no_symlink_components(path)
    metadata = _safe_lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HydrationError("release cohort directory must be a regular directory")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("release cohort directory has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise HydrationError("release cohort directory must have mode 0700")
    if path.name != release_cohort or RELEASE_COHORT_RE.fullmatch(path.name) is None:
        raise HydrationError("release cohort directory name is invalid")


def _resolve_approved_release(
    manifest_path: Path, expected_uid: int, expected_gid: int
) -> tuple[Path, str]:
    if manifest_path.name != APPROVED_MANIFEST_NAME or manifest_path.parent.name != "current":
        raise HydrationError("approved cohort manifest must be selected through releases/current")
    release_root = manifest_path.parent.parent
    root_metadata = _safe_lstat(release_root)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise HydrationError("release root must be a regular directory")
    if (root_metadata.st_uid, root_metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("release root has the wrong owner")
    if stat.S_IMODE(root_metadata.st_mode) & 0o022:
        raise HydrationError("release root is writable outside its owner")
    current_metadata = _safe_lstat(manifest_path.parent)
    if not stat.S_ISLNK(current_metadata.st_mode):
        raise HydrationError("current release pointer must be a symbolic link")
    if (current_metadata.st_uid, current_metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("current release pointer has the wrong owner")
    try:
        current_target = os.readlink(manifest_path.parent)
        resolved_release = manifest_path.parent.resolve(strict=True)
    except OSError:
        raise HydrationError("current release pointer is unavailable") from None
    if (
        not os.path.isabs(current_target)
        or current_target != str(resolved_release)
        or resolved_release.parent != release_root.resolve()
    ):
        raise HydrationError("current release pointer targets an unexpected location")
    release_cohort = resolved_release.name
    _validate_release_directory(
        resolved_release, expected_uid, expected_gid, release_cohort
    )
    return resolved_release, release_cohort


def _read_release_file(
    path: Path,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    description: str,
    maximum_size: int,
) -> bytes:
    metadata = _safe_lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HydrationError(f"{description} must be a regular file")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError(f"{description} has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise HydrationError(f"{description} must have mode {expected_mode:04o}")
    if metadata.st_size <= 0 or metadata.st_size > maximum_size:
        raise HydrationError(f"{description} size is invalid")
    try:
        return path.read_bytes()
    except OSError:
        raise HydrationError(f"{description} cannot be read") from None


def _validate_release_secret_mode(
    release: Path, expected_uid: int, expected_gid: int, expected: bytes
) -> None:
    content = _read_release_file(
        release / "secret-mode",
        expected_uid,
        expected_gid,
        0o400,
        "release secret mode",
        16,
    )
    if content != expected + b"\n":
        raise HydrationError("release secret mode does not match its cohort")


def _parse_marker(content: bytes) -> dict[str, str]:
    if not content or len(content) > 1024 or not content.endswith(b"\n"):
        raise HydrationError("Vault hydration marker is invalid")
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise HydrationError("Vault hydration marker is invalid") from None
    parsed: dict[str, str] = {}
    for line in lines:
        if line.count("=") != 1:
            raise HydrationError("Vault hydration marker is invalid")
        key, value = line.split("=", 1)
        if key in parsed or not value:
            raise HydrationError("Vault hydration marker is invalid")
        parsed[key] = value
    if set(parsed) != {"schema", "release_cohort", "mapping_sha256", "cohort_sha256"}:
        raise HydrationError("Vault hydration marker is invalid")
    if parsed["schema"] != "2":
        raise HydrationError("Vault hydration marker schema is invalid")
    if RELEASE_COHORT_RE.fullmatch(parsed["release_cohort"]) is None:
        raise HydrationError("Vault hydration marker cohort is invalid")
    for key in ("mapping_sha256", "cohort_sha256"):
        if SHA256_RE.fullmatch(parsed[key]) is None:
            raise HydrationError("Vault hydration marker digest is invalid")
    return parsed


def _materialized_file_specs(
    expected_uid: int, expected_gid: int, *, has_sandbox_bundle: bool
) -> dict[str, tuple[int, int, int]]:
    def group(container_gid: int) -> int:
        return container_gid if expected_uid == 0 else expected_gid

    specs = {
        "api.env": (expected_uid, group(65532), 0o440),
        "postgres.env": (expected_uid, expected_gid, 0o400),
        "redis.env": (expected_uid, expected_gid, 0o400),
        "nats.env": (expected_uid, expected_gid, 0o400),
        "grafana.env": (expected_uid, expected_gid, 0o400),
        "backup.env": (expected_uid, expected_gid, 0o400),
        "migrate.env": (expected_uid, group(65532), 0o440),
        "postgres.password": (expected_uid, group(70), 0o440),
        "postgres.pgpass": (expected_uid, expected_gid, 0o400),
        "redis.password": (expected_uid, group(1000), 0o440),
        "redis.acl": (expected_uid, group(1000), 0o440),
        "nats.conf": (expected_uid, group(1000), 0o440),
        "grafana.ini": (expected_uid, group(472), 0o440),
        "metrics.token": (expected_uid, group(65534), 0o440),
        "apns/AuthKey.p8": (expected_uid, group(65532), 0o440),
        "cloudflare-token": (expected_uid, expected_gid, 0o600),
        MARKER_NAME: (expected_uid, expected_gid, 0o400),
    }
    if has_sandbox_bundle:
        specs["apns/AuthKey-sandbox.p8"] = (
            expected_uid,
            group(65532),
            0o440,
        )
    return specs


def _read_materialized_file(
    root: Path,
    relative: str,
    expected: tuple[int, int, int],
) -> tuple[bytes, os.stat_result]:
    uid, gid, mode = expected
    path = root / relative
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise HydrationError(f"materialized secret is unavailable: {relative}") from None
    try:
        metadata = os.fstat(descriptor)
        maximum = MAX_APNS_BYTES if relative.startswith("apns/") else MAX_ENV_BYTES
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise HydrationError(f"materialized secret is unsafe: {relative}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise HydrationError(f"materialized secret changed: {relative}")
            chunks.append(chunk)
            remaining -= len(chunk)
        final = os.fstat(descriptor)
        if os.read(descriptor, 1) or (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_uid,
            final.st_gid,
            final.st_mode,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mode,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise HydrationError(f"materialized secret changed: {relative}")
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _materialized_artifact_records(
    generation: Path,
    specs: Mapping[str, tuple[int, int, int]],
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for relative in sorted(specs):
        content, metadata = _read_materialized_file(
            generation, relative, specs[relative]
        )
        records.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": metadata.st_size,
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
            }
        )
    return records


def _write_materialized_integrity_manifest(
    generation: Path,
    *,
    release_cohort: str,
    mapping_sha256: str,
    cohort_sha256: str,
    has_sandbox_bundle: bool,
    expected_uid: int,
    expected_gid: int,
) -> None:
    specs = _materialized_file_specs(
        expected_uid, expected_gid, has_sandbox_bundle=has_sandbox_bundle
    )
    document = {
        "schema": MATERIALIZED_MANIFEST_SCHEMA,
        "release_cohort": release_cohort,
        "mapping_sha256": mapping_sha256,
        "cohort_sha256": cohort_sha256,
        "artifacts": _materialized_artifact_records(generation, specs),
    }
    content = (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    _write_file(
        generation / MATERIALIZED_MANIFEST_NAME,
        content,
        0o400,
        expected_uid,
        expected_gid,
    )


def _validate_materialized_integrity_manifest(
    generation: Path,
    *,
    release_cohort: str,
    mapping_sha256: str,
    cohort_sha256: str,
    has_sandbox_bundle: bool,
    expected_uid: int,
    expected_gid: int,
) -> None:
    manifest_content = _read_release_file(
        generation / MATERIALIZED_MANIFEST_NAME,
        expected_uid,
        expected_gid,
        0o400,
        "materialized secret integrity manifest",
        MAX_MANIFEST_BYTES,
    )
    document = _load_strict_json(
        manifest_content, "materialized secret integrity manifest"
    )
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "release_cohort",
        "mapping_sha256",
        "cohort_sha256",
        "artifacts",
    }:
        raise HydrationError("materialized secret integrity manifest is invalid")
    if (
        document.get("schema") != MATERIALIZED_MANIFEST_SCHEMA
        or isinstance(document.get("schema"), bool)
        or document.get("release_cohort") != release_cohort
        or document.get("mapping_sha256") != mapping_sha256
        or document.get("cohort_sha256") != cohort_sha256
        or not isinstance(document.get("artifacts"), list)
    ):
        raise HydrationError("materialized secret integrity manifest is invalid")

    specs = _materialized_file_specs(
        expected_uid, expected_gid, has_sandbox_bundle=has_sandbox_bundle
    )
    expected_records = _materialized_artifact_records(generation, specs)
    if document["artifacts"] != expected_records:
        raise HydrationError("materialized secret artifact content changed")

    apns_gid = 65532 if expected_uid == 0 else expected_gid
    apns = generation / "apns"
    metadata = _safe_lstat(apns)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (expected_uid, apns_gid)
        or stat.S_IMODE(metadata.st_mode) != 0o750
    ):
        raise HydrationError("materialized APNs directory is unsafe")
    expected_apns = {
        Path(path).name for path in specs if path.startswith("apns/")
    }
    try:
        actual_apns = {entry.name for entry in apns.iterdir()}
        actual_root = {entry.name for entry in generation.iterdir()}
    except OSError:
        raise HydrationError("materialized secret inventory is unavailable") from None
    if actual_apns != expected_apns:
        raise HydrationError("materialized APNs secret inventory changed")
    expected_root = {
        Path(path).parts[0] for path in specs if not path.startswith("apns/")
    } | {"apns", MATERIALIZED_MANIFEST_NAME}
    if actual_root != expected_root:
        raise HydrationError("materialized secret inventory changed")


def _atomic_publish_release_file(
    path: Path, content: bytes, mode: int, expected_uid: int, expected_gid: int
) -> None:
    if path.exists() or path.is_symlink():
        raise HydrationError(f"release metadata already exists: {path.name}")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}"
    try:
        _write_file(temporary, content, mode, expected_uid, expected_gid)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_secret_root(path: Path, expected_uid: int, expected_gid: int) -> None:
    _validate_no_symlink_components(path)
    metadata = _safe_lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise HydrationError("secret root must be a directory")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("secret root has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise HydrationError("secret root must have mode 0700")


def _validate_tmpfs(path: Path) -> None:
    try:
        completed = subprocess.run(
            ["/usr/bin/findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise HydrationError("cannot verify the runtime secret filesystem") from None
    if completed.returncode != 0 or completed.stdout.strip() != b"tmpfs":
        raise HydrationError("runtime secrets must be materialized on tmpfs")


def _validate_no_swap() -> None:
    try:
        lines = Path("/proc/swaps").read_bytes().splitlines()
    except OSError:
        raise HydrationError("cannot verify that swap is disabled") from None
    if len(lines) != 1:
        raise HydrationError("swap must be disabled before hydrating runtime secrets")


def _validate_executable(path: Path, expected_uid: int) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        raise HydrationError("OCI CLI is unavailable") from None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise HydrationError("OCI CLI is not an executable regular file")
    if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise HydrationError("OCI CLI ownership or mode is unsafe")
    return resolved


def _decode_bundle(encoded: bytes, artifact: str, max_decoded: int) -> bytes:
    if len(encoded) > MAX_ENCODED_BYTES:
        raise HydrationError(f"Vault bundle is too large for {artifact}")
    if encoded.endswith(b"\n"):
        encoded = encoded[:-1]
    if not encoded or b"\n" in encoded or b"\r" in encoded or any(chr(c).isspace() for c in encoded):
        raise HydrationError(f"Vault bundle encoding is invalid for {artifact}")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise HydrationError(f"Vault bundle encoding is invalid for {artifact}") from None
    if base64.b64encode(decoded) != encoded:
        raise HydrationError(f"Vault bundle encoding is noncanonical for {artifact}")
    if not decoded or len(decoded) > max_decoded:
        raise HydrationError(f"Vault bundle content size is invalid for {artifact}")
    return decoded


def _fetch_bundle(
    oci_binary: Path,
    artifact: str,
    ocid: str,
    max_decoded: int,
    *,
    version_number: int | None,
) -> tuple[bytes, int]:
    environment = {
        "HOME": "/run/clixor",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LC_ALL": "C",
        "OCI_CLI_AUTH": "instance_principal",
    }
    command = [
        str(oci_binary),
        "--auth",
        "instance_principal",
        "secrets",
        "secret-bundle",
        "get",
        "--secret-id",
        ocid,
    ]
    if version_number is None:
        command.extend(("--stage", "CURRENT"))
    else:
        if (
            isinstance(version_number, bool)
            or not isinstance(version_number, int)
            or version_number < 1
            or version_number > MAX_OCI_VERSION_NUMBER
        ):
            raise HydrationError(f"approved version is invalid for {artifact}")
        command.extend(("--version-number", str(version_number)))
    command.extend(("--output", "json"))
    try:
        completed = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise HydrationError(f"Vault fetch failed for {artifact}") from None
    if completed.returncode != 0:
        raise HydrationError(f"Vault fetch failed for {artifact}")
    if not completed.stdout or len(completed.stdout) > MAX_OCI_RESPONSE_BYTES:
        raise HydrationError(f"Vault response size is invalid for {artifact}")
    try:
        response = json.loads(
            completed.stdout.decode("utf-8"), object_pairs_hook=_strict_json_object
        )
    except HydrationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HydrationError(f"Vault response is invalid for {artifact}") from None
    if not isinstance(response, dict) or not isinstance(response.get("data"), dict):
        raise HydrationError(f"Vault response is invalid for {artifact}")
    data = response["data"]
    returned_secret_id = data.get("secret-id")
    returned_version = data.get("version-number")
    bundle_content = data.get("secret-bundle-content")
    if returned_secret_id != ocid:
        raise HydrationError(f"Vault returned a different secret for {artifact}")
    if (
        isinstance(returned_version, bool)
        or not isinstance(returned_version, int)
        or returned_version < 1
        or returned_version > MAX_OCI_VERSION_NUMBER
    ):
        raise HydrationError(f"Vault returned an invalid version for {artifact}")
    if version_number is not None and returned_version != version_number:
        raise HydrationError(f"Vault returned the wrong approved version for {artifact}")
    if not isinstance(bundle_content, dict) or not isinstance(
        bundle_content.get("content"), str
    ):
        raise HydrationError(f"Vault response has no content for {artifact}")
    try:
        encoded = bundle_content["content"].encode("ascii")
    except UnicodeEncodeError:
        raise HydrationError(f"Vault bundle encoding is invalid for {artifact}") from None
    return _decode_bundle(encoded, artifact, max_decoded), returned_version


def _parse_env(content: bytes, artifact: str, allowed: frozenset[str], required: frozenset[str]) -> dict[str, bytes]:
    if len(content) > MAX_ENV_BYTES or b"\x00" in content or b"\r" in content:
        raise HydrationError(f"environment bundle is invalid for {artifact}")
    if not content.endswith(b"\n"):
        raise HydrationError(f"environment bundle must end with a newline for {artifact}")
    values: dict[str, bytes] = {}
    for line in content.splitlines():
        if len(line) > 16 * 1024:
            raise HydrationError(f"environment line is too large for {artifact}")
        if not line or line.startswith(b"#"):
            continue
        match = ENV_LINE_RE.fullmatch(line)
        if match is None:
            raise HydrationError(f"environment assignment is invalid for {artifact}")
        key = match.group(1).decode("ascii")
        if key not in allowed:
            raise HydrationError(f"environment key is not allowed for {artifact}: {key}")
        if key in values:
            raise HydrationError(f"environment key is duplicated for {artifact}: {key}")
        values[key] = match.group(2)
    missing = sorted(key for key in required if not values.get(key))
    if missing:
        raise HydrationError(f"environment key is missing for {artifact}: {missing[0]}")
    lowered = content.lower()
    if b"replace_with" in lowered or b"replace-with" in lowered or b"replace_me" in lowered:
        raise HydrationError(f"environment bundle contains a placeholder for {artifact}")
    return values


def _require_exact(values: Mapping[str, bytes], key: str, expected: bytes) -> None:
    if values.get(key) != expected:
        raise HydrationError(f"production API configuration has an invalid {key}")


def _validate_opaque_secret(values: Mapping[str, bytes], key: str) -> None:
    value = values.get(key, b"")
    if OPAQUE_SECRET_RE.fullmatch(value) is None:
        raise HydrationError(f"production API configuration has an invalid {key}")


def _validate_api(values: Mapping[str, bytes]) -> None:
    for key, expected in (
        ("CLUSTER_ENV", b"production"),
        ("CLUSTER_STORE", b"postgres"),
        ("CLUSTER_AUTO_MIGRATE", b"false"),
        ("CLUSTER_TLS_CA_FILE", b"/run/pki/ca.crt"),
        ("CLUSTER_MEDIA_PROVIDER", b"oci"),
        ("CLUSTER_VERIFICATION_PROVIDER", b"telnyx"),
        ("CLUSTER_MAIL_PROVIDER", b"smtp"),
        ("CLUSTER_APNS_ENVIRONMENT", b"production"),
        ("CLUSTER_APNS_PRIVATE_KEY_FILE", b"/run/secrets/apns/AuthKey.p8"),
    ):
        _require_exact(values, key, expected)

    for key in (
        "CLUSTER_JWT_ACCESS_SECRET",
        "CLUSTER_METRICS_TOKEN",
        "CLUSTER_OTP_HMAC_SECRET",
        "CLUSTER_TELNYX_API_KEY",
        "CLUSTER_SMTP_PASSWORD",
        "CLUSTER_PASSWORD_RESET_HMAC_SECRET",
    ):
        _validate_opaque_secret(values, key)

    queue_key = values["CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY"]
    try:
        decoded_key = base64.b64decode(queue_key, validate=True)
    except (binascii.Error, ValueError):
        raise HydrationError("production API configuration has an invalid mail queue key") from None
    if len(decoded_key) != 32 or base64.b64encode(decoded_key) != queue_key:
        raise HydrationError("production API configuration has an invalid mail queue key")


def _url_secret(url: bytes, scheme: str, host: str, port: int) -> tuple[str, str, str]:
    try:
        parsed = urlparse(url.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise HydrationError("API dependency URL is invalid") from None
    try:
        parsed_port = parsed.port
    except ValueError:
        raise HydrationError("API dependency URL is invalid") from None
    if parsed.scheme != scheme or parsed.hostname != host or parsed_port != port:
        raise HydrationError("API dependency URL targets an unexpected endpoint")
    return unquote(parsed.username or ""), unquote(parsed.password or ""), parsed.path


def _validate_dependency_consistency(
    api: Mapping[str, bytes],
    postgres: Mapping[str, bytes],
    redis: Mapping[str, bytes],
    nats: Mapping[str, bytes],
) -> None:
    for key, value in (
        ("POSTGRES_PASSWORD", postgres["POSTGRES_PASSWORD"]),
        ("REDIS_PASSWORD", redis["REDIS_PASSWORD"]),
        ("NATS_AUTH_TOKEN", nats["NATS_AUTH_TOKEN"]),
    ):
        if SERVICE_SECRET_RE.fullmatch(value) is None:
            raise HydrationError(f"service credential has an invalid format for {key}")
    if postgres["POSTGRES_DB"] != b"clixor" or postgres["POSTGRES_USER"] != b"clixor":
        raise HydrationError("PostgreSQL database and user must both be clixor")
    db_user, db_password, db_path = _url_secret(
        api["CLUSTER_DATABASE_URL"], "postgres", "postgres.clixor.internal", 5432
    )
    if (
        db_user.encode() != postgres["POSTGRES_USER"]
        or db_password.encode() != postgres["POSTGRES_PASSWORD"]
        or db_path != "/" + postgres["POSTGRES_DB"].decode("ascii", errors="ignore")
    ):
        raise HydrationError("API and PostgreSQL bundles contain inconsistent credentials")

    _, redis_password, redis_path = _url_secret(
        api["CLUSTER_REDIS_URL"], "rediss", "clixor-tls", 6379
    )
    if redis_password.encode() != redis["REDIS_PASSWORD"] or redis_path != "/0":
        raise HydrationError("API and Redis bundles contain inconsistent credentials")

    nats_user, nats_password, _ = _url_secret(
        api["CLUSTER_NATS_URL"], "tls", "nats.clixor.internal", 4222
    )
    if nats_password or nats_user.encode() != nats["NATS_AUTH_TOKEN"]:
        raise HydrationError("API and NATS bundles contain inconsistent credentials")


def _selected_env(values: Mapping[str, bytes], keys: tuple[str, ...]) -> bytes:
    return b"".join(key.encode() + b"=" + values[key] + b"\n" for key in keys)


def _validate_apns_file(path: Path, content: bytes, openssl_binary: Path) -> None:
    if len(content) > MAX_APNS_BYTES or b"\x00" in content or b"\r" in content:
        raise HydrationError("APNs private key is invalid")
    if not content.startswith(b"-----BEGIN PRIVATE KEY-----\n") or not content.endswith(
        b"-----END PRIVATE KEY-----\n"
    ):
        raise HydrationError("APNs private key is invalid")
    try:
        completed = subprocess.run(
            [str(openssl_binary), "pkey", "-in", str(path), "-check", "-noout"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise HydrationError("APNs private key validation failed") from None
    if completed.returncode != 0:
        raise HydrationError("APNs private key validation failed")


def _write_file(path: Path, content: bytes, mode: int, uid: int, gid: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.fchmod(descriptor, mode)
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_active_target(
    secret_root: Path, expected_uid: int, expected_gid: int
) -> Path | None:
    active = secret_root / ACTIVE_NAME
    try:
        metadata = active.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(metadata.st_mode):
        raise HydrationError("active secret pointer must be a symbolic link")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("active secret pointer has the wrong owner")
    target = os.readlink(active)
    if target == "/srv/clixor/secrets":
        staging_root = Path(target)
        _validate_no_symlink_components(staging_root)
        metadata = _safe_lstat(staging_root)
        if not stat.S_ISDIR(metadata.st_mode):
            raise HydrationError("staging secret root is unavailable")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise HydrationError("staging secret root has the wrong owner")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise HydrationError("staging secret root must have mode 0700")
        return staging_root
    if re.fullmatch(r"vault-generations/gen-[0-9]+-[a-f0-9]{16}", target) is None:
        raise HydrationError("active secret pointer has an invalid target")
    resolved = secret_root / target
    metadata = _safe_lstat(resolved)
    if not stat.S_ISDIR(metadata.st_mode):
        raise HydrationError("active secret generation is unavailable")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("active secret generation has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise HydrationError("active secret generation must have mode 0700")
    return resolved


def _same_generation(active: Path | None, staged: Path, relative_paths: tuple[Path, ...]) -> bool:
    if active is None or active.name == "secrets" or not (active / MARKER_NAME).is_file():
        return False
    for relative in relative_paths:
        current = active / relative
        candidate = staged / relative
        try:
            if current.is_symlink() or not current.is_file() or current.read_bytes() != candidate.read_bytes():
                return False
            current_metadata = current.stat()
            candidate_metadata = candidate.stat()
            if (
                stat.S_IMODE(current_metadata.st_mode) != stat.S_IMODE(candidate_metadata.st_mode)
                or current_metadata.st_uid != candidate_metadata.st_uid
                or current_metadata.st_gid != candidate_metadata.st_gid
            ):
                return False
        except OSError:
            return False
    return True


def _reject_implicit_postgres_credential_rotation(
    active: Path | None, staged: Path
) -> None:
    """Keep an initialized PostgreSQL role outside generic Vault promotion.

    POSTGRES_PASSWORD_FILE is initialization-only. Selecting a different file
    before an explicit, database-aware rotation would make the next reboot
    start clients with a password the persisted role does not recognize.
    """

    if active is None:
        return
    current = active / "postgres.password"
    candidate = staged / "postgres.password"
    current_metadata = _safe_lstat(current)
    candidate_metadata = _safe_lstat(candidate)
    if (
        not stat.S_ISREG(current_metadata.st_mode)
        or stat.S_ISLNK(current_metadata.st_mode)
        or not stat.S_ISREG(candidate_metadata.st_mode)
        or stat.S_ISLNK(candidate_metadata.st_mode)
    ):
        raise HydrationError("PostgreSQL credential artifact is unsafe")
    try:
        unchanged = current.read_bytes() == candidate.read_bytes()
    except OSError:
        raise HydrationError("PostgreSQL credential artifact is unavailable") from None
    if not unchanged:
        raise HydrationError(
            "PostgreSQL credential rotation requires the explicit database rotation procedure"
        )


def _reject_implicit_stateful_secret_rotation(
    active: Path | None, staged: Path, candidate_api: dict[str, bytes]
) -> None:
    if active is None:
        return
    try:
        current_api_content = (active / "api.env").read_bytes()
    except OSError:
        raise HydrationError("active API credential artifact is unavailable") from None
    current_api = _parse_env(
        current_api_content,
        "active api_env",
        API_ALLOWED_KEYS,
        frozenset(),
    )
    for key, procedure in (
        ("CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY", "mail queue key rotation"),
        ("CLUSTER_OTP_HMAC_SECRET", "OTP HMAC rotation"),
        ("CLUSTER_PASSWORD_RESET_HMAC_SECRET", "password-reset HMAC rotation"),
    ):
        if key in current_api and current_api[key] != candidate_api[key]:
            raise HydrationError(f"{procedure} requires the explicit state-drain procedure")

    current_grafana = active / "grafana.env"
    candidate_grafana = staged / "grafana.env"
    current_metadata = _safe_lstat(current_grafana)
    if not stat.S_ISREG(current_metadata.st_mode) or stat.S_ISLNK(
        current_metadata.st_mode
    ):
        raise HydrationError("active Grafana credential artifact is unsafe")
    try:
        grafana_unchanged = (
            current_grafana.read_bytes() == candidate_grafana.read_bytes()
        )
    except OSError:
        raise HydrationError("Grafana credential artifact is unavailable") from None
    if not grafana_unchanged:
        raise HydrationError(
            "Grafana credential rotation requires the explicit database-aware procedure"
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_generation(secret_root: Path, staged: Path) -> Path:
    generation_root = secret_root / GENERATION_ROOT_NAME
    generation_name = f"gen-{time.time_ns()}-{secrets.token_hex(8)}"
    generation = generation_root / generation_name
    os.replace(staged, generation)
    _fsync_directory(generation_root)

    active_link = secret_root / ACTIVE_NAME
    try:
        previous_target = os.readlink(active_link)
    except FileNotFoundError:
        previous_target = None
    temporary_link = secret_root / f".{ACTIVE_NAME}.{secrets.token_hex(8)}"
    os.symlink(f"{GENERATION_ROOT_NAME}/{generation_name}", temporary_link)
    pointer_swapped = False
    try:
        os.replace(temporary_link, active_link)
        pointer_swapped = True
        _fsync_directory(secret_root)
    except BaseException:
        try:
            temporary_link.unlink()
        except FileNotFoundError:
            pass
        pointer_restored = not pointer_swapped
        rollback_link = secret_root / f".{ACTIVE_NAME}.rollback.{secrets.token_hex(8)}"
        if pointer_swapped:
            try:
                if previous_target is None:
                    active_link.unlink()
                else:
                    os.symlink(previous_target, rollback_link)
                    os.replace(rollback_link, active_link)
                _fsync_directory(secret_root)
                pointer_restored = True
            except BaseException:
                try:
                    rollback_link.unlink()
                except FileNotFoundError:
                    pass
        if pointer_restored:
            shutil.rmtree(generation)
            _fsync_directory(generation_root)
        raise
    return generation


def hydrate(
    *,
    mapping_path: Path = DEFAULT_MAPPING,
    candidate_manifest_path: Path | None = None,
    approved_manifest_path: Path | None = None,
    approved_release_manifest_path: Path | None = None,
    release_cohort: str | None = None,
    secret_root: Path = DEFAULT_SECRET_ROOT,
    oci_binary: Path = DEFAULT_OCI_BINARY,
    openssl_binary: Path = DEFAULT_OPENSSL_BINARY,
    expected_uid: int = 0,
    expected_gid: int = 0,
    validate_binary: bool = True,
    require_tmpfs: bool = True,
    require_root: bool = True,
) -> bool:
    """Hydrate one candidate or already-approved complete secret generation."""

    if require_root and os.geteuid() != 0:
        raise HydrationError("hydration must run as root")
    os.umask(0o077)
    candidate_mode = candidate_manifest_path is not None
    approved_mode = approved_manifest_path is not None
    release_approved_mode = approved_release_manifest_path is not None
    if sum((candidate_mode, approved_mode, release_approved_mode)) != 1:
        raise HydrationError(
            "select exactly one candidate, current-approved, or release-approved cohort mode"
        )

    manifest_content: bytes | None = None
    manifest_cohort_sha256: str | None = None
    approved_versions: dict[str, int] | None = None
    if candidate_mode:
        if release_cohort is None or RELEASE_COHORT_RE.fullmatch(release_cohort) is None:
            raise HydrationError("candidate release cohort is invalid")
        if candidate_manifest_path is None:
            raise HydrationError("candidate manifest is required")
        if candidate_manifest_path.name != APPROVED_MANIFEST_NAME:
            raise HydrationError("candidate manifest has an unexpected name")
        _validate_release_directory(
            candidate_manifest_path.parent,
            expected_uid,
            expected_gid,
            release_cohort,
        )
        _validate_release_secret_mode(
            candidate_manifest_path.parent, expected_uid, expected_gid, b"vault"
        )
        mapping_content = _validate_mapping_file(
            mapping_path,
            expected_uid,
            expected_gid,
            expected_mode=0o600,
        )
        mapping = _parse_mapping(mapping_content)
    else:
        if approved_mode:
            if release_cohort is not None:
                raise HydrationError(
                    "current-approved hydration cannot override its release cohort"
                )
            if approved_manifest_path is None:
                raise HydrationError("approved manifest is required")
            approved_release, approved_release_cohort = _resolve_approved_release(
                approved_manifest_path, expected_uid, expected_gid
            )
        else:
            if (
                approved_release_manifest_path is None
                or approved_release_manifest_path.name != APPROVED_MANIFEST_NAME
                or release_cohort is None
                or RELEASE_COHORT_RE.fullmatch(release_cohort) is None
            ):
                raise HydrationError("release-approved cohort arguments are invalid")
            approved_release = approved_release_manifest_path.parent
            approved_release_cohort = release_cohort
            _validate_release_directory(
                approved_release,
                expected_uid,
                expected_gid,
                approved_release_cohort,
            )
        _validate_release_secret_mode(
            approved_release, expected_uid, expected_gid, b"vault"
        )
        approved_mapping_path = approved_release / APPROVED_MAPPING_NAME
        mapping_content = _validate_mapping_file(
            approved_mapping_path,
            expected_uid,
            expected_gid,
            expected_mode=0o400,
        )
        mapping = _parse_mapping(mapping_content)
        manifest_content = _read_release_file(
            approved_release / APPROVED_MANIFEST_NAME,
            expected_uid,
            expected_gid,
            0o400,
            "approved cohort manifest",
            MAX_MANIFEST_BYTES,
        )
        approved_versions, manifest_cohort_sha256 = _parse_manifest(
            manifest_content,
            mapping_content,
            mapping,
            approved_release_cohort,
        )
        release_cohort = approved_release_cohort

    _validate_secret_root(secret_root, expected_uid, expected_gid)
    if require_tmpfs:
        _validate_tmpfs(secret_root)
        _validate_no_swap()
    active = _validate_active_target(secret_root, expected_uid, expected_gid)
    if validate_binary:
        oci_binary = _validate_executable(oci_binary, expected_uid)

    generation_root = secret_root / GENERATION_ROOT_NAME
    if generation_root.exists():
        metadata = _safe_lstat(generation_root)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise HydrationError("Vault generation root must be a regular directory")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise HydrationError("Vault generation root has the wrong owner")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise HydrationError("Vault generation root must have mode 0700")
    else:
        generation_root.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(generation_root, expected_uid, expected_gid)
    existing_generations = [
        entry
        for entry in generation_root.iterdir()
        if entry.name.startswith("gen-") and entry.is_dir() and not entry.is_symlink()
    ]
    staged = Path(tempfile.mkdtemp(prefix=".hydrate-", dir=generation_root))
    changed = False
    try:
        fetched: dict[str, bytes] = {}
        fetched_versions: dict[str, int] = {}
        for artifact in sorted(mapping):
            maximum = MAX_ENV_BYTES if artifact.endswith("_env") else (
                MAX_APNS_BYTES if artifact.endswith("_p8") else MAX_TOKEN_BYTES
            )
            content, returned_version = _fetch_bundle(
                oci_binary,
                artifact,
                mapping[artifact],
                maximum,
                version_number=(
                    None if approved_versions is None else approved_versions[artifact]
                ),
            )
            fetched[artifact] = content
            fetched_versions[artifact] = returned_version

        api_values = _parse_env(
            fetched["api_env"], "api_env", API_ALLOWED_KEYS, API_REQUIRED_KEYS
        )
        postgres_keys = frozenset({"POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"})
        postgres_values = _parse_env(
            fetched["postgres_env"], "postgres_env", postgres_keys, postgres_keys
        )
        redis_keys = frozenset({"REDIS_PASSWORD"})
        redis_values = _parse_env(fetched["redis_env"], "redis_env", redis_keys, redis_keys)
        nats_keys = frozenset({"NATS_AUTH_TOKEN"})
        nats_values = _parse_env(fetched["nats_env"], "nats_env", nats_keys, nats_keys)
        grafana_keys = frozenset({"GF_SECURITY_ADMIN_USER", "GF_SECURITY_ADMIN_PASSWORD"})
        grafana_values = _parse_env(
            fetched["grafana_env"], "grafana_env", grafana_keys, grafana_keys
        )

        _validate_api(api_values)
        _validate_dependency_consistency(api_values, postgres_values, redis_values, nats_values)

        sandbox_path = api_values.get("CLUSTER_APNS_SANDBOX_PRIVATE_KEY_FILE", b"")
        has_sandbox_bundle = "apns_sandbox_p8" in fetched
        if bool(sandbox_path) != has_sandbox_bundle:
            raise HydrationError("sandbox APNs configuration and mapping must be enabled together")
        if sandbox_path and sandbox_path != b"/run/secrets/apns/AuthKey-sandbox.p8":
            raise HydrationError("sandbox APNs private key path is invalid")

        if SERVICE_NAME_RE.fullmatch(grafana_values["GF_SECURITY_ADMIN_USER"]) is None or \
            SERVICE_SECRET_RE.fullmatch(grafana_values["GF_SECURITY_ADMIN_PASSWORD"]) is None:
            raise HydrationError("Grafana credentials have an invalid format")

        for name, content, mode, uid, gid in (
            ("api.env", fetched["api_env"], 0o440, expected_uid, 65532),
            ("postgres.env", fetched["postgres_env"], 0o400, expected_uid, expected_gid),
            ("redis.env", fetched["redis_env"], 0o400, expected_uid, expected_gid),
            ("nats.env", fetched["nats_env"], 0o400, expected_uid, expected_gid),
            ("grafana.env", fetched["grafana_env"], 0o400, expected_uid, expected_gid),
        ):
            _write_file(staged / name, content, mode, uid, gid)

        backup = _selected_env(
            postgres_values, ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")
        )
        migrate = _selected_env(
            api_values,
            (
                "CLUSTER_DATABASE_URL",
                "CLUSTER_DATABASE_MAX_CONNS",
                "CLUSTER_DATABASE_MIN_CONNS",
                "CLUSTER_TLS_CA_FILE",
            ),
        )
        _write_file(staged / "backup.env", backup, 0o400, expected_uid, expected_gid)
        _write_file(staged / "migrate.env", migrate, 0o440, expected_uid, 65532)

        postgres_password = postgres_values["POSTGRES_PASSWORD"]
        _write_file(
            staged / "postgres.password",
            postgres_password + b"\n",
            0o440,
            expected_uid,
            70,
        )
        pgpass = b"postgres.clixor.internal:5432:clixor:clixor:" + postgres_password + b"\n"
        _write_file(staged / "postgres.pgpass", pgpass, 0o400, expected_uid, expected_gid)

        redis_password = redis_values["REDIS_PASSWORD"]
        _write_file(
            staged / "redis.password", redis_password + b"\n", 0o440, expected_uid, 1000
        )
        redis_acl = b"user default on >" + redis_password + b" ~* &* +@all\n"
        _write_file(staged / "redis.acl", redis_acl, 0o440, expected_uid, 1000)

        nats_config = (
            "port: 4222\n"
            "http: 8222\n"
            "jetstream { store_dir: /data }\n"
            "authorization { token: "
            + json.dumps(nats_values["NATS_AUTH_TOKEN"].decode("ascii"))
            + " }\n"
            "tls {\n  cert_file: /run/nats-tls/server.crt\n"
            "  key_file: /run/nats-tls/server.key\n}\n"
        ).encode("ascii")
        _write_file(staged / "nats.conf", nats_config, 0o440, expected_uid, 1000)

        grafana_config = (
            "[security]\nadmin_user = "
            + grafana_values["GF_SECURITY_ADMIN_USER"].decode("ascii")
            + "\nadmin_password = "
            + grafana_values["GF_SECURITY_ADMIN_PASSWORD"].decode("ascii")
            + "\n[users]\nallow_sign_up = false\n[auth.anonymous]\nenabled = false\n"
            "[server]\nroot_url = http://127.0.0.1:13000\n"
        ).encode("ascii")
        _write_file(staged / "grafana.ini", grafana_config, 0o440, expected_uid, 472)

        metrics = api_values["CLUSTER_METRICS_TOKEN"]
        if OPAQUE_SECRET_RE.fullmatch(metrics) is None:
            raise HydrationError("metrics token is invalid")
        _write_file(staged / "metrics.token", metrics, 0o440, expected_uid, 65534)

        apns = staged / "apns"
        apns.mkdir(mode=0o750)
        os.chmod(apns, 0o750)
        if os.geteuid() == 0:
            os.chown(apns, expected_uid, 65532)
        production_key = apns / "AuthKey.p8"
        _write_file(
            production_key, fetched["apns_production_p8"], 0o440, expected_uid, 65532
        )
        _validate_apns_file(
            production_key, fetched["apns_production_p8"], openssl_binary
        )
        if has_sandbox_bundle:
            sandbox_key = apns / "AuthKey-sandbox.p8"
            _write_file(
                sandbox_key, fetched["apns_sandbox_p8"], 0o440, expected_uid, 65532
            )
            _validate_apns_file(sandbox_key, fetched["apns_sandbox_p8"], openssl_binary)

        cloudflare_token = fetched["cloudflare_token"]
        if cloudflare_token.endswith(b"\n"):
            cloudflare_token = cloudflare_token[:-1]
        if TOKEN_RE.fullmatch(cloudflare_token) is None:
            raise HydrationError("Cloudflare tunnel token is invalid")
        _write_file(
            staged / "cloudflare-token", cloudflare_token, 0o600, expected_uid, expected_gid
        )

        if candidate_mode:
            if release_cohort is None:
                raise HydrationError("candidate release cohort is required")
            manifest_content = _build_manifest(
                release_cohort, mapping_content, mapping, fetched_versions
            )
            _, manifest_cohort_sha256 = _parse_manifest(
                manifest_content,
                mapping_content,
                mapping,
                release_cohort,
            )
        if manifest_content is None or manifest_cohort_sha256 is None or release_cohort is None:
            raise HydrationError("cohort metadata is incomplete")
        marker = (
            "schema=2\n"
            + "release_cohort="
            + release_cohort
            + "\n"
            + "mapping_sha256="
            + hashlib.sha256(mapping_content).hexdigest()
            + "\ncohort_sha256="
            + manifest_cohort_sha256
            + "\n"
        ).encode("ascii")
        _write_file(staged / MARKER_NAME, marker, 0o400, expected_uid, expected_gid)
        _write_materialized_integrity_manifest(
            staged,
            release_cohort=release_cohort,
            mapping_sha256=hashlib.sha256(mapping_content).hexdigest(),
            cohort_sha256=manifest_cohort_sha256,
            has_sandbox_bundle=has_sandbox_bundle,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        _fsync_directory(apns)
        _fsync_directory(staged)

        relative_paths = (
            Path("api.env"),
            Path("postgres.env"),
            Path("redis.env"),
            Path("nats.env"),
            Path("grafana.env"),
            Path("backup.env"),
            Path("migrate.env"),
            Path("postgres.password"),
            Path("postgres.pgpass"),
            Path("redis.password"),
            Path("redis.acl"),
            Path("nats.conf"),
            Path("grafana.ini"),
            Path("metrics.token"),
            Path("apns/AuthKey.p8"),
            *((Path("apns/AuthKey-sandbox.p8"),) if has_sandbox_bundle else ()),
            Path("cloudflare-token"),
            Path(MARKER_NAME),
            Path(MATERIALIZED_MANIFEST_NAME),
        )
        _reject_implicit_postgres_credential_rotation(active, staged)
        _reject_implicit_stateful_secret_rotation(active, staged, api_values)
        if candidate_mode:
            if candidate_manifest_path is None:
                raise HydrationError("candidate manifest is required")
            _atomic_publish_release_file(
                candidate_manifest_path.parent / APPROVED_MAPPING_NAME,
                mapping_content,
                0o400,
                expected_uid,
                expected_gid,
            )
            _atomic_publish_release_file(
                candidate_manifest_path,
                manifest_content,
                0o400,
                expected_uid,
                expected_gid,
            )
        if _same_generation(active, staged, relative_paths):
            return False
        if len(existing_generations) >= 16:
            raise HydrationError(
                "Vault generation retention limit reached; reboot or review old generations"
            )
        _publish_generation(secret_root, staged)
        changed = True
        return True
    except HydrationError:
        raise
    except Exception:
        raise HydrationError("atomic secret publication failed") from None
    finally:
        if staged.exists() and not changed:
            shutil.rmtree(staged)


def verify_candidate_selection(
    *,
    candidate_manifest_path: Path,
    release_cohort: str,
    secret_root: Path = DEFAULT_SECRET_ROOT,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> None:
    """Verify that one candidate manifest selects the active complete cohort."""

    if candidate_manifest_path.name != APPROVED_MANIFEST_NAME:
        raise HydrationError("candidate manifest has an unexpected name")
    _validate_release_directory(
        candidate_manifest_path.parent,
        expected_uid,
        expected_gid,
        release_cohort,
    )
    _validate_release_secret_mode(
        candidate_manifest_path.parent, expected_uid, expected_gid, b"vault"
    )
    mapping_content = _validate_mapping_file(
        candidate_manifest_path.parent / APPROVED_MAPPING_NAME,
        expected_uid,
        expected_gid,
        expected_mode=0o400,
    )
    mapping = _parse_mapping(mapping_content)
    manifest_content = _read_release_file(
        candidate_manifest_path,
        expected_uid,
        expected_gid,
        0o400,
        "candidate cohort manifest",
        MAX_MANIFEST_BYTES,
    )
    _, cohort_sha256 = _parse_manifest(
        manifest_content, mapping_content, mapping, release_cohort
    )
    active = _validate_active_target(secret_root, expected_uid, expected_gid)
    if active is None:
        raise HydrationError("candidate cohort is not selected")
    marker_content = _read_release_file(
        active / MARKER_NAME,
        expected_uid,
        expected_gid,
        0o400,
        "Vault hydration marker",
        1024,
    )
    marker = _parse_marker(marker_content)
    if marker["release_cohort"] != release_cohort:
        raise HydrationError("active Vault generation belongs to another release")
    if marker["mapping_sha256"] != hashlib.sha256(mapping_content).hexdigest():
        raise HydrationError("active Vault generation uses another mapping")
    if marker["cohort_sha256"] != cohort_sha256:
        raise HydrationError("active Vault generation uses another cohort")
    _validate_materialized_integrity_manifest(
        active,
        release_cohort=release_cohort,
        mapping_sha256=hashlib.sha256(mapping_content).hexdigest(),
        cohort_sha256=cohort_sha256,
        has_sandbox_bundle="apns_sandbox_p8" in mapping,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def _fsync_regular_file(path: Path, expected_uid: int, expected_gid: int) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise HydrationError(f"release metadata cannot be opened: {path.name}") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise HydrationError(f"release metadata is not regular: {path.name}")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise HydrationError(f"release metadata has the wrong owner: {path.name}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_and_fsync_boot_bundle(
    release: Path, expected_uid: int, expected_gid: int
) -> None:
    boot_root = release / BOOT_SECRET_DIRECTORY_NAME
    metadata = _safe_lstat(boot_root)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HydrationError("release boot-tool root must be a regular directory")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("release boot-tool root has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise HydrationError("release boot-tool root must have mode 0700")
    checksum_content = _read_release_file(
        boot_root / BOOT_CHECKSUM_NAME,
        expected_uid,
        expected_gid,
        0o400,
        "release boot checksum manifest",
        4096,
    )
    if not checksum_content.endswith(b"\n") or b"\x00" in checksum_content:
        raise HydrationError("release boot checksum manifest is malformed")
    try:
        checksum_lines = checksum_content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise HydrationError("release boot checksum manifest must be ASCII") from None
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None or match.group(2) not in BOOT_FILE_MODES:
            raise HydrationError("release boot checksum manifest has an unsupported entry")
        digest, name = match.groups()
        if name in checksums:
            raise HydrationError("release boot checksum manifest has a duplicate entry")
        checksums[name] = digest
    if set(checksums) != set(BOOT_FILE_MODES):
        raise HydrationError("release boot checksum manifest is incomplete")
    for name, mode in BOOT_FILE_MODES.items():
        content = _read_release_file(
            boot_root / name,
            expected_uid,
            expected_gid,
            mode,
            f"release boot file {name}",
            512 * 1024,
        )
        if hashlib.sha256(content).hexdigest() != checksums[name]:
            raise HydrationError(f"release boot checksum mismatch: {name}")
        _fsync_regular_file(boot_root / name, expected_uid, expected_gid)
    _fsync_regular_file(
        boot_root / BOOT_CHECKSUM_NAME, expected_uid, expected_gid
    )
    _fsync_directory(boot_root)


def commit_candidate_release(
    *,
    candidate_manifest_path: Path,
    release_cohort: str,
    secret_root: Path = DEFAULT_SECRET_ROOT,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> None:
    """Durably make one complete selected candidate boot-authoritative."""

    release = candidate_manifest_path.parent
    release_root = release.parent
    _validate_release_directory(release, expected_uid, expected_gid, release_cohort)
    root_metadata = _safe_lstat(release_root)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise HydrationError("release root must be a regular directory")
    if (root_metadata.st_uid, root_metadata.st_gid) != (expected_uid, expected_gid):
        raise HydrationError("release root has the wrong owner")
    if stat.S_IMODE(root_metadata.st_mode) & 0o022:
        raise HydrationError("release root is writable outside its owner")
    verify_candidate_selection(
        candidate_manifest_path=candidate_manifest_path,
        release_cohort=release_cohort,
        secret_root=secret_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    _validate_and_fsync_boot_bundle(release, expected_uid, expected_gid)
    for metadata_name in (
        "secret-mode",
        APPROVED_MAPPING_NAME,
        APPROVED_MANIFEST_NAME,
    ):
        _fsync_regular_file(release / metadata_name, expected_uid, expected_gid)
    _fsync_directory(release)

    current = release_root / "current"
    if current.exists() or current.is_symlink():
        current_metadata = _safe_lstat(current)
        if not stat.S_ISLNK(current_metadata.st_mode):
            raise HydrationError("current release pointer must be a symbolic link")
        if (current_metadata.st_uid, current_metadata.st_gid) != (
            expected_uid,
            expected_gid,
        ):
            raise HydrationError("current release pointer has the wrong owner")
    temporary = release_root / f".current.{secrets.token_hex(8)}"
    try:
        os.symlink(str(release), temporary)
        os.replace(temporary, current)
        _fsync_directory(release_root)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    try:
        selected = os.readlink(current)
    except OSError:
        raise HydrationError("current release pointer is unavailable after commit") from None
    if selected != str(release):
        raise HydrationError("current release pointer did not select the candidate")


def main(argv: list[str]) -> int:
    candidate_manifest_path: Path | None = None
    approved_manifest_path: Path | None = None
    approved_release_manifest_path: Path | None = None
    release_cohort: str | None = None
    verify_only = False
    commit_release = False
    if len(argv) == 2 and argv[0] == "--approved-manifest":
        approved_manifest_path = Path(argv[1])
    elif (
        len(argv) == 4
        and argv[0] == "--approved-release-manifest"
        and argv[2] == "--release-cohort"
    ):
        approved_release_manifest_path = Path(argv[1])
        release_cohort = argv[3]
    elif (
        len(argv) == 4
        and argv[0] == "--candidate-manifest"
        and argv[2] == "--release-cohort"
    ):
        candidate_manifest_path = Path(argv[1])
        release_cohort = argv[3]
    elif (
        len(argv) == 4
        and argv[0] == "--verify-candidate-manifest"
        and argv[2] == "--release-cohort"
    ):
        candidate_manifest_path = Path(argv[1])
        release_cohort = argv[3]
        verify_only = True
    elif (
        len(argv) == 4
        and argv[0] == "--commit-candidate-release"
        and argv[2] == "--release-cohort"
    ):
        candidate_manifest_path = Path(argv[1])
        release_cohort = argv[3]
        commit_release = True
    else:
        print(
            "OCI Vault hydration requires an approved manifest or candidate release cohort.",
            file=sys.stderr,
        )
        return 2
    selected_path = (
        candidate_manifest_path
        or approved_manifest_path
        or approved_release_manifest_path
    )
    if selected_path is None or not selected_path.is_absolute():
        print("OCI Vault manifest path must be absolute.", file=sys.stderr)
        return 2
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if commit_release:
            if candidate_manifest_path is None or release_cohort is None:
                raise HydrationError("candidate commit arguments are incomplete")
            commit_candidate_release(
                candidate_manifest_path=candidate_manifest_path,
                release_cohort=release_cohort,
            )
        elif verify_only:
            if candidate_manifest_path is None or release_cohort is None:
                raise HydrationError("candidate verification arguments are incomplete")
            verify_candidate_selection(
                candidate_manifest_path=candidate_manifest_path,
                release_cohort=release_cohort,
            )
        else:
            hydrate(
                candidate_manifest_path=candidate_manifest_path,
                approved_manifest_path=approved_manifest_path,
                approved_release_manifest_path=approved_release_manifest_path,
                release_cohort=release_cohort,
            )
    except (HydrationError, OSError, ValueError) as exc:
        print(f"OCI Vault hydration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
