#!/usr/bin/python3
"""Materialize Clixor production secrets from OCI Vault without exposing values."""

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
GENERATION_ROOT_NAME = "vault-generations"
ACTIVE_NAME = "active"
MARKER_NAME = ".vault-hydrated"
MAX_ENV_BYTES = 256 * 1024
MAX_APNS_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 8 * 1024
MAX_ENCODED_BYTES = 384 * 1024

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


def _validate_mapping_file(path: Path, expected_uid: int, expected_gid: int) -> bytes:
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
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise HydrationError("mapping must have mode 0600")
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


def _fetch_current_bundle(oci_binary: Path, artifact: str, ocid: str, max_decoded: int) -> bytes:
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
        "--stage",
        "CURRENT",
        "--query",
        'data."secret-bundle-content".content',
        "--raw-output",
    ]
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
    return _decode_bundle(completed.stdout, artifact, max_decoded)


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
    secret_root: Path = DEFAULT_SECRET_ROOT,
    oci_binary: Path = DEFAULT_OCI_BINARY,
    openssl_binary: Path = DEFAULT_OPENSSL_BINARY,
    expected_uid: int = 0,
    expected_gid: int = 0,
    validate_binary: bool = True,
    require_tmpfs: bool = True,
    require_root: bool = True,
) -> bool:
    """Hydrate one complete generation. Return True only when selection changed."""

    if require_root and os.geteuid() != 0:
        raise HydrationError("hydration must run as root")
    os.umask(0o077)
    mapping_content = _validate_mapping_file(mapping_path, expected_uid, expected_gid)
    mapping = _parse_mapping(mapping_content)
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
        for artifact in sorted(mapping):
            maximum = MAX_ENV_BYTES if artifact.endswith("_env") else (
                MAX_APNS_BYTES if artifact.endswith("_p8") else MAX_TOKEN_BYTES
            )
            fetched[artifact] = _fetch_current_bundle(
                oci_binary, artifact, mapping[artifact], maximum
            )

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

        marker = (
            "schema=1\n"
            + "mapping_sha256="
            + hashlib.sha256(mapping_content).hexdigest()
            + "\n"
        ).encode("ascii")
        _write_file(staged / MARKER_NAME, marker, 0o400, expected_uid, expected_gid)
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
        )
        _reject_implicit_postgres_credential_rotation(active, staged)
        _reject_implicit_stateful_secret_rotation(active, staged, api_values)
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


def main(argv: list[str]) -> int:
    if argv:
        print("OCI Vault hydration accepts no command-line arguments.", file=sys.stderr)
        return 2
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        hydrate()
    except (HydrationError, OSError, ValueError) as exc:
        print(f"OCI Vault hydration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
