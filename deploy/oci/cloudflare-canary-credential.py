#!/usr/bin/env python3
"""Release-bound Cloudflare connector credential preparation.

The canary path deliberately does not hydrate an incomplete application-secret
cohort.  It fetches one exact Vault secret version with the instance principal,
validates that the opaque tunnel token is bound to the reviewed account and
tunnel, and publishes it only below /run.  Production continues to consume the
Cloudflare token from the already-verified complete seven-secret cohort.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = 1
CANARY_HOSTNAME = "clixor-oci-canary.atlanteanz.com"
CANARY_ORIGIN = "unix:/run/clixor-origin/gateway.sock"
ACCOUNT_RE = re.compile(r"^[0-9a-f]{32}$")
SECRET_OCID_RE = re.compile(r"^ocid1\.vaultsecret\.oc1\.phx\.[a-z0-9]{20,}$")
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 64 * 1024
DEFAULT_RUNTIME_ROOT = Path("/run/clixor/cloudflare-connector")
DEFAULT_PROJECT_ROOT = Path("/srv/clixor")
DEFAULT_OCI = Path("/usr/local/bin/oci")
METADATA_NAME = "cloudflare-canary-connector.json"
TOKEN_NAME = "token"
SELECTION_NAME = "selection.json"
PRODUCTION_GATE = Path("/run/clixor-origin-gate/public-open")


class CredentialError(RuntimeError):
    """A canary connector credential or its release binding is unsafe."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("JSON input contains a duplicate field")
        result[key] = value
    return result


def _load_json_bytes(raw: bytes, description: str) -> Mapping[str, Any]:
    if not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise CredentialError(f"{description} size is invalid")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except CredentialError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise CredentialError(f"{description} is invalid JSON") from None
    if not isinstance(value, dict):
        raise CredentialError(f"{description} must be an object")
    return value


def _regular_bytes(
    path: Path,
    maximum: int,
    *,
    mode: int | None = None,
    owner: tuple[int, int] | None = None,
) -> bytes:
    try:
        metadata = path.lstat()
    except OSError:
        raise CredentialError(f"required file is unavailable: {path.name}") from None
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size <= 0 or metadata.st_size > maximum):
        raise CredentialError(f"required file is unsafe: {path.name}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise CredentialError(f"required file mode is unsafe: {path.name}")
    if owner is not None and (metadata.st_uid, metadata.st_gid) != owner:
        raise CredentialError(f"required file owner is unsafe: {path.name}")
    try:
        return path.read_bytes()
    except OSError:
        raise CredentialError(f"required file cannot be read: {path.name}") from None


def _metadata_document(
    account_id: str,
    tunnel_id: str,
    secret_ocid: str,
    secret_version: int,
    remote_config_version: int,
) -> dict[str, Any]:
    try:
        normalized_tunnel = str(uuid.UUID(tunnel_id))
    except (ValueError, AttributeError):
        raise CredentialError("Cloudflare tunnel ID is invalid") from None
    if ACCOUNT_RE.fullmatch(account_id) is None:
        raise CredentialError("Cloudflare account ID is invalid")
    if SECRET_OCID_RE.fullmatch(secret_ocid) is None:
        raise CredentialError("OCI Vault secret OCID is invalid")
    for value, label in (
        (secret_version, "OCI secret version"),
        (remote_config_version, "Cloudflare configuration version"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise CredentialError(f"{label} must be a positive integer")
    return {
        "schema": SCHEMA,
        "mode": "canary",
        "account_id": account_id,
        "tunnel_id": normalized_tunnel,
        "secret": {"ocid": secret_ocid, "version": secret_version},
        "remote_config": {
            "version": remote_config_version,
            "ingress": [
                {"hostname": CANARY_HOSTNAME, "service": CANARY_ORIGIN},
                {"service": "http_status:404"},
            ],
        },
    }


def validate_metadata(document: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(document) != {
        "schema", "mode", "account_id", "tunnel_id", "secret", "remote_config"
    }:
        raise CredentialError("canary connector metadata fields are invalid")
    if document.get("schema") != SCHEMA or document.get("mode") != "canary":
        raise CredentialError("canary connector metadata schema is invalid")
    secret = document.get("secret")
    remote = document.get("remote_config")
    if not isinstance(secret, dict) or set(secret) != {"ocid", "version"}:
        raise CredentialError("canary connector secret selection is invalid")
    if not isinstance(remote, dict) or set(remote) != {"version", "ingress"}:
        raise CredentialError("canary connector remote configuration is invalid")
    expected = _metadata_document(
        str(document.get("account_id", "")),
        str(document.get("tunnel_id", "")),
        str(secret.get("ocid", "")),
        secret.get("version"),  # type: ignore[arg-type]
        remote.get("version"),  # type: ignore[arg-type]
    )
    if document != expected:
        raise CredentialError("canary connector metadata is not canonical")
    return document


def load_metadata(release: Path) -> Mapping[str, Any] | None:
    path = release / "runtime-bundle" / METADATA_NAME
    if not path.exists() and not path.is_symlink():
        return None
    raw = _regular_bytes(path, MAX_DOCUMENT_BYTES, mode=0o400)
    return validate_metadata(_load_json_bytes(raw, "canary connector metadata"))


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def stage_metadata(release: Path, document: Mapping[str, Any]) -> Path:
    validate_metadata(document)
    bundle = release / "runtime-bundle"
    if not bundle.is_dir() or bundle.is_symlink():
        raise CredentialError("runtime source must be staged before canary metadata")
    path = bundle / METADATA_NAME
    if path.exists() or path.is_symlink():
        raise CredentialError("canary connector metadata already exists")
    encoded = (json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
    _atomic_write(path, encoded, 0o400)
    return path


def _decode_base64(raw: str, description: str, maximum: int) -> bytes:
    try:
        encoded = raw.encode("ascii")
    except UnicodeError:
        raise CredentialError(f"{description} is not ASCII") from None
    if not encoded or len(encoded) > maximum * 2:
        raise CredentialError(f"{description} size is invalid")
    encoded += b"=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise CredentialError(f"{description} is not valid base64") from None
    if not decoded or len(decoded) > maximum:
        raise CredentialError(f"{description} decoded size is invalid")
    return decoded


def validate_tunnel_token(raw: bytes, account_id: str, tunnel_id: str) -> bytes:
    token = raw.strip()
    if not token or len(token) > MAX_TOKEN_BYTES or any(value < 0x21 or value > 0x7e for value in token):
        raise CredentialError("Cloudflare tunnel token is malformed")
    document = _load_json_bytes(
        _decode_base64(token.decode("ascii"), "Cloudflare tunnel token", MAX_TOKEN_BYTES),
        "Cloudflare tunnel token payload",
    )
    if not {"a", "s", "t"}.issubset(document) or not set(document).issubset({"a", "s", "t", "e"}):
        raise CredentialError("Cloudflare tunnel token payload fields are invalid")
    if document.get("a") != account_id:
        raise CredentialError("Cloudflare tunnel token belongs to another account")
    try:
        token_tunnel = str(uuid.UUID(str(document.get("t", ""))))
    except ValueError:
        raise CredentialError("Cloudflare tunnel token has an invalid tunnel ID") from None
    if token_tunnel != tunnel_id:
        raise CredentialError("Cloudflare tunnel token belongs to another tunnel")
    secret = document.get("s")
    if not isinstance(secret, str):
        raise CredentialError("Cloudflare tunnel token secret is invalid")
    _decode_base64(secret, "Cloudflare tunnel secret", MAX_TOKEN_BYTES)
    return token + b"\n"


def fetch_exact_secret(
    secret_ocid: str,
    secret_version: int,
    *,
    oci_binary: Path = DEFAULT_OCI,
) -> bytes:
    if SECRET_OCID_RE.fullmatch(secret_ocid) is None or secret_version <= 0:
        raise CredentialError("exact OCI secret selection is invalid")
    arguments = [
        str(oci_binary), "--auth", "instance_principal", "secrets",
        "secret-bundle", "get", "--secret-id", secret_ocid,
        "--version-number", str(secret_version), "--output", "json",
    ]
    environment = {
        "HOME": "/run/clixor",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LC_ALL": "C",
        "OCI_CLI_AUTH": "instance_principal",
        "OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING": "True",
    }
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CredentialError("OCI instance-principal secret fetch failed") from None
    if result.returncode != 0 or len(result.stdout) > MAX_DOCUMENT_BYTES:
        raise CredentialError("OCI instance-principal secret fetch failed")
    response = _load_json_bytes(result.stdout, "OCI secret response")
    data = response.get("data")
    if not isinstance(data, dict):
        raise CredentialError("OCI secret response has no data")
    if data.get("secret-id") != secret_ocid or data.get("version-number") != secret_version:
        raise CredentialError("OCI returned a different secret or version")
    content = data.get("secret-bundle-content")
    if (not isinstance(content, dict) or content.get("content-type") != "BASE64"
            or not isinstance(content.get("content"), str)):
        raise CredentialError("OCI secret response content is invalid")
    return _decode_base64(str(content["content"]), "OCI secret content", MAX_TOKEN_BYTES)


def _release_mode(release: Path) -> str:
    raw = _regular_bytes(release / "secret-mode", 16, mode=0o400)
    if raw == b"staging\n":
        return "staging"
    if raw == b"vault\n":
        return "vault"
    raise CredentialError("release secret mode is invalid")


def _runtime_state(release: Path) -> Mapping[str, Any]:
    manifest = _load_json_bytes(
        _regular_bytes(release / "runtime-bundle" / "manifest.json", MAX_DOCUMENT_BYTES, mode=0o400),
        "runtime manifest",
    )
    state = manifest.get("state")
    cloudflared = state.get("cloudflared") if isinstance(state, dict) else None
    if not isinstance(cloudflared, dict) or set(cloudflared) != {"enabled", "active"}:
        raise CredentialError("release Cloudflare service state is invalid")
    return cloudflared


def _validate_canary_origin_boundary(release: Path) -> None:
    nginx = _regular_bytes(
        release / "runtime-bundle" / "runtime" / "api-gateway" / "nginx.conf",
        MAX_DOCUMENT_BYTES,
        mode=0o400,
    ).decode("utf-8", errors="strict")
    production = "server_name clustr-api.atlanteanz.com clixor.atlanteanz.com;"
    canary = f"server_name {CANARY_HOSTNAME};"
    gate = "if (!-f /run/clixor-origin-gate/public-open)"
    if nginx.count(production) != 1 or nginx.count(canary) != 1 or nginx.count(gate) != 1:
        raise CredentialError("release origin boundary is not exact")
    production_start = nginx.index(production)
    next_server = nginx.find("\n  server {", production_start + len(production))
    if next_server < 0:
        raise CredentialError("release production origin boundary is malformed")
    production_block = nginx[production_start:next_server]
    if gate not in production_block or 'return 503 "clixor-origin-gate-closed\\n";' not in production_block:
        raise CredentialError("release production origin does not fail closed")


def _assert_tmpfs(path: Path) -> None:
    try:
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        raise CredentialError("cannot verify the /run tmpfs boundary") from None
    resolved = path.resolve(strict=False)
    matches: list[tuple[int, str]] = []
    for line in mountinfo:
        before, separator, after = line.partition(" - ")
        if not separator:
            continue
        fields = before.split()
        filesystem = after.split()[0] if after.split() else ""
        if len(fields) < 5:
            continue
        mount = Path(fields[4].replace("\\040", " "))
        try:
            resolved.relative_to(mount)
        except ValueError:
            continue
        matches.append((len(mount.parts), filesystem))
    if not matches or max(matches)[1] != "tmpfs":
        raise CredentialError("connector credentials must remain on tmpfs")


def _prepare_directory(runtime_root: Path, *, enforce_tmpfs: bool) -> None:
    if enforce_tmpfs:
        _assert_tmpfs(runtime_root)
    runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = runtime_root.lstat()
    expected_uid = 0 if enforce_tmpfs else os.geteuid()
    if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or (enforce_tmpfs and metadata.st_gid != 0)
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise CredentialError("connector credential directory is unsafe")


def _selection(document: Mapping[str, Any], release: Path) -> bytes:
    raw = (json.dumps(document, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")
    selected = {
        "schema": 1,
        "release": release.name,
        "metadata_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return (json.dumps(selected, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")


def _clean(runtime_root: Path) -> None:
    for name in (TOKEN_NAME, SELECTION_NAME):
        path = runtime_root / name
        if path.is_symlink():
            raise CredentialError("connector credential path is a symbolic link")
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    try:
        runtime_root.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        raise CredentialError("connector credential directory contains unexpected state") from None


def prepare(
    release: Path,
    *,
    project_root: Path = DEFAULT_PROJECT_ROOT,
    runtime_root: Path = DEFAULT_RUNTIME_ROOT,
    oci_binary: Path = DEFAULT_OCI,
    enforce_tmpfs: bool = True,
) -> None:
    del project_root  # reserved for a future multi-project host layout
    mode = _release_mode(release)
    metadata = load_metadata(release)
    service_state = _runtime_state(release)
    active = service_state.get("enabled") is True and service_state.get("active") is True
    if metadata is None and mode == "staging":
        if active:
            raise CredentialError("staging connector state requires canary metadata")
        _clean(runtime_root)
        return
    if metadata is not None:
        if mode != "staging" or not active:
            raise CredentialError("canary metadata is valid only for an active staging connector")
        if PRODUCTION_GATE.exists() or PRODUCTION_GATE.is_symlink():
            raise CredentialError("production origin gate must remain closed during canary")
        _validate_canary_origin_boundary(release)
        secret = metadata["secret"]
        assert isinstance(secret, dict)
        token = fetch_exact_secret(
            str(secret["ocid"]), int(secret["version"]), oci_binary=oci_binary
        )
        token = validate_tunnel_token(
            token, str(metadata["account_id"]), str(metadata["tunnel_id"])
        )
        selection = _selection(metadata, release)
    else:
        if mode != "vault" or not active:
            raise CredentialError("production connector requires a complete Vault release")
        token = _regular_bytes(
            Path("/run/clixor/secrets/active/cloudflare-token"),
            MAX_TOKEN_BYTES,
            mode=0o600,
            owner=(0, 0) if enforce_tmpfs else None,
        )
        selection = (json.dumps({"schema": 1, "release": release.name, "mode": "vault"}, sort_keys=True) + "\n").encode("ascii")
    _prepare_directory(runtime_root, enforce_tmpfs=enforce_tmpfs)
    _atomic_write(runtime_root / TOKEN_NAME, token, 0o600)
    _atomic_write(runtime_root / SELECTION_NAME, selection, 0o600)


def verify(
    release: Path,
    *,
    runtime_root: Path = DEFAULT_RUNTIME_ROOT,
    enforce_tmpfs: bool = True,
) -> None:
    mode = _release_mode(release)
    metadata = load_metadata(release)
    active = _runtime_state(release).get("active") is True
    if not active:
        if any(
            (runtime_root / name).exists() or (runtime_root / name).is_symlink()
            for name in (TOKEN_NAME, SELECTION_NAME)
        ):
            raise CredentialError("disabled connector retains a credential")
        return
    _prepare_directory(runtime_root, enforce_tmpfs=enforce_tmpfs)
    runtime_owner = (0, 0) if enforce_tmpfs else None
    token = _regular_bytes(
        runtime_root / TOKEN_NAME, MAX_TOKEN_BYTES, mode=0o600, owner=runtime_owner
    )
    selection = _regular_bytes(
        runtime_root / SELECTION_NAME, MAX_DOCUMENT_BYTES,
        mode=0o600, owner=runtime_owner,
    )
    if metadata is not None:
        if PRODUCTION_GATE.exists() or PRODUCTION_GATE.is_symlink():
            raise CredentialError("production origin gate must remain closed during canary")
        _validate_canary_origin_boundary(release)
        validate_tunnel_token(token, str(metadata["account_id"]), str(metadata["tunnel_id"]))
        if not hmac.compare_digest(selection, _selection(metadata, release)):
            raise CredentialError("canary connector selection does not match the release")
    elif mode == "vault":
        active_token = _regular_bytes(
            Path("/run/clixor/secrets/active/cloudflare-token"),
            MAX_TOKEN_BYTES,
            mode=0o600,
            owner=(0, 0) if enforce_tmpfs else None,
        )
        if not hmac.compare_digest(token, active_token):
            raise CredentialError("production connector token differs from the complete Vault cohort")
    else:
        raise CredentialError("active staging connector has no canary metadata")


def _verify_remote_config_once(
    metadata: Mapping[str, Any], url: str
) -> None:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read(MAX_DOCUMENT_BYTES + 1)
    except (OSError, urllib.error.URLError):
        raise CredentialError("cloudflared remote configuration is unavailable") from None
    response = _load_json_bytes(raw, "cloudflared remote configuration")
    remote = metadata["remote_config"]
    assert isinstance(remote, dict)
    config = response.get("config")
    if response.get("version") != remote["version"] or not isinstance(config, dict):
        raise CredentialError("cloudflared applied another configuration version")
    ingress = config.get("ingress")
    if not isinstance(ingress, list) or len(ingress) != 2:
        raise CredentialError("cloudflared remote ingress is not canary-only")
    projected = []
    for rule in ingress:
        if not isinstance(rule, dict):
            raise CredentialError("cloudflared remote ingress is invalid")
        projected.append({key: rule[key] for key in ("hostname", "service") if key in rule})
    if projected != remote["ingress"]:
        raise CredentialError("cloudflared remote ingress differs from the reviewed canary")
    warp = config.get("warp-routing")
    if warp not in (None, {}, {"enabled": False}):
        raise CredentialError("cloudflared remote private routing must be disabled")


def verify_remote_config(
    metadata: Mapping[str, Any],
    url: str = "http://127.0.0.1:20241/config",
    *,
    attempts: int = 12,
    retry_delay: float = 2.0,
) -> None:
    if attempts <= 0:
        raise CredentialError("cloudflared verification attempt count is invalid")
    last_error: CredentialError | None = None
    for attempt in range(attempts):
        try:
            _verify_remote_config_once(metadata, url)
            return
        except CredentialError as error:
            last_error = error
        if attempt + 1 < attempts:
            time.sleep(retry_delay)
    assert last_error is not None
    raise last_error


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    stage = subparsers.add_parser("stage-metadata")
    stage.add_argument("--release", required=True, type=Path)
    stage.add_argument("--account-id", required=True)
    stage.add_argument("--tunnel-id", required=True)
    stage.add_argument("--secret-ocid", required=True)
    stage.add_argument("--secret-version", required=True, type=int)
    stage.add_argument("--remote-config-version", required=True, type=int)
    for action in ("prepare", "verify", "verify-remote"):
        command = subparsers.add_parser(action)
        command.add_argument("--release", required=True, type=Path)
        command.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
        if action == "prepare":
            command.add_argument("--project-root", type=Path, default=DEFAULT_PROJECT_ROOT)
            command.add_argument("--oci-binary", type=Path, default=DEFAULT_OCI)
    options = parser.parse_args(arguments)
    try:
        if options.action == "stage-metadata":
            stage_metadata(
                options.release,
                _metadata_document(
                    options.account_id, options.tunnel_id, options.secret_ocid,
                    options.secret_version, options.remote_config_version,
                ),
            )
        elif options.action == "prepare":
            if os.geteuid() != 0 and options.runtime_root == DEFAULT_RUNTIME_ROOT:
                raise CredentialError("connector credential preparation must run as root")
            prepare(
                options.release, project_root=options.project_root,
                runtime_root=options.runtime_root, oci_binary=options.oci_binary,
                enforce_tmpfs=options.runtime_root == DEFAULT_RUNTIME_ROOT,
            )
        elif options.action == "verify":
            verify(
                options.release, runtime_root=options.runtime_root,
                enforce_tmpfs=options.runtime_root == DEFAULT_RUNTIME_ROOT,
            )
        else:
            metadata = load_metadata(options.release)
            if metadata is None:
                raise CredentialError("release is not a canary connector release")
            verify_remote_config(metadata)
    except (CredentialError, OSError) as error:
        print(f"Clixor connector credential refused: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
