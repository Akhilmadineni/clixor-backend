#!/usr/bin/env python3
"""Build and verify immutable, release-local OCI runtime bundles.

The bundle is deliberately independent from Docker's mutable container metadata.
It contains every non-secret artifact needed by the stable host reconciler to
restore and start the exact release selected by ``releases/current``.  Vault
version selection remains in the separately checksummed boot-secret bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


BUNDLE_SCHEMA = 2
CONTROLLER_VERSION = 2
BUNDLE_DIRECTORY = "runtime-bundle"
MANIFEST_NAME = "manifest.json"
PROMOTION_EXTENSION_DIRECTORY = "promotion-host-tools-v1"
PROMOTION_EXTENSION_SCHEMA = 1
RELEASE_RE = re.compile(r"^oci-[0-9a-f]{12}-[A-Za-z0-9._-]{1,160}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ACCOUNT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
VAULT_SECRET_OCID_RE = re.compile(r"^ocid1\.vaultsecret\.oc1\.phx\.[a-z0-9]{20,}$")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
CLOUDFLARED_BINARY = Path("/usr/bin/cloudflared")
CANARY_CONNECTOR_METADATA = "cloudflare-canary-connector.json"
CANARY_CONNECTOR_HELPER = "host-tools/bin/cloudflare-canary-credential.py"
CANARY_HOSTNAME = "clixor-oci-canary.atlanteanz.com"
CANARY_ORIGIN = "unix:/run/clixor-origin/gateway.sock"

SOURCE_EXCLUDES = frozenset({".git", ".DS_Store", ".build", "coverage.out"})


@dataclass(frozen=True)
class RuntimeArtifact:
    bundle_path: str
    source_kind: str
    source_path: str
    target_path: str
    uid: int
    gid: int
    mode: int


# Only runtime-consumed PKI is snapshotted.  The long-lived CA private key stays
# in /srv/clixor/secrets/pki and is never duplicated into release history.
RUNTIME_ARTIFACTS = (
    RuntimeArtifact(
        "runtime/dependency-pki.desired",
        "runtime",
        "dependency-pki.desired",
        "/srv/clixor/runtime/dependency-pki.desired",
        0,
        0,
        0o600,
    ),
    RuntimeArtifact(
        "runtime/dependency-pki.applied",
        "runtime",
        "dependency-pki.applied",
        "/srv/clixor/runtime/dependency-pki.applied",
        0,
        0,
        0o600,
    ),
    RuntimeArtifact(
        "runtime/pki/ca.crt",
        "pki",
        "ca.crt",
        "/srv/clixor/secrets/pki/ca.crt",
        0,
        0,
        0o644,
    ),
    RuntimeArtifact(
        "runtime/dependency-tls/haproxy.cfg",
        "runtime",
        "dependency-tls/haproxy.cfg",
        "/srv/clixor/runtime/dependency-tls/haproxy.cfg",
        0,
        99,
        0o400,
    ),
    RuntimeArtifact(
        "runtime/dependency-tls/server.pem",
        "runtime",
        "dependency-tls/current/server.pem",
        "/srv/clixor/runtime/dependency-tls/current/server.pem",
        0,
        99,
        0o440,
    ),
    RuntimeArtifact(
        "runtime/postgres-tls/server.key",
        "runtime",
        "postgres-tls/current/server.key",
        "/srv/clixor/runtime/postgres-tls/current/server.key",
        0,
        70,
        0o440,
    ),
    RuntimeArtifact(
        "runtime/postgres-tls/server.crt",
        "runtime",
        "postgres-tls/current/server.crt",
        "/srv/clixor/runtime/postgres-tls/current/server.crt",
        0,
        70,
        0o440,
    ),
    RuntimeArtifact(
        "runtime/nats-tls/server.key",
        "runtime",
        "nats-tls/current/server.key",
        "/srv/clixor/runtime/nats-tls/current/server.key",
        0,
        1000,
        0o440,
    ),
    RuntimeArtifact(
        "runtime/nats-tls/server.crt",
        "runtime",
        "nats-tls/current/server.crt",
        "/srv/clixor/runtime/nats-tls/current/server.crt",
        0,
        1000,
        0o440,
    ),
    RuntimeArtifact(
        "runtime/api-gateway/nginx.conf",
        "runtime",
        "api-gateway/nginx.conf",
        "/srv/clixor/runtime/api-gateway/nginx.conf",
        986,
        987,
        0o400,
    ),
    RuntimeArtifact(
        "runtime/postgres-backup/backup.sh",
        "runtime",
        "postgres-backup/backup.sh",
        "/srv/clixor/runtime/postgres-backup/backup.sh",
        0,
        0,
        0o500,
    ),
    RuntimeArtifact(
        "runtime/prometheus/prometheus.yml",
        "runtime",
        "prometheus/prometheus.yml",
        "/srv/clixor/runtime/prometheus/prometheus.yml",
        65534,
        65534,
        0o400,
    ),
    RuntimeArtifact(
        "runtime/grafana/datasource.yml",
        "runtime",
        "grafana/datasource.yml",
        "/srv/clixor/runtime/grafana/datasource.yml",
        472,
        472,
        0o400,
    ),
)

REQUIRED_HOST_TOOLS = frozenset(
    {
        "host-tools/bin/offsite-backup.sh",
        "host-tools/bin/backup-health.sh",
        "host-tools/bin/restore-drill.sh",
        "host-tools/bin/backup_manifest.py",
        "host-tools/bin/cloudflare-promote.py",
        "host-tools/bin/cloudflare-promote.py.sha256",
        "host-tools/bin/cloudflared",
        "host-tools/systemd/clixor-offsite-backup.service",
        "host-tools/systemd/clixor-offsite-backup.timer",
        "host-tools/systemd/clixor-backup-health.service",
        "host-tools/systemd/clixor-backup-health.timer",
        "host-tools/systemd/clixor-restore-drill.service",
        "host-tools/systemd/clixor-restore-drill.timer",
        "host-tools/systemd/cloudflared.service",
        "host-tools/systemd/clixor-cloudflare-promote.service",
        "host-tools/tmpfiles/clixor-cloudflare-origin-gate.conf",
    }
)

HOST_TOOL_SOURCE_MODES = {
    "bin/offsite-backup.sh": True,
    "bin/backup-health.sh": True,
    "bin/restore-drill.sh": True,
    "bin/backup_manifest.py": True,
    "bin/cloudflare-promote.py": True,
    "systemd/clixor-offsite-backup.service": False,
    "systemd/clixor-offsite-backup.timer": False,
    "systemd/clixor-backup-health.service": False,
    "systemd/clixor-backup-health.timer": False,
    "systemd/clixor-restore-drill.service": False,
    "systemd/clixor-restore-drill.timer": False,
    "systemd/cloudflared.service": False,
    "systemd/clixor-cloudflare-promote.service": False,
    "tmpfiles/clixor-cloudflare-origin-gate.conf": False,
}
PROMOTION_EXTENSION_SOURCE_MODES = {
    "host-tools/bin/cloudflare-promote.py": True,
    "host-tools/systemd/clixor-cloudflare-promote.service": False,
    "host-tools/tmpfiles/clixor-cloudflare-origin-gate.conf": False,
}
PROMOTION_EXTENSION_REQUIRED = frozenset(
    {
        *PROMOTION_EXTENSION_SOURCE_MODES,
        "host-tools/bin/cloudflare-promote.py.sha256",
    }
)


class BundleError(RuntimeError):
    """A runtime bundle is incomplete, unsafe, or inconsistent."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"runtime manifest contains duplicate field: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        metadata = path.lstat()
    except OSError:
        raise BundleError("runtime manifest is unavailable") from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BundleError("runtime manifest must be a regular file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_MANIFEST_BYTES:
        raise BundleError("runtime manifest size is invalid")
    try:
        loaded = json.loads(
            path.read_text(encoding="ascii"), object_pairs_hook=_strict_object
        )
    except BundleError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BundleError("runtime manifest is invalid JSON") from None
    if not isinstance(loaded, dict):
        raise BundleError("runtime manifest must be an object")
    return loaded


def _fsync(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        while True:
            chunk = input_file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_tree(root: Path) -> None:
    directories: list[Path] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        directories.append(current)
        for name in names:
            path = current / name
            if path.is_symlink():
                raise BundleError(f"runtime bundle contains a symbolic link: {path.name}")
        for name in files:
            path = current / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BundleError(f"runtime bundle contains a special file: {path.name}")
            _fsync(path)
    for directory in reversed(directories):
        _fsync(directory)


def _lock_tree_directories(root: Path) -> None:
    for directory, names, _ in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        os.chmod(current, 0o700)
        for name in names:
            if (current / name).is_symlink():
                raise BundleError("runtime bundle contains a symbolic link")


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_release_name(release: Path) -> None:
    if not release.is_absolute() or RELEASE_RE.fullmatch(release.name) is None:
        raise BundleError("runtime release path or name is invalid")
    try:
        metadata = release.lstat()
    except OSError:
        raise BundleError("runtime release directory is unavailable") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BundleError("runtime release must be a regular directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise BundleError("runtime release directory must have mode 0700")


def _copy_locked(source: Path, destination: Path, *, executable: bool = False) -> None:
    try:
        metadata = source.lstat()
    except OSError:
        raise BundleError(f"runtime source is unavailable: {source}") from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BundleError(f"runtime source must be a regular file: {source}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_FILE_BYTES:
        raise BundleError(f"runtime source size is invalid: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o500 if executable else 0o400,
    )
    try:
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            shutil.copyfileobj(input_file, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _copy_source_tree(source_root: Path, destination_root: Path) -> None:
    if source_root.is_symlink() or not source_root.is_dir():
        raise BundleError("approved source root is unsafe")
    destination_root.mkdir(mode=0o700)
    for directory, names, files in os.walk(source_root, topdown=True, followlinks=False):
        current = Path(directory)
        relative = current.relative_to(source_root)
        names[:] = [name for name in names if name not in SOURCE_EXCLUDES]
        target_directory = destination_root / relative
        target_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target_directory, 0o700)
        for name in names:
            child = current / name
            if child.is_symlink():
                raise BundleError(f"approved source contains a symbolic link: {child}")
        for name in files:
            if name in SOURCE_EXCLUDES:
                continue
            child = current / name
            if child.is_symlink():
                raise BundleError(f"approved source contains a symbolic link: {child}")
            executable = bool(child.stat().st_mode & 0o111)
            _copy_locked(child, target_directory / name, executable=executable)


def stage_source(
    release: Path,
    source_root: Path,
    source_sha: str,
    compose_source: Path | None = None,
) -> Path:
    """Create the immutable source half of a pending release bundle."""

    _validate_release_name(release)
    if SOURCE_SHA_RE.fullmatch(source_sha) is None:
        raise BundleError("runtime source revision is invalid")
    if release.name[4:16] != source_sha[:12]:
        raise BundleError("runtime release name does not match its source revision")
    bundle = release / BUNDLE_DIRECTORY
    if bundle.exists() or bundle.is_symlink():
        raise BundleError("runtime bundle already exists")
    bundle.mkdir(mode=0o700)
    _copy_source_tree(source_root, bundle / "source")
    selected_compose = (
        source_root / "deploy" / "oci" / "compose.yaml"
        if compose_source is None
        else compose_source
    )
    _copy_locked(selected_compose, bundle / "compose.yaml")
    _atomic_write(bundle / "source-sha", (source_sha + "\n").encode("ascii"), 0o400)
    required = bundle / "source" / "deploy" / "oci" / "compose.yaml"
    if (
        not required.is_file()
        or required.is_symlink()
        or not (bundle / "compose.yaml").is_file()
    ):
        raise BundleError("runtime source has no safe Compose model")
    _fsync_tree(bundle)
    _fsync(release)
    return bundle


def stage_host_tools(
    release: Path,
    source_root: Path,
    cloudflared_binary: Path = CLOUDFLARED_BINARY,
) -> None:
    """Stage the exact selected host programs and units into a pending bundle."""

    _validate_release_name(release)
    bundle = release / BUNDLE_DIRECTORY
    if not bundle.is_dir() or bundle.is_symlink():
        raise BundleError("runtime source must be staged before host tools")
    host_root = bundle / "host-tools"
    if host_root.exists() or host_root.is_symlink():
        raise BundleError("runtime host tools are already staged")
    for relative, executable in HOST_TOOL_SOURCE_MODES.items():
        category, name = relative.split("/", 1)
        _copy_locked(
            source_root / "deploy" / "oci" / name,
            host_root / category / name,
            executable=executable,
        )
    connector_helper = source_root / "deploy" / "oci" / "cloudflare-canary-credential.py"
    if connector_helper.is_file() and not connector_helper.is_symlink():
        _copy_locked(
            connector_helper,
            host_root / "bin" / "cloudflare-canary-credential.py",
            executable=True,
        )
    promoter = host_root / "bin" / "cloudflare-promote.py"
    checksum = (_sha256_file(promoter)
                + "  /usr/local/libexec/clixor/cloudflare-promote.py\n").encode("ascii")
    _atomic_write(host_root / "bin" / "cloudflare-promote.py.sha256",
                  checksum, 0o400)
    # cloudflared is package-managed host state, but it is part of the selected
    # ingress runtime just as much as its systemd unit. Snapshot the exact
    # executable so rollback/reboot does not silently select a later host
    # package than the release approved.
    _copy_locked(
        cloudflared_binary,
        host_root / "bin" / "cloudflared",
        executable=True,
    )
    _lock_tree_directories(host_root)
    _fsync_tree(host_root)
    _fsync(bundle)


def _promotion_extension_inventory(
    root: Path, *, expected_uid: int, expected_gid: int
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        metadata = current.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid)
                or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise BundleError("promotion extension contains an unsafe directory")
        for name in names:
            if (current / name).is_symlink():
                raise BundleError("promotion extension contains a symbolic link")
        for name in files:
            path = current / name
            if path == root / MANIFEST_NAME:
                continue
            file_metadata = path.lstat()
            if (not stat.S_ISREG(file_metadata.st_mode) or stat.S_ISLNK(file_metadata.st_mode)
                    or (file_metadata.st_uid, file_metadata.st_gid)
                    != (expected_uid, expected_gid)
                    or file_metadata.st_size <= 0
                    or file_metadata.st_size > MAX_FILE_BYTES):
                raise BundleError("promotion extension contains an unsafe file")
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _sha256_file(path),
                    "size": file_metadata.st_size,
                    "mode": stat.S_IMODE(file_metadata.st_mode),
                }
            )
    records.sort(key=lambda record: str(record["path"]))
    return records


def validate_promotion_extension(
    release: Path, source_sha: str, *, expected_uid: int = 0, expected_gid: int = 0
) -> Path:
    root = release / PROMOTION_EXTENSION_DIRECTORY
    manifest_path = root / MANIFEST_NAME
    manifest = _load_json(manifest_path)
    manifest_metadata = manifest_path.lstat()
    if ((manifest_metadata.st_uid, manifest_metadata.st_gid)
            != (expected_uid, expected_gid)
            or stat.S_IMODE(manifest_metadata.st_mode) != 0o400
            or set(manifest) != {
                "schema", "release", "source_sha", "controller_sha256", "files"
            }
            or manifest.get("schema") != PROMOTION_EXTENSION_SCHEMA
            or manifest.get("release") != release.name
            or manifest.get("source_sha") != source_sha):
        raise BundleError("promotion extension manifest is invalid")
    records = _promotion_extension_inventory(
        root, expected_uid=expected_uid, expected_gid=expected_gid
    )
    if manifest.get("files") != records:
        raise BundleError("promotion extension inventory changed")
    paths = {str(record["path"]) for record in records}
    if paths != PROMOTION_EXTENSION_REQUIRED:
        raise BundleError("promotion extension inventory is incomplete")
    expected_modes = {
        "host-tools/bin/cloudflare-promote.py": 0o500,
        "host-tools/bin/cloudflare-promote.py.sha256": 0o400,
        "host-tools/systemd/clixor-cloudflare-promote.service": 0o400,
        "host-tools/tmpfiles/clixor-cloudflare-origin-gate.conf": 0o400,
    }
    if any(record["mode"] != expected_modes[str(record["path"])] for record in records):
        raise BundleError("promotion extension file mode is invalid")
    checksum = (root / "host-tools/bin/cloudflare-promote.py.sha256").read_text(
        encoding="ascii"
    )
    promoter_sha = _sha256_file(root / "host-tools/bin/cloudflare-promote.py")
    if (manifest.get("controller_sha256") != promoter_sha
            or checksum
            != promoter_sha + "  /usr/local/libexec/clixor/cloudflare-promote.py\n"):
        raise BundleError("promotion extension checksum is invalid")
    return root / "host-tools"


def install_promotion_extension(release: Path, source_root: Path) -> None:
    """Atomically extend an already-committed pre-promotion runtime release."""
    _validate_release_name(release)
    bundle = release / BUNDLE_DIRECTORY
    release_metadata = release.lstat()
    expected_uid, expected_gid = release_metadata.st_uid, release_metadata.st_gid
    destination = release / PROMOTION_EXTENSION_DIRECTORY
    if destination.exists() or destination.is_symlink():
        validate_runtime_bundle(
            release, expected_uid=expected_uid, expected_gid=expected_gid
        )
        return
    manifest = validate_runtime_bundle(
        release,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        _allow_missing_promotion_extension=True,
    )
    source_sha = manifest["source_sha"]
    assert isinstance(source_sha, str)
    if (bundle / "host-tools/bin/cloudflare-promote.py").is_file():
        return
    temporary = Path(tempfile.mkdtemp(
        prefix=f".{PROMOTION_EXTENSION_DIRECTORY}.", dir=release
    ))
    try:
        for relative, executable in PROMOTION_EXTENSION_SOURCE_MODES.items():
            _, category, name = relative.split("/", 2)
            _copy_locked(source_root / "deploy" / "oci" / name,
                         temporary / "host-tools" / category / name,
                         executable=executable)
        promoter = temporary / "host-tools/bin/cloudflare-promote.py"
        checksum = (_sha256_file(promoter)
                    + "  /usr/local/libexec/clixor/cloudflare-promote.py\n").encode("ascii")
        _atomic_write(temporary / "host-tools/bin/cloudflare-promote.py.sha256",
                      checksum, 0o400)
        _lock_tree_directories(temporary)
        records = _promotion_extension_inventory(
            temporary,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        document = {
            "schema": PROMOTION_EXTENSION_SCHEMA,
            "release": release.name,
            "source_sha": source_sha,
            "controller_sha256": _sha256_file(promoter),
            "files": records,
        }
        _atomic_write(
            temporary / MANIFEST_NAME,
            (
                json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True)
                + "\n"
            ).encode("ascii"),
            0o400,
        )
        _fsync_tree(temporary)
        os.rename(temporary, destination)
        _fsync(release)
        validate_runtime_bundle(
            release, expected_uid=expected_uid, expected_gid=expected_gid
        )
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _copy_runtime_artifacts(bundle: Path, runtime_root: Path, pki_root: Path) -> None:
    for artifact in RUNTIME_ARTIFACTS:
        source_base = runtime_root if artifact.source_kind == "runtime" else pki_root
        source = source_base / artifact.source_path
        destination = bundle / artifact.bundle_path
        _copy_locked(source, destination, executable=bool(artifact.mode & 0o111))


def _inventory(bundle: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for directory, names, files in os.walk(bundle, topdown=True, followlinks=False):
        current = Path(directory)
        for name in names:
            path = current / name
            if path.is_symlink():
                raise BundleError(f"runtime bundle contains a symbolic link: {path.name}")
        for name in files:
            path = current / name
            if path == bundle / MANIFEST_NAME:
                continue
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BundleError(f"runtime bundle contains a special file: {path.name}")
            if metadata.st_size <= 0 or metadata.st_size > MAX_FILE_BYTES:
                raise BundleError(f"runtime bundle file size is invalid: {path.name}")
            relative = path.relative_to(bundle).as_posix()
            digest = _sha256_file(path)
            records.append(
                {
                    "path": relative,
                    "sha256": digest,
                    "size": metadata.st_size,
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            )
    records.sort(key=lambda record: str(record["path"]))
    return records


def _parse_state_file(path: Path) -> dict[str, Any]:
    allowed = {
        "cloudflared_enabled",
        "cloudflared_active",
        "prometheus_active",
        "grafana_active",
        "offsite_timer_enabled",
        "restore_timer_enabled",
        "health_timer_enabled",
    }
    values: dict[str, bool] = {}
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        raise BundleError("runtime state input is unavailable") from None
    for line in lines:
        if line.count("=") != 1:
            raise BundleError("runtime state input is malformed")
        key, raw = line.split("=", 1)
        if key not in allowed or key in values or raw not in ("true", "false"):
            raise BundleError("runtime state input is malformed")
        values[key] = raw == "true"
    if set(values) != allowed:
        raise BundleError("runtime state input is incomplete")
    return {
        "cloudflared": {
            "enabled": values["cloudflared_enabled"],
            "active": values["cloudflared_active"],
        },
        "observability": {
            "prometheus": values["prometheus_active"],
            "grafana": values["grafana_active"],
        },
        "timers": {
            "clixor-offsite-backup.timer": values["offsite_timer_enabled"],
            "clixor-restore-drill.timer": values["restore_timer_enabled"],
            "clixor-backup-health.timer": values["health_timer_enabled"],
        },
    }


def finalize_bundle(
    release: Path,
    runtime_root: Path,
    pki_root: Path,
    source_sha: str,
    image_ref: str,
    image_id: str,
    state_file: Path,
) -> Path:
    """Finish, checksum, and fsync a pending release runtime bundle."""

    _validate_release_name(release)
    if SOURCE_SHA_RE.fullmatch(source_sha) is None or release.name[4:16] != source_sha[:12]:
        raise BundleError("runtime source revision is invalid")
    if image_ref != f"clixor-api:{release.name}":
        raise BundleError("runtime image reference is not release-immutable")
    if IMAGE_ID_RE.fullmatch(image_id) is None:
        raise BundleError("runtime image ID is invalid")
    bundle = release / BUNDLE_DIRECTORY
    source_revision = bundle / "source-sha"
    try:
        if source_revision.read_text(encoding="ascii") != source_sha + "\n":
            raise BundleError("staged source revision changed")
    except (OSError, UnicodeError):
        raise BundleError("staged source revision is unavailable") from None
    if (bundle / MANIFEST_NAME).exists() or (bundle / MANIFEST_NAME).is_symlink():
        raise BundleError("runtime bundle is already finalized")
    _copy_runtime_artifacts(bundle, runtime_root, pki_root)
    _lock_tree_directories(bundle)
    state = _parse_state_file(state_file)
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "minimum_controller_version": CONTROLLER_VERSION,
        "release": release.name,
        "source_sha": source_sha,
        "image": {"ref": image_ref, "id": image_id},
        "state": state,
        "files": _inventory(bundle),
    }
    encoded = (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    _atomic_write(bundle / MANIFEST_NAME, encoded, 0o400)
    _fsync_tree(bundle)
    _fsync(release)
    return bundle


def _require_bool(value: Any, description: str) -> bool:
    if not isinstance(value, bool):
        raise BundleError(f"runtime manifest {description} is invalid")
    return value


def _validate_canary_connector_metadata(path: Path) -> Mapping[str, Any]:
    """Validate the non-secret, release-inventoried canary selection."""

    document = _load_json(path)
    if set(document) != {
        "schema", "mode", "account_id", "tunnel_id", "secret", "remote_config"
    }:
        raise BundleError("canary connector metadata fields are invalid")
    if document.get("schema") != 1 or document.get("mode") != "canary":
        raise BundleError("canary connector metadata schema is invalid")
    account_id = document.get("account_id")
    tunnel_id = document.get("tunnel_id")
    secret = document.get("secret")
    remote = document.get("remote_config")
    if not isinstance(account_id, str) or ACCOUNT_ID_RE.fullmatch(account_id) is None:
        raise BundleError("canary connector account ID is invalid")
    try:
        import uuid

        if str(uuid.UUID(str(tunnel_id))) != tunnel_id:
            raise ValueError
    except (ValueError, AttributeError):
        raise BundleError("canary connector tunnel ID is invalid") from None
    if not isinstance(secret, dict) or set(secret) != {"ocid", "version"}:
        raise BundleError("canary connector secret selection is invalid")
    secret_ocid = secret.get("ocid")
    secret_version = secret.get("version")
    if (not isinstance(secret_ocid, str)
            or VAULT_SECRET_OCID_RE.fullmatch(secret_ocid) is None
            or isinstance(secret_version, bool)
            or not isinstance(secret_version, int)
            or secret_version <= 0):
        raise BundleError("canary connector secret selection is invalid")
    expected_ingress = [
        {"hostname": CANARY_HOSTNAME, "service": CANARY_ORIGIN},
        {"service": "http_status:404"},
    ]
    if (not isinstance(remote, dict)
            or set(remote) != {"version", "ingress"}
            or isinstance(remote.get("version"), bool)
            or not isinstance(remote.get("version"), int)
            or remote["version"] <= 0
            or remote.get("ingress") != expected_ingress):
        raise BundleError("canary connector remote configuration is invalid")
    return document


def validate_runtime_bundle(
    release: Path,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    _allow_missing_promotion_extension: bool = False,
) -> Mapping[str, Any]:
    """Validate an immutable runtime bundle and return its strict manifest."""

    _validate_release_name(release)
    release_metadata = release.lstat()
    if (release_metadata.st_uid, release_metadata.st_gid) != (expected_uid, expected_gid):
        raise BundleError("runtime release has the wrong owner")
    bundle = release / BUNDLE_DIRECTORY
    try:
        bundle_metadata = bundle.lstat()
    except OSError:
        raise BundleError("runtime bundle directory is unavailable") from None
    if (
        not stat.S_ISDIR(bundle_metadata.st_mode)
        or stat.S_ISLNK(bundle_metadata.st_mode)
        or (bundle_metadata.st_uid, bundle_metadata.st_gid) != (expected_uid, expected_gid)
        or stat.S_IMODE(bundle_metadata.st_mode) != 0o700
    ):
        raise BundleError("runtime bundle directory is unsafe")
    manifest_path = bundle / MANIFEST_NAME
    manifest_metadata = manifest_path.lstat()
    if (
        (manifest_metadata.st_uid, manifest_metadata.st_gid) != (expected_uid, expected_gid)
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o400
    ):
        raise BundleError("runtime manifest ownership or mode is unsafe")
    manifest = _load_json(manifest_path)
    expected_keys = {
        "schema",
        "minimum_controller_version",
        "release",
        "source_sha",
        "image",
        "state",
        "files",
    }
    if set(manifest) != expected_keys:
        raise BundleError("runtime manifest has unsupported or missing fields")
    if manifest["schema"] != BUNDLE_SCHEMA or isinstance(manifest["schema"], bool):
        raise BundleError("runtime manifest schema is unsupported")
    minimum = manifest["minimum_controller_version"]
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum > CONTROLLER_VERSION:
        raise BundleError("runtime bundle requires a newer stable controller")
    if manifest["release"] != release.name:
        raise BundleError("runtime manifest is bound to another release")
    source_sha = manifest["source_sha"]
    if (
        not isinstance(source_sha, str)
        or SOURCE_SHA_RE.fullmatch(source_sha) is None
        or source_sha[:12] != release.name[4:16]
    ):
        raise BundleError("runtime manifest source revision is invalid")
    image = manifest["image"]
    if not isinstance(image, dict) or set(image) != {"ref", "id"}:
        raise BundleError("runtime manifest image identity is invalid")
    if image["ref"] != f"clixor-api:{release.name}" or not isinstance(image["id"], str) or IMAGE_ID_RE.fullmatch(image["id"]) is None:
        raise BundleError("runtime manifest image identity is invalid")
    state = manifest["state"]
    if not isinstance(state, dict) or set(state) != {"cloudflared", "observability", "timers"}:
        raise BundleError("runtime manifest service state is invalid")
    cloudflared = state["cloudflared"]
    observability = state["observability"]
    timers = state["timers"]
    if not isinstance(cloudflared, dict) or set(cloudflared) != {"enabled", "active"}:
        raise BundleError("runtime manifest cloudflared state is invalid")
    _require_bool(cloudflared["enabled"], "cloudflared state")
    _require_bool(cloudflared["active"], "cloudflared state")
    if not isinstance(observability, dict) or set(observability) != {"prometheus", "grafana"}:
        raise BundleError("runtime manifest observability state is invalid")
    for value in observability.values():
        _require_bool(value, "observability state")
    expected_timers = {
        "clixor-offsite-backup.timer",
        "clixor-restore-drill.timer",
        "clixor-backup-health.timer",
    }
    if not isinstance(timers, dict) or set(timers) != expected_timers:
        raise BundleError("runtime manifest timer state is invalid")
    for value in timers.values():
        _require_bool(value, "timer state")

    records = manifest["files"]
    if not isinstance(records, list) or not records:
        raise BundleError("runtime manifest file inventory is invalid")
    expected_inventory: dict[str, tuple[str, int, int]] = {}
    previous = ""
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size", "mode"}:
            raise BundleError("runtime manifest file record is invalid")
        path_value = record["path"]
        digest = record["sha256"]
        size = record["size"]
        mode = record["mode"]
        if (
            not isinstance(path_value, str)
            or not path_value
            or path_value <= previous
            or path_value.startswith("/")
            or ".." in Path(path_value).parts
            or Path(path_value).as_posix() != path_value
        ):
            raise BundleError("runtime manifest file path is invalid or unsorted")
        if not isinstance(digest, str) or SHA_RE.fullmatch(digest) is None:
            raise BundleError("runtime manifest file digest is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0 or size > MAX_FILE_BYTES:
            raise BundleError("runtime manifest file size is invalid")
        if isinstance(mode, bool) or not isinstance(mode, int) or mode < 0 or mode > 0o777 or mode & 0o022:
            raise BundleError("runtime manifest file mode is unsafe")
        expected_inventory[path_value] = (digest, size, mode)
        previous = path_value

    actual_paths: set[str] = set()
    for directory, names, files in os.walk(bundle, topdown=True, followlinks=False):
        current = Path(directory)
        directory_metadata = current.lstat()
        if (
            stat.S_ISLNK(directory_metadata.st_mode)
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or (directory_metadata.st_uid, directory_metadata.st_gid)
            != (expected_uid, expected_gid)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise BundleError("runtime bundle contains an unsafe directory")
        for name in names:
            if (current / name).is_symlink():
                raise BundleError("runtime bundle contains a symbolic link")
        for name in files:
            path = current / name
            if path == manifest_path:
                continue
            relative = path.relative_to(bundle).as_posix()
            actual_paths.add(relative)
            if relative not in expected_inventory:
                raise BundleError("runtime bundle has an unrecorded file")
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid)
            ):
                raise BundleError("runtime bundle file is unsafe")
            digest, size, mode = expected_inventory[relative]
            if metadata.st_size != size or stat.S_IMODE(metadata.st_mode) != mode:
                raise BundleError("runtime bundle file metadata changed")
            actual_digest = _sha256_file(path)
            if actual_digest != digest:
                raise BundleError("runtime bundle file checksum changed")
    if actual_paths != set(expected_inventory):
        raise BundleError("runtime bundle is missing an inventoried file")
    canary_metadata_present = CANARY_CONNECTOR_METADATA in actual_paths
    if canary_metadata_present:
        metadata_record = expected_inventory[CANARY_CONNECTOR_METADATA]
        if metadata_record[2] != 0o400:
            raise BundleError("canary connector metadata mode is unsafe")
        _validate_canary_connector_metadata(bundle / CANARY_CONNECTOR_METADATA)
        if CANARY_CONNECTOR_HELPER not in actual_paths:
            raise BundleError("canary connector credential controller is missing")
        if cloudflared != {"enabled": True, "active": True}:
            raise BundleError("canary connector release must own active connector state")
    promotion_paths = actual_paths.intersection(PROMOTION_EXTENSION_REQUIRED)
    extension = release / PROMOTION_EXTENSION_DIRECTORY
    if promotion_paths == PROMOTION_EXTENSION_REQUIRED:
        if extension.exists() or extension.is_symlink():
            raise BundleError("runtime release has an unexpected promotion extension")
    elif promotion_paths:
        raise BundleError("runtime bundle has a partial promotion-controller cohort")
    elif not _allow_missing_promotion_extension:
        # Schema-2 releases committed by the previous stable controller predate
        # these four files. An explicit, shared-lock bootstrap may attach one
        # independently inventoried, release-bound extension so crash recovery
        # can restore the exact pre-deploy controller. No ordinary deploy can
        # create or change this extension.
        validate_promotion_extension(
            release,
            source_sha,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    elif extension.exists() or extension.is_symlink():
        raise BundleError("runtime release has an unvalidated promotion extension")
    required_paths = {artifact.bundle_path for artifact in RUNTIME_ARTIFACTS}
    required_paths.update(REQUIRED_HOST_TOOLS - PROMOTION_EXTENSION_REQUIRED)
    if promotion_paths == PROMOTION_EXTENSION_REQUIRED:
        required_paths.update(PROMOTION_EXTENSION_REQUIRED)
    required_paths.update(
        {"source-sha", "compose.yaml", "source/go.mod", "source/deploy/oci/compose.yaml"}
    )
    if not required_paths.issubset(actual_paths):
        raise BundleError("runtime bundle is incomplete")
    if (bundle / "source-sha").read_text(encoding="ascii") != source_sha + "\n":
        raise BundleError("runtime bundle source marker does not match manifest")
    compose = (bundle / "compose.yaml").read_text(encoding="utf-8")
    for line in compose.splitlines():
        setting = line.split("#", 1)[0].strip()
        if setting.startswith("restart:") and setting != 'restart: "no"':
            raise BundleError("runtime Compose model permits independent restart")
    if compose.count('restart: "no"') < 11:
        raise BundleError("runtime Compose model does not disable every persistent restart")
    return manifest


def promotion_host_tools_root(
    release: Path, *, expected_uid: int = 0, expected_gid: int = 0
) -> Path:
    """Return the single validated promotion-tool cohort for ``release``."""

    manifest = validate_runtime_bundle(
        release, expected_uid=expected_uid, expected_gid=expected_gid
    )
    bundled = release / BUNDLE_DIRECTORY / "host-tools"
    if (bundled / "bin" / "cloudflare-promote.py").is_file():
        return bundled
    source_sha = manifest["source_sha"]
    assert isinstance(source_sha, str)
    return validate_promotion_extension(
        release,
        source_sha,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def runtime_artifact_sources(
    bundle: Path,
) -> Iterable[tuple[RuntimeArtifact, Path]]:
    for artifact in RUNTIME_ARTIFACTS:
        yield artifact, bundle / artifact.bundle_path


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    stage = subparsers.add_parser("stage-source")
    stage.add_argument("--release", required=True, type=Path)
    stage.add_argument("--source", required=True, type=Path)
    stage.add_argument("--source-sha", required=True)
    stage.add_argument("--compose-source", type=Path)
    host_tools = subparsers.add_parser("stage-host-tools")
    host_tools.add_argument("--release", required=True, type=Path)
    host_tools.add_argument("--source", required=True, type=Path)
    host_tools.add_argument(
        "--cloudflared-binary", type=Path, default=CLOUDFLARED_BINARY
    )
    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--release", required=True, type=Path)
    finalize.add_argument("--runtime-root", required=True, type=Path)
    finalize.add_argument("--pki-root", required=True, type=Path)
    finalize.add_argument("--source-sha", required=True)
    finalize.add_argument("--image-ref", required=True)
    finalize.add_argument("--image-id", required=True)
    finalize.add_argument("--state-file", required=True, type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--release", required=True, type=Path)
    extension = subparsers.add_parser("install-promotion-extension")
    extension.add_argument("--release", required=True, type=Path)
    extension.add_argument("--source", required=True, type=Path)
    options = parser.parse_args(arguments)
    try:
        if options.action == "stage-source":
            stage_source(
                options.release,
                options.source,
                options.source_sha,
                options.compose_source,
            )
        elif options.action == "stage-host-tools":
            stage_host_tools(
                options.release, options.source, options.cloudflared_binary
            )
        elif options.action == "finalize":
            finalize_bundle(
                options.release,
                options.runtime_root,
                options.pki_root,
                options.source_sha,
                options.image_ref,
                options.image_id,
                options.state_file,
            )
        elif options.action == "install-promotion-extension":
            install_promotion_extension(options.release, options.source)
        else:
            validate_runtime_bundle(options.release)
    except (BundleError, OSError) as error:
        print(f"Clixor runtime bundle refused: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
