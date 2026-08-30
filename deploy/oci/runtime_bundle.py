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
RELEASE_RE = re.compile(r"^oci-[0-9a-f]{12}-[A-Za-z0-9._-]{1,160}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
CLOUDFLARED_BINARY = Path("/usr/bin/cloudflared")

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
        "host-tools/bin/cloudflared",
        "host-tools/systemd/clixor-offsite-backup.service",
        "host-tools/systemd/clixor-offsite-backup.timer",
        "host-tools/systemd/clixor-backup-health.service",
        "host-tools/systemd/clixor-backup-health.timer",
        "host-tools/systemd/clixor-restore-drill.service",
        "host-tools/systemd/clixor-restore-drill.timer",
        "host-tools/systemd/cloudflared.service",
    }
)

HOST_TOOL_SOURCE_MODES = {
    "bin/offsite-backup.sh": True,
    "bin/backup-health.sh": True,
    "bin/restore-drill.sh": True,
    "bin/backup_manifest.py": True,
    "systemd/clixor-offsite-backup.service": False,
    "systemd/clixor-offsite-backup.timer": False,
    "systemd/clixor-backup-health.service": False,
    "systemd/clixor-backup-health.timer": False,
    "systemd/clixor-restore-drill.service": False,
    "systemd/clixor-restore-drill.timer": False,
    "systemd/cloudflared.service": False,
}


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


def validate_runtime_bundle(
    release: Path, *, expected_uid: int = 0, expected_gid: int = 0
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
    required_paths = {artifact.bundle_path for artifact in RUNTIME_ARTIFACTS}
    required_paths.update(REQUIRED_HOST_TOOLS)
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
        else:
            validate_runtime_bundle(options.release)
    except (BundleError, OSError) as error:
        print(f"Clixor runtime bundle refused: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
