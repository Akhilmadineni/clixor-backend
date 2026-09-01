#!/usr/bin/env python3
"""Stable current-release reconciler and crash-recovery watchdog.

Docker is intentionally not the boot authority for Clixor.  This root-owned
controller validates ``releases/current``, restores its exact immutable runtime
bundle, and only then starts containers and permits ingress.  The same code
recovers an interrupted deploy after the deploy lock is released.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence

import runtime_bundle


CONTROLLER_VERSION = 2
JOURNAL_SCHEMA = 2
PROJECT_ROOT = Path("/srv/clixor")
HOST_TOOL_ROOT = Path("/usr/local/libexec/clixor")
SYSTEMD_ROOT = Path("/etc/systemd/system")
TMPFILES_ROOT = Path("/etc/tmpfiles.d")
CLOUDFLARED_BINARY = Path("/usr/bin/cloudflared")
READY_MARKER = Path("/run/clixor/runtime-ready")
RUNTIME_SECRET_ROOT = Path("/run/clixor/secrets")
STAGING_SECRET_ROOT = Path("/srv/clixor/secrets")
STAGING_SECRET_MANIFEST = "staging-secret-integrity.json"
LEGACY_SOURCE_PROVENANCE = "legacy-source-provenance.json"
SECRET_INTEGRITY_SCHEMA = 1
LEGACY_SOURCE_PROVENANCE_SCHEMA = 1
MAX_SECRET_ARTIFACT_BYTES = 512 * 1024
KNOWN_CONTAINERS = (
    "clixor-oci-api-gateway",
    "clixor-oci-api-a",
    "clixor-oci-api-b",
    "clixor-oci-postgres-backup",
    "clixor-oci-dependency-tls",
    "clixor-oci-postgres",
    "clixor-oci-redis",
    "clixor-oci-nats",
    "clixor-oci-migrate",
    "clixor-oci-prometheus",
    "clixor-oci-grafana",
)
CGROUP_SYSTEM_SLICE = Path("/sys/fs/cgroup/system.slice")
NFT_BINARY = "/usr/sbin/nft"
EMERGENCY_NFT_TABLE = "clixor_fail_closed"
EMERGENCY_NFT_CANDIDATE = "clixor_fail_closed_candidate"
PHASES = (
    "prepared",
    "secrets-hydrating",
    "secrets-hydrated",
    "runtime-mutating",
    "runtime-mutated",
    "migrating",
    "migrated",
    "candidate-ready",
    "publishing",
    "release-published",
    "pointer-committing",
    "pointer-committed",
    "committed",
)
PHASE_INDEX = {phase: index for index, phase in enumerate(PHASES)}
IMAGE_REF_RE = re.compile(r"^clixor-api:oci-[0-9a-f]{12}-[A-Za-z0-9._-]{1,160}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

# The raw 9e41-era application commit predates the recovery helpers.  Those
# helpers and the host model therefore come from this separately reviewed,
# content-addressed controller cohort.  This allowlist is deliberately data in
# the installed controller: mutable /srv/clixor/repo content is never an input.
LEGACY_CONTROLLER_REVISION = "cd94bac4a47e786670aa0f87972203938dace7c9"
# The three Cloudflare promotion artifacts below are an independently
# content-addressed extension to the historical Git cohort (they did not exist
# at LEGACY_CONTROLLER_REVISION). LEGACY_CONTROLLER_ID binds the union, and the
# one-time transition rejects any mutable-source drift before staging it.
LEGACY_CONTROLLER_FILES = {
    "deploy/oci/backup-health.sh": "0f0faf1a077b78bec4d0305aaba3f606cd76906a205155c3ba2373f028c23d02",
    "deploy/oci/backup_manifest.py": "e569004d5c6357e5a8e78bd85cd1091fce7fb768f05f743c8f9f5936dfbebecc",
    "deploy/oci/offsite-backup.sh": "a53fe752142f4011b5a1949e093fd62a716d627265760e1f64a87256c6b35137",
    "deploy/oci/clixor-backup-health.service": "132c69f6f7a03601302ba312ea1932d2ac5649e288c696c9855200f82639776c",
    "deploy/oci/clixor-backup-health.timer": "07bd84da1e6d4e3476bce0b00c8d0e61de543f3b3c7672ca8c1ed988fc7817db",
    "deploy/oci/clixor-offsite-backup.service": "209472ac8b08ccb8b3403e6f6ca505c798b5df664fed1ec9637ee6581618ff6e",
    "deploy/oci/clixor-offsite-backup.timer": "c6049aae7a9889f2448677af8d32b9bb6772175b0c6d7d10d4fb220444b2e057",
    "deploy/oci/clixor-restore-drill.service": "775fd13e967a423ceb70c3196a0903ec31129646a85442beb8310cb957a05f9a",
    "deploy/oci/clixor-restore-drill.timer": "d4758ed25878071de8ebe8ad091cb1171191c57c22fb4777f5bfda9c195baf72",
    "deploy/oci/cloudflared.service": "64aecc58b03879642f0052db54e3a2924ae95e826f72e9dfc28ec7e88d3207bf",
    "deploy/oci/cloudflare-promote.py": "d772d3acba5d771d10a74867d676469fb33811790c3965fcb75777983a41655c",
    "deploy/oci/clixor-cloudflare-promote.service": "db3382e7f4bba5b9feaf89d77479ee04d8a0c1a6a9ec76b869d072dd986b2dcc",
    "deploy/oci/clixor-cloudflare-origin-gate.conf": "386da33cef8cb76bf4359c2137015d7bc01c8c20ccca612ddbc2d084ea0c7b04",
    "deploy/oci/compose.yaml": "98a7bc7c3cc8daec6cf4198d7db5a410530bf633b2e777e03a73a9b984eba3c3",
    "deploy/oci/hydrate-vault-secrets.py": "b0865ebc228f3a7a8a151b8f32c01211a910e534ce104fbb2be6de603ad1de29",
    "deploy/oci/prepare-runtime-secrets.sh": "bde732854eb1f6ebae4e877a59b7bf4ea1a9bebe9679508ac7a585131ccb0e21",
    "deploy/oci/restore-drill.sh": "8f5952f93de53dab17aedbc0a8ef634f0f96e294645901dfe67f7f15013bfe4c",
}
LEGACY_CONTROLLER_ID = hashlib.sha256(
    b"".join(
        (name + "\0" + digest + "\n").encode("ascii")
        for name, digest in sorted(LEGACY_CONTROLLER_FILES.items())
    )
).hexdigest()


class ReconcileError(RuntimeError):
    """The stable controller refused unsafe or inconsistent host state."""


class CommandRunner:
    """Sanitized subprocess boundary, replaceable by deterministic tests."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        check: bool = True,
        capture: bool = False,
        environment: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            completed = subprocess.run(
                list(arguments),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=dict(environment) if environment is not None else None,
                check=False,
            )
        except OSError:
            raise ReconcileError(f"required command is unavailable: {arguments[0]}") from None
        if check and completed.returncode != 0:
            raise ReconcileError(f"host command failed: {Path(arguments[0]).name}")
        return completed


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReconcileError(f"deployment journal contains duplicate field: {key}")
        result[key] = value
    return result


def _fsync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
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


def _regular_file_bytes(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    maximum_size: int,
) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ReconcileError(f"required release file is unavailable: {path.name}") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid)
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_size <= 0
            or metadata.st_size > maximum_size
        ):
            raise ReconcileError(f"required release file is unsafe: {path.name}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ReconcileError(f"required release file changed: {path.name}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReconcileError(f"required release file changed: {path.name}")
        final = os.fstat(descriptor)
        if (
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
            raise ReconcileError(f"required release file changed: {path.name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _canonical_owned_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    exact_mode: int | None = None,
) -> os.stat_result:
    if not path.is_absolute():
        raise ReconcileError("recovery directory path is not absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        raise ReconcileError("recovery directory is unavailable") from None
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid)
        or resolved != path
        or (exact_mode is not None and mode != exact_mode)
        or (exact_mode is None and mode & 0o022)
    ):
        raise ReconcileError("recovery directory is unsafe or noncanonical")
    return metadata


def _open_recovery_file_at(
    directory_descriptor: int,
    name: str,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except OSError:
        raise ReconcileError(f"recovery artifact is unavailable: {name}") from None
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid)
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_size <= 0
    ):
        os.close(descriptor)
        raise ReconcileError(f"recovery artifact is unsafe: {name}")
    return descriptor, metadata


def _read_open_recovery_file(
    descriptor: int,
    metadata: os.stat_result,
    name: str,
    *,
    maximum_size: int | None = None,
) -> bytes:
    if maximum_size is not None and metadata.st_size > maximum_size:
        raise ReconcileError(f"recovery artifact is unsafe: {name}")
    chunks: list[bytes] = []
    remaining = metadata.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            raise ReconcileError(f"recovery artifact changed: {name}")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ReconcileError(f"recovery artifact changed: {name}")
    final = os.fstat(descriptor)
    if (
        (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_uid,
            final.st_gid,
            final.st_mode,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mode,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    ):
        raise ReconcileError(f"recovery artifact changed: {name}")
    return b"".join(chunks)


def durably_commit_pre_migration_boundary(
    project_root: Path, candidate_release: Path
) -> None:
    """Fsync the validated operator rollback boundary before runtime mutation."""

    release_root = _release_root(project_root)
    _validate_release_path(candidate_release, release_root, pending=True)
    try:
        project_metadata = project_root.lstat()
    except OSError:
        raise ReconcileError("project root is unavailable") from None
    uid, gid = project_metadata.st_uid, project_metadata.st_gid
    _canonical_owned_directory(
        project_root, expected_uid=uid, expected_gid=gid
    )
    _canonical_owned_directory(
        release_root, expected_uid=uid, expected_gid=gid
    )
    pending_root = release_root / "pending"
    pending_metadata = _canonical_owned_directory(
        pending_root,
        expected_uid=uid,
        expected_gid=gid,
        exact_mode=0o700,
    )
    candidate_metadata = _canonical_owned_directory(
        candidate_release,
        expected_uid=uid,
        expected_gid=gid,
        exact_mode=0o700,
    )

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    pending_descriptor = os.open(pending_root, directory_flags)
    candidate_descriptor = -1
    dump_descriptor = -1
    checksum_descriptor = -1
    try:
        opened_pending = os.fstat(pending_descriptor)
        if (opened_pending.st_dev, opened_pending.st_ino) != (
            pending_metadata.st_dev,
            pending_metadata.st_ino,
        ):
            raise ReconcileError("pending release root changed during validation")
        candidate_descriptor = os.open(
            candidate_release.name,
            directory_flags,
            dir_fd=pending_descriptor,
        )
        opened_candidate = os.fstat(candidate_descriptor)
        if (opened_candidate.st_dev, opened_candidate.st_ino) != (
            candidate_metadata.st_dev,
            candidate_metadata.st_ino,
        ):
            raise ReconcileError("candidate release changed during validation")

        dump_descriptor, dump_metadata = _open_recovery_file_at(
            candidate_descriptor,
            "pre-migration.dump",
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=0o600,
        )
        dump_content = _read_open_recovery_file(
            dump_descriptor, dump_metadata, "pre-migration.dump"
        )
        actual_digest = hashlib.sha256(dump_content).hexdigest()
        os.fsync(dump_descriptor)

        checksum_descriptor, checksum_metadata = _open_recovery_file_at(
            candidate_descriptor,
            "pre-migration.dump.sha256",
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=0o600,
        )
        checksum_content = _read_open_recovery_file(
            checksum_descriptor,
            checksum_metadata,
            "pre-migration.dump.sha256",
            maximum_size=256,
        )
        expected_content = f"{actual_digest}  pre-migration.dump\n".encode(
            "ascii"
        )
        if checksum_content != expected_content:
            raise ReconcileError("pre-migration recovery checksum is invalid")
        os.fsync(checksum_descriptor)

        # The child fsync persists both file entries; the parent fsync persists
        # the newly-created candidate directory entry itself.
        os.fsync(candidate_descriptor)
        os.fsync(pending_descriptor)
    finally:
        for descriptor in (
            checksum_descriptor,
            dump_descriptor,
            candidate_descriptor,
            pending_descriptor,
        ):
            if descriptor >= 0:
                os.close(descriptor)


def _journal_path(project_root: Path) -> Path:
    return project_root / "runtime" / "deploy-transaction.json"


def _history_root(project_root: Path) -> Path:
    return project_root / "runtime" / "deploy-transactions"


def _release_root(project_root: Path) -> Path:
    return project_root / "releases"


def _validate_bundle(release: Path, project_root: Path) -> Mapping[str, Any]:
    metadata = project_root.lstat()
    return runtime_bundle.validate_runtime_bundle(
        release, expected_uid=metadata.st_uid, expected_gid=metadata.st_gid
    )


def _read_boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        value = "unavailable"
    return value


def _validate_release_path(
    path: Path, release_root: Path, *, pending: bool
) -> None:
    expected_parent = release_root / "pending" if pending else release_root
    if (
        not path.is_absolute()
        or path.parent != expected_parent
        or runtime_bundle.RELEASE_RE.fullmatch(path.name) is None
    ):
        raise ReconcileError("deployment journal release path is invalid")
    try:
        metadata = path.lstat()
    except OSError:
        raise ReconcileError("deployment journal release directory is unavailable") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReconcileError("deployment journal release path is unsafe")


def _validate_previous_release(value: str, release_root: Path) -> None:
    if value == "none":
        return
    path = Path(value)
    if (
        not path.is_absolute()
        or path.parent != release_root
        or runtime_bundle.RELEASE_RE.fullmatch(path.name) is None
    ):
        raise ReconcileError("deployment journal previous release is invalid")


def _validate_journal(
    document: Mapping[str, Any], project_root: Path, *, require_candidate: bool
) -> Mapping[str, Any]:
    expected_keys = {
        "schema",
        "release",
        "source_sha",
        "candidate_release",
        "final_release",
        "previous_release",
        "previous_image",
        "phase",
        "created_boot_id",
        "transaction_id",
    }
    if set(document) != expected_keys:
        raise ReconcileError("deployment journal has unsupported or missing fields")
    if document["schema"] != JOURNAL_SCHEMA or isinstance(document["schema"], bool):
        raise ReconcileError("deployment journal schema is unsupported")
    release = document["release"]
    source_sha = document["source_sha"]
    if (
        not isinstance(release, str)
        or runtime_bundle.RELEASE_RE.fullmatch(release) is None
        or not isinstance(source_sha, str)
        or runtime_bundle.SOURCE_SHA_RE.fullmatch(source_sha) is None
        or release[4:16] != source_sha[:12]
    ):
        raise ReconcileError("deployment journal release identity is invalid")
    release_root = _release_root(project_root)
    candidate = document["candidate_release"]
    final = document["final_release"]
    previous = document["previous_release"]
    if not all(isinstance(value, str) for value in (candidate, final, previous)):
        raise ReconcileError("deployment journal release boundary is invalid")
    candidate_path = Path(candidate)
    final_path = Path(final)
    if candidate_path != release_root / "pending" / release:
        raise ReconcileError("deployment journal candidate path is invalid")
    if final_path != release_root / release:
        raise ReconcileError("deployment journal final path is invalid")
    phase = document["phase"]
    if not isinstance(phase, str) or phase not in PHASE_INDEX:
        raise ReconcileError("deployment journal phase is invalid")
    if require_candidate:
        if PHASE_INDEX[phase] < PHASE_INDEX["release-published"]:
            _validate_release_path(candidate_path, release_root, pending=True)
        else:
            _validate_release_path(final_path, release_root, pending=False)
    _validate_previous_release(previous, release_root)
    previous_image = document["previous_image"]
    if not isinstance(previous_image, str) or (
        previous_image != "none" and IMAGE_REF_RE.fullmatch(previous_image) is None
    ):
        raise ReconcileError("deployment journal previous image is invalid")
    if not isinstance(document["created_boot_id"], str) or not document["created_boot_id"]:
        raise ReconcileError("deployment journal boot identity is invalid")
    transaction_id = document["transaction_id"]
    if not isinstance(transaction_id, str) or re.fullmatch(
        r"[0-9a-f]{32}", transaction_id
    ) is None:
        raise ReconcileError("deployment journal transaction identity is invalid")
    return document


def load_journal(project_root: Path, *, require_candidate: bool = True) -> Mapping[str, Any]:
    path = _journal_path(project_root)
    try:
        metadata = path.lstat()
    except OSError:
        raise ReconcileError("pending deployment journal is unavailable") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > 64 * 1024
    ):
        raise ReconcileError("pending deployment journal is unsafe")
    try:
        document = json.loads(
            path.read_text(encoding="ascii"), object_pairs_hook=_strict_object
        )
    except ReconcileError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ReconcileError("pending deployment journal is corrupt") from None
    if not isinstance(document, dict):
        raise ReconcileError("pending deployment journal must be an object")
    return _validate_journal(document, project_root, require_candidate=require_candidate)


def create_journal(
    project_root: Path,
    candidate_release: Path,
    source_sha: str,
    previous_release: str,
    previous_image: str,
    runner: CommandRunner | None = None,
) -> Mapping[str, Any]:
    path = _journal_path(project_root)
    if path.exists() or path.is_symlink():
        raise ReconcileError("a pending deployment journal already exists")
    release_root = _release_root(project_root)
    _validate_release_path(candidate_release, release_root, pending=True)
    if runtime_bundle.SOURCE_SHA_RE.fullmatch(source_sha) is None:
        raise ReconcileError("deployment journal source revision is invalid")
    if candidate_release.name[4:16] != source_sha[:12]:
        raise ReconcileError("deployment journal release does not match source revision")
    _validate_previous_release(previous_release, release_root)
    if previous_image != "none" and IMAGE_REF_RE.fullmatch(previous_image) is None:
        raise ReconcileError("deployment journal previous image is invalid")
    selected = _resolve_current(project_root)
    if selected is None:
        if previous_release != "none" or previous_image != "none":
            raise ReconcileError(
                "deployment journal cannot record previous state without current"
            )
    else:
        if previous_release != str(selected):
            raise ReconcileError(
                "deployment journal previous release is not current"
            )
        previous_manifest = _validate_bundle(selected, project_root)
        image = previous_manifest.get("image")
        if not isinstance(image, dict) or image.get("ref") != previous_image:
            raise ReconcileError(
                "deployment journal previous image does not match current"
            )
        if runner is not None:
            _boot_bundle_validate(selected, runner)
    document = {
        "schema": JOURNAL_SCHEMA,
        "release": candidate_release.name,
        "source_sha": source_sha,
        "candidate_release": str(candidate_release),
        "final_release": str(release_root / candidate_release.name),
        "previous_release": previous_release,
        "previous_image": previous_image,
        "phase": "prepared",
        "created_boot_id": _read_boot_id(),
        "transaction_id": secrets.token_hex(16),
    }
    encoded = (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    _atomic_write(path, encoded)
    return _validate_journal(document, project_root, require_candidate=True)


def update_journal_phase(project_root: Path, phase: str) -> Mapping[str, Any]:
    if phase not in PHASE_INDEX:
        raise ReconcileError("requested deployment journal phase is invalid")
    # Publication atomically renames pending -> final while the durable phase
    # still says ``publishing``. Load the old record structurally, then require
    # the artifact selected by the *new* phase before persisting it.
    document = dict(load_journal(project_root, require_candidate=False))
    current = str(document["phase"])
    if PHASE_INDEX[phase] != PHASE_INDEX[current] + 1:
        raise ReconcileError("deployment journal phase transition is not consecutive")
    document["phase"] = phase
    _validate_journal(document, project_root, require_candidate=True)
    encoded = (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    _atomic_write(_journal_path(project_root), encoded)
    return document


def archive_journal(project_root: Path, outcome: str) -> Path:
    if not re.fullmatch(r"(?:committed|rolled-back|recovered|recovered-no-current)", outcome):
        raise ReconcileError("deployment journal outcome is invalid")
    document = dict(load_journal(project_root, require_candidate=False))
    if outcome == "committed" and document["phase"] != "pointer-committed":
        raise ReconcileError("only a pointer-committed journal can complete")
    # A failed candidate is never release history. Move only the journal-bound
    # non-current artifact into a root-owned quarantine before completing the
    # transaction record. This is intentionally a rename, never a deletion;
    # database files and named volumes are outside the release tree entirely.
    if outcome != "committed":
        _quarantine_journal_artifact(project_root, document, outcome)
    history = _history_root(project_root)
    history.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(history, 0o700)
    destination = history / (
        f"{document['release']}-{document['transaction_id']}-{outcome}.json"
    )
    if destination.exists() or destination.is_symlink():
        raise ReconcileError("deployment journal transaction archive already exists")
    os.replace(_journal_path(project_root), destination)
    os.chmod(destination, 0o600)
    _fsync(history)
    _fsync(_journal_path(project_root).parent)
    return destination


def _quarantine_root(project_root: Path) -> Path:
    return _release_root(project_root) / "quarantine"


def _quarantine_journal_artifact(
    project_root: Path, document: Mapping[str, Any], outcome: str
) -> Path | None:
    current = _resolve_current(project_root)
    candidates = (
        Path(str(document["candidate_release"])),
        Path(str(document["final_release"])),
    )
    selected: Path | None = None
    for candidate in candidates:
        if (candidate.exists() or candidate.is_symlink()) and candidate != current:
            selected = candidate
            break
    if selected is None:
        return None
    release_root = _release_root(project_root)
    pending = selected.parent == release_root / "pending"
    _validate_release_path(selected, release_root, pending=pending)
    quarantine = _quarantine_root(project_root)
    quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(quarantine, 0o700)
    destination = quarantine / (
        f".{selected.name}-{outcome}-{time.time_ns()}-{os.getpid()}"
    )
    if destination.exists() or destination.is_symlink():
        raise ReconcileError("release quarantine destination already exists")
    os.replace(selected, destination)
    _fsync(selected.parent)
    _fsync(quarantine)
    return destination


def quarantine_pending_candidate(project_root: Path, candidate: Path) -> Path | None:
    """Quarantine a pre-journal SIGKILL leftover so an exact retry can start."""

    journal = _journal_path(project_root)
    if journal.exists() or journal.is_symlink():
        raise ReconcileError("cannot quarantine a candidate while a journal exists")
    release_root = _release_root(project_root)
    if not (candidate.exists() or candidate.is_symlink()):
        return None
    _validate_release_path(candidate, release_root, pending=True)
    quarantine = _quarantine_root(project_root)
    quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(quarantine, 0o700)
    destination = quarantine / (
        f".{candidate.name}-pre-journal-{time.time_ns()}-{os.getpid()}"
    )
    if destination.exists() or destination.is_symlink():
        raise ReconcileError("release quarantine destination already exists")
    os.replace(candidate, destination)
    _fsync(candidate.parent)
    _fsync(quarantine)
    return destination


def _resolve_current(project_root: Path) -> Path | None:
    release_root = _release_root(project_root)
    current = release_root / "current"
    try:
        metadata = current.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise ReconcileError("current release pointer is unavailable") from None
    if not stat.S_ISLNK(metadata.st_mode):
        raise ReconcileError("current release pointer must be a symbolic link")
    try:
        selected = Path(os.readlink(current))
    except OSError:
        raise ReconcileError("current release pointer cannot be read") from None
    if not selected.is_absolute() or selected.parent != release_root:
        raise ReconcileError("current release pointer targets an unexpected location")
    _validate_release_path(selected, release_root, pending=False)
    try:
        if current.resolve(strict=True) != selected:
            raise ReconcileError("current release pointer does not resolve exactly")
    except OSError:
        raise ReconcileError("current release pointer cannot be resolved") from None
    return selected


def _atomic_install(
    source: Path, target: Path, uid: int, gid: int, mode: int
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.parent / f".{target.name}.reconcile.{os.getpid()}"
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            shutil.copyfileobj(input_file, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        _fsync(target.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _kill_cgroup(path: Path) -> bool:
    """Use cgroup v2's kernel kill primitive and prove the group is empty."""

    try:
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return False
        with (path / "cgroup.kill").open("wb", buffering=0) as output:
            output.write(b"1\n")
        return (path / "cgroup.procs").read_bytes().strip() == b""
    except OSError:
        return False


def _nft_json(runner: CommandRunner, *arguments: str) -> Mapping[str, Any] | None:
    result = runner.run([NFT_BINARY, "-j", *arguments], check=False, capture=True)
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _nft_exact_cut(document: Mapping[str, Any] | None, table: str) -> bool:
    if document is None or set(document) != {"nftables"}:
        return False
    objects = document["nftables"]
    if not isinstance(objects, list):
        return False
    table_seen = False
    chains: dict[str, Mapping[str, Any]] = {}
    for item in objects:
        if not isinstance(item, dict) or len(item) != 1:
            return False
        if "metainfo" in item:
            continue
        if "table" in item:
            value = item["table"]
            if not isinstance(value, dict) or value.get("family") != "inet" or value.get("name") != table:
                return False
            table_seen = not table_seen
            if not table_seen:
                return False
            continue
        if "chain" not in item or not isinstance(item["chain"], dict):
            return False
        chain = item["chain"]
        name = chain.get("name")
        if name not in {"input", "output"} or name in chains:
            return False
        if (
            chain.get("family") != "inet"
            or chain.get("table") != table
            or chain.get("type") != "filter"
            or chain.get("hook") != name
            or chain.get("prio") != -300
            or chain.get("policy") != "drop"
        ):
            return False
        chains[str(name)] = chain
    return table_seen and set(chains) == {"input", "output"}


def _known_nft_cut_states(runner: CommandRunner) -> Mapping[str, str] | None:
    """Return an authoritative state for both controller-owned cut identities."""

    ruleset = _nft_json(runner, "list", "ruleset")
    if ruleset is None or not isinstance(ruleset.get("nftables"), list):
        return None
    known = {EMERGENCY_NFT_TABLE, EMERGENCY_NFT_CANDIDATE}
    present: set[str] = set()
    for item in ruleset["nftables"]:
        if not isinstance(item, dict):
            return None
        table = item.get("table")
        if not isinstance(table, dict):
            continue
        if table.get("family") != "inet" or not isinstance(table.get("name"), str):
            continue
        name = str(table["name"])
        if name in known:
            if name in present:
                return None
            present.add(name)
    states: dict[str, str] = {}
    for table in known:
        if table not in present:
            states[table] = "absent"
            continue
        document = _nft_json(runner, "list", "table", "inet", table)
        states[table] = "exact" if _nft_exact_cut(document, table) else "unknown"
    return states


def _run_nft_transaction(runner: CommandRunner, content: bytes) -> bool:
    descriptor, name = tempfile.mkstemp(prefix="clixor-nft-", suffix=".conf")
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        return runner.run([NFT_BINARY, "-f", str(path)], check=False).returncode == 0
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _nft_install_batch(table: str, *, replace: bool) -> bytes:
    if table not in {EMERGENCY_NFT_TABLE, EMERGENCY_NFT_CANDIDATE}:
        raise ReconcileError("invalid emergency network-cut identity")
    commands = f"delete table inet {table}\n" if replace else ""
    commands += (
        f"add table inet {table}\n"
        f"add chain inet {table} input {{ type filter hook input priority -300; policy drop; }}\n"
        f"add chain inet {table} output {{ type filter hook output priority -300; policy drop; }}\n"
    )
    return commands.encode("ascii")


def _activate_emergency_network_cut(runner: CommandRunner) -> bool:
    """Install or recover either exact controller-owned fail-closed identity."""

    states = _known_nft_cut_states(runner)
    if states is None:
        return False
    if "exact" in states.values():
        # Either name is a complete kernel cut.  In particular, a crash after
        # candidate installation is already a safe, idempotent terminal state.
        return True

    # Prefer creating an absent identity. If both known names contain
    # unrecognized state, replace one within a single nft transaction; there is
    # no verified cut to preserve, and nft applies the delete+add atomically.
    target = next(
        (table for table in (EMERGENCY_NFT_CANDIDATE, EMERGENCY_NFT_TABLE) if states[table] == "absent"),
        EMERGENCY_NFT_CANDIDATE,
    )
    if not _run_nft_transaction(
        runner, _nft_install_batch(target, replace=states[target] == "unknown")
    ):
        return False
    return _nft_exact_cut(
        _nft_json(runner, "list", "table", "inet", target), target
    )


def _kernel_fail_closed(runner: CommandRunner) -> bool:
    """Kill known cgroups or prove an immediate whole-host network cut."""

    connector_empty = _kill_cgroup(CGROUP_SYSTEM_SLICE / "cloudflared.service")
    try:
        docker_groups = list(CGROUP_SYSTEM_SLICE.glob("docker-*.scope"))
    except OSError:
        docker_groups = []
    runtime_empty = bool(docker_groups) and all(
        _kill_cgroup(path) for path in docker_groups
    )
    if connector_empty and runtime_empty:
        return True
    return _activate_emergency_network_cut(runner)


def _clear_emergency_network_cut(runner: CommandRunner) -> None:
    """Atomically clear every exact known cut and prove both names absent."""

    states = _known_nft_cut_states(runner)
    if states is None:
        raise ReconcileError("emergency network-cut state is unavailable")
    if "unknown" in states.values():
        raise ReconcileError("refusing to clear an unrecognized emergency network cut")
    exact = [
        table
        for table in (EMERGENCY_NFT_TABLE, EMERGENCY_NFT_CANDIDATE)
        if states[table] == "exact"
    ]
    if not exact:
        return
    commands = "".join(f"delete table inet {table}\n" for table in exact)
    if not _run_nft_transaction(runner, commands.encode("ascii")):
        raise ReconcileError("emergency network cut was not removed")
    final = _known_nft_cut_states(runner)
    if final is None or any(state != "absent" for state in final.values()):
        raise ReconcileError("emergency network cut was not removed")


def _authoritative_docker_inventory(runner: CommandRunner) -> set[str]:
    result = runner.run(
        ["/usr/bin/docker", "container", "ls", "--all", "--no-trunc", "--format", "{{json .}}"],
        capture=True,
    )
    try:
        raw = result.stdout.decode("utf-8", errors="strict")
        lines = raw.splitlines()
        records = [json.loads(line) for line in lines]
    except (UnicodeError, json.JSONDecodeError):
        raise ReconcileError("Docker inventory is invalid") from None
    if result.stdout and not result.stdout.endswith(b"\n"):
        raise ReconcileError("Docker inventory is truncated")
    names: list[str] = []
    identifiers: list[str] = []
    states = {"created", "restarting", "running", "removing", "paused", "exited", "dead"}
    for record in records:
        if not isinstance(record, dict):
            raise ReconcileError("Docker inventory is invalid")
        name = record.get("Names")
        identifier = record.get("ID")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None
            or not isinstance(identifier, str)
            or re.fullmatch(r"[0-9a-f]{64}", identifier) is None
            or record.get("State") not in states
        ):
            raise ReconcileError("Docker inventory is invalid")
        names.append(name)
        identifiers.append(identifier)
    if len(names) != len(set(names)) or len(identifiers) != len(set(identifiers)):
        raise ReconcileError("Docker inventory is inconsistent")
    return set(names)


def _stop_ingress_and_containers(runner: CommandRunner) -> None:
    errors: list[str] = []
    requires_kernel_fallback = False
    try:
        READY_MARKER.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        errors.append("ready marker could not be removed")

    def attempt(
        arguments: Sequence[str], *, capture: bool = False
    ) -> tuple[subprocess.CompletedProcess[bytes], bool]:
        """Run one best-effort shutdown command without breaking the sequence."""

        try:
            return (
                runner.run(
                    arguments,
                    check=False,
                    capture=capture,
                ),
                False,
            )
        except (OSError, ReconcileError):
            return (
                subprocess.CompletedProcess(
                    list(arguments), 127, stdout=b"", stderr=b""
                ),
                True,
            )

    # Never let an introspection failure skip the actual shutdown attempts. A
    # failed stop is followed by a hard unit kill, Docker is always stopped, and
    # all unverifiable state is reported only after those fail-closed actions.
    load_state, load_state_error = attempt(
        [
            "/usr/bin/systemctl",
            "show",
            "cloudflared.service",
            "--property=LoadState",
            "--value",
        ],
        capture=True,
    )
    load_state_value = ""
    if not load_state_error and load_state.returncode == 0:
        try:
            load_state_value = load_state.stdout.decode(
                "ascii", errors="strict"
            ).strip()
        except UnicodeDecodeError:
            errors.append("cloudflared unit state is invalid")
        if load_state_value not in {"not-found", "loaded", "masked"}:
            errors.append("cloudflared unit state is unsafe")
    else:
        errors.append("cloudflared unit state cannot be verified")

    stop_result, stop_error = attempt(
        ["/usr/bin/systemctl", "stop", "cloudflared.service"]
    )
    disable_result, disable_error = attempt(
        ["/usr/bin/systemctl", "disable", "cloudflared.service"]
    )

    def active_status() -> tuple[bool, bool]:
        state, state_error = attempt(
            [
                "/usr/bin/systemctl",
                "show",
                "cloudflared.service",
                "--property=ActiveState",
                "--value",
            ],
            capture=True,
        )
        active, active_error = attempt(
            [
                "/usr/bin/systemctl",
                "is-active",
                "--quiet",
                "cloudflared.service",
            ],
        )
        state_inactive = False
        state_value = ""
        if not state_error and state.returncode == 0:
            try:
                state_value = state.stdout.decode("ascii", errors="strict").strip()
                state_inactive = state_value in {"inactive", "failed"}
            except UnicodeDecodeError:
                pass
        absent_or_inactive = not active_error and active.returncode in {3, 4}
        safely_inactive = state_inactive and absent_or_inactive
        return safely_inactive, absent_or_inactive

    inactive, inactive_exit = active_status()
    if not inactive:
        _, kill_error = attempt(
            [
                "/usr/bin/systemctl",
                "kill",
                "--kill-who=all",
                "--signal=SIGKILL",
                "cloudflared.service",
            ],
        )
        if kill_error:
            errors.append("cloudflared hard stop failed")
        inactive, inactive_exit = active_status()

    verified_absent = load_state_value == "not-found" and inactive_exit
    if (stop_error or stop_result.returncode != 0) and not verified_absent:
        errors.append("cloudflared stop failed")
    if (disable_error or disable_result.returncode != 0) and not verified_absent:
        errors.append("cloudflared disable failed")
    if not inactive:
        errors.append("cloudflared ingress did not stop")
        requires_kernel_fallback = True

    existing: list[str] = []
    inventory, inventory_error = attempt(
        ["/usr/bin/docker", "container", "ls", "--all", "--no-trunc", "--format", "{{json .}}"],
        capture=True,
    )
    live_restore, live_restore_error = attempt(
        ["/usr/bin/docker", "info", "--format", "{{json .LiveRestoreEnabled}}"],
        capture=True,
    )
    inventory_names: set[str] | None = None
    if not inventory_error and inventory.returncode == 0:
        try:
            lines = inventory.stdout.decode("utf-8", errors="strict").splitlines()
            records = [json.loads(line) for line in lines]
        except (UnicodeError, json.JSONDecodeError):
            lines = []
            records = []
            errors.append("Docker inventory is invalid")
            requires_kernel_fallback = True
        names: list[str] = []
        ids: list[str] = []
        valid_states = {"created", "restarting", "running", "removing", "paused", "exited", "dead"}
        for record in records:
            if not isinstance(record, dict):
                names.append("")
                ids.append("")
                continue
            names.append(str(record.get("Names", "")))
            ids.append(str(record.get("ID", "")))
        if (
            (inventory.stdout and not inventory.stdout.endswith(b"\n"))
            or len(lines) != len(records)
            or len(names) != len(set(names))
            or len(ids) != len(set(ids))
            or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None for name in names)
            or any(re.fullmatch(r"[0-9a-f]{64}", identifier) is None for identifier in ids)
            or any(not isinstance(record, dict) or record.get("State") not in valid_states for record in records)
        ):
            errors.append("Docker inventory is invalid")
            requires_kernel_fallback = True
        else:
            inventory_names = set(names)
    else:
        errors.append("Docker inventory is unavailable")
        requires_kernel_fallback = True
    if live_restore_error or live_restore.returncode != 0:
        errors.append("Docker live-restore state is unavailable")
        requires_kernel_fallback = True
    else:
        value = live_restore.stdout.decode("ascii", errors="ignore").strip()
        if value not in {"true", "false"}:
            errors.append("Docker live-restore state is invalid")
            requires_kernel_fallback = True
        elif value == "true":
            errors.append("Docker live-restore requires kernel isolation")
            requires_kernel_fallback = True
    if inventory_names is not None:
        existing = [name for name in KNOWN_CONTAINERS if name in inventory_names]
    if existing:
        stopped, stop_containers_error = attempt(
            ["/usr/bin/docker", "stop", "--time", "30", *existing]
        )
        if stop_containers_error or stopped.returncode != 0:
            errors.append("runtime container stop failed")
        for name in existing:
            result, verify_error = attempt(
                [
                    "/usr/bin/docker",
                    "inspect",
                    name,
                    "--format",
                    "{{.State.Running}}",
                ],
                capture=True,
            )
            try:
                stopped_value = result.stdout.decode("ascii", errors="strict").strip()
            except UnicodeDecodeError:
                stopped_value = ""
            if verify_error or result.returncode != 0 or stopped_value != "false":
                errors.append("a runtime container did not stop")
                requires_kernel_fallback = True
    if requires_kernel_fallback:
        try:
            fallback_verified = _kernel_fail_closed(runner)
        except (OSError, ReconcileError):
            fallback_verified = False
        if not fallback_verified:
            errors.append("kernel fail-closed fallback could not be verified")
    if errors:
        raise ReconcileError(
            "runtime shutdown could not be verified fail-closed: " + "; ".join(errors)
        )


def _release_secret_mode(release: Path, project_root: Path) -> str:
    metadata = project_root.lstat()
    content = _regular_file_bytes(
        release / "secret-mode",
        expected_uid=metadata.st_uid,
        expected_gid=metadata.st_gid,
        expected_mode=0o400,
        maximum_size=16,
    )
    if content == b"staging\n":
        return "staging"
    if content == b"vault\n":
        return "vault"
    raise ReconcileError("selected release secret mode is invalid")


def _owned_mode_directory(path: Path, uid: int, gid: int, mode: int) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and (metadata.st_uid, metadata.st_gid) == (uid, gid)
        and stat.S_IMODE(metadata.st_mode) == mode
    )


def _runtime_secret_file_specs(
    expected_uid: int, expected_gid: int, *, vault: bool
) -> dict[str, tuple[int, int, int]]:
    """Return the complete runtime-consumed secret-file contract.

    Production uses fixed container group IDs. Test-root mode cannot chown to
    those groups, so a non-root owner deliberately collapses the group IDs to
    the owning test group without changing the file/mode/content checks.
    """

    def group(container_gid: int) -> int:
        return container_gid if expected_uid == 0 else expected_gid

    root_mode = 0o400 if vault else 0o600
    return {
        "api.env": (expected_uid, group(65532), 0o440),
        "postgres.env": (expected_uid, expected_gid, root_mode),
        "redis.env": (expected_uid, expected_gid, root_mode),
        "nats.env": (expected_uid, expected_gid, root_mode),
        "grafana.env": (expected_uid, expected_gid, root_mode),
        "backup.env": (expected_uid, expected_gid, root_mode),
        "migrate.env": (expected_uid, group(65532), 0o440),
        "postgres.password": (expected_uid, group(70), 0o440),
        "postgres.pgpass": (expected_uid, expected_gid, 0o400),
        "redis.password": (expected_uid, group(1000), 0o440),
        "redis.acl": (expected_uid, group(1000), 0o440),
        "nats.conf": (expected_uid, group(1000), 0o440),
        "grafana.ini": (expected_uid, group(472), 0o440),
        "metrics.token": (expected_uid, group(65534), 0o440),
    }


def _secret_artifact_record(
    root: Path,
    relative: str,
    expected: tuple[int, int, int],
) -> dict[str, Any]:
    uid, gid, mode = expected
    content = _regular_file_bytes(
        root / relative,
        expected_uid=uid,
        expected_gid=gid,
        expected_mode=mode,
        maximum_size=MAX_SECRET_ARTIFACT_BYTES,
    )
    return {
        "path": relative,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "uid": uid,
        "gid": gid,
        "mode": mode,
    }


def _staging_secret_artifact_specs(
    expected_uid: int, expected_gid: int, staging_root: Path
) -> dict[str, tuple[int, int, int]]:
    specs = _runtime_secret_file_specs(expected_uid, expected_gid, vault=False)
    # cloudflared consumes this file directly from the selected cohort.  Older
    # staging installs may not have captured a token yet, but once present it
    # must be inseparable from the integrity snapshot.
    cloudflare_token = staging_root / "cloudflare-token"
    try:
        cloudflare_token.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise ReconcileError("staging Cloudflare token is unavailable") from None
    else:
        specs["cloudflare-token"] = (expected_uid, expected_gid, 0o600)
    apns_gid = 65532 if expected_uid == 0 else expected_gid
    apns_root = staging_root / "apns"
    if not _owned_mode_directory(apns_root, expected_uid, apns_gid, 0o750):
        raise ReconcileError("staging APNs secret directory is unsafe")
    try:
        entries = list(apns_root.iterdir())
    except OSError:
        raise ReconcileError("staging APNs secret directory is unavailable") from None
    allowed = {"AuthKey.p8", "AuthKey-sandbox.p8"}
    for entry in entries:
        if entry.name not in allowed:
            raise ReconcileError("staging APNs secret directory has an unexpected entry")
        specs[f"apns/{entry.name}"] = (expected_uid, apns_gid, 0o440)
    return specs


def _build_staging_secret_manifest(
    release: Path, project_root: Path
) -> bytes:
    metadata = project_root.lstat()
    uid, gid = metadata.st_uid, metadata.st_gid
    if not _owned_mode_directory(STAGING_SECRET_ROOT, uid, gid, 0o700):
        raise ReconcileError("staging secret root is unsafe")
    specs = _staging_secret_artifact_specs(uid, gid, STAGING_SECRET_ROOT)
    artifacts = [
        _secret_artifact_record(STAGING_SECRET_ROOT, name, specs[name])
        for name in sorted(specs)
    ]
    document = {
        "schema": SECRET_INTEGRITY_SCHEMA,
        "mode": "staging",
        "release_cohort": release.name,
        "artifacts": artifacts,
    }
    return (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")


def _validate_staging_secret_manifest(
    release: Path, project_root: Path
) -> None:
    metadata = project_root.lstat()
    uid, gid = metadata.st_uid, metadata.st_gid
    manifest_content = _regular_file_bytes(
        release / STAGING_SECRET_MANIFEST,
        expected_uid=uid,
        expected_gid=gid,
        expected_mode=0o400,
        maximum_size=64 * 1024,
    )
    try:
        document = json.loads(
            manifest_content.decode("ascii"), object_pairs_hook=_strict_object
        )
    except (UnicodeError, json.JSONDecodeError):
        raise ReconcileError("staging secret integrity manifest is invalid") from None
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "mode",
        "release_cohort",
        "artifacts",
    }:
        raise ReconcileError("staging secret integrity manifest is invalid")
    if (
        document.get("schema") != SECRET_INTEGRITY_SCHEMA
        or isinstance(document.get("schema"), bool)
        or document.get("mode") != "staging"
        or document.get("release_cohort") != release.name
        or not isinstance(document.get("artifacts"), list)
    ):
        raise ReconcileError("staging secret integrity manifest is invalid")
    if not _owned_mode_directory(STAGING_SECRET_ROOT, uid, gid, 0o700):
        raise ReconcileError("staging secret root is unsafe")
    specs = _staging_secret_artifact_specs(uid, gid, STAGING_SECRET_ROOT)
    expected_names = sorted(specs)
    artifacts = document["artifacts"]
    if len(artifacts) != len(expected_names):
        raise ReconcileError("staging secret artifact inventory is incomplete")
    for expected_name, record in zip(expected_names, artifacts):
        if not isinstance(record, dict) or set(record) != {
            "path",
            "sha256",
            "size",
            "uid",
            "gid",
            "mode",
        }:
            raise ReconcileError("staging secret artifact record is invalid")
        uid_value, gid_value, mode_value = specs[expected_name]
        if (
            record.get("path") != expected_name
            or record.get("uid") != uid_value
            or record.get("gid") != gid_value
            or record.get("mode") != mode_value
            or isinstance(record.get("size"), bool)
            or not isinstance(record.get("size"), int)
            or int(record["size"]) <= 0
            or int(record["size"]) > MAX_SECRET_ARTIFACT_BYTES
            or not isinstance(record.get("sha256"), str)
            or SHA256_RE.fullmatch(str(record["sha256"])) is None
        ):
            raise ReconcileError("staging secret artifact record is invalid")
        actual = _secret_artifact_record(
            STAGING_SECRET_ROOT, expected_name, specs[expected_name]
        )
        if actual != record:
            raise ReconcileError("staging secret artifact content changed")


def snapshot_staging_secret_manifest(release: Path, project_root: Path) -> None:
    """Bind a staging release to hashes of its complete consumed secret cohort."""

    release_root = _release_root(project_root)
    pending = release.parent == release_root / "pending"
    _validate_release_path(release, release_root, pending=pending)
    if _release_secret_mode(release, project_root) != "staging":
        raise ReconcileError("only a staging release may snapshot staging secrets")
    path = release / STAGING_SECRET_MANIFEST
    if path.exists() or path.is_symlink():
        _validate_staging_secret_manifest(release, project_root)
        return
    _atomic_write(path, _build_staging_secret_manifest(release, project_root), 0o400)
    _validate_staging_secret_manifest(release, project_root)


def _validate_legacy_boot_secret_cohort(
    release: Path, project_root: Path
) -> None:
    metadata = project_root.lstat()
    uid, gid = metadata.st_uid, metadata.st_gid
    boot_root = release / "boot-secrets"
    if not _owned_mode_directory(boot_root, uid, gid, 0o700):
        raise ReconcileError("legacy boot-secret directory is unsafe")
    file_modes = {
        "hydrate-vault-secrets.py": 0o500,
        "prepare-runtime-secrets.sh": 0o500,
    }
    try:
        actual = {entry.name for entry in boot_root.iterdir()}
    except OSError:
        raise ReconcileError("legacy boot-secret directory is unavailable") from None
    if actual != set(file_modes) | {"SHA256SUMS"}:
        raise ReconcileError("legacy boot-secret inventory is invalid")
    lines: list[str] = []
    for name in sorted(file_modes):
        content = _regular_file_bytes(
            boot_root / name,
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=file_modes[name],
            maximum_size=MAX_SECRET_ARTIFACT_BYTES,
        )
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
    checksums = _regular_file_bytes(
        boot_root / "SHA256SUMS",
        expected_uid=uid,
        expected_gid=gid,
        expected_mode=0o400,
        maximum_size=4096,
    )
    if checksums != "".join(lines).encode("ascii"):
        raise ReconcileError("legacy boot-secret checksum manifest is invalid")


def _establish_legacy_staging_boot_cohort(
    release: Path,
    project_root: Path,
    boot_files: Mapping[str, bytes],
) -> None:
    """Crash-safely extend a raw legacy release with release-local boot tools."""

    metadata = project_root.lstat()
    uid, gid = metadata.st_uid, metadata.st_gid
    mode_path = release / "secret-mode"
    boot_root = release / "boot-secrets"
    mode_exists = mode_path.exists() or mode_path.is_symlink()
    boot_exists = boot_root.exists() or boot_root.is_symlink()
    for forbidden in ("vault-secrets.map", "vault-approved-cohort.json"):
        path = release / forbidden
        if path.exists() or path.is_symlink():
            raise ReconcileError("legacy staging release contains Vault metadata")
    if mode_exists:
        if _release_secret_mode(release, project_root) != "staging":
            raise ReconcileError(
                "legacy baseline transition is allowed only in staging"
            )
        if not boot_exists:
            raise ReconcileError("legacy release boot-secret cohort is incomplete")
        _validate_legacy_boot_secret_cohort(release, project_root)
        return
    if boot_exists:
        # This is the only permitted partial state: a crash after the complete
        # boot directory rename but before the mode marker publication.
        _validate_legacy_boot_secret_cohort(release, project_root)
    else:
        temporary = release / f".boot-secrets.{secrets.token_hex(8)}"
        temporary.mkdir(mode=0o700)
        try:
            lines: list[str] = []
            for name in (
                "hydrate-vault-secrets.py",
                "prepare-runtime-secrets.sh",
            ):
                source_content = boot_files.get(name)
                if (
                    not isinstance(source_content, bytes)
                    or not source_content
                    or len(source_content) > MAX_SECRET_ARTIFACT_BYTES
                ):
                    raise ReconcileError(
                        "legacy Git boot-secret source is incomplete"
                    )
                _atomic_write(temporary / name, source_content, 0o500)
                lines.append(
                    f"{hashlib.sha256(source_content).hexdigest()}  {name}\n"
                )
            _atomic_write(
                temporary / "SHA256SUMS",
                "".join(sorted(lines)).encode("ascii"),
                0o400,
            )
            _fsync(temporary)
            os.replace(temporary, boot_root)
            _fsync(release)
        finally:
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary, ignore_errors=True)
    _validate_legacy_boot_secret_cohort(release, project_root)
    _atomic_write(mode_path, b"staging\n", 0o400)
    _fsync(release)
    if _release_secret_mode(release, project_root) != "staging":
        raise ReconcileError("legacy staging mode publication failed")


def _staging_secret_selection_matches(
    release: Path, project_root: Path
) -> bool:
    metadata = project_root.lstat()
    for forbidden in ("vault-secrets.map", "vault-approved-cohort.json"):
        path = release / forbidden
        if path.exists() or path.is_symlink():
            return False
    if not _owned_mode_directory(
        RUNTIME_SECRET_ROOT, metadata.st_uid, metadata.st_gid, 0o700
    ) or not _owned_mode_directory(
        STAGING_SECRET_ROOT, metadata.st_uid, metadata.st_gid, 0o700
    ):
        return False
    active = RUNTIME_SECRET_ROOT / "active"
    try:
        active_metadata = active.lstat()
        target = os.readlink(active)
    except OSError:
        return False
    selected = (
        stat.S_ISLNK(active_metadata.st_mode)
        and (active_metadata.st_uid, active_metadata.st_gid)
        == (metadata.st_uid, metadata.st_gid)
        and target == str(STAGING_SECRET_ROOT)
    )
    if not selected:
        return False
    try:
        _validate_staging_secret_manifest(release, project_root)
    except ReconcileError:
        return False
    return True


def _vault_marker_matches_release(release: Path, project_root: Path) -> bool:
    metadata = project_root.lstat()
    uid, gid = metadata.st_uid, metadata.st_gid
    if not _owned_mode_directory(RUNTIME_SECRET_ROOT, uid, gid, 0o700):
        return False
    active = RUNTIME_SECRET_ROOT / "active"
    try:
        active_metadata = active.lstat()
        active_target = os.readlink(active)
    except OSError:
        return False
    if (
        not stat.S_ISLNK(active_metadata.st_mode)
        or (active_metadata.st_uid, active_metadata.st_gid) != (uid, gid)
        or re.fullmatch(r"vault-generations/gen-[0-9]+-[a-f0-9]{16}", active_target)
        is None
    ):
        return False
    generation_root = RUNTIME_SECRET_ROOT / "vault-generations"
    if not _owned_mode_directory(generation_root, uid, gid, 0o700):
        return False
    generation = RUNTIME_SECRET_ROOT / active_target
    if not _owned_mode_directory(generation, uid, gid, 0o700):
        return False
    try:
        mapping = _regular_file_bytes(
            release / "vault-secrets.map",
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=0o400,
            maximum_size=64 * 1024,
        )
        manifest_content = _regular_file_bytes(
            release / "vault-approved-cohort.json",
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=0o400,
            maximum_size=64 * 1024,
        )
        marker_content = _regular_file_bytes(
            generation / ".vault-hydrated",
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=0o400,
            maximum_size=1024,
        )
        manifest = json.loads(
            manifest_content.decode("ascii"), object_pairs_hook=_strict_object
        )
        marker_lines = marker_content.decode("ascii").splitlines()
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ReconcileError,
    ):
        return False
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "release_cohort",
        "mapping_sha256",
        "cohort_sha256",
        "artifacts",
    }:
        return False
    if (
        manifest.get("schema") != 1
        or isinstance(manifest.get("schema"), bool)
        or manifest.get("release_cohort") != release.name
        or manifest.get("mapping_sha256") != hashlib.sha256(mapping).hexdigest()
        or not isinstance(manifest.get("cohort_sha256"), str)
        or re.fullmatch(r"[a-f0-9]{64}", str(manifest.get("cohort_sha256")))
        is None
    ):
        return False
    marker: dict[str, str] = {}
    for line in marker_lines:
        if line.count("=") != 1:
            return False
        key, value = line.split("=", 1)
        if not key or not value or key in marker:
            return False
        marker[key] = value
    return marker == {
        "schema": "2",
        "release_cohort": release.name,
        "mapping_sha256": hashlib.sha256(mapping).hexdigest(),
        "cohort_sha256": str(manifest["cohort_sha256"]),
    }


def _secret_selection_matches_release(
    release: Path, project_root: Path, runner: CommandRunner
) -> bool:
    try:
        mode = _release_secret_mode(release, project_root)
        if mode == "staging":
            return _staging_secret_selection_matches(release, project_root)
        if not _vault_marker_matches_release(release, project_root):
            return False
        hydrator = release / "boot-secrets" / "hydrate-vault-secrets.py"
        verification = runner.run(
            [
                "/usr/bin/python3",
                str(hydrator),
                "--verify-candidate-manifest",
                str(release / "vault-approved-cohort.json"),
                "--release-cohort",
                release.name,
            ],
            check=False,
        )
        return verification.returncode == 0
    except (OSError, UnicodeError, ReconcileError):
        return False


def _prepare_current_secrets(
    release: Path, project_root: Path, runner: CommandRunner
) -> None:
    # The boot secret unit may already have prepared the exact current cohort.
    # Verify that local, non-network state first so a healthy boot/watchdog does
    # not make a second complete OCI Vault request set.
    if _secret_selection_matches_release(release, project_root, runner):
        return
    worker = release / "boot-secrets" / "prepare-runtime-secrets.sh"
    runner.run(["/bin/sh", str(worker), str(release)])
    if _resolve_current(project_root) != release:
        raise ReconcileError("current release changed while restoring secrets")
    if not _secret_selection_matches_release(release, project_root, runner):
        raise ReconcileError("selected release secret cohort was not restored exactly")


def _restore_source(release: Path, project_root: Path, runner: CommandRunner) -> None:
    source = release / runtime_bundle.BUNDLE_DIRECTORY / "source"
    target = project_root / "repo"
    target.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or not target.is_dir():
        raise ReconcileError("active source root is unsafe")
    runner.run(
        [
            "/usr/bin/rsync",
            "-a",
            "--delete",
            f"{source}/",
            f"{target}/",
        ]
    )


def _restore_tls_generation(
    release: Path,
    artifact_sources: Mapping[str, Path],
    service: str,
    files: Sequence[tuple[str, int, int, int]],
    project_root: Path,
) -> None:
    service_root = project_root / "runtime" / service
    service_root.mkdir(parents=True, exist_ok=True)
    generation = service_root / f"reconciled-{release.name}"
    if generation.exists() or generation.is_symlink():
        if generation.is_symlink() or not generation.is_dir():
            raise ReconcileError("reconciled PKI generation is unsafe")
        exact = True
        for name, uid, gid, mode in files:
            target = generation / name
            try:
                metadata = target.lstat()
                exact = exact and stat.S_ISREG(metadata.st_mode)
                exact = exact and not stat.S_ISLNK(metadata.st_mode)
                exact = exact and (metadata.st_uid, metadata.st_gid) == (uid, gid)
                exact = exact and stat.S_IMODE(metadata.st_mode) == mode
                exact = exact and target.read_bytes() == artifact_sources[
                    f"runtime/{service}/{name}"
                ].read_bytes()
            except OSError:
                exact = False
        if not exact:
            quarantine = service_root / (
                f".{generation.name}.drifted-{time.time_ns()}-{os.getpid()}"
            )
            os.replace(generation, quarantine)
            _fsync(service_root)
    if not generation.exists():
        staged = service_root / f".reconciled-{release.name}.{os.getpid()}"
        staged.mkdir(mode=0o700)
        try:
            for name, uid, gid, mode in files:
                _atomic_install(
                    artifact_sources[f"runtime/{service}/{name}"],
                    staged / name,
                    uid,
                    gid,
                    mode,
                )
            os.replace(staged, generation)
            _fsync(service_root)
        finally:
            try:
                staged.rmdir()
            except OSError:
                pass
    if generation.is_symlink() or not generation.is_dir():
        raise ReconcileError("reconciled PKI generation is unsafe")
    temporary = service_root / f".current.reconcile.{os.getpid()}"
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    os.symlink(generation.name, temporary)
    os.replace(temporary, service_root / "current")
    _fsync(service_root)


def _restore_runtime(release: Path, project_root: Path) -> None:
    bundle = release / runtime_bundle.BUNDLE_DIRECTORY
    sources = {
        artifact.bundle_path: source
        for artifact, source in runtime_bundle.runtime_artifact_sources(bundle)
    }
    tls_services = {"dependency-tls", "postgres-tls", "nats-tls"}
    for artifact in runtime_bundle.RUNTIME_ARTIFACTS:
        parts = Path(artifact.bundle_path).parts
        if len(parts) >= 3 and parts[1] in tls_services and parts[-1] != "haproxy.cfg":
            continue
        target = Path(artifact.target_path)
        if str(target).startswith("/srv/clixor/"):
            target = project_root / target.relative_to("/srv/clixor")
        _atomic_install(
            sources[artifact.bundle_path],
            target,
            artifact.uid,
            artifact.gid,
            artifact.mode,
        )
    _restore_tls_generation(
        release,
        sources,
        "dependency-tls",
        (("server.pem", 0, 99, 0o440),),
        project_root,
    )
    _restore_tls_generation(
        release,
        sources,
        "postgres-tls",
        (("server.key", 0, 70, 0o440), ("server.crt", 0, 70, 0o440)),
        project_root,
    )
    _restore_tls_generation(
        release,
        sources,
        "nats-tls",
        (("server.key", 0, 1000, 0o440), ("server.crt", 0, 1000, 0o440)),
        project_root,
    )


def _restore_host_tools(release: Path, runner: CommandRunner) -> None:
    root = release / runtime_bundle.BUNDLE_DIRECTORY / "host-tools"
    release_metadata = release.lstat()
    promotion_root = runtime_bundle.promotion_host_tools_root(
        release,
        expected_uid=release_metadata.st_uid,
        expected_gid=release_metadata.st_gid,
    )
    HOST_TOOL_ROOT.mkdir(parents=True, exist_ok=True)
    for tool in ("offsite-backup.sh", "backup-health.sh", "restore-drill.sh", "backup_manifest.py"):
        _atomic_install(root / "bin" / tool, HOST_TOOL_ROOT / tool, 0, 0, 0o500)
    _atomic_install(promotion_root / "bin" / "cloudflare-promote.py",
                    HOST_TOOL_ROOT / "cloudflare-promote.py", 0, 0, 0o555)
    _atomic_install(promotion_root / "bin" / "cloudflare-promote.py.sha256",
                    HOST_TOOL_ROOT / "cloudflare-promote.py.sha256", 0, 0, 0o444)
    _atomic_install(
        root / "bin" / "cloudflared", CLOUDFLARED_BINARY, 0, 0, 0o555
    )
    for unit in (
        "clixor-offsite-backup.service",
        "clixor-offsite-backup.timer",
        "clixor-backup-health.service",
        "clixor-backup-health.timer",
        "clixor-restore-drill.service",
        "clixor-restore-drill.timer",
        "cloudflared.service",
    ):
        _atomic_install(root / "systemd" / unit, SYSTEMD_ROOT / unit, 0, 0, 0o644)
    _atomic_install(promotion_root / "systemd" / "clixor-cloudflare-promote.service",
                    SYSTEMD_ROOT / "clixor-cloudflare-promote.service", 0, 0, 0o644)
    _atomic_install(promotion_root / "tmpfiles" / "clixor-cloudflare-origin-gate.conf",
                    TMPFILES_ROOT / "clixor-cloudflare-origin-gate.conf", 0, 0, 0o644)
    runner.run(["/usr/bin/systemd-tmpfiles", "--create",
                str(TMPFILES_ROOT / "clixor-cloudflare-origin-gate.conf")])
    runner.run(["/usr/bin/systemctl", "daemon-reload"])


def _set_service_selection(manifest: Mapping[str, Any], runner: CommandRunner) -> None:
    state = manifest["state"]
    assert isinstance(state, dict)
    cloudflared = state["cloudflared"]
    timers = state["timers"]
    assert isinstance(cloudflared, dict) and isinstance(timers, dict)
    cloud_action = "enable" if cloudflared["enabled"] else "disable"
    runner.run(["/usr/bin/systemctl", cloud_action, "cloudflared.service"])
    for timer, enabled in timers.items():
        action = "enable" if enabled else "disable"
        runner.run(["/usr/bin/systemctl", action, str(timer)])


def _validate_image(manifest: Mapping[str, Any], runner: CommandRunner) -> tuple[str, str]:
    image = manifest["image"]
    assert isinstance(image, dict)
    image_ref = str(image["ref"])
    expected_id = str(image["id"])
    result = runner.run(
        ["/usr/bin/docker", "image", "inspect", image_ref, "--format", "{{.Id}}"],
        capture=True,
    )
    actual_id = result.stdout.decode("ascii", errors="strict").strip()
    if actual_id != expected_id:
        raise ReconcileError("selected release image ID is unavailable or changed")
    return image_ref, expected_id


def _compose_up(
    release: Path,
    manifest: Mapping[str, Any],
    image_ref: str,
    runner: CommandRunner,
) -> None:
    compose = release / runtime_bundle.BUNDLE_DIRECTORY / "compose.yaml"
    tag = image_ref.split(":", 1)[1]
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LC_ALL": "C",
        "CLIXOR_IMAGE_TAG": tag,
    }
    base = ["/usr/bin/docker", "compose", "--file", str(compose)]
    runner.run([*base, "config", "--quiet"], environment=environment)
    runner.run(
        [*base, "up", "-d", "--no-build", "--force-recreate", "--remove-orphans"],
        environment=environment,
    )
    state = manifest["state"]
    assert isinstance(state, dict)
    observability = state["observability"]
    assert isinstance(observability, dict)
    selected = [name for name, active in observability.items() if active]
    if selected:
        runner.run(
            [
                *base,
                "--profile",
                "observability",
                "up",
                "-d",
                "--no-build",
                "--force-recreate",
                *selected,
            ],
            environment=environment,
        )
    for name, active in observability.items():
        if active:
            continue
        container = f"clixor-oci-{name}"
        if container in _authoritative_docker_inventory(runner):
            # The data bind mount is retained. Removing only the stopped
            # immutable container prevents a retired restart policy or config
            # from becoming an alternate boot authority.
            runner.run(["/usr/bin/docker", "rm", container])


def _wait_ready(
    source_sha: str,
    expected_image_id: str,
    runner: CommandRunner,
    *,
    host_probe: bool = True,
) -> None:
    for container in ("clixor-oci-api-a", "clixor-oci-api-b"):
        result = runner.run(
            ["/usr/bin/docker", "inspect", container, "--format", "{{.Image}}"],
            capture=True,
        )
        if result.stdout.decode("ascii", errors="strict").strip() != expected_image_id:
            raise ReconcileError("API container does not use the selected image ID")
    deadline = time.monotonic() + 180
    while True:
        replicas_ready = True
        for replica in ("api-a", "api-b"):
            probe = runner.run(
                [
                    "/usr/bin/docker",
                    "exec",
                    "clixor-oci-api-gateway",
                    "wget",
                    "--quiet",
                    "--output-document=-",
                    f"http://{replica}:8080/health/ready",
                ],
                check=False,
                capture=True,
            )
            try:
                document = json.loads(probe.stdout)
            except (UnicodeError, json.JSONDecodeError):
                document = None
            if probe.returncode != 0 or document != {
                "status": "ready",
                "revision": source_sha,
            }:
                replicas_ready = False
        if replicas_ready and not host_probe:
            return
        try:
            request = urllib.request.Request(
                "http://172.30.254.2:8080/health/ready",
                headers={"Cache-Control": "no-cache"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read(64 * 1024 + 1)
                revision = response.headers.get("X-Clixor-Revision")
                document = json.loads(raw)
            if (
                len(raw) <= 64 * 1024
                and replicas_ready
                and revision == source_sha
                and document == {"status": "ready", "revision": source_sha}
            ):
                return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            pass
        if time.monotonic() >= deadline:
            raise ReconcileError("selected release did not pass exact local readiness")
        time.sleep(2)


def _publish_ready_marker(release: Path) -> None:
    READY_MARKER.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _atomic_write(READY_MARKER, (str(release) + "\n").encode("ascii"), 0o600)


def _boot_bundle_validate(release: Path, runner: CommandRunner) -> None:
    stable_launcher = Path(
        "/usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py"
    )
    runner.run(
        [
            "/usr/bin/python3",
            str(stable_launcher),
            "--verify-release-bundle",
            str(release),
        ]
    )


def _connector_credential_controller(release: Path) -> Path | None:
    bundle = release / runtime_bundle.BUNDLE_DIRECTORY
    helper = bundle / "host-tools" / "bin" / "cloudflare-canary-credential.py"
    if helper.is_file() and not helper.is_symlink():
        return helper
    # Historical schema-2 releases used the complete selected secret cohort
    # directly. They remain rollback-compatible; a release using the new
    # unified path without its controller is never accepted.
    unit = bundle / "host-tools" / "systemd" / "cloudflared.service"
    try:
        unit_text = unit.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        # The runtime bundle validator is the authority. This compatibility
        # branch is also exercised by controller unit tests that replace that
        # validator with an already-reviewed manifest fixture.
        return None
    if "/run/clixor/cloudflare-connector/" in unit_text:
        raise ReconcileError("selected release connector credential controller is missing")
    return None


def _prepare_connector_credential(
    release: Path, project_root: Path, runner: CommandRunner
) -> None:
    helper = _connector_credential_controller(release)
    if helper is None:
        return
    runner.run(
        [
            "/usr/bin/python3", str(helper), "prepare",
            "--release", str(release), "--project-root", str(project_root),
        ]
    )


def _connector_credential_matches(
    release: Path, project_root: Path, runner: CommandRunner
) -> bool:
    del project_root
    try:
        helper = _connector_credential_controller(release)
    except ReconcileError:
        return False
    if helper is None:
        return True
    verified = runner.run(
        ["/usr/bin/python3", str(helper), "verify", "--release", str(release)],
        check=False,
    )
    if verified.returncode != 0:
        return False
    canary_metadata = (
        release / runtime_bundle.BUNDLE_DIRECTORY
        / runtime_bundle.CANARY_CONNECTOR_METADATA
    )
    if canary_metadata.is_file() and not canary_metadata.is_symlink():
        return runner.run(
            [
                "/usr/bin/python3", str(helper), "verify-remote",
                "--release", str(release),
            ],
            check=False,
        ).returncode == 0
    return True


def _verify_started_connector(
    release: Path, project_root: Path, runner: CommandRunner
) -> None:
    """Synchronously bind a started connector to the selected release.

    systemd ``--no-block`` only queues the start.  It is not evidence that the
    connector consumed the exact reviewed remote configuration, so wait for
    the unit and then run both the local credential and canary configuration
    authorities before returning from a repair.
    """

    helper = _connector_credential_controller(release)
    if helper is None:
        return
    for attempt in range(45):
        active = runner.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", "cloudflared.service"],
            check=False,
        )
        if active.returncode == 0:
            break
        if attempt + 1 == 45:
            raise ReconcileError("selected cloudflared service did not become active")
        time.sleep(2)
    verified = runner.run(
        ["/usr/bin/python3", str(helper), "verify", "--release", str(release)],
        check=False,
    )
    if verified.returncode != 0:
        raise ReconcileError("selected cloudflared credential did not verify")
    canary_metadata = (
        release
        / runtime_bundle.BUNDLE_DIRECTORY
        / runtime_bundle.CANARY_CONNECTOR_METADATA
    )
    if canary_metadata.is_file() and not canary_metadata.is_symlink():
        remote = runner.run(
            [
                "/usr/bin/python3",
                str(helper),
                "verify-remote",
                "--release",
                str(release),
            ],
            check=False,
        )
        if remote.returncode != 0:
            raise ReconcileError(
                "selected cloudflared remote configuration did not verify"
            )


def reconcile_current(
    project_root: Path,
    runner: CommandRunner,
    *,
    boot: bool,
    stop_first: bool = True,
) -> Path:
    # Validation failure is also a fail-closed event. Do not leave a mutable or
    # unvalidated runtime exposed merely because current itself is corrupt.
    if stop_first:
        _stop_ingress_and_containers(runner)
    release = _resolve_current(project_root)
    if release is None:
        raise ReconcileError("no committed release is selected")
    manifest = _validate_bundle(release, project_root)
    _boot_bundle_validate(release, runner)
    image_ref, image_id = _validate_image(manifest, runner)
    # Secrets are part of the selected release boundary.  An interrupted
    # candidate may have switched the tmpfs pointer before releases/current;
    # restore and verify current's exact staging/Vault cohort before any
    # mutable runtime file or container is recreated.
    _prepare_current_secrets(release, project_root, runner)
    _prepare_connector_credential(release, project_root, runner)
    _restore_source(release, project_root, runner)
    _restore_runtime(release, project_root)
    _restore_host_tools(release, runner)
    _set_service_selection(manifest, runner)
    _compose_up(release, manifest, image_ref, runner)
    _wait_ready(str(manifest["source_sha"]), image_id, runner, host_probe=False)
    _clear_emergency_network_cut(runner)
    # The cut may have hidden a host-routing defect. Recheck the exact local
    # release immediately after reopening networking and before ingress starts.
    _wait_ready(str(manifest["source_sha"]), image_id, runner)
    _publish_ready_marker(release)
    state = manifest["state"]
    assert isinstance(state, dict)
    cloudflared = state["cloudflared"]
    timers = state["timers"]
    assert isinstance(cloudflared, dict) and isinstance(timers, dict)
    # --no-block avoids a boot-order cycle: cloudflared Requires this oneshot,
    # while still guaranteeing its condition marker exists before it can run.
    if cloudflared["active"]:
        try:
            runner.run(
                ["/usr/bin/systemctl", "start", "--no-block", "cloudflared.service"]
            )
            _verify_started_connector(release, project_root, runner)
        except (OSError, ReconcileError):
            # Do not let the watchdog report a repaired runtime after it has
            # reopened a connector with unknown authority.  The shared stop
            # primitive removes the readiness marker, disables ingress, and
            # stops the application before the error escapes.
            _stop_ingress_and_containers(runner)
            raise
    else:
        runner.run(["/usr/bin/systemctl", "stop", "cloudflared.service"])
    for timer, enabled in timers.items():
        arguments = ["/usr/bin/systemctl", "start" if enabled else "stop"]
        if enabled:
            arguments.append("--no-block")
        arguments.append(str(timer))
        runner.run(arguments)
    return release


def _runtime_matches_current(project_root: Path, runner: CommandRunner) -> bool:
    try:
        release = _resolve_current(project_root)
        if release is None:
            return False
        manifest = _validate_bundle(release, project_root)
        _boot_bundle_validate(release, runner)
        if READY_MARKER.read_text(encoding="ascii") != str(release) + "\n":
            return False
        if not _secret_selection_matches_release(release, project_root, runner):
            return False
        if not _connector_credential_matches(release, project_root, runner):
            return False
        bundle = release / runtime_bundle.BUNDLE_DIRECTORY

        def same_content(source: Path, target: Path) -> bool:
            try:
                target_metadata = target.lstat()
                if not stat.S_ISREG(target_metadata.st_mode) or stat.S_ISLNK(
                    target_metadata.st_mode
                ):
                    return False
                source_digest = hashlib.sha256(source.read_bytes()).digest()
                target_digest = hashlib.sha256(target.read_bytes()).digest()
                return source_digest == target_digest
            except OSError:
                return False

        # The mutable checkout is not boot authority. Detect any source drift so
        # the periodic watchdog restores it from the selected immutable bundle.
        source_root = bundle / "source"
        active_source = project_root / "repo"
        expected_source: set[str] = set()
        for directory, names, files in os.walk(source_root, followlinks=False):
            current = Path(directory)
            if any((current / name).is_symlink() for name in names):
                return False
            for name in files:
                source = current / name
                relative = source.relative_to(source_root).as_posix()
                expected_source.add(relative)
                if not same_content(source, active_source / relative):
                    return False
        actual_source: set[str] = set()
        for directory, names, files in os.walk(active_source, followlinks=False):
            current = Path(directory)
            if any((current / name).is_symlink() for name in names):
                return False
            for name in files:
                target = current / name
                if target.is_symlink():
                    return False
                actual_source.add(target.relative_to(active_source).as_posix())
        if actual_source != expected_source:
            return False

        for artifact, source in runtime_bundle.runtime_artifact_sources(bundle):
            target = Path(artifact.target_path)
            if str(target).startswith("/srv/clixor/"):
                target = project_root / target.relative_to("/srv/clixor")
            if not same_content(source, target):
                return False
            metadata = target.stat()
            if (
                (metadata.st_uid, metadata.st_gid) != (artifact.uid, artifact.gid)
                or stat.S_IMODE(metadata.st_mode) != artifact.mode
            ):
                return False

        host_root = bundle / "host-tools"
        project_metadata = project_root.lstat()
        promotion_root = runtime_bundle.promotion_host_tools_root(
            release,
            expected_uid=project_metadata.st_uid,
            expected_gid=project_metadata.st_gid,
        )
        if not same_content(host_root / "bin" / "cloudflared", CLOUDFLARED_BINARY):
            return False
        cloudflared_metadata = CLOUDFLARED_BINARY.stat()
        if (
            (cloudflared_metadata.st_uid, cloudflared_metadata.st_gid) != (0, 0)
            or stat.S_IMODE(cloudflared_metadata.st_mode) != 0o555
        ):
            return False
        for tool in (
            "offsite-backup.sh",
            "backup-health.sh",
            "restore-drill.sh",
            "backup_manifest.py",
        ):
            if not same_content(host_root / "bin" / tool, HOST_TOOL_ROOT / tool):
                return False
        for unit in (
            "clixor-offsite-backup.service",
            "clixor-offsite-backup.timer",
            "clixor-backup-health.service",
            "clixor-backup-health.timer",
            "clixor-restore-drill.service",
            "clixor-restore-drill.timer",
            "cloudflared.service",
        ):
            if not same_content(host_root / "systemd" / unit, SYSTEMD_ROOT / unit):
                return False
        for tool in ("cloudflare-promote.py", "cloudflare-promote.py.sha256"):
            if not same_content(promotion_root / "bin" / tool, HOST_TOOL_ROOT / tool):
                return False
        for path, mode in (
            (HOST_TOOL_ROOT / "cloudflare-promote.py", 0o555),
            (HOST_TOOL_ROOT / "cloudflare-promote.py.sha256", 0o444),
            (SYSTEMD_ROOT / "clixor-cloudflare-promote.service", 0o644),
            (TMPFILES_ROOT / "clixor-cloudflare-origin-gate.conf", 0o644),
        ):
            metadata = path.stat()
            if ((metadata.st_uid, metadata.st_gid) != (0, 0)
                    or stat.S_IMODE(metadata.st_mode) != mode):
                return False
        if not same_content(
            promotion_root / "systemd" / "clixor-cloudflare-promote.service",
            SYSTEMD_ROOT / "clixor-cloudflare-promote.service",
        ):
            return False
        if not same_content(
            promotion_root / "tmpfiles" / "clixor-cloudflare-origin-gate.conf",
            TMPFILES_ROOT / "clixor-cloudflare-origin-gate.conf",
        ):
            return False

        image = manifest["image"]
        assert isinstance(image, dict)
        expected = str(image["id"])
        for container in ("clixor-oci-api-a", "clixor-oci-api-b"):
            result = runner.run(
                [
                    "/usr/bin/docker",
                    "inspect",
                    container,
                    "--format",
                    "{{if .State.Running}}{{.Image}}{{end}}",
                ],
                capture=True,
            )
            if result.stdout.decode("ascii", errors="strict").strip() != expected:
                return False
        base_containers = KNOWN_CONTAINERS[:8]
        for container in base_containers:
            state = _command_value(
                runner,
                [
                    "/usr/bin/docker",
                    "inspect",
                    container,
                    "--format",
                    "{{.State.Running}}|{{.HostConfig.RestartPolicy.Name}}",
                ],
            )
            if state != "true|no":
                return False
        state = manifest["state"]
        assert isinstance(state, dict)
        cloudflared = state["cloudflared"]
        timers = state["timers"]
        observability = state["observability"]
        assert isinstance(cloudflared, dict)
        assert isinstance(timers, dict)
        assert isinstance(observability, dict)
        docker_inventory = _authoritative_docker_inventory(runner)
        cloud_enabled = runner.run(
            ["/usr/bin/systemctl", "is-enabled", "--quiet", "cloudflared.service"],
            check=False,
        ).returncode == 0
        cloud_active = runner.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", "cloudflared.service"],
            check=False,
        ).returncode == 0
        if cloud_enabled != cloudflared["enabled"] or cloud_active != cloudflared["active"]:
            return False
        for timer, expected_enabled in timers.items():
            enabled = runner.run(
                ["/usr/bin/systemctl", "is-enabled", "--quiet", str(timer)],
                check=False,
            ).returncode == 0
            active = runner.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", str(timer)],
                check=False,
            ).returncode == 0
            if enabled != expected_enabled or active != expected_enabled:
                return False
        for service, expected_active in observability.items():
            container = f"clixor-oci-{service}"
            result = runner.run(
                [
                    "/usr/bin/docker",
                    "inspect",
                    container,
                    "--format",
                    "{{.State.Running}}|{{.HostConfig.RestartPolicy.Name}}",
                ],
                check=False,
                capture=True,
            )
            if result.returncode != 0:
                if expected_active or container in docker_inventory:
                    return False
                continue
            expected_state = f"{'true' if expected_active else 'false'}|no"
            if result.stdout.decode("ascii", errors="strict").strip() != expected_state:
                return False
        return True
    except (OSError, UnicodeError, ReconcileError, runtime_bundle.BundleError):
        return False


def _archive_after_recovery(project_root: Path, current: Path | None) -> None:
    outcome = "recovered" if current is not None else "recovered-no-current"
    archive_journal(project_root, outcome)


def watchdog(project_root: Path, runner: CommandRunner) -> str:
    lock = project_root / "runtime" / "deploy.lock"
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    project_metadata = project_root.lstat()
    expected_uid, expected_gid = project_metadata.st_uid, project_metadata.st_gid
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid)
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ReconcileError("shared deploy lock metadata is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return "deploy-active"
        journal = _journal_path(project_root)
        if journal.exists() or journal.is_symlink():
            try:
                load_journal(project_root, require_candidate=False)
            except ReconcileError:
                _stop_ingress_and_containers(runner)
                raise
            current = _resolve_current(project_root)
            if current is None:
                _stop_ingress_and_containers(runner)
                _archive_after_recovery(project_root, None)
                return "recovered-no-current"
            reconcile_current(project_root, runner, boot=False)
            _archive_after_recovery(project_root, current)
            return "recovered"
        if not _runtime_matches_current(project_root, runner):
            reconcile_current(project_root, runner, boot=False)
            return "reconciled-drift"
        return "healthy"
    finally:
        os.close(descriptor)


def publish_pending_release(
    project_root: Path, candidate: Path, runner: CommandRunner
) -> Path:
    document = load_journal(project_root, require_candidate=True)
    if document["phase"] != "publishing" or document["candidate_release"] != str(candidate):
        raise ReconcileError("pending release publication does not match its journal")
    release_root = _release_root(project_root)
    _validate_release_path(candidate, release_root, pending=True)
    _validate_bundle(candidate, project_root)
    _boot_bundle_validate(candidate, runner)
    final = release_root / candidate.name
    if final.exists() or final.is_symlink():
        raise ReconcileError("final release destination already exists")
    os.replace(candidate, final)
    _fsync(release_root / "pending")
    _fsync(release_root)
    _validate_bundle(final, project_root)
    _boot_bundle_validate(final, runner)
    try:
        selected_marker = READY_MARKER.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise ReconcileError(
            "candidate ingress marker disappeared during publication"
        ) from None
    if selected_marker != str(candidate) + "\n":
        raise ReconcileError("candidate ingress marker does not select the publication")
    _publish_ready_marker(final)
    return final


def permit_candidate_ingress(
    project_root: Path, candidate: Path, runner: CommandRunner
) -> None:
    document = load_journal(project_root, require_candidate=True)
    if document["candidate_release"] != str(candidate):
        raise ReconcileError("candidate readiness does not match its journal")
    if PHASE_INDEX[str(document["phase"])] < PHASE_INDEX["migrated"]:
        raise ReconcileError("candidate cannot permit ingress before migration proof")
    _validate_bundle(candidate, project_root)
    image_ref, expected_image = _validate_image(
        _validate_bundle(candidate, project_root), runner
    )
    del image_ref
    for container in ("clixor-oci-api-a", "clixor-oci-api-b"):
        actual = _command_value(
            runner,
            ["/usr/bin/docker", "inspect", container, "--format", "{{.Image}}"],
        )
        if actual != expected_image:
            raise ReconcileError("candidate API does not use its bundled image")
    _publish_ready_marker(candidate)


def _command_value(runner: CommandRunner, arguments: Sequence[str]) -> str:
    completed = runner.run(arguments, capture=True)
    try:
        return completed.stdout.decode("ascii", errors="strict").strip()
    except UnicodeError:
        raise ReconcileError("host command returned invalid text") from None


def _legacy_git_arguments(git_directory: Path, *arguments: str) -> list[str]:
    return [
        "/usr/bin/git",
        "--no-replace-objects",
        f"--git-dir={git_directory}",
        *arguments,
    ]


def _legacy_git_environment() -> Mapping[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def _legacy_git_tree(
    project_root: Path,
    git_directory: Path,
    source_sha: str,
    runner: CommandRunner,
) -> str:
    metadata = project_root.lstat()
    _canonical_owned_directory(
        git_directory,
        expected_uid=metadata.st_uid,
        expected_gid=metadata.st_gid,
        exact_mode=0o700,
    )
    environment = _legacy_git_environment()
    runner.run(
        _legacy_git_arguments(
            git_directory, "cat-file", "-e", f"{source_sha}^{{commit}}"
        ),
        environment=environment,
    )
    runner.run(
        _legacy_git_arguments(
            git_directory, "fsck", "--full", "--strict", source_sha
        ),
        environment=environment,
    )
    completed = runner.run(
        _legacy_git_arguments(
            git_directory, "rev-parse", f"{source_sha}^{{tree}}"
        ),
        capture=True,
        environment=environment,
    )
    try:
        tree_sha = completed.stdout.decode("ascii", errors="strict").strip()
    except UnicodeError:
        raise ReconcileError("legacy Git tree identity is invalid") from None
    if runtime_bundle.SOURCE_SHA_RE.fullmatch(tree_sha) is None:
        raise ReconcileError("legacy Git tree identity is invalid")
    return tree_sha


def _verified_legacy_controller(controller_source: Path) -> Mapping[str, bytes]:
    """Authenticate every controller file consumed by the legacy transition."""

    consumed = {
        "deploy/oci/compose.yaml",
        "deploy/oci/hydrate-vault-secrets.py",
        "deploy/oci/prepare-runtime-secrets.sh",
        *(
            f"deploy/oci/{relative.split('/', 1)[1]}"
            for relative in runtime_bundle.HOST_TOOL_SOURCE_MODES
        ),
    }
    if set(LEGACY_CONTROLLER_FILES) != consumed:
        raise ReconcileError("legacy controller inventory is incomplete")
    result: dict[str, bytes] = {}
    for relative, expected_digest in LEGACY_CONTROLLER_FILES.items():
        content = _regular_file_bytes(
            controller_source / relative,
            expected_uid=controller_source.lstat().st_uid,
            expected_gid=controller_source.lstat().st_gid,
            expected_mode=stat.S_IMODE((controller_source / relative).lstat().st_mode),
            maximum_size=MAX_SECRET_ARTIFACT_BYTES,
        )
        if hashlib.sha256(content).hexdigest() != expected_digest:
            raise ReconcileError("legacy controller cohort digest is invalid")
        result[relative] = content
    return result


def _materialize_legacy_controller(
    project_root: Path, files: Mapping[str, bytes]
) -> Path:
    """Create a private immutable view; staging never rereads verified input."""

    root = Path(tempfile.mkdtemp(prefix=".legacy-controller.", dir=project_root / "runtime"))
    os.chmod(root, 0o700)
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target.parent, 0o700)
        _atomic_write(target, content, 0o500 if relative.endswith((".sh", ".py")) else 0o400)
    _fsync(root)
    return root


def _legacy_provenance_content(source_sha: str, tree_sha: str) -> bytes:
    return (
        json.dumps(
            {
                "schema": LEGACY_SOURCE_PROVENANCE_SCHEMA,
                "source_sha": source_sha,
                "tree_sha": tree_sha,
                "source_kind": "root-owned-git-archive",
                "controller_id": LEGACY_CONTROLLER_ID,
                "controller_kind": "installed-content-addressed-cohort",
                "controller_revision": LEGACY_CONTROLLER_REVISION,
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _validate_legacy_source_provenance(
    release: Path,
    project_root: Path,
    source_sha: str,
    tree_sha: str,
) -> None:
    metadata = project_root.lstat()
    content = _regular_file_bytes(
        release
        / runtime_bundle.BUNDLE_DIRECTORY
        / LEGACY_SOURCE_PROVENANCE,
        expected_uid=metadata.st_uid,
        expected_gid=metadata.st_gid,
        expected_mode=0o400,
        maximum_size=4096,
    )
    if content != _legacy_provenance_content(source_sha, tree_sha):
        raise ReconcileError("staged legacy source provenance is invalid")


def _stage_legacy_source_from_git(
    release: Path,
    project_root: Path,
    controller_source: Path,
    git_directory: Path,
    source_sha: str,
    tree_sha: str,
    runner: CommandRunner,
) -> None:
    runtime_root = project_root / "runtime"
    metadata = project_root.lstat()
    _canonical_owned_directory(
        runtime_root,
        expected_uid=metadata.st_uid,
        expected_gid=metadata.st_gid,
    )
    temporary = Path(
        tempfile.mkdtemp(prefix=".legacy-source.", dir=runtime_root)
    )
    os.chmod(temporary, 0o700)
    archive = temporary / "source.tar"
    source = temporary / "source"
    source.mkdir(mode=0o700)
    try:
        runner.run(
            _legacy_git_arguments(
                git_directory,
                "archive",
                "--format=tar",
                f"--output={archive}",
                source_sha,
            ),
            environment=_legacy_git_environment(),
        )
        try:
            archive_metadata = archive.lstat()
        except OSError:
            raise ReconcileError("legacy Git source archive is unavailable") from None
        if (
            not stat.S_ISREG(archive_metadata.st_mode)
            or stat.S_ISLNK(archive_metadata.st_mode)
            or (archive_metadata.st_uid, archive_metadata.st_gid)
            != (metadata.st_uid, metadata.st_gid)
            or archive_metadata.st_size <= 0
        ):
            raise ReconcileError("legacy Git source archive is unsafe")
        os.chmod(archive, 0o600)
        _fsync(archive)
        runner.run(
            [
                "/usr/bin/tar",
                "--extract",
                f"--file={archive}",
                f"--directory={source}",
                "--no-same-owner",
                "--no-same-permissions",
            ],
            environment={
                "PATH": "/usr/bin:/bin",
                "HOME": "/root",
                "LC_ALL": "C",
            },
        )
        runtime_bundle.stage_source(
            release,
            source,
            source_sha,
            compose_source=controller_source / "deploy" / "oci" / "compose.yaml",
        )
        _atomic_write(
            release
            / runtime_bundle.BUNDLE_DIRECTORY
            / LEGACY_SOURCE_PROVENANCE,
            _legacy_provenance_content(source_sha, tree_sha),
            0o400,
        )
        _validate_legacy_source_provenance(
            release, project_root, source_sha, tree_sha
        )
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def establish_legacy_baseline(
    project_root: Path,
    controller_source: Path,
    runner: CommandRunner,
    cloudflared_binary: Path = CLOUDFLARED_BINARY,
    legacy_git_directory: Path | None = None,
) -> Path:
    """Upgrade one existing staging release to the schema-2 runtime contract.

    This is an explicit, one-time operator transition.  It never changes the
    current pointer or database files.  If the live image/source/PKI cannot form
    one complete exact baseline, it fails before installing the new boot
    reconciler.
    """

    journal = _journal_path(project_root)
    if journal.exists() or journal.is_symlink():
        raise ReconcileError(
            "legacy baseline is forbidden while a deployment journal exists"
        )
    release = _resolve_current(project_root)
    if release is None:
        raise ReconcileError("legacy baseline requires an existing current release")
    committed_bundle = release / runtime_bundle.BUNDLE_DIRECTORY
    if committed_bundle.exists() or committed_bundle.is_symlink():
        if _release_secret_mode(release, project_root) != "staging":
            raise ReconcileError(
                "legacy baseline transition is allowed only in staging"
            )
        snapshot_staging_secret_manifest(release, project_root)
        _validate_bundle(release, project_root)
        return release
    image_ref = _command_value(
        runner,
        [
            "/usr/bin/docker",
            "inspect",
            "clixor-oci-api-a",
            "--format",
            "{{.Config.Image}}",
        ],
    )
    second_image = _command_value(
        runner,
        [
            "/usr/bin/docker",
            "inspect",
            "clixor-oci-api-b",
            "--format",
            "{{.Config.Image}}",
        ],
    )
    if image_ref != f"clixor-api:{release.name}" or second_image != image_ref:
        raise ReconcileError("legacy API replicas do not match the current release")
    image_id = _command_value(
        runner,
        ["/usr/bin/docker", "image", "inspect", image_ref, "--format", "{{.Id}}"],
    )
    source_sha = _command_value(
        runner,
        [
            "/usr/bin/docker",
            "image",
            "inspect",
            image_ref,
            "--format",
            '{{index .Config.Labels "org.opencontainers.image.revision"}}',
        ],
    )
    if (
        runtime_bundle.SOURCE_SHA_RE.fullmatch(source_sha) is None
        or source_sha[:12] != release.name[4:16]
    ):
        raise ReconcileError("legacy API image revision does not match current release")
    if legacy_git_directory is None:
        raise ReconcileError(
            "legacy baseline requires a root-owned Git object directory"
        )
    tree_sha = _legacy_git_tree(
        project_root, legacy_git_directory, source_sha, runner
    )
    controller_files = _verified_legacy_controller(controller_source)
    boot_files = {
        name: controller_files[f"deploy/oci/{name}"]
        for name in ("hydrate-vault-secrets.py", "prepare-runtime-secrets.sh")
    }
    # Only after the exact live image commit exists and passes Git object
    # validation may a raw legacy release gain the new boot-secret authority.
    _establish_legacy_staging_boot_cohort(
        release, project_root, boot_files
    )
    snapshot_staging_secret_manifest(release, project_root)
    pending_root = _release_root(project_root) / "pending"
    pending_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(pending_root, 0o700)
    staged_release = pending_root / release.name
    staged_manifest: Mapping[str, Any] | None = None
    if staged_release.exists() or staged_release.is_symlink():
        try:
            staged_manifest = _validate_bundle(staged_release, project_root)
            _validate_legacy_source_provenance(
                staged_release, project_root, source_sha, tree_sha
            )
        except (OSError, runtime_bundle.BundleError, ReconcileError):
            quarantine_pending_candidate(project_root, staged_release)
            staged_manifest = None
    if not staged_release.exists():
        staged_release.mkdir(mode=0o700)
    if staged_manifest is not None:
        staged_image = staged_manifest["image"]
        if (
            staged_manifest["source_sha"] != source_sha
            or not isinstance(staged_image, dict)
            or staged_image.get("ref") != image_ref
            or staged_image.get("id") != image_id
        ):
            quarantine_pending_candidate(project_root, staged_release)
            staged_release.mkdir(mode=0o700)
            staged_manifest = None
        else:
            os.replace(
                staged_release / runtime_bundle.BUNDLE_DIRECTORY,
                committed_bundle,
            )
            _fsync(release)
            _fsync(_release_root(project_root))
            _validate_bundle(release, project_root)
            return release
    if not (staged_release / runtime_bundle.BUNDLE_DIRECTORY).exists():
        immutable_controller = _materialize_legacy_controller(
            project_root, controller_files
        )
        try:
            _stage_legacy_source_from_git(
                staged_release,
                project_root,
                immutable_controller,
                legacy_git_directory,
                source_sha,
                tree_sha,
                runner,
            )
            runtime_bundle.stage_host_tools(
                staged_release, immutable_controller, cloudflared_binary
            )
        finally:
            shutil.rmtree(immutable_controller, ignore_errors=True)
    state_path = staged_release / ".baseline-runtime-state"

    def service_state(arguments: Sequence[str]) -> bool:
        return runner.run(arguments, check=False).returncode == 0

    lines = {
        "cloudflared_enabled": service_state(
            ["/usr/bin/systemctl", "is-enabled", "--quiet", "cloudflared.service"]
        ),
        "cloudflared_active": service_state(
            ["/usr/bin/systemctl", "is-active", "--quiet", "cloudflared.service"]
        ),
        "prometheus_active": service_state(
            [
                "/usr/bin/docker",
                "inspect",
                "clixor-oci-prometheus",
                "--format",
                "{{.State.Running}}",
            ]
        ),
        "grafana_active": service_state(
            [
                "/usr/bin/docker",
                "inspect",
                "clixor-oci-grafana",
                "--format",
                "{{.State.Running}}",
            ]
        ),
        "offsite_timer_enabled": service_state(
            [
                "/usr/bin/systemctl",
                "is-enabled",
                "--quiet",
                "clixor-offsite-backup.timer",
            ]
        ),
        "restore_timer_enabled": service_state(
            [
                "/usr/bin/systemctl",
                "is-enabled",
                "--quiet",
                "clixor-restore-drill.timer",
            ]
        ),
        "health_timer_enabled": service_state(
            [
                "/usr/bin/systemctl",
                "is-enabled",
                "--quiet",
                "clixor-backup-health.timer",
            ]
        ),
    }
    # Docker inspect returns success for stopped containers.  Resolve the actual
    # observability run state instead of treating mere existence as active.
    for key, container in (
        ("prometheus_active", "clixor-oci-prometheus"),
        ("grafana_active", "clixor-oci-grafana"),
    ):
        result = runner.run(
            [
                "/usr/bin/docker",
                "inspect",
                container,
                "--format",
                "{{.State.Running}}",
            ],
            check=False,
            capture=True,
        )
        lines[key] = (
            result.returncode == 0
            and result.stdout.decode("ascii", errors="ignore").strip() == "true"
        )
    _atomic_write(
        state_path,
        "".join(f"{key}={'true' if value else 'false'}\n" for key, value in lines.items()).encode(
            "ascii"
        ),
    )
    try:
        runtime_bundle.finalize_bundle(
            staged_release,
            project_root / "runtime",
            project_root / "secrets" / "pki",
            source_sha,
            image_ref,
            image_id,
            state_path,
        )
    finally:
        try:
            state_path.unlink()
            _fsync(staged_release)
        except FileNotFoundError:
            pass
    _validate_bundle(staged_release, project_root)
    os.replace(
        staged_release / runtime_bundle.BUNDLE_DIRECTORY,
        committed_bundle,
    )
    _fsync(release)
    _fsync(_release_root(project_root))
    _validate_bundle(release, project_root)
    return release


def _configuration() -> tuple[Path, int, int]:
    test_root = os.environ.get("CLIXOR_RECONCILER_TEST_ROOT")
    if test_root:
        if os.geteuid() == 0:
            raise ReconcileError("test-root override is forbidden for root")
        root = Path(test_root)
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ReconcileError("test-root override is unsafe")
        return root, metadata.st_uid, metadata.st_gid
    if os.geteuid() != 0:
        raise ReconcileError("runtime reconciler must run as root")
    return PROJECT_ROOT, 0, 0


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    create = subparsers.add_parser("journal-create")
    create.add_argument("--candidate", required=True, type=Path)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--previous-release", required=True)
    create.add_argument("--previous-image", required=True)
    phase = subparsers.add_parser("journal-phase")
    phase.add_argument("--phase", required=True)
    archive = subparsers.add_parser("journal-archive")
    archive.add_argument("--outcome", required=True)
    validate = subparsers.add_parser("validate-release")
    validate.add_argument("--release", required=True, type=Path)
    staging_snapshot = subparsers.add_parser("snapshot-staging-secrets")
    staging_snapshot.add_argument("--release", required=True, type=Path)
    commit_dump = subparsers.add_parser("commit-pre-migration-boundary")
    commit_dump.add_argument("--candidate", required=True, type=Path)
    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--boot", action="store_true")
    baseline = subparsers.add_parser("establish-legacy-baseline")
    baseline.add_argument("--controller-source", required=True, type=Path)
    baseline.add_argument("--legacy-git-dir", type=Path)
    publish = subparsers.add_parser("publish-release")
    publish.add_argument("--candidate", required=True, type=Path)
    permit = subparsers.add_parser("permit-candidate-ingress")
    permit.add_argument("--candidate", required=True, type=Path)
    quarantine = subparsers.add_parser("quarantine-pending")
    quarantine.add_argument("--candidate", required=True, type=Path)
    subparsers.add_parser("watchdog")
    options = parser.parse_args(arguments)
    try:
        project_root, expected_uid, expected_gid = _configuration()
        if options.action == "journal-create":
            create_journal(
                project_root,
                options.candidate,
                options.source_sha,
                options.previous_release,
                options.previous_image,
                CommandRunner(),
            )
        elif options.action == "journal-phase":
            update_journal_phase(project_root, options.phase)
        elif options.action == "journal-archive":
            archive_journal(project_root, options.outcome)
        elif options.action == "validate-release":
            runtime_bundle.validate_runtime_bundle(
                options.release, expected_uid=expected_uid, expected_gid=expected_gid
            )
            _boot_bundle_validate(options.release, CommandRunner())
        elif options.action == "snapshot-staging-secrets":
            snapshot_staging_secret_manifest(options.release, project_root)
        elif options.action == "commit-pre-migration-boundary":
            durably_commit_pre_migration_boundary(project_root, options.candidate)
        elif options.action == "reconcile":
            reconcile_current(project_root, CommandRunner(), boot=options.boot)
        elif options.action == "establish-legacy-baseline":
            establish_legacy_baseline(
                project_root,
                options.controller_source,
                CommandRunner(),
                legacy_git_directory=options.legacy_git_dir,
            )
        elif options.action == "publish-release":
            publish_pending_release(project_root, options.candidate, CommandRunner())
        elif options.action == "permit-candidate-ingress":
            permit_candidate_ingress(project_root, options.candidate, CommandRunner())
        elif options.action == "quarantine-pending":
            quarantine_pending_candidate(project_root, options.candidate)
        else:
            watchdog(project_root, CommandRunner())
    except (ReconcileError, runtime_bundle.BundleError, OSError) as error:
        print(f"Clixor runtime reconciliation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
