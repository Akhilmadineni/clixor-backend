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
CLOUDFLARED_BINARY = Path("/usr/bin/cloudflared")
READY_MARKER = Path("/run/clixor/runtime-ready")
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


def _stop_ingress_and_containers(runner: CommandRunner) -> None:
    try:
        READY_MARKER.unlink()
    except FileNotFoundError:
        pass
    runner.run(["/usr/bin/systemctl", "stop", "cloudflared.service"])
    existing: list[str] = []
    for name in KNOWN_CONTAINERS:
        result = runner.run(["/usr/bin/docker", "inspect", name], check=False)
        if result.returncode == 0:
            existing.append(name)
    if existing:
        runner.run(["/usr/bin/docker", "stop", "--time", "30", *existing])
        for name in existing:
            result = runner.run(
                [
                    "/usr/bin/docker",
                    "inspect",
                    name,
                    "--format",
                    "{{.State.Running}}",
                ],
                capture=True,
            )
            if result.stdout.decode("ascii", errors="strict").strip() != "false":
                raise ReconcileError("a runtime container did not stop fail-closed")


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
    HOST_TOOL_ROOT.mkdir(parents=True, exist_ok=True)
    for tool in ("offsite-backup.sh", "backup-health.sh", "restore-drill.sh", "backup_manifest.py"):
        _atomic_install(root / "bin" / tool, HOST_TOOL_ROOT / tool, 0, 0, 0o500)
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
        exists = runner.run(
            ["/usr/bin/docker", "inspect", container], check=False
        ).returncode == 0
        if exists:
            # The data bind mount is retained. Removing only the stopped
            # immutable container prevents a retired restart policy or config
            # from becoming an alternate boot authority.
            runner.run(["/usr/bin/docker", "rm", container])


def _wait_ready(source_sha: str, expected_image_id: str, runner: CommandRunner) -> None:
    for container in ("clixor-oci-api-a", "clixor-oci-api-b"):
        result = runner.run(
            ["/usr/bin/docker", "inspect", container, "--format", "{{.Image}}"],
            capture=True,
        )
        if result.stdout.decode("ascii", errors="strict").strip() != expected_image_id:
            raise ReconcileError("API container does not use the selected image ID")
    deadline = time.monotonic() + 180
    while True:
        replicas_ready = all(
            runner.run(
                [
                    "/usr/bin/docker",
                    "exec",
                    "clixor-oci-api-gateway",
                    "wget",
                    "--quiet",
                    "--output-document=/dev/null",
                    f"http://{replica}:8080/health/ready",
                ],
                check=False,
            ).returncode
            == 0
            for replica in ("api-a", "api-b")
        )
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
    _restore_source(release, project_root, runner)
    _restore_runtime(release, project_root)
    _restore_host_tools(release, runner)
    _set_service_selection(manifest, runner)
    _compose_up(release, manifest, image_ref, runner)
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
        runner.run(
            ["/usr/bin/systemctl", "start", "--no-block", "cloudflared.service"]
        )
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
        if READY_MARKER.read_text(encoding="ascii") != str(release) + "\n":
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
                if expected_active:
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
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
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


def establish_legacy_baseline(
    project_root: Path,
    controller_source: Path,
    runner: CommandRunner,
    cloudflared_binary: Path = CLOUDFLARED_BINARY,
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
    mode_path = release / "secret-mode"
    try:
        mode = mode_path.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise ReconcileError("legacy baseline secret mode is unavailable") from None
    if mode != "staging\n":
        raise ReconcileError("legacy baseline transition is allowed only in staging")
    committed_bundle = release / runtime_bundle.BUNDLE_DIRECTORY
    if committed_bundle.exists() or committed_bundle.is_symlink():
        _validate_bundle(release, project_root)
        return release
    pending_root = _release_root(project_root) / "pending"
    pending_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(pending_root, 0o700)
    staged_release = pending_root / release.name
    staged_manifest: Mapping[str, Any] | None = None
    if staged_release.exists() or staged_release.is_symlink():
        try:
            staged_manifest = _validate_bundle(staged_release, project_root)
        except runtime_bundle.BundleError:
            quarantine_pending_candidate(project_root, staged_release)
    if not staged_release.exists():
        staged_release.mkdir(mode=0o700)
    stable_source = project_root / "repo"
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
    if staged_manifest is not None:
        staged_image = staged_manifest["image"]
        if (
            staged_manifest["source_sha"] != source_sha
            or not isinstance(staged_image, dict)
            or staged_image.get("ref") != image_ref
            or staged_image.get("id") != image_id
        ):
            raise ReconcileError("staged legacy baseline no longer matches the live release")
        os.replace(
            staged_release / runtime_bundle.BUNDLE_DIRECTORY,
            committed_bundle,
        )
        _fsync(release)
        _fsync(_release_root(project_root))
        _validate_bundle(release, project_root)
        return release
    compose_override = controller_source / "deploy" / "oci" / "compose.yaml"
    if not (staged_release / runtime_bundle.BUNDLE_DIRECTORY).exists():
        runtime_bundle.stage_source(
            staged_release,
            stable_source,
            source_sha,
            compose_source=compose_override,
        )
        runtime_bundle.stage_host_tools(
            staged_release, controller_source, cloudflared_binary
        )
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
    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--boot", action="store_true")
    baseline = subparsers.add_parser("establish-legacy-baseline")
    baseline.add_argument("--controller-source", required=True, type=Path)
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
        elif options.action == "reconcile":
            reconcile_current(project_root, CommandRunner(), boot=options.boot)
        elif options.action == "establish-legacy-baseline":
            establish_legacy_baseline(
                project_root, options.controller_source, CommandRunner()
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
