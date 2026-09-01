#!/usr/bin/python3
"""Select and execute only the boot tooling approved by releases/current."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import sys
from pathlib import Path


PROJECT_ROOT = Path("/srv/clixor")
INITIAL_STAGING_WORKER = Path(
    "/usr/local/libexec/clixor/prepare-initial-staging-secrets.sh"
)
RELEASE_RE = re.compile(r"^oci-[a-f0-9]{12}-[A-Za-z0-9._-]{1,160}$")
CHECKSUM_RE = re.compile(r"^([a-f0-9]{64})  ([A-Za-z0-9._-]+)$")
BOOT_FILES = {
    "hydrate-vault-secrets.py": (0o500, 512 * 1024),
    "prepare-runtime-secrets.sh": (0o500, 64 * 1024),
}


class LaunchError(RuntimeError):
    """A sanitized boot-selection failure."""


def _lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError:
        raise LaunchError(f"required boot path is unavailable: {path}") from None


def _validate_directory(
    path: Path,
    expected_uid: int,
    expected_gid: int,
    *,
    exact_mode: int | None = None,
) -> None:
    metadata = _lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LaunchError(f"boot path must be a regular directory: {path}")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise LaunchError(f"boot directory has the wrong owner: {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if exact_mode is not None:
        if mode != exact_mode:
            raise LaunchError(f"boot directory has an unsafe mode: {path}")
    elif mode & 0o022:
        raise LaunchError(f"boot directory is writable outside its owner: {path}")


def _read_regular_file(
    path: Path,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    maximum_size: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise LaunchError(f"boot file cannot be opened safely: {path}") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LaunchError(f"boot file must be regular: {path}")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise LaunchError(f"boot file has the wrong owner: {path}")
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise LaunchError(f"boot file has an unsafe mode: {path}")
        if metadata.st_size <= 0 or metadata.st_size > maximum_size:
            raise LaunchError(f"boot file has an invalid size: {path}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise LaunchError(f"boot file changed while being read: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise LaunchError(f"boot file changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_release_bundle(
    release: Path,
    release_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> Path:
    if not release.is_absolute() or release.parent not in {
        release_root,
        release_root / "pending",
    }:
        raise LaunchError(
            "release must be an immediate committed or pending child of the release root"
        )
    if RELEASE_RE.fullmatch(release.name) is None:
        raise LaunchError("release name is invalid")
    _validate_directory(release, expected_uid, expected_gid, exact_mode=0o700)
    try:
        resolved = release.resolve(strict=True)
    except OSError:
        raise LaunchError("release cannot be resolved") from None
    if resolved != release:
        raise LaunchError("release path contains a symbolic link")

    boot_root = release / "boot-secrets"
    _validate_directory(boot_root, expected_uid, expected_gid, exact_mode=0o700)
    checksum_content = _read_regular_file(
        boot_root / "SHA256SUMS", expected_uid, expected_gid, 0o400, 4096
    )
    if not checksum_content.endswith(b"\n") or b"\x00" in checksum_content:
        raise LaunchError("boot checksum manifest is malformed")
    try:
        checksum_lines = checksum_content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise LaunchError("boot checksum manifest must be ASCII") from None
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        match = CHECKSUM_RE.fullmatch(line)
        if match is None or match.group(2) not in BOOT_FILES:
            raise LaunchError("boot checksum manifest has an unsupported entry")
        digest, name = match.groups()
        if name in checksums:
            raise LaunchError("boot checksum manifest has a duplicate entry")
        checksums[name] = digest
    if set(checksums) != set(BOOT_FILES):
        raise LaunchError("boot checksum manifest is incomplete")

    for name, (mode, maximum_size) in BOOT_FILES.items():
        content = _read_regular_file(
            boot_root / name,
            expected_uid,
            expected_gid,
            mode,
            maximum_size,
        )
        if hashlib.sha256(content).hexdigest() != checksums[name]:
            raise LaunchError(f"boot file checksum mismatch: {name}")
    return boot_root / "prepare-runtime-secrets.sh"


def _fsync_path(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise LaunchError(f"boot path cannot be opened for durability: {path}") from None
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_release_bundle(
    release: Path,
    release_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> bytes:
    validate_release_bundle(release, release_root, expected_uid, expected_gid)
    mode_content = _read_regular_file(
        release / "secret-mode", expected_uid, expected_gid, 0o400, 128
    )
    if mode_content not in (b"staging\n", b"vault\n"):
        raise LaunchError("release secret mode is invalid")
    boot_root = release / "boot-secrets"
    for name in (*sorted(BOOT_FILES), "SHA256SUMS"):
        _fsync_path(boot_root / name)
    _fsync_path(boot_root)
    _fsync_path(release / "secret-mode")
    _fsync_path(release)
    return mode_content


def commit_staging_release(
    release: Path,
    release_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if fsync_release_bundle(
        release, release_root, expected_uid, expected_gid
    ) != b"staging\n":
        raise LaunchError("staging pointer commit requires staging secret mode")
    for forbidden in ("vault-secrets.map", "vault-approved-cohort.json"):
        path = release / forbidden
        if path.exists() or path.is_symlink():
            raise LaunchError("staging release contains approved Vault metadata")
    current = release_root / "current"
    if current.exists() or current.is_symlink():
        metadata = _lstat(current)
        if not stat.S_ISLNK(metadata.st_mode):
            raise LaunchError("current release pointer must be a symbolic link")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise LaunchError("current release pointer has the wrong owner")
    temporary = release_root / f".current.{secrets.token_hex(8)}"
    try:
        os.symlink(str(release), temporary)
        os.replace(temporary, current)
        _fsync_path(release_root)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    try:
        selected = os.readlink(current)
    except OSError:
        raise LaunchError("current release pointer is unavailable after commit") from None
    if selected != str(release):
        raise LaunchError("current release pointer did not select the staging release")


def _select_initial_staging(
    worker: Path, expected_uid: int, expected_gid: int
) -> tuple[str, ...]:
    _validate_directory(worker.parent, expected_uid, expected_gid)
    _read_regular_file(worker, expected_uid, expected_gid, 0o500, 64 * 1024)
    return (str(worker),)


def select_boot_command(
    project_root: Path,
    initial_staging_worker: Path,
    expected_uid: int,
    expected_gid: int,
) -> tuple[str, ...]:
    if not project_root.is_absolute():
        raise LaunchError("project root must be absolute")
    _validate_directory(project_root, expected_uid, expected_gid)
    release_root = project_root / "releases"
    try:
        _validate_directory(release_root, expected_uid, expected_gid)
    except LaunchError:
        if release_root.exists() or release_root.is_symlink():
            raise
        return _select_initial_staging(
            initial_staging_worker, expected_uid, expected_gid
        )

    current = release_root / "current"
    try:
        current_metadata = current.lstat()
    except FileNotFoundError:
        # Candidate and orphan directories are never boot authority.  With no
        # current pointer, initial staging secrets may be prepared, but the
        # independent runtime reconciler keeps every application container and
        # ingress stopped.  This also makes a failed first deploy retryable.
        return _select_initial_staging(
            initial_staging_worker, expected_uid, expected_gid
        )
    except OSError:
        raise LaunchError("current release pointer is unavailable") from None
    if not stat.S_ISLNK(current_metadata.st_mode):
        raise LaunchError("current release pointer must be a symbolic link")
    if (current_metadata.st_uid, current_metadata.st_gid) != (
        expected_uid,
        expected_gid,
    ):
        raise LaunchError("current release pointer has the wrong owner")
    try:
        selected_text = os.readlink(current)
    except OSError:
        raise LaunchError("current release pointer cannot be read") from None
    selected = Path(selected_text)
    if not selected.is_absolute() or selected.parent != release_root:
        raise LaunchError("current release pointer targets an unexpected location")
    worker = validate_release_bundle(
        selected, release_root, expected_uid, expected_gid
    )
    try:
        if current.resolve(strict=True) != selected:
            raise LaunchError("current release pointer does not resolve exactly")
    except OSError:
        raise LaunchError("current release pointer cannot be resolved") from None
    return (str(worker), str(selected))


def _configuration() -> tuple[Path, Path, int, int]:
    test_root = os.environ.get("CLIXOR_BOOT_LAUNCHER_TEST_ROOT")
    if test_root:
        if os.geteuid() == 0:
            raise LaunchError("test-root override is forbidden for root")
        project_root = Path(test_root)
        metadata = _lstat(project_root)
        if metadata.st_uid != os.geteuid():
            raise LaunchError("test-root override must be owned by the caller")
        return (
            project_root,
            project_root / "bootstrap" / "prepare-initial-staging-secrets.sh",
            os.geteuid(),
            metadata.st_gid,
        )
    if os.geteuid() != 0:
        raise LaunchError("runtime-secret launcher must run as root")
    return PROJECT_ROOT, INITIAL_STAGING_WORKER, 0, 0


def main(argv: list[str]) -> int:
    try:
        project_root, initial_worker, expected_uid, expected_gid = _configuration()
        release_root = project_root / "releases"
        if argv:
            if len(argv) != 2 or argv[0] not in {
                "--verify-release-bundle",
                "--commit-staging-release",
            }:
                raise LaunchError("unsupported launcher arguments")
            release = Path(argv[1])
            if argv[0] == "--verify-release-bundle":
                fsync_release_bundle(
                    release, release_root, expected_uid, expected_gid
                )
            else:
                commit_staging_release(
                    release, release_root, expected_uid, expected_gid
                )
            return 0
        command = select_boot_command(
            project_root, initial_worker, expected_uid, expected_gid
        )
        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        os.execve("/bin/sh", ("/bin/sh", *command), environment)
    except (LaunchError, OSError) as exc:
        print(f"[clixor-runtime-secrets-launcher] ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
