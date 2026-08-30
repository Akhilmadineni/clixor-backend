from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_ROOT = Path(__file__).resolve().parent
LAUNCHER_PATH = SCRIPT_ROOT / "prepare-runtime-secrets-launcher.py"
SPEC = importlib.util.spec_from_file_location("clixor_boot_launcher", LAUNCHER_PATH)
assert SPEC is not None and SPEC.loader is not None
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class BootSecretLauncherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="clixor-boot-launcher-",
            dir="/private/tmp" if Path("/private/tmp").is_dir() else None,
        )
        self.project_root = Path(self.temporary.name)
        self.project_root.chmod(0o750)
        self.release_root = self.project_root / "releases"
        self.release_root.mkdir(mode=0o700)
        self.bootstrap_root = self.project_root / "bootstrap"
        self.bootstrap_root.mkdir(mode=0o700)
        self.initial_worker = (
            self.bootstrap_root / "prepare-initial-staging-secrets.sh"
        )
        self.initial_worker.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        self.initial_worker.chmod(0o500)
        self.uid = self.project_root.stat().st_uid
        self.gid = self.project_root.stat().st_gid

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _release(self, suffix: str, worker: bytes | None = None) -> Path:
        release = self.release_root / f"oci-0123456789ab-{suffix}"
        release.mkdir(mode=0o700)
        release.chmod(0o700)
        mode = release / "secret-mode"
        mode.write_bytes(b"staging\n")
        mode.chmod(0o400)
        boot = release / "boot-secrets"
        boot.mkdir(mode=0o700)
        boot.chmod(0o700)
        contents = {
            "hydrate-vault-secrets.py": b"#!/usr/bin/python3\nraise SystemExit(0)\n",
            "prepare-runtime-secrets.sh": worker
            or b"#!/bin/sh\nexit 0\n",
        }
        checksum_lines = []
        for name, content in contents.items():
            path = boot / name
            path.write_bytes(content)
            path.chmod(0o500)
            checksum_lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
        checksum = boot / "SHA256SUMS"
        checksum.write_text("".join(checksum_lines), encoding="ascii")
        checksum.chmod(0o400)
        return release

    def _select(self) -> tuple[str, ...]:
        return LAUNCHER.select_boot_command(
            self.project_root,
            self.initial_worker,
            self.uid,
            self.gid,
        )

    def _point_to(self, release: Path) -> None:
        temporary = self.release_root / ".current.test"
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(release)
        os.replace(temporary, self.release_root / "current")

    def test_uncommitted_candidate_cannot_replace_current_selection(self) -> None:
        previous = self._release("previous")
        candidate = self._release("candidate")
        self._point_to(previous)
        self.assertEqual(
            self._select(),
            (
                str(previous / "boot-secrets" / "prepare-runtime-secrets.sh"),
                str(previous),
            ),
        )
        self._point_to(candidate)
        self.assertEqual(
            self._select(),
            (
                str(candidate / "boot-secrets" / "prepare-runtime-secrets.sh"),
                str(candidate),
            ),
        )

    def test_initial_staging_is_allowed_only_before_release_history(self) -> None:
        self.assertEqual(self._select(), (str(self.initial_worker),))
        self._release("history")
        with self.assertRaisesRegex(
            LAUNCHER.LaunchError, "release history exists"
        ):
            self._select()

    def test_pointer_and_release_paths_fail_closed(self) -> None:
        release = self._release("safe")
        current = self.release_root / "current"
        current.symlink_to(Path("oci-0123456789ab-safe"))
        with self.assertRaisesRegex(LAUNCHER.LaunchError, "unexpected location"):
            self._select()
        current.unlink()
        outside = self.project_root / "outside"
        outside.mkdir(mode=0o700)
        linked_release = self.release_root / "oci-0123456789ab-linked"
        linked_release.symlink_to(outside)
        self._point_to(linked_release)
        with self.assertRaisesRegex(LAUNCHER.LaunchError, "regular directory"):
            self._select()

    def test_modes_symlinks_and_checksum_tampering_fail_closed(self) -> None:
        release = self._release("tamper")
        self._point_to(release)
        release.chmod(0o755)
        with self.assertRaisesRegex(LAUNCHER.LaunchError, "unsafe mode"):
            self._select()
        release.chmod(0o700)

        worker = release / "boot-secrets" / "prepare-runtime-secrets.sh"
        worker.chmod(0o700)
        with self.assertRaisesRegex(LAUNCHER.LaunchError, "unsafe mode"):
            self._select()
        worker.chmod(0o500)

        original = worker.read_bytes()
        worker.chmod(0o600)
        worker.write_bytes(original + b"# changed\n")
        worker.chmod(0o500)
        with self.assertRaisesRegex(LAUNCHER.LaunchError, "checksum mismatch"):
            self._select()

        worker.chmod(0o600)
        worker.unlink()
        target = self.project_root / "worker-target"
        target.write_bytes(original)
        target.chmod(0o500)
        worker.symlink_to(target)
        with self.assertRaisesRegex(LAUNCHER.LaunchError, "opened safely"):
            self._select()

    @unittest.skipIf(os.geteuid() == 0, "root intentionally cannot use test-root mode")
    def test_launcher_exec_propagates_release_worker_status(self) -> None:
        release = self._release("status", b"#!/bin/sh\nexit 37\n")
        self._point_to(release)
        environment = dict(os.environ)
        environment["CLIXOR_BOOT_LAUNCHER_TEST_ROOT"] = str(self.project_root)
        completed = subprocess.run(
            [sys.executable, str(LAUNCHER_PATH)],
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 37, completed.stderr.decode())

    def test_post_swap_fsync_failure_leaves_candidate_committed(self) -> None:
        previous = self._release("old")
        candidate = self._release("new")
        self._point_to(previous)
        real_fsync = LAUNCHER._fsync_path

        def fail_after_swap(path: Path) -> None:
            if (
                path == self.release_root
                and (self.release_root / "current").is_symlink()
                and os.readlink(self.release_root / "current") == str(candidate)
            ):
                raise OSError("injected post-swap fsync failure")
            real_fsync(path)

        with mock.patch.object(LAUNCHER, "_fsync_path", side_effect=fail_after_swap):
            with self.assertRaises(OSError):
                LAUNCHER.commit_staging_release(
                    candidate,
                    self.release_root,
                    self.uid,
                    self.gid,
                )
        self.assertEqual(os.readlink(self.release_root / "current"), str(candidate))
        self.assertEqual(self._select()[1], str(candidate))


if __name__ == "__main__":
    unittest.main()
