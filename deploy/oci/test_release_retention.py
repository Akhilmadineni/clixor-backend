from __future__ import annotations

import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import release_retention


class ReleaseRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "releases"
        self.root.mkdir()
        self.gate = Path(self.temporary.name) / "gate"
        self.marker = Path(self.temporary.name) / "offsite"
        self.gate.write_text("gate\n", encoding="utf-8")
        self.marker.write_text("offsite\n", encoding="utf-8")
        now = time.time_ns()
        os.utime(self.gate, ns=(now - 2_000_000_000, now - 2_000_000_000))
        os.utime(self.marker, ns=(now - 1_000_000_000, now - 1_000_000_000))

    def release(self, name: str, age: int) -> Path:
        path = self.root / name
        path.mkdir()
        (path / "pre-migration.dump").write_bytes(name.encode("ascii"))
        (path / "pre-migration.dump.sha256").write_text(
            "checksum\n", encoding="utf-8"
        )
        timestamp = time.time_ns() - age * 1_000_000_000
        os.utime(path, ns=(timestamp, timestamp))
        return path

    def test_preserves_both_boundaries_and_bounds_other_history(self) -> None:
        current = self.release("oci-current", 0)
        previous = self.release("oci-previous", 1)
        newest_extra = self.release("oci-extra-new", 2)
        middle_extra = self.release("oci-extra-middle", 3)
        oldest_extra = self.release("oci-extra-old", 4)

        result = release_retention.prune_release_history(
            release_root=self.root,
            current_release=str(current),
            previous_release=previous.name,
            offsite_marker=self.marker,
            gate_start=self.gate,
            keep_extra=2,
        )

        self.assertTrue(current.is_dir())
        self.assertTrue(previous.is_dir())
        self.assertTrue((current / "pre-migration.dump").is_file())
        self.assertTrue((previous / "pre-migration.dump").is_file())
        self.assertTrue(newest_extra.is_dir())
        self.assertTrue(middle_extra.is_dir())
        self.assertFalse((newest_extra / "pre-migration.dump").exists())
        self.assertFalse((middle_extra / "pre-migration.dump").exists())
        self.assertFalse(oldest_extra.exists())
        self.assertEqual(result.removed_releases, (oldest_extra,))
        self.assertEqual(len(result.stripped_dumps), 4)

    def test_refuses_stale_confirmation_and_unsafe_boundaries(self) -> None:
        current = self.release("oci-current", 0)
        now = time.time_ns()
        os.utime(self.marker, ns=(now - 3_000_000_000, now - 3_000_000_000))
        os.utime(self.gate, ns=(now - 1_000_000_000, now - 1_000_000_000))
        with self.assertRaises(release_retention.RetentionError):
            release_retention.prune_release_history(
                release_root=self.root,
                current_release=str(current),
                previous_release="none",
                offsite_marker=self.marker,
                gate_start=self.gate,
                keep_extra=3,
            )

        os.utime(self.marker, ns=(now, now))
        with self.assertRaises(release_retention.RetentionError):
            release_retention.prune_release_history(
                release_root=self.root,
                current_release=str(current),
                previous_release="../outside",
                offsite_marker=self.marker,
                gate_start=self.gate,
                keep_extra=3,
            )

    def test_never_follows_a_release_symlink(self) -> None:
        current = self.release("oci-current", 0)
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("keep\n", encoding="utf-8")
        (self.root / "oci-link").symlink_to(outside, target_is_directory=True)

        release_retention.prune_release_history(
            release_root=self.root,
            current_release=str(current),
            previous_release="none",
            offsite_marker=self.marker,
            gate_start=self.gate,
            keep_extra=0,
        )
        self.assertTrue(sentinel.is_file())
        self.assertTrue((self.root / "oci-link").is_symlink())


if __name__ == "__main__":
    unittest.main()
