#!/usr/bin/env python3
"""Prune OCI release history without crossing rollback or backup boundaries."""

from __future__ import annotations

import argparse
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class RetentionError(ValueError):
    """A retention request is unsafe or incomplete."""


@dataclass(frozen=True)
class RetentionResult:
    removed_releases: tuple[Path, ...]
    stripped_dumps: tuple[Path, ...]


def _regular_file(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise RetentionError(f"{description} is not a regular file")
    return path


def _boundary(root: Path, raw: str, description: str, *, optional: bool) -> Path | None:
    if optional and raw in ("", "none", "unrecorded"):
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    if candidate.parent != root or not candidate.name.startswith("oci-"):
        raise RetentionError(f"{description} is outside the release root")
    if candidate.is_symlink() or not candidate.is_dir():
        raise RetentionError(f"{description} is not a retained release directory")
    return candidate


def prune_release_history(
    *,
    release_root: Path,
    current_release: str,
    previous_release: str,
    offsite_marker: Path,
    gate_start: Path,
    keep_extra: int,
) -> RetentionResult:
    if keep_extra < 0 or keep_extra > 20:
        raise RetentionError("extra release retention must be between 0 and 20")
    if not release_root.is_absolute() or release_root.is_symlink() or not release_root.is_dir():
        raise RetentionError("release root is not a safe absolute directory")
    marker = _regular_file(offsite_marker, "offsite success marker")
    gate = _regular_file(gate_start, "release backup gate marker")
    if marker.stat().st_mtime_ns <= gate.stat().st_mtime_ns:
        raise RetentionError("offsite success marker does not belong to this release gate")

    current = _boundary(
        release_root, current_release, "current release", optional=False
    )
    previous = _boundary(
        release_root, previous_release, "previous release", optional=True
    )
    protected = {current}
    if previous is not None:
        protected.add(previous)

    candidates = sorted(
        (
            child
            for child in release_root.iterdir()
            if child.name.startswith("oci-") and child.is_dir() and not child.is_symlink()
        ),
        key=lambda child: (child.stat().st_mtime_ns, child.name),
        reverse=True,
    )
    if current not in candidates:
        raise RetentionError("current release is absent from the retention inventory")

    removed: list[Path] = []
    stripped: list[Path] = []
    retained_extra = 0
    dump_names = (
        "pre-migration.dump",
        "pre-migration.dump.sha256",
        "pre-migration.dump.partial",
    )
    for candidate in candidates:
        if candidate in protected:
            continue
        if retained_extra < keep_extra:
            retained_extra += 1
            for dump_name in dump_names:
                artifact = candidate / dump_name
                if artifact.is_symlink() or artifact.is_file():
                    artifact.unlink()
                    stripped.append(artifact)
                elif artifact.exists():
                    raise RetentionError(
                        f"retained release dump artifact is not a file: {artifact}"
                    )
            continue
        shutil.rmtree(candidate)
        removed.append(candidate)
    return RetentionResult(tuple(removed), tuple(stripped))


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", required=True, type=Path)
    parser.add_argument("--current-release", required=True)
    parser.add_argument("--previous-release", required=True)
    parser.add_argument("--offsite-marker", required=True, type=Path)
    parser.add_argument("--gate-start", required=True, type=Path)
    parser.add_argument("--keep-extra", required=True, type=int)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_args(arguments)
    try:
        result = prune_release_history(
            release_root=options.release_root,
            current_release=options.current_release,
            previous_release=options.previous_release,
            offsite_marker=options.offsite_marker,
            gate_start=options.gate_start,
            keep_extra=options.keep_extra,
        )
    except RetentionError as error:
        print(f"Clixor release retention refused: {error}")
        return 1
    for path in result.removed_releases:
        print(f"Retired release audit directory: {path}")
    for path in result.stripped_dumps:
        print(f"Retired non-boundary pre-migration artifact: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
