#!/usr/bin/env python3
"""Fail-closed local gate for an operator-controlled Cloudflare ownership move."""
from __future__ import annotations

import argparse
import re
import stat
import sys
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}")

def validate(evidence: Path, revision: str, *, expected_uid: int = 0) -> None:
    if SHA.fullmatch(revision) is None:
        raise ValueError("revision must be an exact Git SHA")
    metadata = evidence.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("canary evidence must be a regular non-symlink file")
    if metadata.st_uid != expected_uid:
        raise ValueError("canary evidence must be owned by the promotion authority")
    if stat.S_IMODE(metadata.st_mode) != 0o400:
        raise ValueError("canary evidence must have mode 0400")
    lines = evidence.read_text(encoding="utf-8").splitlines()
    if (
        len(lines) != 3
        or lines[0] != f"revision={revision}"
        or lines[1] != "stage=canary"
    ):
        raise ValueError("canary evidence does not bind the exact release and stage")
    if (
        re.fullmatch(
            r"smoke=passed prefix=clixor-smoke-[^ ]+ checks=[1-9][0-9]* cleanup=passed",
            lines[2],
        )
        is None
    ):
        raise ValueError("canary evidence does not prove disposable lifecycle cleanup")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    try:
        validate(args.evidence, args.revision)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"promotion=denied reason={error}", file=sys.stderr)
        return 1
    print(f"promotion=approved revision={args.revision}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
