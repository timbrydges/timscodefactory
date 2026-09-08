#!/usr/bin/env python3
"""Build or verify the deterministic repository integrity manifest."""

from __future__ import annotations

import argparse
import difflib
import hashlib
from pathlib import Path


EXCLUDED_PARTS = {".git", ".pytest_cache", "__pycache__", ".venv"}
EXCLUDED_FILES = {"MANIFEST.sha256"}


def iter_manifest_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if relative.as_posix() in EXCLUDED_FILES:
            continue
        yield path, relative.as_posix()


def render_manifest(root: Path) -> str:
    lines = []
    for path, relative in iter_manifest_files(root):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest_path = args.root / "MANIFEST.sha256"
    expected = render_manifest(args.root)
    if args.check:
        actual = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""
        if actual != expected:
            print("MANIFEST.sha256 is missing or stale")
            diff = difflib.unified_diff(
                actual.splitlines(),
                expected.splitlines(),
                fromfile="MANIFEST.sha256",
                tofile="expected MANIFEST.sha256",
                lineterm="",
            )
            for line in diff:
                print(line)
            return 1
        print("MANIFEST.sha256 verified")
        return 0
    manifest_path.write_text(expected, encoding="utf-8")
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
