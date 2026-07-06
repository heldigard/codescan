"""knip dead-code sensor (JS/TS)."""

from __future__ import annotations

import sys
from pathlib import Path

from codescan.shared.runner import find_upward, have, print_topn, run


def cmd_dead_js(path: Path) -> int:
    """Run knip on a JS/TS project. Requires package.json."""
    if not have("knip"):
        print("knip not installed — skipping JS/TS dead-code", file=sys.stderr)
        return 1
    root = find_upward(path, "package.json")
    if root is None:
        print("knip needs a package.json project — skipping JS/TS dead-code", file=sys.stderr)
        return 1
    rc, out, err = run(
        [
            "knip",
            "--no-progress",
            "--reporter",
            "symbols",
            "--no-exit-code",
        ],
        cwd=root,
    )
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    if rc != 0 and not lines:
        print(f"knip error: {err.strip()}", file=sys.stderr)
        return 2
    print(f"== knip (JS/TS dead code) on {root} ==")
    print(f"items: {len(lines)}")
    print_topn(lines)
    if err.strip():
        print(f"  (knip stderr: {err.strip()[:120]})", file=sys.stderr)
    return 0
