"""knip dead-code sensor (JS/TS)."""
from __future__ import annotations

import sys
from pathlib import Path

from codescan.shared.runner import have, run


def cmd_dead_js(path: Path) -> int:
    """Run knip on a JS/TS project. Requires package.json."""
    if not have("knip"):
        print("knip not installed — skipping JS/TS dead-code", file=sys.stderr)
        return 1
    if not (path / "package.json").exists() and not (Path.cwd() / "package.json").exists():
        print("knip needs a package.json project — skipping JS/TS dead-code", file=sys.stderr)
        return 1
    root = path if (path / "package.json").exists() else Path.cwd()
    rc, out, err = run([
        "knip", "--no-progress", "--reporter", "symbols", "--no-exit-code",
    ])
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    print(f"== knip (JS/TS dead code) on {root} ==")
    print(f"items: {len(lines)}")
    for ln in lines[:40]:
        print(f"  {ln}")
    if len(lines) > 40:
        print(f"  ... {len(lines) - 40} more")
    if err.strip():
        print(f"  (knip stderr: {err.strip()[:120]})", file=sys.stderr)
    return 0
