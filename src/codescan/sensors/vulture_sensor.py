"""vulture dead-code sensor (Python)."""
from __future__ import annotations

import sys
from pathlib import Path

from codescan.shared.runner import have, run


def cmd_dead_py(path: Path, min_confidence: int) -> int:
    """Run vulture on a Python project. Short exclude list (vulture chokes on long lists)."""
    if not have("vulture"):
        print("vulture not installed — skipping Python dead-code", file=sys.stderr)
        return 1
    py_excludes = ",".join([
        ".venv", "venv", "env", "site-packages", ".python_packages",
        "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", ".eggs", ".git", "build", "dist",
    ])
    rc, out, err = run([
        "vulture", str(path), "--min-confidence", str(min_confidence),
        "--exclude", py_excludes,
    ])
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    print(f"== vulture (Python dead code, min-confidence {min_confidence}) on {path} ==")
    print(f"items: {len(lines)}")
    for ln in lines[:40]:
        print(f"  {ln}")
    if len(lines) > 40:
        print(f"  ... {len(lines) - 40} more")
    return 0
