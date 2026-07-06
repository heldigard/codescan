"""dependency-cruiser architecture/import-rule sensor (JS/TS)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from codescan.shared.runner import die, find_upward, have, print_topn, run


def _is_violation(ln: str) -> bool:
    """Check if a depcruiser output line looks like a violation."""
    low = ln.lower()
    return "error" in low or "warn" in low or "✖" in ln or "→" in ln


def _root_for(path: Path) -> Path:
    """Find the JS project/config root for dependency-cruiser."""
    return (
        find_upward(path, ".dependency-cruiser.cjs")
        or find_upward(path, ".dependency-cruiser.js")
        or find_upward(path, "package.json")
        or (path if path.is_dir() else path.parent).expanduser().resolve()
    )


def cmd_arch(args: argparse.Namespace) -> int:
    """dependency-cruiser: validate import-graph rules. Requires .dependency-cruiser.cjs/.js."""
    tool = "depcruise" if have("depcruise") else "dependency-cruiser"
    if not have(tool):
        die("dependency-cruiser not installed", 2)
    path = Path(args.path)
    root = _root_for(path)
    configs = [root / ".dependency-cruiser.cjs", root / ".dependency-cruiser.js"]
    cfg = next((candidate for candidate in configs if candidate.exists()), None)
    if cfg is None:
        print(f"no .dependency-cruiser.cjs/.js in {root} — skipping arch rules", file=sys.stderr)
        print(
            "  create one: npx depcruise init (a project decision, not auto-run)", file=sys.stderr
        )
        return 1
    target = args.target or "src"
    rc, out, err = run([tool, "--config", str(cfg), target], cwd=root)
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    lines = [ln for ln in lines if _is_violation(ln)]  # keep only rule violations
    if rc != 0 and not lines:
        print(f"dependency-cruiser error: {err.strip()}", file=sys.stderr)
        return 2
    print(f"== dependency-cruiser on {root}/{target} ==")
    print(f"output lines: {len(lines)}")
    print_topn(lines)
    return 0
