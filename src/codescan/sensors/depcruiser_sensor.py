"""dependency-cruiser architecture/import-rule sensor (JS/TS)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from codescan.shared.runner import die, have, run


def _is_violation(ln: str) -> bool:
    """Check if a depcruiser output line looks like a violation."""
    low = ln.lower()
    return "error" in low or "warn" in low or "✖" in ln or "→" in ln


def cmd_arch(args: argparse.Namespace) -> int:
    """dependency-cruiser: validate import-graph rules. Requires .dependency-cruiser.cjs."""
    if not have("dependency-cruiser"):
        die("dependency-cruiser not installed", 2)
    path = Path(args.path)
    root = path if (path / "package.json").exists() else Path.cwd()
    cfg = root / ".dependency-cruiser.cjs"
    if not cfg.exists() and not (root / ".dependency-cruiser.js").exists():
        print(f"no .dependency-cruiser.cjs in {root} — skipping arch rules",
              file=sys.stderr)
        print("  create one: npx depcruise init (a project decision, not auto-run)",
              file=sys.stderr)
        return 1
    target = args.target or "src"
    rc, out, err = run(["depcruise", "--config", str(cfg), target])
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    _ = [ln for ln in lines if _is_violation(ln)]
    print(f"== dependency-cruiser on {root}/{target} ==")
    print(f"output lines: {len(lines)}")
    for ln in lines[:40]:
        print(f"  {ln}")
    if len(lines) > 40:
        print(f"  ... {len(lines) - 40} more")
    return 0
