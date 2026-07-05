"""semgrep SAST sensor — bugs + security anti-patterns."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codescan.shared.runner import die, have, run


def cmd_sec(args: argparse.Namespace) -> int:
    """semgrep SAST. Prints finding counts by severity — not the full diff."""
    if not have("semgrep"):
        die("semgrep not installed (pip3 install --user semgrep)", 2)
    cfg = args.config or "auto"
    path = str(Path(args.path))
    rc, out, err = run([
        "semgrep", "scan", "--config", cfg, "--json", "--quiet",
        "--disable-version-check", path,
    ])
    if rc != 0 and not out.strip():
        print(f"semgrep error:\n{err.strip()}", file=sys.stderr)
        return 2
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        print(out.strip() or err.strip())
        return 1
    results = data.get("results", [])
    by_sev: dict[str, int] = {}
    for r in results:
        sev = r.get("extra", {}).get("severity", "?")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    print(f"== semgrep SAST on {path} (config={cfg}) ==")
    print(f"findings: {len(results)}  " +
          "  ".join(f"{k}:{v}" for k, v in sorted(by_sev.items())) or "findings: 0")
    if results and not args.summary_only:
        for r in results[:40]:
            chk = r.get("check_id", "?").split(".")[-1]
            loc = r.get("path", "?") + ":" + str(r.get("start", {}).get("line", "?"))
            sev = r.get("extra", {}).get("severity", "?")
            print(f"  [{sev}] {loc}  {chk}")
        if len(results) > 40:
            print(f"  ... {len(results) - 40} more (re-run on a narrower path)")
    return 0
