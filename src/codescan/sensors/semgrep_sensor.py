"""semgrep SAST sensor — bugs + security anti-patterns."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codescan.shared.runner import die, have, print_topn, run


def cmd_sec(args: argparse.Namespace) -> int:
    """semgrep SAST. Prints finding counts by severity — not the full diff."""
    if not have("semgrep"):
        die("semgrep not installed (pip3 install --user semgrep)", 2)
    cfg = args.config or "auto"
    path = str(Path(args.path))
    rc, out, err = run(
        [
            "semgrep",
            "scan",
            "--config",
            cfg,
            "--json",
            "--quiet",
            "--disable-version-check",
            path,
        ]
    )
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
    counts = "  ".join(f"{k}:{v}" for k, v in sorted(by_sev.items()))
    print(f"findings: {len(results)}" + (f"  {counts}" if counts else ""))
    if results and not args.summary_only:
        items = []
        for result in results:
            check = result.get("check_id", "?").split(".")[-1]
            loc = result.get("path", "?") + ":" + str(result.get("start", {}).get("line", "?"))
            sev = result.get("extra", {}).get("severity", "?")
            items.append(f"[{sev}] {loc}  {check}")
        print_topn(items)
    return 0
