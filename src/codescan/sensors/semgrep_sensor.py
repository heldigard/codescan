"""semgrep SAST sensor — bugs + security anti-patterns."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from codescan.shared.runner import die, have, print_topn, run


def _finding_payload(result: dict[str, Any]) -> dict[str, Any]:
    extra = result.get("extra", {})
    return {
        "severity": extra.get("severity", "?"),
        "path": result.get("path", "?"),
        "line": result.get("start", {}).get("line"),
        "check_id": result.get("check_id", "?"),
        "message": extra.get("message"),
    }


def sec_payload(
    path: Path, config: str | None, *, include_findings: bool = True
) -> tuple[int, dict[str, Any], str]:
    """Return the semgrep result payload without printing."""
    cfg = config or "auto"
    path_s = str(path)
    payload: dict[str, Any] = {
        "command": "sec",
        "schema_version": 1,
        "tool": "semgrep",
        "path": path_s,
        "config": cfg,
        "status": "ok",
        "counts": {"findings": 0, "by_severity": {}},
        "findings": [],
        "findings_omitted": not include_findings,
        "truncated": False,
    }
    if not have("semgrep"):
        payload["status"] = "missing_tool"
        payload["error"] = "semgrep not installed"
        return 2, payload, "semgrep not installed (pip3 install --user semgrep)"
    rc, out, err = run(
        [
            "semgrep",
            "scan",
            "--config",
            cfg,
            "--json",
            "--quiet",
            "--disable-version-check",
            path_s,
        ]
    )
    if rc != 0 and not out.strip():
        payload["status"] = "error"
        payload["error"] = err.strip()
        return 2, payload, err.strip()
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        payload["status"] = "error"
        payload["error"] = out.strip() or err.strip()
        return 1, payload, out.strip() or err.strip()
    results = data.get("results", [])
    by_sev: dict[str, int] = {}
    for result in results:
        sev = result.get("extra", {}).get("severity", "?")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    findings = [_finding_payload(result) for result in results[:40]] if include_findings else []
    payload.update(
        {
            "counts": {"findings": len(results), "by_severity": by_sev},
            "findings": findings,
            "findings_omitted": not include_findings,
            "truncated": include_findings and len(results) > len(findings),
        }
    )
    return 0, payload, ""


def cmd_sec(args: argparse.Namespace) -> int:
    """semgrep SAST. Prints finding counts by severity — not the full diff."""
    cfg = args.config or "auto"
    path = str(Path(args.path))
    include_findings = not getattr(args, "summary_only", False)
    rc, payload, error = sec_payload(Path(path), cfg, include_findings=include_findings)
    if payload["status"] == "missing_tool":
        die("semgrep not installed (pip3 install --user semgrep)", 2)
    if payload["status"] == "error":
        print(error, file=sys.stderr)
        return rc
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    print(f"== semgrep SAST on {path} (config={cfg}) ==")
    counts_map = payload["counts"]["by_severity"]
    counts = "  ".join(f"{k}:{v}" for k, v in sorted(counts_map.items()))
    total = payload["counts"]["findings"]
    print(f"findings: {total}" + (f"  {counts}" if counts else ""))
    if payload["findings"] and not args.summary_only:
        items = []
        for result in payload["findings"]:
            check = str(result.get("check_id", "?")).split(".")[-1]
            loc = result.get("path", "?") + ":" + str(result.get("line", "?"))
            sev = result.get("severity", "?")
            items.append(f"[{sev}] {loc}  {check}")
        print_topn(items)
    return 0
