"""ruff lint sensor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from codescan.shared.config import SCAN_EXCLUDES
from codescan.shared.runner import die, have, print_topn, run


def _finding_payload(item: dict[str, Any]) -> dict[str, Any]:
    location = item.get("location") or {}
    return {
        "code": item.get("code") or "?",
        "path": item.get("filename") or "?",
        "line": location.get("row"),
        "message": item.get("message") or "",
    }


def lint_payload(path: Path, *, include_findings: bool = True) -> tuple[int, dict[str, Any], str]:
    """Return the ruff result payload without printing."""
    payload: dict[str, Any] = {
        "command": "lint",
        "schema_version": 1,
        "tool": "ruff",
        "path": str(path),
        "status": "ok",
        "counts": {"findings": 0, "by_code": {}},
        "findings": [],
        "findings_omitted": not include_findings,
        "truncated": False,
    }
    if not have("ruff"):
        payload["status"] = "missing_tool"
        payload["error"] = "ruff not installed"
        return 2, payload, "ruff not installed"

    excludes = ",".join(f"**/{token}/**" for token in SCAN_EXCLUDES)
    rc, out, err = run(
        [
            "ruff",
            "check",
            "--output-format",
            "json",
            "--extend-exclude",
            excludes,
            str(path),
        ]
    )
    if rc != 0 and not out.strip():
        payload["status"] = "error"
        payload["error"] = err.strip()
        return 2, payload, err.strip()
    try:
        items = json.loads(out or "[]")
    except json.JSONDecodeError:
        payload["status"] = "error"
        payload["error"] = out.strip() or err.strip()
        return 1, payload, payload["error"]

    by_code: dict[str, int] = {}
    for item in items:
        code = item.get("code") or "?"
        by_code[code] = by_code.get(code, 0) + 1
    findings = [_finding_payload(item) for item in items[:40]] if include_findings else []
    payload.update(
        {
            "counts": {"findings": len(items), "by_code": by_code},
            "findings": findings,
            "findings_omitted": not include_findings,
            "truncated": include_findings and len(items) > len(findings),
        }
    )
    return 0, payload, ""


def cmd_lint(args: argparse.Namespace) -> int:
    """Run ruff and print a compact lint summary."""
    path = Path(args.path)
    include_findings = not getattr(args, "summary_only", False)
    rc, payload, error = lint_payload(path, include_findings=include_findings)
    if getattr(args, "json", False):
        # --json always emits a parseable payload (status carries the outcome).
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if payload["status"] in ("ok", "skipped") else rc
    if payload["status"] == "missing_tool":
        die("ruff not installed (pip install --user ruff)", 2)
    if payload["status"] == "error":
        print(error, file=sys.stderr)
        return rc

    print(f"== ruff lint on {path} ==")
    counts = payload["counts"]["by_code"]
    total = payload["counts"]["findings"]
    by_code = "  ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
    print(f"findings: {total}" + (f"  {by_code}" if by_code else ""))
    if payload["findings"] and include_findings:
        items = []
        for finding in payload["findings"]:
            loc = f"{finding.get('path', '?')}:{finding.get('line', '?')}"
            items.append(f"[{finding.get('code', '?')}] {loc}  {finding.get('message', '')}")
        print_topn(items)
    return 0
