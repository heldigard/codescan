"""Python type-check sensor (pyright preferred, mypy fallback)."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from codescan.shared.runner import die, have, print_topn, run

_MYPY_RE = re.compile(
    r"^(?P<path>.*?):(?P<line>\d+)(?::\d+)?: (?P<severity>error|warning|note): "
    r"(?P<message>.*?)(?:  \[(?P<code>[^\]]+)\])?$"
)


def _select_tool(tool: str) -> str | None:
    if tool != "auto":
        return tool if have(tool) else None
    if have("pyright"):
        return "pyright"
    if have("mypy"):
        return "mypy"
    return None


def _pyright_command(path: Path) -> list[str]:
    """Honor a project config instead of overriding its include/exclude scope."""
    config = path / "pyrightconfig.json" if path.is_dir() else None
    if config is not None and config.is_file():
        return ["pyright", "--project", str(config), "--outputjson"]
    return ["pyright", str(path), "--outputjson"]


def _pyright_payload(path: Path, include_findings: bool) -> tuple[int, dict[str, Any], str]:
    workdir = path if path.is_dir() else path.parent
    rc, out, err = run(_pyright_command(path), cwd=workdir)
    payload: dict[str, Any] = {
        "command": "type",
        "schema_version": 1,
        "tool": "pyright",
        "path": str(path),
        "status": "ok",
        "counts": {"diagnostics": 0, "by_severity": {}},
        "findings": [],
        "findings_omitted": not include_findings,
        "truncated": False,
    }
    if rc != 0 and not out.strip():
        payload["status"] = "error"
        payload["error"] = err.strip()
        return 2, payload, err.strip()
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        payload["status"] = "error"
        payload["error"] = out.strip() or err.strip()
        return 1, payload, payload["error"]

    diagnostics = data.get("generalDiagnostics", [])
    by_sev: dict[str, int] = {}
    for diag in diagnostics:
        sev = diag.get("severity") or "?"
        by_sev[sev] = by_sev.get(sev, 0) + 1
    findings = []
    if include_findings:
        for diag in diagnostics[:40]:
            start = (diag.get("range") or {}).get("start") or {}
            line = start.get("line")
            findings.append(
                {
                    "severity": diag.get("severity") or "?",
                    "path": diag.get("file") or "?",
                    "line": (line + 1) if isinstance(line, int) else None,
                    "message": diag.get("message") or "",
                    "rule": diag.get("rule"),
                }
            )
    payload.update(
        {
            "counts": {"diagnostics": len(diagnostics), "by_severity": by_sev},
            "findings": findings,
            "truncated": include_findings and len(diagnostics) > len(findings),
        }
    )
    return 0, payload, ""


def _mypy_payload(path: Path, include_findings: bool) -> tuple[int, dict[str, Any], str]:
    workdir = path if path.is_dir() else path.parent
    rc, out, err = run(
        ["mypy", "--show-error-codes", "--no-error-summary", str(path)], cwd=workdir
    )
    payload: dict[str, Any] = {
        "command": "type",
        "schema_version": 1,
        "tool": "mypy",
        "path": str(path),
        "status": "ok",
        "counts": {"diagnostics": 0, "by_severity": {}},
        "findings": [],
        "findings_omitted": not include_findings,
        "truncated": False,
    }
    if rc not in (0, 1):
        payload["status"] = "error"
        payload["error"] = err.strip() or out.strip()
        return 2, payload, payload["error"]

    parsed = []
    by_sev: dict[str, int] = {}
    for line in out.splitlines():
        match = _MYPY_RE.match(line)
        if not match:
            continue
        severity = match.group("severity")
        by_sev[severity] = by_sev.get(severity, 0) + 1
        parsed.append(
            {
                "severity": severity,
                "path": match.group("path"),
                "line": int(match.group("line")),
                "message": match.group("message"),
                "rule": match.group("code"),
            }
        )
    payload.update(
        {
            "counts": {"diagnostics": len(parsed), "by_severity": by_sev},
            "findings": parsed[:40] if include_findings else [],
            "truncated": include_findings and len(parsed) > 40,
        }
    )
    return 0, payload, ""


def type_payload(
    path: Path, tool: str = "auto", *, include_findings: bool = True
) -> tuple[int, dict[str, Any], str]:
    """Return type-check diagnostics from pyright or mypy."""
    selected = _select_tool(tool)
    if selected is None:
        payload: dict[str, Any] = {
            "command": "type",
            "schema_version": 1,
            "tool": tool,
            "path": str(path),
            "status": "missing_tool",
            "counts": {"diagnostics": 0, "by_severity": {}},
            "findings": [],
            "findings_omitted": not include_findings,
            "truncated": False,
            "error": "pyright/mypy not installed" if tool == "auto" else f"{tool} not installed",
        }
        return 2, payload, payload["error"]
    if selected == "pyright":
        return _pyright_payload(path, include_findings)
    return _mypy_payload(path, include_findings)


def cmd_type(args: argparse.Namespace) -> int:
    """Run a Python type checker and print compact diagnostics."""
    path = Path(args.path)
    include_findings = not getattr(args, "summary_only", False)
    rc, payload, error = type_payload(
        path,
        getattr(args, "tool", getattr(args, "type_tool", "auto")),
        include_findings=include_findings,
    )
    if payload["status"] == "missing_tool":
        die(error, 2)
    if payload["status"] == "error":
        print(error, file=sys.stderr)
        return rc
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(f"== {payload['tool']} type check on {path} ==")
    counts = payload["counts"]["by_severity"]
    total = payload["counts"]["diagnostics"]
    by_sev = "  ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
    print(f"diagnostics: {total}" + (f"  {by_sev}" if by_sev else ""))
    if payload["findings"] and include_findings:
        items = []
        for finding in payload["findings"]:
            loc = f"{finding.get('path', '?')}:{finding.get('line', '?')}"
            sev = finding.get("severity", "?")
            rule = finding.get("rule")
            suffix = f" [{rule}]" if rule else ""
            items.append(f"[{sev}] {loc}  {finding.get('message', '')}{suffix}")
        print_topn(items)
    return 0
