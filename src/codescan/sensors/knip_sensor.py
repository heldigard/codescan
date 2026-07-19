"""knip dead-code sensor (JS/TS)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from codescan.shared.runner import find_upward, have, print_topn, run


def dead_js_payload(
    path: Path, *, include_findings: bool = True
) -> tuple[int, dict[str, Any], str]:
    """Return the knip result payload without printing."""
    payload: dict[str, Any] = {
        "command": "dead",
        "schema_version": 1,
        "tool": "knip",
        "language": "javascript-typescript",
        "path": str(path),
        "status": "ok",
        "counts": {"items": 0},
        "findings": [],
        "findings_omitted": not include_findings,
        "truncated": False,
    }
    if not have("knip"):
        payload["status"] = "skipped"
        payload["reason"] = "knip not installed"
        return 1, payload, "knip not installed — skipping JS/TS dead-code"
    root = find_upward(path, "package.json")
    if root is None:
        payload["status"] = "skipped"
        payload["reason"] = "package.json not found"
        return 1, payload, "knip needs a package.json project — skipping JS/TS dead-code"
    payload["root"] = str(root)
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
        payload["status"] = "error"
        payload["error"] = err.strip()
        return 2, payload, err.strip()
    findings = [{"text": line} for line in lines[:40]] if include_findings else []
    payload.update(
        {
            "counts": {"items": len(lines)},
            "findings": findings,
            "findings_omitted": not include_findings,
            "truncated": include_findings and len(lines) > len(findings),
        }
    )
    if err.strip():
        payload["stderr"] = err.strip()[:120]
    return 0, payload, ""


def cmd_dead_js(path: Path, *, precomputed: tuple[int, dict[str, Any], str] | None = None) -> int:
    """Run knip on a JS/TS project. Requires package.json.

    ``precomputed`` lets the ``all`` orchestrator render a parallel-collected
    result instead of re-running knip.
    """
    if precomputed is None:
        rc, payload, error = dead_js_payload(path)
    else:
        rc, payload, error = precomputed
    if payload["status"] == "skipped":
        print(error, file=sys.stderr)
        return rc
    if payload["status"] == "error":
        print(f"knip error: {error}", file=sys.stderr)
        return rc
    print(f"== knip (JS/TS dead code) on {payload['root']} ==")
    print(f"items: {payload['counts']['items']}")
    print_topn([str(item.get("text", "")) for item in payload["findings"]])
    if payload.get("stderr"):
        print(f"  (knip stderr: {payload['stderr']})", file=sys.stderr)
    return 0
