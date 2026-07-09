"""gitleaks secret scan sensor — working tree only (--no-git)."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from codescan.shared.config import VENDOR_EXCLUDES
from codescan.shared.runner import die, have, print_topn, run


def _leak_payload(leak: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": leak.get("RuleID", "?"),
        "file": leak.get("File", "?"),
        "line": leak.get("StartLine"),
    }


def _gitleaks_allowlist_config() -> str:
    escaped = [re.escape(item) for item in VENDOR_EXCLUDES]
    path_pattern = rf"(^|/)({'|'.join(escaped)})(/|$)"
    return "\n".join(
        [
            "[extend]",
            "useDefault = true",
            "",
            "[allowlist]",
            "paths = [",
            f"  '''{path_pattern}''',",
            "]",
            "",
        ]
    )


def secrets_payload(path: Path) -> tuple[int, dict[str, Any], str]:
    """Return the gitleaks result payload without printing."""
    path_s = str(path)
    payload: dict[str, Any] = {
        "command": "secrets",
        "schema_version": 1,
        "tool": "gitleaks",
        "path": path_s,
        "status": "ok",
        "redacted": True,
        "counts": {"leaks": 0},
        "findings": [],
        "truncated": False,
    }
    if not have("gitleaks"):
        payload["status"] = "missing_tool"
        payload["error"] = "gitleaks not installed"
        return 2, payload, "gitleaks not installed"
    config_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".toml", delete=False
        ) as config:
            config.write(_gitleaks_allowlist_config())
            config_path = config.name
        rc, out, err = run(
            [
                "gitleaks",
                "detect",
                "--no-git",
                "--source",
                path_s,
                "--config",
                config_path,
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--no-banner",
                "--redact",
            ]
        )
    finally:
        if config_path:
            try:
                Path(config_path).unlink()
            except OSError:
                pass
    findings: list[dict[str, Any]] = []
    if out.strip():
        try:
            findings = json.loads(out) or []
        except json.JSONDecodeError:
            findings = []
    if rc != 0 and not findings and rc != 1:
        payload["status"] = "error"
        payload["error"] = err.strip()
        return 2, payload, err.strip()
    leaks = [_leak_payload(leak) for leak in findings[:40]]
    payload.update(
        {
            "counts": {"leaks": len(findings)},
            "findings": leaks,
            "truncated": len(findings) > len(leaks),
        }
    )
    return 0, payload, ""


def cmd_secrets(args: argparse.Namespace) -> int:
    """gitleaks secret scan on the WORKING TREE. Pass src/, not '.'."""
    path = Path(args.path)
    rc, payload, error = secrets_payload(path)
    if payload["status"] == "missing_tool":
        die("gitleaks not installed", 2)
    if payload["status"] == "error":
        print(f"gitleaks error: {error}", file=sys.stderr)
        return rc
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    print(f"== gitleaks secrets on {path} (working tree, redacted) ==")
    print(f"leaks: {payload['counts']['leaks']}")
    items = [
        f"[{leak.get('rule_id', '?')}] {leak.get('file', '?')}:{leak.get('line', '?')}"
        for leak in payload["findings"]
    ]
    print_topn(items)
    return 0
