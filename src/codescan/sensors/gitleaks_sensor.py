"""gitleaks secret scan sensor — working tree only (--no-git)."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from codescan.shared.config import SCAN_EXCLUDES, SENSITIVE_FILE_PATTERNS, UNSAFE_PATH_EXCLUDES
from codescan.shared.runner import die, have, print_topn, run


def _leak_payload(leak: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": leak.get("RuleID", "?"),
        "file": leak.get("File", "?"),
        "line": leak.get("StartLine"),
    }


def _gitleaks_allowlist_config() -> str:
    # UNSAFE_PATH_EXCLUDES (tmp/temp) collides with OS-standard absolute paths
    # (/tmp, /var/tmp): gitleaks resolves --source to an absolute path and
    # matches `paths` against it, so `(^|/)tmp(/|$)` drops every file under
    # /tmp — pytest tmp_path, CI temp dirs, manual /tmp/... work — and real
    # secrets go undetected (false-negative). Drop those tokens; project-local
    # tmp/ scratch dirs simply get scanned too, the safer default for a secret
    # sensor. Same collision class already fixed for vulture.
    safe_excludes = [item for item in SCAN_EXCLUDES if item not in UNSAFE_PATH_EXCLUDES]
    escaped = [re.escape(item) for item in safe_excludes]
    directory_pattern = rf"(^|/)({'|'.join(escaped)})(/|$)"
    sensitive_file_pattern = rf"(^|/)({'|'.join(SENSITIVE_FILE_PATTERNS)})$"
    return "\n".join(
        [
            "[extend]",
            "useDefault = true",
            "",
            "[allowlist]",
            "paths = [",
            f"  '''{directory_pattern}''',",
            f"  '''{sensitive_file_pattern}''',",
            "]",
            "",
        ]
    )


def _run_gitleaks(path_s: str) -> tuple[int, str, str]:
    """Write the allowlist config to a temp file, run gitleaks, then clean up."""
    config_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".toml", delete=False
        ) as config:
            config.write(_gitleaks_allowlist_config())
            config_path = config.name
        return run(
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


def secrets_payload(
    path: Path, *, include_findings: bool = True
) -> tuple[int, dict[str, Any], str]:
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
        "findings_omitted": not include_findings,
        "truncated": False,
    }
    if not have("gitleaks"):
        payload["status"] = "missing_tool"
        payload["error"] = "gitleaks not installed"
        return 2, payload, "gitleaks not installed"
    rc, out, err = _run_gitleaks(path_s)
    findings: list[dict[str, Any]] = []
    if out.strip():
        try:
            findings = json.loads(out) or []
        except json.JSONDecodeError:
            findings = []
    # gitleaks exit codes: 0 = no leaks, 1 = leaks found, anything else = error
    # (run() returns -1 on timeout, 127 on a vanished binary).
    if rc not in (0, 1) and not findings:
        payload["status"] = "error"
        payload["error"] = err.strip() or f"gitleaks exited {rc}"
        return 2, payload, payload["error"]
    if rc == 1 and not findings:
        # gitleaks signalled leaks (exit 1) but the report did not parse — do
        # NOT report a clean 0 leaks; surface it so real secrets are not missed.
        payload["status"] = "error"
        payload["error"] = "gitleaks reported leaks (exit 1) but report did not parse"
        return 2, payload, payload["error"]
    leaks = [_leak_payload(leak) for leak in findings[:40]] if include_findings else []
    payload.update(
        {
            "counts": {"leaks": len(findings)},
            "findings": leaks,
            "findings_omitted": not include_findings,
            "truncated": include_findings and len(findings) > len(leaks),
        }
    )
    return 0, payload, ""


def cmd_secrets(
    args: argparse.Namespace, *, precomputed: tuple[int, dict[str, Any], str] | None = None
) -> int:
    """gitleaks secret scan on the WORKING TREE. Pass src/, not '.'.

    ``precomputed`` lets the ``all`` orchestrator render a result it already
    collected in parallel instead of re-running the scan.
    """
    path = Path(args.path)
    if precomputed is None:
        rc, payload, error = secrets_payload(path)
    else:
        rc, payload, error = precomputed
    if getattr(args, "json", False):
        # --json always emits a parseable payload (status carries the outcome);
        # never die/return empty, which would break router/worker JSON parsing.
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if payload["status"] in ("ok", "skipped") else rc
    if payload["status"] == "missing_tool":
        die("gitleaks not installed", 2)
    if payload["status"] == "error":
        print(f"gitleaks error: {error}", file=sys.stderr)
        return rc
    print(f"== gitleaks secrets on {path} (working tree, redacted) ==")
    print(f"leaks: {payload['counts']['leaks']}")
    items = [
        f"[{leak.get('rule_id', '?')}] {leak.get('file', '?')}:{leak.get('line', '?')}"
        for leak in payload["findings"]
    ]
    print_topn(items)
    return 0
