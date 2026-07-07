"""gitleaks secret scan sensor — working tree only (--no-git)."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from codescan.shared.config import VENDOR_EXCLUDES
from codescan.shared.runner import die, have, print_topn, run


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


def cmd_secrets(args: argparse.Namespace) -> int:
    """gitleaks secret scan on the WORKING TREE. Pass src/, not '.'."""
    if not have("gitleaks"):
        die("gitleaks not installed", 2)
    path = str(Path(args.path))
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
                path,
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
    findings: list = []
    if out.strip():
        try:
            findings = json.loads(out) or []
        except json.JSONDecodeError:
            findings = []
    if rc != 0 and not findings and rc != 1:
        print(f"gitleaks error: {err.strip()}", file=sys.stderr)
        return 2
    print(f"== gitleaks secrets on {path} (working tree, redacted) ==")
    print(f"leaks: {len(findings)}")
    items = [
        f"[{leak.get('RuleID', '?')}] {leak.get('File', '?')}:{leak.get('StartLine', '?')}"
        for leak in findings
    ]
    print_topn(items)
    return 0
