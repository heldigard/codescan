"""gitleaks secret scan sensor — working tree only (--no-git)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codescan.shared.runner import die, have, print_topn, run


def cmd_secrets(args: argparse.Namespace) -> int:
    """gitleaks secret scan on the WORKING TREE. Pass src/, not '.'."""
    if not have("gitleaks"):
        die("gitleaks not installed", 2)
    path = str(Path(args.path))
    rc, out, err = run(
        [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            path,
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
            "--redact",
        ]
    )
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
