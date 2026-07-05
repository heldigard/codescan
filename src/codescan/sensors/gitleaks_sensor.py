"""gitleaks secret scan sensor — working tree only (--no-git)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codescan.shared.runner import die, have, run


def cmd_secrets(args: argparse.Namespace) -> int:
    """gitleaks secret scan on the WORKING TREE. Pass src/, not '.'."""
    if not have("gitleaks"):
        die("gitleaks not installed", 2)
    path = str(Path(args.path))
    rc, out, err = run([
        "gitleaks", "detect", "--no-git", "--source", path,
        "--report-format", "json", "--report-path", "-",
        "--no-banner", "--redact",
    ])
    findings: list = []
    if out.strip():
        try:
            findings = json.loads(out) or []
        except json.JSONDecodeError:
            findings = []
    print(f"== gitleaks secrets on {path} (working tree, redacted) ==")
    print(f"leaks: {len(findings)}")
    for f in findings[:40]:
        rule = f.get("RuleID", "?")
        loc = f.get("File", "?") + ":" + str(f.get("StartLine", "?"))
        print(f"  [{rule}] {loc}")
    if len(findings) > 40:
        print(f"  ... {len(findings) - 40} more")
    if rc == 2 and not findings:
        print(f"gitleaks note: {err.strip()}", file=sys.stderr)
    return 0
