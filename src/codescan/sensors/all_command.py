"""`codescan all` orchestration — sequential multi-sensor ship check.

Aggregates secrets/sec/dead/lint/type/arch into one text or JSON report.
Individual sensors remain in their own modules; this file only sequences them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from codescan.sensors.dead_dispatch import dead_payloads, run_dead_sensors


def _run_sensor(fn: Any, args: argparse.Namespace, label: str) -> None:
    """Run one sensor, suppressing SystemExit from missing tools."""
    print(f"\n----- {label} -----")
    try:
        fn(args)
    except SystemExit:
        pass


def offline_skip_payload(path: Path, command: str, sensor: str) -> dict[str, Any]:
    """Emit a 'skipped' payload when --offline excludes a sensor."""
    return {
        "command": command,
        "schema_version": 1,
        "tool": sensor,
        "path": str(path),
        "status": "skipped",
        "reason": f"--offline: {sensor} is the only open-world sensor",
        "counts": {},
        "findings": [],
        "findings_omitted": True,
        "truncated": False,
    }


def summary_payload(sensor_payloads: list[dict[str, Any]]) -> dict[str, int]:
    """Compact aggregate counts for routers."""
    summary = {
        "secrets": 0,
        "sast_findings": 0,
        "dead_items": 0,
        "lint_findings": 0,
        "type_diagnostics": 0,
        "arch_violations": 0,
        "errors": 0,
        "skipped": 0,
    }
    for payload in sensor_payloads:
        counts = payload.get("counts", {})
        summary["secrets"] += int(counts.get("leaks", 0) or 0)
        if payload.get("command") == "sec":
            summary["sast_findings"] += int(counts.get("findings", 0) or 0)
        summary["dead_items"] += int(counts.get("items", 0) or 0)
        if payload.get("command") == "lint":
            summary["lint_findings"] += int(counts.get("findings", 0) or 0)
        if payload.get("command") == "type":
            summary["type_diagnostics"] += int(counts.get("diagnostics", 0) or 0)
        summary["arch_violations"] += int(counts.get("violations", 0) or 0)
        status = payload.get("status")
        if status in ("error", "missing_tool"):
            summary["errors"] += 1
        elif status == "skipped":
            summary["skipped"] += 1
    return summary


def findings_total(summary: dict[str, int]) -> int:
    """Count actionable findings without treating skips or sensor errors as findings."""
    finding_keys = (
        "secrets",
        "sast_findings",
        "dead_items",
        "lint_findings",
        "type_diagnostics",
        "arch_violations",
    )
    return sum(summary[key] for key in finding_keys)


def cmd_all(args: argparse.Namespace) -> int:
    """Run every applicable sensor sequentially. CPU-safe (no parallel)."""
    from codescan.sensors.depcruiser_sensor import arch_payload, cmd_arch
    from codescan.sensors.gitleaks_sensor import cmd_secrets, secrets_payload
    from codescan.sensors.ruff_sensor import cmd_lint, lint_payload
    from codescan.sensors.semgrep_sensor import cmd_sec, sec_payload
    from codescan.sensors.type_sensor import cmd_type, type_payload
    from codescan.shared.runner import detect_langs

    path = Path(args.path)
    langs = detect_langs(path)
    fail_on = getattr(args, "fail_on", "never")
    if fail_on != "never" and not getattr(args, "json", False):
        print("codescan all: --fail-on requires --json", file=sys.stderr)
        return 2
    offline = bool(getattr(args, "offline", False))
    if getattr(args, "json", False):
        include = not getattr(args, "summary_only", False)
        sensors: list[dict[str, Any]] = []
        _, payload, _ = secrets_payload(path, include_findings=include)
        sensors.append(payload)
        if offline:
            sensors.append(offline_skip_payload(path, "sec", "semgrep"))
        else:
            _, payload, _ = sec_payload(path, args.config, include_findings=include)
            sensors.append(payload)
        sensors.extend(dead_payloads(path, langs, args.min_confidence, include_findings=include))
        if "py" in langs:
            _, payload, _ = lint_payload(path, include_findings=include)
            sensors.append(payload)
            _, payload, _ = type_payload(path, args.type_tool, include_findings=include)
            sensors.append(payload)
        _, payload, _ = arch_payload(path, args.target, include_findings=include)
        sensors.append(payload)
        summary = summary_payload(sensors)
        findings = findings_total(summary)
        status = "degraded" if summary["errors"] else "findings" if findings else "ok"
        print(
            json.dumps(
                {
                    "command": "all",
                    "schema_version": 1,
                    "path": str(path),
                    "status": status,
                    "offline": offline,
                    "summary": summary,
                    "sensors": sensors,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        if summary["errors"] and fail_on in ("errors", "findings"):
            return 2
        if findings and fail_on == "findings":
            return 1
        return 0
    print(f"#### codescan all on {path} ####")
    if offline:
        print("(offline mode: skipping semgrep — the only open-world sensor)\n")
    else:
        print()
    _run_sensor(cmd_secrets, args, "secrets")
    if not offline:
        _run_sensor(cmd_sec, args, "SAST")
    print("\n----- dead -----")
    run_dead_sensors(path, langs, args.min_confidence)
    if "py" in langs:
        _run_sensor(cmd_lint, args, "lint")
        _run_sensor(cmd_type, args, "type")
    _run_sensor(cmd_arch, args, "arch")
    return 0
