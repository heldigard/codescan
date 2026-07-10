"""codescan CLI — entry point for the code-quality sensor orchestrator."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codescan import __version__
from codescan.capabilities import capabilities_payload
from codescan.shared.config import SENSORS
from codescan.shared.runner import have, version_of


def cmd_list(_args: argparse.Namespace) -> int:
    """Show available sensors + versions."""
    print(f"{'sensor':<20} {'version':<22} available")
    print("-" * 50)
    for tool in SENSORS:
        avail = "yes" if have(tool) else "NO (install)"
        print(f"{tool:<20} {version_of(tool):<22} {avail}")
    return 0


def cmd_capabilities(_args: argparse.Namespace) -> int:
    """Emit sensor capability metadata for orchestrators."""
    print(json.dumps(capabilities_payload(), ensure_ascii=False, separators=(",", ":")))
    return 0


def _run_sensor(fn, args, label: str) -> None:
    """Run one sensor, suppressing SystemExit from missing tools."""
    print(f"\n----- {label} -----")
    try:
        fn(args)
    except SystemExit:
        pass


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
    if getattr(args, "json", False):
        sensors = []
        _, payload, _ = secrets_payload(path)
        sensors.append(payload)
        _, payload, _ = sec_payload(
            path,
            args.config,
            include_findings=not getattr(args, "summary_only", False),
        )
        sensors.append(payload)
        sensors.extend(_dead_payloads(path, langs, args.min_confidence))
        if "py" in langs:
            _, payload, _ = lint_payload(
                path,
                include_findings=not getattr(args, "summary_only", False),
            )
            sensors.append(payload)
            _, payload, _ = type_payload(
                path,
                args.type_tool,
                include_findings=not getattr(args, "summary_only", False),
            )
            sensors.append(payload)
        _, payload, _ = arch_payload(path, args.target)
        sensors.append(payload)
        summary = _summary_payload(sensors)
        findings = _findings_total(summary)
        status = "degraded" if summary["errors"] else "findings" if findings else "ok"
        print(
            json.dumps(
                {
                    "command": "all",
                    "schema_version": 1,
                    "path": str(path),
                    "status": status,
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
    print(f"#### codescan all on {path} ####\n")
    _run_sensor(cmd_secrets, args, "secrets")
    _run_sensor(cmd_sec, args, "SAST")
    _run_dead_sensors(path, langs, args.min_confidence)
    if "py" in langs:
        _run_sensor(cmd_lint, args, "lint")
        _run_sensor(cmd_type, args, "type")
    _run_sensor(cmd_arch, args, "arch")
    return 0


def _run_dead_sensors(path: Path, langs: set[str], min_confidence: int | None) -> int:
    """Dispatch dead-code sensors for detected languages."""
    from codescan.sensors.knip_sensor import cmd_dead_js
    from codescan.sensors.vulture_sensor import cmd_dead_py

    ran = False
    if "py" in langs:
        ran = True
        cmd_dead_py(path, min_confidence)
    if "js" in langs or "ts" in langs:
        ran = True
        cmd_dead_js(path)
    if not ran:
        print(
            f"no Python/JS/TS project detected under {path} (pass -l py|js|ts to force)",
            file=sys.stderr,
        )
        return 1
    return 0


def _dead_payloads(path: Path, langs: set[str], min_confidence: int | None) -> list[dict]:
    """Run applicable dead-code sensors and return their payloads."""
    from codescan.sensors.knip_sensor import dead_js_payload
    from codescan.sensors.vulture_sensor import dead_py_payload

    payloads: list[dict] = []
    if "py" in langs:
        _, payload, _ = dead_py_payload(path, min_confidence)
        payloads.append(payload)
    if "js" in langs or "ts" in langs:
        _, payload, _ = dead_js_payload(path)
        payloads.append(payload)
    if not payloads:
        payloads.append(
            {
                "command": "dead",
                "schema_version": 1,
                "tool": "auto",
                "path": str(path),
                "status": "skipped",
                "reason": "no Python/JS/TS project detected",
                "counts": {"items": 0},
                "findings": [],
                "truncated": False,
            }
        )
    return payloads


def _summary_payload(sensor_payloads: list[dict]) -> dict[str, int]:
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


def _findings_total(summary: dict[str, int]) -> int:
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


def _cmd_dead(args: argparse.Namespace) -> int:
    """Dead-code dispatch: auto-detect languages, run appropriate sensors."""
    from codescan.shared.runner import detect_langs

    path = Path(args.path)
    langs = {args.lang} if args.lang else detect_langs(path)
    if getattr(args, "json", False):
        sensors = _dead_payloads(path, langs, args.min_confidence)
        print(
            json.dumps(
                {
                    "command": "dead",
                    "schema_version": 1,
                    "path": str(path),
                    "status": "ok"
                    if all(item.get("status") in ("ok", "skipped") for item in sensors)
                    else "degraded",
                    "counts": {
                        "items": sum(item.get("counts", {}).get("items", 0) for item in sensors)
                    },
                    "sensors": sensors,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    return _run_dead_sensors(path, langs, args.min_confidence)


def _add_path(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--path", default=".", help="path to scan (default: cwd)")


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    from codescan.sensors.depcruiser_sensor import cmd_arch
    from codescan.sensors.gitleaks_sensor import cmd_secrets
    from codescan.sensors.ruff_sensor import cmd_lint
    from codescan.sensors.semgrep_sensor import cmd_sec
    from codescan.sensors.type_sensor import cmd_type

    ap = argparse.ArgumentParser(
        prog="codescan",
        description="Code-quality sensor orchestrator (semgrep/gitleaks/vulture/knip/dep-cruiser).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--version", action="version", version=f"codescan {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # list
    list_parser = sub.add_parser("list", help="show available sensors + versions")
    list_parser.set_defaults(func=cmd_list)

    capabilities_parser = sub.add_parser(
        "capabilities",
        help="emit machine-readable sensor capability metadata",
    )
    capabilities_parser.add_argument(
        "--json",
        action="store_true",
        help="accepted for uniform router invocation; output is always JSON",
    )
    capabilities_parser.set_defaults(func=cmd_capabilities)

    # dead
    dead_parser = sub.add_parser("dead", help="dead code (vulture py / knip ts,js)")
    _add_path(dead_parser)
    dead_parser.add_argument(
        "-l", "--lang", default=None, choices=["py", "js", "ts"],
        help="force language (default: auto-detect)",
    )
    dead_parser.add_argument(
        "--min-confidence", type=int, default=None,
        help="vulture min confidence (default: tool.vulture config, else 60)",
    )
    dead_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    dead_parser.set_defaults(func=_cmd_dead)

    # lint
    lint_parser = sub.add_parser("lint", help="fast Python lint checks (ruff)")
    _add_path(lint_parser)
    lint_parser.add_argument("--summary-only", action="store_true", help="counts only")
    lint_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    lint_parser.set_defaults(func=cmd_lint)

    # type
    type_parser = sub.add_parser("type", help="Python type checks (pyright/mypy)")
    _add_path(type_parser)
    type_parser.add_argument(
        "--tool",
        choices=["auto", "pyright", "mypy"],
        default="auto",
        help="type checker to run (default: auto)",
    )
    type_parser.add_argument("--summary-only", action="store_true", help="counts only")
    type_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    type_parser.set_defaults(func=cmd_type)

    # sec
    sec_parser = sub.add_parser("sec", help="SAST bugs+security (semgrep)")
    _add_path(sec_parser)
    sec_parser.add_argument("-c", "--config", default=None, help="semgrep config (default: auto)")
    sec_parser.add_argument("--summary-only", action="store_true", help="counts only")
    sec_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    sec_parser.set_defaults(func=cmd_sec)

    # secrets
    secrets_parser = sub.add_parser("secrets", help="leaked secrets (gitleaks, working tree)")
    _add_path(secrets_parser)
    secrets_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    secrets_parser.set_defaults(func=cmd_secrets)

    # arch
    arch_parser = sub.add_parser("arch", help="architecture/import rules (dependency-cruiser)")
    _add_path(arch_parser)
    arch_parser.add_argument("target", nargs="?", default="src", help="entry to cruise")
    arch_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    arch_parser.set_defaults(func=cmd_arch)

    # all
    all_parser = sub.add_parser("all", help="run every applicable sensor")
    _add_path(all_parser)
    all_parser.add_argument("-c", "--config", default=None, help="semgrep config (default: auto)")
    all_parser.add_argument("--summary-only", action="store_true", help="semgrep counts only")
    all_parser.add_argument(
        "--min-confidence", type=int, default=None,
        help="vulture min confidence (default: tool.vulture config, else 60)",
    )
    all_parser.add_argument(
        "--arch-target", dest="target", default="src",
        help="dependency-cruiser entry to cruise (default: src)",
    )
    all_parser.add_argument(
        "--type-tool",
        choices=["auto", "pyright", "mypy"],
        default="auto",
        help="type checker for Python projects (default: auto)",
    )
    all_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    all_parser.add_argument(
        "--fail-on",
        choices=["never", "errors", "findings"],
        default="never",
        help="JSON mode exit policy: never (default), sensor errors, or any finding",
    )
    all_parser.set_defaults(func=cmd_all)

    return ap


def main() -> int:
    ap = _build_parser()
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
