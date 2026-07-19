"""codescan CLI — entry point for the code-quality sensor orchestrator.

Thin surface: list/capabilities + argparse wiring. Sensor orchestration lives
in sensors/* (one file per sensor) and all_command / dead_dispatch for multi-
sensor flows.
"""

from __future__ import annotations

import argparse
import json
import sys

from codescan import __version__
from codescan.capabilities import capabilities_payload
from codescan.sensors.all_command import cmd_all
from codescan.sensors.dead_dispatch import cmd_dead
from codescan.shared.config import SENSORS
from codescan.shared.runner import have, version_of


def cmd_list(args: argparse.Namespace) -> int:
    """Show available sensors + versions (text table or compact JSON)."""
    rows = []
    for tool in SENSORS:
        available = have(tool)
        rows.append(
            {
                "sensor": tool,
                "version": version_of(tool) if available else None,
                "available": available,
            }
        )
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "command": "list",
                    "schema_version": 1,
                    "sensors": rows,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return 0
    print(f"{'sensor':<20} {'version':<22} available")
    print("-" * 50)
    for row in rows:
        avail = "yes" if row["available"] else "NO (install)"
        version = row["version"] or "?"
        print(f"{row['sensor']:<20} {version:<22} {avail}")
    return 0


def cmd_capabilities(_args: argparse.Namespace) -> int:
    """Emit sensor capability metadata for orchestrators."""
    print(json.dumps(capabilities_payload(), ensure_ascii=False, separators=(",", ":")))
    return 0


def _add_path(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--path", default=".", help="path to scan (default: cwd)")


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    # vs-soft-allow — argparse subparser tree; one responsibility (CLI surface).
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

    list_parser = sub.add_parser("list", help="show available sensors + versions")
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="emit compact JSON (sensor name, version, available) for routers",
    )
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

    dead_parser = sub.add_parser("dead", help="dead code (vulture py / knip ts,js)")
    _add_path(dead_parser)
    dead_parser.add_argument(
        "-l",
        "--lang",
        default=None,
        choices=["py", "js", "ts"],
        help="force language (default: auto-detect)",
    )
    dead_parser.add_argument(
        "--min-confidence",
        type=int,
        default=None,
        help="vulture min confidence (default: tool.vulture config, else 60)",
    )
    dead_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    dead_parser.set_defaults(func=cmd_dead)

    lint_parser = sub.add_parser("lint", help="fast Python lint checks (ruff)")
    _add_path(lint_parser)
    lint_parser.add_argument("--summary-only", action="store_true", help="counts only")
    lint_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    lint_parser.set_defaults(func=cmd_lint)

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

    sec_parser = sub.add_parser("sec", help="SAST bugs+security (semgrep)")
    _add_path(sec_parser)
    sec_parser.add_argument("-c", "--config", default=None, help="semgrep config (default: auto)")
    sec_parser.add_argument("--summary-only", action="store_true", help="counts only")
    sec_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    sec_parser.set_defaults(func=cmd_sec)

    secrets_parser = sub.add_parser("secrets", help="leaked secrets (gitleaks, working tree)")
    _add_path(secrets_parser)
    secrets_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    secrets_parser.set_defaults(func=cmd_secrets)

    arch_parser = sub.add_parser("arch", help="architecture/import rules (dependency-cruiser)")
    _add_path(arch_parser)
    arch_parser.add_argument("target", nargs="?", default="src", help="entry to cruise")
    arch_parser.add_argument(
        "--init",
        action="store_true",
        help="write a starter .dependency-cruiser.cjs; refuses to overwrite",
    )
    arch_parser.add_argument("--json", action="store_true", help="emit compact JSON")
    arch_parser.set_defaults(func=cmd_arch)

    all_parser = sub.add_parser("all", help="run every applicable sensor")
    _add_path(all_parser)
    all_parser.add_argument("-c", "--config", default=None, help="semgrep config (default: auto)")
    all_parser.add_argument("--summary-only", action="store_true", help="semgrep counts only")
    all_parser.add_argument(
        "--min-confidence",
        type=int,
        default=None,
        help="vulture min confidence (default: tool.vulture config, else 60)",
    )
    all_parser.add_argument(
        "--arch-target",
        dest="target",
        default="src",
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
    all_parser.add_argument(
        "--offline",
        action="store_true",
        help="skip semgrep (the only open-world sensor); much faster, sandboxed. "
        "Also set by CODESCAN_OFFLINE=1 for sandboxed agents without flag plumbing",
    )
    all_parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        help="max sensors to run in parallel (default: host-aware, "
        "min(6, cores); CODESCAN_JOBS env; 1 = sequential)",
    )
    all_parser.add_argument(
        "--skip",
        default="",
        help="comma-separated sensors to omit entirely from the run "
        "(secrets,sec,dead,lint,type,arch); dropped sensors do not appear "
        "in JSON. Use to skip the slow open-world sensor without --offline "
        "semantics, e.g. --skip sec,arch",
    )
    all_parser.set_defaults(func=cmd_all)

    return ap


def main() -> int:
    ap = _build_parser()
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
