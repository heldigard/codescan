"""codescan CLI — entry point for the code-quality sensor orchestrator."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

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


def _run_sensor(fn, args, label: str) -> None:
    """Run one sensor, suppressing SystemExit from missing tools."""
    print(f"\n----- {label} -----")
    try:
        fn(args)
    except SystemExit:
        pass


def cmd_all(args: argparse.Namespace) -> int:
    """Run every applicable sensor sequentially. CPU-safe (no parallel)."""
    from codescan.sensors.depcruiser_sensor import cmd_arch
    from codescan.sensors.gitleaks_sensor import cmd_secrets
    from codescan.sensors.semgrep_sensor import cmd_sec
    from codescan.shared.runner import detect_langs

    path = Path(args.path)
    print(f"#### codescan all on {path} ####\n")
    _run_sensor(cmd_secrets, args, "secrets")
    _run_sensor(cmd_sec, args, "SAST")
    _run_dead_sensors(path, detect_langs(path), args.min_confidence)
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


def _cmd_dead(args: argparse.Namespace) -> int:
    """Dead-code dispatch: auto-detect languages, run appropriate sensors."""
    from codescan.shared.runner import detect_langs

    path = Path(args.path)
    langs = {args.lang} if args.lang else detect_langs(path)
    return _run_dead_sensors(path, langs, args.min_confidence)


def _add_path(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--path", default=".", help="path to scan (default: cwd)")


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    from codescan.sensors.depcruiser_sensor import cmd_arch
    from codescan.sensors.gitleaks_sensor import cmd_secrets
    from codescan.sensors.semgrep_sensor import cmd_sec

    ap = argparse.ArgumentParser(
        prog="codescan",
        description="Code-quality sensor orchestrator (semgrep/gitleaks/vulture/knip/dep-cruiser).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # list
    list_parser = sub.add_parser("list", help="show available sensors + versions")
    list_parser.set_defaults(func=cmd_list)

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
    dead_parser.set_defaults(func=_cmd_dead)

    # sec
    sec_parser = sub.add_parser("sec", help="SAST bugs+security (semgrep)")
    _add_path(sec_parser)
    sec_parser.add_argument("-c", "--config", default=None, help="semgrep config (default: auto)")
    sec_parser.add_argument("--summary-only", action="store_true", help="counts only")
    sec_parser.set_defaults(func=cmd_sec)

    # secrets
    secrets_parser = sub.add_parser("secrets", help="leaked secrets (gitleaks, working tree)")
    _add_path(secrets_parser)
    secrets_parser.set_defaults(func=cmd_secrets)

    # arch
    arch_parser = sub.add_parser("arch", help="architecture/import rules (dependency-cruiser)")
    _add_path(arch_parser)
    arch_parser.add_argument("target", nargs="?", default="src", help="entry to cruise")
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
    all_parser.set_defaults(func=cmd_all)

    return ap


def main() -> int:
    ap = _build_parser()
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
