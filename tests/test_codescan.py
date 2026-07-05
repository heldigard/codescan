"""CI gate for the codescan quality-sensor orchestrator.

Verifies codescan is installed and its core delegation works on temporary
fixtures. Heavy sensors (semgrep, full knip project) are NOT exercised here —
they need network / a full package.json project and are too slow for the gate.
This asserts: list works, vulture dead-code delegation detects real dead code
and EXCLUDES vendor dirs, and missing-tool paths degrade gracefully.

Safe anywhere; does not mutate the current project.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def run(cmd: list[str], cwd: Path | None = None,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=check)


def test_codescan_list() -> None:
    r = run(["codescan", "list"])
    assert "semgrep" in r.stdout, f"codescan list missing semgrep: {r.stdout}"
    assert "vulture" in r.stdout, f"codescan list missing vulture: {r.stdout}"
    assert "available" in r.stdout, f"codescan list malformed: {r.stdout}"


def test_codescan_dead_detects(fixture_dir: Path) -> None:
    """codescan dead (vulture) must report the real dead symbol AND must NOT
    report symbols planted in __pycache__/.venv (vendor exclusion)."""
    (fixture_dir / "app.py").write_text(
        "import os\n"
        "def live_caller():\n    return helper()\n"
        "def helper():\n    return 1\n"
        "def dead_func():\n    return 999\n"
        "class Unused:\n    pass\n"
    )
    (fixture_dir / "__pycache__").mkdir()
    (fixture_dir / "__pycache__" / "c.py").write_text("def cache_leak():\n    pass\n")
    (fixture_dir / ".venv").mkdir()
    (fixture_dir / ".venv" / "v.py").write_text("def venv_leak():\n    pass\n")

    r = run(["codescan", "dead", "-p", str(fixture_dir), "-l", "py"], check=False)
    assert "dead_func" in r.stdout, f"dead missed dead_func: {r.stdout}"
    assert "__pycache__" not in r.stdout, f"dead leaked __pycache__: {r.stdout}"
    assert ".venv" not in r.stdout, f"dead leaked .venv: {r.stdout}"


def test_codescan_arch_skips_without_config(fixture_dir: Path) -> None:
    """dependency-cruiser must SKIP cleanly (exit 1, not crash) when the project
    has no .dependency-cruiser.cjs — never auto-generate one."""
    r = run(["codescan", "arch", "-p", str(fixture_dir)], check=False)
    assert r.returncode == 1, f"arch should exit 1 without config, got {r.returncode}"
    assert "no .dependency-cruiser" in r.stderr.lower(), (
        f"arch should explain the skip: {r.stderr}"
    )


def main() -> int:
    print("codescan orchestrator smoke test")
    run(["which", "codescan"])

    test_codescan_list()
    print("  codescan list: OK")

    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp) / "proj"
        proj.mkdir()
        test_codescan_dead_detects(proj)
        print("  codescan dead (vulture, vendor-excluded): OK")
        test_codescan_arch_skips_without_config(proj)
        print("  codescan arch (skip without config): OK")

    print("\n✅ all codescan checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
