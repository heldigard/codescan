"""CI gate for the codescan quality-sensor orchestrator.

Verifies codescan is installed and its core delegation works on temporary
fixtures. Heavy sensors (semgrep, full knip project) are NOT exercised here —
they need network / a full package.json project and are too slow for the gate.
This asserts: list works, vulture dead-code delegation detects real dead code
and EXCLUDES vendor dirs, and missing-tool paths degrade gracefully.

Safe anywhere; does not mutate the current project.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def run(
    cmd: list[str],
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, check=check)


def fake_bin(path: Path, name: str, body: str) -> None:
    exe = path / name
    exe.write_text("#!/usr/bin/env sh\n" + body)
    exe.chmod(0o755)


def test_codescan_list() -> None:
    r = run(["codescan", "list"])
    assert "semgrep" in r.stdout, f"codescan list missing semgrep: {r.stdout}"
    assert "vulture" in r.stdout, f"codescan list missing vulture: {r.stdout}"
    assert "available" in r.stdout, f"codescan list malformed: {r.stdout}"


def test_all_parser_has_sensor_options() -> None:
    """all reuses sensor functions, so its Namespace must expose their options."""
    from codescan.cli import _build_parser

    args = _build_parser().parse_args(["all"])
    assert args.config is None
    assert args.summary_only is False
    assert args.min_confidence is None
    assert args.target == "src"


def test_codescan_dead_detects(tmp_path: Path) -> None:
    """codescan dead (vulture) must report the real dead symbol AND must NOT
    report symbols planted in __pycache__/.venv (vendor exclusion)."""
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def live_caller():\n    return helper()\n"
        "def helper():\n    return 1\n"
        "def dead_func():\n    return 999\n"
        "class Unused:\n    pass\n"
    )
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "c.py").write_text("def cache_leak():\n    pass\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "v.py").write_text("def venv_leak():\n    pass\n")

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert "dead_func" in r.stdout, f"dead missed dead_func: {r.stdout}"
    assert "__pycache__" not in r.stdout, f"dead leaked __pycache__: {r.stdout}"
    assert ".venv" not in r.stdout, f"dead leaked .venv: {r.stdout}"


def test_codescan_dead_respects_vulture_pyproject(tmp_path: Path) -> None:
    """codescan must pass the nearest pyproject.toml to vulture."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.vulture]\n"
        'ignore_names = ["configured_dead_func"]\n'
        "min_confidence = 60\n"
    )
    (tmp_path / "app.py").write_text(
        "def configured_dead_func():\n    return 1\n"
        "def ordinary_dead_func():\n    return 2\n"
    )

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert r.returncode == 0, f"dead failed: stdout={r.stdout} stderr={r.stderr}"
    assert "configured_dead_func" not in r.stdout, f"vulture config was ignored: {r.stdout}"
    assert "ordinary_dead_func" in r.stdout, f"expected normal vulture finding: {r.stdout}"


def test_codescan_dead_ignores_pep562_module_hooks(tmp_path: Path) -> None:
    """PEP 562 module hooks are public protocol hooks, not dead functions."""
    (tmp_path / "app.py").write_text(
        "def __getattr__(name):\n    raise AttributeError(name)\n"
        "def __dir__():\n    return []\n"
        "def ordinary_dead_func():\n    return 2\n"
    )

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert r.returncode == 0, f"dead failed: stdout={r.stdout} stderr={r.stderr}"
    assert "__getattr__" not in r.stdout, f"PEP 562 __getattr__ leaked: {r.stdout}"
    assert "__dir__" not in r.stdout, f"PEP 562 __dir__ leaked: {r.stdout}"
    assert "ordinary_dead_func" in r.stdout, f"expected normal vulture finding: {r.stdout}"


def test_codescan_arch_skips_without_config(tmp_path: Path) -> None:
    """dependency-cruiser must SKIP cleanly (exit 1, not crash) when the project
    has no .dependency-cruiser.cjs — never auto-generate one."""
    r = run(["codescan", "arch", "-p", str(tmp_path)], check=False)
    assert r.returncode == 1, f"arch should exit 1 without config, got {r.returncode}"
    assert "no .dependency-cruiser" in r.stderr.lower(), f"arch should explain the skip: {r.stderr}"


def test_codescan_dead_js_runs_knip_from_package_root(tmp_path: Path) -> None:
    """knip must execute from the package root even when -p points at src/."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    src = project / "src"
    bin_dir.mkdir()
    src.mkdir(parents=True)
    (project / "package.json").write_text("{}")
    fake_bin(bin_dir, "knip", 'printf "warn cwd=%s\\n" "$(pwd)"\n')

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "dead", "-p", str(src), "-l", "js"], check=False, env=env)

    assert r.returncode == 0, f"knip sensor failed: stdout={r.stdout} stderr={r.stderr}"
    assert f"warn cwd={project}" in r.stdout, f"knip did not run in package root: {r.stdout}"


def test_codescan_arch_uses_js_config_and_project_root(tmp_path: Path) -> None:
    """dependency-cruiser must honor .dependency-cruiser.js and run at its root."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    src = project / "src"
    bin_dir.mkdir()
    src.mkdir(parents=True)
    (project / ".dependency-cruiser.js").write_text("module.exports = {};")
    fake_bin(bin_dir, "depcruise", 'printf "warn cwd=%s args=%s\\n" "$(pwd)" "$*"\n')

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "arch", "-p", str(src)], check=False, env=env)

    assert r.returncode == 0, f"arch sensor failed: stdout={r.stdout} stderr={r.stderr}"
    assert f"warn cwd={project}" in r.stdout, f"depcruise ran from wrong cwd: {r.stdout}"
    assert ".dependency-cruiser.js" in r.stdout, f"arch did not pass JS config: {r.stdout}"


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
