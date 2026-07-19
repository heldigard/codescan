"""Tests: arch sensor + --init. Extracted from the former monolithic test_codescan.py."""
from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401
from pathlib import Path

from ._helpers import _codescan, fake_bin, run  # noqa: F401


def test_codescan_arch_json_skips_without_config(tmp_path: Path) -> None:
    """JSON mode should encode expected arch skips instead of forcing stderr scraping."""
    # Self-contained: a fake depcruise on PATH makes have() True so the sensor
    # reaches the no-config skip path without requiring a real install.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_bin(bin_dir, "depcruise", "exit 0\n")
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(_codescan("arch", "-p", str(tmp_path), "--json"), check=False, env=env)

    assert r.returncode == 0, f"arch json skip failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "arch"
    assert payload["status"] == "skipped"
    assert payload["counts"]["violations"] == 0



def test_codescan_arch_skips_without_config(tmp_path: Path) -> None:
    """dependency-cruiser must SKIP cleanly (exit 1, not crash) when the project
    has no .dependency-cruiser.cjs — never auto-generate one."""
    # Self-contained: fake depcruise so have() is True and the sensor reaches the
    # no-config skip path without requiring a real install.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_bin(bin_dir, "depcruise", "exit 0\n")
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(_codescan("arch", "-p", str(tmp_path)), check=False, env=env)
    assert r.returncode == 1, f"arch should exit 1 without config, got {r.returncode}"
    assert "no .dependency-cruiser" in r.stderr.lower(), f"arch should explain the skip: {r.stderr}"



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
    r = run(_codescan("arch", "-p", str(src)), check=False, env=env)

    assert r.returncode == 0, f"arch sensor failed: stdout={r.stdout} stderr={r.stderr}"
    assert f"warn cwd={project}" in r.stdout, f"depcruise ran from wrong cwd: {r.stdout}"
    assert ".dependency-cruiser.js" in r.stdout, f"arch did not pass JS config: {r.stdout}"



def test_codescan_arch_init_creates_starter(tmp_path: Path) -> None:
    """codescan arch --init writes a starter config; second call refuses to overwrite."""
    r1 = run(_codescan("arch", "--init", "-p", str(tmp_path)), check=False)
    assert r1.returncode == 0, f"init failed: {r1.stderr}"
    assert "wrote:" in r1.stdout, r1.stdout
    starter = tmp_path / ".dependency-cruiser.cjs"
    assert starter.is_file(), "starter config was not written"
    body = starter.read_text()
    assert "dependency-cruiser" in body, "missing dependency-cruiser header"
    assert "doNotFollow" in body, "missing doNotFollow vendor excludes"
    assert "no-cross-feature-imports" in body, "missing vertical-slice rule"

    r2 = run(_codescan("arch", "--init", "-p", str(tmp_path)), check=False)
    assert r2.returncode == 1, "second --init must refuse to overwrite"
    assert "exists, not overwritten" in r2.stderr, r2.stderr

