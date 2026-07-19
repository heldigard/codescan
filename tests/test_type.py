"""Tests: type sensor (pyright delegation)."""
from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401
from pathlib import Path

import pytest

from ._helpers import _codescan, fake_bin, run  # noqa: F401


def test_codescan_type_json_pyright_is_compact(tmp_path: Path) -> None:
    """Pyright JSON mode carries bounded diagnostic metadata."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    fake_bin(
        bin_dir,
        "pyright",
        "printf '%s\\n' "
        '\'{"generalDiagnostics":[{"severity":"error","file":"app.py",'
        '"range":{"start":{"line":4}},"message":"not assignable",'
        '"rule":"reportAssignmentType"}]}\'\n'
        "exit 1\n",
    )

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(
        _codescan("type", "-p", str(project), "--tool", "pyright", "--json"),
        check=False,
        env=env,
    )

    assert r.returncode == 0, f"type json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "type"
    assert payload["tool"] == "pyright"
    assert payload["counts"] == {"diagnostics": 1, "by_severity": {"error": 1}}
    assert payload["findings"] == [
        {
            "severity": "error",
            "path": "app.py",
            "line": 5,
            "message": "not assignable",
            "rule": "reportAssignmentType",
        }
    ]



def test_type_sensor_uses_scanned_project_as_working_directory(monkeypatch, tmp_path: Path) -> None:
    """Project-local pyright config/imports must not depend on caller cwd."""
    import codescan.sensors.type_sensor as sensor

    captured: dict[str, Path | None] = {}

    def fake_run(_command, *, cwd=None, timeout=None):
        del timeout
        captured["cwd"] = cwd
        return 0, '{"generalDiagnostics":[]}', ""

    monkeypatch.setattr(sensor, "run", fake_run)
    rc, payload, _ = sensor._pyright_payload(tmp_path, include_findings=False)

    assert rc == 0
    assert payload["counts"]["diagnostics"] == 0
    assert captured["cwd"] == tmp_path



def test_type_sensor_honors_project_pyright_scope(monkeypatch, tmp_path: Path) -> None:
    """A directory config owns include/exclude; do not override it with a path arg."""
    import codescan.sensors.type_sensor as sensor

    config = tmp_path / "pyrightconfig.json"
    config.write_text('{"include":["src"],"exclude":["vendor"]}\n', encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(command, *, cwd=None, timeout=None):
        del timeout
        captured.update(command=command, cwd=cwd)
        return 0, '{"generalDiagnostics":[]}', ""

    monkeypatch.setattr(sensor, "run", fake_run)
    rc, payload, _ = sensor._pyright_payload(tmp_path, include_findings=False)

    assert rc == 0
    assert payload["counts"]["diagnostics"] == 0
    assert captured["command"] == [
        "pyright",
        "--project",
        str(config),
        "--outputjson",
    ]
    assert captured["cwd"] == tmp_path



def test_codescan_type_resolves_relative_subdir(tmp_path: Path) -> None:
    """Relative -p dir must not double-resolve against its own cwd.

    Regression: the type sensor ``cd``s into the target dir AND passed the dir
    as the tool arg, so a relative dir re-resolved against itself (``src`` ->
    ``src/src``). pyright/mypy errored on the non-existent path and --json
    emitted nothing — silently breaking the documented ``codescan all -p src``.
    """
    if not shutil.which("pyright") and not shutil.which("mypy"):
        pytest.skip("pyright/mypy not installed")
    sub = tmp_path / "relsub"
    sub.mkdir()
    (sub / "app.py").write_text("x: int = 1\n", encoding="utf-8")

    r = run(_codescan("type", "-p", "relsub", "--json"), cwd=tmp_path, check=False)

    assert r.returncode == 0, f"type rel failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["status"] != "error", f"relative path doubled: {payload}"

