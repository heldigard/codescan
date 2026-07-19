"""Tests: lint sensor delegation. Extracted from the former monolithic test_codescan.py."""
from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401
from pathlib import Path

from ._helpers import _codescan, fake_bin, run  # noqa: F401


def test_codescan_lint_json_is_compact(tmp_path: Path) -> None:
    """Ruff JSON mode carries bounded lint metadata."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    fake_bin(
        bin_dir,
        "ruff",
        "printf '%s\\n' "
        '\'[{"code":"F401","filename":"app.py",'
        '"location":{"row":3},"message":"imported but unused"}]\'\n',
    )

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(_codescan("lint", "-p", str(project), "--json"), check=False, env=env)

    assert r.returncode == 0, f"lint json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "lint"
    assert payload["tool"] == "ruff"
    assert payload["counts"] == {"findings": 1, "by_code": {"F401": 1}}
    assert payload["findings"] == [
        {
            "code": "F401",
            "path": "app.py",
            "line": 3,
            "message": "imported but unused",
        }
    ]

