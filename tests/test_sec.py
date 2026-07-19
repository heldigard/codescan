"""Tests: sec sensor (semgrep delegation). Extracted from the former monolithic test_codescan.py."""
from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401
from pathlib import Path

from ._helpers import _codescan, fake_bin, run  # noqa: F401


def test_codescan_sec_json_is_compact(tmp_path: Path) -> None:
    """Semgrep JSON mode carries counts and bounded finding metadata."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    fake_bin(
        bin_dir,
        "semgrep",
        "printf '%s\\n' "
        '\'{"results":[{"check_id":"python.lang.security.audit.dynamic-urllib-use-detected",'
        '"path":"app.py","start":{"line":12},'
        '"extra":{"severity":"WARNING","message":"dynamic urllib"}}]}\'\n',
    )

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(_codescan("sec", "-p", str(project), "--json"), check=False, env=env)

    assert r.returncode == 0, f"sec json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "sec"
    assert payload["counts"] == {"findings": 1, "by_severity": {"WARNING": 1}}
    assert payload["findings"] == [
        {
            "severity": "WARNING",
            "path": "app.py",
            "line": 12,
            "check_id": "python.lang.security.audit.dynamic-urllib-use-detected",
            "message": "dynamic urllib",
        }
    ]
    assert payload["findings_omitted"] is False

