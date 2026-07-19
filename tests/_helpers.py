"""Shared harness helpers for codescan tests (extracted from the former monolith)."""
from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess
import sys
import tempfile  # noqa: F401
from pathlib import Path


def _codescan(*args: str) -> list[str]:
    return [sys.executable, "-m", "codescan", *args]



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

