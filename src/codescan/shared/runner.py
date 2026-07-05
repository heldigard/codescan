"""Shared utilities: subprocess helpers, tool detection, language detection."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def die(msg: str, code: int = 2) -> None:
    """Print error to stderr and exit."""
    print(f"codescan: {msg}", file=sys.stderr)
    sys.exit(code)


def run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def have(tool: str) -> bool:
    """Check if a tool is available on PATH."""
    return shutil.which(tool) is not None


def version_of(tool: str) -> str:
    """Get the version string of an installed tool."""
    flags = {
        "semgrep": ["--version"],
        "gitleaks": ["version"],
        "vulture": ["--version"],
        "knip": ["--version"],
        "dependency-cruiser": ["--version"],
    }.get(tool, ["--version"])
    try:
        _, out, _ = run([tool] + flags)
        return (out or "?").strip().splitlines()[0][:40]
    except Exception:
        return "?"


def _has_py_markers(p: Path) -> bool:
    """Check if a directory looks like a Python project."""
    return (p / "pyproject.toml").exists() or (p / "requirements.txt").exists() \
        or any(p.glob("*.py"))


def detect_langs(path: Path) -> set[str]:
    """Heuristic: which language ecosystems are present under path (depth 2)."""
    langs: set[str] = set()
    candidates = [path, *path.iterdir()] if path.is_dir() else [path]
    for p in candidates:
        if not p.is_dir():
            continue
        if (p / "package.json").exists():
            langs.add("js")
        if _has_py_markers(p):
            langs.add("py")
    return langs
