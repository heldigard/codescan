"""Shared utilities: subprocess helpers, tool detection, language detection."""

from __future__ import annotations

import shutil
import subprocess
import sys
from os import environ
from pathlib import Path

DEFAULT_BIN_TIMEOUT = 180.0


def _text(value: str | bytes | None) -> str:
    """Normalize subprocess output captured from timeout exceptions."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _env_timeout() -> float:
    """Read the sensor timeout from env, falling back on bad values."""
    raw = environ.get("CODESCAN_BIN_TIMEOUT")
    if raw is None:
        return DEFAULT_BIN_TIMEOUT
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_BIN_TIMEOUT


def die(msg: str, code: int = 2) -> None:
    """Print error to stderr and exit."""
    print(f"codescan: {msg}", file=sys.stderr)
    sys.exit(code)


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr).

    On timeout, returns rc=-1 with a stderr message rather than dying: each
    sensor already handles rc != 0, so this degrades gracefully (the sensor
    reports the timeout and the orchestrator continues with the next one)."""
    timeout = _env_timeout() if timeout is None else timeout
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        tool = cmd[0] if cmd else "command"
        out = _text(exc.stdout)
        err = _text(exc.stderr)
        note = f"{tool} timed out after {int(timeout)}s (set CODESCAN_BIN_TIMEOUT to raise it)"
        if err:
            err = f"{err.rstrip()}\n{note}"
        else:
            err = note
        return (
            -1,
            out,
            err,
        )
    except FileNotFoundError:
        # Defense in depth: every sensor checks `have()` before calling run(),
        # but if a binary vanishes from PATH between that check and the spawn
        # (e.g. CI removes it), or a future sensor forgets the guard, degrade
        # gracefully instead of printing a traceback. rc=127 follows the shell
        # convention for "command not found"; sensors treat rc != 0 as error.
        tool = cmd[0] if cmd else "command"
        return (127, "", f"{tool} not found on PATH")
    return p.returncode, p.stdout, p.stderr


def print_topn(items: list[str], *, max_items: int = 40) -> None:
    """Print up to `max_items` pre-formatted lines (indented two spaces), then
    a `... N more` truncator. Shared by every sensor so the truncation shape is
    identical across dead / sec / secrets / arch output."""
    for line in items[:max_items]:
        print(f"  {line}")
    if len(items) > max_items:
        print(f"  ... {len(items) - max_items} more")


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
    # run() already absorbs subprocess spawn/timeout errors and returns rc;
    # the only remaining failure mode is empty output yielding IndexError on
    # splitlines()[0]. Catch that specific case rather than swallowing bugs.
    try:
        # Some tools (historically gitleaks, npm wrappers) print version on
        # stderr; prefer stdout, fall back to stderr so `list` never shows "?".
        _, out, err = run([tool] + flags, timeout=10)
        first_line = (out or err or "").strip().splitlines()
        return first_line[0][:40] if first_line else "?"
    except (OSError, IndexError):
        return "?"


def find_upward(path: Path, marker: str) -> Path | None:
    """Find nearest ancestor containing marker, starting at path."""
    start = path if path.is_dir() else path.parent
    start = start.expanduser().resolve()
    for candidate in (start, *start.parents):
        if (candidate / marker).exists():
            return candidate
    return None


def _has_py_markers(p: Path) -> bool:
    """Check if a directory looks like a Python project."""
    return (
        (p / "pyproject.toml").exists() or (p / "requirements.txt").exists() or any(p.glob("*.py"))
    )


def detect_langs(path: Path) -> set[str]:
    """Heuristic: which language ecosystems are present under path.

    Checks ``path`` itself and its direct child directories (depth 1) for
    language markers (``package.json`` → js, ``pyproject.toml``/``*.py`` → py).
    Deeper monorepo layouts are not traversed; pass the package root explicitly.
    """
    langs: set[str] = set()
    if not path.exists():
        return langs
    if not path.is_dir():
        if path.suffix == ".py":
            langs.add("py")
        elif path.suffix in (".js", ".ts", ".jsx", ".tsx"):
            langs.add("js")
        return langs

    try:
        candidates = [path, *path.iterdir()]
    except OSError:
        candidates = [path]

    for p in candidates:
        if not p.is_dir():
            continue
        if (p / "package.json").exists():
            langs.add("js")
        if _has_py_markers(p):
            langs.add("py")
    return langs
