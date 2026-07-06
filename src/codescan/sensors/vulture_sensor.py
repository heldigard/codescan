"""vulture dead-code sensor (Python)."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from codescan.shared.config import VENDOR_EXCLUDES
from codescan.shared.runner import find_upward, have, print_topn, run

_DEFAULT_MIN_CONFIDENCE = 60
_DEFAULT_IGNORE_NAMES = ["__getattr__", "__dir__"]
_VULTURE_UNSAFE_EXCLUDES = {"tmp", "temp"}


def _vulture_settings(config: Path | None) -> dict:
    """Read [tool.vulture] settings when available."""
    if config is None:
        return {}
    try:
        with config.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    settings = data.get("tool", {}).get("vulture", {})
    return settings if isinstance(settings, dict) else {}


def _vulture_excludes(settings: dict) -> list[str]:
    """Merge codescan vendor excludes with project-level Vulture excludes."""
    excludes = [
        exclude for exclude in VENDOR_EXCLUDES if exclude not in _VULTURE_UNSAFE_EXCLUDES
    ]
    project_excludes = settings.get("exclude", [])
    if isinstance(project_excludes, list):
        excludes.extend(str(exclude) for exclude in project_excludes)
    return list(dict.fromkeys(excludes))


def _vulture_ignore_names(settings: dict) -> list[str]:
    """Merge module-hook names with project-level Vulture ignore names."""
    ignore_names = [*_DEFAULT_IGNORE_NAMES]
    project_ignore_names = settings.get("ignore_names", [])
    if isinstance(project_ignore_names, list):
        ignore_names.extend(str(name) for name in project_ignore_names)
    return list(dict.fromkeys(ignore_names))


def _vulture_command(path: Path, min_confidence: int | None) -> tuple[list[str], int | str]:
    config_root = find_upward(path, "pyproject.toml")
    config = config_root / "pyproject.toml" if config_root is not None else None
    settings = _vulture_settings(config)
    command = ["vulture", str(path)]
    if config is not None:
        command.extend(["--config", str(config)])

    effective_confidence: int | str
    if min_confidence is not None:
        effective_confidence = min_confidence
        command.extend(["--min-confidence", str(min_confidence)])
    elif "min_confidence" in settings:
        effective_confidence = settings["min_confidence"]
    else:
        effective_confidence = _DEFAULT_MIN_CONFIDENCE
        command.extend(["--min-confidence", str(_DEFAULT_MIN_CONFIDENCE)])

    command.extend(["--exclude", ",".join(_vulture_excludes(settings))])
    command.extend(["--ignore-names", ",".join(_vulture_ignore_names(settings))])
    return command, effective_confidence


def cmd_dead_py(path: Path, min_confidence: int | None) -> int:
    """Run vulture on a Python project."""
    if not have("vulture"):
        print("vulture not installed — skipping Python dead-code", file=sys.stderr)
        return 1
    command, effective_confidence = _vulture_command(path, min_confidence)
    rc, out, err = run(command)
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    if rc != 0 and not lines:
        print(f"vulture error: {err.strip()}", file=sys.stderr)
        return 2
    print(f"== vulture (Python dead code, min-confidence {effective_confidence}) on {path} ==")
    print(f"items: {len(lines)}")
    print_topn(lines)
    return 0
