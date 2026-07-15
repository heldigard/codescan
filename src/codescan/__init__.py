"""codescan — code-quality sensor orchestrator for LLM coding agents."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

# Single source of truth: project.version in pyproject.toml. Avoids the
# __version__/pyproject/test-assertion triplication that silently drifts.
try:
    __version__ = version("codescan-cli")
except PackageNotFoundError:  # not installed (e.g. raw pythonpath run)
    __version__ = "0.0.0+unknown"
