"""Host-aware parallelism for multi-sensor runs.

Sensors are independent subprocess invocations (semgrep, pyright, vulture, ...)
with no shared mutable state, so a ``codescan all`` pass is embarrassingly
parallel. On a native multi-core host the slow sensor (typically semgrep) bound
the wall-clock; running sensors concurrently collapses the total to roughly the
slowest one.

This replaces the earlier WSL2-era sequential model (single scheduler, one
core) which no longer applies on the native Ubuntu host. The default job count
is capped low so concurrent sensors leave headroom for Ollama, the desktop, and
other agents — the same CPU-safety intent as ``DEV_TEST_WORKERS``, applied to
external sensor processes instead of test runners.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from os import cpu_count, environ
from typing import Callable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

# Cap so a 20-core host runs at most this many sensors at once. External tools
# (semgrep/pyright) are memory- and CPU-heavy; 6 leaves the rest of the machine
# responsive. Overridable per-invocation with --jobs / CODESCAN_JOBS.
_DEFAULT_MAX_JOBS = 6


def _clamp_jobs(value: int) -> int:
    return max(1, value)


def default_jobs() -> int:
    """Resolve the default parallel width.

    Precedence: ``CODESCAN_JOBS`` env var (``0``/``1`` → serial), else
    ``min(_DEFAULT_MAX_JOBS, cpu_count())``. Always >= 1.
    """
    raw = environ.get("CODESCAN_JOBS")
    if raw is not None and raw.strip():
        try:
            return _clamp_jobs(int(raw))
        except ValueError:
            pass  # ignore malformed env, fall through to host-aware default
    return _clamp_jobs(min(_DEFAULT_MAX_JOBS, cpu_count() or 1))


def parallel_map(fn: Callable[[T], R], items: list[T], jobs: int | None = None) -> list[R]:
    """Apply ``fn`` to each item, returning results in input order.

    ``jobs <= 1`` runs serially — the exact pre-parallel behavior, useful for
    debugging and for single-core CI runners. ``jobs >= 2`` dispatches via a
    thread pool; each sensor does its work in a subprocess, so the GIL never
    serializes the expensive part. ``ThreadPoolExecutor.map`` preserves input
    order regardless of completion order, so the aggregated report is stable.
    """
    width = default_jobs() if jobs is None else _clamp_jobs(jobs)
    if width <= 1 or len(items) <= 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=width) as pool:
        return list(pool.map(fn, items))
