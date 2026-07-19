"""Dead-code sensor dispatch (vulture/knip orchestration).

Owns language detection routing for `codescan dead` and the dead section of
`codescan all`. Sensor implementations stay in vulture_sensor / knip_sensor.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable


def run_dead_sensors(path: Path, langs: set[str], min_confidence: int | None) -> int:
    """Dispatch dead-code sensors for detected languages (text mode)."""
    from codescan.sensors.knip_sensor import cmd_dead_js
    from codescan.sensors.vulture_sensor import cmd_dead_py

    ran = False
    if "py" in langs:
        ran = True
        cmd_dead_py(path, min_confidence)
    if "js" in langs or "ts" in langs:
        ran = True
        cmd_dead_js(path)
    if not ran:
        print(
            f"no Python/JS/TS project detected under {path} (pass -l py|js|ts to force)",
            file=sys.stderr,
        )
        return 1
    return 0


def dead_results(
    path: Path,
    langs: set[str],
    min_confidence: int | None,
    *,
    include_findings: bool = True,
) -> list[tuple[int, dict[str, Any], str]]:
    """Run applicable dead-code sensors, returning ``(rc, payload, error)`` tuples.

    Tuple form (vs. :func:`dead_payloads`) lets the ``all`` orchestrator run
    these concurrently with the other sensors and stamp per-sensor timing
    without a second pass. Language ordering is stable: Python first, then
    JS/TS — :func:`dead_payloads` and the text renderer rely on that order.

    When both ecosystems are present, vulture and knip run in parallel (native
    multi-core host): they are independent subprocesses with no shared state.
    """
    from codescan.sensors.knip_sensor import dead_js_payload
    from codescan.sensors.vulture_sensor import dead_py_payload
    from codescan.shared.concurrency import parallel_map

    producers: list[Callable[[], tuple[int, dict[str, Any], str]]] = []
    if "py" in langs:
        producers.append(
            lambda: dead_py_payload(path, min_confidence, include_findings=include_findings)
        )
    if "js" in langs or "ts" in langs:
        producers.append(lambda: dead_js_payload(path, include_findings=include_findings))
    if not producers:
        return []
    if len(producers) == 1:
        return [producers[0]()]
    # Two independent sensors — parallelize; order preserved by parallel_map.
    return parallel_map(lambda produce: produce(), producers, jobs=len(producers))


def dead_payloads(
    path: Path,
    langs: set[str],
    min_confidence: int | None,
    *,
    include_findings: bool = True,
) -> list[dict[str, Any]]:
    """Run applicable dead-code sensors and return their payloads.

    Thin projection over :func:`dead_results` (payloads only). When no
    Python/JS/TS project is detected, emits one ``skipped`` payload so the
    ``all`` JSON report still carries a typed dead section.
    """
    payloads = [
        result[1]
        for result in dead_results(path, langs, min_confidence, include_findings=include_findings)
    ]
    if not payloads:
        payloads.append(
            {
                "command": "dead",
                "schema_version": 1,
                "tool": "auto",
                "path": str(path),
                "status": "skipped",
                "reason": "no Python/JS/TS project detected",
                "counts": {"items": 0},
                "findings": [],
                "findings_omitted": not include_findings,
                "truncated": False,
            }
        )
    return payloads


def cmd_dead(args: argparse.Namespace) -> int:
    """Dead-code dispatch: auto-detect languages, run appropriate sensors."""
    from codescan.shared.runner import detect_langs

    path = Path(args.path)
    langs = {args.lang} if args.lang else detect_langs(path)
    if getattr(args, "json", False):
        sensors = dead_payloads(path, langs, args.min_confidence)
        print(
            json.dumps(
                {
                    "command": "dead",
                    "schema_version": 1,
                    "path": str(path),
                    "status": "ok"
                    if all(item.get("status") in ("ok", "skipped") for item in sensors)
                    else "degraded",
                    "counts": {
                        "items": sum(item.get("counts", {}).get("items", 0) for item in sensors)
                    },
                    "sensors": sensors,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    return run_dead_sensors(path, langs, args.min_confidence)
