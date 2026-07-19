# vs-soft-allow — _build_sections is a single-responsibility ordered section table
"""`codescan all` orchestration — parallel multi-sensor ship check.

Aggregates secrets/sec/dead/lint/type/arch into one text or JSON report.
Sensors are independent subprocess invocations with no shared mutable state,
so a pass runs concurrently on a native multi-core host: total wall-clock
collapses to roughly the slowest sensor (typically semgrep) instead of the
sum of all of them. ``--jobs`` / ``CODESCAN_JOBS`` bounds the width; ``jobs<=1``
reproduces the exact pre-parallel sequential behavior. Individual sensor
implementations stay in their own modules; this file only schedules and
renders.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

from codescan.sensors.dead_dispatch import dead_results
from codescan.shared.concurrency import default_jobs, parallel_map


def offline_skip_payload(path: Path, command: str, sensor: str) -> dict[str, Any]:
    """Emit a 'skipped' payload when --offline excludes a sensor."""
    return {
        "command": command,
        "schema_version": 1,
        "tool": sensor,
        "path": str(path),
        "status": "skipped",
        "reason": f"--offline: {sensor} is the only open-world sensor",
        "counts": {},
        "findings": [],
        "findings_omitted": True,
        "truncated": False,
    }


def _dead_skip_payload(path: Path, include_findings: bool) -> dict[str, Any]:
    """Typed 'skipped' dead section when no Python/JS/TS project is detected."""
    return {
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


# A producer returns the (rc, payload, error) tuples for one section. Most
# sections yield exactly one; dead may yield one per detected language.
Producer = Callable[[], list[tuple[int, dict[str, Any], str]]]

# Sensors a user may drop with `--skip`. Closed set so typos are caught.
_SKIPABLE: frozenset[str] = frozenset({"secrets", "sec", "dead", "lint", "type", "arch"})


def _parse_skip(raw: str) -> set[str]:
    """Parse a comma-separated --skip value into a validated sensor-name set.

    Unknown names are dropped with a stderr warning rather than failing the run,
    so a typo does not abort a long scan; the valid names are echoed so the
    typo is obvious.
    """
    requested = {token.strip() for token in (raw or "").split(",") if token.strip()}
    unknown = requested - _SKIPABLE
    if unknown:
        print(
            f"codescan all: ignoring unknown --skip sensor(s) {sorted(unknown)} "
            f"(valid: {sorted(_SKIPABLE)})",
            file=sys.stderr,
        )
    return requested & _SKIPABLE


def _section(key: str, label: str, produce: Producer) -> dict[str, Any]:
    return {"key": key, "label": label, "produce": produce}


def _dead_produce(
    path: Path,
    langs: set[str],
    min_confidence: int | None,
    include: bool,
) -> list[tuple[int, dict[str, Any], str]]:
    """Dead section results, synthesizing a typed skip when no language matched."""
    results = dead_results(path, langs, min_confidence, include_findings=include)
    if results:
        return results
    return [(1, _dead_skip_payload(path, include), "no Python/JS/TS project detected")]


def _build_sections(
    args: argparse.Namespace,
    path: Path,
    langs: set[str],
    include: bool,
    offline: bool,
) -> list[dict[str, Any]]:
    """Ordered sensor sections for this run.

    Order is stable (secrets, sec, dead, lint, type, arch) so the text report
    and the JSON ``sensors`` array read top-to-bottom identically every run,
    regardless of which sensor finishes first under parallel scheduling.
    """
    from codescan.sensors.depcruiser_sensor import arch_payload
    from codescan.sensors.gitleaks_sensor import secrets_payload
    from codescan.sensors.ruff_sensor import lint_payload
    from codescan.sensors.semgrep_sensor import sec_payload
    from codescan.sensors.type_sensor import type_payload

    min_confidence = getattr(args, "min_confidence", None)
    sections: list[dict[str, Any]] = [
        _section("secrets", "secrets", lambda: [secrets_payload(path, include_findings=include)]),
    ]
    if offline:
        sections.append(
            _section("sec", "SAST", lambda: [(0, offline_skip_payload(path, "sec", "semgrep"), "")])
        )
    else:
        sections.append(
            _section(
                "sec", "SAST", lambda: [sec_payload(path, args.config, include_findings=include)]
            )
        )
    sections.append(
        _section("dead", "dead", lambda: _dead_produce(path, langs, min_confidence, include))
    )
    if "py" in langs:
        sections.append(
            _section("lint", "lint", lambda: [lint_payload(path, include_findings=include)])
        )
        sections.append(
            _section(
                "type",
                "type",
                lambda: [type_payload(path, args.type_tool, include_findings=include)],
            )
        )
    sections.append(
        _section(
            "arch", "arch", lambda: [arch_payload(path, args.target, include_findings=include)]
        )
    )
    skip = _parse_skip(getattr(args, "skip", "") or "")
    return [section for section in sections if section["key"] not in skip]


def _run_section(section: dict[str, Any]) -> list[tuple[int, dict[str, Any], str]]:
    """Execute one section's producer, stamping wall-clock ``duration_ms`` per payload.

    Timing wraps the whole producer (subprocess spawn + parse), which is the
    number a router cares about when deciding which sensor is slow.
    """
    start = time.perf_counter()
    results = section["produce"]()
    duration_ms = int((time.perf_counter() - start) * 1000)
    for result in results:
        result[1]["duration_ms"] = duration_ms
    return results


def _collect(
    args: argparse.Namespace, langs: set[str], jobs: int | None
) -> tuple[list[dict[str, Any]], list[list[tuple[int, dict[str, Any], str]]]]:
    """Run all sections in parallel; return (sections, per-section results).

    Results stay grouped by section so the text renderer can walk
    section→results directly. ``parallel_map`` preserves order regardless of
    completion order, and falls back to serial when ``jobs<=1``.
    """
    path = Path(args.path)
    include = not getattr(args, "summary_only", False)
    offline = bool(getattr(args, "offline", False))
    sections = _build_sections(args, path, langs, include, offline)
    return sections, parallel_map(_run_section, sections, jobs=jobs)


def summary_payload(sensor_payloads: list[dict[str, Any]]) -> dict[str, int]:
    """Compact aggregate counts for routers."""
    summary = {
        "secrets": 0,
        "sast_findings": 0,
        "dead_items": 0,
        "lint_findings": 0,
        "type_diagnostics": 0,
        "arch_violations": 0,
        "errors": 0,
        "skipped": 0,
    }
    for payload in sensor_payloads:
        _accumulate(summary, payload)
    return summary


def _accumulate(summary: dict[str, int], payload: dict[str, Any]) -> None:
    """Fold one sensor payload into the aggregate summary."""
    counts = payload.get("counts", {})
    command = payload.get("command")
    summary["secrets"] += int(counts.get("leaks", 0) or 0)
    if command == "sec":
        summary["sast_findings"] += int(counts.get("findings", 0) or 0)
    # Guard on command == "dead": only dead payloads use the ``items`` key.
    # Counting it unconditionally would misattribute if another sensor ever
    # reused that key.
    if command == "dead":
        summary["dead_items"] += int(counts.get("items", 0) or 0)
    if command == "lint":
        summary["lint_findings"] += int(counts.get("findings", 0) or 0)
    if command == "type":
        summary["type_diagnostics"] += int(counts.get("diagnostics", 0) or 0)
    if command == "arch":
        summary["arch_violations"] += int(counts.get("violations", 0) or 0)
    status = payload.get("status")
    if status in ("error", "missing_tool"):
        summary["errors"] += 1
    elif status == "skipped":
        summary["skipped"] += 1


def findings_total(summary: dict[str, int]) -> int:
    """Count actionable findings without treating skips or sensor errors as findings."""
    finding_keys = (
        "secrets",
        "sast_findings",
        "dead_items",
        "lint_findings",
        "type_diagnostics",
        "arch_violations",
    )
    return sum(summary[key] for key in finding_keys)


def _render_section(
    key: str, results: list[tuple[int, dict[str, Any], str]], args: argparse.Namespace
) -> None:
    """Render one already-computed section as text. Caller swallows SystemExit."""
    from codescan.sensors.depcruiser_sensor import cmd_arch
    from codescan.sensors.gitleaks_sensor import cmd_secrets
    from codescan.sensors.ruff_sensor import cmd_lint
    from codescan.sensors.type_sensor import cmd_type

    if key == "secrets":
        cmd_secrets(args, precomputed=results[0])
    elif key == "sec":
        _render_sec(results[0], args)
    elif key == "dead":
        _render_dead(results, args)
    elif key == "lint":
        cmd_lint(args, precomputed=results[0])
    elif key == "type":
        cmd_type(args, precomputed=results[0])
    elif key == "arch":
        cmd_arch(args, precomputed=results[0])


def _render_sec(result: tuple[int, dict[str, Any], str], args: argparse.Namespace) -> None:
    """Render the SAST section, surfacing offline skips without re-running semgrep."""
    from codescan.sensors.semgrep_sensor import cmd_sec

    payload = result[1]
    if payload.get("status") == "skipped":
        print(f"skipped: {payload.get('reason', '')}")
        return
    cmd_sec(args, precomputed=result)


def _render_dead(results: list[tuple[int, dict[str, Any], str]], args: argparse.Namespace) -> None:
    """Render each dead sub-sensor (Python vulture and/or JS/TS knip)."""
    from codescan.sensors.knip_sensor import cmd_dead_js
    from codescan.sensors.vulture_sensor import cmd_dead_py

    for result in results:
        rc, payload, error = result
        if payload.get("status") == "skipped":
            print(error or payload.get("reason", ""), file=sys.stderr)
            continue
        _render_one_dead(cmd_dead_py, cmd_dead_js, rc, payload, error, args)


def _render_one_dead(
    cmd_dead_py: Callable[..., int],
    cmd_dead_js: Callable[..., int],
    rc: int,
    payload: dict[str, Any],
    error: str,
    args: argparse.Namespace,
) -> None:
    """Dispatch one dead payload to its language renderer."""
    section_path = Path(payload.get("path", args.path))
    precomputed = (rc, payload, error)
    language = payload.get("language")
    if language == "python":
        cmd_dead_py(section_path, payload.get("min_confidence"), precomputed=precomputed)
    elif language == "javascript-typescript":
        cmd_dead_js(section_path, precomputed=precomputed)


def cmd_all(args: argparse.Namespace) -> int:
    """Run every applicable sensor in parallel (host-aware; ``--jobs`` bounds width)."""
    from codescan.shared.runner import detect_langs

    path = Path(args.path)
    langs = detect_langs(path)
    fail_on = getattr(args, "fail_on", "never")
    if fail_on != "never" and not getattr(args, "json", False):
        print("codescan all: --fail-on requires --json", file=sys.stderr)
        return 2
    jobs = getattr(args, "jobs", None)
    effective_jobs = jobs if jobs is not None else default_jobs()
    sections, per_section = _collect(args, langs, jobs)

    sensors = [result[1] for section_results in per_section for result in section_results]
    summary = summary_payload(sensors)
    findings = findings_total(summary)

    if getattr(args, "json", False):
        return _emit_json(args, path, summary, findings, sensors, effective_jobs)
    _emit_text(args, path, sections, per_section)
    return 0


def _emit_json(
    args: argparse.Namespace,
    path: Path,
    summary: dict[str, int],
    findings: int,
    sensors: list[dict[str, Any]],
    effective_jobs: int,
) -> int:
    """Print the aggregated JSON handoff and apply the --fail-on exit policy."""
    offline = bool(getattr(args, "offline", False))
    fail_on = getattr(args, "fail_on", "never")
    status = "degraded" if summary["errors"] else "findings" if findings else "ok"
    print(
        json.dumps(
            {
                "command": "all",
                "schema_version": 1,
                "path": str(path),
                "status": status,
                "offline": offline,
                "jobs": effective_jobs,
                "summary": summary,
                "sensors": sensors,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    if summary["errors"] and fail_on in ("errors", "findings"):
        return 2
    if findings and fail_on == "findings":
        return 1
    return 0


def _emit_text(
    args: argparse.Namespace,
    path: Path,
    sections: list[dict[str, Any]],
    per_section: list[list[tuple[int, dict[str, Any], str]]],
) -> None:
    """Print the human-readable multi-section report in stable section order."""
    offline = bool(getattr(args, "offline", False))
    print(f"#### codescan all on {path} ####")
    if offline:
        print("(offline mode: skipping semgrep — the only open-world sensor)\n")
    else:
        print()
    for section, results in zip(sections, per_section):
        print(f"\n----- {section['label']} -----")
        try:
            _render_section(section["key"], results, args)
        except SystemExit:
            # cmd_* calls die() on missing_tool; the payload already records the
            # status and summary counts it as an error, so swallow the exit here.
            pass
