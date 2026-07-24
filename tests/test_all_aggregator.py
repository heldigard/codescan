"""Tests: `all` aggregator + parallelism. Extracted from the former monolithic test_codescan.py."""

from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401
from pathlib import Path

from ._helpers import _codescan, fake_bin, run  # noqa: F401


def test_parallel_map_preserves_order_and_serial_fallback() -> None:
    """parallel_map must preserve input order and fall back to serial at jobs<=1."""
    import time

    from codescan.shared.concurrency import parallel_map

    def slow(item: int) -> int:
        time.sleep(0.02)
        return item * 10

    items = list(range(6))
    # Force concurrent scheduling; completion order is nondeterministic, so
    # order preservation is the real assertion.
    parallel = parallel_map(slow, items, jobs=4)
    serial = parallel_map(slow, items, jobs=1)
    assert parallel == serial == [0, 10, 20, 30, 40, 50]
    # Empty and single-item inputs short-circuit without dispatching a pool.
    assert parallel_map(slow, [], jobs=4) == []
    assert parallel_map(slow, [99], jobs=4) == [990]


def test_default_jobs_env_override(monkeypatch) -> None:
    """CODESCAN_JOBS overrides the host-aware default; 1 forces serial."""
    from codescan.shared.concurrency import default_jobs

    monkeypatch.setenv("CODESCAN_JOBS", "2")
    assert default_jobs() == 2
    monkeypatch.setenv("CODESCAN_JOBS", "0")
    # 0 clamps to 1 (serial), not 0 — ThreadPoolExecutor needs >= 1 worker.
    assert default_jobs() == 1
    monkeypatch.setenv("CODESCAN_JOBS", "garbage")
    # Malformed env falls through to the host-aware default (>= 1).
    assert default_jobs() >= 1


def test_codescan_all_json_reports_jobs_and_duration(tmp_path: Path) -> None:
    """all --json carries the effective job width and per-sensor timing."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    (project / "app.py").write_text("def ordinary_dead_func():\n    return 2\n")
    fake_bin(bin_dir, "gitleaks", "printf '[]\\n'\n")
    fake_bin(bin_dir, "semgrep", "printf '%s\\n' '{\"results\":[]}'\n")
    fake_bin(bin_dir, "ruff", "printf '[]\\n'\n")
    fake_bin(bin_dir, "pyright", "printf '%s\\n' '{\"generalDiagnostics\":[]}'\n")
    fake_bin(bin_dir, "depcruise", "exit 0\n")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(
        _codescan("all", "-p", str(project), "--json", "--summary-only", "--jobs", "3"),
        check=False,
        env=env,
    )
    assert r.returncode == 0, f"all json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["jobs"] == 3
    assert isinstance(payload.get("wall_ms"), int)
    assert payload["wall_ms"] >= 0
    # Every sensor payload carries a non-negative duration_ms so routers can
    # see which sensor dominates wall-clock.
    for sensor in payload["sensors"]:
        assert isinstance(sensor.get("duration_ms"), int), sensor
        assert sensor["duration_ms"] >= 0, sensor


def test_codescan_all_isolates_sensor_exceptions(tmp_path: Path) -> None:
    """A crashing sensor becomes a typed error payload (does not abort the pool)."""
    from codescan.sensors import all_command

    section = {
        "key": "sec",
        "label": "SAST",
        "path": tmp_path,
        "produce": lambda: (_ for _ in ()).throw(RuntimeError("synthetic sensor boom")),
    }
    results = all_command._run_section(section)
    assert len(results) == 1
    rc, payload, error = results[0]
    assert rc == 2
    assert payload["status"] == "error"
    assert "synthetic sensor boom" in error
    assert payload["duration_ms"] >= 0
    # summary_payload must count the isolated failure as an error.
    summary = all_command.summary_payload([payload])
    assert summary["errors"] == 1


def test_codescan_all_offline_env(tmp_path: Path) -> None:
    """CODESCAN_OFFLINE=1 skips semgrep the same way as --offline."""
    (tmp_path / "app.py").write_text("x = 1\n")
    env = os.environ.copy()
    env["CODESCAN_OFFLINE"] = "1"
    r = run(
        _codescan("all", "-p", str(tmp_path), "--json", "--summary-only", "--jobs", "1"),
        check=False,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload["offline"] is True
    sec = next(s for s in payload["sensors"] if s.get("command") == "sec")
    assert sec["status"] == "skipped"


def test_codescan_all_parallel_matches_serial_summary(tmp_path: Path) -> None:
    """Parallel and --jobs 1 (serial) runs must aggregate identically.

    Parallelism changes only wall-clock, never the per-sensor payloads or the
    aggregate summary — the contract routers depend on. A fake semgrep sleeps
    so a genuine parallel speedup is observable, proving the scheduler engaged.
    """
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    (project / "app.py").write_text("def ordinary_dead_func():\n    return 2\n")
    # A sleeping semgrep makes the parallel vs serial wall-clock difference
    # measurable; both still report 0 findings.
    fake_bin(bin_dir, "gitleaks", "printf '[]\\n'\n")
    fake_bin(bin_dir, "semgrep", "sleep 0.3\nprintf '%s\\n' '{\"results\":[]}'\n")
    fake_bin(bin_dir, "ruff", "printf '[]\\n'\n")
    fake_bin(bin_dir, "pyright", "printf '%s\\n' '{\"generalDiagnostics\":[]}'\n")
    fake_bin(bin_dir, "depcruise", "exit 0\n")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]

    serial = run(
        _codescan("all", "-p", str(project), "--json", "--summary-only", "--jobs", "1"),
        check=False,
        env=env,
    )
    parallel = run(
        _codescan("all", "-p", str(project), "--json", "--summary-only", "--jobs", "4"),
        check=False,
        env=env,
    )
    assert serial.returncode == 0
    assert parallel.returncode == 0
    serial_summary = json.loads(serial.stdout)["summary"]
    parallel_summary = json.loads(parallel.stdout)["summary"]
    assert serial_summary == parallel_summary


def test_codescan_all_skip_drops_named_sensors(tmp_path: Path) -> None:
    """--skip removes sensors from the run entirely (no payload, no section)."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    (project / "app.py").write_text("def ordinary_dead_func():\n    return 2\n")
    fake_bin(bin_dir, "gitleaks", "printf '[]\\n'\n")
    fake_bin(bin_dir, "semgrep", "printf '%s\\n' '{\"results\":[]}'\n")
    fake_bin(bin_dir, "ruff", "printf '[]\\n'\n")
    fake_bin(bin_dir, "pyright", "printf '%s\\n' '{\"generalDiagnostics\":[]}'\n")
    fake_bin(bin_dir, "depcruise", "exit 0\n")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(
        _codescan("all", "-p", str(project), "--json", "--summary-only", "--skip", "sec,arch"),
        check=False,
        env=env,
    )
    assert r.returncode == 0, f"all --skip failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    commands = {sensor["command"] for sensor in payload["sensors"]}
    assert commands == {"secrets", "dead", "lint", "type"}, commands


def test_codescan_all_skip_warns_on_unknown_name(tmp_path: Path) -> None:
    """Unknown --skip names are ignored with a stderr warning, not a hard failure."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")
    fake_bin(bin_dir, "gitleaks", "printf '[]\\n'\n")
    fake_bin(bin_dir, "semgrep", "printf '%s\\n' '{\"results\":[]}'\n")
    fake_bin(bin_dir, "ruff", "printf '[]\\n'\n")
    fake_bin(bin_dir, "pyright", "printf '%s\\n' '{\"generalDiagnostics\":[]}'\n")
    fake_bin(bin_dir, "depcruise", "exit 0\n")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(
        _codescan("all", "-p", str(project), "--json", "--summary-only", "--skip", "sec,bogus"),
        check=False,
        env=env,
    )
    assert r.returncode == 0
    # 'bogus' warned; 'sec' honored (dropped from the run).
    assert "bogus" in r.stderr, f"missing unknown-name warning: {r.stderr}"
    payload = json.loads(r.stdout)
    assert "sec" not in {s["command"] for s in payload["sensors"]}


def test_codescan_all_json_aggregates_sensor_payloads(tmp_path: Path) -> None:
    """all --json is the compact router handoff for a whole quality pass."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    (project / "app.py").write_text("def ordinary_dead_func():\n    return 2\n")
    fake_bin(bin_dir, "gitleaks", "printf '[]\\n'\n")
    fake_bin(bin_dir, "semgrep", "printf '%s\\n' '{\"results\":[]}'\n")
    fake_bin(bin_dir, "ruff", "printf '[]\\n'\n")
    fake_bin(bin_dir, "pyright", "printf '%s\\n' '{\"generalDiagnostics\":[]}'\n")
    fake_bin(
        bin_dir, "depcruise", "exit 0\n"
    )  # present so arch skips (no config), not missing_tool

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(
        _codescan("all", "-p", str(project), "--json", "--summary-only"),
        check=False,
        env=env,
    )

    assert r.returncode == 0, f"all json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "all"
    assert payload["status"] == "findings"
    assert payload["summary"]["secrets"] == 0
    assert payload["summary"]["sast_findings"] == 0
    assert payload["summary"]["dead_items"] >= 1
    assert payload["summary"]["lint_findings"] == 0
    assert payload["summary"]["type_diagnostics"] == 0
    assert {sensor["command"] for sensor in payload["sensors"]} == {
        "secrets",
        "sec",
        "dead",
        "lint",
        "type",
        "arch",
    }
    sec_sensor = next(sensor for sensor in payload["sensors"] if sensor["command"] == "sec")
    assert sec_sensor["findings_omitted"] is True
    # --summary-only must omit findings across EVERY actionable sensor, not
    # just sec/lint/type. Regression: secrets/dead/arch used to ignore it.
    for cmd in ("secrets", "sec", "dead", "lint", "type", "arch"):
        sensor = next(s for s in payload["sensors"] if s["command"] == cmd)
        assert sensor.get("findings_omitted") is True, (
            f"{cmd} did not honor --summary-only: {sensor}"
        )

    gated = run(
        [
            "codescan",
            "all",
            "-p",
            str(project),
            "--json",
            "--summary-only",
            "--fail-on",
            "findings",
        ],
        check=False,
        env=env,
    )
    assert gated.returncode == 1
    assert json.loads(gated.stdout)["status"] == "findings"


def test_codescan_all_fail_on_requires_json(tmp_path: Path) -> None:
    r = run(
        _codescan("all", "-p", str(tmp_path), "--fail-on", "errors"),
        check=False,
    )
    assert r.returncode == 2
    assert "requires --json" in r.stderr


def test_codescan_all_fail_on_errors_distinguishes_sensor_failure(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    (project / "app.py").write_text("value = 1\n")
    fake_bin(bin_dir, "gitleaks", "printf '[]\\n'\n")
    fake_bin(bin_dir, "semgrep", "printf 'sensor unavailable\\n' >&2\nexit 2\n")
    fake_bin(bin_dir, "ruff", "printf '[]\\n'\n")
    fake_bin(bin_dir, "pyright", "printf '%s\\n' '{\"generalDiagnostics\":[]}'\n")
    fake_bin(bin_dir, "depcruise", "exit 0\n")  # present so arch skips, not missing_tool
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]

    r = run(
        [
            "codescan",
            "all",
            "-p",
            str(project),
            "--json",
            "--summary-only",
            "--fail-on",
            "errors",
        ],
        check=False,
        env=env,
    )

    assert r.returncode == 2
    payload = json.loads(r.stdout)
    assert payload["status"] == "degraded"
    assert payload["summary"]["errors"] == 1


def test_codescan_all_offline_skips_semgrep(tmp_path: Path) -> None:
    """codescan all --offline --json must skip sec and emit a 'skipped' payload for it."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='s'\nversion='0'\n")
    (tmp_path / "app.py").write_text("import os\ndef live(): return os.getcwd()\n")
    r = run(
        _codescan("all", "-p", str(tmp_path), "--offline", "--json", "--summary-only"),
        check=False,
    )
    assert r.returncode == 0, f"offline run failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["offline"] is True
    sec = next(s for s in payload["sensors"] if s.get("command") == "sec")
    assert sec["status"] == "skipped", sec
    assert "open-world" in sec.get("reason", ""), sec
    assert payload["summary"]["sast_findings"] == 0
