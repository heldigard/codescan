"""CI gate for the codescan quality-sensor orchestrator.

Verifies codescan is installed and its core delegation works on temporary
fixtures. Heavy sensors (semgrep, full knip project) are NOT exercised here —
they need network / a full package.json project and are too slow for the gate.
This asserts: list works, vulture dead-code delegation detects real dead code
and EXCLUDES vendor dirs, and missing-tool paths degrade gracefully.

Safe anywhere; does not mutate the current project.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


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


def test_codescan_list() -> None:
    r = run(["codescan", "list"])
    assert "semgrep" in r.stdout, f"codescan list missing semgrep: {r.stdout}"
    assert "vulture" in r.stdout, f"codescan list missing vulture: {r.stdout}"
    assert "available" in r.stdout, f"codescan list malformed: {r.stdout}"


def test_codescan_version() -> None:
    from codescan import __version__

    r = run(["codescan", "--version"])
    assert r.stdout.strip() == f"codescan {__version__}", r.stdout


def test_codescan_capabilities_contract() -> None:
    r = run(["codescan", "capabilities", "--json"])
    payload = json.loads(r.stdout)
    assert payload["command"] == "capabilities"
    assert payload["schema_version"] == 1
    capabilities = payload["capabilities"]
    by_name = {item["name"]: item for item in capabilities}
    for name in ("dead", "lint", "type", "sec", "secrets", "arch", "all", "capabilities"):
        assert name in by_name
        assert by_name[name]["read_only"] is True
        assert by_name[name]["destructive"] is False
    assert by_name["capabilities"]["structured_json"] is True
    assert by_name["dead"]["structured_json"] is True
    assert by_name["lint"]["structured_json"] is True
    assert by_name["type"]["structured_json"] is True
    assert by_name["sec"]["structured_json"] is True
    assert by_name["secrets"]["structured_json"] is True
    assert by_name["arch"]["structured_json"] is True
    assert by_name["all"]["structured_json"] is True
    assert by_name["all"]["open_world"] is True
    assert by_name["all"]["ci_exit_policies"] == ["never", "errors", "findings"]
    assert r.stdout.count("\n") == 1, "router manifest stays compact"


def test_all_parser_has_sensor_options() -> None:
    """all reuses sensor functions, so its Namespace must expose their options."""
    from codescan.cli import _build_parser

    args = _build_parser().parse_args(["all"])
    assert args.config is None
    assert args.summary_only is False
    assert args.min_confidence is None
    assert args.target == "src"
    assert args.type_tool == "auto"
    assert args.fail_on == "never"


def test_all_parser_has_jobs_option() -> None:
    """--jobs bounds parallel width; default None lets the host-aware value apply."""
    from codescan.cli import _build_parser

    default = _build_parser().parse_args(["all"])
    assert default.jobs is None
    pinned = _build_parser().parse_args(["all", "--jobs", "1"])
    assert pinned.jobs == 1
    short = _build_parser().parse_args(["all", "-j", "3"])
    assert short.jobs == 3


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
        ["codescan", "all", "-p", str(project), "--json", "--summary-only", "--jobs", "3"],
        check=False,
        env=env,
    )
    assert r.returncode == 0, f"all json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["jobs"] == 3
    # Every sensor payload carries a non-negative duration_ms so routers can
    # see which sensor dominates wall-clock.
    for sensor in payload["sensors"]:
        assert isinstance(sensor.get("duration_ms"), int), sensor
        assert sensor["duration_ms"] >= 0, sensor


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
        ["codescan", "all", "-p", str(project), "--json", "--summary-only", "--jobs", "1"],
        check=False,
        env=env,
    )
    parallel = run(
        ["codescan", "all", "-p", str(project), "--json", "--summary-only", "--jobs", "4"],
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
        ["codescan", "all", "-p", str(project), "--json", "--summary-only", "--skip", "sec,arch"],
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
        ["codescan", "all", "-p", str(project), "--json", "--summary-only", "--skip", "sec,bogus"],
        check=False,
        env=env,
    )
    assert r.returncode == 0
    # 'bogus' warned; 'sec' honored (dropped from the run).
    assert "bogus" in r.stderr, f"missing unknown-name warning: {r.stderr}"
    payload = json.loads(r.stdout)
    assert "sec" not in {s["command"] for s in payload["sensors"]}


def test_codescan_dead_detects(tmp_path: Path) -> None:
    """codescan dead (vulture) must report the real dead symbol AND must NOT
    report symbols planted in __pycache__/.venv (vendor exclusion)."""
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def live_caller():\n    return helper()\n"
        "def helper():\n    return 1\n"
        "def dead_func():\n    return 999\n"
        "class Unused:\n    pass\n"
    )
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "c.py").write_text("def cache_leak():\n    pass\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "v.py").write_text("def venv_leak():\n    pass\n")

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert "dead_func" in r.stdout, f"dead missed dead_func: {r.stdout}"
    assert "__pycache__" not in r.stdout, f"dead leaked __pycache__: {r.stdout}"
    assert ".venv" not in r.stdout, f"dead leaked .venv: {r.stdout}"


def test_codescan_dead_no_substring_exclude_false_positive(tmp_path: Path) -> None:
    """Vendor excludes must segment-anchor, not substring-match.

    A bare 'out' token becomes vulture '*out*' which silently excludes every
    path containing 'out' — e.g. router.py (r-OUT-er). That blinded the sensor
    and falsely reported cross-file callees as dead. Regression for the
    update_from_prompt incident (flagged dead while live-called from
    agentic_cycle_router.py). helper is used by caller in router.py, so it
    must NOT be reported dead even though router.py contains the 'out' token.
    """
    (tmp_path / "lib.py").write_text("def helper():\n    return 1\n")
    (tmp_path / "router.py").write_text(
        "from lib import helper\ndef caller():\n    return helper()\n"
    )

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert "helper" not in r.stdout, (
        f"substring exclude blinded vulture: router.py excluded, helper falsely dead: {r.stdout}"
    )


def test_archived_harness_code_is_not_quality_gate_input() -> None:
    from codescan.sensors.vulture_sensor import _vulture_excludes

    assert "*/_archive/*" in _vulture_excludes({})


def test_codescan_dead_respects_vulture_pyproject(tmp_path: Path) -> None:
    """codescan must pass the nearest pyproject.toml to vulture."""
    (tmp_path / "pyproject.toml").write_text(
        '[tool.vulture]\nignore_names = ["configured_dead_func"]\nmin_confidence = 60\n'
    )
    (tmp_path / "app.py").write_text(
        "def configured_dead_func():\n    return 1\ndef ordinary_dead_func():\n    return 2\n"
    )

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert r.returncode == 0, f"dead failed: stdout={r.stdout} stderr={r.stderr}"
    assert "configured_dead_func" not in r.stdout, f"vulture config was ignored: {r.stdout}"
    assert "ordinary_dead_func" in r.stdout, f"expected normal vulture finding: {r.stdout}"


def test_codescan_dead_ignores_pep562_module_hooks(tmp_path: Path) -> None:
    """PEP 562 module hooks are public protocol hooks, not dead functions."""
    (tmp_path / "app.py").write_text(
        "def __getattr__(name):\n    raise AttributeError(name)\n"
        "def __dir__():\n    return []\n"
        "def ordinary_dead_func():\n    return 2\n"
    )

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert r.returncode == 0, f"dead failed: stdout={r.stdout} stderr={r.stderr}"
    assert "__getattr__" not in r.stdout, f"PEP 562 __getattr__ leaked: {r.stdout}"
    assert "__dir__" not in r.stdout, f"PEP 562 __dir__ leaked: {r.stdout}"
    assert "ordinary_dead_func" in r.stdout, f"expected normal vulture finding: {r.stdout}"


def test_codescan_dead_ignores_parser_callbacks(tmp_path: Path) -> None:
    """HTMLParser/SAX override callbacks are invoked by the framework by name.

    vulture is AST-local: it sees the def but not that HTMLParser().feed()
    dispatches to handle_starttag/handle_data by reflection. The same applies
    to SAX ContentHandler overrides (startElement/characters). These are the
    single largest source of vulture false-positives in real codebases.
    Regression: callbacks must NOT be reported dead; real dead code still is.

    Note: __str__/setUp/__init__ are NOT tested here — vulture already ignores
    the standard protocol dunders and unittest lifecycle internally; only the
    parser/ContentHandler callbacks are missed and thus merit ignore-names.
    """
    (tmp_path / "app.py").write_text(
        "from html.parser import HTMLParser\n"
        "\n"
        "class P(HTMLParser):\n"
        "    def handle_starttag(self, tag, attrs):\n"
        "        pass\n"
        "    def handle_data(self, data):\n"
        "        pass\n"
        "\n"
        "def ordinary_dead_func():\n"
        "    return 2\n"
    )

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert r.returncode == 0, f"dead failed: stdout={r.stdout} stderr={r.stderr}"
    assert "handle_starttag" not in r.stdout, f"HTMLParser callback flagged dead (FP): {r.stdout}"
    assert "handle_data" not in r.stdout, f"HTMLParser callback flagged dead (FP): {r.stdout}"
    # vulture also reports the override signature params (tag/attrs/data) as
    # unused on the same def line. The method is a framework override we ignore,
    # so its params are protocol-signature noise, not actionable dead code.
    assert "unused variable 'tag'" not in r.stdout, f"callback arg flagged dead (FP): {r.stdout}"
    assert "unused variable 'attrs'" not in r.stdout, f"callback arg flagged dead (FP): {r.stdout}"
    assert "unused variable 'data'" not in r.stdout, f"callback arg flagged dead (FP): {r.stdout}"
    assert "ordinary_dead_func" in r.stdout, f"expected normal vulture finding: {r.stdout}"


def test_codescan_dead_ignores_asyncio_protocol_callbacks(tmp_path: Path) -> None:
    """asyncio.Protocol/StreamingProtocol overrides are invoked by the loop by name.

    Same AST-local blind spot as HTMLParser: the event loop dispatches to
    connection_made/data_received/connection_lost by reflection, so vulture
    reports them (and their signature params) as dead. Regression: callbacks
    and their params must NOT be reported; real dead code still is.
    """
    (tmp_path / "app.py").write_text(
        "import asyncio\n"
        "\n"
        "class P(asyncio.Protocol):\n"
        "    def connection_made(self, transport):\n"
        "        pass\n"
        "    def data_received(self, data):\n"
        "        pass\n"
        "    def connection_lost(self, exc):\n"
        "        pass\n"
        "\n"
        "def ordinary_dead_func():\n"
        "    return 2\n"
    )

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py"], check=False)
    assert r.returncode == 0, f"dead failed: stdout={r.stdout} stderr={r.stderr}"
    assert "connection_made" not in r.stdout, f"asyncio callback flagged dead (FP): {r.stdout}"
    assert "data_received" not in r.stdout, f"asyncio callback flagged dead (FP): {r.stdout}"
    assert "connection_lost" not in r.stdout, f"asyncio callback flagged dead (FP): {r.stdout}"
    assert "unused variable 'transport'" not in r.stdout, (
        f"asyncio callback arg flagged dead (FP): {r.stdout}"
    )
    assert "ordinary_dead_func" in r.stdout, f"expected normal vulture finding: {r.stdout}"


def test_codescan_dead_single_file(tmp_path: Path) -> None:
    """codescan dead must correctly detect languages and run on a single file path."""
    app_file = tmp_path / "app.py"
    app_file.write_text("def ordinary_dead_func():\n    return 2\n")
    r = run(["codescan", "dead", "-p", str(app_file)], check=False)
    assert r.returncode == 0, f"dead on single file failed: stdout={r.stdout} stderr={r.stderr}"
    assert "ordinary_dead_func" in r.stdout, f"expected vulture finding: {r.stdout}"


def test_codescan_secrets_excludes_cache_dirs(tmp_path: Path) -> None:
    """gitleaks must not inspect caches, harness runtime, or credential stores."""
    if not shutil.which("gitleaks"):
        pytest.skip("gitleaks not installed")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "fixture.pyc").write_bytes(b"binary ghp_" + b"0" * 36)
    for relative in (
        ".credentials.json",
        ".env",
        "file-history/old.txt",
        "plugins/cache/vendor.txt",
        "plugins/marketplaces/vendor.txt",
        "sessions/archived.jsonl",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("ghp_" + "0" * 36, encoding="utf-8")

    r = run(["codescan", "secrets", "-p", str(tmp_path)], check=False)

    assert r.returncode == 0, f"secrets failed: stdout={r.stdout} stderr={r.stderr}"
    assert "leaks: 0" in r.stdout, r.stdout
    assert "__pycache__" not in r.stdout, r.stdout


def test_codescan_secrets_json_is_compact_and_redacted(tmp_path: Path) -> None:
    """JSON mode gives routers typed findings without exposing secret payloads."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    fake_bin(
        bin_dir,
        "gitleaks",
        'printf \'[{"RuleID":"generic-api-key","File":"app.py","StartLine":7}]\\n\'\n',
    )

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "secrets", "-p", str(project), "--json"], check=False, env=env)

    assert r.returncode == 0, f"secrets json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "secrets"
    assert payload["redacted"] is True
    assert payload["counts"]["leaks"] == 1
    assert payload["findings"] == [{"rule_id": "generic-api-key", "file": "app.py", "line": 7}]


def test_codescan_secrets_error_when_gitleaks_signals_leaks_unparseable(tmp_path: Path) -> None:
    """gitleaks exit 1 means leaks found. If the report did not parse, codescan
    must surface an error rather than report a silent clean 0 leaks
    (false-negative). Regression for the rc==1-without-findings path."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    fake_bin(bin_dir, "gitleaks", "printf 'not-json\\n'\nexit 1\n")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "secrets", "-p", str(project), "--json"], check=False, env=env)

    assert r.returncode == 2, f"secrets should error: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["status"] == "error"
    assert payload["counts"]["leaks"] == 0


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
    r = run(["codescan", "sec", "-p", str(project), "--json"], check=False, env=env)

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


def test_codescan_dead_json_reports_sensor_payload(tmp_path: Path) -> None:
    """Dead-code JSON mode gives routers typed sensor payloads."""
    (tmp_path / "app.py").write_text("def ordinary_dead_func():\n    return 2\n")

    r = run(["codescan", "dead", "-p", str(tmp_path), "-l", "py", "--json"], check=False)

    assert r.returncode == 0, f"dead json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "dead"
    assert payload["counts"]["items"] >= 1
    assert payload["sensors"][0]["tool"] == "vulture"
    assert any(
        item.get("name") == "ordinary_dead_func" for item in payload["sensors"][0]["findings"]
    )


def test_codescan_lint_json_is_compact(tmp_path: Path) -> None:
    """Ruff JSON mode carries bounded lint metadata."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    fake_bin(
        bin_dir,
        "ruff",
        "printf '%s\\n' "
        '\'[{"code":"F401","filename":"app.py",'
        '"location":{"row":3},"message":"imported but unused"}]\'\n',
    )

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "lint", "-p", str(project), "--json"], check=False, env=env)

    assert r.returncode == 0, f"lint json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "lint"
    assert payload["tool"] == "ruff"
    assert payload["counts"] == {"findings": 1, "by_code": {"F401": 1}}
    assert payload["findings"] == [
        {
            "code": "F401",
            "path": "app.py",
            "line": 3,
            "message": "imported but unused",
        }
    ]


def test_codescan_type_json_pyright_is_compact(tmp_path: Path) -> None:
    """Pyright JSON mode carries bounded diagnostic metadata."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    bin_dir.mkdir()
    project.mkdir()
    fake_bin(
        bin_dir,
        "pyright",
        "printf '%s\\n' "
        '\'{"generalDiagnostics":[{"severity":"error","file":"app.py",'
        '"range":{"start":{"line":4}},"message":"not assignable",'
        '"rule":"reportAssignmentType"}]}\'\n'
        "exit 1\n",
    )

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(
        ["codescan", "type", "-p", str(project), "--tool", "pyright", "--json"],
        check=False,
        env=env,
    )

    assert r.returncode == 0, f"type json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "type"
    assert payload["tool"] == "pyright"
    assert payload["counts"] == {"diagnostics": 1, "by_severity": {"error": 1}}
    assert payload["findings"] == [
        {
            "severity": "error",
            "path": "app.py",
            "line": 5,
            "message": "not assignable",
            "rule": "reportAssignmentType",
        }
    ]


def test_type_sensor_uses_scanned_project_as_working_directory(monkeypatch, tmp_path: Path) -> None:
    """Project-local pyright config/imports must not depend on caller cwd."""
    import codescan.sensors.type_sensor as sensor

    captured: dict[str, Path | None] = {}

    def fake_run(_command, *, cwd=None, timeout=None):
        del timeout
        captured["cwd"] = cwd
        return 0, '{"generalDiagnostics":[]}', ""

    monkeypatch.setattr(sensor, "run", fake_run)
    rc, payload, _ = sensor._pyright_payload(tmp_path, include_findings=False)

    assert rc == 0
    assert payload["counts"]["diagnostics"] == 0
    assert captured["cwd"] == tmp_path


def test_type_sensor_honors_project_pyright_scope(monkeypatch, tmp_path: Path) -> None:
    """A directory config owns include/exclude; do not override it with a path arg."""
    import codescan.sensors.type_sensor as sensor

    config = tmp_path / "pyrightconfig.json"
    config.write_text('{"include":["src"],"exclude":["vendor"]}\n', encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(command, *, cwd=None, timeout=None):
        del timeout
        captured.update(command=command, cwd=cwd)
        return 0, '{"generalDiagnostics":[]}', ""

    monkeypatch.setattr(sensor, "run", fake_run)
    rc, payload, _ = sensor._pyright_payload(tmp_path, include_findings=False)

    assert rc == 0
    assert payload["counts"]["diagnostics"] == 0
    assert captured["command"] == [
        "pyright",
        "--project",
        str(config),
        "--outputjson",
    ]
    assert captured["cwd"] == tmp_path


def test_codescan_arch_json_skips_without_config(tmp_path: Path) -> None:
    """JSON mode should encode expected arch skips instead of forcing stderr scraping."""
    # Self-contained: a fake depcruise on PATH makes have() True so the sensor
    # reaches the no-config skip path without requiring a real install.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_bin(bin_dir, "depcruise", "exit 0\n")
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "arch", "-p", str(tmp_path), "--json"], check=False, env=env)

    assert r.returncode == 0, f"arch json skip failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "arch"
    assert payload["status"] == "skipped"
    assert payload["counts"]["violations"] == 0


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
        ["codescan", "all", "-p", str(project), "--json", "--summary-only"],
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
        ["codescan", "all", "-p", str(tmp_path), "--fail-on", "errors"],
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


def test_codescan_arch_skips_without_config(tmp_path: Path) -> None:
    """dependency-cruiser must SKIP cleanly (exit 1, not crash) when the project
    has no .dependency-cruiser.cjs — never auto-generate one."""
    # Self-contained: fake depcruise so have() is True and the sensor reaches the
    # no-config skip path without requiring a real install.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_bin(bin_dir, "depcruise", "exit 0\n")
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "arch", "-p", str(tmp_path)], check=False, env=env)
    assert r.returncode == 1, f"arch should exit 1 without config, got {r.returncode}"
    assert "no .dependency-cruiser" in r.stderr.lower(), f"arch should explain the skip: {r.stderr}"


def test_codescan_dead_js_runs_knip_from_package_root(tmp_path: Path) -> None:
    """knip must execute from the package root even when -p points at src/."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    src = project / "src"
    bin_dir.mkdir()
    src.mkdir(parents=True)
    (project / "package.json").write_text("{}")
    fake_bin(bin_dir, "knip", 'printf "warn cwd=%s\\n" "$(pwd)"\n')

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "dead", "-p", str(src), "-l", "js"], check=False, env=env)

    assert r.returncode == 0, f"knip sensor failed: stdout={r.stdout} stderr={r.stderr}"
    assert f"warn cwd={project}" in r.stdout, f"knip did not run in package root: {r.stdout}"


def test_codescan_arch_uses_js_config_and_project_root(tmp_path: Path) -> None:
    """dependency-cruiser must honor .dependency-cruiser.js and run at its root."""
    bin_dir = tmp_path / "bin"
    project = tmp_path / "project"
    src = project / "src"
    bin_dir.mkdir()
    src.mkdir(parents=True)
    (project / ".dependency-cruiser.js").write_text("module.exports = {};")
    fake_bin(bin_dir, "depcruise", 'printf "warn cwd=%s args=%s\\n" "$(pwd)" "$*"\n')

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    r = run(["codescan", "arch", "-p", str(src)], check=False, env=env)

    assert r.returncode == 0, f"arch sensor failed: stdout={r.stdout} stderr={r.stderr}"
    assert f"warn cwd={project}" in r.stdout, f"depcruise ran from wrong cwd: {r.stdout}"
    assert ".dependency-cruiser.js" in r.stdout, f"arch did not pass JS config: {r.stdout}"


def test_gitleaks_allowlist_drops_tmp_temp_collision() -> None:
    """tmp/temp tokens collide with OS-standard absolute paths (/tmp, /var/tmp).

    gitleaks resolves ``--source`` to an absolute path and matches allowlist
    ``paths`` against it, so a ``(^|/)tmp(/|$)`` token blanks every file under
    /tmp — pytest ``tmp_path``, CI temp dirs, manual ``/tmp/...`` work — and
    real secrets go undetected (false-negative). Regression: those tokens must
    be absent from the generated config while real vendor excludes remain.
    """
    import re as path_re
    import tomllib

    from codescan.sensors.gitleaks_sensor import _gitleaks_allowlist_config

    data = tomllib.loads(_gitleaks_allowlist_config())
    patterns = [path_re.compile(p) for p in data["allowlist"]["paths"]]
    for victim in ("/tmp/work/secret.txt", "/var/tmp/work/secret.txt"):
        assert not any(pat.search(victim) for pat in patterns), (
            f"OS temp path allowlisted (would blank scans under it): {victim}"
        )
    assert any(pat.search("/proj/node_modules/leak.js") for pat in patterns), (
        "vendor exclude dropped with tmp/temp"
    )


def test_codescan_secrets_detects_leak_under_tmp(tmp_path: Path) -> None:
    """End-to-end regression: a real secret under /tmp (pytest tmp_path) must be
    detected. Before the allowlist fix, the tmp/temp token blanked the whole
    scan under /tmp (gitleaks reported "scanned ~0 bytes", 0 leaks)."""
    if not shutil.which("gitleaks"):
        pytest.skip("gitleaks not installed")
    # Assemble at runtime so no continuous secret literal lives in source
    # (keeps repo push-protection clean); gitleaks still scans the written file.
    token = (
        "xoxb-" + ("1234567890123") + "-" + ("0987654321098") + "-" + ("abcdefghij1234567890abcd")
    )
    (tmp_path / "slack.txt").write_text(token + "\n", encoding="utf-8")

    r = run(["codescan", "secrets", "-p", str(tmp_path), "--json"], check=False)

    assert r.returncode == 0, f"secrets failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["counts"]["leaks"] >= 1, f"secret under /tmp missed: {r.stdout}"


def test_codescan_type_resolves_relative_subdir(tmp_path: Path) -> None:
    """Relative -p dir must not double-resolve against its own cwd.

    Regression: the type sensor ``cd``s into the target dir AND passed the dir
    as the tool arg, so a relative dir re-resolved against itself (``src`` ->
    ``src/src``). pyright/mypy errored on the non-existent path and --json
    emitted nothing — silently breaking the documented ``codescan all -p src``.
    """
    if not shutil.which("pyright") and not shutil.which("mypy"):
        pytest.skip("pyright/mypy not installed")
    sub = tmp_path / "relsub"
    sub.mkdir()
    (sub / "app.py").write_text("x: int = 1\n", encoding="utf-8")

    r = run(["codescan", "type", "-p", "relsub", "--json"], cwd=tmp_path, check=False)

    assert r.returncode == 0, f"type rel failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["status"] != "error", f"relative path doubled: {payload}"


def test_codescan_arch_init_creates_starter(tmp_path: Path) -> None:
    """codescan arch --init writes a starter config; second call refuses to overwrite."""
    r1 = run(["codescan", "arch", "--init", "-p", str(tmp_path)], check=False)
    assert r1.returncode == 0, f"init failed: {r1.stderr}"
    assert "wrote:" in r1.stdout, r1.stdout
    starter = tmp_path / ".dependency-cruiser.cjs"
    assert starter.is_file(), "starter config was not written"
    body = starter.read_text()
    assert "dependency-cruiser" in body, "missing dependency-cruiser header"
    assert "doNotFollow" in body, "missing doNotFollow vendor excludes"
    assert "no-cross-feature-imports" in body, "missing vertical-slice rule"

    r2 = run(["codescan", "arch", "--init", "-p", str(tmp_path)], check=False)
    assert r2.returncode == 1, "second --init must refuse to overwrite"
    assert "exists, not overwritten" in r2.stderr, r2.stderr


def test_codescan_all_offline_skips_semgrep(tmp_path: Path) -> None:
    """codescan all --offline --json must skip sec and emit a 'skipped' payload for it."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='s'\nversion='0'\n")
    (tmp_path / "app.py").write_text("import os\ndef live(): return os.getcwd()\n")
    r = run(
        ["codescan", "all", "-p", str(tmp_path), "--offline", "--json", "--summary-only"],
        check=False,
    )
    assert r.returncode == 0, f"offline run failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["offline"] is True
    sec = next(s for s in payload["sensors"] if s.get("command") == "sec")
    assert sec["status"] == "skipped", sec
    assert "open-world" in sec.get("reason", ""), sec
    assert payload["summary"]["sast_findings"] == 0


def test_vendor_excludes_cover_agent_and_mcp_noise() -> None:
    """VENDOR_EXCLUDES must drop harness/MCP caches that pollute quality scans.

    Parity target: codeq's VENDOR_EXCLUDES. Keep this regression list when
    either project grows agent/editor/MCP dirs so facts and quality layers
    exclude the same non-source noise.
    """
    from codescan.shared.config import SCAN_EXCLUDES, VENDOR_EXCLUDES

    required = {
        ".venv",
        "node_modules",
        ".memory-bank",
        ".claude",
        ".codex",
        ".cursor",
        ".playwright-mcp",
        ".chrome-devtools-mcp",
        ".agent-browser",
        "cdk.out",
        ".aws-sam",
        ".jdtls-data",
        "storybook-static",
    }
    missing = required - set(VENDOR_EXCLUDES)
    assert not missing, f"VENDOR_EXCLUDES missing agent/MCP dirs: {sorted(missing)}"
    # Runtime harness paths stay on SCAN_EXCLUDES (secrets path) even if not
    # pure "vendor".
    for token in (".memory-bank", "sessions", "shell-snapshots"):
        assert token in SCAN_EXCLUDES, token


def test_vendor_excludes_parity_with_colocated_codeq() -> None:
    """When ~/codeq is present, codescan vendor tokens must be ⊆ codeq's list.

    Keeps facts (codeq) and quality (codescan) from drifting apart. Skips
    cleanly on hosts without a co-located codeq checkout.
    """
    import ast

    from codescan.shared.config import VENDOR_EXCLUDES

    codeq_cfg = Path.home() / "codeq" / "src" / "codeq" / "shared" / "config.py"
    if not codeq_cfg.is_file():
        pytest.skip("codeq not co-located at ~/codeq")
    tree = ast.parse(codeq_cfg.read_text())
    codeq_vendor: set[str] | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if getattr(target, "id", None) == "VENDOR_EXCLUDES":
                    codeq_vendor = set(ast.literal_eval(node.value))
        elif (
            isinstance(node, ast.AnnAssign)
            and getattr(node.target, "id", None) == "VENDOR_EXCLUDES"
        ):
            codeq_vendor = set(ast.literal_eval(node.value))
    assert codeq_vendor is not None, "could not parse codeq VENDOR_EXCLUDES"
    # codescan may use wildcard tokens codeq also has (e.g. .aider*);
    # require exact token membership for non-glob entries.
    extras = set()
    for token in VENDOR_EXCLUDES:
        if "*" in token:
            # wildcard: require a matching prefix entry exists in codeq
            if not any(token.rstrip("*") in item or item == token for item in codeq_vendor):
                extras.add(token)
        elif token not in codeq_vendor:
            extras.add(token)
    assert not extras, f"codescan VENDOR_EXCLUDES not in codeq (add to both): {sorted(extras)}"


def main() -> int:
    print("codescan orchestrator smoke test")
    run(["which", "codescan"])

    test_codescan_list()
    print("  codescan list: OK")

    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp) / "proj"
        proj.mkdir()
        test_codescan_dead_detects(proj)
        print("  codescan dead (vulture, vendor-excluded): OK")
        substring_proj = Path(tmp) / "substring"
        substring_proj.mkdir()
        test_codescan_dead_no_substring_exclude_false_positive(substring_proj)
        print("  codescan dead (no substring-exclude false positive): OK")
        test_codescan_arch_skips_without_config(proj)
        print("  codescan arch (skip without config): OK")
        test_codescan_arch_init_creates_starter(proj)
        print("  codescan arch --init: OK")
        test_codescan_all_offline_skips_semgrep(proj)
        print("  codescan all --offline: OK")

    print("\n✅ all codescan checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
