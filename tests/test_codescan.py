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
    r = run(["codescan", "--version"])
    assert r.stdout.strip() == "codescan 1.1.0"


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
    assert payload["findings"] == [
        {"rule_id": "generic-api-key", "file": "app.py", "line": 7}
    ]


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
        "'{\"results\":[{\"check_id\":\"python.lang.security.audit.dynamic-urllib-use-detected\","
        "\"path\":\"app.py\",\"start\":{\"line\":12},"
        "\"extra\":{\"severity\":\"WARNING\",\"message\":\"dynamic urllib\"}}]}'\n",
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
        "'[{\"code\":\"F401\",\"filename\":\"app.py\","
        "\"location\":{\"row\":3},\"message\":\"imported but unused\"}]'\n",
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
        "'{\"generalDiagnostics\":[{\"severity\":\"error\",\"file\":\"app.py\","
        "\"range\":{\"start\":{\"line\":4}},\"message\":\"not assignable\","
        "\"rule\":\"reportAssignmentType\"}]}'\n"
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


def test_codescan_arch_json_skips_without_config(tmp_path: Path) -> None:
    """JSON mode should encode expected arch skips instead of forcing stderr scraping."""
    r = run(["codescan", "arch", "-p", str(tmp_path), "--json"], check=False)

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
    r = run(["codescan", "arch", "-p", str(tmp_path)], check=False)
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

    print("\n✅ all codescan checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
