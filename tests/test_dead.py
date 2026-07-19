"""Tests: dead-code sensor (vulture delegation)."""
from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401
from pathlib import Path

from ._helpers import _codescan, fake_bin, run  # noqa: F401


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

    r = run(_codescan("dead", "-p", str(tmp_path), "-l", "py"), check=False)
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

    r = run(_codescan("dead", "-p", str(tmp_path), "-l", "py"), check=False)
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

    r = run(_codescan("dead", "-p", str(tmp_path), "-l", "py"), check=False)
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

    r = run(_codescan("dead", "-p", str(tmp_path), "-l", "py"), check=False)
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

    r = run(_codescan("dead", "-p", str(tmp_path), "-l", "py"), check=False)
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

    r = run(_codescan("dead", "-p", str(tmp_path), "-l", "py"), check=False)
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
    r = run(_codescan("dead", "-p", str(app_file)), check=False)
    assert r.returncode == 0, f"dead on single file failed: stdout={r.stdout} stderr={r.stderr}"
    assert "ordinary_dead_func" in r.stdout, f"expected vulture finding: {r.stdout}"



def test_codescan_dead_json_reports_sensor_payload(tmp_path: Path) -> None:
    """Dead-code JSON mode gives routers typed sensor payloads."""
    (tmp_path / "app.py").write_text("def ordinary_dead_func():\n    return 2\n")

    r = run(_codescan("dead", "-p", str(tmp_path), "-l", "py", "--json"), check=False)

    assert r.returncode == 0, f"dead json failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["command"] == "dead"
    assert payload["counts"]["items"] >= 1
    assert payload["sensors"][0]["tool"] == "vulture"
    assert any(
        item.get("name") == "ordinary_dead_func" for item in payload["sensors"][0]["findings"]
    )



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
    r = run(_codescan("dead", "-p", str(src), "-l", "js"), check=False, env=env)

    assert r.returncode == 0, f"knip sensor failed: stdout={r.stdout} stderr={r.stderr}"
    assert f"warn cwd={project}" in r.stdout, f"knip did not run in package root: {r.stdout}"

