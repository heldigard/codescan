"""Tests: codescan CLI meta (list/version/capabilities)."""
from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401

from ._helpers import _codescan, fake_bin, run  # noqa: F401


def test_codescan_list() -> None:
    r = run(_codescan("list"))
    assert "semgrep" in r.stdout, f"codescan list missing semgrep: {r.stdout}"
    assert "vulture" in r.stdout, f"codescan list missing vulture: {r.stdout}"
    assert "available" in r.stdout, f"codescan list malformed: {r.stdout}"



def test_codescan_list_json() -> None:
    """list --json is a compact router handoff (sensor availability matrix)."""
    r = run(_codescan("list", "--json"))
    payload = json.loads(r.stdout)
    assert payload["command"] == "list"
    assert payload["schema_version"] == 1
    sensors = {row["sensor"]: row for row in payload["sensors"]}
    assert "semgrep" in sensors
    assert "vulture" in sensors
    assert "available" in sensors["semgrep"]
    assert r.stdout.count("\n") == 1, "list --json stays single-line compact"



def test_codescan_version() -> None:
    from codescan import __version__

    r = run(_codescan("--version"))
    assert r.stdout.strip() == f"codescan {__version__}", r.stdout



def test_codescan_capabilities_contract() -> None:
    r = run(_codescan("capabilities", "--json"))
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

