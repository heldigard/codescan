"""Tests: secrets sensor (gitleaks delegation)."""

from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401
from pathlib import Path

import pytest

from ._helpers import _codescan, fake_bin, run  # noqa: F401


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

    r = run(_codescan("secrets", "-p", str(tmp_path)), check=False)

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
    r = run(_codescan("secrets", "-p", str(project), "--json"), check=False, env=env)

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
    r = run(_codescan("secrets", "-p", str(project), "--json"), check=False, env=env)

    assert r.returncode == 2, f"secrets should error: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["status"] == "error"
    assert payload["counts"]["leaks"] == 0


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

    r = run(_codescan("secrets", "-p", str(tmp_path), "--json"), check=False)

    assert r.returncode == 0, f"secrets failed: stdout={r.stdout} stderr={r.stderr}"
    payload = json.loads(r.stdout)
    assert payload["counts"]["leaks"] >= 1, f"secret under /tmp missed: {r.stdout}"
