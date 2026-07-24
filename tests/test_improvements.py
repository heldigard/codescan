"""Tests for 1.2.2 improvements: secrets guard, dead isolation, semgrep metrics."""

from __future__ import annotations

from pathlib import Path


def test_secrets_accumulation_guarded_by_command() -> None:
    """_accumulate must count leaks only for command=="secrets" payloads."""
    from codescan.sensors.all_command import summary_payload

    secrets_payload = {
        "command": "secrets",
        "counts": {"leaks": 3},
        "status": "ok",
    }
    non_secrets_with_leaks_key = {
        "command": "sec",
        "counts": {"leaks": 999, "findings": 5},
        "status": "ok",
    }
    summary = summary_payload([secrets_payload, non_secrets_with_leaks_key])
    # Only the secrets payload's leaks (3) counted; the sec payload's stray
    # "leaks" key (999) ignored. sast_findings from sec payload (5) counted.
    assert summary["secrets"] == 3, summary
    assert summary["sast_findings"] == 5, summary


def test_dead_results_isolates_crashing_sensor(tmp_path: Path) -> None:
    """A crashing dead-sensor producer yields a typed error, not an exception."""
    # Monkeypatch dead_py_payload to raise.
    import codescan.sensors.vulture_sensor as vulture_mod
    from codescan.sensors.dead_dispatch import dead_results

    original = vulture_mod.dead_py_payload

    def boom(_path, _min_confidence, **_kwargs):
        raise RuntimeError("synthetic vulture crash")

    vulture_mod.dead_py_payload = boom
    try:
        results = dead_results(tmp_path, {"py"}, None)
        assert len(results) == 1
        rc, payload, error = results[0]
        assert rc == 2
        assert payload["status"] == "error"
        assert "synthetic vulture crash" in error
        assert payload["tool"] == "vulture"
        assert payload["language"] == "python"
    finally:
        vulture_mod.dead_py_payload = original


def test_semgrep_command_includes_metrics_off() -> None:
    """_semgrep_command builds the invocation with --metrics off."""
    from codescan.sensors.semgrep_sensor import _semgrep_command

    cmd = _semgrep_command("/some/path", "auto")
    assert "semgrep" in cmd
    assert "--metrics" in cmd
    assert "off" in cmd
    metrics_idx = cmd.index("--metrics")
    assert cmd[metrics_idx + 1] == "off"
