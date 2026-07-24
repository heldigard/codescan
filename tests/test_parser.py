"""Tests: argument parser surface. Extracted from the former monolithic test_codescan.py."""

from __future__ import annotations

import json  # noqa: F401
import os  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import tempfile  # noqa: F401

from ._helpers import _codescan, fake_bin, run  # noqa: F401


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
