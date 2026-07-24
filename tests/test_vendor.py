"""Tests: vendor-exclusion parity. Extracted from the former monolithic test_codescan.py."""

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
        ".grok",
        ".opencode",
        ".gemini",
        ".antigravity",
        ".kimi",
        ".qwen",
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
