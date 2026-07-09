"""Machine-readable sensor capabilities for orchestrators and worker prompts."""

from __future__ import annotations

from typing import Any

CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "name": "list",
        "purpose": "Report installed sensor binaries and versions.",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": False,
        "structured_json": False,
        "external_tools": tuple(),
        "cost": "cheap",
    },
    {
        "name": "dead",
        "purpose": "Find unused Python, JavaScript, and TypeScript code.",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": False,
        "structured_json": True,
        "external_tools": ("vulture", "knip"),
        "cost": "moderate",
    },
    {
        "name": "sec",
        "purpose": "Run SAST checks for bugs and security anti-patterns.",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": True,
        "structured_json": True,
        "external_tools": ("semgrep",),
        "cost": "moderate",
    },
    {
        "name": "secrets",
        "purpose": "Detect leaked secrets in the working tree.",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": False,
        "structured_json": True,
        "external_tools": ("gitleaks",),
        "cost": "cheap",
    },
    {
        "name": "arch",
        "purpose": "Check import architecture rules when a dependency-cruiser config exists.",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": False,
        "structured_json": True,
        "external_tools": ("dependency-cruiser",),
        "cost": "moderate",
    },
    {
        "name": "all",
        "purpose": "Run all applicable quality sensors sequentially.",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": True,
        "structured_json": True,
        "external_tools": ("gitleaks", "semgrep", "vulture", "knip", "dependency-cruiser"),
        "cost": "expensive",
    },
    {
        "name": "capabilities",
        "purpose": "Emit this sensor capability manifest for routers, doctors, and workers.",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": False,
        "structured_json": True,
        "external_tools": tuple(),
        "cost": "cheap",
    },
)


def capabilities_payload() -> dict[str, Any]:
    """Return the stable capabilities payload."""
    return {
        "command": "capabilities",
        "schema_version": 1,
        "capabilities": [dict(item) for item in CAPABILITIES],
    }
