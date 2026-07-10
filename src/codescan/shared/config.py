"""Shared configuration: vendor exclusions and sensor registry.

VENDOR_EXCLUDES mirrors codeq's list — keep the two in sync.
"""
from __future__ import annotations

# Dirs excluded where a tool lets us exclude on the CLI (vulture).
# semgrep/knip/dep-cruiser use .gitignore + their own configs.
VENDOR_EXCLUDES: list[str] = [
    ".venv", "venv", "env", "site-packages", ".python_packages",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox",
    ".eggs", ".benchmarks", ".pyre", ".pytype", "htmlcov", ".ipynb_checkpoints",
    "node_modules", "bower_components", "jspm_packages",
    ".next", ".nuxt", ".svelte-kit", ".remix", ".astro", ".gatsby",
    ".turbo", ".nx-cache", ".parcel-cache", ".ngc-cache", ".vite",
    ".eslintcache", ".stylelintcache", ".cache",
    ".npm", ".pnpm-store", ".yarn",
    "coverage", ".nyc_output",
    ".docusaurus",
    "dist", "build", "out", "target", "dist-electron",
    ".serverless", ".vercel", "tmp", "temp",
    ".gradle", ".mvn",
    ".git", ".hg", ".svn",
    ".idea", ".vscode", ".vs", ".history",
]

# Harness/runtime trees that are neither project source nor safe secret-scan
# inputs. Keep known credential stores out of gitleaks separately below.
RUNTIME_EXCLUDES: list[str] = [
    ".memory-bank",
    ".ssh",
    "delegations",
    "file-history",
    "logs",
    "plugins/cache",
    "plugins/marketplaces",
    "plugins/plugin-catalog-cache.json",
    "projects",
    "sessions",
    "shell-snapshots",
    "tasks",
]

SCAN_EXCLUDES: list[str] = [*VENDOR_EXCLUDES, *RUNTIME_EXCLUDES]

SENSITIVE_FILE_PATTERNS: tuple[str, ...] = (
    r"\.env(?:\.[^/]*)?",
    r"\.?credentials\.json",
    r"auth\.json",
)

# Sensor binary names → display names.
SENSORS: dict[str, str] = {
    "ruff": "ruff",
    "pyright": "pyright",
    "mypy": "mypy",
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "vulture": "vulture",
    "knip": "knip",
    "dependency-cruiser": "dependency-cruiser",
}
