"""Shared configuration: vendor exclusions and sensor registry.

VENDOR_EXCLUDES mirrors codeq's list — keep the two in sync.
Source of truth for project-local vendor noise lives in both:
  ~/codeq/src/codeq/shared/config.py  (VENDOR_EXCLUDES)
  ~/codescan/src/codescan/shared/config.py  (this file)
When adding a dir to either, add it to the other (or add a parity test).
"""

from __future__ import annotations

# Dirs excluded where a tool lets us exclude on the CLI (vulture/ruff/semgrep).
# knip/dep-cruiser primarily honor .gitignore + their own configs.
# Keep in parity with codeq VENDOR_EXCLUDES (facts layer) so quality scans
# never re-open the same harness/MCP/IDE caches that codeq already drops.
VENDOR_EXCLUDES: list[str] = [
    # Python
    ".venv",
    "venv",
    "env",
    "site-packages",
    ".python_packages",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".eggs",
    ".benchmarks",
    ".pyre",
    ".pytype",
    "htmlcov",
    ".ipynb_checkpoints",
    # Node / JS / TS
    "node_modules",
    "bower_components",
    "jspm_packages",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".remix",
    ".astro",
    ".gatsby",
    ".turbo",
    ".nx",
    ".nx-cache",
    ".parcel-cache",
    ".ngc-cache",
    ".vite",
    ".angular",
    ".eslintcache",
    ".stylelintcache",
    ".cache",
    ".npm",
    ".pnpm-store",
    ".yarn",
    "coverage",
    ".nyc_output",
    ".docusaurus",
    "storybook-static",
    # Cloud / serverless artifacts
    "cdk.out",
    ".aws-sam",
    "amplify",
    # React Native / Expo
    ".expo",
    ".expo-shared",
    ".metro",
    # Python offline wheel cache
    "wheelhouse",
    # Generic build / output
    "dist",
    "build",
    "out",
    "target",
    "dist-electron",
    ".serverless",
    ".vercel",
    "tmp",
    "temp",
    # Agent harness / memory noise (not source)
    ".memory-bank",
    "memory-bank",
    ".claude",
    ".codex",
    "file-history",
    # JVM
    ".gradle",
    ".mvn",
    # VCS / IDE / editors
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".vs",
    ".history",
    # LSP server workspaces
    ".jdtls-data",
    ".metals",
    ".gopls",
    ".rust-analyzer",
    ".tsserver",
    # AI coding-assistant caches
    ".kilocode",
    ".cursor",
    ".continue",
    ".trae",
    ".windsurf",
    ".cline",
    ".roo",
    ".cody",
    ".augment",
    ".aider*",
    ".codebuddy",
    # Browser automation / MCP server caches
    ".playwright-mcp",
    ".chrome-devtools-mcp",
    ".puppeteer-mcp",
    ".browserbase-mcp",
    ".firecrawl-mcp",
    ".agent-browser",
    ".puppeteer",
    ".playwright",
]

# Harness/runtime trees that are neither project source nor safe secret-scan
# inputs. Keep known credential stores out of gitleaks separately below.
RUNTIME_EXCLUDES: list[str] = [
    "_archive",
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

# Tokens that collide with OS-standard absolute paths (/tmp, /var/tmp).
# A path-matching exclude built from these silently blanks ANY scan under
# /tmp/ — pytest ``tmp_path``, CI temp dirs, manual ``/tmp/...`` work. This is
# the false-negative class behind the original vulture exclude fix; gitleaks
# hits it too because its allowlist ``paths`` is a regex matched against the
# *resolved absolute* ``--source`` path, so ``(^|/)tmp(/|$)`` drops every file
# under /tmp (real secrets go undetected). Drop these tokens from any exclude
# regex that matches on absolute paths. Tools that match on directory SEGMENTS
# (semgrep/ruff ``**/<dir>/**`` globs) are unaffected and keep using the full
# SCAN_EXCLUDES list.
UNSAFE_PATH_EXCLUDES: frozenset[str] = frozenset({"tmp", "temp"})

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
