# Project: codescan

`codescan` — code-quality sensor orchestrator for LLM coding agents. Public
repo: https://github.com/heldigard/codescan · PyPI: `codescan-cli`.

Parallel to `codeq` (code-FACTS: find/body/refs/tags).
codescan = code-QUALITY sensors (Böckeler/Fowler "maintainability sensors",
May 2026). Each subcommand DELEGATES to a best-in-class tool and prints a
NORMALIZED summary — it does not reinvent analysis.

## Architecture: CLI + skill, NOT MCP
Same rationale as codeq: CLI invoked on-demand by agents, not an MCP server
that loads schemas into context permanently.

## Commands
- Install (dev): `pip install -e .`
- Test: `python3 -m pytest tests/ -q`
- Lint: `ruff check .` · Format: `ruff format --check .`

## Subcommands
`codescan` console script: `list`, `dead`, `sec`, `secrets`, `arch`, `all`.

## Stack
- Python ≥ 3.11; build backend hatchling; package `codescan-cli` (import `codescan`).
- External sensors (not bundled): **semgrep**, **gitleaks**, **vulture** (Python),
  **knip** (JS/TS), **dependency-cruiser** (JS/TS).

## Conventions
- One sensor per file in `src/codescan/sensors/` (vertical slices).
- Shared infra in `src/codescan/shared/` (config, runner).
- `VENDOR_EXCLUDES` in `shared/config.py` mirrors codeq's list — keep in sync.
- CPU-safe: sensors run SEQUENTIALLY (semgrep is heavy; WSL2 single scheduler).
- Zero external Python dependencies — delegates to external binaries.

## Key decisions
- **No MCP** — CLI + skill keeps context minimal.
- **Sequential execution** — CPU safety on WSL2.
- **Normalized output** — counts + top findings, not raw diffs.
