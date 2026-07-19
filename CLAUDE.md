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
`codescan` console script: `list`, `capabilities`, `dead`, `lint`, `type`,
`sec`, `secrets`, `arch`, `all`.

For CI/router gates, use `codescan all --json --summary-only --fail-on errors`
to fail only on unavailable/broken sensors, or `--fail-on findings` to fail on
quality findings too. The default remains report-only for agent workflows.

## Stack
- Python ≥ 3.11; build backend hatchling; package `codescan-cli` (import `codescan`).
- External sensors (not bundled): **semgrep**, **gitleaks**, **vulture** (Python),
  **knip** (JS/TS), **dependency-cruiser** (JS/TS).

## Conventions
- One sensor per file in `src/codescan/sensors/` (vertical slices).
- Shared infra in `src/codescan/shared/` (config, runner).
- `VENDOR_EXCLUDES` in `shared/config.py` mirrors codeq's list — keep in sync.
- Parallel by default: sensors run concurrently via `shared/concurrency.py`
  (host-aware `min(6, cores)`, `--jobs` / `CODESCAN_JOBS` to override, `--jobs 1`
  for sequential). Sensors are independent subprocesses with no shared state.
- Zero external Python dependencies — delegates to external binaries.

## Key decisions
- **No MCP** — CLI + skill keeps context minimal.
- **Parallel execution** — independent sensor subprocesses run concurrently on
  multi-core hosts; total wall-clock collapses to the slowest sensor.
  `--jobs 1` reproduces the old sequential behavior (the WSL2-era single-core
  rationale no longer applies on the native Ubuntu host).
- **Normalized output** — counts + top findings, not raw diffs.
