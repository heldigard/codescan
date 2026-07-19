# codescan

Code-quality sensor orchestrator for LLM coding agents. Delegates to
best-in-class tools and prints normalized, token-friendly summaries.

## Sensors

| Subcommand | Tool | What it catches |
|------------|------|-----------------|
| `dead` | vulture (py) / knip (ts,js) | Unused funcs, classes, imports, exports |
| `lint` | ruff | Fast Python lint diagnostics |
| `type` | pyright / mypy | Python type diagnostics |
| `sec` | semgrep | SAST bugs + security anti-patterns (30+ langs) |
| `secrets` | gitleaks | Leaked keys/tokens in working tree |
| `arch` | dependency-cruiser | Import-rule violations (layering, circular) |
| `all` | (runs all above) | Parallel, host-aware (collapses to the slowest sensor) |
| `capabilities` | built-in | Machine-readable sensor metadata for routers/workers |

## Install

```bash
pip install -e .        # dev install
codescan list           # verify sensors
```

## Usage

```bash
codescan list                          # show available sensors + versions
codescan capabilities                  # JSON metadata: safety, cost, external tools
codescan dead -p src/                  # dead code detection
codescan lint -p src/                  # Python lint checks
codescan type -p src/ --tool auto      # Python type checks
codescan sec -p src/                   # SAST scan
codescan secrets -p src/               # secret leak scan
codescan arch -p src/                  # architecture rules (needs .dependency-cruiser.cjs)
codescan all -p src/                   # run every sensor, summarize (parallel)
codescan all -p src/ --json            # compact structured handoff for routers/workers
codescan all -p src/ --jobs 1          # force sequential (debugging / single-core CI)
codescan all -p src/ --skip sec,arch   # omit sensors from the run entirely
```

### Parallelism

`codescan all` runs sensors concurrently — they are independent subprocess
invocations with no shared state, so on a multi-core host the total wall-clock
collapses to roughly the slowest sensor (typically semgrep) instead of the sum
of all of them. Width is host-aware and bounded:

- default: `min(6, cpu_count)` — leaves headroom for Ollama / desktop / agents
- `CODESCAN_JOBS=N` env var, or `--jobs N` flag, overrides it
- `--jobs 1` reproduces the exact pre-parallel sequential behavior

Each sensor payload in `--json` output carries a `duration_ms` field so a
router can see which sensor dominates.

### CI / router gates

`codescan all --json` is the machine-readable handoff. Combine flags to control
how findings map to the exit code:

```bash
# Report-only (default): always exit 0, findings are advisory. Best for agent loops.
codescan all -p src/ --json --summary-only

# Fail only when a sensor is unavailable/broken (exit 2), not on findings.
codescan all -p src/ --json --summary-only --fail-on errors

# Strict quality gate: exit 1 on any finding, 2 on sensor failure.
codescan all -p src/ --json --summary-only --fail-on findings
```

`--summary-only` omits the per-finding lists across **every** sensor
(secrets/sec/dead/lint/type/arch) and keeps only aggregate counts — the compact
form for routers and cheap/local model triage. `--fail-on` requires `--json`.

`codescan dead` passes the nearest `pyproject.toml` to Vulture when present,
merges project `tool.vulture` ignores with vendor excludes, and suppresses
PEP 562 module hooks (`__getattr__`, `__dir__`) by default.

`codescan capabilities` is the integration contract for controllers, routers,
and workers. It reports `schema_version`, available sensor names, safety hints
(`read_only`, `destructive`, `idempotent`, `open_world`), required external
tools, and rough cost so the big model can choose the narrowest useful quality
sensor without memorizing CLI details.

Every actionable sensor (`dead`, `lint`, `type`, `sec`, `secrets`, `arch`, `all`) supports
`--json`. Prefer this mode for worker scripts and cheap/local model triage:
payloads are bounded, schema-versioned, and expose aggregate counts plus a
small findings list without forcing regex scraping of human output.

## External tools

codescan delegates — it does NOT bundle the analysis tools. Install what you need:

```bash
pip install --user vulture semgrep ruff mypy  # Python sensors
npm install -g pyright                         # Python type sensor
npm install -g knip dependency-cruiser # JS/TS sensors
# gitleaks: https://github.com/gitleaks/gitleaks/releases
```

## Related

- [codeq](https://github.com/heldigard/codeq) — code-FACTS (find/body/refs/tags)
- [code-intelligence skill](~/.claude/skills/code-intelligence/) — Claude Code integration
