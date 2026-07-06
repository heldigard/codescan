# codescan

Code-quality sensor orchestrator for LLM coding agents. Delegates to
best-in-class tools and prints normalized, token-friendly summaries.

## Sensors

| Subcommand | Tool | What it catches |
|------------|------|-----------------|
| `dead` | vulture (py) / knip (ts,js) | Unused funcs, classes, imports, exports |
| `sec` | semgrep | SAST bugs + security anti-patterns (30+ langs) |
| `secrets` | gitleaks | Leaked keys/tokens in working tree |
| `arch` | dependency-cruiser | Import-rule violations (layering, circular) |
| `all` | (runs all above) | Sequential, CPU-safe |

## Install

```bash
pip install -e .        # dev install
codescan list           # verify sensors
```

## Usage

```bash
codescan list                          # show available sensors + versions
codescan dead -p src/                  # dead code detection
codescan sec -p src/                   # SAST scan
codescan secrets -p src/               # secret leak scan
codescan arch -p src/                  # architecture rules (needs .dependency-cruiser.cjs)
codescan all -p src/                   # run every sensor, summarize
```

`codescan dead` passes the nearest `pyproject.toml` to Vulture when present,
merges project `tool.vulture` ignores with vendor excludes, and suppresses
PEP 562 module hooks (`__getattr__`, `__dir__`) by default.

## External tools

codescan delegates — it does NOT bundle the analysis tools. Install what you need:

```bash
pip install --user vulture semgrep     # Python sensors
npm install -g knip dependency-cruiser # JS/TS sensors
# gitleaks: https://github.com/gitleaks/gitleaks/releases
```

## Related

- [codeq](https://github.com/heldigard/codeq) — code-FACTS (find/body/refs/tags)
- [code-intelligence skill](~/.claude/skills/code-intelligence/) — Claude Code integration
