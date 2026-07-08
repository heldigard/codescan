"""vulture dead-code sensor (Python)."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

from codescan.shared.config import VENDOR_EXCLUDES
from codescan.shared.runner import find_upward, have, print_topn, run

_DEFAULT_MIN_CONFIDENCE = 60
_DEFAULT_IGNORE_NAMES = ["__getattr__", "__dir__"]
# Override callbacks invoked by the framework by reflection, not by AST call.
# vulture is AST-local: it sees the def but not that HTMLParser().feed() and
# SAX ContentHandler dispatch to these by name, so it reports them as dead —
# the single largest source of vulture false-positives in real codebases.
# Only specific override names (never bare generics like `run`/`handle`/
# `setup`, which would mask genuinely-dead code). Standard protocol dunders
# (__str__/__len__/__init__) and unittest lifecycle (setUp/tearDown) are
# already ignored by vulture itself and intentionally NOT duplicated here.
_PARSER_CALLBACK_NAMES = [
    # html.parser.HTMLParser overrides
    "handle_starttag",
    "handle_endtag",
    "handle_startendtag",
    "handle_data",
    "handle_comment",
    "handle_entityref",
    "handle_charref",
    "handle_decl",
    "handle_pi",
    "unknown_decl",
    # xml.sax ContentHandler overrides
    "startElement",
    "endElement",
    "startElementNS",
    "endElementNS",
    "characters",
    "startDocument",
    "endDocument",
    "startPrefixMapping",
    "endPrefixMapping",
    "ignorableWhitespace",
    "processingInstruction",
    "skippedEntity",
]
# Tokens that collide with OS-standard absolute paths (/tmp, /var/tmp) which
# vulture resolves to. Segment-anchoring cannot rescue these: */tmp/* matches
# every path under /tmp/, blinding the sensor under pytest's tmp_path and CI.
# Strip them entirely; the substring-artifact tokens (out/env/build/dist/target)
# are handled by segment-anchoring in _vulture_excludes instead.
_VULTURE_UNSAFE_EXCLUDES = {"tmp", "temp"}


def _vulture_settings(config: Path | None) -> dict:
    """Read [tool.vulture] settings when available."""
    if config is None:
        return {}
    try:
        with config.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    settings = data.get("tool", {}).get("vulture", {})
    return settings if isinstance(settings, dict) else {}


def _vulture_excludes(settings: dict) -> list[str]:
    """Segment-anchored vendor excludes for vulture.

    vulture wraps any pattern lacking glob chars (``*?[``) in ``*...*``, turning
    a bare ``out`` into ``*out*`` — a substring match that silently excludes
    every path containing "out", e.g. ``agentic_cycle_router.py`` (r-OUT-er).
    That blinded the sensor and produced false "unused" reports for symbols
    called from such files (incident: ``update_from_prompt`` flagged dead while
    live-called from ``agentic_cycle_router.py``).

    Fix: emit directory-segment-anchored globs — ``*/<dir>/*`` for nested
    vendor dirs (``src/pkg/<dir>/x.py``) and ``<dir>/*`` for scan-root vendor
    dirs (``<dir>/x.py``). Both require ``<dir>/`` as a real path segment, so
    ``router.py``/``environment.py``/``build_command.py`` are never matched.
    This follows vulture's own convention for test detection (``*/test/*``).
    Project-level excludes pass through verbatim; vulture's prepare_pattern
    anchors bare project tokens per its own contract (the user's choice).
    """
    excludes: list[str] = []
    for token in VENDOR_EXCLUDES:
        if token in _VULTURE_UNSAFE_EXCLUDES:
            continue
        excludes.append(f"*/{token}/*")
        excludes.append(f"{token}/*")
    project_excludes = settings.get("exclude", [])
    if isinstance(project_excludes, list):
        excludes.extend(str(exclude) for exclude in project_excludes)
    return list(dict.fromkeys(excludes))


def _vulture_ignore_names(settings: dict) -> list[str]:
    """Names vulture suppresses itself via --ignore-names (hooks + project).

    Parser/ContentHandler callbacks are intentionally NOT here: vulture would
    then suppress the method, but the method's def line is what lets the
    post-filter pair it with its unused signature params. Callbacks are
    suppressed in the post-filter instead, where the def line stays visible.
    """
    ignore_names = [*_DEFAULT_IGNORE_NAMES]
    project_ignore_names = settings.get("ignore_names", [])
    if isinstance(project_ignore_names, list):
        ignore_names.extend(str(name) for name in project_ignore_names)
    return list(dict.fromkeys(ignore_names))


_VULTURE_LINE_RE = re.compile(r"^(?P<loc>.+?:\d+):\s+unused\s+(?P<kind>\w+)\s+'(?P<name>[^']+)'")


def _parse_vulture_finding(line: str) -> tuple[str, str, str] | None:
    """Return (loc_key, kind, name) for a vulture output line, else None.

    ``loc_key`` is ``path:line`` — the def line vulture reports — so a callback
    method and its signature parameters share the same key. That co-location is
    what lets the arg-noise post-filter pair them.
    """
    match = _VULTURE_LINE_RE.match(line)
    if match is None:
        return None
    return match["loc"], match["kind"], match["name"]


def _drop_callback_findings(lines: list[str], callbacks: list[str]) -> list[str]:
    """Suppress framework-callback findings and their signature-param noise.

    vulture emits both the override method (e.g. ``handle_starttag``) and its
    unused signature params (``tag``/``attrs``) on the same def line. We drop:
    (a) the callback method/function/class itself, and (b) any unused-variable
    /argument hit sharing its ``path:line`` — those params are protocol-signature
    noise, not actionable dead code. Params on standalone lines are untouched.
    """
    suppressed = set(callbacks)
    dominated: set[str] = set()
    for ln in lines:
        parsed = _parse_vulture_finding(ln)
        if parsed and parsed[1] in ("method", "function", "class") and parsed[2] in suppressed:
            dominated.add(parsed[0])
    kept: list[str] = []
    for ln in lines:
        parsed = _parse_vulture_finding(ln)
        if parsed is None:
            kept.append(ln)
            continue
        loc, kind, name = parsed
        if name in suppressed:
            continue
        if kind in ("variable", "argument") and loc in dominated:
            continue
        kept.append(ln)
    return kept


def _vulture_command(
    path: Path, min_confidence: int | None
) -> tuple[list[str], int | str, list[str]]:
    config_root = find_upward(path, "pyproject.toml")
    config = config_root / "pyproject.toml" if config_root is not None else None
    settings = _vulture_settings(config)
    command = ["vulture", str(path)]
    if config is not None:
        command.extend(["--config", str(config)])

    effective_confidence: int | str
    if min_confidence is not None:
        effective_confidence = min_confidence
        command.extend(["--min-confidence", str(min_confidence)])
    elif "min_confidence" in settings:
        effective_confidence = settings["min_confidence"]
    else:
        effective_confidence = _DEFAULT_MIN_CONFIDENCE
        command.extend(["--min-confidence", str(_DEFAULT_MIN_CONFIDENCE)])

    command.extend(["--exclude", ",".join(_vulture_excludes(settings))])
    command.extend(["--ignore-names", ",".join(_vulture_ignore_names(settings))])
    # Callbacks are post-filtered (not via --ignore-names) so their def line
    # stays visible to dominate their signature params.
    return command, effective_confidence, list(_PARSER_CALLBACK_NAMES)


def cmd_dead_py(path: Path, min_confidence: int | None) -> int:
    """Run vulture on a Python project."""
    if not have("vulture"):
        print("vulture not installed — skipping Python dead-code", file=sys.stderr)
        return 1
    command, effective_confidence, callbacks = _vulture_command(path, min_confidence)
    rc, out, err = run(command)
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    if rc != 0 and not lines:
        print(f"vulture error: {err.strip()}", file=sys.stderr)
        return 2
    lines = _drop_callback_findings(lines, callbacks)
    print(f"== vulture (Python dead code, min-confidence {effective_confidence}) on {path} ==")
    print(f"items: {len(lines)}")
    print_topn(lines)
    return 0
