"""Manual smoke runner preserved from the former monolithic test_codescan.py.

`python -m pytest` remains the canonical gate; this only keeps the legacy
`python tests/test_codescan.py` workflow working after the slice split by
importing the same test functions from their new modules.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ._helpers import run
from .test_all_aggregator import test_codescan_all_offline_skips_semgrep
from .test_arch import (
    test_codescan_arch_init_creates_starter,
    test_codescan_arch_skips_without_config,
)
from .test_cli_meta import test_codescan_list
from .test_dead import (
    test_codescan_dead_detects,
    test_codescan_dead_no_substring_exclude_false_positive,
)


def main() -> int:
    print("codescan orchestrator smoke test")
    run(["which", "codescan"])  # host PATH probe

    test_codescan_list()
    print("  codescan list: OK")

    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp) / "proj"
        proj.mkdir()
        test_codescan_dead_detects(proj)
        print("  codescan dead (vulture, vendor-excluded): OK")
        substring_proj = Path(tmp) / "substring"
        substring_proj.mkdir()
        test_codescan_dead_no_substring_exclude_false_positive(substring_proj)
        print("  codescan dead (no substring-exclude false positive): OK")
        test_codescan_arch_skips_without_config(proj)
        print("  codescan arch (skip without config): OK")
        test_codescan_arch_init_creates_starter(proj)
        print("  codescan arch --init: OK")
        test_codescan_all_offline_skips_semgrep(proj)
        print("  codescan all --offline: OK")

    print("\n✅ all codescan checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
