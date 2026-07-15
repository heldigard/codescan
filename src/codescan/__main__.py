"""Allow `python -m codescan`."""

from __future__ import annotations

import sys

from codescan.cli import main

if __name__ == "__main__":
    sys.exit(main())
