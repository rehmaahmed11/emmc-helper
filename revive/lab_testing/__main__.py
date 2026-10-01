"""`python -m revive.lab_testing` - the lab's own entry point."""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
