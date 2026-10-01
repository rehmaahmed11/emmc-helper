"""Shared test fixtures: build the synthetic demo tree once and reuse it."""
from __future__ import annotations

import functools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))


@functools.lru_cache(maxsize=1)
def demo_tree() -> dict:
    """A cached demo tree in the system temp dir (built once per test run)."""
    import make_demo
    import tempfile

    base = Path(tempfile.gettempdir()) / "revive-demo"
    return make_demo.make_demo_tree(base)


def fresh(name: str) -> Path:
    import tempfile

    return Path(tempfile.mkdtemp(prefix=f"revive-{name}-"))


def read(path) -> bytes:
    return Path(path).read_bytes()
