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


class patched:
    """Context manager: temporarily replace attributes on a module, then restore them.

    The suite is plain Python (no pytest fixtures), so fault-injection tests need their own
    monkeypatch. Usage::

        with patched(usbfinder, wait_for_device=lambda *a, **k: None):
            ...
    """

    def __init__(self, module, **attrs):
        self._module = module
        self._attrs = attrs
        self._saved = {}
        self._missing = set()

    def __enter__(self):
        for name, value in self._attrs.items():
            if hasattr(self._module, name):
                self._saved[name] = getattr(self._module, name)
            else:
                self._missing.add(name)
            setattr(self._module, name, value)
        return self._module

    def __exit__(self, *exc):
        for name in self._attrs:
            if name in self._saved:
                setattr(self._module, name, self._saved[name])
            elif name in self._missing:
                delattr(self._module, name)
        return False
