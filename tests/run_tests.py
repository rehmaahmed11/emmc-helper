"""Zero-dependency test runner.

Revive must run on repair-shop machines where installing pytest may not be possible, so the
test suite is plain Python. Run it with:

    python tests/run_tests.py            # everything
    python tests/run_tests.py gpt sparse # only modules whose name contains these words
"""
from __future__ import annotations

import importlib
import inspect
import shutil
import os
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

MODULES = [
    "test_util",
    "test_errors",
    "test_gpt",
    "test_storage",
    "test_firmware",
    "test_ops",
    "test_backends",
    "test_dead_device_audit",
    "test_ui",
    # LAB TESTING
    "test_lab_device",
    "test_virtual_emmc",
    "test_brick_engine",
    "test_recovery_flow",
    "test_lab_ui",
]

_RESULTS = {"pass": 0, "fail": 0, "error": 0}
_FAILURES: list = []


def _run_module(name: str) -> None:
    module = importlib.import_module(name)
    tests = [(n, f) for n, f in vars(module).items() if n.startswith("test_") and callable(f)]
    tests.sort(key=lambda pair: getattr(pair[1], "__code__", None).co_firstlineno if
               getattr(pair[1], "__code__", None) else 0)
    print(f"\n=== {name} ({len(tests)} tests) ===")
    for test_name, fn in tests:
        tmp = tempfile.mkdtemp(prefix="revive-test-")
        try:
            # Tests take the temp dir when they want it; the rest are plain callables.
            if inspect.signature(fn).parameters:
                fn(Path(tmp))
            else:
                fn()
            _RESULTS["pass"] += 1
            print(f"  PASS  {test_name}")
        except AssertionError as exc:
            _RESULTS["fail"] += 1
            _FAILURES.append((name, test_name, str(exc) or "assertion failed"))
            print(f"  FAIL  {test_name}: {exc}")
        except Exception as exc:  # unexpected error in the test itself
            _RESULTS["error"] += 1
            _FAILURES.append((name, test_name, f"{type(exc).__name__}: {exc}"))
            print(f"  ERROR {test_name}: {type(exc).__name__}: {exc}")
            traceback.print_exc(limit=4)
        finally:
            # The lab tests build real device images, so a run that does not clean up after
            # itself fills the disk. Every test gets a fresh directory and gives it back.
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list) -> int:
    filters = [a for a in argv if not a.startswith("-")]
    modules = [m for m in MODULES if not filters or any(f.lower() in m for f in filters)]
    if not modules:
        print(f"no test modules match {filters}")
        return 2
    for name in modules:
        try:
            _run_module(name)
        except Exception as exc:  # module level failure
            _RESULTS["error"] += 1
            _FAILURES.append((name, "<import>", str(exc)))
            print(f"\n=== {name} ===\n  ERROR importing: {exc}")
            traceback.print_exc(limit=3)

    total = sum(_RESULTS.values())
    print(f"\n{'-' * 60}")
    print(f"{total} tests: {_RESULTS['pass']} passed, {_RESULTS['fail']} failed, "
          f"{_RESULTS['error']} errored")
    if _FAILURES:
        print("\nfailures:")
        for module, test, message in _FAILURES:
            print(f"  {module}.{test}: {message}")
    return 0 if _RESULTS["fail"] == 0 and _RESULTS["error"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
