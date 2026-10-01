"""revive-termux: Revive for a plain Termux install (Python standard library only).

  revive-termux <revive command> ...      any normal Revive command (inspect, plan, serve, ...)
  revive-termux usb [opts] <command> ...  same, but first attach a phone over USB-OTG through
                                          termux-usb (Android asks for permission once)
  revive-termux usb-list                  list USB devices Android can see
  revive-termux doctor                    check this Termux install
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent          # termux-variant/revive_termux -> repo root
for candidate in (REPO, HERE.parent):
    if (candidate / "revive" / "cli.py").is_file() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

ENV_ARGV = "REVIVE_TERMUX_ARGV"
ENV_PATH = "REVIVE_TERMUX_PATH"


def _err(msg: str) -> None:
    print(f"revive-termux: {msg}", file=sys.stderr)


def _run_revive(argv: List[str]) -> int:
    try:
        from revive import cli
    except ImportError as exc:
        _err(f"cannot import the Revive package ({exc}). Keep termux-variant/ inside the "
             "emmc-helper checkout, or re-run termux-variant/install.sh.")
        return 2
    from . import patch
    patch.apply()
    return int(cli.main(argv) or 0)


# ------------------------------------------------------------------------------------------
# termux-usb plumbing
# ------------------------------------------------------------------------------------------
def list_usb() -> List[str]:
    if not shutil.which("termux-usb"):
        _err("termux-usb not found. Run:  pkg install termux-api   and install the "
             "Termux:API app (same source as Termux: F-Droid or GitHub, not Play Store).")
        return []
    try:
        out = subprocess.run(["termux-usb", "-l"], capture_output=True, text=True, timeout=20).stdout
        data = json.loads(out or "[]")
        return [str(p) for p in data] if isinstance(data, list) else []
    except (subprocess.TimeoutExpired, ValueError) as exc:
        _err(f"termux-usb -l failed ({exc}). Is the Termux:API app installed and opened once?")
        return []


def cmd_usb(argv: List[str]) -> int:
    device: Optional[str] = None
    wait = 0.0
    while argv and argv[0].startswith("--"):
        opt = argv.pop(0)
        if opt == "--device" and argv:
            device = argv.pop(0)
        elif opt == "--wait" and argv:
            wait = float(argv.pop(0))
        elif opt == "--":
            break
        else:
            _err(f"unknown option {opt}. Usage: revive-termux usb [--device PATH] [--wait SEC] <command>")
            return 2
    if not argv:
        argv = ["detect"]

    before = set(list_usb())
    if device is None:
        deadline = time.time() + wait
        paths = sorted(before)
        if wait > 0:
            print(f"Waiting up to {wait:g}s for a NEW USB device - plug the phone in now...")
            while time.time() < deadline:
                new = sorted(set(list_usb()) - before)
                if new:
                    paths = new
                    break
                time.sleep(0.2)
        if not paths:
            _err("no USB device visible. Check the OTG adapter/cable and that the phone is in "
                 "a download mode (see: revive-termux guide testpoint).")
            return 1
        if len(paths) > 1 and sys.stdin.isatty():
            for i, p in enumerate(paths):
                print(f"  [{i}] {p}")
            choice = input("Which device? [0] ").strip() or "0"
            device = paths[int(choice)] if choice.isdigit() and int(choice) < len(paths) else paths[0]
        else:
            device = paths[0]

    # termux-usb runs one executable with the fd appended as its last argument, so the real
    # Revive argv travels through the environment.
    fd_script = Path(os.environ.get("TMPDIR") or tempfile.gettempdir()) / "revive-termux-fd.sh"
    fd_script.write_text(
        "#!/data/data/com.termux/files/usr/bin/sh\n"
        f"exec {shlex.quote(sys.executable)} -m revive_termux --fd-run \"$@\"\n")
    fd_script.chmod(0o755)
    env = dict(os.environ)
    env[ENV_ARGV] = json.dumps(argv)
    env[ENV_PATH] = device
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(HERE.parent), env.get("PYTHONPATH")]))
    print(f"Requesting USB permission for {device} (accept the Android dialog)...")
    return subprocess.call(["termux-usb", "-r", "-e", str(fd_script), device], env=env)


def cmd_fd_run(argv: List[str]) -> int:
    fd_text = os.environ.get("TERMUX_USB_FD") or (argv[-1] if argv else "")
    if not fd_text.strip().isdigit():
        _err("termux-usb did not pass a file descriptor (permission denied?).")
        return 1
    revive_argv = json.loads(os.environ.get(ENV_ARGV, '["detect"]'))
    from . import patch
    try:
        dev = patch.register_fd(int(fd_text), os.environ.get(ENV_PATH, ""))
    except Exception as exc:
        _err(f"could not read the USB device: {exc}")
        return 1
    print(f"Attached {dev.idVendor:04x}:{dev.idProduct:04x} {dev.product or ''} via termux-usb")
    return _run_revive(revive_argv)


def cmd_doctor() -> int:
    from . import patch
    ok = True

    def row(good: bool, label: str, hint: str = "") -> None:
        nonlocal ok
        ok = ok and good
        print(f"  [{'OK' if good else '!!'}] {label}" + (f"\n        -> {hint}" if hint and not good else ""))

    print("Revive Termux doctor")
    row(sys.version_info >= (3, 8), f"Python {sys.version.split()[0]}", "pkg install python")
    row(patch.is_termux(), "running inside Termux", "this variant is meant for Termux")
    try:
        import ctypes, fcntl  # noqa: F401,E401
        row(True, "ctypes + fcntl (needed for USB ioctls)")
    except ImportError:
        row(False, "ctypes + fcntl", "pkg reinstall python")
    try:
        import revive  # noqa: F401
        row(True, "Revive package importable")
    except ImportError:
        row(False, "Revive package importable", "keep termux-variant/ inside the checkout")
    row(bool(shutil.which("termux-usb")), "termux-usb (USB-OTG access)",
        "pkg install termux-api  + install the Termux:API app")
    row(bool(shutil.which("termux-open-url")), "termux-open-url (opens the web UI)",
        "pkg install termux-api")
    row(Path.home().joinpath("storage").exists(), "~/storage (access to Download/ firmware)",
        "run: termux-setup-storage")
    print("All good." if ok else "Some optional pieces are missing; file tools still work.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--fd-run":
        return cmd_fd_run(argv[1:])
    if argv and argv[0] == "usb":
        return cmd_usb(argv[1:])
    if argv and argv[0] == "usb-list":
        paths = list_usb()
        print("\n".join(paths) if paths else "no USB devices visible")
        return 0 if paths else 1
    if argv and argv[0] == "doctor":
        return cmd_doctor()
    if argv and argv[0] in ("-h", "--help", "help"):
        print(__doc__)
    return _run_revive(argv)


if __name__ == "__main__":
    raise SystemExit(main())
