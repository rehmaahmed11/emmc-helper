"""Re-route Revive's USB layer onto termux-usb file descriptors.

Revive's backends always call `usbfinder.<func>` / `usbmodes.<func>` through the module, so
replacing those attributes is enough - no file of the main package is modified.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import webbrowser
from typing import Any, Dict, List, Optional, Set, Tuple

from .usbdevfs import TermuxUsbDevice

DEVICES: List[TermuxUsbDevice] = []


def is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or os.path.isdir("/data/data/com.termux")


def register_fd(fd: int, path: str = "") -> TermuxUsbDevice:
    dev = TermuxUsbDevice(fd, path)
    DEVICES.append(dev)
    return dev


def _install_hint() -> str:
    return ("pkg install termux-api  (and install the Termux:API app from F-Droid), then run "
            "your command through:  revive-termux usb <command>")


def apply() -> None:
    from revive.backends import usbfinder
    from revive.core import usbmodes

    def libusb_available() -> bool:
        return bool(DEVICES)

    def pyserial_available() -> bool:
        return False          # /dev/ttyACM* is not reachable without root on Android

    def _match(dev: Any, vid: Optional[int], pid: Optional[int]) -> bool:
        return (vid is None or dev.idVendor == vid) and (pid is None or dev.idProduct == pid)

    def find_devices(vid: Optional[int] = None, pid: Optional[int] = None,
                     mode: Optional[str] = None) -> Tuple[List[Any], List[str]]:
        if not DEVICES:
            return [], ["No USB device has been handed to Revive. On Termux run: "
                        "revive-termux usb <command>  (it asks Android for USB permission)."]
        found = [d for d in DEVICES if _match(d, vid, pid)]
        if mode:
            found = [d for d in found if usbmodes.classify(d.idVendor, d.idProduct)[0] == mode]
        return found, []

    def fast_find_devices(target_vid_pids: Optional[Set[Tuple[int, int]]] = None,
                          target_vids: Optional[Set[int]] = None,
                          target_modes: Optional[Set[str]] = None) -> List[Any]:
        out = []
        for d in DEVICES:
            mode = usbmodes.classify(d.idVendor, d.idProduct)[0]
            if target_vid_pids and (d.idVendor, d.idProduct) in target_vid_pids:
                out.append(d)
            elif target_vids and d.idVendor in target_vids and not target_modes:
                out.append(d)
            elif target_modes and mode in target_modes:
                out.append(d)
            elif not (target_vid_pids or target_vids or target_modes) and mode != usbmodes.MODE_UNKNOWN:
                out.append(d)
        return out

    original_open = usbfinder.open_device

    def open_device(device: Any, endpoints: Any = None, detach: bool = True,
                    set_configuration: bool = True) -> Any:
        if not getattr(device, "is_termux_usb", False):
            return original_open(device, endpoints, detach, set_configuration)
        eps = original_open(device, endpoints, detach, set_configuration=False)
        try:
            device.claim_interface(eps.interface)
        except Exception as exc:
            raise usbfinder._translate_usb_error(exc, device)
        return eps

    def fast_open_device(device: Any, endpoints: Any = None) -> Any:
        return open_device(device, endpoints, detach=True, set_configuration=False)

    def enumerate_devices(include_unknown: bool = True):
        devices, warnings = [], []
        for d in DEVICES:
            hit = usbmodes.match(d.idVendor, d.idProduct)
            if not hit and not include_unknown:
                continue
            mode, label = usbmodes.classify(d.idVendor, d.idProduct)
            info = usbmodes.mode_info(mode)
            devices.append(usbmodes.UsbDevice(
                d.idVendor, d.idProduct, bus=d.bus, address=d.address,
                manufacturer=d.manufacturer, product=d.product, serial=d.serial_number,
                mode=mode, label=hit.label if hit else label,
                backend=info.backend, flashable=info.flashable))
        if not DEVICES:
            warnings.append("Termux: no USB device attached to this run. Use "
                            "`revive-termux usb detect` to pick one (Android will ask permission).")
        return devices, warnings

    usbmodes.libusb_available = libusb_available
    usbmodes.pyserial_available = pyserial_available
    usbmodes.install_hint = _install_hint
    usbmodes.enumerate_devices = enumerate_devices
    usbmodes.serial_ports = lambda: []
    usbfinder.find_devices = find_devices
    usbfinder.fast_find_devices = fast_find_devices
    usbfinder.find_serial_devices = lambda *a, **k: []
    usbfinder.open_device = open_device
    usbfinder.fast_open_device = fast_open_device
    # sysfs/dmesg tricks need root on Android; keep them harmless.
    usbfinder.scan_usb_bounces = lambda max_lines=80: []

    original_reenum = usbfinder.force_usb_reenumeration

    def force_usb_reenumeration(device: Any = None, vid: Any = None, pid: Any = None) -> List[str]:
        if getattr(device, "is_termux_usb", False):
            try:
                device.reset()
                return ["USBDEVFS_RESET via termux-usb fd"]
            except Exception as exc:
                return [f"reset failed: {exc}"]
        return [] if is_termux() else original_reenum(device, vid, pid)

    usbfinder.force_usb_reenumeration = force_usb_reenumeration

    # The web UI's --open: Termux has no desktop browser hook, but termux-open-url works.
    if shutil.which("termux-open-url"):
        def _open(url: str, *a: Any, **k: Any) -> bool:
            subprocess.Popen(["termux-open-url", url], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return True
        webbrowser.open = _open
