"""Finding and claiming USB devices without making libusb a hard dependency.

Everything here degrades gracefully: if pyusb/libusb is missing, the caller gets a warning it
can print and a hint it can show the user, never a stack trace. When libusb is present we also
take care of the two things that make raw USB on phones annoying on Linux/macOS: detaching the
kernel driver and (optionally) resetting a device that is stuck from a previous failed session.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..core import usbmodes
from .base import BackendError, BackendUnavailable, Endpoints


@dataclass
class UsbDevice:
    """A found USB device plus the identity we care about."""

    handle: Any = None
    vid: int = 0
    pid: int = 0
    bus: Optional[int] = None
    address: Optional[int] = None
    serial: str = ""
    manufacturer: str = ""
    product: str = ""
    mode: str = ""
    label: str = ""

    @property
    def usb_id(self) -> str:
        return f"{self.vid:04x}:{self.pid:04x}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "usb_id": self.usb_id, "vid": self.vid, "pid": self.pid,
            "bus": self.bus, "address": self.address, "serial": self.serial,
            "manufacturer": self.manufacturer, "product": self.product,
            "mode": self.mode, "label": self.label,
        }


def have_libusb() -> bool:
    return usbmodes.libusb_available()


def _usb():
    import usb.core  # noqa: WPS433 (import inside function on purpose)
    import usb.util

    return usb.core, usb.util


def find_devices(vid: Optional[int] = None, pid: Optional[int] = None,
                 mode: Optional[str] = None) -> Tuple[List[Any], List[str]]:
    """Find USB devices, optionally filtered by ID or by revive mode. Returns (devices, warnings)."""
    warnings: List[str] = []
    if not have_libusb():
        return [], [
            "pyusb/libusb is not installed, so no phone can be opened. Install it with: "
            + usbmodes.install_hint()
        ]
    usb_core, _ = _usb()
    try:
        kwargs: Dict[str, Any] = {"find_all": True}
        if vid is not None:
            kwargs["idVendor"] = vid
        if pid is not None:
            kwargs["idProduct"] = pid
        devices = list(usb_core.find(**kwargs))
    except Exception as exc:  # pragma: no cover - host dependent
        return [], [f"libusb could not enumerate devices: {exc}"]

    if mode:
        wanted = {m.mode for m in usbmodes.MODES.values() if m.mode == mode}
        devices = [d for d in devices
                   if usbmodes.classify(int(d.idVendor), int(d.idProduct))[0] in wanted]
    return devices, warnings


def open_device(device: Any, endpoints: Optional[Endpoints] = None,
                detach: bool = True, set_configuration: bool = True) -> Endpoints:
    """Claim the device and work out which endpoints to use."""
    usb_core, usb_util = _usb()
    eps = endpoints or Endpoints()
    try:
        if set_configuration:
            try:
                device.set_configuration()
            except Exception:
                pass          # already configured / kernel driver owns it
        if detach:
            try:
                if device.is_kernel_driver_active(eps.interface):
                    device.detach_kernel_driver(eps.interface)
            except Exception:
                pass
        try:
            usb_util.claim_interface(device, eps.interface)
        except Exception:
            pass
    except Exception as exc:
        raise _translate_usb_error(exc, device)

    # Discover real endpoints when the caller did not pin them.
    try:
        cfg = device.get_active_configuration()
        for intf in cfg:
            for ep in intf:
                direction = int(getattr(ep, "bEndpointAddress", 0))
                if direction & 0x80 and eps.in_ep == 0x81:
                    eps.in_ep = direction
                    eps.interface = int(intf.bInterfaceNumber)
                elif not direction & 0x80 and eps.out_ep == 0x01:
                    eps.out_ep = direction
    except Exception:
        pass
    return eps


def _translate_usb_error(exc: Exception, device: Any) -> BackendError:
    text = str(exc).lower()
    vid = getattr(device, "idVendor", 0)
    pid = getattr(device, "idProduct", 0)
    usb_id = f"{vid:04x}:{pid:04x}"
    if "access" in text or "permission" in text or "errno 13" in text:
        return BackendUnavailable(
            f"Permission denied opening {usb_id} (device is present but this user cannot claim it).",
            code="driver_missing",
            detail="On Linux install the udev rule from `revive drivers`; on Windows run as "
                   "Administrator once to bind the driver.",
        )
    if "busy" in text or "resource busy" in text:
        return BackendUnavailable(
            f"{usb_id} is busy: another program is holding it.",
            code="port_busy",
            detail="Close SP Flash Tool / other flashers, stop the adb server, then replug.",
        )
    if "no such device" in text or "not found" in text or "disconnected" in text:
        return BackendUnavailable(
            f"{usb_id} disappeared while opening it.",
            code="no_device",
            detail="BROM devices leave this mode within about a second of power-up - start the "
                   "operation first, then plug the phone in.",
        )
    return BackendError(f"USB open failed for {usb_id}: {exc}", code="driver_missing")


def wait_for_device(vid: int, pid: int, timeout: float = 30.0, interval: float = 0.25
                    ) -> Optional[Any]:
    """Poll for a device to appear (BROM only shows up for a moment after power-up)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        devices, _ = find_devices(vid, pid)
        if devices:
            return devices[0]
        time.sleep(interval)
    return None


def reset_device(device: Any) -> None:
    """Try a USB port reset - the standard cure for a device stuck from a bad session."""
    try:
        device.reset()
    except Exception:
        try:
            import usb.core

            device.ctrl_transfer(0x21, 0x20, 0, 0, b"", 1000)
        except Exception:
            pass


def describe_device(device: Any) -> Dict[str, Any]:
    vid = int(getattr(device, "idVendor", 0))
    pid = int(getattr(device, "idProduct", 0))
    mode, label = usbmodes.classify(vid, pid)
    info = usbmodes.mode_info(mode)
    out = {
        "usb_id": f"{vid:04x}:{pid:04x}",
        "mode": mode,
        "label": label,
        "backend": info.backend,
        "flashable": info.flashable,
        "bus": getattr(device, "bus", None),
        "address": getattr(device, "address", None),
    }
    try:
        _, usb_util = _usb()
        out["manufacturer"] = usb_util.get_string(device, device.iManufacturer) or ""
        out["product"] = usb_util.get_string(device, device.iProduct) or ""
        out["serial"] = usb_util.get_string(device, device.iSerialNumber) or ""
    except Exception:
        pass
    return out
