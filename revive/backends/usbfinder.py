"""Finding and claiming USB devices without making libusb a hard dependency.

Everything here degrades gracefully: if pyusb/libusb is missing, the caller gets a warning it
can print and a hint it can show the user, never a stack trace. When libusb is present we also
take care of the two things that make raw USB on phones annoying on Linux/macOS: detaching the
kernel driver and (optionally) resetting a device that is stuck from a previous failed session.

For sub-millisecond BROM/EDL interception this module also provides:
  * `fast_find_devices`: zero-string-descriptor enumeration (inspects integer VID:PID only)
  * `fast_open_device`: atomic multi-interface kernel driver detach + immediate bulk EP claim
  * `SerialTransportAdapter`: exposes a serial/COM/ttyACM port with the same `.read`/`.write`/
    `.ctrl_transfer` surface as a libusb device so backends work even when the OS bound a VCOM
    driver first
  * `force_usb_reenumeration` & `scan_usb_bounces`: host-side port reset, sysfs authorized
    cycling, and kernel USB bounce detection
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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


class SerialTransportAdapter:
    """Wraps a pyserial (or file-like) port to look like a libusb device handle.

    On Windows (MediaTek VCOM / Qualcomm 9008 COM port) and on Linux when `cdc_acm` or `option`
    claims the interface before libusb detaches it, the fastest path into BROM/Preloader/BSL is
    often the serial port node itself. Wrapping it with `.write(ep, data, timeout_ms)` and
    `.read(ep, length, timeout_ms)` lets every backend and handshake hammer run unmodified.
    """

    def __init__(self, port_obj: Any, port_name: str = "", vid: int = 0, pid: int = 0,
                 serial_number: str = ""):
        self._port = port_obj
        self.port_name = port_name or getattr(port_obj, "port", "") or ""
        self.idVendor = int(vid)
        self.idProduct = int(pid)
        self.bus = None
        self.address = None
        self.serial_number = serial_number
        self.is_serial_adapter = True

    def write(self, endpoint: int, data: bytes, timeout: Optional[float] = None) -> int:
        if timeout is not None and hasattr(self._port, "write_timeout"):
            try:
                self._port.write_timeout = max(0.005, float(timeout) / 1000.0)
            except Exception:
                pass
        written = self._port.write(bytes(data))
        try:
            self._port.flush()
        except Exception:
            pass
        return int(written or len(data))

    def read(self, endpoint: int, length: int, timeout: Optional[float] = None) -> bytes:
        if timeout is not None and hasattr(self._port, "timeout"):
            try:
                self._port.timeout = max(0.002, float(timeout) / 1000.0)
            except Exception:
                pass
        data = self._port.read(length)
        return bytes(data) if data else b""

    def ctrl_transfer(self, bmRequestType: int, bRequest: int, wValue: int = 0,
                      wIndex: int = 0, data_or_wLength: Any = b"",
                      timeout: Optional[float] = None) -> bytes:
        # Map CDC SET_CONTROL_LINE_STATE (0x22) to DTR/RTS toggles on the serial port.
        if bRequest == 0x22:
            try:
                self._port.dtr = bool(wValue & 0x01)
                self._port.rts = bool(wValue & 0x02)
            except Exception:
                pass
        elif bRequest == 0x20 and isinstance(data_or_wLength, (bytes, bytearray)) and len(data_or_wLength) >= 4:
            try:
                baud = struct.unpack_from("<I", data_or_wLength, 0)[0]
                if baud > 0:
                    self._port.baudrate = baud
            except Exception:
                pass
        return b""

    def reset(self) -> None:
        try:
            if hasattr(self._port, "reset_input_buffer"):
                self._port.reset_input_buffer()
            if hasattr(self._port, "reset_output_buffer"):
                self._port.reset_output_buffer()
            if hasattr(self._port, "send_break"):
                self._port.send_break(duration=0.05)
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._port.close()
        except Exception:
            pass


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


def fast_find_devices(target_vid_pids: Optional[Set[Tuple[int, int]]] = None,
                      target_vids: Optional[Set[int]] = None,
                      target_modes: Optional[Set[str]] = None) -> List[Any]:
    """Zero-overhead USB enumeration for tight spin loops.

    Never reads string descriptors (`iManufacturer`, `iProduct`, `iSerialNumber`), because each
    string read is a control transfer taking 5-30 ms that can cause us to miss a brief BROM
    window or stall a sensitive boot ROM USB stack.
    """
    if not have_libusb():
        return []
    usb_core, _ = _usb()
    try:
        raw_devices = usb_core.find(find_all=True)
        if raw_devices is None:
            return []
        matched: List[Any] = []
        for dev in raw_devices:
            vid = int(getattr(dev, "idVendor", 0))
            pid = int(getattr(dev, "idProduct", 0))
            if target_vid_pids and (vid, pid) in target_vid_pids:
                matched.append(dev)
                continue
            if target_vids and vid in target_vids:
                if not target_modes:
                    matched.append(dev)
                    continue
            if target_modes:
                mode, _ = usbmodes.classify(vid, pid)
                if mode in target_modes:
                    matched.append(dev)
                    continue
            if not target_vid_pids and not target_vids and not target_modes:
                mode, _ = usbmodes.classify(vid, pid)
                if mode != usbmodes.MODE_UNKNOWN:
                    matched.append(dev)
        return matched
    except Exception:
        return []


def find_serial_devices(target_modes: Optional[Set[str]] = None,
                        open_handle: bool = False,
                        baudrate: int = 115200) -> List[SerialTransportAdapter]:
    """Scan COM / ttyACM / ttyUSB ports for download-mode interfaces without blocking."""
    if not usbmodes.pyserial_available():
        return []
    out: List[SerialTransportAdapter] = []
    try:
        import serial
        from serial.tools import list_ports

        for p in list_ports.comports():
            vid = int(p.vid or 0)
            pid = int(p.pid or 0)
            desc = (p.description or "").lower()
            if not vid:
                if "mediatek" in desc or "preloader" in desc or "vcom" in desc:
                    vid, pid = 0x0E8D, 0x0003 if "brom" in desc or "usb port" in desc else 0x2000
                elif "9008" in desc or "qdloader" in desc:
                    vid, pid = 0x05C6, 0x9008
                elif "sprd" in desc or "unisoc" in desc or "spreadtrum" in desc:
                    vid, pid = 0x1782, 0x4D00
            if not vid:
                continue
            mode, _ = usbmodes.classify(vid, pid)
            if target_modes and mode not in target_modes:
                continue
            if open_handle:
                try:
                    ser = serial.Serial(
                        port=p.device,
                        baudrate=baudrate,
                        timeout=0.01,
                        write_timeout=0.05,
                        dsrdtr=False,
                        rtscts=False,
                    )
                    ser.dtr = True
                    ser.rts = True
                    out.append(SerialTransportAdapter(ser, p.device, vid, pid, p.serial_number or ""))
                except Exception:
                    continue
            else:
                out.append(SerialTransportAdapter(None, p.device, vid, pid, p.serial_number or ""))
    except Exception:
        pass
    return out


def open_device(device: Any, endpoints: Optional[Endpoints] = None,
                detach: bool = True, set_configuration: bool = True) -> Endpoints:
    """Claim the device and work out which endpoints to use."""
    eps = endpoints or Endpoints()
    if getattr(device, "is_serial_adapter", False):
        return eps

    try:
        usb_core, usb_util = _usb()
    except Exception:
        usb_core = usb_util = None

    try:
        if detach:
            # Detach kernel drivers across interface 0 and 1 (CDC ACM uses two interfaces:
            # control + data). Detaching before set_configuration avoids EBUSY on Linux.
            for intf_num in (eps.interface, 0, 1, 2):
                try:
                    if hasattr(device, "is_kernel_driver_active") and device.is_kernel_driver_active(intf_num):
                        device.detach_kernel_driver(intf_num)
                except Exception:
                    pass
        if set_configuration:
            try:
                if hasattr(device, "set_configuration"):
                    device.set_configuration()
            except Exception:
                pass          # already configured / kernel driver owns it
        if usb_util is not None:
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
                bm_attr = int(getattr(ep, "bmAttributes", 0x02)) & 0x03
                # Prefer Bulk endpoints (bmAttributes & 0x03 == 0x02), fallback to any IN/OUT
                if bm_attr not in (0x02, 0x00):
                    continue
                if direction & 0x80 and eps.in_ep == 0x81:
                    eps.in_ep = direction
                    eps.interface = int(getattr(intf, "bInterfaceNumber", eps.interface))
                elif not (direction & 0x80) and eps.out_ep == 0x01:
                    eps.out_ep = direction
                    eps.interface = int(getattr(intf, "bInterfaceNumber", eps.interface))
        if usb_util is not None:
            try:
                usb_util.claim_interface(device, eps.interface)
            except Exception:
                pass
    except Exception:
        pass
    return eps


def fast_open_device(device: Any, endpoints: Optional[Endpoints] = None) -> Endpoints:
    """Ultra-low-latency claim for sub-millisecond BROM/EDL interception.

    Skips redundant configuration resets when an active configuration is already present, detaches
    kernel drivers on interfaces 0/1 immediately, and claims the bulk data interface.
    """
    return open_device(device, endpoints=endpoints, detach=True, set_configuration=False)


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


def wait_for_device(vid: int, pid: int, timeout: float = 30.0, interval: float = 0.001
                    ) -> Optional[Any]:
    """Tight poll for a device to appear (1 ms default interval to catch transient BROM windows)."""
    deadline = time.perf_counter() + timeout
    target = {(int(vid), int(pid))}
    while time.perf_counter() < deadline:
        devices = fast_find_devices(target_vid_pids=target)
        if devices:
            return devices[0]
        if interval > 0:
            time.sleep(interval)
    return None


def reset_device(device: Any) -> None:
    """Try a USB port reset - the standard cure for a device stuck from a bad session."""
    try:
        device.reset()
    except Exception:
        try:
            device.ctrl_transfer(0x21, 0x20, 0, 0, b"", 250)
        except Exception:
            pass


def force_usb_reenumeration(device: Any = None, vid: Optional[int] = None,
                            pid: Optional[int] = None) -> List[str]:
    """Aggressively reset and re-enumerate USB ports to unstick a silent or half-hung device.

    Works across three layers:
      1. Direct USBDEVFS_RESET + CDC line-state/break pulse on the open device handle
      2. Linux sysfs `/sys/bus/usb/devices/*/authorized` toggle (0 -> 1)
      3. Linux sysfs USB driver `unbind` -> `bind` to force a fresh descriptor read and VBUS pulse
    """
    actions: List[str] = []
    if device is not None:
        try:
            # Pulse CDC control lines (drop DTR/RTS then re-assert) + send break
            device.ctrl_transfer(0x21, 0x22, 0x0000, 0, b"", 100)
            device.ctrl_transfer(0x21, 0x23, 0x0050, 0, b"", 100)
            device.ctrl_transfer(0x21, 0x22, 0x0003, 0, b"", 100)
            actions.append("sent CDC control-line drop/break/assert pulse")
        except Exception:
            pass
        try:
            device.reset()
            actions.append("issued USB port reset (USBDEVFS_RESET)")
        except Exception:
            pass
        if vid is None:
            vid = int(getattr(device, "idVendor", 0)) or None
        if pid is None:
            pid = int(getattr(device, "idProduct", 0)) or None

    sysfs_root = Path("/sys/bus/usb/devices")
    if sysfs_root.exists():
        target_vids = {f"{vid:04x}"} if vid else {"0e8d", "05c6", "1782", "18d1"}
        for dev_dir in sysfs_root.iterdir():
            vid_file = dev_dir / "idVendor"
            pid_file = dev_dir / "idProduct"
            if not vid_file.exists():
                continue
            try:
                cur_vid = vid_file.read_text(encoding="utf-8").strip().lower()
                cur_pid = pid_file.read_text(encoding="utf-8").strip().lower() if pid_file.exists() else ""
            except OSError:
                continue
            if cur_vid not in target_vids:
                continue
            if pid is not None and cur_pid and cur_pid != f"{pid:04x}":
                continue
            auth_file = dev_dir / "authorized"
            if auth_file.exists() and os.access(auth_file, os.W_OK):
                try:
                    auth_file.write_text("0\n", encoding="utf-8")
                    time.sleep(0.02)
                    auth_file.write_text("1\n", encoding="utf-8")
                    actions.append(f"cycled sysfs authorized on {dev_dir.name} ({cur_vid}:{cur_pid})")
                except OSError:
                    pass
            unbind = Path("/sys/bus/usb/drivers/usb/unbind")
            bind = Path("/sys/bus/usb/drivers/usb/bind")
            if unbind.exists() and bind.exists() and os.access(unbind, os.W_OK):
                try:
                    unbind.write_text(dev_dir.name, encoding="utf-8")
                    time.sleep(0.02)
                    bind.write_text(dev_dir.name, encoding="utf-8")
                    actions.append(f"cycled sysfs usb driver unbind/bind on {dev_dir.name}")
                except OSError:
                    pass
    return actions


def scan_usb_bounces(max_lines: int = 80) -> List[Dict[str, str]]:
    """Inspect kernel USB logs for sub-millisecond contact bounces or failed descriptor reads.

    When a phone's BROM/EDL pull-up only flickers for a few milliseconds (bad cable, loose test
    point, PMIC brownout with battery attached), libusb may never see a completed device, but the
    kernel logs `device descriptor read/64, error -71` or `unable to enumerate USB device`.
    """
    bounces: List[Dict[str, str]] = []
    if usbmodes.current_os() != "linux":
        return bounces
    try:
        proc = subprocess.run(
            ["dmesg", "--time-format=reltime"],
            capture_output=True, text=True, timeout=0.5, check=False,
        )
        text = proc.stdout or ""
        if not text:
            proc = subprocess.run(
                ["dmesg"], capture_output=True, text=True, timeout=0.5, check=False,
            )
            text = proc.stdout or ""
    except Exception:
        return bounces

    patterns = (
        ("descriptor_error", re.compile(r"usb\s+([\d\-.:]+):\s+device descriptor read.*error\s+(-\d+)", re.I)),
        ("enumerate_fail", re.compile(r"usb\s+([\d\-.:]+):\s+unable to enumerate USB device", re.I)),
        ("not_accepting_address", re.compile(r"usb\s+([\d\-.:]+):\s+device not accepting address.*error\s+(-\d+)", re.I)),
        ("disconnect_bounce", re.compile(r"usb\s+([\d\-.:]+):\s+USB disconnect", re.I)),
    )
    for line in text.splitlines()[-max_lines:]:
        for kind, regex in patterns:
            m = regex.search(line)
            if m:
                port = m.group(1)
                err = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                bounces.append({
                    "kind": kind,
                    "port": port,
                    "error": err,
                    "raw": line.strip(),
                })
                break
    return bounces


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
        "port": getattr(device, "port_name", None),
    }
    if getattr(device, "is_serial_adapter", False):
        out["serial"] = getattr(device, "serial_number", "") or ""
        return out
    try:
        _, usb_util = _usb()
        out["manufacturer"] = usb_util.get_string(device, device.iManufacturer) or ""
        out["product"] = usb_util.get_string(device, device.iProduct) or ""
        out["serial"] = usb_util.get_string(device, device.iSerialNumber) or ""
    except Exception:
        out["manufacturer"] = str(getattr(device, "manufacturer", "") or "")
        out["product"] = str(getattr(device, "product", "") or "")
        out["serial"] = str(getattr(device, "serial_number", "") or getattr(device, "serial", "") or "")
    return out
