"""Pure standard-library USB access for Termux (no libusb, no pyusb, nothing to compile).

On a non-rooted Android phone an app cannot open /dev/bus/usb/* by itself. Termux:API's
`termux-usb -r -e <cmd> <path>` asks Android for permission and then runs <cmd> with an already
opened usbfs file descriptor. This module speaks the Linux usbfs ioctl interface directly on
that descriptor, using only `fcntl`, `struct`, `ctypes` and `os` - all part of the Python that
`pkg install python` ships.

`TermuxUsbDevice` exposes the subset of the pyusb `Device` API that Revive's backends use:
`idVendor`, `idProduct`, `write`, `read`, `ctrl_transfer`, `reset`, `set_configuration`,
`get_active_configuration`, `is_kernel_driver_active`, `detach_kernel_driver`.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import struct
from typing import Any, Dict, Iterator, List, Optional

# ----------------------------------------------------------------------------------------
# ioctl numbers (asm-generic encoding: used by arm, aarch64, x86 and x86_64 Android kernels)
# ----------------------------------------------------------------------------------------
_IOC_WRITE, _IOC_READ = 1, 2
_PTR = struct.calcsize("P")


def _ioc(direction: int, nr: int, size: int) -> int:
    return (direction << 30) | (size << 16) | (ord("U") << 8) | nr


_CTRL_FMT = "@BBHHHIP"      # struct usbdevfs_ctrltransfer
_BULK_FMT = "@IIIP"         # struct usbdevfs_bulktransfer
_IOCTL_FMT = "@iiP"         # struct usbdevfs_ioctl

USBDEVFS_CONTROL = _ioc(_IOC_READ | _IOC_WRITE, 0, struct.calcsize(_CTRL_FMT))
USBDEVFS_BULK = _ioc(_IOC_READ | _IOC_WRITE, 2, struct.calcsize(_BULK_FMT))
USBDEVFS_SETCONFIGURATION = _ioc(_IOC_READ, 5, 4)
USBDEVFS_GETDRIVER = _ioc(_IOC_WRITE, 8, 4 + 256)
USBDEVFS_CLAIMINTERFACE = _ioc(_IOC_READ, 15, 4)
USBDEVFS_RELEASEINTERFACE = _ioc(_IOC_READ, 16, 4)
USBDEVFS_IOCTL = _ioc(_IOC_READ | _IOC_WRITE, 18, struct.calcsize(_IOCTL_FMT))
USBDEVFS_RESET = (ord("U") << 8) | 20
USBDEVFS_CLEAR_HALT = _ioc(_IOC_READ, 21, 4)
USBDEVFS_DISCONNECT = (ord("U") << 8) | 22


class UsbTimeout(IOError):
    """Raised when a transfer times out (message mirrors pyusb so callers match on it)."""


class UsbError(IOError):
    pass


# ----------------------------------------------------------------------------------------
# Descriptor objects shaped like pyusb's so open_device() can iterate them
# ----------------------------------------------------------------------------------------
class Endpoint:
    def __init__(self, address: int, attributes: int, max_packet: int):
        self.bEndpointAddress = address
        self.bmAttributes = attributes
        self.wMaxPacketSize = max_packet

    def __repr__(self) -> str:
        return f"<EP 0x{self.bEndpointAddress:02x} attr={self.bmAttributes} mps={self.wMaxPacketSize}>"


class Interface:
    def __init__(self, number: int, alt: int, cls: int, sub: int, proto: int):
        self.bInterfaceNumber = number
        self.bAlternateSetting = alt
        self.bInterfaceClass = cls
        self.bInterfaceSubClass = sub
        self.bInterfaceProtocol = proto
        self.endpoints: List[Endpoint] = []

    def __iter__(self) -> Iterator[Endpoint]:
        return iter(self.endpoints)


class Configuration:
    def __init__(self, value: int):
        self.bConfigurationValue = value
        self.interfaces: List[Interface] = []

    def __iter__(self) -> Iterator[Interface]:
        return iter(self.interfaces)


def parse_descriptors(raw: bytes) -> Dict[str, Any]:
    """Parse the blob usbfs returns from read(): device descriptor + every config descriptor."""
    if len(raw) < 18 or raw[1] != 0x01:
        raise UsbError("usbfs did not return a device descriptor")
    (_, _, bcd_usb, d_cls, d_sub, d_proto, mps0, vid, pid, bcd_dev,
     i_man, i_prod, i_ser, n_cfg) = struct.unpack_from("<BBHBBBBHHHBBBB", raw, 0)
    configs: List[Configuration] = []
    cfg: Optional[Configuration] = None
    intf: Optional[Interface] = None
    pos = raw[0] or 18
    while pos + 2 <= len(raw):
        length, dtype = raw[pos], raw[pos + 1]
        if length < 2:
            break
        body = raw[pos:pos + length]
        if dtype == 0x02 and len(body) >= 9:                          # configuration
            cfg = Configuration(body[5])
            configs.append(cfg)
            intf = None
        elif dtype == 0x04 and len(body) >= 9 and cfg is not None:    # interface
            intf = Interface(body[2], body[3], body[5], body[6], body[7])
            cfg.interfaces.append(intf)
        elif dtype == 0x05 and len(body) >= 7 and intf is not None:   # endpoint
            intf.endpoints.append(Endpoint(body[2], body[3], struct.unpack_from("<H", body, 4)[0]))
        pos += length
    return {
        "bcdUSB": bcd_usb, "bDeviceClass": d_cls, "bDeviceSubClass": d_sub,
        "bDeviceProtocol": d_proto, "bMaxPacketSize0": mps0, "idVendor": vid,
        "idProduct": pid, "bcdDevice": bcd_dev, "iManufacturer": i_man,
        "iProduct": i_prod, "iSerialNumber": i_ser, "bNumConfigurations": n_cfg,
        "configs": configs,
    }


# ----------------------------------------------------------------------------------------
# The device
# ----------------------------------------------------------------------------------------
def _ms(timeout: Optional[float]) -> int:
    """pyusb timeouts are milliseconds; None/0 means 'default' (5 s)."""
    return 5000 if not timeout else max(1, int(timeout))


class TermuxUsbDevice:
    """A usbfs file descriptor handed over by `termux-usb`, wrapped in a pyusb-like API."""

    is_termux_usb = True

    def __init__(self, fd: int, path: str = ""):
        self.fd = int(fd)
        self.path = path
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
        except OSError:
            pass
        raw = b""
        while True:
            chunk = os.read(self.fd, 4096)
            raw += chunk
            if len(chunk) < 4096:
                break
        info = parse_descriptors(raw)
        for key, value in info.items():
            if key != "configs":
                setattr(self, key, value)
        self.configs: List[Configuration] = info["configs"]
        self._claimed: set = set()
        parts = [p for p in path.split("/") if p]
        self.bus = int(parts[-2]) if len(parts) >= 2 and parts[-2].isdigit() else None
        self.address = int(parts[-1]) if parts and parts[-1].isdigit() else None
        self.manufacturer = self.get_string(self.iManufacturer)
        self.product = self.get_string(self.iProduct)
        self.serial_number = self.get_string(self.iSerialNumber)

    # -- raw ioctl with pyusb-like error text (Revive's error translator matches on it) --
    def _ioctl(self, request: int, arg: Any) -> int:
        try:
            if isinstance(arg, bytearray):
                return fcntl.ioctl(self.fd, request, arg, True)
            return fcntl.ioctl(self.fd, request, arg)
        except OSError as exc:
            code = exc.errno or 0
            if code == errno.ETIMEDOUT:
                raise UsbTimeout(code, "Operation timed out") from None
            if code == errno.ENODEV:
                raise UsbError(code, "No such device (it may have been disconnected)") from None
            if code == errno.EBUSY:
                raise UsbError(code, "Resource busy") from None
            if code in (errno.EACCES, errno.EPERM):
                raise UsbError(code, "Access denied (insufficient permissions)") from None
            if code == errno.EPIPE:
                raise UsbError(code, "Pipe error (endpoint stalled)") from None
            raise UsbError(code, f"usbfs ioctl failed: {os.strerror(code)}") from None

    def _int_ioctl(self, request: int, value: int) -> int:
        return self._ioctl(request, bytearray(struct.pack("@I", value)))

    # -- interface management ------------------------------------------------------------
    def is_kernel_driver_active(self, number: int) -> bool:
        buf = bytearray(struct.pack("@I", number) + b"\0" * 256)
        try:
            self._ioctl(USBDEVFS_GETDRIVER, buf)
            return True
        except UsbError:
            return False

    def detach_kernel_driver(self, number: int) -> None:
        if not self.is_kernel_driver_active(number):
            return
        try:
            self._ioctl(USBDEVFS_IOCTL, bytearray(struct.pack(_IOCTL_FMT, number, USBDEVFS_DISCONNECT, 0)))
        except UsbError:
            pass

    def claim_interface(self, number: int) -> None:
        if number in self._claimed:
            return
        self.detach_kernel_driver(number)
        self._int_ioctl(USBDEVFS_CLAIMINTERFACE, number)
        self._claimed.add(number)

    def release_interface(self, number: int) -> None:
        try:
            self._int_ioctl(USBDEVFS_RELEASEINTERFACE, number)
        except UsbError:
            pass
        self._claimed.discard(number)

    def set_configuration(self, value: Optional[int] = None) -> None:
        if value is None:
            value = self.configs[0].bConfigurationValue if self.configs else 1
        self._int_ioctl(USBDEVFS_SETCONFIGURATION, value)

    def get_active_configuration(self) -> Configuration:
        if not self.configs:
            raise UsbError(errno.ENOENT, "device reported no configuration")
        return self.configs[0]

    def clear_halt(self, endpoint: int) -> None:
        self._int_ioctl(USBDEVFS_CLEAR_HALT, int(endpoint))

    def _claim_for(self, endpoint: int) -> None:
        try:
            for intf in self.get_active_configuration():
                if any(ep.bEndpointAddress == endpoint for ep in intf):
                    self.claim_interface(intf.bInterfaceNumber)
                    return
        except UsbError:
            pass

    # -- transfers -----------------------------------------------------------------------
    def _bulk(self, endpoint: int, cbuf: Any, length: int, timeout: Optional[float]) -> int:
        self._claim_for(endpoint)
        req = bytearray(struct.pack(_BULK_FMT, endpoint, length, _ms(timeout), ctypes.addressof(cbuf)))
        return int(self._ioctl(USBDEVFS_BULK, req))

    def write(self, endpoint: int, data: Any, timeout: Optional[float] = None) -> int:
        payload = bytes(data)
        if not payload:
            cbuf = ctypes.create_string_buffer(1)
            return self._bulk(endpoint & 0x7F, cbuf, 0, timeout)
        sent, chunk = 0, 16384        # usbfs rejects very large single URBs on old kernels
        while sent < len(payload):
            part = payload[sent:sent + chunk]
            cbuf = ctypes.create_string_buffer(part, len(part))
            sent += self._bulk(endpoint & 0x7F, cbuf, len(part), timeout)
        return sent

    def read(self, endpoint: int, length: int, timeout: Optional[float] = None) -> bytes:
        length = int(length)
        cbuf = ctypes.create_string_buffer(max(1, length))
        got = self._bulk(endpoint | 0x80, cbuf, length, timeout)
        return cbuf.raw[:got]

    def ctrl_transfer(self, bmRequestType: int, bRequest: int, wValue: int = 0, wIndex: int = 0,
                      data_or_wLength: Any = None, timeout: Optional[float] = None) -> Any:
        if bmRequestType & 0x80:
            length = int(data_or_wLength or 0)
            cbuf = ctypes.create_string_buffer(max(1, length))
        else:
            payload = bytes(data_or_wLength or b"")
            length = len(payload)
            cbuf = ctypes.create_string_buffer(payload, max(1, length))
        req = bytearray(struct.pack(_CTRL_FMT, bmRequestType, bRequest, wValue, wIndex, length,
                                    _ms(timeout), ctypes.addressof(cbuf)))
        got = int(self._ioctl(USBDEVFS_CONTROL, req))
        return cbuf.raw[:got] if bmRequestType & 0x80 else got

    def get_string(self, index: int) -> str:
        if not index:
            return ""
        try:
            langs = self.ctrl_transfer(0x80, 0x06, 0x0300, 0, 255, 500)
            lang = struct.unpack_from("<H", langs, 2)[0] if len(langs) >= 4 else 0x0409
            raw = self.ctrl_transfer(0x80, 0x06, 0x0300 | index, lang, 255, 500)
            return raw[2:raw[0]].decode("utf-16-le", "replace") if len(raw) > 2 else ""
        except Exception:
            return ""

    def reset(self) -> None:
        self._ioctl(USBDEVFS_RESET, 0)

    def close(self) -> None:
        for number in list(self._claimed):
            self.release_interface(number)
        try:
            os.close(self.fd)
        except OSError:
            pass

    def __repr__(self) -> str:
        return f"<TermuxUsbDevice {self.idVendor:04x}:{self.idProduct:04x} {self.path or 'fd ' + str(self.fd)}>"
