"""Unisoc (Spreadtrum) backend - framing and identification; flashing is deliberately not here.

Unisoc devices talk HDLC-style frames (0x7E flags, 0x7D escaping, CRC16) on a serial-over-USB
interface. What is *not* publicly documented in a stable way is the command vocabulary and the
pac container layout, both of which change per tool generation.

Rather than shipping a guess that can brick a phone, this backend:

  * finds the device and reports which Unisoc USB/COM interface is present,
  * builds and validates HDLC frames (so the transport is real and testable),
  * attempts the documented "connect" handshake and reports exactly what came back,
  * refuses flashing with a clear message pointing at the vendor tool.

That honesty matters more than a feature checkbox: a wrong write to a Unisoc boot area is not
recoverable with the tools a repair shop has.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..core import usbmodes
from ..util import ProgressFn, null_progress
from . import interceptor as interceptor_mod
from . import usbfinder
from .base import BackendError, BackendUnavailable, DeviceBackend, DeviceInfo, Partition

VID_UNISOC = 0x1782
HDLC_FLAG = 0x7E
HDLC_ESCAPE = 0x7D
HDLC_XOR = 0x20


def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE: the checksum used inside Unisoc/HDLC frames."""
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def frame(payload: bytes) -> bytes:
    """Wrap a payload in an HDLC frame with escaping and a trailing CRC16."""
    body = payload + struct.pack("<H", crc16_ccitt(payload))
    escaped = bytearray()
    for byte in body:
        if byte in (HDLC_FLAG, HDLC_ESCAPE):
            escaped += bytes([HDLC_ESCAPE, byte ^ HDLC_XOR])
        else:
            escaped.append(byte)
    return bytes([HDLC_FLAG]) + bytes(escaped) + bytes([HDLC_FLAG])


def unframe(data: bytes) -> bytes:
    """Extract and verify the payload of an HDLC frame. Raises ValueError on bad CRC."""
    body = bytearray()
    escaping = False
    for byte in data.strip(b"\x7e"):
        if escaping:
            body.append(byte ^ HDLC_XOR)
            escaping = False
        elif byte == HDLC_ESCAPE:
            escaping = True
        else:
            body.append(byte)
    if len(body) < 3:
        raise ValueError("frame too short")
    payload, checksum = bytes(body[:-2]), struct.unpack("<H", body[-2:])[0]
    if crc16_ccitt(payload) != checksum:
        raise ValueError("CRC mismatch")
    return payload


@dataclass
class UnisocHello:
    raw: bytes = b""
    version: int = 0
    baud: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"raw": self.raw.hex(), "version": self.version, "baud": self.baud}


class UnisocBackend(DeviceBackend):
    name = "unisoc"
    label = "Unisoc / Spreadtrum (BSL)"
    vendor = "Unisoc"
    modes = [usbmodes.MODE_UNISOC]
    capability_read = False
    capability_write = False
    capability_erase = False
    capability_partitions = False
    tested = False
    protocol = "HDLC framing with CRC16/CCITT; command vocabulary not publicly stable"
    notes = [
        "Revive can find a Unisoc device and validate the frame transport, but does not flash it.",
        "Unisoc flashing is done with the vendor's own tool and the .pac for the exact model.",
        "This is a deliberate safety decision: an undocumented wrong write to Unisoc boot areas "
        "is unrecoverable with repair-shop tools.",
    ]

    def __init__(self, progress: ProgressFn = null_progress, verbose: bool = False,
                 timeout: float = 10.0, baud: int = 115200,
                 wait: bool = False, force_entry: bool = False):
        super().__init__(progress, verbose)
        self.timeout = timeout
        self.baud = baud
        self.wait = wait
        self.force_entry = force_entry
        self.endpoints = {"out": 0x01, "in": 0x81}
        self.hello: Optional[UnisocHello] = None
        self.intercept_result: Optional[interceptor_mod.InterceptResult] = None

    def open(self, device: Any = None) -> None:
        if device is None and (self.wait or self.force_entry):
            engine = interceptor_mod.UsbInterceptor(
                target_modes={usbmodes.MODE_UNISOC},
                force_entry=self.force_entry,
                verbose=self.verbose,
            )
            res = engine.intercept(timeout=self.timeout)
            self.intercept_result = res
            if not res.ok or res.device is None:
                raise BackendUnavailable(
                    res.error or "No Unisoc device answered the sub-ms interceptor.",
                    code="unisoc_no_response",
                    detail="Hold Volume Down while plugging in on most models.",
                )
            self.device = res.device
            self.endpoints = {"out": res.endpoints.out_ep, "in": res.endpoints.in_ep}
            self.info.usb_id = res.usb_id
            self.info.mode = usbmodes.MODE_UNISOC
            self.info.vendor = "Unisoc"
            if "unisoc_hello_hex" in res.telemetry:
                self.hello = UnisocHello(raw=bytes.fromhex(res.telemetry["unisoc_hello_hex"]))
            self.log_line(f"intercepted Unisoc interface ({res.usb_id}) in {res.capture_latency_ms:.3f} ms")
            return

        if device is None:
            devices, warnings = usbfinder.find_devices(VID_UNISOC)
            if not devices:
                serial_devs = usbfinder.find_serial_devices(
                    target_modes={usbmodes.MODE_UNISOC}, open_handle=True
                )
                if serial_devs:
                    devices = serial_devs
            if not devices:
                raise BackendUnavailable(
                    "No Unisoc device on USB. " + (warnings[0] if warnings else ""),
                    code="unisoc_no_response",
                    detail="Hold Volume Down while plugging in on most models; the device should "
                           "appear as 'SPRD U2S Diag' or a COM port.",
                )
            device = devices[0]
        self.device = device
        self.info.usb_id = f"{int(device.idVendor):04x}:{int(device.idProduct):04x}"
        self.info.mode = usbmodes.MODE_UNISOC
        self.info.vendor = "Unisoc"
        eps = usbfinder.fast_open_device(device)
        self.endpoints = {"out": eps.out_ep, "in": eps.in_ep}
        self.log_line("Unisoc interface opened")

    def exchange(self, payload: bytes, expect: int = 1024) -> bytes:
        """Send one frame and read the answer."""
        self.device.write(self.endpoints["out"], frame(payload), self.timeout * 1000)
        try:
            raw = bytes(self.device.read(self.endpoints["in"], expect, self.timeout * 1000))
        except Exception as exc:
            raise BackendError(f"no answer from the device: {exc}", code="unisoc_no_response",
                               detail="Check the cable/port and that the phone is in download mode "
                                      "(the volume-key combo differs per model).")
        return raw

    def connect(self) -> UnisocHello:
        """Send a minimal connect frame and report what comes back.

        The payload layout differs between tool generations, so this intentionally starts with
        the smallest plausible frame and surfaces the device's raw answer for identification.
        """
        if self.hello is not None:
            return self.hello
        try:
            self.device.write(self.endpoints["out"], b"\x7e", 250)
        except Exception:
            pass
        attempts = [
            ("empty connect", b"\x00" * 4),
            ("version query", b"\x7f" + b"\x00" * 3),
            ("baud announce", b"\x00\x01" + struct.pack("<I", self.baud)),
        ]
        last = ""
        for label, payload in attempts:
            self.log_line(f"unisoc connect attempt: {label}")
            try:
                answer = self.exchange(payload)
            except BackendError as exc:
                last = str(exc)
                continue
            if answer:
                self.log_line(f"answer: {answer[:32].hex()}")
                try:
                    decoded = unframe(answer)
                except ValueError:
                    decoded = answer
                self.hello = UnisocHello(raw=decoded)
                return self.hello
        raise BackendError(
            "The Unisoc bootloader did not answer any connect frame" + (f" ({last})" if last else ""),
            code="unisoc_no_response",
            detail="Either the device is not in download mode, or this generation uses a different "
                   "handshake. Revive reports the raw bytes for every attempt in the log - that log "
                   "is what a useful bug report looks like.",
        )

    def identify(self) -> DeviceInfo:
        hello = self.connect()
        self.info.extras["hello"] = hello.to_dict()
        self.info.chip = "Unisoc SoC (identify from the phone model or the pac's own header)"
        self.info.notes.append(
            "Unisoc chips do not report a MediaTek/Qualcomm-style hardware code over this "
            "interface; match the model number instead."
        )
        self.info.notes.extend(self.guard_tested())
        return self.info

    def read_flash(self, offset: int, length: int, out_path, chunk: int = 1024 * 1024) -> Dict[str, Any]:
        raise BackendError(
            "Reading storage from Unisoc devices is not implemented in this build.",
            code="unisoc_no_response",
            detail="The frame transport works (see `revive identify --backend unisoc`), but the "
                   "read command vocabulary is not documented reliably enough to risk it.",
        )

    def write_flash(self, offset: int, data_path, length: Optional[int] = None) -> Dict[str, Any]:
        raise BackendError(
            "Writing to Unisoc devices is intentionally not implemented.",
            code="unisoc_no_response",
            detail="Flash Unisoc phones with the vendor's own tool and the .pac for the exact "
                   "model, and verify it with `revive inspect <file.pac>` first.",
        )

    def list_partitions(self) -> List[Partition]:
        return []
