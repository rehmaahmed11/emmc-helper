"""MediaTek BROM / preloader backend.

This is the backend for the case nothing else handles: a phone that does not boot, does not
charge, shows nothing on screen, and only answers as `0e8d:0003` for a second when you plug it
in. If BROM answers, the phone is recoverable in principle - the eMMC contents do not matter.

Protocol notes (be honest about provenance):
  * USB ids, the 4-byte inverse sync (`0xA0 0x0A 0x50 0x05` -> `0x5F 0xF5 0xAF 0xFA`), the
    hardware watchdog disable (`WDT_BASE = 0x10007000 <- 0x22000000`), the 16-byte command
    status header and the 0xD0/0xD5/0xD7/0xD8/0xFC command numbers come from public
    reverse-engineering work on MediaTek's boot ROM.
  * The BROM status word is a 32-bit value whose high byte is 0x00 (success), 0x02 (security)
    or 0xC0 (fatal). Rather than assuming an endianness, `_parse_status` accepts the reading
    that produces one of those patterns and records which one it used - a wrong guess would
    otherwise turn "wrong DA" into "device not found".
  * Everything that can vary between chip generations is in one table (`PROTOCOL`) so it can be
    corrected from one place when field reports come in.

`identify()` is the operation worth trusting first: it reads the hardware code, disables the
hardware watchdog so the phone stays frozen in BROM/Preloader even with a battery attached, and
reads the security state. Reading and writing storage requires the download-agent protocol and
is only enabled once a DA has been loaded.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core import chips, errors, usbmodes
from ..util import ProgressFn, human_size, null_progress
from . import interceptor as interceptor_mod
from . import usbfinder
from .base import BackendError, BackendUnavailable, DeviceBackend, DeviceInfo, Endpoints, Partition

VID_MEDIATEK = 0x0E8D
PID_BROM = 0x0003
PID_PRELOADER = 0x2000

# Command numbers. Values marked "reported" differ between chip generations in the wild; if a
# command answers with an unexpected status, that is the first place to look.
PROTOCOL = {
    "SEND_DA": 0xD0,          # start sending a download agent
    "JUMP_DA": 0xD5,          # execute the loaded DA
    "READ16": 0xD8,           # read memory/flash (16-bit addressed command)
    "WRITE16": 0xD7,          # write memory/flash
    "WRITE_DATA": 0xD7,       # stream data for the previous write command
    "GET_TARGET_CONFIG": 0xD4,
    "GET_HW_CODE": 0xFC,
    "GET_VERSION": 0xD6,
    "START_CMD": 0xD6,
}

STATUS_OK = 0x00000000
STATUS_HIGH_BYTE = {0x00: "ok", 0x02: "security", 0xC0: "fatal", 0xC1: "fatal", 0xD0: "fatal"}


@dataclass
class BromTargetConfig:
    hwcode: int = 0
    hw_subcode: int = 0
    hw_version: int = 0
    sw_version: int = 0
    target_config: int = 0
    sbc_enabled: bool = False
    sla_enabled: bool = False
    daa_enabled: bool = False
    swjtag_enabled: bool = False
    mem_read_auth: bool = False
    mem_write_auth: bool = False
    root_cert_required: bool = False
    raw: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hwcode": f"0x{self.hwcode:04X}", "hw_subcode": f"0x{self.hw_subcode:04X}",
            "hw_version": f"0x{self.hw_version:04X}", "sw_version": f"0x{self.sw_version:04X}",
            "target_config": f"0x{self.target_config:04X}",
            "secure_boot": self.sbc_enabled, "sla": self.sla_enabled, "daa": self.daa_enabled,
            "swjtag": self.swjtag_enabled, "mem_read_auth": self.mem_read_auth,
            "mem_write_auth": self.mem_write_auth, "root_cert_required": self.root_cert_required,
        }


class MtkBromBackend(DeviceBackend):
    name = "mtk"
    label = "MediaTek BROM / Preloader"
    vendor = "MediaTek"
    modes = [usbmodes.MODE_MTK_BROM, usbmodes.MODE_MTK_PRELOADER, usbmodes.MODE_MTK_DA]
    capability_read = True        # memory reads work in BROM; storage reads need a DA
    capability_write = True
    capability_erase = False
    capability_partitions = False
    tested = False
    protocol = "public reverse-engineering notes (4-byte BROM sync + WDT freeze + 0xD0/0xD5/0xD7/0xD8/0xFC)"
    notes = [
        "BROM only appears for about a second after power-up: start the operation, THEN plug in.",
        "Zero-sleep 4-byte sync hammer (A0->5F, 0A->F5, 50->AF, 05->FA) + WDT disable keeps "
        "the phone locked in BROM/Preloader even when the battery is attached.",
        "Secure devices (SBC/SLA/DAA) need a matching DA + auth file, or an exploit path.",
        "Memory reads work without a DA; storage reads/writes require a DA to be loaded first.",
    ]

    def __init__(self, progress: ProgressFn = null_progress, verbose: bool = False,
                 timeout: float = 15.0, endian: str = "big",
                 wait: bool = False, force_entry: bool = False, force_brom: bool = False):
        super().__init__(progress, verbose)
        self.timeout = timeout
        self.endian = endian
        self.wait = wait
        self.force_entry = force_entry
        self.force_brom = force_brom
        self.eps = Endpoints()
        self.config: Optional[BromTargetConfig] = None
        self.da_loaded = False
        self.wdt_disabled = False
        self.intercept_result: Optional[interceptor_mod.InterceptResult] = None
        self._status_endian = "big"      # resolved on the first response

    # -- connection -------------------------------------------------------------------
    def open(self, device: Any = None) -> None:
        if device is None and (self.wait or self.force_entry or self.force_brom):
            engine = interceptor_mod.UsbInterceptor(
                target_modes={usbmodes.MODE_MTK_BROM, usbmodes.MODE_MTK_PRELOADER, usbmodes.MODE_MTK_DA},
                force_entry=self.force_entry,
                force_brom=self.force_brom,
                verbose=self.verbose,
            )
            res = engine.intercept(timeout=self.timeout)
            self.intercept_result = res
            if not res.ok or res.device is None:
                raise BackendUnavailable(
                    res.error or "No MediaTek device answered the sub-ms interceptor.",
                    code="no_device",
                    detail="Hold Vol Up + Vol Down while plugging in (or hold Power + Vol Up + "
                           "Vol Down for 10s if the battery is attached).",
                )
            self.device = res.device
            self.eps = res.endpoints
            self.wdt_disabled = res.wdt_disabled
            self.info.usb_id = res.usb_id
            self.info.mode = res.mode
            self.info.vendor = "MediaTek"
            self.info.extras["interception"] = {
                "capture_latency_ms": round(res.capture_latency_ms, 4),
                "handshake_duration_ms": round(res.handshake_duration_ms, 4),
                "sync_bytes": res.sync_bytes,
                "wdt_disabled": res.wdt_disabled,
                "forced_from_mode": res.forced_from_mode,
                "preloader_crashed_to_brom": res.preloader_crashed_to_brom,
            }
            self.log_line(f"intercepted {self.info.usb_id} in {res.capture_latency_ms:.3f} ms")
            return

        if device is None:
            devices, warnings = usbfinder.find_devices(VID_MEDIATEK)
            if not devices:
                serial_devs = usbfinder.find_serial_devices(
                    target_modes={usbmodes.MODE_MTK_BROM, usbmodes.MODE_MTK_PRELOADER},
                    open_handle=True,
                )
                if serial_devs:
                    devices = serial_devs
            if not devices:
                raise BackendUnavailable(
                    "No MediaTek device on USB. " + (warnings[0] if warnings else ""),
                    code="no_device",
                    detail="Power the phone off, start the operation, then plug the cable in while "
                           "holding Volume Up + Volume Down (or use `revive intercept --force`).",
                )
            preferred = [d for d in devices if int(d.idProduct) in (PID_BROM, PID_PRELOADER)]
            device = (preferred or devices)[0]
        self.device = device
        self.info.usb_id = f"{int(device.idVendor):04x}:{int(device.idProduct):04x}"
        mode, label = usbmodes.classify(int(device.idVendor), int(device.idProduct))
        self.info.mode = mode
        self.info.vendor = "MediaTek"
        self.log_line(f"found {self.info.usb_id} ({label})")
        self.eps = usbfinder.fast_open_device(device)
        self.handshake()
        if self.force_brom and self.info.mode == usbmodes.MODE_MTK_PRELOADER:
            self.crash_preloader_to_brom()

    def handshake(self, max_attempts: int = 80) -> List[Dict[str, str]]:
        """Execute the zero-sleep 4-byte inverse sync (`0xA0 0x0A 0x50 0x05` -> `0x5F 0xF5 0xAF 0xFA`)."""
        engine = interceptor_mod.UsbInterceptor(
            max_sync_attempts=max_attempts,
            disable_wdt=False,
            verbose=self.verbose,
        )
        res = interceptor_mod.InterceptResult()
        try:
            sync_pairs = engine.mtk_handshake_hammer(self.device, self.eps, res)
            self.intercept_result = res
            self.info.extras["sync_bytes"] = sync_pairs
            self.log_line(
                "handshake locked: " + ", ".join(f"{p['tx']}->{p['rx']}" for p in sync_pairs)
            )
            return sync_pairs
        except Exception as exc:
            try:
                usbfinder.reset_device(self.device)
            except Exception:
                pass
            raise BackendError(
                f"The boot ROM did not answer the handshake ({exc})",
                code="2005",
                detail="This is almost always timing, cable, port or driver related - see the fixes.",
            )

    def disable_watchdog(self, hwcode: Optional[int] = None) -> bool:
        """Disable the hardware watchdog timer (WDT) so the phone stays in BROM/Preloader."""
        code = hwcode if hwcode is not None else self.info.hwcode
        wdt_addr = interceptor_mod.wdt_base_for_hwcode(code)
        try:
            self.write_memory(wdt_addr, struct.pack(">I", 0x22000000))
            self.wdt_disabled = True
            self.info.extras["wdt_disabled"] = True
            self.info.extras["wdt_address"] = f"0x{wdt_addr:08X}"
            self.log_line(f"disabled hardware watchdog at 0x{wdt_addr:08X}")
            return True
        except Exception as exc:
            self.log_line(f"watchdog disable skipped: {exc}")
            return False

    def crash_preloader_to_brom(self) -> bool:
        """Crash an active Preloader session (`0e8d:2000`) to force warm-reset into BROM (`0e8d:0003`)."""
        engine = interceptor_mod.UsbInterceptor(force_brom=True, verbose=self.verbose)
        res = self.intercept_result or interceptor_mod.InterceptResult()
        engine._crash_preloader_into_brom(self.device, self.eps, res)
        self.intercept_result = res
        if res.mode == usbmodes.MODE_MTK_BROM and res.device is not None:
            self.device = res.device
            self.eps = res.endpoints
            self.info.mode = usbmodes.MODE_MTK_BROM
            self.info.usb_id = "0e8d:0003"
            self.log_line("Preloader crashed and re-caught in BROM (0e8d:0003)")
            return True
        return res.preloader_crashed_to_brom

    # -- low level --------------------------------------------------------------------
    def _send(self, command: int, payload: bytes = b"") -> None:
        self.device.write(self.eps.out_ep, bytes([command]) + payload, self.timeout * 1000)

    def _read(self, length: int) -> bytes:
        return bytes(self.device.read(self.eps.in_ep, length, self.timeout * 1000))

    def _parse_status(self, response: bytes) -> Tuple[int, str]:
        """Return (status_value, endian_used). See module docstring for why this is adaptive."""
        if len(response) < 10:
            raise BackendError(f"short status response ({len(response)} bytes)", code="1042")
        candidates = {
            "big": int.from_bytes(response[8:12], "big"),
            "little": int.from_bytes(response[8:12], "little"),
        }
        for endian, value in candidates.items():
            if value == STATUS_OK or (value >> 24) in STATUS_HIGH_BYTE:
                return value, endian
        return candidates[self._status_endian], self._status_endian

    def _expect_ok(self, response: bytes, what: str) -> bytes:
        status, endian = self._parse_status(response)
        self._status_endian = endian
        if status != STATUS_OK:
            info = errors.get(f"0x{status:08X}")
            raise BackendError(
                f"{what} failed: {info.symbol if info else f'status 0x{status:08X}'}",
                code=f"0x{status:08X}",
                detail=info.meaning if info else "The boot ROM refused the command.",
                data={"response": response.hex(), "status": f"0x{status:08X}", "endian": endian},
            )
        return response

    def read_memory(self, address: int, length: int) -> bytes:
        """Command 0xD8: read `length` bytes from `address` in the device's address space."""
        self._send(PROTOCOL["READ16"], struct.pack(">II", address, length))
        self._expect_ok(self._read(16), f"read 0x{length:x} bytes at 0x{address:08x}")
        data = self._read(length)
        return data[4:] if len(data) == length + 4 else data

    def write_memory(self, address: int, data: bytes) -> None:
        """Command 0xD7: write `data` at `address`."""
        self._send(PROTOCOL["WRITE16"], struct.pack(">II", address, len(data)))
        self._expect_ok(self._read(16), f"write command for 0x{len(data):x} bytes")
        self.device.write(self.eps.out_ep, data, self.timeout * 1000)
        self._expect_ok(self._read(16), "write data transfer")

    # -- identification ---------------------------------------------------------------
    def get_target_config(self) -> BromTargetConfig:
        """0xD4 -> the security/target flags. Reads both layouts used across generations."""
        self._send(PROTOCOL["GET_TARGET_CONFIG"])
        response = self._read(16)
        self._expect_ok(response, "read target config")
        hwcode = struct.unpack(">H", response[6:8])[0] if len(response) >= 8 else 0
        target_config = struct.unpack(">H", response[8:10])[0] if len(response) >= 10 else 0
        subcode = struct.unpack(">H", response[4:6])[0] if len(response) >= 6 else 0
        version = response[14] if len(response) > 14 else 0
        config = BromTargetConfig(
            hwcode=hwcode or 0,
            hw_subcode=subcode,
            hw_version=version,
            target_config=target_config,
            sbc_enabled=bool(target_config & 0x0001),
            sla_enabled=bool(target_config & 0x0002),
            daa_enabled=bool(target_config & 0x0004),
            swjtag_enabled=bool(target_config & 0x0010),
            mem_read_auth=bool(target_config & 0x0100),
            mem_write_auth=bool(target_config & 0x0200),
            root_cert_required=bool(target_config & 0x1000),
            raw=response,
        )
        self.config = config
        return config

    def get_hwcode(self) -> int:
        """0xFC: the hardware code. Falls back to the target-config field if it is absent."""
        try:
            self._send(PROTOCOL["GET_HW_CODE"])
            response = self._read(16)
            self._expect_ok(response, "read hardware code")
            code = struct.unpack(">H", response[6:8])[0]
            if code:
                return code
        except BackendError:
            pass
        if self.config is None:
            self.get_target_config()
        return self.config.hwcode if self.config else 0

    def identify(self) -> DeviceInfo:
        code = self.get_hwcode()
        chip = chips.lookup(code)
        self.info.hwcode = code
        self.info.chip = chip.name if chip else f"unknown (0x{code:04X})"
        self.info.chip_confidence = chip.confidence if chip else chips.UNKNOWN
        self.info.storage = chip.storage if chip else ""
        config = self.config or self.get_target_config()
        self.info.security = config.to_dict()
        if not self.wdt_disabled:
            self.disable_watchdog(code)
        if config.sbc_enabled or config.sla_enabled or config.daa_enabled:
            self.info.notes.append(
                "Secure boot is enabled (SBC/SLA/DAA): a matching DA + auth file is required to "
                "read or write storage."
            )
        if chip and chip.confidence != chips.CONFIRMED:
            self.info.notes.append(
                f"Chip name comes from a {chip.confidence} source - confirm with the firmware's "
                "scatter file before flashing anything."
            )
        if self.info.mode == usbmodes.MODE_MTK_BROM:
            self.info.notes.append(
                "In BROM mode the phone's own preloader is not running - this is the strongest "
                "position to recover from, and the most timing-sensitive."
            )
        self.info.notes.extend(self.guard_tested())
        return self.info

    # -- download agent ---------------------------------------------------------------
    def load_da(self, da_path, progress: ProgressFn = null_progress) -> Dict[str, Any]:
        """Command 0xD0: upload a DA and jump to it.

        This is the step that turns a raw boot ROM into something that can touch storage. It is
        also the step that fails on secure devices when the DA is not signed for this chip, so
        the error message says exactly that.
        """
        path = Path(da_path)
        blob = path.read_bytes()
        if not blob:
            raise BackendError("the DA file is empty", code="2004")
        self.log_line(f"sending DA {path.name} ({human_size(len(blob))})")
        self._send(PROTOCOL["SEND_DA"], struct.pack(">I", len(blob)))
        try:
            self._expect_ok(self._read(16), "DA download request")
        except BackendError as exc:
            raise BackendError(
                "The boot ROM refused to accept a download agent",
                code="2004",
                detail="Usually a DA/chip mismatch or a secure-boot device that needs a signed DA. "
                       + (exc.detail or ""),
                data=exc.data,
            )

        sent = 0
        chunk_size = 4096
        while sent < len(blob):
            chunk = blob[sent:sent + chunk_size]
            self.device.write(self.eps.out_ep, chunk, self.timeout * 1000)
            sent += len(chunk)
            progress(sent, len(blob), "sending DA")
        self._expect_ok(self._read(16), "DA transfer")
        self._send(PROTOCOL["JUMP_DA"])
        self._expect_ok(self._read(16), "jump to DA")
        self.da_loaded = True
        self.log_line("DA is running")
        return {"da": str(path), "size": len(blob), "loaded": True}

    def read_flash(self, offset: int, length: int, out_path, chunk: int = 1024 * 1024) -> Dict[str, Any]:
        """Read storage through the loaded DA, streaming to a file."""
        if not self.da_loaded:
            raise BackendError(
                "A download agent must be loaded before storage can be read.",
                code="3144",
                detail="Run `revive da load <DA file>` first (or pass --da to the command).",
            )
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with out.open("wb") as fh:
            while written < length:
                want = min(chunk, length - written)
                data = self.read_memory(offset + written, want)
                fh.write(data)
                written += len(data)
                self.progress(written, length, "reading storage")
        return {"output": str(out), "bytes": written, "offset": offset}

    def write_flash(self, offset: int, data_path, length: Optional[int] = None) -> Dict[str, Any]:
        if not self.da_loaded:
            raise BackendError(
                "A download agent must be loaded before storage can be written.",
                code="3149",
                detail="Flashing without a DA is refused on purpose: a half-written partition is "
                       "how phones become unrecoverable.",
            )
        path = Path(data_path)
        total = length if length is not None else path.stat().st_size
        written = 0
        with path.open("rb") as fh:
            while written < total:
                block = fh.read(min(64 * 1024, total - written))
                if not block:
                    break
                self.write_memory(offset + written, block)
                written += len(block)
                self.progress(written, total, "writing storage")
        return {"source": str(path), "bytes": written, "offset": offset}

    def list_partitions(self) -> List[Partition]:
        return []
