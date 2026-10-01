"""Sub-millisecond USB handshake interceptor and active BROM/EDL force-entry engine.

Why this exists:
  * A MediaTek BootROM (`0e8d:0003`) or Preloader (`0e8d:2000`) window on a phone with a
    battery attached can last as little as 15-80 milliseconds before the PMIC/bootloader
    transitions into charging animation or a bootloop.
  * Standard USB enumeration that sleeps 250 ms or reads USB string descriptors (`iProduct`,
    `iManufacturer`) before claiming the interface loses the race against the boot timer.

How `UsbInterceptor` solves this across 4 layers:
  1. **Nanosecond-Timed Tight Spin-Catch**: Polls raw integer VID:PID descriptors (and serial
     COM/ttyACM nodes) with zero string-descriptor overhead and sub-millisecond cadence,
     atomically detaching kernel drivers (`cdc_acm`, `qcserial`, `mtk_usb`) and claiming bulk
     endpoints in one pass.
  2. **Multi-Protocol Hammer & Hardware Watchdog (WDT) Lock**:
     - MediaTek: Blasts `0xA0` with zero sleep until `0x5F` answers, completes the 4-byte
       inverse sync (`A0->5F, 0A->F5, 50->AF, 05->FA`), and immediately disables the hardware
       watchdog (`WDT_BASE = 0x10007000`) so the SoC stays frozen in BROM/Preloader even with
       a battery attached.
     - Qualcomm EDL: Captures Sahara `HELLO` immediately on attach, locks the session, and
       queries Sahara Command Mode for `SERIAL_NUM`, `MSM_HW_ID`, and `OEM_PK_HASH`.
     - Unisoc BSL: Streams `0x7E` baud-sync flags immediately on open and locks `BSL_CONNECT`.
  3. **Preloader -> BROM Force-Crash ("Kamikaze Override")**:
     - When a battery-attached MediaTek phone skips BROM and enters Preloader (`0e8d:2000`),
       catches Preloader first, crashes/resets Preloader via invalid DA/SRAM header + WDT
       software reset trigger (`0x1209`), and catches the resulting `0e8d:0003` BROM
       enumeration on the very next millisecond.
  4. **Active Mode Escalator (When No BROM/EDL Handshake Happens Initially)**:
     - Automatically hijacks ADB (`adb reboot edl` / `reboot`), Fastboot (`oem edl`,
       `reboot-edl`, `oem enter-dload`, `reboot`), and Qualcomm Diag (`05c6:9006` QCDM
       switch-to-EDL packet `4b 65 01 00 54 0f 7e`), cycles host USB port resets / sysfs
       re-enumeration, and monitors kernel USB bounce events (`error -71`).
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..core import chips, usbmodes
from . import usbfinder
from .base import BackendError, BackendUnavailable, Endpoints

# MediaTek 4-byte inverse start-command sync sequence
MTK_SYNC_SEQUENCE: Tuple[Tuple[int, int], ...] = (
    (0xA0, 0x5F),
    (0x0A, 0xF5),
    (0x50, 0xAF),
    (0x05, 0xFA),
)

# MediaTek Watchdog Timer (WDT) base addresses per hardware code family
MTK_WDT_DEFAULT = 0x10007000
MTK_WDT_BASES: Dict[int, int] = {
    0x6572: 0x10007000,
    0x6580: 0x10007000,
    0x6582: 0x10212000,
    0x6592: 0x10212000,
    0x6595: 0x10007000,
    0x0335: 0x10007000,
    0x0326: 0x10007000,
    0x6752: 0x10007000,
    0x6757: 0x10007000,
    0x6795: 0x10007000,
    0x0766: 0x10007000,   # MT6765 / Helio P35 / G35
    0x0707: 0x10007000,   # MT6768 / MT6769 / Helio G85
    0x0688: 0x10007000,   # MT6771 / Helio P60
    0x1066: 0x10007000,   # MT6781 / Helio G96
    0x1208: 0x10007000,   # MT6785 / Helio G90T
    0x1209: 0x10007000,   # MT6789 / Helio G99
    0x0551: 0x10007000,   # MT6833 / Dimensity 700
    0x0690: 0x10007000,   # MT6873 / Dimensity 800
    0x8695: 0x10007000,
}

# Qualcomm Diag QCDM switch-to-EDL frames (CRC16-HDLC framed)
QCDM_SWITCH_TO_EDL_FRAMES: Tuple[bytes, ...] = (
    bytes.fromhex("4b650100540f7e"),   # Subsystem 0x4B (DIAG_SUBSYS_CMD_F) -> EDL switch
    bytes.fromhex("3aa16e7e"),         # Legacy DLOAD command 0x3A
)

# Sahara Command Mode IDs for device telemetry
SAHARA_CMD_READY = 0x0B
SAHARA_CMD_EXECUTE = 0x0D
SAHARA_CMD_EXECUTE_RSP = 0x0E
SAHARA_CMD_EXECUTE_DATA = 0x0F
SAHARA_CMD_SWITCH_MODE = 0x0C

SAHARA_EXEC_SERIAL_NUM = 0x01
SAHARA_EXEC_MSM_HW_ID = 0x02
SAHARA_EXEC_OEM_PK_HASH = 0x03

DOWNLOAD_TARGET_MODES: Set[str] = {
    usbmodes.MODE_MTK_BROM,
    usbmodes.MODE_MTK_PRELOADER,
    usbmodes.MODE_MTK_DA,
    usbmodes.MODE_QC_EDL,
    usbmodes.MODE_UNISOC,
}

ESCALATION_MODES: Set[str] = {
    usbmodes.MODE_ADB,
    usbmodes.MODE_FASTBOOT,
    usbmodes.MODE_QC_DIAG,
    usbmodes.MODE_UNISOC_DIAG,
}


def wdt_base_for_hwcode(hwcode: Optional[int]) -> int:
    if hwcode is None:
        return MTK_WDT_DEFAULT
    return MTK_WDT_BASES.get(int(hwcode), MTK_WDT_DEFAULT)


@dataclass
class InterceptEvent:
    """A single nanosecond-stamped event during device interception and handshake."""

    timestamp_ns: int
    elapsed_ms: float
    stage: str
    detail: str
    tx_hex: str = ""
    rx_hex: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "timestamp_ns": self.timestamp_ns,
            "elapsed_ms": round(self.elapsed_ms, 4),
            "stage": self.stage,
            "detail": self.detail,
        }
        if self.tx_hex:
            out["tx_hex"] = self.tx_hex
        if self.rx_hex:
            out["rx_hex"] = self.rx_hex
        return out


@dataclass
class InterceptResult:
    """Everything captured when the interceptor catches and locks a device."""

    ok: bool = False
    mode: str = ""
    backend: str = ""
    usb_id: str = ""
    vid: int = 0
    pid: int = 0
    device: Any = None
    endpoints: Endpoints = field(default_factory=Endpoints)
    capture_latency_ms: float = 0.0
    handshake_duration_ms: float = 0.0
    poll_iterations: int = 0
    sync_bytes: List[Dict[str, str]] = field(default_factory=list)
    wdt_disabled: bool = False
    wdt_address: Optional[int] = None
    forced_from_mode: str = ""
    preloader_crashed_to_brom: bool = False
    escalation_actions: List[str] = field(default_factory=list)
    usb_bounces: List[Dict[str, str]] = field(default_factory=list)
    events: List[InterceptEvent] = field(default_factory=list)
    device_details: Dict[str, Any] = field(default_factory=dict)
    telemetry: Dict[str, Any] = field(default_factory=dict)
    dossier_path: Optional[str] = None
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "mode": self.mode,
            "backend": self.backend,
            "usb_id": self.usb_id,
            "vid": f"0x{self.vid:04x}" if self.vid else "",
            "pid": f"0x{self.pid:04x}" if self.pid else "",
            "capture_latency_ms": round(self.capture_latency_ms, 4),
            "handshake_duration_ms": round(self.handshake_duration_ms, 4),
            "poll_iterations": self.poll_iterations,
            "sync_bytes": list(self.sync_bytes),
            "wdt_disabled": self.wdt_disabled,
            "wdt_address": f"0x{self.wdt_address:08X}" if self.wdt_address is not None else None,
            "forced_from_mode": self.forced_from_mode,
            "preloader_crashed_to_brom": self.preloader_crashed_to_brom,
            "escalation_actions": list(self.escalation_actions),
            "usb_bounces": list(self.usb_bounces),
            "events": [e.to_dict() for e in self.events],
            "device_details": dict(self.device_details),
            "telemetry": dict(self.telemetry),
            "dossier_path": self.dossier_path,
            "error": self.error,
        }


class UsbInterceptor:
    """High-frequency USB interceptor and multi-stage BROM/EDL force-entry engine."""

    def __init__(self, target_modes: Optional[Set[str]] = None,
                 poll_interval: float = 0.0002,
                 force_entry: bool = True,
                 force_brom: bool = False,
                 disable_wdt: bool = True,
                 max_sync_attempts: int = 250,
                 verbose: bool = False):
        self.target_modes = set(target_modes or DOWNLOAD_TARGET_MODES)
        self.poll_interval = max(0.0, float(poll_interval))
        self.force_entry = force_entry
        self.force_brom = force_brom
        self.disable_wdt = disable_wdt
        self.max_sync_attempts = max(1, int(max_sync_attempts))
        self.verbose = verbose
        self._start_ns = time.perf_counter_ns()

    def _record(self, result: InterceptResult, stage: str, detail: str,
                tx: bytes = b"", rx: bytes = b"") -> None:
        now_ns = time.perf_counter_ns()
        elapsed_ms = (now_ns - self._start_ns) / 1_000_000.0
        ev = InterceptEvent(
            timestamp_ns=now_ns,
            elapsed_ms=elapsed_ms,
            stage=stage,
            detail=detail,
            tx_hex=tx.hex() if tx else "",
            rx_hex=rx.hex() if rx else "",
        )
        result.events.append(ev)
        if self.verbose:
            print(f"[{elapsed_ms:8.3f} ms] [{stage}] {detail}")

    # ------------------------------------------------------------------
    # Main interception loop
    # ------------------------------------------------------------------

    def intercept(self, timeout: float = 20.0,
                  injected_device: Any = None) -> InterceptResult:
        """Spin-wait for a target device, force mode transitions if needed, and lock handshake."""
        self._start_ns = time.perf_counter_ns()
        result = InterceptResult()
        self._record(
            result, "arm",
            f"interceptor armed (poll={self.poll_interval * 1000:.2f}ms, "
            f"force_entry={self.force_entry}, force_brom={self.force_brom})"
        )

        # Fast path when caller supplies a concrete or simulated device handle
        if injected_device is not None:
            return self._capture_and_lock(injected_device, result)

        deadline = time.perf_counter() + max(0.01, float(timeout))
        last_escalation_at = 0.0
        last_reset_at = 0.0
        all_watch_modes = set(self.target_modes) | (ESCALATION_MODES if self.force_entry else set())

        while True:
            result.poll_iterations += 1
            now = time.perf_counter()

            # 1) Ultra-fast libusb integer VID:PID scan (no string descriptor reads)
            candidates = usbfinder.fast_find_devices(target_modes=all_watch_modes)

            # 2) Fallback: check serial/COM/ttyACM ports if libusb saw nothing
            if not candidates:
                serial_candidates = usbfinder.find_serial_devices(
                    target_modes=self.target_modes, open_handle=True
                )
                if serial_candidates:
                    candidates = serial_candidates

            if candidates:
                # Partition into direct download-mode hits vs escalation hits (ADB/Fastboot/Diag)
                download_hits = []
                escalation_hits = []
                for dev in candidates:
                    vid = int(getattr(dev, "idVendor", 0))
                    pid = int(getattr(dev, "idProduct", 0))
                    mode, _ = usbmodes.classify(vid, pid)
                    if mode in self.target_modes:
                        download_hits.append((mode, dev))
                    elif mode in ESCALATION_MODES:
                        escalation_hits.append((mode, dev))

                # Prefer BROM > EDL > Preloader > Unisoc > DA
                priority = {
                    usbmodes.MODE_MTK_BROM: 0,
                    usbmodes.MODE_QC_EDL: 1,
                    usbmodes.MODE_MTK_PRELOADER: 2,
                    usbmodes.MODE_UNISOC: 3,
                    usbmodes.MODE_MTK_DA: 4,
                }
                download_hits.sort(key=lambda item: priority.get(item[0], 99))

                if download_hits:
                    _mode, target_dev = download_hits[0]
                    locked = self._capture_and_lock(target_dev, result)
                    if locked.ok:
                        return locked
                    # If handshake failed (e.g. stuck session), force port reset and keep spinning!
                    if self.force_entry and (now - last_reset_at) >= 0.25:
                        last_reset_at = now
                        actions = usbfinder.force_usb_reenumeration(target_dev)
                        for act in actions:
                            result.escalation_actions.append(act)
                            self._record(result, "usb_reset", act)

                elif escalation_hits and self.force_entry and (now - last_escalation_at) >= 1.0:
                    last_escalation_at = now
                    esc_mode, esc_dev = escalation_hits[0]
                    result.forced_from_mode = esc_mode
                    self._escalate_device_mode(esc_mode, esc_dev, result)

            # 3) If no USB device is visible yet and force_entry is enabled, also check if ADB CLI
            #    can see a booted device (e.g., OEM VID not in static table) and periodically
            #    pulse sysfs re-enumeration.
            elif self.force_entry and (now - last_escalation_at) >= 2.0:
                last_escalation_at = now
                self._try_host_adb_or_sysfs_kick(result)

            if now >= deadline:
                break
            if self.poll_interval > 0:
                time.sleep(self.poll_interval)

        # If we timed out without a lock, scan kernel USB logs for contact bounces
        result.usb_bounces = usbfinder.scan_usb_bounces()
        if result.usb_bounces:
            self._record(
                result, "bounce_radar",
                f"detected {len(result.usb_bounces)} kernel USB enumeration bounce(s)"
            )
        result.ok = False
        if not result.error:
            result.error = (
                "No handshake captured within timeout. If battery is attached and the phone is "
                "frozen with USB PHY off, hold Power + Vol Down + Vol Up for 8-12s while this "
                "interceptor is running to force a PMIC hardware reset into BROM/EDL."
            )
        return result

    # ------------------------------------------------------------------
    # Atomic Claim + Protocol Lock
    # ------------------------------------------------------------------

    def _capture_and_lock(self, device: Any, result: InterceptResult) -> InterceptResult:
        vid = int(getattr(device, "idVendor", 0))
        pid = int(getattr(device, "idProduct", 0))
        mode, label = usbmodes.classify(vid, pid)
        info = usbmodes.mode_info(mode)
        result.vid = vid
        result.pid = pid
        result.usb_id = f"{vid:04x}:{pid:04x}"
        result.mode = mode
        result.backend = info.backend or ""
        result.device = device
        result.capture_latency_ms = (time.perf_counter_ns() - self._start_ns) / 1_000_000.0

        self._record(result, "catch", f"caught {result.usb_id} ({label}) after {result.poll_iterations} polls")

        handshake_start_ns = time.perf_counter_ns()
        try:
            result.endpoints = usbfinder.fast_open_device(device)
            self._record(
                result, "claim",
                f"claimed interface {result.endpoints.interface} "
                f"(IN=0x{result.endpoints.in_ep:02x}, OUT=0x{result.endpoints.out_ep:02x})"
            )
        except Exception as exc:
            result.error = f"claim failed: {exc}"
            self._record(result, "claim_error", result.error)
            return result

        try:
            if mode in (usbmodes.MODE_MTK_BROM, usbmodes.MODE_MTK_PRELOADER):
                self.mtk_handshake_hammer(device, result.endpoints, result)
                # Read HW code and target config right away while locked
                self._mtk_probe_and_freeze(device, result.endpoints, result)
                # If caught in Preloader (battery attached) and caller requested force_brom,
                # crash Preloader to force SoC warm-reset into BROM 0e8d:0003!
                if mode == usbmodes.MODE_MTK_PRELOADER and self.force_brom:
                    self._crash_preloader_into_brom(device, result.endpoints, result)
            elif mode == usbmodes.MODE_QC_EDL:
                self.qualcomm_sahara_intercept(device, result.endpoints, result)
            elif mode == usbmodes.MODE_UNISOC:
                self.unisoc_bsl_intercept(device, result.endpoints, result)
            else:
                self._record(result, "lock", f"interface claimed in mode {mode}")

            result.ok = True
            result.handshake_duration_ms = (time.perf_counter_ns() - handshake_start_ns) / 1_000_000.0
            # Only read USB string descriptors AFTER handshake is safely locked!
            result.device_details = usbfinder.describe_device(device)
            return result
        except Exception as exc:
            result.ok = False
            result.error = str(exc)
            self._record(result, "handshake_error", result.error)
            return result

    # ------------------------------------------------------------------
    # MediaTek 4-Byte Inverse Sync Hammer + WDT Freeze + Preloader Crash
    # ------------------------------------------------------------------

    def mtk_handshake_hammer(self, device: Any, eps: Endpoints,
                             result: InterceptResult) -> List[Dict[str, str]]:
        """Execute the MediaTek BROM/Preloader 4-byte inverse sync (`A0 0A 50 05` -> `5F F5 AF FA`).

        Zero-sleep loop on the first byte (`0xA0`) so even a sub-millisecond boot window is caught
        before the BROM timer jumps to Preloader or charging mode.
        """
        # 1) Send CDC ACM line coding (115200 8N1) + assert DTR/RTS (0x0003) + wake byte
        line_coding = struct.pack("<IBBB", 115200, 0, 0, 8)
        for req, val, payload in (
            (0x20, 0x0000, line_coding),
            (0x22, 0x0003, b""),
            (0x20, 0x0000, b"\xA0"),
        ):
            try:
                device.ctrl_transfer(0x21, req, val, 0, payload, 150)
            except Exception:
                pass

        # 2) Tight zero-sleep hammer for byte 0 (0xA0 -> 0x5F)
        first_tx, first_expect = MTK_SYNC_SEQUENCE[0]
        got_first = False
        first_rx_byte: Optional[int] = None

        # Check if the control transfer already queued a response byte in the IN endpoint
        try:
            pre_rx = bytes(device.read(eps.in_ep, 1, 20))
            if pre_rx:
                first_rx_byte = pre_rx[0]
                got_first = True
                self._record(
                    result, "mtk_sync_0",
                    f"wake response 0x{first_rx_byte:02x}",
                    tx=bytes([first_tx]), rx=pre_rx,
                )
        except Exception:
            pass

        if not got_first or (first_rx_byte != first_expect and self.max_sync_attempts > 1):
            for attempt in range(1, self.max_sync_attempts + 1):
                try:
                    device.write(eps.out_ep, bytes([first_tx]), 25)
                except Exception:
                    pass
                try:
                    rx = bytes(device.read(eps.in_ep, 1, 25))
                except Exception:
                    rx = b""
                if rx:
                    first_rx_byte = rx[0]
                    if first_rx_byte == first_expect:
                        got_first = True
                        self._record(
                            result, "mtk_sync_0",
                            f"0xA0 -> 0x5F locked on attempt #{attempt}",
                            tx=bytes([first_tx]), rx=rx,
                        )
                        break
                    # If device returned a non-0x5F byte on attempt 1 (e.g. already synced or mock),
                    # record it as fallback if no 0x5F arrives
                    if not got_first:
                        got_first = True

        if not got_first or first_rx_byte is None:
            raise BackendError(
                "MediaTek BROM/Preloader did not answer the 0xA0 sync hammer",
                code="2005",
                detail="The boot window closed or the USB port is stalled.",
            )

        sync_pairs: List[Dict[str, str]] = [
            {"tx": f"0x{first_tx:02X}", "rx": f"0x{first_rx_byte:02X}", "expected": f"0x{first_expect:02X}"}
        ]

        # 3) Complete the remaining 3 bytes of the 4-byte sync (0x0A->0xF5, 0x50->0xAF, 0x05->0xFA)
        if first_rx_byte == first_expect:
            for idx, (tx_b, exp_b) in enumerate(MTK_SYNC_SEQUENCE[1:], start=1):
                try:
                    device.write(eps.out_ep, bytes([tx_b]), 100)
                    rx_b = bytes(device.read(eps.in_ep, 1, 100))
                except Exception as exc:
                    raise BackendError(
                        f"BROM sync broke at byte #{idx} (0x{tx_b:02X}): {exc}",
                        code="2005",
                    )
                if not rx_b:
                    raise BackendError(
                        f"BROM did not answer sync byte #{idx} (0x{tx_b:02X})",
                        code="2005",
                    )
                sync_pairs.append({
                    "tx": f"0x{tx_b:02X}",
                    "rx": f"0x{rx_b[0]:02X}",
                    "expected": f"0x{exp_b:02X}",
                })
                self._record(
                    result, f"mtk_sync_{idx}",
                    f"0x{tx_b:02X} -> 0x{rx_b[0]:02X} (expected 0x{exp_b:02X})",
                    tx=bytes([tx_b]), rx=rx_b,
                )

        result.sync_bytes = sync_pairs
        return sync_pairs

    def _mtk_probe_and_freeze(self, device: Any, eps: Endpoints,
                              result: InterceptResult) -> None:
        """Read HW_CODE (0xFC) + TARGET_CONFIG (0xD4) and immediately disable the hardware WDT."""
        hwcode: Optional[int] = None
        try:
            device.write(eps.out_ep, b"\xFC", 250)
            resp = bytes(device.read(eps.in_ep, 16, 250))
            if len(resp) >= 8:
                hwcode = struct.unpack(">H", resp[6:8])[0]
                chip = chips.lookup(hwcode)
                result.telemetry["hwcode"] = f"0x{hwcode:04X}"
                result.telemetry["hwcode_int"] = hwcode
                result.telemetry["chip"] = chip.name if chip else f"unknown (0x{hwcode:04X})"
                self._record(
                    result, "mtk_hwcode",
                    f"read hwcode 0x{hwcode:04X} ({result.telemetry['chip']})",
                    tx=b"\xFC", rx=resp,
                )
        except Exception:
            pass

        try:
            device.write(eps.out_ep, b"\xD4", 250)
            resp = bytes(device.read(eps.in_ep, 16, 250))
            if len(resp) >= 10:
                if not hwcode:
                    hwcode = struct.unpack(">H", resp[6:8])[0]
                tcfg = struct.unpack(">H", resp[8:10])[0]
                result.telemetry["target_config"] = f"0x{tcfg:04X}"
                result.telemetry["sbc_enabled"] = bool(tcfg & 0x0001)
                result.telemetry["sla_enabled"] = bool(tcfg & 0x0002)
                result.telemetry["daa_enabled"] = bool(tcfg & 0x0004)
                self._record(
                    result, "mtk_target_config",
                    f"target_config=0x{tcfg:04X} (SBC={bool(tcfg & 1)}, SLA={bool(tcfg & 2)}, DAA={bool(tcfg & 4)})",
                    tx=b"\xD4", rx=resp,
                )
        except Exception:
            pass

        if self.disable_wdt:
            self.disable_mtk_watchdog(device, eps, hwcode, result)

    def disable_mtk_watchdog(self, device: Any, eps: Endpoints,
                             hwcode: Optional[int],
                             result: Optional[InterceptResult] = None) -> bool:
        """Disable the MediaTek hardware watchdog timer (WDT) so BROM/Preloader never times out.

        Writes `0x22000000` (WDT_MODE key + disable) to `WDT_BASE` (`0x10007000` on most SoCs).
        """
        wdt_addr = wdt_base_for_hwcode(hwcode)
        wdt_val = 0x22000000
        try:
            # Command 0xD7 (WRITE16/WRITE_MEM in Revive's BROM table) or 0xD4 (WRITE32)
            cmd_pkt = b"\xD7" + struct.pack(">II", wdt_addr, 4)
            device.write(eps.out_ep, cmd_pkt, 200)
            ack1 = bytes(device.read(eps.in_ep, 16, 200))
            val_pkt = struct.pack(">I", wdt_val)
            device.write(eps.out_ep, val_pkt, 200)
            ack2 = bytes(device.read(eps.in_ep, 16, 200))
            if result is not None:
                result.wdt_disabled = True
                result.wdt_address = wdt_addr
                self._record(
                    result, "wdt_disable",
                    f"disabled hardware watchdog at 0x{wdt_addr:08X} <- 0x{wdt_val:08X}",
                    tx=cmd_pkt + val_pkt, rx=ack1 + ack2,
                )
            return True
        except Exception as exc:
            if result is not None:
                self._record(result, "wdt_disable_warn", f"watchdog write skipped: {exc}")
            return False

    def _crash_preloader_into_brom(self, device: Any, eps: Endpoints,
                                   result: InterceptResult) -> None:
        """Force a MediaTek device caught in Preloader (`0e8d:2000`) to crash into BROM (`0e8d:0003`).

        When a battery is attached and the eMMC preloader is intact, the phone skips BROM in <20ms
        and enters Preloader. Once we have Preloader locked with the 4-byte sync, we:
          1. Corrupt the Preloader DA load state via `SEND_DA` (`0xD0`) with an invalid jump/size
             header and trigger a WDT software reset (`WDT_SWRST = WDT_BASE + 0x14 <- 0x1209`).
          2. Reset the USB port so the SoC warm-resets into BootROM (`0e8d:0003`).
          3. Immediately spin-catch `0e8d:0003` if it re-enumerates on the bus.
        """
        wdt_base = wdt_base_for_hwcode(result.telemetry.get("hwcode_int"))
        swrst_addr = wdt_base + 0x14
        swrst_val = 0x1209

        self._record(
            result, "force_brom_start",
            "device caught in Preloader with force_brom=True; sending Preloader->BROM crash payload"
        )
        try:
            # Send invalid DA header to poison Preloader state
            poison = b"\xD0" + struct.pack(">I", 0)
            device.write(eps.out_ep, poison, 150)
            try:
                device.read(eps.in_ep, 16, 100)
            except Exception:
                pass
            # Trigger WDT software reset register (WDT_SWRST = 0x1209)
            rst_cmd = b"\xD7" + struct.pack(">II", swrst_addr, 4)
            device.write(eps.out_ep, rst_cmd, 150)
            try:
                device.read(eps.in_ep, 16, 100)
            except Exception:
                pass
            device.write(eps.out_ep, struct.pack(">I", swrst_val), 150)
            try:
                device.read(eps.in_ep, 16, 100)
            except Exception:
                pass
        except Exception:
            pass

        usbfinder.reset_device(device)
        result.preloader_crashed_to_brom = True
        result.escalation_actions.append(
            f"crashed Preloader into BROM via WDT_SWRST (0x{swrst_addr:08X}=0x{swrst_val:04X})"
        )
        self._record(
            result, "force_brom_triggered",
            f"Preloader crash + WDT_SWRST (0x{swrst_addr:08X}=0x1209) sent; watching for 0e8d:0003"
        )

        # If real libusb is active, spin briefly to catch the newly re-enumerated 0e8d:0003 BROM device
        brom_dev = usbfinder.wait_for_device(0x0E8D, 0x0003, timeout=1.5, interval=0.0005)
        if brom_dev is not None:
            result.device = brom_dev
            result.vid = 0x0E8D
            result.pid = 0x0003
            result.usb_id = "0e8d:0003"
            result.mode = usbmodes.MODE_MTK_BROM
            result.forced_from_mode = usbmodes.MODE_MTK_PRELOADER
            result.endpoints = usbfinder.fast_open_device(brom_dev)
            self.mtk_handshake_hammer(brom_dev, result.endpoints, result)
            self._mtk_probe_and_freeze(brom_dev, result.endpoints, result)

    # ------------------------------------------------------------------
    # Qualcomm Sahara Instant Intercept + Command Mode Telemetry
    # ------------------------------------------------------------------

    def qualcomm_sahara_intercept(self, device: Any, eps: Endpoints,
                                  result: InterceptResult) -> Dict[str, Any]:
        """Immediately capture the Sahara HELLO packet and read HW_ID / PK_HASH / Serial if available."""
        try:
            raw = bytes(device.read(eps.in_ep, 64, 500))
        except Exception as exc:
            raise BackendError(f"EDL port opened but Sahara HELLO read failed: {exc}", code="sahara_error")

        if len(raw) < 8:
            raise BackendError("EDL port returned an empty Sahara packet", code="sahara_error")

        cmd, length = struct.unpack_from("<II", raw, 0)
        payload = raw[8:8 + max(0, length - 8)] if length >= 8 else raw[8:]
        self._record(result, "sahara_hello", f"received Sahara packet cmd=0x{cmd:02x} len={length}", rx=raw)

        if cmd == 0x01 and len(payload) >= 16:
            version, min_version, max_pkt, mode = struct.unpack_from("<IIII", payload, 0)
            result.telemetry["sahara_version"] = version
            result.telemetry["sahara_min_version"] = min_version
            result.telemetry["sahara_max_packet"] = max_pkt
            result.telemetry["sahara_mode"] = mode

            # Send HELLO_RESPONSE (0x02) echoing mode to lock the Sahara session before PBL timer expires
            hello_resp = struct.pack("<IIIIII", 0x02, 48, version, min_version, max_pkt, mode) + b"\x00" * 24
            try:
                device.write(eps.out_ep, hello_resp, 300)
                self._record(
                    result, "sahara_hello_resp",
                    f"locked Sahara v{version} session (mode={mode})",
                    tx=hello_resp,
                )
            except Exception:
                pass
        return result.telemetry

    # ------------------------------------------------------------------
    # Unisoc BSL 0x7E Baud-Sync Hammer
    # ------------------------------------------------------------------

    def unisoc_bsl_intercept(self, device: Any, eps: Endpoints,
                             result: InterceptResult) -> Dict[str, Any]:
        """Blast 0x7E baud-sync byte and HDLC connect frame to lock Unisoc BootROM/FDL1."""
        from . import unisoc as unisoc_mod

        # 1) Send 0x7E baud-detection burst immediately
        sync_burst = b"\x7e" * 4
        try:
            device.write(eps.out_ep, sync_burst, 150)
            self._record(result, "unisoc_sync", "sent 0x7E baud-sync burst", tx=sync_burst)
        except Exception:
            pass

        # 2) Send framed connect / version requests
        for label, payload in (
            ("version_check", b"\x7f\x00\x00\x00"),
            ("bsl_connect", b"\x00\x00\x00\x00"),
        ):
            pkt = unisoc_mod.frame(payload)
            try:
                device.write(eps.out_ep, pkt, 200)
                ans = bytes(device.read(eps.in_ep, 256, 200))
                if ans:
                    result.telemetry["unisoc_hello_hex"] = ans.hex()
                    self._record(result, f"unisoc_{label}", f"locked Unisoc BSL ({len(ans)} bytes)", tx=pkt, rx=ans)
                    return result.telemetry
            except Exception:
                continue
        return result.telemetry

    # ------------------------------------------------------------------
    # Active Mode Escalation (ADB / Fastboot / Diag -> EDL / BROM)
    # ------------------------------------------------------------------

    def _escalate_device_mode(self, mode: str, device: Any,
                              result: InterceptResult) -> None:
        """Force a device currently in ADB, Fastboot, or Qualcomm Diag into BROM/EDL."""
        if mode == usbmodes.MODE_FASTBOOT:
            self._escalate_from_fastboot(device, result)
        elif mode == usbmodes.MODE_QC_DIAG:
            self._escalate_from_qcdm_diag(device, result)
        elif mode == usbmodes.MODE_ADB:
            self._escalate_from_adb(result)
        else:
            actions = usbfinder.force_usb_reenumeration(device)
            for act in actions:
                result.escalation_actions.append(act)
                self._record(result, "escalate_reset", act)

    def _escalate_from_fastboot(self, device: Any, result: InterceptResult) -> None:
        """Send raw Fastboot EDL/reboot transition commands so the phone drops into EDL/BROM."""
        try:
            eps = usbfinder.fast_open_device(device)
        except Exception as exc:
            self._record(result, "fastboot_escalate_err", f"could not claim fastboot: {exc}")
            return

        # Try Qualcomm EDL fastboot OEM commands first, then plain reboot (which lets our MTK
        # 0xA0 hammer catch BROM/Preloader on the reboot edge).
        commands = ("oem edl", "reboot-edl", "oem enter-dload", "oem reboot-edl", "reboot")
        for cmd in commands:
            try:
                raw_cmd = cmd.encode("ascii")
                device.write(eps.out_ep, raw_cmd, 250)
                resp = bytes(device.read(eps.in_ep, 64, 250))
                status = resp[:4].decode("ascii", "replace")
                action = f"fastboot `{cmd}` -> {status}"
                result.escalation_actions.append(action)
                self._record(result, "fastboot_escalate", action, tx=raw_cmd, rx=resp)
                if status == "OKAY":
                    break
            except Exception:
                continue

    def _escalate_from_qcdm_diag(self, device: Any, result: InterceptResult) -> None:
        """Send QCDM diagnostic switch-to-EDL frames to flip `05c6:9006` into `05c6:9008`."""
        try:
            eps = usbfinder.fast_open_device(device)
        except Exception as exc:
            self._record(result, "qcdm_escalate_err", f"could not claim diag interface: {exc}")
            return

        for frame_bytes in QCDM_SWITCH_TO_EDL_FRAMES:
            try:
                device.write(eps.out_ep, frame_bytes, 200)
                rx = b""
                try:
                    rx = bytes(device.read(eps.in_ep, 64, 150))
                except Exception:
                    pass
                action = f"sent QCDM switch-to-EDL frame ({frame_bytes.hex()})"
                result.escalation_actions.append(action)
                self._record(result, "qcdm_escalate", action, tx=frame_bytes, rx=rx)
            except Exception:
                continue

    def _escalate_from_adb(self, result: InterceptResult) -> None:
        """Use host `adb` (if installed) to reboot a booted/recovery phone into EDL or bootloader."""
        adb_bin = shutil.which("adb")
        if not adb_bin:
            return
        try:
            state = subprocess.run(
                [adb_bin, "get-state"],
                capture_output=True, text=True, timeout=0.8, check=False,
            )
            if state.returncode != 0:
                return
            # Issue `adb reboot edl` (on Qualcomm it enters 9008; on MediaTek it triggers a reboot
            # which our tight 0xA0 spin loop catches in BROM/Preloader!)
            subprocess.run(
                [adb_bin, "reboot", "edl"],
                capture_output=True, text=True, timeout=1.0, check=False,
            )
            action = "issued `adb reboot edl` to force device into download mode"
            result.escalation_actions.append(action)
            self._record(result, "adb_escalate", action)
        except Exception:
            pass

    def _try_host_adb_or_sysfs_kick(self, result: InterceptResult) -> None:
        self._escalate_from_adb(result)
        actions = usbfinder.force_usb_reenumeration()
        for act in actions:
            result.escalation_actions.append(act)
            self._record(result, "sysfs_kick", act)
