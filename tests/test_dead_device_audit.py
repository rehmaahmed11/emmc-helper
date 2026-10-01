"""Rigorous audit of the dead-device recovery path: handshake capture + forced BROM/EDL entry.

What this module does
---------------------
Every test here conditions a *simulated, deliberately damaged* phone: a boot ROM that ignores the
sync hammer, answers garbage, drops out mid-handshake, dribbles USB packets, refuses WDT writes,
or never comes back as BROM after a Preloader crash. The invariants under test are the promises
the tool makes to a user holding a hard-bricked phone:

  1. ``ok=True`` is only ever reported when a real handshake locked on the wire.
  2. Every byte the tool claims to have captured (the 4-byte BROM sync, the Sahara HELLO) is
     verified, not assumed - a partial or wrong packet is a failure.
  3. ``preloader_crashed_to_brom`` means the crash payload went out; ``brom_recaptured`` means
     the phone was actually caught again as ``0e8d:0003`` and re-handshaken. The two are separate.
  4. Dead devices (nothing enumerates, USB contact bounces) end in an actionable message, never
     in a phantom success and never in a traceback.
  5. Timing claims hold: the sync hammer is a tight zero-sleep loop and does not touch USB string
     descriptors before the lock, because those cost milliseconds the BROM window does not have.

All transports are in-process fakes with nanosecond-stamped transfer logs; no hardware, no libusb
and no third-party dependency is required.
"""
from __future__ import annotations

import json
import struct
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from fixtures import patched
from revive.backends import interceptor, usbfinder
from revive.backends.mtk_brom import MtkBromBackend
from revive.backends import intercept_and_capture
from revive.backends.base import BackendError, BackendUnavailable, Endpoints
from revive.core import usbmodes

VID_MTK = 0x0E8D
VID_QC = 0x05C6


# ---------------------------------------------------------------------------------------------
# Fault-injecting transports
# ---------------------------------------------------------------------------------------------

class FakeTransport:
    """Common libusb-shaped surface: records every transfer with a nanosecond stamp."""

    def __init__(self, vid: int, pid: int, serial_number: str = ""):
        self.idVendor = vid
        self.idProduct = pid
        self.bus = 9
        self.address = 3
        self.serial_number = serial_number
        self.writes: List[Tuple[int, int, bytes]] = []      # (t_ns, endpoint, data)
        self.reads: List[Tuple[int, int, int]] = []         # (t_ns, endpoint, requested)
        self.ctrl: List[Tuple[Any, ...]] = []
        self.resets = 0
        self.fail_writes = False
        self.string_reads = 0
        self.string_read_ns: Optional[int] = None

    # -- libusb surface ------------------------------------------------------------------
    def get_active_configuration(self):
        return []

    def is_kernel_driver_active(self, _intf: int) -> bool:
        return False

    def set_configuration(self) -> None:
        return None

    def ctrl_transfer(self, *args, **kwargs) -> bytes:
        self.ctrl.append(args)
        return b""

    def write(self, ep: int, data: bytes, timeout: Optional[float] = None) -> int:
        if self.fail_writes:
            raise OSError("simulated USB write failure")
        raw = bytes(data)
        self.writes.append((time.perf_counter_ns(), ep, raw))
        self._on_write(raw)
        return len(raw)

    def read(self, ep: int, length: int, timeout: Optional[float] = None) -> bytes:
        self.reads.append((time.perf_counter_ns(), ep, length))
        return self._on_read(length)

    def reset(self) -> None:
        self.resets += 1

    # -- string descriptors (must not be touched on the hot path) ------------------------
    @property
    def iManufacturer(self):
        self.string_reads += 1
        self.string_read_ns = self.string_read_ns or time.perf_counter_ns()
        return 1

    @property
    def iProduct(self):
        self.string_reads += 1
        self.string_read_ns = self.string_read_ns or time.perf_counter_ns()
        return 2

    @property
    def iSerialNumber(self):
        self.string_reads += 1
        self.string_read_ns = self.string_read_ns or time.perf_counter_ns()
        return 3

    # -- hooks ---------------------------------------------------------------------------
    def _on_write(self, raw: bytes) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _on_read(self, length: int) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError


def brom_ack(value: int = 0x00000000) -> bytes:
    """A 16-byte MediaTek command-status reply with `value` in the status word."""
    return b"\x00" * 8 + struct.pack(">I", value) + b"\x00" * 4


class BromScript:
    """Request/response engine for a simulated BROM/Preloader (transport-independent)."""

    def __init__(self, a0_plan: Sequence[bytes] = (b"\x5F",),
                 sync_plan: Optional[Dict[int, bytes]] = None,
                 hwcode: int = 0x0766,
                 target_config: int = 0x0005,
                 hwcode_status: int = 0x00000000,
                 wdt_status: int = 0x00000000,
                 poison_status: int = 0x00000000):
        self.a0_plan = list(a0_plan) or [b""]
        self.sync_plan = dict(sync_plan) if sync_plan is not None else {
            0x0A: b"\xF5", 0x50: b"\xAF", 0x05: b"\xFA"}
        self.hwcode = hwcode
        self.target_config = target_config
        self.hwcode_status = hwcode_status
        self.wdt_status = wdt_status
        self.poison_status = poison_status
        self.a0_count = 0
        self.queue: List[bytes] = []
        self.last_cmd: Optional[int] = None

    def _push(self, data: bytes) -> None:
        self.queue.append(data)

    def on_write(self, raw: bytes) -> None:
        if not raw:
            return
        cmd = raw[0]
        if raw == b"\xA0":
            idx = min(self.a0_count, len(self.a0_plan) - 1)
            self.a0_count += 1
            self._push(self.a0_plan[idx])
        elif cmd in (0x0A, 0x50, 0x05) and len(raw) == 1:
            self._push(self.sync_plan.get(cmd, b""))
        elif raw == b"\xFC":
            resp = bytearray(16)
            struct.pack_into(">H", resp, 6, self.hwcode)
            struct.pack_into(">I", resp, 8, self.hwcode_status)
            self._push(bytes(resp))
        elif raw == b"\xD4":
            resp = bytearray(16)
            struct.pack_into(">H", resp, 6, self.hwcode)
            struct.pack_into(">H", resp, 8, self.target_config)
            self._push(bytes(resp))
        elif cmd == 0xD7 and len(raw) == 9:
            self._push(brom_ack(self.wdt_status))
        elif cmd == 0xD7 and len(raw) == 4:
            self._push(brom_ack(self.wdt_status))
        elif cmd == 0xD0 or (len(raw) == 4 and self.last_cmd == 0xD0):
            self._push(brom_ack(self.poison_status))
        else:
            self._push(brom_ack(0))
        self.last_cmd = cmd

    def on_read(self, length: int) -> bytes:
        if self.queue:
            return self.queue.pop(0)
        return b""


class ScriptedBrom(FakeTransport):
    """A MediaTek BROM/Preloader that answers (or refuses) according to a plan."""

    def __init__(self, vid: int = VID_MTK, pid: int = 0x0003, serial_number: str = "AUDIT_BROM",
                 **script_kwargs):
        super().__init__(vid, pid, serial_number)
        self.script = BromScript(**script_kwargs)

    def _on_write(self, raw: bytes) -> None:
        self.script.on_write(raw)

    def _on_read(self, length: int) -> bytes:
        return self.script.on_read(length)

    @property
    def a0_writes(self) -> int:
        return sum(1 for _t, _e, data in self.writes if data == b"\xA0")

    def writes_matching(self, prefix: bytes) -> List[bytes]:
        return [data for _t, _e, data in self.writes if data.startswith(prefix)]


class ScriptedSerialPort:
    """A pyserial-shaped COM port driven by the same BromScript (Windows/VCOM path)."""

    def __init__(self, **script_kwargs):
        self.script = BromScript(**script_kwargs)
        self.timeout = 0.01
        self.write_timeout = 0.05
        self.baudrate = 9600
        self.dtr = False
        self.rts = False
        self.closed = False
        self.history: List[bytes] = []

    def write(self, data: bytes) -> int:
        raw = bytes(data)
        self.history.append(raw)
        self.script.on_write(raw)
        return len(raw)

    def read(self, length: int) -> bytes:
        return self.script.on_read(length)

    def flush(self) -> None:
        return None

    def reset_input_buffer(self) -> None:
        return None

    def reset_output_buffer(self) -> None:
        return None

    def send_break(self, duration: float = 0.05) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def sahara_hello_frame(version: int = 2, min_version: int = 1, max_packet: int = 1024,
                       mode: int = 0) -> bytes:
    return struct.pack("<IIIIII", 0x01, 48, version, min_version, max_packet, mode) + b"\x00" * 24


class ScriptedSahara(FakeTransport):
    """A Qualcomm EDL boot ROM that dribbles Sahara frames in configurable chunks."""

    def __init__(self, frames: Sequence[bytes], chunk: Optional[int] = None,
                 serial_number: str = "0014d0e1"):
        super().__init__(VID_QC, 0x9008, serial_number)
        self._wire = bytearray(b"".join(frames))
        self.chunk = chunk

    def _on_write(self, raw: bytes) -> None:
        return None                     # the caller's writes are asserted from self.writes

    def _on_read(self, length: int) -> bytes:
        if self.chunk is None:
            take = min(length, len(self._wire))
        else:
            take = min(length, self.chunk, len(self._wire))
        out = bytes(self._wire[:take])
        del self._wire[:take]
        return out


class ScriptedFastboot(FakeTransport):
    """Fastboot transport: per-command replies (missing commands get FAIL)."""

    def __init__(self, replies: Dict[str, bytes]):
        super().__init__(0x18D1, 0x4EE0, "FB_AUDIT")
        self.replies = {k.encode("ascii"): v for k, v in replies.items()}

    def _on_write(self, raw: bytes) -> None:
        return None

    def _on_read(self, length: int) -> bytes:
        for _t, _e, data in reversed(self.writes):
            if data in self.replies:
                return self.replies[data]
        return b"FAILunknown command"


class ScriptedDiag(FakeTransport):
    """Qualcomm 9006 diagnostic port: records frames, answers nothing."""

    def __init__(self):
        super().__init__(VID_QC, 0x9006, "DIAG_AUDIT")

    def _on_write(self, raw: bytes) -> None:
        return None

    def _on_read(self, length: int) -> bytes:
        return b""


def dead_finder(**kwargs):
    """A finder that never sees anything - the *no phone on the bus at all* condition."""
    return []


# ---------------------------------------------------------------------------------------------
# Group A - dead / hard-bricked device conditions
# ---------------------------------------------------------------------------------------------

def test_dead_device_intercept_times_out_with_actionable_guidance():
    engine = interceptor.UsbInterceptor(force_entry=True, poll_interval=0.0)
    with patched(usbfinder, fast_find_devices=dead_finder,
                 find_serial_devices=lambda **kw: [], scan_usb_bounces=lambda: []):
        started = time.perf_counter()
        res = engine.intercept(timeout=0.05)
        elapsed = time.perf_counter() - started
    assert res.ok is False, "a device that never enumerates must not be reported as captured"
    assert res.poll_iterations >= 1
    assert elapsed < 1.0, f"a 50 ms timeout must not take {elapsed:.3f} s"
    lowered = (res.error or "").lower()
    assert "hold" in lowered or "power" in lowered, (
        "the timeout message must tell the user how to force the phone into BROM (power/volume "
        f"combo), got: {res.error!r}"
    )
    assert not res.sync_bytes and not res.wdt_disabled and not res.brom_recaptured


def test_dead_device_bounce_radar_surfaces_kernel_contact_bounces():
    bounces = [{
        "kind": "descriptor_error", "port": "1-2", "error": "-71",
        "raw": "usb 1-2: device descriptor read/64, error -71",
    }]
    engine = interceptor.UsbInterceptor(force_entry=False, poll_interval=0.0)
    with patched(usbfinder, fast_find_devices=dead_finder,
                 find_serial_devices=lambda **kw: [], scan_usb_bounces=lambda: list(bounces)):
        res = engine.intercept(timeout=0.03)
    assert res.ok is False
    assert res.usb_bounces == bounces, "kernel USB bounces must be carried into the result"
    assert any(e.stage == "bounce_radar" for e in res.events), (
        "the bounce must be visible in the nanosecond trace, not just in a field"
    )
    assert res.to_dict()["usb_bounces"] == bounces


def test_no_device_backend_open_raises_backend_unavailable_not_crash():
    backend = MtkBromBackend()
    with patched(usbfinder, find_devices=lambda *a, **k: ([], ["pyusb/libusb is not installed"]),
                 find_serial_devices=lambda **kw: [],
                 fast_find_devices=lambda **kw: []):
        try:
            backend.open()
        except BackendUnavailable as exc:
            assert exc.code == "no_device"
            assert "MediaTek" in str(exc) or "No MediaTek" in str(exc)
            assert exc.detail and ("Volume" in exc.detail or "volume" in exc.detail)
        else:  # pragma: no cover - would be a hard failure
            raise AssertionError("opening with no device must raise BackendUnavailable")


def test_stale_session_with_no_sync_reply_fails_honestly_and_caps_attempts():
    """A device that enumerates but never answers the hammer: the classic stale/frozen session."""
    stale = ScriptedBrom(a0_plan=(b"",))
    backend = MtkBromBackend()
    try:
        backend.open(device=stale)
    except BackendError as exc:
        assert exc.code == "2005", f"expected the documented BROM sync failure code, got {exc.code}"
        assert "sync hammer" in str(exc) or "0x5F" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("a silent device must not open successfully")
    assert stale.a0_writes == 80, (
        f"the backend handshake must stop after its 80 max attempts, saw {stale.a0_writes}"
    )
    assert stale.resets == 1, "a failed BROM handshake must reset the port for the next attempt"


def test_intercept_keeps_spinning_after_a_failed_handshake_until_one_locks():
    bad = ScriptedBrom(a0_plan=(b"\x11",))          # answers noise forever
    good = ScriptedBrom(serial_number="GOOD_BROM")
    polls = {"n": 0}

    def finder(**_kwargs):
        polls["n"] += 1
        return [bad] if polls["n"] <= 2 else [good]

    engine = interceptor.UsbInterceptor(force_entry=False, poll_interval=0.0,
                                        max_sync_attempts=3)
    with patched(usbfinder, fast_find_devices=finder,
                 find_serial_devices=lambda **kw: [], scan_usb_bounces=lambda: []):
        res = engine.intercept(timeout=1.0)
    assert res.ok is True, "the interceptor must keep trying after a failed lock"
    assert res.usb_id == "0e8d:0003"
    assert res.poll_iterations >= 3
    assert res.error == "", "a locked session must not carry the earlier attempt's error"
    failed = [e for e in res.events if e.stage == "handshake_error"]
    assert failed, "the failed attempt must stay in the trace for the dossier"


def test_bounce_radar_parses_kernel_usb_enumeration_failures():
    """A hard-bricked phone whose pull-up flickers for 1 ms never enumerates - the kernel log is
    the only evidence, and the tool must read it rather than say 'nothing connected'."""
    dmesg = "\n".join([
        "usb 1-2: device descriptor read/64, error -71",
        "usb 1-2: unable to enumerate USB device",
        "usb 3-1: device not accepting address 5, error -110",
        "usb 3-1: USB disconnect, device number 4",
    ])
    with patched(usbmodes, current_os=lambda: "linux"), \
         patched(usbfinder.subprocess, run=lambda *a, **k: SimpleNamespace(
             stdout=dmesg, stderr="", returncode=0)):
        bounces = usbfinder.scan_usb_bounces()
    kinds = [b["kind"] for b in bounces]
    assert kinds == ["descriptor_error", "enumerate_fail", "not_accepting_address",
                     "disconnect_bounce"], f"kernel bounce kinds mis-parsed: {kinds}"
    assert bounces[0]["port"] == "1-2" and bounces[0]["error"] == "-71"
    assert bounces[2]["error"] == "-110"
    with patched(usbmodes, current_os=lambda: "windows"):
        assert usbfinder.scan_usb_bounces() == [], "dmesg parsing is Linux-only"


def test_force_usb_reenumeration_records_what_it_did():
    dev = FakeTransport(VID_MTK, 0x0003)
    with patched(usbmodes, current_os=lambda: "windows"):     # skip sysfs layer
        actions = usbfinder.force_usb_reenumeration(dev)
    assert any("USB port reset" in a for a in actions), (
        f"a stuck device must be reset and the action recorded, got {actions}"
    )
    assert dev.resets >= 1

    class Unresettable(FakeTransport):
        def reset(self):
            raise OSError("device gone")

    with patched(usbmodes, current_os=lambda: "windows"):
        actions = usbfinder.force_usb_reenumeration(Unresettable(VID_MTK, 0x0003))
    assert isinstance(actions, list), "a device that vanished mid-reset must not raise"


def test_usb_open_errors_are_translated_into_plain_english():
    dev = FakeTransport(VID_MTK, 0x0003)
    permission = usbfinder._translate_usb_error(PermissionError("Access denied (errno 13)"), dev)
    assert isinstance(permission, BackendUnavailable) and permission.code == "driver_missing"
    busy = usbfinder._translate_usb_error(Exception("device busy: resource busy"), dev)
    assert busy.code == "port_busy"
    gone = usbfinder._translate_usb_error(Exception("no such device"), dev)
    assert gone.code == "no_device"


# ---------------------------------------------------------------------------------------------
# Group B - MediaTek handshake capture rigor
# ---------------------------------------------------------------------------------------------

def test_mtk_sync_requires_all_four_exact_bytes():
    """Garbage answers must never add up to a captured handshake."""
    noise = ScriptedBrom(a0_plan=(b"\x42",))
    engine = interceptor.UsbInterceptor(max_sync_attempts=5)
    res = engine.intercept(timeout=0.5, injected_device=noise)
    assert res.ok is False, "0x42 is not the 0x5F sync reply - this is not a captured handshake"
    assert res.mode == usbmodes.MODE_MTK_BROM, "the caught mode itself is still reported"
    assert res.error and "0x5F" in res.error
    assert noise.a0_writes == 5
    assert len(res.sync_bytes) <= 1
    assert res.wdt_disabled is False, "no WDT write may be attempted before the sync locks"


def test_mtk_sync_rejects_wrong_byte_mid_sequence():
    """0xA0 -> 0x5F but 0x0A -> 0x13: the sync broke at byte #1 and must be reported as broken."""
    broken = ScriptedBrom(sync_plan={0x0A: b"\x13", 0x50: b"\xAF", 0x05: b"\xFA"})
    engine = interceptor.UsbInterceptor()
    res = engine.intercept(timeout=0.5, injected_device=broken)
    assert res.ok is False
    assert res.error and "0x13" in res.error and "expected 0x5F" not in res.error
    assert [p["rx"] for p in res.sync_bytes] == ["0x5F", "0x13"], (
        "the trace must show exactly how far the sync got before it broke"
    )


def test_mtk_sync_recovers_from_noise_then_locks_on_the_exact_byte():
    noisy = ScriptedBrom(a0_plan=(b"\x00", b"", b"\xF3", b"\x5F"))
    engine = interceptor.UsbInterceptor(max_sync_attempts=20)
    res = engine.intercept(timeout=0.5, injected_device=noisy)
    assert res.ok is True, "the hammer must keep going until the exact 0x5F arrives"
    assert [p["rx"] for p in res.sync_bytes] == ["0x5F", "0xF5", "0xAF", "0xFA"]
    assert noisy.a0_writes == 4, "one hammer write per attempt, including the noise replies"
    stages = [e.stage for e in res.events]
    assert {"mtk_sync_0", "mtk_sync_1", "mtk_sync_2", "mtk_sync_3"} <= set(stages)


def test_mtk_sync_gives_up_within_the_attempt_budget():
    silent = ScriptedBrom(a0_plan=(b"",))
    engine = interceptor.UsbInterceptor(max_sync_attempts=7)
    result = interceptor.InterceptResult()
    started = time.perf_counter()
    try:
        engine.mtk_handshake_hammer(silent, Endpoints(), result)
    except BackendError as exc:
        assert exc.code == "2005"
        assert "7 attempt" in str(exc), f"the error must state the budget used, got: {exc}"
    else:  # pragma: no cover
        raise AssertionError("a silent boot ROM must raise, not return success")
    elapsed = time.perf_counter() - started
    assert silent.a0_writes == 7
    assert elapsed < 1.5, f"the zero-sleep hammer must not stall ({elapsed:.3f} s for 7 attempts)"


def test_mtk_wdt_disable_requires_an_acknowledged_zero_status():
    refused = ScriptedBrom(wdt_status=0x02000000)      # security refusal on both WDT writes
    res = interceptor.UsbInterceptor().intercept(timeout=0.5, injected_device=refused)
    assert res.ok is True                         # the sync itself locked
    assert res.wdt_disabled is False, (
        "claiming the watchdog is disabled when the write was refused would tell the user the "
        "phone is frozen in BROM when it is about to drop out"
    )
    assert "wdt_error" in res.telemetry
    assert any(e.stage == "wdt_disable_refused" for e in res.events)

    accepted = ScriptedBrom()
    res2 = interceptor.UsbInterceptor().intercept(timeout=0.5, injected_device=accepted)
    assert res2.wdt_disabled is True and res2.wdt_address == 0x10007000
    assert any(e.stage == "wdt_disable" for e in res2.events)


def test_mtk_probe_refuses_to_fabricate_a_chip_from_an_error_status():
    """A refused GET_HW_CODE must not turn into a random chip name to download firmware for."""
    refused = ScriptedBrom(hwcode=0xDEAD, hwcode_status=0x02000000)
    res = interceptor.UsbInterceptor().intercept(timeout=0.5, injected_device=refused)
    assert res.ok is True, "the handshake locked; only the identity read was refused"
    assert "hwcode_int" not in res.telemetry, "no chip identity may be invented from a refusal"
    assert "hwcode" not in res.telemetry
    assert "hwcode_refused" in res.telemetry
    assert any(e.stage == "mtk_hwcode_refused" for e in res.events)


def test_mtk_probe_reads_chip_identity_and_security_from_valid_responses():
    dev = ScriptedBrom(hwcode=0x0766, target_config=0x0007)   # SBC + SLA + DAA set
    res = interceptor.UsbInterceptor().intercept(timeout=0.5, injected_device=dev)
    assert res.ok is True
    assert res.telemetry["hwcode"] == "0x0766"
    assert res.telemetry["hwcode_int"] == 0x0766
    assert res.telemetry["chip"]
    assert res.telemetry["sbc_enabled"] and res.telemetry["sla_enabled"] and res.telemetry["daa_enabled"]


def test_sync_hammer_never_reads_usb_string_descriptors_on_the_hot_path():
    """String descriptors cost milliseconds the BROM window does not have."""
    dev = ScriptedBrom()
    result = interceptor.InterceptResult()
    interceptor.UsbInterceptor().mtk_handshake_hammer(dev, Endpoints(), result)
    assert dev.string_reads == 0, (
        "the sync hammer must use integer VID:PID data only; reading iManufacturer/iProduct "
        "before the lock loses the race against the boot timer"
    )
    assert len(result.sync_bytes) == 4


def test_serial_vcom_transport_runs_the_same_handshake():
    """Windows/COM-port path: MediaTek VCOM bound by the OS must still be capturable."""
    port = ScriptedSerialPort(a0_plan=(b"", b"\x5F"))
    adapter = usbfinder.SerialTransportAdapter(port, "/dev/ttyACM0", VID_MTK, 0x2000)
    res = interceptor.UsbInterceptor().intercept(timeout=1.0, injected_device=adapter)
    assert res.ok is True
    assert res.mode == usbmodes.MODE_MTK_PRELOADER
    assert [p["rx"] for p in res.sync_bytes] == ["0x5F", "0xF5", "0xAF", "0xFA"]
    assert port.baudrate == 115200, "the CDC line coding must be applied through the adapter"
    assert port.dtr is True and port.rts is True, "DTR/RTS must be asserted to wake the port"


# ---------------------------------------------------------------------------------------------
# Group C - forced BROM entry (Preloader -> BROM crash)
# ---------------------------------------------------------------------------------------------

def test_force_brom_recaptures_and_rehandshakes_the_new_brom_device():
    preloader = ScriptedBrom(pid=0x2000, hwcode=0x0766)
    brom = ScriptedBrom(pid=0x0003, hwcode=0x0766, serial_number="REBORN_BROM")
    engine = interceptor.UsbInterceptor(force_brom=True, disable_wdt=True)
    with patched(usbfinder, wait_for_device=lambda vid, pid, **kw: brom if (vid, pid) == (0x0E8D, 0x0003) else None):
        res = engine.intercept(timeout=1.0, injected_device=preloader)

    assert res.ok is True
    assert res.preloader_crashed_to_brom is True, "the crash payload must be recorded"
    assert res.brom_recaptured is True, "the re-caught BROM must be reported separately"
    assert res.mode == usbmodes.MODE_MTK_BROM
    assert res.usb_id == "0e8d:0003"
    assert res.forced_from_mode == usbmodes.MODE_MTK_PRELOADER
    assert res.device is brom, "the result must point at the new BROM handle, not the dead preloader"
    assert [p["rx"] for p in res.sync_bytes] == ["0x5F", "0xF5", "0xAF", "0xFA"]
    assert brom.a0_writes >= 1, "the re-caught BROM must be re-handshaken, not merely detected"
    assert res.telemetry.get("hwcode") == "0x0766"
    assert preloader.resets == 1
    assert any("re-caught 0e8d:0003" in act for act in res.escalation_actions)


def test_force_brom_without_a_reappearing_brom_is_not_reported_as_success():
    preloader = ScriptedBrom(pid=0x2000)
    engine = interceptor.UsbInterceptor(force_brom=True)
    with patched(usbfinder, wait_for_device=lambda *a, **kw: None):
        res = engine.intercept(timeout=0.5, injected_device=preloader)
    assert res.ok is False, (
        "the phone did not come back as BROM; reporting a locked BROM session would be a lie"
    )
    assert res.preloader_crashed_to_brom is True, "the attempt must still be visible in the trace"
    assert res.brom_recaptured is False
    assert res.device is None, "a dead preloader handle must not be handed to the caller"
    assert res.error and "BROM" in res.error and "0e8d:0003" in res.error
    assert any(e.stage == "force_brom_unconfirmed" for e in res.events)


def test_force_brom_sends_the_exact_crash_payload_and_swrst():
    preloader = ScriptedBrom(pid=0x2000, hwcode=0x0766)
    engine = interceptor.UsbInterceptor(force_brom=True, disable_wdt=False)
    with patched(usbfinder, wait_for_device=lambda *a, **kw: None):
        engine.intercept(timeout=0.5, injected_device=preloader)
    poisons = [w for _t, _e, w in preloader.writes if w.startswith(b"\xD0")]
    assert poisons == [b"\xD0\x00\x00\x00\x00"], "the DA state must be poisoned with a size of 0"
    writes = [w for _t, _e, w in preloader.writes if w.startswith(b"\xD7")]
    assert writes == [b"\xD7" + struct.pack(">II", 0x10007014, 4)], (
        "WDT_SWRST must be written at WDT_BASE + 0x14"
    )
    assert struct.pack(">I", 0x1209) in [w for _t, _e, w in preloader.writes], (
        "the software-reset magic 0x1209 must be sent"
    )
    assert preloader.resets == 1


def test_force_brom_is_attempted_once_per_intercept_run():
    """Hammering a dead preloader with crash payloads for the whole timeout helps nobody."""
    preloader = ScriptedBrom(pid=0x2000)
    engine = interceptor.UsbInterceptor(force_brom=True, force_entry=False, poll_interval=0.0)
    with patched(usbfinder, fast_find_devices=lambda **kw: [preloader],
                 find_serial_devices=lambda **kw: [], scan_usb_bounces=lambda: [],
                 wait_for_device=lambda *a, **kw: None):
        res = engine.intercept(timeout=0.3)
    assert res.ok is False
    assert preloader.resets == 1, f"expected exactly one crash/reset, got {preloader.resets}"
    assert len(preloader.writes_matching(b"\xD0")) == 1
    assert res.preloader_crashed_to_brom is True
    assert res.brom_recaptured is False


def test_device_already_in_brom_is_not_crashed_by_force_brom():
    brom = ScriptedBrom(pid=0x0003)
    engine = interceptor.UsbInterceptor(force_brom=True)
    res = engine.intercept(timeout=0.5, injected_device=brom)
    assert res.ok is True and res.mode == usbmodes.MODE_MTK_BROM
    assert res.brom_recaptured is False, "nothing was recaptured - it was already BROM"
    assert res.preloader_crashed_to_brom is False
    assert not brom.writes_matching(b"\xD0"), "no crash payload may be sent to a BROM device"
    assert brom.resets == 0
    assert res.telemetry.get("already_brom") is True


def test_backend_force_brom_reports_failure_when_brom_never_returns():
    preloader = ScriptedBrom(pid=0x2000)
    backend = MtkBromBackend(force_brom=True)
    backend.open(device=preloader)
    assert backend.info.mode == usbmodes.MODE_MTK_PRELOADER
    with patched(usbfinder, wait_for_device=lambda *a, **kw: None):
        assert backend.crash_preloader_to_brom() is False
    assert any("force_brom was requested" in note for note in backend.info.notes), (
        "the backend must tell the user BROM was never reached instead of silently continuing"
    )
    assert backend.info.mode == usbmodes.MODE_MTK_PRELOADER


def test_dossier_distinguishes_crash_sent_from_brom_recaptured():
    from fixtures import fresh

    preloader = ScriptedBrom(pid=0x2000)
    brom = ScriptedBrom(pid=0x0003, serial_number="REBORN_BROM")
    out_dir = fresh("brom-dossier")
    with patched(usbfinder, wait_for_device=lambda vid, pid, **kw: brom):
        payload = intercept_and_capture(backend_name="mtk", timeout=1.0, force_brom=True,
                                        out_dir=str(out_dir), injected_device=preloader)
    assert payload["ok"] is True
    assert payload["interception"]["brom_recaptured"] is True
    dossier_dir = Path(payload["dossier"]["dossier_dir"])
    checklist = (dossier_dir / "recovery_checklist.txt").read_text(encoding="utf-8")
    trace = (dossier_dir / "handshake_trace.txt").read_text(encoding="utf-8")
    assert "BROM (0e8d:0003) re-captured" in checklist, (
        "the checklist must say BROM was actually re-captured, not just that a crash was sent"
    )
    assert "BROM re-captured=True" in trace


def test_intercept_and_capture_does_not_claim_success_for_an_unconfirmed_brom_switch():
    preloader = ScriptedBrom(pid=0x2000)
    with patched(usbfinder, wait_for_device=lambda *a, **kw: None):
        payload = intercept_and_capture(backend_name="mtk", timeout=0.5, force_brom=True,
                                        out_dir=None, injected_device=preloader)
    assert payload["ok"] is False
    assert payload["error"], "the CLI/UI must get a reason, not an empty success"
    interception = payload["interception"]
    assert interception["preloader_crashed_to_brom"] is True
    assert interception["brom_recaptured"] is False
    assert "dossier" in payload


# ---------------------------------------------------------------------------------------------
# Group D - Qualcomm EDL handshake and forced EDL entry
# ---------------------------------------------------------------------------------------------

def test_sahara_dribbled_hello_is_reassembled_and_locked():
    """USB short reads are normal; a 48-byte HELLO arriving in 8-byte pieces must still lock."""
    edl = ScriptedSahara([sahara_hello_frame(version=2, min_version=1, max_packet=4096, mode=0)],
                         chunk=8)
    res = interceptor.UsbInterceptor().intercept(timeout=1.0, injected_device=edl)
    assert res.ok is True
    assert res.telemetry["sahara_version"] == 2
    assert res.telemetry["sahara_min_version"] == 1
    assert res.telemetry["sahara_max_packet"] == 4096
    assert res.telemetry["sahara_mode"] == 0
    assert res.telemetry.get("sahara_session_locked") is True
    responses = [w for _t, _e, w in edl.writes if w[:4] == struct.pack("<I", 0x02)]
    assert responses, "the session is not locked until HELLO_RESPONSE goes out"
    cmd, length = struct.unpack_from("<II", responses[0], 0)
    assert (cmd, length) == (0x02, 48)
    assert responses[0][8:24] == struct.pack("<IIII", 2, 1, 4096, 0)


def test_sahara_non_hello_first_packet_is_rejected():
    """A device mid-session (DONE/RESET on the wire) is not a captured handshake."""
    edl = ScriptedSahara([struct.pack("<II", 0x05, 8)])
    res = interceptor.UsbInterceptor().intercept(timeout=0.5, injected_device=edl)
    assert res.ok is False
    assert res.error and "DONE" in res.error
    assert not any(w[:4] == struct.pack("<I", 0x02) for _t, _e, w in edl.writes), (
        "no HELLO_RESPONSE may be sent to a device that did not send HELLO"
    )


def test_sahara_implausible_packet_lengths_are_rejected():
    for length in (4, 0x2000000):
        edl = ScriptedSahara([struct.pack("<II", 0x01, length)])
        res = interceptor.UsbInterceptor().intercept(timeout=0.3, injected_device=edl)
        assert res.ok is False, f"length {length} must not be accepted"
        assert "length" in (res.error or "").lower()


def test_sahara_truncated_payload_fails_cleanly():
    header = struct.pack("<II", 0x01, 48)
    edl = ScriptedSahara([header + b"\x00" * 12])          # promises 48, delivers 20
    engine = interceptor.UsbInterceptor(io_timeout=0.15)
    res = engine.intercept(timeout=0.5, injected_device=edl)
    assert res.ok is False
    assert "truncated" in (res.error or "").lower()
    assert any(e.stage.endswith("short_read") for e in res.events), (
        "the trace must record exactly how many bytes arrived"
    )


def test_sahara_session_is_not_reported_locked_if_hello_response_write_fails():
    edl = ScriptedSahara([sahara_hello_frame()])
    edl.fail_writes = True
    res = interceptor.UsbInterceptor().intercept(timeout=0.5, injected_device=edl)
    assert res.ok is False
    assert res.error and "HELLO_RESPONSE" in res.error
    assert not res.telemetry.get("sahara_session_locked")


def test_qualcomm_backend_sahara_reader_tolerates_short_reads_and_rejects_truncation():
    """The identify/loader path must reassemble packets the same way the interceptor does."""
    from revive.backends.qualcomm_edl import QualcommEdlBackend

    backend = QualcommEdlBackend(timeout=0.2)
    backend.endpoints = {"cmd_in": 0x81, "cmd_out": 0x01, "data_in": 0x81, "data_out": 0x01}
    backend.device = ScriptedSahara([sahara_hello_frame(version=2, min_version=1,
                                                        max_packet=1024, mode=0)], chunk=8)
    packet = backend.read_sahara_packet()
    assert packet["command"] == 0x01 and packet["length"] == 48
    assert len(packet["payload"]) == 40
    assert struct.unpack_from("<IIII", packet["payload"], 0) == (2, 1, 1024, 0)

    backend.device = ScriptedSahara([struct.pack("<II", 0x01, 48) + b"\x00" * 12])
    try:
        backend.read_sahara_packet()
    except BackendError as exc:
        assert "truncated" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("a packet that stops mid-flight must raise")

    backend.device = ScriptedSahara([struct.pack("<II", 0x01, 4)])
    try:
        backend.read_sahara_packet()
    except BackendError as exc:
        assert "length" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("length 4 cannot hold a Sahara header and must be rejected")


def test_fastboot_escalation_uses_oem_edl_commands_and_reports_the_okay():
    fb = ScriptedFastboot({
        "oem edl": b"FAILNot supported",
        "reboot-edl": b"OKAY",
        "oem enter-dload": b"OKAY",
        "oem reboot-edl": b"OKAY",
        "reboot": b"OKAY",
    })
    engine = interceptor.UsbInterceptor(force_entry=True, poll_interval=0.0)
    with patched(usbfinder, fast_find_devices=lambda **kw: [fb],
                 find_serial_devices=lambda **kw: [], scan_usb_bounces=lambda: [],
                 force_usb_reenumeration=lambda *a, **kw: []):
        engine.intercept(timeout=0.02)
    sent = [w for _t, _e, w in fb.writes]
    assert b"oem edl" in sent and b"reboot-edl" in sent
    assert sent.index(b"oem edl") < sent.index(b"reboot-edl"), "EDL commands are tried in order"


def test_fastboot_escalation_records_failure_when_nothing_is_accepted():
    fb = ScriptedFastboot({})                                # every command answers FAIL
    engine = interceptor.UsbInterceptor(force_entry=True, poll_interval=0.0)
    result = interceptor.InterceptResult()
    with patched(usbfinder, fast_open_device=lambda device, **kw: Endpoints()):
        engine._escalate_device_mode(usbmodes.MODE_FASTBOOT, fb, result)
    assert any("none of the EDL/reboot transition commands" in a for a in result.escalation_actions), (
        "a failed escalation must be recorded so the user is not told EDL was forced"
    )
    assert any(e.stage == "fastboot_escalate_failed" for e in result.events)


def test_qcdm_diag_switch_to_edl_frame_is_exact():
    diag = ScriptedDiag()
    engine = interceptor.UsbInterceptor()
    result = interceptor.InterceptResult()
    with patched(usbfinder, fast_open_device=lambda device, **kw: Endpoints()):
        engine._escalate_device_mode(usbmodes.MODE_QC_DIAG, diag, result)
    frames = [w for _t, _e, w in diag.writes]
    assert bytes.fromhex("4b650100540f7e") in frames, "the QCDM DIAG_SUBSYS switch frame must be sent"
    assert bytes.fromhex("3aa16e7e") in frames, "the legacy DLOAD frame must be sent as a fallback"
    assert any("QCDM" in a or "qcdm" in e.stage for a in result.escalation_actions
               for e in result.events)


def test_adb_escalation_issues_reboot_edl_for_a_booted_phone():
    calls: List[List[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout="device\n", stderr="")

    engine = interceptor.UsbInterceptor()
    result = interceptor.InterceptResult()
    with patched(interceptor.shutil, which=lambda name: "/usr/bin/adb" if name == "adb" else None), \
         patched(interceptor.subprocess, run=fake_run):
        engine._escalate_from_adb(result)
    assert calls and calls[0][1:] == ["get-state"]
    assert any(c[1:] == ["reboot", "edl"] for c in calls), "`adb reboot edl` must be issued"
    assert any("adb reboot edl" in a for a in result.escalation_actions)


# ---------------------------------------------------------------------------------------------
# Group E - cross-cutting invariants
# ---------------------------------------------------------------------------------------------

def test_intercept_result_is_json_safe_and_carries_the_new_honesty_fields():
    dev = ScriptedBrom()
    res = interceptor.UsbInterceptor().intercept(timeout=0.5, injected_device=dev)
    payload = res.to_dict()
    assert "brom_recaptured" in payload and "preloader_crashed_to_brom" in payload
    assert "device" not in payload, "a live USB handle must never leak into the JSON"
    encoded = json.dumps(payload)
    assert "0x5F" in encoded and "wdt_disabled" in encoded


def test_no_phantom_success_across_pathological_device_conditions():
    """Sweep every damaged-device scenario: ok=True must be impossible without a real lock."""
    scenarios = {
        "brom_answering_noise": ScriptedBrom(a0_plan=(b"\x42",)),
        "brom_silent": ScriptedBrom(a0_plan=(b"",)),
        "brom_wrong_second_byte": ScriptedBrom(sync_plan={0x0A: b"\x13"}),
        "edl_mid_session": ScriptedSahara([struct.pack("<II", 0x05, 8)]),
        "edl_empty_port": ScriptedSahara([]),
    }
    engine = interceptor.UsbInterceptor(max_sync_attempts=3, io_timeout=0.1)
    for name, device in scenarios.items():
        res = engine.intercept(timeout=0.4, injected_device=device)
        assert res.ok is False, f"{name}: phantom handshake capture"
        assert res.error, f"{name}: failure without an explanation"
        assert res.brom_recaptured is False
        assert res.to_dict()["ok"] is False
