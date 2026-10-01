"""Tests for the connection layer: the backend registry, capabilities, sub-ms interceptor,
force-entry escalation, and automatic handshake & scatter dossier folder generation.

No hardware is available in CI, so these tests check the parts that can be checked offline
and against simulated USB/serial device transports.
"""
from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path
from typing import List

from fixtures import demo_tree, patched
from revive import backends
from revive.backends import interceptor, usbfinder
from revive.core import usbmodes
from revive.firmware import rawprogram, scatter
from revive.ops import dossier
from revive.ui import api

CAPABILITY_KEYS = {"name", "label", "vendor", "modes", "read", "write", "erase", "partitions",
                   "tested", "protocol", "notes"}

# Every route the front end calls; the UI must keep working when this list changes.
UI_ROUTES = {
    "info", "chips", "modes", "errors", "errors.decode", "drivers", "detect", "identify",
    "intercept", "dossier.list",
    "inspect", "plan", "dump.analyse", "dump.extract", "dump.scan", "gpt.list", "gpt.repair",
    "convert", "super.list", "super.extract", "manifest.create", "manifest.verify",
    "sparse.verify", "demo.build",
}


class FakeMtkUsbDevice:
    """Simulates a transient MediaTek BROM/Preloader USB device that only answers after N hammers."""

    def __init__(self, vid: int = 0x0E8D, pid: int = 0x0003,
                 ignore_first_a0: int = 4, hwcode: int = 0x0707, target_config: int = 0x0005):
        self.idVendor = vid
        self.idProduct = pid
        self.bus = 1
        self.address = 12
        self.serial_number = "MTK_TEST_01"
        self.ignore_first_a0 = ignore_first_a0
        self.hwcode = hwcode
        self.target_config = target_config
        self.a0_seen = 0
        self.tx_log: List[bytes] = []
        self.rx_queue: List[bytes] = []
        self.ctrl_log: List[tuple] = []
        self.was_reset = False

    def is_kernel_driver_active(self, _intf: int) -> bool:
        return False

    def set_configuration(self) -> None:
        return None

    def get_active_configuration(self):
        return []

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data, timeout=None):
        self.ctrl_log.append((bmRequestType, bRequest, wValue, bytes(data) if isinstance(data, (bytes, bytearray)) else b""))
        return b""

    def write(self, ep: int, data: bytes, timeout: float = 1000) -> int:
        raw = bytes(data)
        self.tx_log.append(raw)
        if raw == b"\xA0":
            self.a0_seen += 1
            if self.a0_seen > self.ignore_first_a0:
                self.rx_queue.append(b"\x5F")
            else:
                self.rx_queue.append(b"")
        elif raw == b"\x0A":
            self.rx_queue.append(b"\xF5")
        elif raw == b"\x50":
            self.rx_queue.append(b"\xAF")
        elif raw == b"\x05":
            self.rx_queue.append(b"\xFA")
        elif raw == b"\xFC":
            # GET_HW_CODE response: 16 bytes with hwcode at [6:8] and status=0 at [8:12]
            resp = bytearray(16)
            struct.pack_into(">H", resp, 6, self.hwcode)
            struct.pack_into(">I", resp, 8, 0)
            self.rx_queue.append(bytes(resp))
        elif raw == b"\xD4":
            # GET_TARGET_CONFIG response: hwcode at [6:8], target_config at [8:10]
            resp = bytearray(16)
            struct.pack_into(">H", resp, 6, self.hwcode)
            struct.pack_into(">H", resp, 8, self.target_config)
            self.rx_queue.append(bytes(resp))
        elif raw.startswith(b"\xD7") and len(raw) == 9:
            # WRITE16 command header -> status OK
            self.rx_queue.append(b"\x00" * 16)
        elif len(raw) == 4:
            # 4-byte data payload for WDT disable / SWRST -> status OK
            self.rx_queue.append(b"\x00" * 16)
        elif raw.startswith(b"\xD0"):
            self.rx_queue.append(b"\x00" * 16)
        return len(raw)

    def read(self, ep: int, length: int, timeout: float = 1000) -> bytes:
        if self.rx_queue:
            return self.rx_queue.pop(0)
        return b""

    def reset(self) -> None:
        self.was_reset = True


class FakeQualcommEdlDevice:
    """Simulates a Qualcomm EDL 9008 device sending a Sahara HELLO packet."""

    def __init__(self):
        self.idVendor = 0x05C6
        self.idProduct = 0x9008
        self.bus = 2
        self.address = 7
        self.serial_number = "0014d0e1"
        self.tx_log: List[bytes] = []

    def get_active_configuration(self):
        return []

    def read(self, ep: int, length: int, timeout: float = 1000) -> bytes:
        # Sahara HELLO: cmd=1, len=48, version=2, min_ver=1, max_pkt=1024, mode=0
        return struct.pack("<IIIIII", 0x01, 48, 2, 1, 1024, 0) + b"\x00" * 24

    def write(self, ep: int, data: bytes, timeout: float = 1000) -> int:
        self.tx_log.append(bytes(data))
        return len(data)


def _caps_by_name() -> dict:
    return {cap["name"]: cap for cap in backends.describe_backends()}


def test_every_backend_advertises_capabilities():
    caps = backends.describe_backends()
    assert caps, "the registry must not be empty"
    for cap in caps:
        missing = CAPABILITY_KEYS - set(cap)
        assert not missing, f"{cap.get('name')} is missing {sorted(missing)}"
        assert isinstance(cap["modes"], list) and cap["modes"]
        assert isinstance(cap["notes"], list)


def test_unverified_backends_say_so():
    caps = _caps_by_name()
    assert "mock" in caps and caps["mock"]["tested"] is True
    for name in ("mtk", "qualcomm", "unisoc", "fastboot"):
        assert name in caps, f"{name} backend is missing from the registry"
        assert caps[name]["tested"] is False, f"{name} must not claim to be hardware-verified"
    warnings = backends.get_backend("mtk").guard_tested()
    assert warnings, "an untested backend must produce a warning"
    assert any("hardware" in w.lower() or "verified" in w.lower() for w in warnings)


def test_backend_labels_are_human_readable():
    for cap in backends.describe_backends():
        assert cap["label"] and cap["vendor"]
        assert cap["label"] != cap["name"]


def test_ui_route_table_is_complete():
    assert set(api.ROUTES) == UI_ROUTES, (set(UI_ROUTES) - set(api.ROUTES),
                                          set(api.ROUTES) - set(UI_ROUTES))
    assert api.MUTATING, "the UI needs to know which routes write to disk"
    assert api.MUTATING <= set(api.ROUTES)


def test_dispatch_returns_errors_instead_of_raising():
    result = api.dispatch("no.such.route", {})
    assert result["ok"] is False
    assert "no.such.route" in json.dumps(result)


def test_api_inspect_is_read_only():
    info = demo_tree()
    root = Path(info["firmware_mtk"]["root"])
    before = sorted((p.name, p.stat().st_size) for p in root.iterdir())
    result = api.dispatch("inspect", {"path": str(root)})
    assert result["ok"] is True
    assert result["kind"] == "mtk_spflash"
    assert any(item.get("detected") for item in result["images_detail"])
    after = sorted((p.name, p.stat().st_size) for p in root.iterdir())
    assert before == after, "inspect must not modify the package it looks at"


def test_api_plan_and_dump_json_contract():
    info = demo_tree()
    plan = api.dispatch("plan", {"path": info["firmware_broken"]["root"]})
    assert plan["ok"] is True
    assert plan["risk"] == "blocked"
    assert plan["entries"] and all("action" in e for e in plan["entries"])
    assert "RISK" in plan["rendered"] and "PARTITION" in plan["rendered"]
    dump = api.dispatch("dump.analyse", {"path": info["dump"]})
    assert dump["ok"] is True
    assert dump["partition_count"] == 6
    assert dump["gpt_offset"] == 0
    assert "unaccounted" in dump and dump["findings"]
    assert dump["partitions"][0]["offset_hex"].startswith("0x")


def test_api_identify_uses_the_mock_backend_offline():
    result = api.dispatch("identify", {"backend": "mock"}, {"demo_storage": None})
    assert result["ok"] is True
    assert result["device"] and result["capabilities"]
    assert result["warnings"] == [] or isinstance(result["warnings"], list)


def test_mtk_4byte_sync_hammer_and_wdt_disable():
    fake_dev = FakeMtkUsbDevice(vid=0x0E8D, pid=0x0003, ignore_first_a0=5, hwcode=0x0707)
    engine = interceptor.UsbInterceptor(disable_wdt=True)
    res = engine.intercept(timeout=1.0, injected_device=fake_dev)
    assert res.ok is True
    assert res.mode == usbmodes.MODE_MTK_BROM
    assert len(res.sync_bytes) == 4
    assert [p["rx"] for p in res.sync_bytes] == ["0x5F", "0xF5", "0xAF", "0xFA"]
    assert res.wdt_disabled is True
    assert res.wdt_address == 0x10007000
    assert res.telemetry.get("hwcode") == "0x0707"
    assert "MT6768" in res.telemetry.get("chip", "")


def test_mtk_preloader_force_brom_crash():
    """The crash payload must go out - but with no BROM re-catch, success must NOT be claimed."""
    fake_pl = FakeMtkUsbDevice(vid=0x0E8D, pid=0x2000, ignore_first_a0=1, hwcode=0x0766)
    engine = interceptor.UsbInterceptor(force_brom=True, disable_wdt=True)
    with patched(usbfinder, wait_for_device=lambda *a, **k: None):   # BROM never re-enumerates
        res = engine.intercept(timeout=0.5, injected_device=fake_pl)
    assert res.preloader_crashed_to_brom is True, "sending the crash payload must be recorded"
    assert res.brom_recaptured is False
    assert res.ok is False, "without a BROM re-catch this is not a locked BROM session"
    assert "BROM" in (res.error or "")
    assert fake_pl.was_reset is True
    assert any("WDT_SWRST" in act for act in res.escalation_actions)


def test_qualcomm_edl_sahara_instant_lock():
    fake_qc = FakeQualcommEdlDevice()
    engine = interceptor.UsbInterceptor()
    res = engine.intercept(timeout=1.0, injected_device=fake_qc)
    assert res.ok is True
    assert res.mode == usbmodes.MODE_QC_EDL
    assert res.telemetry.get("sahara_version") == 2
    assert fake_qc.tx_log, "interceptor must reply with SAHARA_HELLO_RESPONSE to lock session"
    cmd, length = struct.unpack_from("<II", fake_qc.tx_log[0], 0)
    assert cmd == 0x02 and length == 48


def test_handshake_dossier_folder_creates_valid_scatter_and_rawprogram():
    with tempfile.TemporaryDirectory() as tmp:
        fake_dev = FakeMtkUsbDevice(vid=0x0E8D, pid=0x0003, ignore_first_a0=2, hwcode=0x0707)
        captured = backends.intercept_and_capture(
            backend_name="mtk",
            out_dir=tmp,
            injected_device=fake_dev,
        )
        assert captured["ok"] is True
        dos = captured["dossier"]
        assert dos and dos["ok"] is True
        dossier_dir = Path(dos["dossier_dir"])
        assert dossier_dir.is_dir()

        # Verify all expected files exist inside the per-device folder and root
        scatter_path = Path(dos["scatter_file"])
        rawprogram_path = Path(dos["rawprogram_file"])
        assert scatter_path.exists() and scatter_path.name == "MT6768_Android_scatter.txt"
        assert rawprogram_path.exists()
        assert (dossier_dir / "device_details.json").exists()
        assert (dossier_dir / "handshake_log.json").exists()
        assert (dossier_dir / "handshake_trace.txt").exists()
        assert (dossier_dir / "security_and_chip.json").exists()
        assert (dossier_dir / "partitions_and_backup_plan.json").exists()
        assert (dossier_dir / "udev_and_driver_info.txt").exists()
        assert (dossier_dir / "recovery_checklist.txt").exists()
        assert (Path(tmp) / "index.json").exists()
        assert (Path(tmp) / "SUMMARY.txt").exists()

        # Verify the generated scatter parses cleanly with Revive's scatter parser
        parsed_scatter = scatter.parse_unvalidated(scatter_path)
        assert parsed_scatter.platform == "MT6768"
        assert len(parsed_scatter.partitions) >= 10

        # Verify the generated rawprogram0.xml parses cleanly with Revive's rawprogram parser
        entries = rawprogram.parse_program_file(rawprogram_path)
        assert len(entries) >= 10

        # Capture a second device (simulated demo) into the same folder and verify master index tracks both
        api_res = api.dispatch("intercept", {"demo": True, "out": tmp}, {"demo": True})
        assert api_res["ok"] is True
        listed = dossier.list_dossiers(tmp)
        assert listed["ok"] is True
        assert listed["device_count"] == 2
        assert len(listed["devices"]) == 2
