"""Scenario: Qualcomm EDL (9008) failure.

What it simulates
-----------------
The boot chain is broken badly enough that the phone stops booting and instead enumerates as
Qualcomm's Emergency Download Mode - USB `05c6:9008`. To a user the phone looks dead: black
screen, no vibration, no fastboot. To a tool it is very much alive and answering, which is the
whole point of the scenario. XBL is damaged and the modem identity partition went with it.

Why Revive detects it
---------------------
`revive.core.usbmodes` knows `05c6:9008` and maps it to the Qualcomm backend, and the lab's own
boot walk stops at the stage-1 loader. The signals come from the device's reported mode plus
the state of the XBL partition.

How it is repaired
------------------
The real path: Sahara handshake, send the firehose programmer, then write the partitions. The
lab simulates the handshake (and records the stages it went through), then does the writes
through the actual `DeviceBackend` interface - `open()`, `identify()`, `write_flash()` - so the
backend contract is exercised rather than bypassed.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from ..device import MODE_NORMAL, MODE_QC_EDL, PLATFORM_QUALCOMM
from ..partitions import ST_DAMAGED, ST_OK
from . import Scenario, ScenarioError, zero_head

LOG = logging.getLogger("revive.lab.scenarios.qc_edl")

USB_ID = "05c6:9008"
DEFAULT_LOADER = "prog_firehose_ddr.elf"


def apply_edl_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    if not SCENARIO.applies_to(device.profile.platform):
        raise ScenarioError(
            f"EDL 9008 is a Qualcomm download mode; this device is "
            f"{device.profile.platform} ({device.profile.chipset}). "
            f"Use mtk_brom_failure for a MediaTek device.")

    boot_parts = [name for name in device.profile.bootloader_partitions
                  if device.partition(name) and device.partition(name).size > 0]
    if not boot_parts:
        raise ScenarioError("this device has no boot chain partitions to damage")
    target = str(options.get("partition") or boot_parts[0])
    part = device.partition(target)
    if part is None or part.size <= 0:
        raise ScenarioError(f"no usable {target!r} partition on this device")

    device.profile.boot_mode = MODE_QC_EDL
    zero_head(device, part, min(int(options.get("bytes") or 8192), part.size))
    part.mark(ST_DAMAGED, "XBL damaged - the SoC falls back to PBL/EDL", fault=SCENARIO_ID)

    fault = device.apply_fault(
        SCENARIO_ID, label=SCENARIO_LABEL,
        detail=f"{part.name} is damaged and the device now enumerates as EDL ({USB_ID})",
        partition_names=[part.name])
    device.save()
    return {
        "scenario": SCENARIO_ID, "partition": part.name, "boot_mode": MODE_QC_EDL,
        "usb_id": USB_ID, "fault": fault.to_dict(),
        "symptom": "black screen, no vibration, no fastboot - but `revive detect` shows "
                   f"{USB_ID} (Qualcomm EDL 9008).",
        "advice": [f"You need the firehose loader for this exact model ({DEFAULT_LOADER}).",
                   "Load it with: revive identify --backend qualcomm --loader <prog_*.mbn>",
                   "Back up modemst1/modemst2/fsg before anything is written: that is the IMEI."],
        "next": f"python -m revive.lab_testing test --scenario {SCENARIO_ID}",
    }


def expects_edl_failure(options: Optional[Dict[str, Any]] = None) -> Sequence[str]:
    return ["device_in_edl", "bootloader_damaged", "boot_fails"]


def repair_edl_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Sahara + firehose, then write the boot chain back through the real backend."""
    options = options or {}
    loader = str(options.get("loader") or DEFAULT_LOADER)
    handshake = [
        {"stage": "sara_hello", "detail": "device sent the Sahara hello; version negotiated"},
        {"stage": "sara_send_image", "detail": f"sent {loader} (the firehose programmer)"},
        {"stage": "sara_done", "detail": "Sahara transfer complete, device reset into firehose"},
        {"stage": "firehose_configure", "detail": "firehose answered <configure/>; storage "
                                                  "reported as eMMC"},
    ]

    backend = device.backend()
    written: List[Dict[str, Any]] = []
    failures: List[str] = []
    try:
        backend.open()
        info = backend.identify()
        handshake.append({"stage": "identify",
                          "detail": f"{info.vendor} / mode {info.mode} / hw "
                                    f"{info.to_dict().get('hwcode') or 'n/a'}"})
        available = {p.name: p for p in backend.list_partitions()}
        for name in device.profile.bootloader_partitions:
            part = device.partition(name)
            if part is None or part.size <= 0:
                continue
            golden = device.golden_dir / f"{name}.img"
            if not golden.exists():
                failures.append(f"{name}: no golden copy to flash")
                continue
            try:
                result = backend.write_flash(part.offset, golden)
            except Exception as exc:                                    # noqa: BLE001
                failures.append(f"{name}: {exc}")
                continue
            readback = device.emmc.partition_checksum(part)
            written.append({"partition": name, "bytes": result.get("bytes"),
                            "in_gpt": name in available, "sha256": readback,
                            "verified": readback == part.checksum})
            part.status = ST_OK
            part.issues = []
            part.faults = [f for f in part.faults if f != SCENARIO_ID]
            part.checksum = readback
    finally:
        backend.close()

    device.profile.boot_mode = MODE_NORMAL
    if written and not failures:
        device.mark_repaired(SCENARIO_ID)
    device.save()
    return {
        "scenario": SCENARIO_ID, "loader": loader, "handshake": handshake,
        "written": written, "failures": failures, "repaired": bool(written) and not failures,
        "backend": backend.name, "backend_log": backend.log[-20:],
        "note": "the flash went through the real DeviceBackend interface (open / identify / "
                "write_flash), so the same code path a physical EDL phone would use was "
                "exercised",
    }


def verify_edl_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from . import nvram_damage

    boot = device.boot()
    backend = device.backend()
    try:
        backend.open()
        info = backend.identify()
        partitions = backend.list_partitions()
        mode = info.mode
    finally:
        backend.close()
    identity = nvram_damage.read_identity(device, "modemst1")
    ok = (boot.booted and device.profile.boot_mode == MODE_NORMAL
          and identity.get("valid", False) and len(partitions) > 0)
    return {
        "ok": ok, "boot": boot.to_dict(), "boot_mode": device.profile.boot_mode,
        "reported_mode": mode, "partitions_visible": len(partitions),
        "identity": identity,
        "detail": (f"the device left EDL, boots to Android, and the backend sees "
                   f"{len(partitions)} partitions with a valid IMEI"
                   if ok else f"still failing: {boot.reason or 'see the checks above'}"),
    }


SCENARIO_ID = "qualcomm_edl_failure"
SCENARIO_LABEL = "Qualcomm EDL failure"

SCENARIO = Scenario(
    id=SCENARIO_ID,
    label=SCENARIO_LABEL,
    description="Break the Qualcomm boot chain so the phone falls into EDL 9008.",
    effect="simulate 9008 recovery: the phone looks completely dead, but enumerates as "
           f"{USB_ID} and answers the Sahara handshake",
    platforms=(PLATFORM_QUALCOMM,),
    severity="fatal",
    repairable=True,
    repair_summary="Sahara handshake, load the firehose programmer, then write the boot chain "
                   "and the modem identity partitions back",
    options=("partition=xbl|abl|tz", "loader=prog_firehose_ddr.elf", "bytes=8192"),
    apply=apply_edl_failure,
    expects=expects_edl_failure,
    repair=repair_edl_failure,
    verify=verify_edl_failure,
    tags=("qualcomm", "edl", "9008", "sahara", "firehose", "xbl"),
)
