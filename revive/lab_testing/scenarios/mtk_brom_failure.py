"""Scenario: MediaTek BROM failure.

What it simulates
-----------------
The preloader is gone, so the SoC never gets past the Boot ROM. The phone is black and
unresponsive, but the Boot ROM is mask ROM inside the chip: it cannot be damaged, so the device
always enumerates as MediaTek BROM on USB `0e8d:0003` for roughly a second after power is
applied. "Dead phone that is still detectable" is the single most common MediaTek repair case,
and it is also the easiest one to miss, because the port disappears if you blink.

Why Revive detects it
---------------------
`revive.core.usbmodes` maps `0e8d:0003` to BROM and `revive.core.chips` turns the hardware code
the BROM reports into a SoC name with a confidence level. The signals here are the device's
reported mode plus the state of the preloader partition.

How it is repaired
------------------
The real path: catch the BROM handshake (it is a sub-millisecond window, which is why Revive
has an interceptor), disable the watchdog, send a Download Agent, then write the preloader.
The lab simulates the handshake and does the write through the actual `DeviceBackend`
interface.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from ..device import MODE_MTK_BROM, MODE_NORMAL, PLATFORM_MTK
from ..partitions import ST_DAMAGED, ST_OK
from . import Scenario, ScenarioError, zero_head

LOG = logging.getLogger("revive.lab.scenarios.mtk_brom")

USB_ID = "0e8d:0003"


def apply_brom_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    if not SCENARIO.applies_to(device.profile.platform):
        raise ScenarioError(
            f"BROM is a MediaTek download mode; this device is "
            f"{device.profile.platform} ({device.profile.chipset}). "
            f"Use qualcomm_edl_failure for a Qualcomm device.")

    boot_parts = [name for name in device.profile.bootloader_partitions
                  if device.partition(name) and device.partition(name).size > 0]
    if not boot_parts:
        raise ScenarioError("this device has no preloader partition to damage")
    target = str(options.get("partition") or boot_parts[0])
    part = device.partition(target)
    if part is None or part.size <= 0:
        raise ScenarioError(f"no usable {target!r} partition on this device")

    device.profile.boot_mode = MODE_MTK_BROM
    zero_head(device, part, min(int(options.get("bytes") or 16384), part.size))
    part.mark(ST_DAMAGED, "preloader erased - the SoC stays in the Boot ROM", fault=SCENARIO_ID)

    fault = device.apply_fault(
        SCENARIO_ID, label=SCENARIO_LABEL,
        detail=f"{part.name} is erased and the device now enumerates as BROM ({USB_ID})",
        partition_names=[part.name])
    device.save()
    return {
        "scenario": SCENARIO_ID, "partition": part.name, "boot_mode": MODE_MTK_BROM,
        "usb_id": USB_ID, "hwcode": device.profile.to_dict()["hwcode"], "fault": fault.to_dict(),
        "symptom": "black screen, no charging LED, no fastboot - but the port appears as "
                   f"{USB_ID} for about a second when power is applied.",
        "advice": [
            "BROM only waits about a second: `revive intercept --force` catches the handshake.",
            "Read the security state BEFORE flashing: `revive identify --backend mtk`. The "
            "SBC/SLA/DAA flags decide whether you need an auth file.",
            "Back up nvram/nvdata/proinfo first - that is the IMEI, and it is not in the "
            "firmware.",
        ],
        "next": f"python -m revive.lab_testing test --scenario {SCENARIO_ID}",
    }


def expects_brom_failure(options: Optional[Dict[str, Any]] = None) -> Sequence[str]:
    return ["device_in_brom", "preloader_damaged", "boot_fails"]


def repair_brom_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Catch the BROM handshake, load a DA, then write the boot chain back."""
    options = options or {}
    handshake = [
        {"stage": "sync", "detail": "BROM sync bytes exchanged (0xA0/0x5F, 0x0A/0xF5, "
                                   "0x50/0xAF, 0x05/0xFA)"},
        {"stage": "wdt_disable", "detail": "watchdog disabled so the chip does not reset "
                                          "mid-transfer"},
        {"stage": "hwcode", "detail": f"hardware code {device.profile.to_dict()['hwcode']} -> "
                                      f"{device.profile.chipset}"},
        {"stage": "download_agent", "detail": "Download Agent sent and running "
                                              f"({device.profile.to_dict()['hwcode']} DA mode)"},
    ]

    backend = device.backend()
    written: List[Dict[str, Any]] = []
    failures: List[str] = []
    try:
        backend.open()
        info = backend.identify()
        handshake.append({
            "stage": "identify",
            "detail": f"{info.vendor} / mode {info.mode} / hw "
                      f"{info.to_dict().get('hwcode') or 'n/a'} / "
                      f"security {info.security or '{}'}",
        })
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
                            "region": part.region, "sha256": readback,
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
        "scenario": SCENARIO_ID, "handshake": handshake, "written": written,
        "failures": failures, "repaired": bool(written) and not failures,
        "backend": backend.name, "backend_log": backend.log[-20:],
        "note": "the preloader write went through the real DeviceBackend interface, and the "
                "read-back checksum was compared against the value taken before the brick",
    }


def verify_brom_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from . import nvram_damage

    boot = device.boot()
    backend = device.backend()
    try:
        backend.open()
        info = backend.identify()
        partitions = backend.list_partitions()
    finally:
        backend.close()
    preloader = device.partition("preloader")
    preloader_ok = False
    if preloader is not None and preloader.size > 0:
        try:
            preloader_ok = device.emmc.read(preloader.offset, 9) == b"EMMC_BOOT"
        except Exception:                                               # noqa: BLE001
            preloader_ok = False
    identity = nvram_damage.read_identity(device, "nvram")
    ok = (boot.booted and device.profile.boot_mode == MODE_NORMAL and preloader_ok
          and len(partitions) > 0)
    return {
        "ok": ok, "boot": boot.to_dict(), "boot_mode": device.profile.boot_mode,
        "preloader_marker": preloader_ok, "partitions_visible": len(partitions),
        "chip": info.chip, "identity": identity,
        "detail": (f"the device left BROM, boots to Android, and the backend sees "
                   f"{len(partitions)} partitions"
                   if ok else f"still failing: {boot.reason or 'see the checks above'}"),
    }


SCENARIO_ID = "mtk_brom_failure"
SCENARIO_LABEL = "MTK BROM failure"

SCENARIO = Scenario(
    id=SCENARIO_ID,
    label=SCENARIO_LABEL,
    description="Erase the preloader so the SoC never leaves the Boot ROM.",
    effect="the device appears completely dead but is still detectable as MediaTek BROM "
           f"({USB_ID}) for about a second after power is applied",
    platforms=(PLATFORM_MTK,),
    severity="fatal",
    repairable=True,
    repair_summary="catch the BROM handshake, disable the watchdog, load a Download Agent, then "
                   "write the preloader back",
    options=("partition=preloader|lk", "bytes=16384"),
    apply=apply_brom_failure,
    expects=expects_brom_failure,
    repair=repair_brom_failure,
    verify=verify_brom_failure,
    tags=("mediatek", "mtk", "brom", "preloader", "download agent", "0e8d:0003"),
)
