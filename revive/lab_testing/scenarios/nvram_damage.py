"""Scenario: NVRAM damage.

What it simulates
-----------------
The identity partitions are damaged. On MediaTek that is `nvram`/`proinfo`; on Qualcomm it is
`modemst1`/`modemst2`; on Unisoc it is `fixnv`/`prodnv`. These hold the IMEI, the Wi-Fi and
Bluetooth MAC addresses and the RF calibration. When they are lost the phone may still boot -
and then has no IMEI, no signal, and no Wi-Fi. It is the one repair that cannot be redone from
firmware, because the data was never in the firmware.

Why Revive treats this specially
--------------------------------
Revive names these partitions before any write and tells the user to back them up first, and it
refuses to implement IMEI *rewriting* (altering an IMEI is illegal in most countries). This
scenario therefore only ever damages the data and restores it from the device's own backup -
never invents a new identity.

Why Revive detects it
---------------------
The lab writes a recognisable NVRAM header with readable identity records, so the damage is a
real, checkable condition: the magic is gone, or the IMEI record no longer decodes. The signal
comes from parsing what is actually in the partition.
"""
from __future__ import annotations

import logging
import struct
from typing import Any, Dict, List, Optional, Sequence

from ..partitions import ST_DAMAGED, ST_OK, NVRAM_MAGIC
from . import Scenario, ScenarioError, zero_head

LOG = logging.getLogger("revive.lab.scenarios.nvram")

DEFAULT_BYTES = 512


def identity_partitions(device) -> List[str]:
    """The partitions that hold IMEI / MAC / calibration on this platform.

    Only partitions that actually carry an NVRAM block are listed: `nvdata` and `protect*` sit
    next to the identity data on a MediaTek phone but hold filesystems, and calling them
    "identity partitions" would make every healthy device look damaged.
    """
    out: List[str] = []
    for name in device.profile.identity_partitions:
        part = device.partition(name)
        if part is not None and (part.kind or "").lower() == "nvram":
            out.append(name)
    return out


def apply_nvram_damage(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    names = identity_partitions(device)
    if not names:
        raise ScenarioError(f"this device ({device.profile.platform}) has no identity partitions")
    only = options.get("partition")
    if only:
        names = [str(only)]
    length = int(options.get("bytes") or DEFAULT_BYTES)

    before = {name: read_identity(device, name) for name in names}
    damaged: List[str] = []
    for name in names:
        part = device.partition(name)
        if part is None or part.size <= 0:
            continue
        zero_head(device, part, min(length, part.size))
        part.mark(ST_DAMAGED, "identity data destroyed: IMEI and calibration are unreadable",
                  fault=SCENARIO_ID)
        damaged.append(name)
    if not damaged:
        raise ScenarioError("none of the identity partitions exist in this device's image")

    after = {name: read_identity(device, name) for name in damaged}
    fault = device.apply_fault(
        SCENARIO_ID, label=SCENARIO_LABEL,
        detail=f"{', '.join(damaged)}: the NVRAM header and identity records were erased",
        partition_names=damaged)
    device.save()
    return {
        "scenario": SCENARIO_ID, "partitions": damaged,
        "imei_before": (before.get(damaged[0]) or {}).get("imei", ""),
        "imei_after": (after.get(damaged[0]) or {}).get("imei", ""),
        "before": before, "after": after, "fault": fault.to_dict(),
        "symptom": "the phone may still boot, but with no IMEI ('invalid IMEI'), no network "
                   "registration, and no Wi-Fi MAC. This data is not in the firmware.",
        "warning": "Revive does not rewrite IMEIs: altering an IMEI is illegal in most "
                   "countries. The only correct repair is restoring this device's own backup.",
        "next": f"python -m revive.lab_testing test --scenario {SCENARIO_ID}",
    }


def expects_nvram_damage(options: Optional[Dict[str, Any]] = None) -> Sequence[str]:
    return ["nvram_invalid"]


def repair_nvram_damage(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Restore the device's own identity from the backup taken before the brick."""
    options = options or {}
    names = identity_partitions(device)
    restored: List[Dict[str, Any]] = []
    failed: List[str] = []
    for name in names:
        part = device.partition(name)
        if part is None or part.size <= 0:
            continue
        try:
            result = device.emmc.restore_golden(part)
        except Exception as exc:                                        # noqa: BLE001
            failed.append(f"{name}: {exc}")
            continue
        if result.get("ok"):
            part.status = ST_OK
            part.issues = []
            part.faults = [f for f in part.faults if f != SCENARIO_ID]
            part.checksum = result["sha256"]
            restored.append({"partition": name, "identity": read_identity(device, name)})
        else:
            failed.append(f"{name}: the golden copy did not verify")
    if restored and not failed:
        device.mark_repaired(SCENARIO_ID)
    device.save()
    return {
        "scenario": SCENARIO_ID, "restored": restored, "failed": failed,
        "repaired": bool(restored) and not failed,
        "imei_restored": (restored[0]["identity"].get("imei", "") if restored else ""),
        "note": "restored from the device's own backup taken before the brick - no identity was "
                "invented, because writing a new IMEI is not something this tool does",
    }


def verify_nvram_damage(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    names = identity_partitions(device)
    checks: List[Dict[str, Any]] = []
    for name in names:
        info = read_identity(device, name)
        checks.append({"partition": name, **info})
    ok = bool(checks) and all(c["valid"] for c in checks)
    imei_ok = any(c.get("imei") == device.imei for c in checks)
    return {
        "ok": ok and imei_ok, "partitions": checks,
        "expected_imei": device.imei,
        "imei_match": imei_ok,
        "detail": ("every identity partition holds a valid header and the original IMEI "
                   f"({device.imei})" if ok and imei_ok else
                   "identity data is still missing or does not match the device's own IMEI"),
    }


def read_identity(device, name: str) -> Dict[str, Any]:
    """Parse the lab NVRAM block in a partition: magic, record count and the IMEI."""
    part = device.partition(name)
    if part is None or part.size <= 0:
        return {"present": False, "valid": False, "reason": "partition is missing"}
    try:
        blob = device.emmc.read(part.offset, min(part.size, 16 * 1024))
    except Exception as exc:                                            # noqa: BLE001
        return {"present": True, "valid": False, "reason": f"unreadable: {exc}"}
    if blob[:len(NVRAM_MAGIC)] != NVRAM_MAGIC:
        return {"present": True, "valid": False, "imei": "",
                "reason": f"no NVRAM magic (the partition starts with {blob[:16].hex()})"}
    try:
        records = struct.unpack_from("<I", blob, 16)[0]
        version = struct.unpack_from("<I", blob, 20)[0]
    except struct.error:
        return {"present": True, "valid": False, "imei": "", "reason": "truncated header"}
    fields = {"imei": "", "serial": "", "wifi_mac": "", "bt_mac": ""}
    offset = 64
    while offset + 128 <= len(blob):
        try:
            lid, length = struct.unpack_from("<HH", blob, offset)
        except struct.error:
            break
        if not lid:
            break
        label = blob[offset + 4:offset + 40].split(b"\x00")[0].decode("ascii", "replace")
        value = blob[offset + 40:offset + 40 + max(0, min(length, 64))] \
            .split(b"\x00")[0].decode("ascii", "replace").strip()
        key = label.lower()
        if key in fields and value:
            fields[key] = value
        offset += 128
    valid = bool(fields["imei"]) and records > 0
    return {"present": True, "valid": valid, "records": records,
            "version": f"{version >> 8}.{version & 0xFF}", **fields,
            "reason": "" if valid else "the IMEI record is missing or unreadable"}


SCENARIO_ID = "nvram_damage"
SCENARIO_LABEL = "NVRAM damage"

SCENARIO = Scenario(
    id=SCENARIO_ID,
    label=SCENARIO_LABEL,
    description="Erase the identity partitions: IMEI, MAC addresses and RF calibration.",
    effect="IMEI / security partition failure: the phone may boot with an invalid IMEI, no "
           "network registration and no Wi-Fi - and this data is not in any firmware",
    severity="error",
    repairable=True,
    repair_summary="restore the device's own NVRAM backup. Revive never writes a new IMEI: "
                   "altering an IMEI is illegal in most countries",
    options=("partition=nvram|proinfo|modemst1|fixnv", "bytes=512"),
    apply=apply_nvram_damage,
    expects=expects_nvram_damage,
    repair=repair_nvram_damage,
    verify=verify_nvram_damage,
    tags=("nvram", "imei", "mac", "calibration", "identity", "modemst", "fixnv"),
)
