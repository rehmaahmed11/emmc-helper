"""Scenario: boot corruption.

What it simulates
-----------------
The boot partition stops holding a bootable image. On a real phone this happens when an OTA or
a flash is interrupted while writing `boot`: the `ANDROID!` magic is overwritten, the header
sizes no longer add up, or the kernel is half-written. The phone powers on, the bootloader
runs, and then it hangs on the logo or boot-loops - the classic "hard brick that still enters
download mode".

Why Revive detects it
---------------------
`revive.storage.magic` recognises the `ANDROID!` header and `revive.storage.bootimg` parses it.
Erasing the head of the partition makes the magic disappear, so `revive.ops.dump.analyse`
probes the partition as blank instead of as a boot image, and the lab's own boot walk stops at
the kernel stage with the same reason a bootloader would.

How it is repaired
------------------
Re-flash `boot` from a known-good copy. The lab keeps a golden copy of every partition taken at
creation time, which is exactly the backup-first rule Revive applies to real devices.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Sequence

from ..partitions import ST_DAMAGED, ST_OK
from . import Scenario, require_partition, zero_head

LOG = logging.getLogger("revive.lab.scenarios.boot")

DEFAULT_PARTITION = "boot"
DEFAULT_BYTES = 8192


def _target(device, options: Dict[str, Any]):
    name = str(options.get("partition") or DEFAULT_PARTITION)
    part = device.partition(name)
    if part is None or part.size <= 0:
        # Fall back to whatever this platform boots from, so the scenario works everywhere.
        for candidate in device.profile.boot_partitions:
            part = device.partition(candidate)
            if part is not None and part.size > 0:
                break
    return require_partition(device, part.name if part else name)


def apply_boot_corruption(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    part = _target(device, options)
    length = min(int(options.get("bytes") or DEFAULT_BYTES), part.size)
    before = _boot_state(device, part)
    damage = zero_head(device, part, length)
    part.mark(ST_DAMAGED, "boot image header erased - the kernel cannot be located",
              fault=SCENARIO_ID)
    fault = device.apply_fault(SCENARIO_ID, label=SCENARIO_LABEL,
                               detail=f"{part.name}: the first {length} bytes were erased, "
                                      "so the Android boot header and its magic are gone",
                               partition_names=[part.name])
    device.save()
    return {
        "scenario": SCENARIO_ID, "partition": part.name, "damage": damage,
        "before": before, "after": _boot_state(device, part), "fault": fault.to_dict(),
        "symptom": "the phone powers on, the bootloader runs, then it hangs on the logo or "
                   "boot-loops. Download mode still answers.",
        "next": f"python -m revive.lab_testing test --scenario {SCENARIO_ID}",
    }


def expects_boot_corruption(options: Optional[Dict[str, Any]] = None) -> Sequence[str]:
    return ["boot_image_invalid", "boot_fails"]


def repair_boot_corruption(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    part = _target(device, options)
    restored = device.emmc.restore_golden(part)
    ok = bool(restored.get("ok"))
    if ok:
        part.status = ST_OK
        part.issues = []
        part.faults = [f for f in part.faults if f != SCENARIO_ID]
        part.checksum = restored["sha256"]
        device.mark_repaired(SCENARIO_ID)
    device.save()
    return {
        "scenario": SCENARIO_ID, "partition": part.name,
        # `restored` is a list of records, matching what nvram_damage returns, so reports can
        # render either scenario the same way.
        "restore": restored,
        "restored": ([{"partition": part.name, "bytes": restored.get("bytes"),
                       "sha256": restored.get("sha256"), "identity": {}}] if ok else []),
        "repaired": ok,
        "note": ("boot image re-flashed from the golden copy taken before the brick"
                 if ok else "the golden copy did not verify - do not trust this partition"),
    }


def verify_boot_corruption(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    part = _target(device, options)
    state = _boot_state(device, part)
    boot = device.boot()
    ok = state["parses"] and boot.booted
    return {
        "ok": ok, "partition": part.name, "boot_image": state,
        "boot": boot.to_dict(),
        "detail": (f"{part.name} holds a parseable boot image and the device boots to Android"
                   if ok else f"boot still fails: {state['detail'] or boot.reason}"),
    }


def _boot_state(device, part) -> Dict[str, Any]:
    """Ask Revive's own boot parser whether this partition still holds a boot image."""
    from ...storage import bootimg

    if part.size <= 0:
        return {"present": False, "magic": False, "parses": False, "detail": "no such partition"}
    try:
        head = device.emmc.read(part.offset, min(part.size, 16))
    except Exception as exc:                                            # noqa: BLE001
        return {"present": True, "magic": False, "parses": False,
                "detail": f"unreadable: {exc}"}
    has_magic = head[:8] == b"ANDROID!"
    detail = ""
    parses = False
    tmp = None
    if has_magic:
        try:
            tmp = device._slice(part)
            image = bootimg.parse(tmp)
            parses = True
            detail = f"boot image v{image.header_version}"
        except Exception as exc:                                        # noqa: BLE001
            detail = f"header does not parse: {exc}"
        finally:
            if tmp:
                import os

                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    else:
        detail = f"no ANDROID! magic (the partition starts with {head[:8].hex() or 'zeros'})"
    return {"present": True, "magic": has_magic, "parses": parses, "detail": detail,
            "sha256": device.emmc.partition_checksum(part)}


SCENARIO_ID = "boot_corruption"
SCENARIO_LABEL = "Boot corruption"

SCENARIO = Scenario(
    id=SCENARIO_ID,
    label=SCENARIO_LABEL,
    description="Erase the head of the boot partition so the kernel can no longer be found.",
    effect="Android boot failure: the bootloader runs and then hangs or boot-loops; the phone "
           "still answers in download mode",
    severity="error",
    repairable=True,
    repair_summary="re-flash boot from a known-good image (the lab restores its golden copy)",
    options=("partition=boot|recovery", "bytes=8192"),
    apply=apply_boot_corruption,
    expects=expects_boot_corruption,
    repair=repair_boot_corruption,
    verify=verify_boot_corruption,
    tags=("boot", "kernel", "bootloop", "android"),
)
