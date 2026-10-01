"""Scenario: userdata failure.

What it simulates
-----------------
The data partition's filesystem is no longer cleanly mounted. A phone that died mid-write - or
whose eMMC silently dropped a write - leaves the superblock saying "has errors" or "orphan
recovery needed". Android responds with a boot-loop into recovery, or a factory reset that
takes the user's photos with it.

Why Revive detects it
---------------------
`revive.storage.ext4fs` reads the superblock's state field, and `revive.ops.dump.analyse` turns
a non-clean state into a finding with the exact command to repair the *extracted copy*. This
scenario flips that state byte, so the finding comes from the real parser.

How it is repaired
------------------
Two honest options, and the lab exposes both:

* ``mode=fsck`` - restore the golden copy of the superblock, which is what repairing the
  filesystem with `e2fsck -fy` on an extracted image amounts to here.
* ``mode=format`` - rebuild a clean filesystem. This is the factory reset: it fixes the boot
  loop and destroys the data, which the report says out loud.
"""
from __future__ import annotations

import logging
import struct
from typing import Any, Dict, Optional, Sequence

from ..partitions import (ST_DIRTY, ST_OK, build_ext4_superblock,
                          build_f2fs_superblock)
from . import Scenario, ScenarioError, require_partition

LOG = logging.getLogger("revive.lab.scenarios.userdata")

DEFAULT_PARTITION = "userdata"
MODE_FSCK = "fsck"
MODE_FORMAT = "format"

# ext4 s_state values, as `revive.storage.ext4fs.FS_STATES` reads them.
STATE_CLEAN = 1
STATE_ERRORS = 2
STATE_ORPHAN = 4


def _target(device, options: Dict[str, Any]):
    name = str(options.get("partition") or DEFAULT_PARTITION)
    part = device.partition(name)
    if part is None or part.size <= 0:
        raise ScenarioError(f"this device has no usable {name!r} partition")
    return part


def _superblock_state(device, part) -> Optional[int]:
    """The ext4 s_state byte, read from where `revive.storage.ext4fs` reads it."""
    try:
        blob = device.emmc.read(part.offset + 1024, 1024)
    except Exception:                                                   # noqa: BLE001
        return None
    if len(blob) < 0x40:
        return None
    if struct.unpack_from("<H", blob, 0x38)[0] != 0xEF53:
        return None
    return struct.unpack_from("<H", blob, 0x3A)[0]


def apply_userdata_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    part = _target(device, options)
    state = int(options.get("state") or STATE_ERRORS)
    if part.kind not in ("ext4", "f2fs"):
        raise ScenarioError(f"{part.name} is {part.kind}, not a filesystem partition")
    before = _superblock_state(device, part)

    if part.kind == "ext4":
        blob = build_ext4_superblock(part.name, part.size, state=state)
    else:
        # F2FS has no dirty bit Revive reads, so the lab damages it the way a failed write
        # would: the superblock's block count stops matching the partition.
        blob = bytearray(build_f2fs_superblock(part.name, part.size))
        struct.pack_into("<Q", blob, 1024 + 40, 0xFFFFFFFFFFFFFFFF)
        blob = bytes(blob)
    device.emmc.write(part.offset, blob[:min(len(blob), part.size)])

    part.mark(ST_DIRTY, f"filesystem state: {'has errors' if state == STATE_ERRORS else 'orphan recovery needed'}",
              fault=SCENARIO_ID)
    fault = device.apply_fault(
        SCENARIO_ID, label=SCENARIO_LABEL,
        detail=f"{part.name}: the superblock reports the filesystem was not cleanly unmounted",
        partition_names=[part.name])
    device.save()
    return {
        "scenario": SCENARIO_ID, "partition": part.name, "kind": part.kind,
        "state_before": before, "state_after": _superblock_state(device, part),
        "fault": fault.to_dict(),
        "symptom": "Android boot-loops into recovery, or offers a factory reset. The data is "
                   "usually still there until somebody accepts that offer.",
        "next": f"python -m revive.lab_testing test --scenario {SCENARIO_ID}",
    }


def expects_userdata_failure(options: Optional[Dict[str, Any]] = None) -> Sequence[str]:
    return ["userdata_fs_dirty"]


def repair_userdata_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    part = _target(device, options)
    mode = str(options.get("mode") or MODE_FSCK).lower()
    if mode == MODE_FORMAT:
        blob = (build_ext4_superblock(part.name, part.size, state=STATE_CLEAN)
                if part.kind == "ext4" else build_f2fs_superblock(part.name, part.size))
        device.emmc.write(part.offset, blob[:min(len(blob), part.size)])
        note = ("the filesystem was rebuilt from scratch: the boot loop is gone and the user's "
                "data is gone with it. This is the factory reset.")
    else:
        restored = device.emmc.restore_golden(part)
        note = ("the clean superblock was restored - the equivalent of running "
                "`e2fsck -fy` on the extracted image and writing it back"
                if restored.get("ok") else
                "the golden copy did not verify; a format is the only option left")
    state = _superblock_state(device, part)
    ok = part.kind != "ext4" or state == STATE_CLEAN
    if ok:
        part.status = ST_OK
        part.issues = []
        part.faults = [f for f in part.faults if f != SCENARIO_ID]
        part.checksum = device.emmc.partition_checksum(part)
        device.mark_repaired(SCENARIO_ID)
    device.save()
    return {"scenario": SCENARIO_ID, "partition": part.name, "mode": mode,
            "state_after": state, "repaired": ok, "note": note}


def verify_userdata_failure(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from ...storage import ext4fs

    options = options or {}
    part = _target(device, options)
    state = _superblock_state(device, part)
    try:
        blob = device.emmc.read(part.offset, min(part.size, 4096))
        info = ext4fs.identify(blob)
    except Exception as exc:                                            # noqa: BLE001
        return {"ok": False, "partition": part.name, "detail": f"could not read: {exc}"}
    kind = info.kind if info else "unknown"
    fs_state = info.state if info else ""
    clean = (part.kind != "ext4") or (state == STATE_CLEAN and fs_state == "clean")
    boot = device.boot()
    ok = clean and not any("userdata" in w for w in boot.warnings)
    return {
        "ok": ok, "partition": part.name, "filesystem": kind,
        "state_byte": state, "filesystem_state": fs_state,
        "detail": (f"{part.name} is a clean {kind} filesystem"
                   if ok else f"{part.name} still reports {fs_state or 'damage'}"),
    }


SCENARIO_ID = "userdata_failure"
SCENARIO_LABEL = "Userdata failure"

SCENARIO = Scenario(
    id=SCENARIO_ID,
    label=SCENARIO_LABEL,
    description="Mark the data partition's filesystem as not cleanly unmounted.",
    effect="Android boot-loops into recovery or demands a factory reset; the user's data is at "
           "risk the moment anybody accepts that",
    severity="warn",
    repairable=True,
    repair_summary="repair the filesystem from a clean superblock (`e2fsck -fy` on the "
                   "extracted copy), or format it and lose the data",
    options=("partition=userdata", "mode=fsck|format", "state=2|4"),
    apply=apply_userdata_failure,
    expects=expects_userdata_failure,
    repair=repair_userdata_failure,
    verify=verify_userdata_failure,
    tags=("userdata", "ext4", "f2fs", "factory reset", "fsck"),
)
