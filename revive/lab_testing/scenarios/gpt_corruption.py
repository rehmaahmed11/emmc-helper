"""Scenario: GPT corruption.

What it simulates
-----------------
A write to the partition table that was interrupted - a flat battery, a pulled cable, a phone
that reset mid-flash. The result on a real phone is a header whose CRC no longer matches, an
entry array with a flipped byte, or a primary table that is simply gone while the backup copy
at the end of the eMMC is still fine.

Why Revive detects it
---------------------
`revive.storage.gpt.read_gpt` recomputes both CRCs and falls back to the backup table, and
`revive.ops.dump.analyse` turns that into a finding. This scenario damages the table with
`gpt_virtual` and then expects exactly the signals that reader produces.

How it is repaired
------------------
`revive gpt-repair`: recompute the CRCs and rewrite both copies. When the primary header is
gone entirely the tool cannot find a table to repair, and the fallback - rebuild the primary
from the backup - is what a technician does with the vendor tool, so the lab does the same.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .. import gpt_virtual
from ..partitions import ST_DAMAGED, ST_OK
from . import Scenario, ScenarioError, require_partition

DEFAULT_MODE = gpt_virtual.MODE_CRC

_MODE_TEXT = {
    gpt_virtual.MODE_CRC: "invalid header and entry CRCs (the classic interrupted write)",
    gpt_virtual.MODE_MISSING: "the primary table is erased; only the backup copy survives",
    gpt_virtual.MODE_TOTAL: "both table copies are erased: nothing to recover from",
}


def _table_partition(device):
    """The partition that carries the table, or the first partition if there is no pgpt."""
    part = device.partition("pgpt") or device.partition("gpt")
    if part is None:
        parts = [p for p in device.partitions if p.size > 0]
        if not parts:
            raise ScenarioError("this device has no partitions in its image")
        part = parts[0]
    return part


def apply_gpt_corruption(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    mode = str(options.get("mode") or DEFAULT_MODE).lower()
    if mode not in gpt_virtual.GPT_MODES:
        raise ScenarioError(f"unknown GPT damage mode {mode!r}; expected one of "
                            f"{', '.join(gpt_virtual.GPT_MODES)}")
    part = _table_partition(device)
    before = gpt_virtual.read(device.image_path, device.emmc.sector_size).to_dict()
    damage = gpt_virtual.damage(device.image_path, mode)
    part.mark(ST_DAMAGED, f"partition table damaged ({mode})", fault=SCENARIO_ID)
    fault = device.apply_fault(
        SCENARIO_ID, label=SCENARIO_LABEL,
        detail=_MODE_TEXT[mode], partition_names=[part.name])
    device.save()
    return {
        "scenario": SCENARIO_ID, "mode": mode, "mode_text": _MODE_TEXT[mode],
        "partition": part.name, "before": before, "damage": damage,
        "fault": fault.to_dict(),
        "next": f"python -m revive.lab_testing test --scenario {SCENARIO_ID}",
    }


def expects_gpt_corruption(options: Optional[Dict[str, Any]] = None) -> Sequence[str]:
    options = options or {}
    mode = str(options.get("mode") or DEFAULT_MODE).lower()
    if mode == gpt_virtual.MODE_TOTAL:
        return ["gpt_missing", "boot_fails"]
    if mode == gpt_virtual.MODE_MISSING:
        return ["gpt_primary_damaged"]
    return ["gpt_header_crc_bad", "gpt_entries_crc_bad", "gpt_primary_damaged"]


def repair_gpt_corruption(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    part = _table_partition(device)
    report = gpt_virtual.repair(device.image_path, apply=True,
                                sector_size=device.emmc.sector_size,
                                layout=device.partitions)
    after = report.get("after", {})
    if after.get("readable") and not (after.get("signals") or []):
        part.status = ST_OK
        part.issues = []
        part.faults = [f for f in part.faults if f != SCENARIO_ID]
        part.checksum = device.emmc.partition_checksum(part)
        device.mark_repaired(SCENARIO_ID)
    device.save()
    return {
        "scenario": SCENARIO_ID, "method": report.get("method", ""),
        "changes": report.get("changes", []), "before": report.get("before", {}),
        "after": after, "repaired": bool(after.get("readable")),
        "note": ("CRCs recomputed and both table copies rewritten"
                 if report.get("method") == "revive.gpt.repair_gpt" else
                 "the primary table was rebuilt from the backup copy"),
    }


def verify_gpt_corruption(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    # LBA-0 entries (pgpt) are excluded by Revive's reader on purpose; see device.verify().
    names: List[str] = [p.name for p in device.partitions
                        if p.size > 0 and p.first_lba > 0]
    return gpt_virtual.verify(device.image_path, names, device.emmc.sector_size)


SCENARIO_ID = "gpt_corruption"
SCENARIO_LABEL = "GPT corruption"

SCENARIO = Scenario(
    id=SCENARIO_ID,
    label=SCENARIO_LABEL,
    description="Damage the GUID partition table the way an interrupted write does.",
    effect="invalid CRC / missing partition table: the bootloader cannot find any partition, "
           "so the phone is dead but the storage is still readable in download mode",
    severity="fatal",
    repairable=True,
    repair_summary="recompute the CRCs and rewrite both table copies (`revive gpt-repair`), "
                   "or rebuild the primary table from the backup copy",
    options=("mode=crc|missing|total",),
    apply=apply_gpt_corruption,
    expects=expects_gpt_corruption,
    repair=repair_gpt_corruption,
    verify=verify_gpt_corruption,
    tags=("gpt", "partition table", "crc", "pgpt"),
)
