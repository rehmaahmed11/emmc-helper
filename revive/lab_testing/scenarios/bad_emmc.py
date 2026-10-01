"""Scenario: bad eMMC.

What it simulates
-----------------
Worn-out storage. The chip still answers, still accepts writes - and no longer holds them. On
the registers this shows up as PRE_EOL_INFO moving from 0x01 (normal) to 0x02 (warning) and
then 0x03 (urgent), with DEVICE_LIFE_TIME_EST_TYP_A/B climbing to 0x0B ("exceeded the rated
life"), plus bad blocks scattered through the user area.

Why this scenario matters most
------------------------------
It is the fault that makes a repair tool dangerous. A flash to a dying chip reports success,
the phone boots once, and then the data is gone. So the damage here is not cosmetic:
`VirtualEMMC.write` really does corrupt writes while PRE_EOL is urgent, and a read that lands
on a bad block really does fail.

Why Revive detects it
---------------------
`revive.storage.emmc.assess` reads PRE_EOL and the life-time bytes and returns a fatal verdict
with the "dump everything now, then replace the chip" advice. The lab feeds it registers it
generated itself and expects that verdict back.

How it is repaired
------------------
Not in software, and the scenario says so. The only fix is a new chip, so the repair replaces
the virtual eMMC and writes every partition back from the golden copies - a blank chip arrives
blank, exactly like the real part on the bench.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from .. import extcsd_virtual as regs
from ..extcsd_virtual import DEAD, WARNING
from ..partitions import ST_DAMAGED, ST_OK
from . import Scenario

LOG = logging.getLogger("revive.lab.scenarios.bad_emmc")

DEFAULT_HEALTH = DEAD
DEFAULT_BAD_BLOCKS = 12


def apply_bad_emmc(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    health = str(options.get("health") or DEFAULT_HEALTH).lower()
    if health not in regs.HEALTH_STATES:
        raise ValueError(f"unknown health {health!r}; expected one of "
                         f"{', '.join(regs.HEALTH_STATES)}")
    count = int(options.get("bad_blocks", DEFAULT_BAD_BLOCKS))
    before = device.emmc.health()

    device.emmc.set_health(health)
    blocks: List[Dict[str, Any]] = []
    if count > 0:
        blocks = device.emmc.add_random_bad_blocks(count)
    # A worn chip also reports more program cycles than a healthy one.
    device.emmc.spec.write_cycles = 2900 if health == DEAD else 2200 if health == WARNING else 1200

    after = device.emmc.health()
    damaged = _mark_unstable(device)
    fault = device.apply_fault(
        SCENARIO_ID, label=SCENARIO_LABEL,
        detail=f"PRE_EOL {after['pre_eol']} ({after['pre_eol_text']}), {after['life_a_text']}, "
               f"{len(device.emmc.bad_blocks)} bad block(s)",
        partition_names=damaged)
    device.save()
    return {
        "scenario": SCENARIO_ID, "health": health, "before": _short(before),
        "after": _short(after), "bad_blocks": len(blocks),
        "bad_block_sample": blocks[:5], "fault": fault.to_dict(),
        "write_behaviour": ("writes are accepted and then corrupted - this is the failure that "
                            "makes a reflash look like it worked"
                            if device.emmc.spec.pre_eol_value >= 0x03 else
                            "writes still hold, but the chip is near its rated life"),
        "next": f"python -m revive.lab_testing test --scenario {SCENARIO_ID}",
    }


def _mark_unstable(device) -> List[str]:
    """Flag the partitions that sit on the blocks the chip has given up on."""
    damaged: List[str] = []
    for part in device.partitions:
        if part.size <= 0:
            continue
        if device.emmc.is_bad(part.offset) or device.emmc.is_bad(part.offset + part.size // 2):
            part.mark(ST_DAMAGED, "a bad block was reported inside this partition",
                      fault=SCENARIO_ID)
            damaged.append(part.name)
    return damaged


def expects_bad_emmc(options: Optional[Dict[str, Any]] = None) -> Sequence[str]:
    options = options or {}
    health = str(options.get("health") or DEFAULT_HEALTH).lower()
    signals = ["emmc_health_fatal", "emmc_pre_eol_urgent"]
    if health == WARNING:
        signals = ["emmc_health_warn", "emmc_pre_eol_warning"]
    if int(options.get("bad_blocks", DEFAULT_BAD_BLOCKS)) > 0:
        signals = signals + ["emmc_bad_blocks", "emmc_life_exceeded"]
    return signals


def repair_bad_emmc(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Replace the chip. There is no software repair for worn-out NAND, and this says so."""
    options = options or {}
    verdict = device.emmc.assess().get("verdict", "ok")
    replacement = device.replace_storage()
    for part in device.partitions:
        part.status = ST_OK
        part.issues = []
        part.faults = []
    device.mark_repaired(SCENARIO_ID)
    device.save()
    return {
        "scenario": SCENARIO_ID, "repaired": True, "method": "eMMC replacement (simulated)",
        "software_repair_possible": False,
        "old_chip": replacement["old_chip"], "new_chip": _short(replacement["new_chip"]),
        "restored_partitions": replacement["restored_partitions"],
        "diagnosis_before_repair": verdict,
        "note": "No software repair exists for a worn-out chip: the flash would appear to "
                "succeed and then lose data. The lab replaced the virtual eMMC and rewrote "
                "every partition from the golden copies taken before the brick.",
    }


def verify_bad_emmc(device, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    health = device.emmc.health()
    assessment = device.emmc.assess()
    # Prove the storage behaves the way the registers claim: a healthy chip must hold a write.
    probe = device.partition("userdata") or next(
        (p for p in device.partitions if p.size > 0), None)
    write_ok, write_detail = False, "no partition available to test"
    if probe is not None:
        marker = b"REVIVE-LAB-WRITE-TEST" + bytes(64)
        offset = probe.offset + 512
        try:
            device.emmc.write(offset, marker)
            write_ok = device.emmc.read(offset, len(marker)) == marker
            write_detail = ("a test write was read back intact" if write_ok else
                            "a test write did NOT read back intact - the chip is still failing")
        except Exception as exc:                                        # noqa: BLE001
            write_detail = f"the test write failed: {exc}"
    boot = device.boot()
    ok = (assessment.get("verdict") == "ok" and health["state"] == "healthy"
          and not device.emmc.bad_blocks and write_ok and boot.booted)
    return {
        "ok": ok, "health": _short(health), "verdict": assessment.get("verdict"),
        "bad_blocks": len(device.emmc.bad_blocks), "write_test": write_detail,
        "boot": boot.to_dict(),
        "detail": ("the replacement chip is healthy, holds a write, and the device boots"
                   if ok else f"storage still reports {health['state']}: {write_detail}"),
    }


def _short(health: Dict[str, Any]) -> Dict[str, Any]:
    return {key: health.get(key) for key in
            ("state", "pre_eol", "pre_eol_text", "life_a_text", "life_b_text", "verdict",
             "used_percent_estimate", "write_cycles", "bad_blocks", "capacity_human")}


SCENARIO_ID = "bad_emmc"
SCENARIO_LABEL = "Bad eMMC"

SCENARIO = Scenario(
    id=SCENARIO_ID,
    label=SCENARIO_LABEL,
    description="Age the storage: PRE_EOL, life-time estimates and bad blocks.",
    effect="EXT_CSD health warning / end-of-life: writes are accepted and then lost, reads hit "
           "bad blocks, and a reflash that 'succeeds' destroys the data",
    severity="fatal",
    repairable=True,
    repair_summary="there is no software repair - replace the chip and rewrite every partition "
                   "from the backups taken before the brick",
    options=("health=healthy|warning|dead", "bad_blocks=12"),
    apply=apply_bad_emmc,
    expects=expects_bad_emmc,
    repair=repair_bad_emmc,
    verify=verify_bad_emmc,
    tags=("emmc", "storage", "pre_eol", "wear", "bad blocks", "health"),
)
