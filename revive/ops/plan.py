"""Dry-run flash planning.

This is the module that makes Revive different from the tools it replaces. Both SP Flash Tool
and Qualcomm's firehose execute a plan someone else wrote; Revive prints the plan first, in the
order it would happen, with the risk of every single write and a verdict at the top.

The plan is built from the package itself (scatter file or rawprogram XML), never from a guess.
When the package cannot be validated the plan is "blocked" and says why.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..firmware import detect as fw_detect
from ..firmware import rawprogram, scatter
from ..util import Finding, human_size

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "blocked": 3}

# Partitions whose loss turns a repairable phone into a broken one, and the reason.
BACKUP_FIRST = {
    "nvram": "IMEI + radio calibration",
    "nvdata": "radio/network settings",
    "nvcfg": "radio configuration",
    "persist": "sensor calibration, Wi-Fi/BT MAC",
    "proinfo": "product identity (serial, model)",
    "protect1": "DRM/security data",
    "protect2": "DRM/security data",
    "frp": "factory reset protection state",
    "seccfg": "bootloader lock state",
    "keystore": "device keys",
    "efuse": "one-time-programmable identity data",
    "md1img": "modem firmware",
    "preloader": "boot chain stage 1",
}

# Writes that are always worth a second look.
HIGH_RISK_TARGETS = {
    "preloader", "pgpt", "sgpt", "bootloader", "lk", "lk2", "uboot", "xbl", "abl",
    "seccfg", "efuse", "keystore",
}
MEDIUM_RISK_TARGETS = {
    "boot", "recovery", "vbmeta", "dtbo", "modem", "md1img", "persist", "nvram", "nvdata",
    "super", "system", "vendor",
}


@dataclass
class PlanEntry:
    name: str = ""
    action: str = "write"                 # write | erase | skip | inspect
    source: str = ""                      # file name (or "-" for erase)
    source_size: Optional[int] = None
    target_size: int = 0
    target_offset: int = 0
    region: str = "user"
    critical: bool = False
    notes: str = ""
    file_exists: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "action": self.action, "source": self.source or "-",
            "source_size": self.source_size, "target_size": self.target_size,
            "target_offset": self.target_offset, "region": self.region,
            "critical": self.critical, "notes": self.notes,
            "file_exists": self.file_exists,
            "source_human": human_size(self.source_size) if self.source_size else "",
            "target_human": human_size(self.target_size) if self.target_size else "",
        }


@dataclass
class FlashPlan:
    root: str
    kind: str = "unknown"
    entries: List[PlanEntry] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk: str = "unknown"
    risk_reasons: List[str] = field(default_factory=list)
    backup_targets: List[str] = field(default_factory=list)
    summary: str = ""
    steps: List[str] = field(default_factory=list)
    device_notes: List[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(e.source_size or e.target_size for e in self.entries if e.action == "write")

    @property
    def writes(self) -> List[PlanEntry]:
        return [e for e in self.entries if e.action == "write"]

    @property
    def ok_to_proceed(self) -> bool:
        return self.risk != "blocked"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root, "kind": self.kind, "risk": self.risk,
            "risk_reasons": self.risk_reasons, "ok_to_proceed": self.ok_to_proceed,
            "summary": self.summary, "steps": self.steps, "device_notes": self.device_notes,
            "total_bytes": self.total_bytes, "total_bytes_human": human_size(self.total_bytes),
            "entry_count": len(self.entries), "write_count": len(self.writes),
            "backup_targets": self.backup_targets,
            "entries": [e.to_dict() for e in self.entries],
            "findings": [f.to_dict() for f in self.findings],
        }


def _risk_for(name: str, operation: str) -> str:
    low = name.lower()
    if low in HIGH_RISK_TARGETS or operation.upper() in ("BOOTLOADERS", "PGPT", "SGPT"):
        return "high"
    if low in MEDIUM_RISK_TARGETS:
        return "medium"
    return "low"


def _bump(current: str, candidate: str) -> str:
    return candidate if RISK_ORDER[candidate] > RISK_ORDER[current] else current


def plan_from_scatter(scatter_path: os.PathLike, check_files: bool = True) -> FlashPlan:
    parsed = scatter.load(scatter_path, check_files=check_files)
    plan = FlashPlan(root=parsed.folder.as_posix(), kind="mtk_spflash")
    plan.findings.extend(parsed.findings)

    for part in parsed.partitions:
        if part.operation_type.upper() in ("FORMAT",) or (part.is_download and not part.file_name):
            action = "erase"
        elif not part.is_download:
            action = "skip"
        elif part.file_name and not part.file_exists:
            action = "skip"          # referenced image is missing: nothing can be written
        else:
            action = "write"
        entry = PlanEntry(
            name=part.name, action=action, source=part.file_name,
            source_size=part.file_size,
            target_size=part.partition_size, target_offset=part.physical_start_addr,
            region=part.region or "user", critical=False,
        )
        if part.file_size and part.partition_size and part.file_size > part.partition_size:
            entry.notes = "file is larger than the partition - blocked"
        elif part.file_size and part.partition_size and \
                part.file_size < part.partition_size * 0.95:
            entry.notes = "image is smaller than the partition (tail is left untouched)"
        entry.critical = part.operation_type.upper() in ("BOOTLOADERS", "PGPT", "SGPT") or \
            part.name.lower() in BACKUP_FIRST
        if entry.critical and part.name.lower() in BACKUP_FIRST:
            entry.notes = (entry.notes + "; " if entry.notes else "") + \
                f"holds {BACKUP_FIRST[part.name.lower()]}"
        plan.entries.append(entry)

    for entry in plan.entries:
        if entry.action != "write":
            continue
        level = _risk_for(entry.name, "")
        plan.risk = _bump(plan.risk if plan.risk != "unknown" else "low", level)
        if level == "high":
            plan.risk_reasons.append(
                f"{entry.name} is a boot-chain or identity partition")
        elif level == "medium":
            plan.risk_reasons.append(f"{entry.name} affects boot or radio behaviour")

    plan.backup_targets = sorted({e.name for e in plan.entries
                                  if e.action == "write" and e.name.lower() in BACKUP_FIRST})
    _finish(plan, parsed)
    return plan


def _finish(plan: FlashPlan, parsed: Optional[Any] = None) -> None:
    """Common risk/advice/summary logic shared by every package type."""
    if plan.risk == "unknown":
        plan.risk = "low"
    errors = [f for f in plan.findings if f.severity in ("error", "fatal")]
    if errors:
        plan.risk = "blocked"
        plan.risk_reasons = [f.title for f in errors[:4]] or plan.risk_reasons

    writes = plan.writes
    erases = [e for e in plan.entries if e.action == "erase"]
    if not writes and not erases:
        plan.risk = "blocked" if errors else plan.risk
        plan.summary = "Nothing in this package would be written."
    else:
        plan.summary = (f"{len(writes)} partition(s) written"
                        + (f", {len(erases)} erased" if erases else "")
                        + f" ({human_size(plan.total_bytes)})")
    if plan.risk_reasons:
        plan.risk_reasons = list(dict.fromkeys(plan.risk_reasons))[:6]

    plan.steps = [
        "1. Back up the partitions listed as 'back these up first' (nvram/persist/proinfo are the "
        "ones users regret losing).",
        "2. Confirm the phone is the model this package was built for - the scatter platform is "
        f"{getattr(parsed, 'platform', '') or 'unknown'}.",
        "3. Flash with the tool that matches the package (SP Flash Tool for a scatter package, "
        "an EDL tool for Qualcomm). Revive's own writing backends are labelled experimental "
        "until you have verified them on your hardware.",
        "4. After flashing, power on and check the IMEI and Wi-Fi. If they are gone, restore the "
        "nvram/persist backup you made in step 1.",
    ]
    if plan.backup_targets:
        plan.device_notes.append(
            "Back these up now if the phone still answers: " + ", ".join(plan.backup_targets))
    for entry in write_entries_with_risk(plan):
        plan.device_notes.append(f"{entry['name']}: {entry['risk']} risk - "
                                 f"{entry.get('note') or 'normal write'}")


def write_entries_with_risk(plan: FlashPlan) -> List[Dict[str, Any]]:
    out = []
    for entry in plan.writes:
        operation = ""
        if plan.kind.startswith("MediaTek"):
            operation = "BOOTLOADERS" if entry.name.lower() == "preloader" else ""
        out.append({"name": entry.name, "risk": _risk_for(entry.name, operation),
                    "note": entry.notes})
    return out


def plan_from_qualcomm(folder: os.PathLike) -> FlashPlan:
    package = rawprogram.load(folder)
    plan = FlashPlan(root=str(folder), kind="qualcomm_edl")
    plan.findings.extend(package.findings)
    for entry in package.entries:
        action = "erase" if entry.is_erase else "write"
        plan.entries.append(PlanEntry(
            name=entry.label or entry.filename or "unlabelled",
            action=action, source=entry.filename,
            source_size=(Path(folder) / entry.filename).stat().st_size
            if entry.filename and (Path(folder) / entry.filename).exists() else None,
            target_size=entry.size, target_offset=entry.start_byte,
            region=f"lun{entry.physical_partition}", critical=False,
            notes="erase only" if action == "erase" else "",
        ))
    for entry in plan.writes:
        level = _risk_for(entry.name, "")
        plan.risk = _bump(plan.risk if plan.risk != "unknown" else "low", level)
        if level != "low":
            plan.risk_reasons.append(f"{entry.name} affects boot or radio behaviour")
        if entry.name.lower() in BACKUP_FIRST:
            entry.critical = True
            entry.notes = (entry.notes + "; " if entry.notes else "") + \
                f"holds {BACKUP_FIRST[entry.name.lower()]}"
    for patch in package.patches:
        plan.entries.append(PlanEntry(
            name=patch.what or f"patch {patch.filename}", action="patch",
            source=patch.filename or "-", target_size=0,
            region="lun0", critical=False,
            notes=f"write {patch.value or '?'} at sector {patch.start_sector or '?'} "
                  f"offset {patch.byte_offset or '?'}",
        ))
    plan.backup_targets = sorted({e.name for e in plan.writes if e.name.lower() in BACKUP_FIRST})
    _finish(plan)
    return plan


def plan_for_path(path: os.PathLike) -> FlashPlan:
    """Build the right plan for whatever the user pointed at."""
    target = Path(path)
    package = fw_detect.detect(target)
    if package.kind in ("mtk_spflash", "mtk") and package.scatter:
        plan = plan_from_scatter(package.scatter)
        plan.device_notes.extend(getattr(package, "summary_lines", [])[:4])
        return plan
    if package.kind in ("qualcomm_edl", "qualcomm"):
        return plan_from_qualcomm(package.root)
    if package.kind in ("unisoc_pac", "unisoc"):
        plan = FlashPlan(root=package.root, kind="Unisoc PAC package")
        plan.risk = "blocked"
        plan.risk_reasons = ["Revive does not write Unisoc PAC images: the download-mode "
                             "protocol is not documented well enough to risk a write"]
        plan.findings.append(Finding(
            "warn", "Use the vendor tool to flash a PAC",
            "Revive can list and extract images from a PAC (read-only) but will not write one.",
            ["`revive pac-list <file.pac>` to see what is inside",
             "`revive pac-extract <file.pac> --name preloader` to pull an image out",
             "Flash the .pac with the Unisoc/Spreadtrum download tool"]))
        plan.summary = "Read-only package: nothing Revive will write."
        plan.steps = ["Extract the images you need, then use the vendor tool to flash them."]
        return plan

    plan = FlashPlan(root=package.root, kind=package.kind or "unknown")
    plan.findings.extend(package.findings)
    plan.risk = "blocked" if any(f.severity in ("error", "fatal") for f in package.findings) else "low"
    plan.summary = package.label or "No flashable package detected."
    plan.risk_reasons = [f.title for f in package.findings if f.severity in ("error", "fatal")][:4]
    plan.steps = [
        "Point Revive at a folder that contains a scatter file (MediaTek) or rawprogram XML "
        "(Qualcomm), or at a .pac file to inspect.",
        "`revive inspect <path>` explains what Revive found in this folder.",
    ]
    return plan


def render_text(plan: FlashPlan, max_entries: int = 60) -> str:
    lines: List[str] = []
    lines.append(f"Flash plan: {plan.kind}")
    lines.append(f"  package: {plan.root}")
    lines.append(f"  summary: {plan.summary}")
    lines.append(f"  RISK   : {plan.risk.upper()}")
    for reason in plan.risk_reasons:
        lines.append(f"    - {reason}")
    lines.append(f"  safe to proceed: {'yes' if plan.ok_to_proceed else 'NO'}")
    if plan.backup_targets:
        lines.append(f"  back up first: {', '.join(plan.backup_targets)}")
    lines.append("")
    lines.append(f"  {'PARTITION':<22} {'ACTION':<7} {'SOURCE':<34} {'SOURCE SIZE':>11} "
                 f"{'TARGET':>11}  NOTES")
    lines.append("  " + "-" * 118)
    for entry in plan.entries[:max_entries]:
        lines.append(
            f"  {entry.name[:22]:<22} {entry.action:<7} {entry.source[:34]:<34} "
            f"{(human_size(entry.source_size) if entry.source_size else '-'):>11} "
            f"{human_size(entry.target_size):>11}  {entry.notes[:36]}")
    if len(plan.entries) > max_entries:
        lines.append(f"  ... and {len(plan.entries) - max_entries} more")
    lines.append("")
    for finding in plan.findings:
        marker = {"ok": "OK  ", "info": "info", "warn": "WARN", "error": "FAIL",
                  "fatal": "STOP"}.get(finding.severity, "info")
        lines.append(f"  [{marker}] {finding.title}")
        if finding.detail:
            lines.append(f"          {finding.detail}")
        for fix in finding.fixes[:3]:
            lines.append(f"          -> {fix}")
    if plan.steps:
        lines.append("")
        lines.append("  Next steps:")
        for step in plan.steps:
            lines.append(f"    {step}")
    return "\n".join(lines)
