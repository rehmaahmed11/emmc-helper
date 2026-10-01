"""MediaTek scatter file parsing and validation.

A scatter file *is* the flashing plan: every partition's name, offset, size and source file.
SP Flash Tool happily starts writing and then fails halfway when something in the folder does
not match the scatter. Revive parses the scatter first and reports the contradictions before
anything is written - which is the single most useful thing a flash tool can do.

Both the classic (v1.x) and the newer (v2/MT6768-era) scatter layouts are YAML-ish and parse
with the same state machine: a line starting a new block (``- partition_index:`` / ``- general:``)
followed by ``key: value`` lines.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..util import Finding, human_size

STORAGE_EMMC = "HW_STORAGE_EMMC"
STORAGE_UFS = "HW_STORAGE_UFS"
STORAGE_NAND = "HW_STORAGE_NAND"
STORAGE_NOR = "HW_STORAGE_NOR"

REGION_BOOT1 = "EMMC_BOOT_1"
REGION_BOOT2 = "EMMC_BOOT_2"
REGION_USER = "EMMC_USER"
REGION_UFS_LU0 = "UFS_LU0"

# operations that are risky enough to always be called out in a plan
HIGH_RISK_OPERATIONS = {
    "BOOTLOADERS": "This writes the boot chain. A wrong preloader on a locked device is the "
                   "classic way to turn a soft brick into a hard brick.",
    "PGPT": "This rewrites the partition table. If the offsets do not match your device's "
            "storage layout, the phone will not boot.",
    "SGPT": "This writes the backup partition table, which must come from the same layout as "
            "the primary one.",
}

PROTECTED_PARTITIONS = {
    "nvram", "nvdata", "nvcfg", "persist", "proinfo", "protect1", "protect2", "sec1",
    "keystore", "frp", "md1img", "md1dsp", "modem", "efuse", "seccfg", "oem_keystore",
}
PROTECTED_REASON = (
    "This partition holds this specific phone's identity or calibration data "
    "(IMEI, Wi-Fi/BT MAC, security state). Writing another device's copy breaks the radio, "
    "and writing it back is not always possible. Back it up first."
)


@dataclass
class ScatterPartition:
    index: int = 0
    name: str = ""
    file_name: str = ""
    is_download: bool = True
    type: str = ""
    linear_start_addr: int = 0
    physical_start_addr: int = 0
    partition_size: int = 0
    region: str = ""
    storage: str = ""
    boundary_check: bool = False
    is_reserved: bool = False
    operation_type: str = ""
    reserve: int = 0
    d_type: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    file_size: Optional[int] = None
    file_exists: bool = False

    @property
    def end_addr(self) -> int:
        return self.linear_start_addr + self.partition_size

    @property
    def wants_file(self) -> bool:
        """True when this entry asks for an image to be written."""
        return bool(self.is_download and self.file_name)

    @property
    def risk_note(self) -> str:
        if self.name.lower() in PROTECTED_PARTITIONS:
            return PROTECTED_REASON
        return HIGH_RISK_OPERATIONS.get(self.operation_type.upper(), "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index, "name": self.name, "file": self.file_name,
            "download": self.is_download, "type": self.type, "region": self.region,
            "storage": self.storage, "operation": self.operation_type,
            "start_addr": self.linear_start_addr, "physical_addr": self.physical_start_addr,
            "size": self.partition_size, "size_human": human_size(self.partition_size),
            "file_exists": self.file_exists, "file_size": self.file_size,
            "file_size_human": human_size(self.file_size) if self.file_size else "",
            "risk_note": self.risk_note,
        }


@dataclass
class ScatterFile:
    path: str
    version: str = ""
    platform: str = ""
    project: str = ""
    storage: str = ""
    block_size: int = 0x20000
    boot_channel: str = ""
    partitions: List[ScatterPartition] = field(default_factory=list)
    extra_general: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    raw_line_count: int = 0

    @property
    def folder(self) -> Path:
        return Path(self.path).parent

    @property
    def total_size(self) -> int:
        return sum(p.partition_size for p in self.partitions)

    @property
    def ok_to_flash(self) -> bool:
        return not any(f.severity in ("error", "fatal") for f in self.findings)

    def by_name(self, name: str) -> Optional[ScatterPartition]:
        low = name.lower()
        for part in self.partitions:
            if part.name.lower() == low:
                return part
        return None

    # "entries"/"find" are the names the planner and the docs use.
    @property
    def entries(self) -> List[ScatterPartition]:
        return self.partitions

    def find(self, name: str) -> Optional[ScatterPartition]:
        return self.by_name(name)

    @property
    def download_entries(self) -> List[ScatterPartition]:
        return [part for part in self.partitions if part.is_download]

    def total_download_size(self) -> int:
        total = 0
        for part in self.partitions:
            if not (part.is_download and part.file_name):
                continue
            try:
                total += (self.folder / part.file_name).stat().st_size
            except OSError:
                continue
        return total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "version": self.version, "platform": self.platform,
            "project": self.project, "storage": self.storage, "block_size": self.block_size,
            "boot_channel": self.boot_channel, "partition_count": len(self.partitions),
            "total_size": self.total_size, "total_size_human": human_size(self.total_size),
            "ok_to_flash": self.ok_to_flash,
            "partitions": [p.to_dict() for p in self.partitions],
            "findings": [f.to_dict() for f in self.findings],
        }


def _value(text: str) -> Any:
    text = text.strip().strip('"').strip("'")
    if not text:
        return ""
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return text
    if re.fullmatch(r"-?\d+", text):
        try:
            return int(text)
        except ValueError:
            return text
    return text


def parse(path: os.PathLike) -> ScatterFile:
    """Parse and validate a scatter file. Raises ValueError for a non-scatter file."""
    return validate(parse_unvalidated(path))


def parse_unvalidated(path: os.PathLike) -> ScatterFile:
    """Parse only - no cross-checks against the folder. Used by the planner."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    scatter = ScatterFile(path=str(p))

    current: Optional[ScatterPartition] = None
    in_general = False
    general_partition: Optional[ScatterPartition] = None

    for raw_line in text.splitlines():
        scatter.raw_line_count += 1
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
            if line.startswith("partition_index:"):
                value = _value(line.split(":", 1)[1])
                index = 0
                if isinstance(value, str):
                    match = re.search(r"(\d+)", value)
                    index = int(match.group(1)) if match else 0
                current = ScatterPartition(index=index)
                scatter.partitions.append(current)
                in_general = False
                continue
            if line.startswith("general:"):
                in_general = True
                current = None
                general_partition = ScatterPartition(name="general")
                continue
            # a bare "- key: value" line inside the general block
            if ":" in line and (in_general or current is not None):
                key, _, value = line.partition(":")
                _assign(scatter, current, general_partition, key.strip(), _value(value),
                        in_general)
                continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        _assign(scatter, current, general_partition, key.strip(), _value(value), in_general)

    if not scatter.partitions:
        raise ValueError(f"{p.name} does not look like a MediaTek scatter file "
                         "(no partition_index entries found)")
    return scatter


def _assign(scatter: ScatterFile, part: Optional[ScatterPartition],
            general: Optional[ScatterPartition], key: str, value: Any, in_general: bool) -> None:
    target = general if in_general else part
    if in_general and key in ("config_version", "platform", "project", "storage",
                              "boot_channel", "block_size"):
        if key == "config_version":
            scatter.version = str(value)
        elif key == "block_size":
            scatter.block_size = value if isinstance(value, int) else scatter.block_size
        else:
            setattr(scatter, key, value)
        return
    if target is None:
        return
    mapping = {
        "partition_name": "name", "file_name": "file_name", "is_download": "is_download",
        "type": "type", "linear_start_addr": "linear_start_addr",
        "physical_start_addr": "physical_start_addr", "partition_size": "partition_size",
        "region": "region", "storage": "storage", "boundary_check": "boundary_check",
        "is_reserved": "is_reserved", "operation_type": "operation_type", "reserve": "reserve",
        "d_type": "d_type",
    }
    attr = mapping.get(key)
    if attr is None:
        if in_general:
            scatter.extra_general[key] = value
        else:
            target.extra[key] = value
        return
    if in_general:
        scatter.extra_general[key] = value
    else:
        setattr(target, attr, value if value != "" else getattr(target, attr))


def validate(scatter: ScatterFile, check_files: bool = True) -> ScatterFile:
    """Cross-check the scatter against the folder it lives in. Appends findings."""
    findings = scatter.findings
    if not scatter.platform:
        findings.append(Finding("warn", "Scatter has no platform line",
                                "Without a platform this package cannot be matched to a chip.",
                                ["Re-download the firmware package: a missing platform usually "
                                 "means the file was edited or truncated"]))
    storage = (scatter.storage or "").upper()
    if storage and storage not in ("EMMC", "UFS", "NAND", "NOR", "SD"):
        findings.append(Finding("warn", f"Unusual storage type {scatter.storage!r}",
                                "Revive only knows how to reason about EMMC/UFS/NAND layouts.",
                                ["Check the scatter was not hand-edited"]))

    seen: Dict[str, ScatterPartition] = {}
    ranges: List[tuple] = []      # (start, end, name, region)
    missing_files: List[str] = []
    size_mismatch: List[str] = []
    too_big: List[str] = []

    for part in scatter.partitions:
        name = part.name.lower()
        if not part.name:
            findings.append(Finding("error", "A partition has no name",
                                    f"partition_index {part.index} is unusable.",
                                    ["Re-download the firmware"]))
            continue
        if name in seen:
            findings.append(Finding(
                "error", f"Duplicate partition {part.name}",
                f"Defined twice (index {seen[name].index} and {part.index}). Flashing a scatter "
                "with duplicates writes one copy over the other.",
                ["Re-download the firmware from the vendor or a trusted mirror"]))
        seen[name] = part

        if part.partition_size <= 0:
            findings.append(Finding("error", f"{part.name} has a zero size",
                                    "A zero-length partition cannot be flashed.",
                                    ["Re-download the firmware"]))
        if part.linear_start_addr % max(scatter.block_size, 1):
            findings.append(Finding(
                "warn", f"{part.name} starts at an unaligned address",
                f"0x{part.linear_start_addr:x} is not a multiple of the block size "
                f"0x{scatter.block_size:x}.",
                ["This is normal on some layouts, but an unaligned preloader or partition table "
                 "usually means the scatter was edited"]))

        if part.partition_size > 0:
            region = (part.region or scatter.storage or "EMMC_USER").upper()
            ranges.append((part.linear_start_addr, part.end_addr, part.name, region))
        if part.operation_type.upper() in ("PGPT", "SGPT") and not part.file_exists:
            pass  # checked below with the other files

        if check_files:
            file_name = part.file_name
            if part.is_download and not file_name:
                findings.append(Finding(
                    "warn", f"{part.name} is marked for download but has no file",
                    "SP Flash Tool treats this as 'erase this partition' when the operation is "
                    "FORMAT, and as an error otherwise.",
                    ["Decide explicitly whether you want this partition erased"]))
            if part.is_download and file_name:
                target = scatter.folder / file_name
                part.file_exists = target.exists()
                if not part.file_exists:
                    missing_files.append(file_name)
                else:
                    part.file_size = target.stat().st_size
                    if part.file_size > part.partition_size:
                        too_big.append(f"{part.name} ({human_size(part.file_size)} > "
                                       f"{human_size(part.partition_size)})")
                    elif part.file_size < part.partition_size and part.file_size > 0:
                        ratio = part.file_size / part.partition_size
                        if ratio < 0.95:
                            size_mismatch.append(
                                f"{part.name} ({human_size(part.file_size)} into "
                                f"{human_size(part.partition_size)})")

    # Overlap check inside one region only: EMMC_BOOT_1, EMMC_BOOT_2 and EMMC_USER are
    # separate address spaces, which is why a preloader and PGPT can both start at 0.
    for region in sorted({r[3] for r in ranges}):
        user = sorted((r for r in ranges if r[3] == region), key=lambda r: r[0])
        for (start_a, end_a, name_a, _r1), (start_b, _end_b, name_b, _r2) in zip(user, user[1:]):
            if start_b >= end_a:
                continue
            findings.append(Finding(
                "error", f"Overlapping partitions: {name_a} and {name_b}",
                f"{name_a} ends at 0x{end_a:x}, {name_b} starts at 0x{start_b:x} (region "
                f"{region}). Writing one will destroy the other, and the loss may not be noticed "
                "until boot time.",
                ["Do not flash this package", "Compare with a known-good scatter for the model"],
                code="plan_overlap"))

    if missing_files:
        findings.append(Finding(
            "error", f"{len(missing_files)} file(s) referenced by the scatter are missing",
            ", ".join(missing_files[:12]) + (" ..." if len(missing_files) > 12 else ""),
            ["Re-download the firmware package, or point Revive at the folder that contains the "
             "missing images",
             "Some vendor packages ship images as `.img` while the scatter expects `.bin` - "
             "rename only if the content is really identical (check the hash)"],
            code="firmware_missing_files"))
    if too_big:
        findings.append(Finding(
            "error", f"{len(too_big)} image(s) are larger than their partition",
            "; ".join(too_big[:6]) + (" ..." if len(too_big) > 6 else ""),
            ["This package does not belong to this scatter/layout",
             "Flashing would truncate the image - do not proceed"],
            code="plan_size_mismatch"))
    if size_mismatch:
        findings.append(Finding(
            "warn", f"{len(size_mismatch)} image(s) are smaller than their partition",
            "; ".join(size_mismatch[:6]) + (" ..." if len(size_mismatch) > 6 else ""),
            ["Usually harmless: the rest of the partition keeps its old content",
             "For preloader/boot images it can mean the image is truncated - compare sizes with "
             "a known-good copy"],
            code="plan_size_mismatch"))

    has_preloader = "preloader" in seen
    has_pgpt = any(p.operation_type.upper() == "PGPT" for p in scatter.partitions)
    if not has_preloader:
        findings.append(Finding(
            "warn", "No preloader partition in this scatter",
            "Without a preloader the phone will not be able to boot into download mode after a "
            "full erase.",
            ["Flash the preloader separately, or use SP Flash Tool's 'Download Only' with the "
             "full vendor package",
             "Keep a preloader for this exact model in your repair folder - it is the one image "
             "you cannot recover from the internet if the phone is already bricked"]))
    if not has_pgpt:
        findings.append(Finding(
            "info", "No partition table (PGPT/SGPT) entries in this scatter",
            "This is normal for packages that only update the system, and dangerous for a full "
            "restore of a phone with a wiped table.",
            ["If the partition table is gone, you need a package that includes PGPT and SGPT"]))

    protected = [p.name for p in scatter.partitions
                 if p.is_download and p.name.lower() in PROTECTED_PARTITIONS]
    if protected:
        findings.append(Finding(
            "warn", f"{len(protected)} partition(s) hold device identity/calibration data",
            ", ".join(protected[:10]),
            ["Back them up before flashing if the phone still communicates",
             "Only restore them from a backup of *this* phone - never from another device"]))

    if scatter.ok_to_flash and not any(f.severity == "ok" for f in findings):
        findings.append(Finding(
            "ok", "Scatter and folder are consistent",
            f"{len(scatter.partitions)} partitions, {human_size(scatter.total_size)} total, "
            f"every referenced file present and sized correctly.", []))
    return scatter


def find_scatter_files(folder: os.PathLike) -> List[str]:
    """Every scatter-looking file in a folder, best candidate first."""
    root = Path(folder)
    try:
        candidates = [p for p in root.iterdir() if p.is_file() and p.suffix.lower() == ".txt"
                      and "scatter" in p.name.lower()]
    except OSError:
        return []
    if not candidates:
        candidates = [p for p in root.iterdir()
                      if p.is_file() and p.name.upper().startswith("MT")]
    ranked = []
    for path in candidates:
        try:
            ranked.append((len(parse(path).partitions), str(path)))
        except (ValueError, OSError):
            continue
    ranked.sort(reverse=True)
    return [path for _count, path in ranked]


def summarise(scatter: ScatterFile) -> Dict[str, Any]:
    """One-screen verdict for a scatter: is it safe to flash, and what is missing."""
    blocking = [f for f in scatter.findings if f.severity in ("error", "fatal")]
    return {
        "path": scatter.path, "platform": scatter.platform, "project": scatter.project,
        "storage": scatter.storage, "partition_count": len(scatter.partitions),
        "ok_to_flash": not blocking,
        "blocking": [f.title for f in blocking],
        "warnings": [f.title for f in scatter.findings if f.severity == "warn"],
        "total_size": scatter.total_size, "total_download_size": scatter.total_download_size(),
        "download_count": len(scatter.download_entries),
        "missing_files": [p.file_name for p in scatter.partitions
                          if p.is_download and p.file_name and not p.file_exists],
    }


def find_scatter(folder: os.PathLike) -> Optional[str]:
    """Locate the scatter file in a firmware folder (there can be several; pick the best)."""
    root = Path(folder)
    candidates = [p for p in root.iterdir()
                  if p.is_file() and p.suffix.lower() == ".txt"
                  and "scatter" in p.name.lower()]
    if not candidates:
        candidates = [p for p in root.iterdir()
                      if p.is_file() and p.name.upper().startswith("MT")]
    if not candidates:
        return None
    # prefer the one that actually parses with the most partitions
    best, best_count = None, -1
    for path in candidates:
        try:
            parsed = parse(path)
        except (ValueError, OSError):
            continue
        if len(parsed.partitions) > best_count:
            best, best_count = str(path), len(parsed.partitions)
    return best


def load(path: os.PathLike, check_files: bool = True) -> ScatterFile:
    """Parse and validate. `check_files=False` skips touching the folder (for planning)."""
    if check_files:
        return parse(path)
    return parse_unvalidated(path)
