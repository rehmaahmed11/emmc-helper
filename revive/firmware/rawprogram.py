"""Qualcomm ``rawprogram*.xml`` / ``patch*.xml`` parsing and validation.

Qualcomm packages do not have a scatter file; the flashing plan lives in XML that firehose
executes literally. That makes a missing image or a wrong sector count a silent half-flash, so
Revive reads the XML, checks every referenced file, and converts sector numbers into byte
offsets that a human can sanity-check against the phone's actual capacity.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..util import Finding, human_size


@dataclass
class ProgramEntry:
    label: str = ""
    filename: str = ""
    start_sector: int = 0
    num_sectors: int = 0
    physical_partition: int = 0
    sector_size: int = 512
    sparse: bool = False
    file_sector_offset: int = 0
    part_of_single_image: bool = False
    readback_verify: Optional[bool] = None
    source: str = ""

    @property
    def start_byte(self) -> int:
        return self.start_sector * self.sector_size

    @property
    def size(self) -> int:
        return self.num_sectors * self.sector_size

    @property
    def is_erase(self) -> bool:
        return not self.filename

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label, "file": self.filename, "source": self.source,
            "physical_partition": self.physical_partition,
            "start_sector": self.start_sector, "sectors": self.num_sectors,
            "start_byte": self.start_byte, "size": self.size, "size_human": human_size(self.size),
            "sparse": self.sparse, "erase": self.is_erase,
        }


@dataclass
class PatchEntry:
    """One <patch .../> instruction: a value firehose writes into an image, not a raw file."""
    filename: str = ""
    start_sector: str = ""
    byte_offset: str = ""
    size_in_bytes: str = ""
    value: str = ""
    what: str = ""
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"filename": self.filename, "start_sector": self.start_sector,
                "byte_offset": self.byte_offset, "size_in_bytes": self.size_in_bytes,
                "value": self.value, "what": self.what, "source": self.source}


@dataclass
class QualcommPackage:
    root: str
    program_files: List[str] = field(default_factory=list)
    patch_files: List[str] = field(default_factory=list)
    entries: List[ProgramEntry] = field(default_factory=list)
    patches: List[PatchEntry] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def ok_to_flash(self) -> bool:
        return not any(f.severity in ("error", "fatal") for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root, "program_files": self.program_files,
            "patch_files": self.patch_files, "entry_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
            "patches": [p.to_dict() for p in self.patches],
            "ok_to_flash": self.ok_to_flash,
            "findings": [f.to_dict() for f in self.findings],
        }


def _int(value: Optional[str], default: int = 0) -> int:
    if value is None:
        return default
    value = value.strip()
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return default


def _bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    return value.strip().lower() in ("1", "true", "yes")


def parse_program_file(path: os.PathLike) -> List[ProgramEntry]:
    tree = ET.parse(path)
    root = tree.getroot()
    entries: List[ProgramEntry] = []
    for node in root.iter():
        if node.tag.lower() not in ("program", "erase"):
            continue
        attrs = node.attrib
        entries.append(ProgramEntry(
            label=attrs.get("label", ""),
            filename=attrs.get("filename", ""),
            start_sector=_int(attrs.get("start_sector")),
            num_sectors=_int(attrs.get("num_partition_sectors")),
            physical_partition=_int(attrs.get("physical_partition_number")),
            sector_size=_int(attrs.get("SECTOR_SIZE_IN_BYTES"), 512) or 512,
            sparse=_bool(attrs.get("sparse")) or False,
            file_sector_offset=_int(attrs.get("file_sector_offset")),
            part_of_single_image=_bool(attrs.get("partofsingleimage")) or False,
            readback_verify=_bool(attrs.get("readbackverify")),
            source=Path(path).name,
        ))
    return entries


def parse_patch_file(path: os.PathLike) -> List[PatchEntry]:
    tree = ET.parse(path)
    patches: List[PatchEntry] = []
    for node in tree.getroot().iter():
        if node.tag.lower() != "patch":
            continue
        patches.append(PatchEntry(
            filename=node.attrib.get("filename", ""),
            start_sector=node.attrib.get("start_sector", ""),
            byte_offset=node.attrib.get("byte_offset", ""),
            size_in_bytes=node.attrib.get("size_in_bytes", ""),
            value=node.attrib.get("value", ""),
            what=node.attrib.get("what", ""),
            source=Path(path).name,
        ))
    return patches


def find_xml_files(folder: os.PathLike) -> Dict[str, List[str]]:
    """Sort the XML files of a Qualcomm package into program / patch / erase recipes."""
    root = Path(folder)
    out: Dict[str, List[str]] = {"program": [], "patch": [], "erase": []}
    try:
        entries = sorted(p for p in root.iterdir() if p.is_file() and p.suffix.lower() == ".xml")
    except OSError:
        return out
    for path in entries:
        name = path.name.lower()
        if name.startswith(("rawprogram", "program")) or "rawprogram" in name:
            out["program"].append(str(path))
        elif name.startswith(("patch", "erase")) or "patch" in name:
            out["patch"].append(str(path))
    return out


def load(folder: os.PathLike, check_files: bool = True) -> QualcommPackage:
    root = Path(folder)
    package = QualcommPackage(root=str(root))
    program_files = sorted(p for p in root.glob("rawprogram*.xml"))
    patch_files = sorted(p for p in root.glob("patch*.xml"))
    package.program_files = [str(p) for p in program_files]
    package.patch_files = [str(p) for p in patch_files]

    for xml in program_files:
        try:
            package.entries.extend(parse_program_file(xml))
        except ET.ParseError as exc:
            package.findings.append(Finding(
                "error", f"{xml.name} is not valid XML",
                str(exc), ["Re-download the package; the file is corrupt or truncated"]))
    for xml in patch_files:
        try:
            package.patches.extend(parse_patch_file(xml))
        except ET.ParseError as exc:
            package.findings.append(Finding(
                "error", f"{xml.name} is not valid XML",
                str(exc), ["Re-download the package; the file is corrupt or truncated"]))
    if program_files and not patch_files:
        package.findings.append(Finding(
            "warn", "No patch XML next to the rawprogram files",
            "Qualcomm instructions usually include patch0.xml: it fixes the GPT backup header "
            "and disk signature after the images are written. Without it the phone can fail to "
            "boot even though every image was written correctly.",
            ["Re-extract the firmware package",
             "If you know the patches for this model, add them to a patch0.xml next to the XML"]))

    if not package.entries:
        package.findings.append(Finding(
            "error", "No flashing instructions found",
            "rawprogram*.xml files exist but contain no <program> entries.",
            ["Re-extract the firmware package; some tools flatten the XML when unzipping"]))

    seen: Dict[tuple, ProgramEntry] = {}
    missing: List[str] = []
    for entry in package.entries:
        if entry.num_sectors <= 0 and not entry.is_erase:
            package.findings.append(Finding(
                "error", f"{entry.label or entry.filename}: zero sectors",
                "firehose will not write anything for this entry.",
                ["Re-download the package"]))
        key = (entry.physical_partition, entry.start_sector,
               entry.start_sector + entry.num_sectors)
        for (part, start, _end), other in list(seen.items()):
            if part != entry.physical_partition:
                continue
            if start < entry.start_sector + entry.num_sectors and entry.start_sector < _end:
                package.findings.append(Finding(
                    "error", f"Overlapping writes on physical partition {part}",
                    f"{other.label or other.filename} "
                    f"(sectors {other.start_sector}-{other.start_sector + other.num_sectors}) "
                    f"overlaps {entry.label or entry.filename} "
                    f"(sectors {entry.start_sector}-{entry.start_sector + entry.num_sectors}).",
                    ["Do not flash this package"]))
                break
        seen[key] = entry

        if not check_files or entry.is_erase:
            continue
        target = root / entry.filename
        if not target.exists():
            if entry.filename not in missing:
                missing.append(entry.filename)
            continue
        actual = target.stat().st_size
        offset = entry.file_sector_offset * entry.sector_size
        usable = max(0, actual - offset)
        if usable < entry.size and not entry.sparse:
            package.findings.append(Finding(
                "warn", f"{entry.filename} is smaller than its target range",
                f"{human_size(usable)} available (after a {entry.file_sector_offset}-sector file "
                f"offset) for a {human_size(entry.size)} range. firehose will fail partway.",
                ["Re-download the package",
                 "If this is a partial update image, flash only the matching partitions"]))

    if missing:
        package.findings.append(Finding(
            "error", f"{len(missing)} image(s) are missing from the folder",
            ", ".join(missing[:12]) + (" ..." if len(missing) > 12 else ""),
            ["Re-download the package; Qualcomm tools abort on the first missing file anyway"],
            code="firmware_missing_files"))

    has_programmer = any(root.glob("prog_firehose*")) or any(root.glob("*firehose*.elf")) \
        or any(root.glob("*firehose*.mbn"))
    if not has_programmer:
        package.findings.append(Finding(
            "warn", "No firehose programmer found in this folder",
            "Qualcomm EDL flashing needs the vendor's programmer (prog_firehose_*.mbn/.elf) to "
            "be uploaded before any read or write.",
            ["Keep the programmer next to this XML; Revive asks for it when you flash",
             "The programmer must match the SoC (and sometimes the firmware generation)"]))

    if package.ok_to_flash and package.entries:
        package.findings.append(Finding(
            "ok", "Qualcomm package is internally consistent",
            f"{len(package.entries)} entries across {len(program_files)} rawprogram file(s).",
            []))
    return package


def missing_files(folder: os.PathLike) -> List[str]:
    package = load(folder)
    out: List[str] = []
    for entry in package.entries:
        if entry.part_of_single_image and entry.file_sector_offset > 0:
            continue
        if entry.filename and not (Path(folder) / entry.filename).exists():
            out.append(entry.filename)
    return sorted(set(out))


# ``parse`` is the name the package detector and the planner use.
parse = load
