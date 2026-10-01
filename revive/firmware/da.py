"""MediaTek Download Agent / preloader inspection.

Two jobs:

1. Tell the user which DA modes and chip codes a ``.bin`` loader actually supports, so the
   right one is chosen before a session starts. Revive reads the structure it can identify and
   reports the rest as strings-scanned candidates rather than inventing a table.
2. Feed chip codes discovered in a DA back into ``revive.core.chips`` so that identifying a
   *connected* device becomes more accurate as the user's own files are seen.

MediaTek never published the DA container format, so everything here is heuristic and labelled
as such. The one thing it is safe to be certain about is the DA mode string, because the vendor
put it in plain text.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core import chips
from ..util import Finding, human_size

DA_VERSION_RE = re.compile(rb"MTK_DA_v\d|MTK_DOWNLOAD_AGENT|MTK_AllInOne_DA[^\x00]{0,20}")
CHIP_NAME_RE = re.compile(rb"MT\d{4}[A-Z]?")
HWCODE_HINT_WINDOW = 96

KNOWN_DA_MODES = {
    "MTK_DA_v1": "legacy (v1)",
    "MTK_DA_v2": "legacy (v2)",
    "MTK_DA_v3": "legacy (v3)",
    "MTK_DA_v5": "xflash (v5)",
    "MTK_DA_v6": "xml (v6)",
}


@dataclass
class DaInfo:
    path: str
    size: int = 0
    sha256: str = ""
    da_modes: List[str] = field(default_factory=list)
    markers: List[str] = field(default_factory=list)
    generation: str = ""
    chip_names: List[str] = field(default_factory=list)
    hw_codes: List[int] = field(default_factory=list)
    auth_companion: str = ""
    findings: List[Finding] = field(default_factory=list)

    @property
    def hardware_codes(self) -> List[int]:
        return self.hw_codes

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "size": self.size, "size_human": human_size(self.size),
                "sha256": self.sha256, "da_modes": self.da_modes, "markers": self.markers,
                "generation": self.generation, "chip_names": self.chip_names,
                "hw_codes": [f"0x{c:04X}" for c in self.hw_codes],
                "hw_code_ints": self.hw_codes, "auth_companion": self.auth_companion,
                "findings": [f.to_dict() for f in self.findings]}


def _scan_chip_pairs(blob: bytes) -> List[int]:
    """Look for a chip name with a known hardware code nearby - a weak but useful hint."""
    hints: List[int] = []
    for match in CHIP_NAME_RE.finditer(blob):
        name = match.group(0).decode("ascii")
        window = blob[max(0, match.start() - HWCODE_HINT_WINDOW):
                      min(len(blob), match.end() + HWCODE_HINT_WINDOW)]
        for offset in range(0, max(0, len(window) - 4)):
            candidate = int.from_bytes(window[offset:offset + 4], "little")
            chip = chips.lookup(candidate)
            if chip is None:
                continue
            family = (getattr(chip, "family", "") or chip.name.split("/")[0]).strip().lower()
            if family and family in name.lower():
                hints.append(candidate)
                break
    return sorted(set(hints))


def inspect(path: os.PathLike, register: bool = False) -> DaInfo:
    p = Path(path)
    info = DaInfo(path=str(p), size=p.stat().st_size)
    digest = hashlib.sha256()
    blob_parts: List[bytes] = []
    read = 0
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            if read < 32 * 1024 * 1024:          # only keep the head for string scans
                blob_parts.append(chunk)
                read += len(chunk)
    info.sha256 = digest.hexdigest()
    blob = b"".join(blob_parts)

    for match in DA_VERSION_RE.finditer(blob):
        text = match.group(0).decode("ascii", "replace").strip("\x00")
        if text not in info.markers:
            info.markers.append(text)
        for key, label in KNOWN_DA_MODES.items():
            if text.startswith(key) and label not in info.da_modes:
                info.da_modes.append(label)
        if text.startswith("MTK_AllInOne"):
            info.chip_names.append("AllInOne DA (multi-chip)")
    version_match = re.search(r"_DA_v(\d)", " ".join(info.markers))
    if version_match:
        info.generation = f"MTK_DA_v{version_match.group(1)}"
    elif info.markers:
        info.generation = "MTK_DOWNLOAD_AGENT" if "MTK_DOWNLOAD_AGENT" in info.markers else ""

    names = sorted({m.group(0).decode("ascii") for m in CHIP_NAME_RE.finditer(blob)})
    info.chip_names.extend(n for n in names if n not in info.chip_names)
    info.hw_codes = _scan_chip_pairs(blob)

    for companion in (".auth", ".sig", ".sign"):
        candidate = p.with_suffix(p.suffix + companion)
        if candidate.exists():
            info.auth_companion = str(candidate)
            break

    if not info.da_modes:
        info.findings.append(Finding(
            "warn", "No MediaTek DA version marker found",
            "This may be a signed/encrypted DA, a preloader rather than a DA, or a file from "
            "another vendor.",
            ["Check the file with `revive inspect <file>` to see what it actually is",
             "Use the DA that came with this exact firmware package"]))
    if info.da_modes:
        info.findings.append(Finding(
            "info", f"DA mode: {', '.join(info.da_modes)}",
            "The DA mode decides which protocol conversation the tool has with the phone. "
            "Using the wrong one ends in a failed handshake, not in damage.", []))
    if info.chip_names:
        shown = ", ".join(info.chip_names[:12])
        info.findings.append(Finding(
            "info", f"{len(info.chip_names)} chip name(s) referenced",
            shown + (" ..." if len(info.chip_names) > 12 else ""),
            ["Match this list against the phone's hardware code before uploading the DA"]))
    if info.hw_codes and register:
        for code in info.hw_codes:
            existing = chips.lookup(code)
            if existing and existing.confidence == chips.UNKNOWN:
                chips.register_from_da(code, existing.name, source=f"DA string scan: {p.name}")
    if not info.hw_codes:
        info.findings.append(Finding(
            "info", "No hardware-code hints extracted",
            "DA containers vary; some carry no plain-text code table. The device itself always "
            "reports its hardware code when it enters BROM mode.", []))
    if info.auth_companion:
        info.findings.append(Finding(
            "info", "Authentication file found next to this loader",
            f"{Path(info.auth_companion).name} will be offered automatically for secure-boot "
            "devices.", []))
    return info


def find_da_files(folder: os.PathLike) -> List[Path]:
    """Files in a folder that look like a MediaTek Download Agent."""
    root = Path(folder)
    out: List[Path] = []
    try:
        entries = [p for p in sorted(root.iterdir()) if p.is_file()]
    except OSError:
        return out
    for path in entries:
        if path.suffix.lower() not in (".bin", ".da", ".img"):
            continue
        if "da" in path.name.lower() and is_probably_da(path):
            out.append(path)
    return out


def is_probably_da(path: os.PathLike) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(2 * 1024 * 1024)
    except OSError:
        return False
    if head[:4] == b"MTK_":
        return True
    return bool(DA_VERSION_RE.search(head)) or b"MTK_DOWNLOAD_AGENT" in head


def is_probably_preloader(path: os.PathLike) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return head[:4] == b"EMMC" or b"PRELOADER" in head.upper()


# ``parse`` is the name the package detector and the CLI use.
parse = inspect
looks_like_da = is_probably_da
