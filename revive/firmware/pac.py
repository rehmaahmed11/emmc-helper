"""Unisoc/Spreadtrum ``.pac`` container reader.

A PAC is an archive of partition images with an XML manifest inside. Revive deliberately does
**not** flash PACs: the on-wire protocol for Unisoc download mode is undocumented enough that a
write could end in a corrupt partition. What it does do is the part that is unambiguous and
safe - read the manifest, list the contents, and pull a single image out (boot, recovery,
preloader) with exact offsets.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..util import Finding, human_size

PAC_MAGIC = b"BP_R"
PAC_ALT_MAGIC = b"PAC"
XML_START = b"<?xml"
MAX_MANIFEST = 8 * 1024 * 1024

ATTRIBUTE_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"')


@dataclass
class PacFile:
    name: str = ""
    size: int = 0
    offset: int = 0
    file_type: str = ""
    flag: str = ""
    inside_bounds: bool = True
    part_of_image: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "size": self.size, "size_human": human_size(self.size),
                "offset": self.offset, "offset_hex": f"0x{self.offset:x}", "type": self.file_type,
                "flag": self.flag, "inside_bounds": self.inside_bounds,
                "part_of_image": self.part_of_image}


@dataclass
class PacInfo:
    path: str
    file_size: int = 0
    magic: str = ""
    version: str = ""
    manifest_offset: int = 0
    files: List[PacFile] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    sha256: str = ""
    parse_confidence: str = "xml-manifest"

    @property
    def entries(self) -> List[PacFile]:
        return self.files

    @property
    def declared_size(self) -> int:
        return sum(f.size for f in self.files)

    def find(self, name: str) -> Optional[PacFile]:
        low = name.lower()
        for entry in self.files:
            if entry.name.lower() == low:
                return entry
        for entry in self.files:
            if low in entry.name.lower():
                return entry
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "file_size": self.file_size,
            "file_size_human": human_size(self.file_size), "magic": self.magic,
            "version": self.version, "manifest_offset": self.manifest_offset,
            "file_count": len(self.files), "declared_size": self.declared_size,
            "parse_confidence": self.parse_confidence,
            "declared_size_human": human_size(self.declared_size),
            "files": [f.to_dict() for f in self.files], "sha256": self.sha256,
            "findings": [f.to_dict() for f in self.findings],
        }


def _parse_manifest(text: str) -> List[PacFile]:
    """Pull <File ...> entries out of the manifest, whatever the surrounding tag names are."""
    files: List[PacFile] = []
    for match in re.finditer(r"<File\b([^>]*?)/?>", text, re.IGNORECASE | re.DOTALL):
        attrs = {k.lower(): v for k, v in ATTRIBUTE_RE.findall(match.group(1))}
        name = attrs.get("name") or attrs.get("filename") or ""
        if not name:
            continue
        try:
            size = int(attrs.get("size", "0") or 0)
        except ValueError:
            size = 0
        raw_offset = attrs.get("offset") or attrs.get("fileoffset") or "0"
        try:
            offset = int(raw_offset, 16) if raw_offset.lower().startswith("0x") else int(raw_offset)
        except ValueError:
            offset = 0
        files.append(PacFile(
            name=name, size=size, offset=offset,
            file_type=attrs.get("type", ""), flag=attrs.get("flag", ""),
            part_of_image=attrs.get("partofimage", "") or attrs.get("image", ""),
        ))
    return files


INVENTORY_RE = re.compile(
    rb"[ -~]{3,72}?\.(?:bin|img|mbn|elf|pac|xml|txt|cfg|ini)\x00")


def looks_like_pac(path: os.PathLike) -> bool:
    """A .pac by extension, or by the header magic the container uses."""
    p = Path(path)
    if p.suffix.lower() == ".pac":
        return True
    try:
        with p.open("rb") as fh:
            head = fh.read(64)
    except OSError:
        return False
    return head[:4] in (PAC_MAGIC, PAC_ALT_MAGIC, b"PAC\x00") or head[:3] == PAC_ALT_MAGIC


def _inventory(path) -> PacInfo:
    """Last-resort listing: find image names and their declared sizes by scanning."""
    p = Path(path)
    size = p.stat().st_size
    info = PacInfo(path=str(p), file_size=size, parse_confidence="inventory-only")
    with p.open("rb") as fh:
        head = fh.read(8)
        fh.seek(0)
        blob = fh.read(min(size, 32 * 1024 * 1024))
    info.magic = head[:4].decode("ascii", "replace").strip("\x00")
    seen = set()
    for match in INVENTORY_RE.finditer(blob):
        name = match.group(0)[:-1].decode("ascii", "replace")
        if name in seen:
            continue
        seen.add(name)
        after = match.end()
        declared = 0
        if after + 4 <= len(blob):
            declared = int.from_bytes(blob[after:after + 4], "little")
        if not (0 < declared <= size):
            declared = 0
        info.files.append(PacFile(name=name, size=declared, offset=0, file_type="inventory",
                                  inside_bounds=declared > 0))
    if info.files:
        info.findings.append(Finding(
            "warn", "PAC contents were found by scanning, not by reading a manifest",
            f"{len(info.files)} image name(s) with plausible sizes were found. Revive cannot "
            "guarantee the exact offsets of this container layout, so extraction is labelled "
            "best-effort.",
            ["Use the vendor tool if you need a byte-exact extraction",
             "Report this PAC so the layout can be added properly"]))
    else:
        info.findings.append(Finding(
            "warn", "This .pac could not be read",
            "Neither an XML manifest nor recognisable image names were found.",
            ["Re-download the file", "It may be encrypted or split across volumes"]))
    return info


def parse(path: os.PathLike, hashing: bool = False) -> PacInfo:
    """Read a PAC: the manifest when possible, an inventory scan otherwise."""
    try:
        return inspect(path, hashing=hashing)
    except ValueError:
        return _inventory(path)


def inspect(path: os.PathLike, hashing: bool = False) -> PacInfo:
    p = Path(path)
    info = PacInfo(path=str(p), file_size=p.stat().st_size)
    with p.open("rb") as fh:
        head = fh.read(64)
        if head[:4] != PAC_MAGIC:
            raise ValueError(f"{p.name} does not start with the PAC magic 'BP_R'")
        info.magic = head[:4].decode("ascii", "replace")
        info.version = head[4:8].decode("ascii", "replace").strip("\x00 ")
        fh.seek(0)
        blob = fh.read(min(info.file_size, MAX_MANIFEST))
        if hashing:
            fh.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
            info.sha256 = digest.hexdigest()

    start = blob.find(XML_START)
    if start < 0:
        raise ValueError("no XML manifest found: this PAC is either encrypted, truncated, or a "
                         "format Revive does not know")
    info.manifest_offset = start
    text_blob = blob[start:]
    # Find the longest prefix that ends at a plausible closing tag.
    text = text_blob.decode("utf-8", "replace")
    files = _parse_manifest(text)
    if not files:
        cut = text.rfind("</")
        if cut > 0:
            files = _parse_manifest(text[:cut])
    info.files = files

    for entry in info.files:
        if entry.size <= 0:
            continue
        if entry.offset <= 0 or entry.offset + entry.size > info.file_size:
            entry.inside_bounds = False

    bad = [f.name for f in info.files if not f.inside_bounds]
    if bad:
        info.findings.append(Finding(
            "error", f"{len(bad)} PAC entry/entries point outside the file",
            ", ".join(bad[:8]),
            ["The PAC is truncated or corrupt; re-download it before using any of its images"]))
    if not info.files:
        info.findings.append(Finding(
            "warn", "PAC manifest could not be decoded",
            "Offsets and sizes in this PAC use a layout Revive does not recognise.",
            ["Use the vendor tool to list its contents",
             "Report the PAC header (first 512 bytes) so the format can be added"]))

    preloader = info.find("preloader")
    if preloader:
        info.findings.append(Finding(
            "info", "Preloader is inside this PAC",
            f"{preloader.name} ({human_size(preloader.size)}) - the image you need if the phone "
            "cannot enter download mode.",
            ["Extract it with `revive pac-extract <file> --name preloader` and keep it with your "
             "repair notes for this model"]))
    if info.files:
        info.findings.append(Finding(
            "info", f"{len(info.files)} images inside the PAC",
            f"Declared payload {human_size(info.declared_size)} of "
            f"{human_size(info.file_size)}.",
            ["`revive pac-list` shows them all; `revive pac-extract` pulls one out"]))
    return info


def extract(path: os.PathLike, name: str, out_path: os.PathLike) -> Dict[str, Any]:
    info = inspect(path)
    entry = info.find(name)
    if entry is None:
        available = ", ".join(f.name for f in info.files[:20]) or "none readable"
        raise ValueError(f"{name!r} is not in this PAC. Found: {available}")
    if not entry.inside_bounds:
        raise ValueError(f"refusing to extract {entry.name}: its offset/size fall outside the file")
    dst = Path(out_path)
    if dst.is_dir() or not dst.suffix:
        dst = dst / entry.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(path, "rb") as src, dst.open("wb") as out:
        src.seek(entry.offset)
        remaining = entry.size
        while remaining > 0:
            block = src.read(min(remaining, 4 * 1024 * 1024))
            if not block:
                break
            out.write(block)
            written += len(block)
            remaining -= len(block)
    digest = hashlib.sha256()
    with dst.open("rb") as check:
        for chunk in iter(lambda: check.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return {"name": entry.name, "output": str(dst), "size": written, "sha256": digest.hexdigest(),
            "declared_size": entry.size}
