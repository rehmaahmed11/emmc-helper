"""Firmware package detection: one entry point that figures out what you downloaded.

Point Revive at a folder (or a single file) and it works out whether it is an SP Flash Tool
package, a Qualcomm EDL package, a Unisoc pac, an Odin tar, a Revive dump, or something else -
then hands it to the right parser. This is the "does this firmware even match my phone?"
question answered before anything is written.
"""
from __future__ import annotations

import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..storage import magic, sparse
from ..util import Finding, SEV_ERROR, SEV_INFO, SEV_WARN, human_size
from . import da as da_mod
from . import pac as pac_mod
from . import rawprogram as raw_mod
from . import scatter as scatter_mod

KIND_MTK = "mtk_spflash"
KIND_QUALCOMM = "qualcomm_edl"
KIND_UNISOC = "unisoc_pac"
KIND_ODIN = "samsung_odin"
KIND_REVIVE_DUMP = "revive_dump"
KIND_IMAGES = "image_collection"
KIND_UNKNOWN = "unknown"

IMAGE_EXTS = (".img", ".bin", ".mbn", ".elf", ".iso")
VENDOR_NOISE = ("flash.xml", "checksum.ini", "ver.cfg", "mtk_AllInOne_DA", "scatter", "secro")


@dataclass
class FirmwarePackage:
    root: str
    kind: str = KIND_UNKNOWN
    label: str = ""
    platform: str = ""
    storage: str = ""
    images: List[Dict[str, object]] = field(default_factory=list)
    scatter: Optional[str] = None
    rawprogram_files: List[str] = field(default_factory=list)
    patch_files: List[str] = field(default_factory=list)
    pac_files: List[str] = field(default_factory=list)
    da_files: List[str] = field(default_factory=list)
    loaders: List[str] = field(default_factory=list)
    archives: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    total_size: int = 0

    @property
    def ok_to_flash(self) -> bool:
        return not any(f.severity in (SEV_ERROR, "fatal") for f in self.findings)

    def to_dict(self) -> Dict[str, object]:
        return {
            "root": self.root, "kind": self.kind, "label": self.label,
            "platform": self.platform, "storage": self.storage,
            "images": self.images, "scatter": self.scatter,
            "rawprogram_files": self.rawprogram_files, "patch_files": self.patch_files,
            "pac_files": self.pac_files, "da_files": self.da_files, "loaders": self.loaders,
            "archives": self.archives, "total_size": self.total_size,
            "ok_to_flash": self.ok_to_flash,
            "findings": [f.to_dict() for f in self.findings],
        }


def detect(path: os.PathLike, deep: bool = True) -> FirmwarePackage:
    p = Path(path)
    if p.is_file():
        return _detect_file(p)
    pkg = FirmwarePackage(root=str(p), label=p.name)

    try:
        entries = [e for e in p.iterdir() if e.is_file()]
    except OSError as exc:
        pkg.findings.append(Finding(SEV_ERROR, "Cannot read folder", str(exc), where=str(p)))
        return pkg

    archives = [e for e in entries if e.suffix.lower() in (".zip", ".tar", ".tar.md5", ".tgz", ".7z", ".rar")]
    if archives and not [e for e in entries if e.suffix.lower() in IMAGE_EXTS]:
        pkg.archives = [str(a) for a in archives]
        pkg.findings.append(Finding(
            SEV_WARN, f"{len(archives)} archive(s) found, no extracted images",
            "Revive works on extracted firmware; archives must be unpacked first "
            "(the .zip may itself be one of several parts).",
            ["Extract the archive next to itself, then re-run",
             f"Linux/macOS: unzip '{archives[0].name}' -d {p.name}",
             f"Windows: right-click -> Extract All"],
            where=str(p)))

    scatter_files = scatter_mod.find_scatter_files(p) if deep else []
    xml = raw_mod.find_xml_files(p) if deep else {"program": [], "patch": [], "erase": []}
    pacs = [e for e in entries if e.suffix.lower() == ".pac"]
    tar_like = [e for e in entries if e.suffix.lower() in (".tar", ".md5") and "AP" in e.name.upper()]
    loader_files = [e for e in entries if e.suffix.lower() in (".mbn", ".elf")
                    and ("firehose" in e.name.lower() or "prog" in e.name.lower())]
    da_files = da_mod.find_da_files(p) if deep else []

    pkg.scatter = str(scatter_files[0]) if scatter_files else None
    pkg.rawprogram_files = [str(x) for x in xml["program"]]
    pkg.patch_files = [str(x) for x in xml["patch"]]
    pkg.pac_files = [str(e) for e in pacs]
    pkg.da_files = [str(e) for e in da_files]
    pkg.loaders = [str(e) for e in loader_files]

    images: List[Dict[str, object]] = []
    for e in entries:
        if e.suffix.lower() not in IMAGE_EXTS:
            continue
        try:
            st = e.stat()
        except OSError:
            continue
        entry = {"name": e.name, "path": str(e), "size": st.st_size}
        if deep and st.st_size > 0:
            entry["kind"] = magic.sniff_file(e).kind
        images.append(entry)
        pkg.total_size += st.st_size
    for e in entries:
        if e.suffix.lower() == ".pac":
            pkg.total_size += e.stat().st_size
    images.sort(key=lambda i: i["size"], reverse=True)
    pkg.images = images

    # Classify
    if pkg.scatter:
        pkg.kind = KIND_MTK
        pkg.label = f"SP Flash Tool package ({Path(pkg.scatter).name})"
    elif pkg.rawprogram_files:
        pkg.kind = KIND_QUALCOMM
        pkg.label = "Qualcomm EDL package (rawprogram XML)"
    elif pkg.pac_files:
        pkg.kind = KIND_UNISOC
        pkg.label = "Unisoc (Spreadtrum) pac package"
    elif tar_like:
        pkg.kind = KIND_ODIN
        pkg.label = "Samsung Odin-style tar package"
    elif (p / "manifest.json").exists() and (p / "partitions").exists():
        pkg.kind = KIND_REVIVE_DUMP
        pkg.label = "Revive partition dump"
    elif images:
        pkg.kind = KIND_IMAGES
        pkg.label = f"Image collection ({len(images)} images)"
    else:
        pkg.kind = KIND_UNKNOWN
        pkg.label = "Unrecognised folder"

    if pkg.kind == KIND_MTK and deep:
        scatter = scatter_mod.parse(pkg.scatter)
        pkg.platform = scatter.platform
        pkg.storage = scatter.storage
        pkg.findings.extend(scatter.findings)
        if pkg.images:
            pkg.findings.append(Finding(
                SEV_INFO, f"Package contains {len(pkg.images)} image files "
                          f"({human_size(pkg.total_size)}) and {len(scatter.entries)} scatter entries",
                f"Platform: {scatter.platform or 'unknown'}, project: {scatter.project or 'unknown'}",
                where=str(p)))
    elif pkg.kind == KIND_QUALCOMM and deep:
        qplan = raw_mod.parse(p)
        pkg.findings.extend(qplan.findings)
        if loader_files:
            pkg.findings.append(Finding(
                SEV_INFO, f"Firehose loader(s) present: {', '.join(e.name for e in loader_files[:3])}",
                "Revive uses this to talk to the device in EDL mode.", where=str(p)))
        else:
            pkg.findings.append(Finding(
                SEV_WARN, "No firehose loader found in this folder",
                "Qualcomm EDL flashing needs the programmer that matches this SoC "
                "(prog_emmc_firehose_*.mbn or prog_firehose_*.elf).",
                ["Find the loader in the stock firmware for this exact model",
                 "A loader from another model will fail the Sahara handshake"],
                where=str(p)))
    elif pkg.kind == KIND_UNISOC and deep:
        info = pac_mod.parse(pkg.pac_files[0])
        pkg.findings.extend(info.findings)
    elif pkg.kind == KIND_UNKNOWN:
        pkg.findings.append(Finding(
            SEV_WARN, "Could not classify this folder",
            "No scatter file, no rawprogram XML, no .pac, and no recognizable images.",
            ["Point Revive at the folder that actually contains the firmware files",
             "Or at a single file: Revive inspects .img/.bin/.pac/.txt files directly"],
            where=str(p)))
    return pkg


def _detect_file(p: Path) -> FirmwarePackage:
    pkg = FirmwarePackage(root=str(p), label=p.name)
    name = p.name.lower()
    size = p.stat().st_size
    pkg.total_size = size

    if name.endswith(".pac") or pac_mod.looks_like_pac(p):
        pkg.kind = KIND_UNISOC
        pkg.label = "Unisoc (Spreadtrum) pac package"
        pkg.pac_files = [str(p)]
        info = pac_mod.parse(p)
        pkg.findings.extend(info.findings)
        return pkg

    if name.endswith(".txt") and ("scatter" in name):
        pkg.kind = KIND_MTK
        pkg.label = "MediaTek scatter file"
        pkg.scatter = str(p)
        scatter = scatter_mod.parse(p)
        pkg.platform = scatter.platform
        pkg.storage = scatter.storage
        pkg.findings.extend(scatter.findings)
        return pkg

    if name.endswith(".xml"):
        folder = p.parent
        if name.startswith(("rawprogram", "program")):
            pkg = detect(folder, deep=True)
            return pkg
        if name.startswith(("patch", "erase")):
            pkg.kind = KIND_QUALCOMM
            pkg.label = "Qualcomm patch/erase XML"
            pkg.patch_files = [str(p)]
            pkg.findings.append(Finding(
                SEV_INFO, "This is a patch or erase recipe",
                "It only makes sense together with the matching rawprogram XML in the same folder.",
                ["Run `revive inspect` on the folder instead of the single file"], where=str(p)))
            return pkg

    if da_mod.looks_like_da(p):
        pkg.kind = KIND_MTK
        pkg.label = "MediaTek Download Agent"
        pkg.da_files = [str(p)]
        info = da_mod.parse(p)
        pkg.findings.extend(info.findings)
        return pkg

    sig = magic.sniff_file(p)
    kind_map = {
        "boot_image": "Android boot image",
        "vendor_boot": "Android vendor_boot image",
        "android_sparse": "Android sparse image",
        "super_image": "Android super.img (dynamic partitions)",
        "ext4": "filesystem image",
        "f2fs": "F2FS filesystem image",
        "erofs": "EROFS filesystem image",
        "gpt_disk": "Full disk/dump image with a partition table",
        "firehose_loader": "Qualcomm firehose programmer",
        "mtk_preloader": "MediaTek preloader",
        "blank": "Blank (all zero) image",
        "blank_ff": "Erased (all 0xFF) image",
        "zip": "Archive (extract it first)",
        "lz4": "LZ4-compressed file",
    }
    pkg.kind = KIND_IMAGES
    pkg.label = kind_map.get(sig.kind, f"Single file: {sig.label}")
    pkg.images = [{"name": p.name, "path": str(p), "size": size, "kind": sig.kind}]
    pkg.findings.append(Finding(
        SEV_INFO, f"Detected: {sig.label}" + (f" ({sig.detail})" if sig.detail else ""),
        f"Confidence: {sig.confidence}", where=str(p)))
    return pkg
