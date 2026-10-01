"""File-type detection for phone images and dumps.

Detecting content by signature is what lets Revive work on a dump whose partition table is
gone: instead of refusing to help, it can say "this region is an ext4 filesystem", "this is a
boot image", "this range has never been written".

Everything here is intentionally forgiving: `sniff_file` never raises on a normal file, it
returns kind="unknown" instead.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..util import human_size

# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

MBR_SIG = 0x55AA
GPT_SIG = b"EFI PART"
SPARSE_MAGIC = 0xED26FF3A
BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
F2FS_MAGIC = 0xF2F52010
EROFS_MAGIC = 0xE0F5E1E2
EXT4_MAGIC = 0xEF53
LP_HEADER_MAGIC = 0x414C5030          # "ALP0": liblp metadata header
LP_GEOMETRY_MAGIC = 0x616C4467
MTK_DA_STRINGS = (b"MTK_DOWNLOAD_AGENT", b"MTK_DA_v", b"MTK_AllInOne_DA")
MTK_HEADER = b"\x88\x16\x88\x58"
SQUASHFS_MAGIC = b"hsqs"
UBI_MAGIC = b"UBI#"
NTFS_MAGIC = b"NTFS    "
GZIP_MAGIC = b"\x1f\x8b"
LZ4_MAGIC = b"\x04\x22\x4d\x18"
XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
ZIP_MAGIC = b"PK\x03\x04"
ELF_MAGIC = b"\x7fELF"
TAR_MAGIC = b"ustar"

KIND_LABELS = {
    "empty": "Empty file",
    "blank": "Blank/unwritten region",
    "gpt_disk": "eMMC/UFS dump with GPT partition table",
    "mbr": "MBR-partitioned image",
    "android_sparse": "Android sparse image",
    "boot_image": "Android boot image",
    "vendor_boot_image": "Android vendor_boot image",
    "ext4": "ext4 filesystem",
    "f2fs": "F2FS filesystem",
    "erofs": "EROFS filesystem",
    "squashfs": "squashfs filesystem",
    "ubifs": "UBI/UBIFS volume",
    "ntfs": "NTFS filesystem",
    "fat": "FAT/vfat filesystem",
    "super_image": "Android super image (dynamic partitions)",
    "elf": "ELF binary",
    "zip": "ZIP archive (firmware/OTA)",
    "gzip": "gzip stream",
    "lz4": "LZ4 stream",
    "xz": "xz stream",
    "zstd": "zstd stream",
    "tar": "tar archive",
    "mtk_da": "MediaTek Download Agent",
    "mtk_image": "MediaTek image (header present)",
    "mtk_preloader": "MediaTek preloader",
    "unknown": "Unknown / raw data",
    "text": "Text file",
}

CONFIRMED, LIKELY, GUESS = "confirmed", "likely", "guess"


@dataclass
class Signature:
    kind: str
    label: str
    description: str = ""
    confidence: str = GUESS
    size: int = 0
    offset: int = 0

    @property
    def detail(self) -> str:
        return self.description

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "label": self.label, "description": self.description,
                "confidence": self.confidence, "size": self.size, "offset": self.offset,
                "size_human": human_size(self.size) if self.size else ""}


def _is_blank(data: bytes) -> bool:
    if not data:
        return False
    if data == b"\x00" * len(data) or data == b"\xff" * len(data):
        return True
    sample = data[: min(len(data), 65536)]
    zeros = sample.count(0x00) + sample.count(0xFF)
    return zeros / len(sample) > 0.995


def _looks_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.90


def _ext4_at(data: bytes, base: int) -> bool:
    return len(data) >= base + 0x438 + 2 and data[base + 0x438: base + 0x43A] == b"\x53\xef"


def sniff_bytes(data: bytes, path: str = "", size: int = 0) -> Signature:
    """Identify a chunk of data. `size` is the full file size when known."""
    n = len(data)
    if n == 0:
        return Signature("empty", KIND_LABELS["empty"], "This file has no content.", CONFIRMED,
                         size, 0)

    def sig(kind: str, detail: str = "", conf: str = CONFIRMED, off: int = 0) -> Signature:
        return Signature(kind, KIND_LABELS.get(kind, kind), detail, conf, size or n, off)

    if data[:4] == b"\x7fELF":
        detail = "ELF binary - could be a flash programmer"
        if any(s in data[: 1024 * 1024] for s in (b"firehose", b"prog_", b"xbl", b"tz")):
            detail = "ELF flash programmer (Qualcomm-style loader)"
        return sig("elf", detail)

    if len(data) >= 28 and struct.unpack_from("<I", data, 0)[0] == SPARSE_MAGIC:
        _magic, major, minor, fhs = struct.unpack_from("<IHHH", data, 0)
        return sig("android_sparse", f"sparse format {major}.{minor}, {fhs} byte header")

    if data[:8] == BOOT_MAGIC:
        return sig("boot_image", "ANDROID! boot image header")
    if data[:8] == VENDOR_BOOT_MAGIC:
        return sig("vendor_boot_image", "vendor_boot header")

    if data[:4] == ZIP_MAGIC:
        return sig("zip", "ZIP container - firmware archive or OTA package")
    if data[:2] == GZIP_MAGIC:
        return sig("gzip", "gzip-compressed data")
    if data[:4] == LZ4_MAGIC:
        return sig("lz4", "LZ4 frame")
    if data[:6] == XZ_MAGIC:
        return sig("xz", "xz-compressed data")
    if data[:4] == ZSTD_MAGIC:
        return sig("zstd", "zstd-compressed data")
    if data[0x101:0x106] == TAR_MAGIC:
        return sig("tar", "tar archive")

    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] in (LP_GEOMETRY_MAGIC, LP_HEADER_MAGIC):
        return sig("super_image", "Android logical-partition metadata")
    if data[:4] == b"hsqs":
        return sig("squashfs", "squashfs filesystem")
    if data[:4] == b"UBI#":
        return sig("ubifs", "UBI volume (UBIFS/NAND)")
    if data[:8] == NTFS_MAGIC:
        return sig("ntfs", "NTFS filesystem")

    if _ext4_at(data, 1024):
        return sig("ext4", "")
    if _ext4_at(data, 0):
        return sig("ext4", "superblock at offset 0 (raw partition image)")

    if len(data) >= 1024 + 4:
        magic = struct.unpack_from("<I", data, 1024)[0]
        if magic == F2FS_MAGIC:
            return sig("f2fs", "F2FS filesystem")
        if magic == EROFS_MAGIC:
            return sig("erofs", "EROFS filesystem")
        if magic in (LP_HEADER_MAGIC, LP_GEOMETRY_MAGIC):
            return sig("super_image", "Android logical-partition metadata")

    # ZIP-based formats we want to name better than "zip"
    if data[:4] == ZIP_MAGIC and b"payload.bin" in data[:65536]:
        return sig("zip", "OTA package (contains payload.bin)")

    if data[:8] == GPT_SIG or data[512:520] == GPT_SIG:
        off = 512 if data[512:520] == GPT_SIG else 0
        return sig("gpt_disk", f"GPT header at 0x{off:x}", CONFIRMED, off)

    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        # Protective MBR (type 0xEE) or a plain DOS table.
        if len(data) >= 450 and data[446 + 4] == 0xEE:
            return sig("gpt_disk", "protective MBR followed by GPT")
        return sig("mbr", "DOS/MBR partition table")

    if data[:4] == MTK_HEADER or data[0x100:0x104] == MTK_HEADER:
        return sig("mtk_image", "MediaTek image header (0x88168858)")
    if any(s in data[: 512 * 1024] for s in MTK_DA_STRINGS):
        return sig("mtk_da", "MediaTek Download Agent binary")
    if b"PRELOADER" in data[:4096].upper() or b"EMMC_BOOT" in data[:4096]:
        return sig("mtk_preloader", "MediaTek preloader")

    if _is_blank(data):
        return sig("blank", "All 0x00 or all 0xFF - never written or erased")

    if _looks_text(data):
        return sig("text", "Readable text", LIKELY)

    return sig("unknown", f"First bytes: {data[:16].hex(' ')}", GUESS)


def sniff_file(path: os.PathLike, peek: int = 1024 * 1024) -> Signature:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        return Signature("unknown", KIND_LABELS["unknown"], f"Could not read file: {exc}", GUESS, 0)
    try:
        with p.open("rb") as fh:
            data = fh.read(peek)
    except OSError as exc:
        return Signature("unknown", KIND_LABELS["unknown"], f"Could not read file: {exc}", GUESS, size)
    sig = sniff_bytes(data, str(p), size)
    if sig.kind == "unknown" and size == 0:
        return Signature("empty", KIND_LABELS["empty"], "Zero-byte file.", CONFIRMED, 0)
    return sig


def sniff_partition(data: bytes, partition_name: str = "") -> str:
    """A friendlier label for a partition's content, using its name as a hint."""
    sig = sniff_bytes(data)
    name = partition_name.lower()
    if sig.kind in ("android_sparse", "boot_image", "vendor_boot_image", "super_image",
                    "gpt_disk"):
        return sig.label
    if sig.kind == "unknown" and name in ("super", "system", "product", "vendor", "odm"):
        return "raw data (dynamic partition - may be inside super)"
    if sig.kind == "blank" and name:
        return "blank - probably unused on this model"
    return sig.label


# ---------------------------------------------------------------------------
# Batch helper used by the firmware and dump reports
# ---------------------------------------------------------------------------

def describe_folder(folder: os.PathLike, limit: int = 40) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path in sorted(Path(folder).rglob("*")):
        if not path.is_file():
            continue
        sig = sniff_file(path)
        out.append({"name": str(path.relative_to(folder)), "kind": sig.kind,
                    "label": sig.label, "size": sig.size, "confidence": sig.confidence})
        if len(out) >= limit:
            break
    return out


def partition_hints(entries: List[Dict[str, Any]]) -> List[str]:
    """Turn a list of sniffed partitions into human-readable findings."""
    notes: List[str] = []
    for entry in entries:
        kind = entry.get("kind", "")
        if kind in ("blank", "empty"):
            notes.append(f"{entry.get('name', '?')} is {kind} - it may be unused on this model, "
                         "or it may not have been dumped. Verify before you rely on it.")
        elif kind == "unknown":
            notes.append(f"{entry.get('name', '?')} did not match any known format; it is likely "
                         "raw vendor data (calibration, security, or a proprietary blob).")
        elif kind == "android_sparse":
            notes.append(f"{entry.get('name', '?')} is an Android sparse image - it must be "
                         "converted to raw before some tools can use it.")
    return notes
