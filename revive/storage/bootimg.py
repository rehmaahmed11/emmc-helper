"""Android boot image reading (boot.img, recovery.img, vendor_boot.img, and MTK variants).

Boot images are where most "it bootloops after flashing" stories end: the user flashed a boot
image for the wrong build. Being able to read the header - kernel size, ramdisk compression,
cmdline, security patch level, and whether a MediaTek header is present - lets Revive say
*why* an image does not belong on a phone instead of failing on the phone.
"""
from __future__ import annotations

import gzip
import hashlib
import os
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..util import human_size
from . import lz4blk

BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
MTK_HEADER_MAGIC = 0x58881688        # 88 16 88 58 little-endian
MTK_RAMDISK_MAGIC = 0x58444D88

COMPRESSION_NAMES = {
    "": "uncompressed", "gzip": "gzip", "lz4": "LZ4 (legacy block)", "lz4f": "LZ4 frame",
    "xz": "xz", "lzma": "lzma", "zstd": "zstd", "bzip2": "bzip2",
}

# v3+ has a 4096-byte header; v0-v2 use a 16 KiB offset for the ramdisk on x86, but ARM(64)
# uses 2048-byte pages. The header carries the page size, so no guessing is needed.
V4_KERNEL_ADDR = 0x10008000


class BootImageError(Exception):
    pass


@dataclass
class Section:
    name: str
    offset: int = 0
    size: int = 0
    load_addr: int = 0
    compression: str = ""
    magic: str = ""

    @property
    def compressed(self) -> str:
        """Name of the compression applied to this section ("" when stored raw)."""
        return COMPRESSION_NAMES.get(self.compression, self.compression)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "offset": self.offset, "size": self.size,
                "size_human": human_size(self.size) if self.size else "",
                "load_addr": f"0x{self.load_addr:08X}" if self.load_addr else "",
                "compression": self.compressed, "magic": self.magic}


@dataclass
class BootImage:
    path: str
    kind: str = "boot"
    header_version: int = 0
    header_size: int = 0
    page_size: int = 2048
    os_version: str = ""
    os_patch_level: str = ""
    kernel_version: str = ""
    cmdline: str = ""
    product: str = ""
    board: str = ""
    name: str = ""
    image_size: int = 0
    file_size: int = 0
    sha1: str = ""
    mtk_header: bool = False
    sections: List[Section] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def section(self, name: str) -> Optional[Section]:
        for item in self.sections:
            if item.name == name:
                return item
        return None

    # Convenience accessors: most callers only care about kernel/ramdisk.
    @property
    def kernel(self) -> Optional[Section]:
        return self.section("kernel")

    @property
    def ramdisk(self) -> Optional[Section]:
        return self.section("ramdisk")

    @property
    def second(self) -> Optional[Section]:
        return self.section("second")

    @property
    def dtb(self) -> Optional[Section]:
        return self.section("dtb")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "kind": self.kind,
            "header_version": self.header_version, "header_size": self.header_size,
            "page_size": self.page_size, "os_version": self.os_version,
            "os_patch_level": self.os_patch_level, "kernel_version": self.kernel_version,
            "cmdline": self.cmdline, "product": self.product, "board": self.board,
            "name": self.name, "image_size": self.image_size,
            "image_size_human": human_size(self.image_size),
            "file_size": self.file_size, "sha1": self.sha1, "mtk_header": self.mtk_header,
            "sections": [s.to_dict() for s in self.sections], "findings": self.findings,
        } | {s.name: s.to_dict() for s in self.sections}


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, offset)[0]


def _cstr(data: bytes, offset: int, length: int) -> str:
    return data[offset:offset + length].split(b"\x00")[0].decode("utf-8", "replace")


def _format_os_version(raw: int) -> str:
    if not raw:
        return ""
    major = (raw >> 25) & 0x7F
    minor = (raw >> 18) & 0x7F
    patch = (raw >> 11) & 0x7F
    year = 2000 + ((raw >> 4) & 0x7F)
    month = raw & 0x0F
    return f"Android {major}.{minor}.{patch} ({year:04d}-{month:02d})"


def _detect_compression(data: bytes) -> str:
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh":
        return "bzip2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if data[:4] == b"\x02\x21\x4c\x18":
        return "lz4"
    if data[:4] == b"\x04\x22\x4d\x18":
        return "lz4f"
    if data[:1] == b"\x5d" and len(data) > 4:
        return "lzma"
    return ""


def _section_compression(data: bytes, offset: int, size: int, name: str) -> str:
    if size <= 0 or offset >= len(data):
        return ""
    return _detect_compression(data[offset:offset + min(size, 64)])


def looks_like_boot_image(path: os.PathLike) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return head in (BOOT_MAGIC, VENDOR_BOOT_MAGIC)


def parse(path: os.PathLike, max_read: int = 128 * 1024 * 1024) -> BootImage:
    p = Path(path)
    size = p.stat().st_size
    with p.open("rb") as fh:
        blob = fh.read(min(size, max_read))
    if len(blob) < 8:
        raise BootImageError(f"{p.name} is too small to be a boot image")

    digest = hashlib.sha1()
    if size <= max_read:
        digest.update(blob)
        sha1 = digest.hexdigest()
    else:
        sha1 = ""

    if blob[:8] == VENDOR_BOOT_MAGIC:
        return _parse_vendor_boot(p, blob, size, sha1)
    if blob[:8] != BOOT_MAGIC:
        raise BootImageError(f"{p.name} does not start with ANDROID! - this is not a boot image")

    image = BootImage(path=str(p), file_size=size, sha1=sha1)
    kernel_size = _u32(blob, 8)
    kernel_addr = _u32(blob, 12)
    ramdisk_size = _u32(blob, 16)
    ramdisk_addr = _u32(blob, 20)
    second_size = _u32(blob, 24)
    second_addr = _u32(blob, 28)
    tags_addr = _u32(blob, 32)
    page_size = _u32(blob, 36) or 2048
    image.header_version = _u32(blob, 40)
    os_version_raw = _u32(blob, 44)
    image.name = _cstr(blob, 48, 16)
    image.cmdline = _cstr(blob, 64, 512)
    image_id = blob[576:608]
    image.image_size = _u32(blob, 608)
    image.page_size = page_size
    image.os_version = _format_os_version(os_version_raw)
    image.os_patch_level = f"{2000 + ((os_version_raw >> 4) & 0x7F)}-{os_version_raw & 0x0F:02d}" \
        if os_version_raw else ""

    if image.header_version > 0:
        if image.header_version == 1:
            image.os_version = _format_os_version(_u32(blob, 44))
        if image.header_version == 2:
            image.kernel_version = _cstr(blob, 616, 64)
            image.cmdline = _cstr(blob, 680, 512)
        if image.header_version >= 3:
            image.header_size = _u32(blob, 20)
            image.header_version = _u32(blob, 40)
        if image.header_version >= 4:
            image.kernel_version = _cstr(blob, 616, 64)
            image.cmdline = _cstr(blob, 680, 512)

    # Sections start after the header, page aligned.
    header_bytes = 4096 if image.header_version >= 3 else page_size
    cursor = _align(header_bytes, page_size)
    sections: List[Section] = []

    def add(name: str, offset: int, length: int, addr: int = 0) -> int:
        if length <= 0:
            return offset
        section = Section(name=name, offset=offset, size=length, load_addr=addr,
                          compression=_section_compression(blob, offset, length, name))
        sections.append(section)
        return _align(offset + length, page_size)

    cursor = add("kernel", cursor, kernel_size, kernel_addr)
    cursor = add("ramdisk", cursor, ramdisk_size, ramdisk_addr)
    if image.header_version == 0:
        cursor = add("second", cursor, second_size, second_addr)
    elif image.header_version == 1:
        recovery_dtbo_size = _u32(blob, 1632)
        recovery_dtbo_offset = struct.unpack_from("<Q", blob, 1636)[0] \
            if len(blob) >= 1644 else 0
        if recovery_dtbo_size:
            sections.append(Section("recovery_dtbo", recovery_dtbo_offset, recovery_dtbo_size,
                                    compression=_section_compression(
                                        blob, recovery_dtbo_offset, recovery_dtbo_size, "dtbo")))
        cursor = add("dtb", cursor, _u32(blob, 1648), 0)
    elif image.header_version == 2:
        cursor = add("dtb", cursor, _u32(blob, 1648), 0)
    elif image.header_version >= 4:
        cursor = add("boot_signature", cursor, _u32(blob, 1648), 0)

    # MediaTek images carry a 512-byte MTK header before the kernel payload.
    kernel = image.section("kernel") or (sections[0] if sections else None)
    if kernel and kernel.size and len(blob) >= kernel.offset + 4:
        if struct.unpack_from("<I", blob, kernel.offset)[0] == MTK_HEADER_MAGIC:
            image.mtk_header = True
            image.findings.append(
                "MediaTek header found before the kernel (0x88168858). The kernel starts 512 "
                "bytes into this section; tools that ignore it will produce a bootloop."
            )
    image.sections = sections

    if image.page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
        image.findings.append(f"page size {image.page_size} is not a power-of-two Android "
                              "page size; the header may be corrupt")
    if image.image_size and image.image_size > size:
        image.findings.append(
            f"header says the image is {human_size(image.image_size)} but the file is "
            f"{human_size(size)}: this image is truncated. Do not flash it."
        )
    if image.header_version:
        image.kind = "boot" if image.header_version >= 3 else "boot (legacy header)"
    return image


def _parse_vendor_boot(p: Path, blob: bytes, size: int, sha1: str) -> BootImage:
    image = BootImage(path=str(p), kind="vendor_boot", file_size=size, sha1=sha1)
    if len(blob) < 2128:
        raise BootImageError("vendor_boot header is truncated")
    image.header_version = _u32(blob, 8)
    image.page_size = _u32(blob, 12) or 2048
    kernel_addr = _u32(blob, 16)
    ramdisk_addr = _u32(blob, 20)
    vendor_ramdisk_size = _u32(blob, 24)
    image.cmdline = _cstr(blob, 28, 2048)
    header_size = _u32(blob, 2092) or 2112
    sections: List[Section] = []
    if image.header_version >= 3:
        # vendor_ramdisk table
        table_entry_num = _u32(blob, 2096)
        table_entry_size = _u32(blob, 2100)
        table_offset = 2112
        cursor = _align(header_size, image.page_size)
        for index in range(min(table_entry_num, 64)):
            base = table_offset + index * (table_entry_size or 108)
            if base + 8 > len(blob):
                break
            ramdisk_size = _u32(blob, base)
            ramdisk_offset = _u32(blob, base + 4)
            sections.append(Section(f"vendor_ramdisk_{index}", ramdisk_offset, ramdisk_size,
                                    compression=_section_compression(
                                        blob, ramdisk_offset, ramdisk_size, "ramdisk")))
    elif vendor_ramdisk_size:
        cursor = _align(header_size, image.page_size)
        sections.append(Section("vendor_ramdisk", cursor, vendor_ramdisk_size,
                                compression=_section_compression(blob, cursor,
                                                                 vendor_ramdisk_size, "ramdisk")))
    dtb_size = _u32(blob, 2104)
    if dtb_size:
        sections.append(Section("dtb", size - dtb_size, dtb_size))
    image.sections = sections
    return image


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    remainder = value % alignment
    return value if remainder == 0 else value + (alignment - remainder)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def decompress_section(data: bytes, compression: str) -> Tuple[bytes, str]:
    """Decompress a kernel/ramdisk payload. Returns (data, note)."""
    if not compression:
        return data, "stored uncompressed"
    try:
        if compression == "gzip":
            return gzip.decompress(data), "gunzipped"
        if compression == "lz4":
            return lz4blk.decompress(data), "LZ4 legacy block stream expanded"
        if compression == "lz4f":
            return lz4blk.decompress(data), "LZ4 frame expanded"
        if compression in ("xz", "lzma"):
            import lzma

            return lzma.decompress(data), "xz/lzma expanded"
        if compression == "zstd":
            try:
                import zstandard  # type: ignore

                return zstandard.ZstdDecompressor().decompress(data), "zstd expanded"
            except ImportError:
                return b"", ("this ramdisk is zstd-compressed and the optional `zstandard` "
                             "module is not installed; install it or use `zstd -d`")
    except Exception as exc:                                  # noqa: BLE001
        return b"", f"could not decompress ({compression}): {exc}"
    return data, "left as-is (compression not handled)"


def extract(image: BootImage, out_dir: os.PathLike, what: str = "all") -> List[Dict[str, Any]]:
    """Write the sections (kernel/ramdisk/...) out, decompressing when Revive can."""
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, Any]] = []
    with open(image.path, "rb") as fh:
        for section in image.sections:
            if what != "all" and section.name != what:
                continue
            fh.seek(section.offset)
            data = fh.read(section.size)
            if section.name == "kernel" and image.mtk_header:
                data = data[512:]
            entry: Dict[str, Any] = {
                "name": section.name, "size": len(data), "compression": section.compressed,
                "offset": section.offset,
            }
            raw_target = out_root / f"{Path(image.path).stem}_{section.name}"
            raw_target.write_bytes(data)
            entry["path"] = str(raw_target)
            decompressed, note = decompress_section(data, section.compression)
            entry["note"] = note
            if decompressed and decompressed != data:
                target = out_root / f"{Path(image.path).stem}_{section.name}.decompressed"
                target.write_bytes(decompressed)
                entry["decompressed_path"] = str(target)
                entry["decompressed_size"] = len(decompressed)
            elif decompressed:
                entry["decompressed_path"] = str(raw_target)
                entry["decompressed_size"] = len(decompressed)
            else:
                entry["error"] = note
            results.append(entry)
    return results
