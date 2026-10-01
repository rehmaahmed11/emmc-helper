"""Android ``super.img`` (dynamic partitions) reader.

A super image is a container: the LP metadata describes logical partitions that live inside,
and the data itself is usually stored either raw, as an Android sparse image, or wrapped in
LZ4. Revive reads the metadata, lists what is inside, and can pull a single partition back out.

The metadata format has two on-disk shapes:

    1.0 / 1.1   tables are written one after another, each as "count, then records"
    1.2+        the header carries descriptors (offset, count, record size) for each table

Both are handled; anything that does not validate produces an explanation instead of a guess.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..util import ProgressFn, human_size, null_progress

LP_HEADER_MAGIC = 0x414C5030
LP_GEOMETRY_MAGIC = 0x616C4467
GEOMETRY_SIZE = 4096
PARTITION_RECORD = 52
EXTENT_RECORD = 24
GROUP_RECORD = 48
BLOCK_DEVICE_RECORD = 64

TARGET_LINEAR = 0
TARGET_ZERO = 1
TARGET_ANDROID_SPARSE = 2
TARGET_ANDROID_VERITY = 3
TARGET_FILL = 4
TARGET_NAMES = {
    TARGET_LINEAR: "linear", TARGET_ZERO: "zero", TARGET_ANDROID_SPARSE: "android-sparse",
    TARGET_ANDROID_VERITY: "verity", TARGET_FILL: "fill",
}


class SuperError(Exception):
    pass


@dataclass
class Extent:
    num_sectors: int = 0
    target_type: int = TARGET_LINEAR
    target_data: int = 0
    target_source: int = 0

    @property
    def size(self) -> int:
        return self.num_sectors * 512

    @property
    def type_name(self) -> str:
        return TARGET_NAMES.get(self.target_type, f"type-{self.target_type}")

    def to_dict(self) -> Dict[str, Any]:
        return {"sectors": self.num_sectors, "size": self.size, "type": self.type_name,
                "target_data": self.target_data, "source": self.target_source}


@dataclass
class SuperPartition:
    name: str
    group: str = ""
    extents: List[Extent] = field(default_factory=list)
    attributes: int = 0

    @property
    def size(self) -> int:
        return sum(e.size for e in self.extents)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "group": self.group, "size": self.size,
                "size_human": human_size(self.size), "extents": [e.to_dict() for e in self.extents]}


@dataclass
class SuperInfo:
    path: str
    geometry_size: int = GEOMETRY_SIZE
    logical_block_size: int = 4096
    metadata_max_size: int = 0
    metadata_slots: int = 1
    major: int = 0
    minor: int = 0
    partitions: List[SuperPartition] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    block_devices: List[str] = field(default_factory=list)
    file_size: int = 0
    sparse_wrapped: bool = False
    notes: List[str] = field(default_factory=list)

    def find(self, name: str) -> Optional[SuperPartition]:
        for p in self.partitions:
            if p.name == name:
                return p
        return None

    @property
    def version_supported(self) -> bool:
        """True when the metadata version could be parsed (1.0/1.1/1.2+ are all handled)."""
        return bool(self.partitions) and self.major >= 1

    def total_size(self) -> int:
        return sum(p.size for p in self.partitions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "major": self.major, "minor": self.minor,
            "logical_block_size": self.logical_block_size, "metadata_slots": self.metadata_slots,
            "metadata_max_size": self.metadata_max_size, "file_size": self.file_size,
            "container": "sparse" if self.sparse_wrapped else "raw",
            "partitions": [p.to_dict() for p in self.partitions],
            "groups": self.groups, "block_devices": self.block_devices,
            "total_size": self.total_size(), "notes": self.notes,
        }


def _read_blob(path: os.PathLike, limit: int = 8 * 1024 * 1024) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit)


def _parse_extents(blob: bytes, offset: int, count: int, entry_size: int,
                   info: Optional[SuperInfo] = None) -> List[Extent]:
    """Extents are 20 bytes of data; some builders pad the record to 24. Both are handled."""
    if entry_size not in (20, 24) and info is not None:
        info.notes.append(f"extent records declare an unusual size ({entry_size} bytes); "
                          "the first 20 bytes of each record are used")
    if entry_size < 20:
        return []
    out: List[Extent] = []
    stride = max(entry_size, 20)
    for i in range(count):
        base = offset + i * stride
        if base + 20 > len(blob):
            break
        sectors, ttype, tdata, tsource = struct.unpack_from("<QIII", blob, base)
        if ttype not in TARGET_NAMES:
            out.append(Extent(sectors, ttype, tdata, tsource))
            continue
        out.append(Extent(sectors, ttype, tdata, tsource))
    return out


def _parse_partitions(blob: bytes, offset: int, count: int, entry_size: int,
                      extents: List[Extent]) -> List[SuperPartition]:
    parts: List[SuperPartition] = []
    for i in range(count):
        base = offset + i * entry_size
        if base + PARTITION_RECORD > len(blob):
            break
        name = blob[base:base + 36].split(b"\x00")[0].decode("utf-8", "replace")
        attributes, first_extent, num_extents, group_index = struct.unpack_from(
            "<IIII", blob, base + 36)
        part = SuperPartition(name, "", [], attributes)
        if first_extent + num_extents <= len(extents):
            part.extents = extents[first_extent:first_extent + num_extents]
        else:
            part.extents = []
        part.group = str(group_index)
        parts.append(part)
    return parts


def _parse_groups(blob: bytes, offset: int, count: int, entry_size: int) -> List[str]:
    names: List[str] = []
    for i in range(count):
        base = offset + i * entry_size
        if base + 36 > len(blob):
            break
        names.append(blob[base:base + 36].split(b"\x00")[0].decode("utf-8", "replace"))
    return names


def _parse_block_devices(blob: bytes, offset: int, count: int, entry_size: int) -> List[str]:
    """Report "<name>: <size>" per backing device when the record layout is recognisable."""
    names: List[str] = []
    for i in range(count):
        base = offset + i * entry_size
        if base + 36 > len(blob):
            break
        name = blob[base:base + 36].split(b"\x00")[0].decode("utf-8", "replace")
        details = name
        if entry_size >= 100:
            size = struct.unpack_from("<Q", blob, base + 52)[0]
            partition = blob[base + 60:base + 96].split(b"\x00")[0].decode("utf-8", "replace")
            details = f"{name} ({human_size(size)}{', backing ' + partition if partition else ''})"
        names.append(details)
    return names


def _parse_slot(blob: bytes, slot_start: int, info: SuperInfo) -> bool:
    if slot_start + 0x14 > len(blob):
        return False
    magic, major, minor, header_size, header_checksum, tables_size, tables_checksum = \
        struct.unpack_from("<IHHHHII", blob, slot_start)
    if magic != LP_HEADER_MAGIC:
        return False
    info.major, info.minor = major, minor
    header_off = slot_start
    if header_size < 0x14 or header_size > 4096:
        info.notes.append(f"metadata header size {header_size} is implausible; parsing stopped")
        return False

    extents: List[Extent] = []
    parts: List[SuperPartition] = []

    if minor >= 2:
        # descriptor table: three u32 per table (offset, num_entries, entry_size)
        tables = {}
        desc = header_off + 0x14
        for name in ("partitions", "extents", "groups", "block_devices"):
            if desc + 12 > len(blob):
                return False
            offset, num_entries, entry_size = struct.unpack_from("<III", blob, desc)
            tables[name] = (header_off + offset, num_entries, entry_size)
            desc += 12
        if tables["extents"][1] > 4096 or tables["partitions"][1] > 4096:
            info.notes.append("metadata table sizes are implausible; not listing partitions")
            return False
        extents = _parse_extents(blob, *tables["extents"], info=info)
        parts = _parse_partitions(blob, *tables["partitions"], extents)
        info.groups = _parse_groups(blob, *tables["groups"])
        info.block_devices = _parse_block_devices(blob, *tables["block_devices"])
    else:
        # 1.0/1.1: count-prefixed tables in a fixed order
        cursor = header_off + header_size
        if cursor + 4 > len(blob):
            return False
        n_parts = struct.unpack_from("<I", blob, cursor)[0]
        cursor += 4
        if n_parts > 1024:
            info.notes.append("partition count is implausible; not listing partitions")
            return False
        part_records = _parse_partitions(blob, cursor, n_parts, PARTITION_RECORD, [])
        cursor += n_parts * PARTITION_RECORD
        if cursor + 4 > len(blob):
            return False
        n_extents = struct.unpack_from("<I", blob, cursor)[0]
        cursor += 4
        if n_extents > 8192:
            info.notes.append("extent count is implausible; not listing partitions")
            return False
        extents = _parse_extents(blob, cursor, n_extents, EXTENT_RECORD, info=info)
        cursor += n_extents * EXTENT_RECORD
        if cursor + 4 <= len(blob):
            n_groups = struct.unpack_from("<I", blob, cursor)[0]
            cursor += 4
            info.groups = _parse_groups(blob, cursor, min(n_groups, 64), GROUP_RECORD)
            cursor += min(n_groups, 64) * GROUP_RECORD
        if cursor + 4 <= len(blob):
            n_devices = struct.unpack_from("<I", blob, cursor)[0]
            cursor += 4
            info.block_devices = _parse_block_devices(blob, cursor, min(n_devices, 16),
                                                       BLOCK_DEVICE_RECORD)
        # re-resolve extents now that they are known
        parts = _parse_partitions(blob, header_off + header_size + 4, n_parts,
                                  PARTITION_RECORD, extents)
        info.groups = info.groups or ["default"]
        for part in parts:
            try:
                index = int(part.group)
                if 0 <= index < len(info.groups):
                    part.group = info.groups[index]
            except ValueError:
                part.group = "default"

    for part in parts:
        if not part.group.isdigit() and part.group:
            continue
        try:
            index = int(part.group)
            if 0 <= index < len(info.groups):
                part.group = info.groups[index]
        except ValueError:
            part.group = part.group or "default"

    info.partitions = [p for p in parts if p.name]
    return bool(info.partitions)


def inspect(path: os.PathLike, deep: bool = True) -> SuperInfo:
    """Read the LP metadata at the start of a super image."""
    p = Path(path)
    info = SuperInfo(path=str(p))
    info.file_size = p.stat().st_size
    blob = _read_blob(p)

    if len(blob) < GEOMETRY_SIZE + 32:
        raise SuperError(f"{p.name} is too small to be a super image ({info.file_size} bytes)")

    magic, struct_size, checksum, metadata_max_size, slots, block_size = \
        struct.unpack_from("<IIIIII", blob, 0)
    if magic == LP_GEOMETRY_MAGIC:
        info.geometry_size = struct_size or GEOMETRY_SIZE
        info.metadata_max_size = metadata_max_size
        info.metadata_slots = max(1, slots)
        info.logical_block_size = block_size if block_size in (512, 4096) else 4096
        slot_offsets = [info.geometry_size + i * metadata_max_size
                        for i in range(info.metadata_slots)]
    else:
        # Some vendor images have no geometry header; slot 0 starts right after the first sector.
        info.notes.append("no liblp geometry header found; trying metadata at offset 4096")
        slot_offsets = [GEOMETRY_SIZE]
        info.metadata_max_size = 0

    for start in slot_offsets:
        if start + 0x14 > len(blob):
            continue
        if _parse_slot(blob, start, info):
            break

    if not info.partitions:
        version = f"{info.major}.{info.minor}" if info.major else "unknown"
        info.notes.append(
            f"could not read the partition list from this image (metadata version {version}). "
            "If this is an official super.img, convert it to raw first "
            "(`revive convert --mode raw`) - sparse containers hide the metadata from this "
            "reader in some vendor builds."
        )

    declared = info.total_size()
    if declared and declared > info.file_size:
        info.notes.append(
            f"partitions declare {human_size(declared)} but the file is only "
            f"{human_size(info.file_size)}: this image is truncated. Do not flash it."
        )
    return info


def list_partitions(path: os.PathLike) -> List[SuperPartition]:
    return inspect(path).partitions


def extract(path: os.PathLike, name: str, out_path: os.PathLike,
            progress: ProgressFn = null_progress) -> Dict[str, Any]:
    """Write one logical partition out as a plain image (LINEAR extents only)."""
    info = inspect(path)
    part = info.find(name)
    if part is None:
        available = ", ".join(p.name for p in info.partitions[:20]) or "none readable"
        raise SuperError(f"partition {name!r} is not in this super image. Found: {available}")

    unsupported = sorted({e.type_name for e in part.extents if e.target_type != TARGET_LINEAR})
    sparse_extents = [e for e in part.extents if e.target_type == TARGET_ANDROID_SPARSE]
    if unsupported and not sparse_extents:
        raise SuperError(
            f"{name} uses extent types {unsupported} that have no file offset in this layout; "
            "extract from a raw super image or use the vendor tool for this partition"
        )

    src = Path(path)
    dst = Path(out_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with src.open("rb") as fin, dst.open("wb") as fout:
        for extent in part.extents:
            if extent.target_type == TARGET_ZERO or extent.target_type == TARGET_FILL:
                fill = b"\x00" if extent.target_type == TARGET_ZERO else b"\xff"
                remaining = extent.size
                while remaining > 0:
                    block = min(remaining, 4 * 1024 * 1024)
                    fout.write(fill * block)
                    written += block
                    remaining -= block
                    progress(written, part.size, f"writing {name}")
                continue
            if extent.target_type != TARGET_LINEAR:
                raise SuperError(f"{name} contains a {extent.type_name} extent that this reader "
                                 "cannot map to a file offset; nothing further was written")
            offset = extent.target_data * 512
            if offset + extent.size > info.file_size:
                raise SuperError(f"{name} points past the end of the image (offset {offset} + "
                                 f"{extent.size} > {info.file_size}); the image is truncated")
            fin.seek(offset)
            remaining = extent.size
            while remaining > 0:
                block = fin.read(min(remaining, 4 * 1024 * 1024))
                if not block:
                    break
                fout.write(block)
                written += len(block)
                remaining -= len(block)
                progress(written, part.size, f"extracting {name}")
    return {"partition": name, "output": str(dst), "size": written,
            "extents": len(part.extents), "declared_size": part.size}
