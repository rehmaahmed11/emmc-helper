"""GUID Partition Table reader, validator and repair tool.

Dumps from MediaTek/Qualcomm tools are usually a whole eMMC image starting at LBA 0, but they
can also be a UF2-style image with a header, or a partial read that starts mid-disk. Everything
here therefore takes a ``disk_offset``, and the reader searches a small window for the GPT when
the caller does not know where it is.

The repair path is real: recomputing the CRCs and rewriting the backup table turns a dump whose
header was corrupted by an interrupted write back into something mountable, without touching a
single byte of partition data.
"""
from __future__ import annotations

import os
import struct
import uuid as uuid_mod
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..util import Finding, human_size

GPT_SIGNATURE = b"EFI PART"
GPT_HEADER_SIZE = 92
GPT_ENTRY_SIZE = 128
DEFAULT_ENTRY_COUNT = 128
SEARCH_WINDOW = 4 * 1024 * 1024

TYPE_NAMES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft basic data",
    "21686148-6449-6e6f-744e-656564454649": "BIOS boot",
    "1e5f7fbd-1a5e-4b8f-9c2a-2c8b5a4b1e5f": "Android (custom)",
}
KNOWN_ANDROID_TYPES = {
    "1e5f7fbd-1a5e-4b8f-9c2a-2c8b5a4b1e5f",
}


class GptError(Exception):
    pass


@dataclass
class PartitionEntry:
    index: int = 0
    name: str = ""
    type_guid: str = ""
    unique_guid: str = ""
    first_lba: int = 0
    last_lba: int = 0
    attributes: int = 0
    sector_size: int = 512
    disk_offset: int = 0

    @property
    def sector_count(self) -> int:
        return max(0, self.last_lba - self.first_lba + 1)

    @property
    def size(self) -> int:
        return self.sector_count * self.sector_size

    @property
    def offset(self) -> int:
        return self.disk_offset + self.first_lba * self.sector_size

    @property
    def end_offset(self) -> int:
        return self.offset + self.size

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type_guid.lower(), self.type_guid)

    @property
    def is_used(self) -> bool:
        return bool(self.type_guid.strip("0-")) and self.first_lba > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index, "name": self.name, "type_guid": self.type_guid,
            "type_name": self.type_name,
            "unique_guid": self.unique_guid, "first_lba": self.first_lba, "last_lba": self.last_lba,
            "sectors": self.sector_count, "size": self.size, "size_human": human_size(self.size),
            "offset": self.offset, "attributes": f"0x{self.attributes:x}",
        }


@dataclass
class Gpt:
    path: str = ""
    disk_offset: int = 0
    sector_size: int = 512
    header_crc_ok: bool = False
    entries_crc_ok: bool = False
    backup_used: bool = False
    primary_damaged: bool = False
    disk_guid: str = ""
    entry_count: int = DEFAULT_ENTRY_COUNT
    header_lba: int = 1
    backup_lba: int = 0
    first_usable_lba: int = 0
    last_usable_lba: int = 0
    disk_sectors: int = 0
    partitions: List[PartitionEntry] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.partitions)

    @property
    def used(self) -> List[PartitionEntry]:
        return [p for p in self.partitions if p.is_used]

    def find(self, name: str) -> Optional[PartitionEntry]:
        low = name.lower()
        for part in self.used:
            if part.name.lower() == low:
                return part
        return None

    def find_all(self, pattern: str) -> List[PartitionEntry]:
        low = pattern.lower()
        return [p for p in self.used if low in p.name.lower()]

    def by_slot(self, name: str) -> List[PartitionEntry]:
        """Every partition that belongs to a slot family: by_slot("boot") -> boot_a, boot_b, boot."""
        base = name.rstrip("_ab")
        if base.endswith("_"):
            base = base[:-1]
        out: List[PartitionEntry] = []
        for part in self.used:
            if part.name == name or part.name in (f"{base}_a", f"{base}_b") or \
                    part.name.rstrip("_ab") in (base, name):
                out.append(part)
        return out

    def overlaps(self) -> List[Tuple[PartitionEntry, PartitionEntry]]:
        out: List[Tuple[PartitionEntry, PartitionEntry]] = []
        parts = sorted(self.used, key=lambda p: p.first_lba)
        for a, b in zip(parts, parts[1:]):
            if b.first_lba <= a.last_lba:
                out.append((a, b))
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "disk_offset": self.disk_offset, "sector_size": self.sector_size,
            "header_crc_ok": self.header_crc_ok, "entries_crc_ok": self.entries_crc_ok,
            "backup_used": self.backup_used, "disk_guid": self.disk_guid,
            "entry_count": self.entry_count, "entry_count_used": len(self.used),
            "partition_count": len(self.used),
            "first_usable_lba": self.first_usable_lba, "last_usable_lba": self.last_usable_lba,
            "disk_sectors": self.disk_sectors,
            "disk_size": self.disk_sectors * self.sector_size,
            "disk_size_human": human_size(self.disk_sectors * self.sector_size),
            "partitions": [p.to_dict() for p in self.used],
            "findings": [f.to_dict() for f in self.findings],
        }


def _guid_str(raw: bytes) -> str:
    if len(raw) < 16:
        return ""
    return str(uuid_mod.UUID(bytes_le=raw[:16]))


def _parse_header(blob: bytes, offset: int, sector_size: int, disk_offset: int,
                  path: str, entries_abs: Optional[int] = None) -> Optional[Gpt]:
    if offset + GPT_HEADER_SIZE > len(blob):
        return None
    if blob[offset:offset + 8] != GPT_SIGNATURE:
        return None
    (_sig, revision, header_size, header_crc, _reserved, current_lba, backup_lba, first_usable,
     last_usable, disk_guid_raw, entry_lba, entry_count, entry_size, entries_crc) = \
        struct.unpack_from("<8sIIIIQQQQ16sQIII", blob, offset)
    if entry_size not in (128, 0) and entry_size > 4096:
        return None

    gpt = Gpt(path=path, disk_offset=disk_offset, sector_size=sector_size, disk_guid=_guid_str(disk_guid_raw),
              entry_count=entry_count, header_lba=current_lba, backup_lba=backup_lba,
              first_usable_lba=first_usable, last_usable_lba=last_usable)

    header_copy = bytearray(blob[offset:offset + header_size])
    struct.pack_into("<I", header_copy, 16, 0)
    gpt.header_crc_ok = zlib.crc32(bytes(header_copy)) & 0xFFFFFFFF == header_crc
    if header_size != GPT_HEADER_SIZE and header_size < GPT_HEADER_SIZE:
        gpt.findings.append(Finding("warn", "GPT header size is unusual",
                                    f"header_size={header_size}", []))

    entries_offset = entry_lba * sector_size if entries_abs is None else entries_abs
    total = entry_count * entry_size
    if entries_offset + total > len(blob):
        gpt.entries_crc_ok = False
        gpt.findings.append(Finding(
            "error", "Partition table extends past the end of the file",
            f"The table needs {human_size(total)} at offset {entries_offset} but the dump is "
            f"{human_size(len(blob))}. This dump is truncated.",
            ["Re-read the dump or use the backup table if it is present"]))
        return gpt

    entries_blob = blob[entries_offset:entries_offset + total]
    gpt.entries_crc_ok = zlib.crc32(entries_blob) & 0xFFFFFFFF == entries_crc
    for index in range(entry_count):
        base = index * entry_size
        if base + 128 > len(entries_blob):
            break
        type_guid = entries_blob[base:base + 16]
        if type_guid == b"\x00" * 16:
            continue
        unique = entries_blob[base + 16:base + 32]
        first, last, attrs = struct.unpack_from("<QQQ", entries_blob, base + 32)
        name_raw = entries_blob[base + 56:base + 128]
        name = name_raw.decode("utf-16-le", "replace").split("\x00")[0].strip()
        if not name:
            name = name_raw.split(b"\x00")[0].decode("utf-8", "replace").strip()
        part = PartitionEntry(name=name.strip(), type_guid=_guid_str(type_guid),
                              unique_guid=_guid_str(unique), first_lba=first, last_lba=last,
                              attributes=attrs, sector_size=sector_size, disk_offset=disk_offset)
        gpt.partitions.append(part)
    return gpt


def read_gpt_from_bytes(data: bytes, disk_offset: int = 0, sector_size: int = 512,
                        path: str = "") -> Optional[Gpt]:
    """Parse a GPT out of an in-memory blob. ``disk_offset`` is where the disk frame starts."""
    candidates: List[int] = []
    if disk_offset:
        candidates.append(disk_offset + sector_size)
    candidates += [disk_offset, sector_size, 512, 1024, 4096]
    tried = set()
    for offset in candidates:
        if offset in tried or offset < 0 or offset + GPT_HEADER_SIZE > len(data):
            continue
        tried.add(offset)
        if data[offset:offset + 8] != GPT_SIGNATURE:
            continue
        entry_lba = struct.unpack_from("<Q", data, offset + 72)[0]
        entries_abs = disk_offset + entry_lba * sector_size
        if entries_abs < 0 or entries_abs >= len(data):
            entries_abs = None
        gpt = _parse_header(data, offset, sector_size, disk_offset, path, entries_abs=entries_abs)
        if gpt is None:
            continue
        gpt.sector_size = sector_size
        for part in gpt.partitions:
            part.sector_size = sector_size
            part.disk_offset = disk_offset
        return gpt
    return None


def find_gpt_offset(fh, window: int = SEARCH_WINDOW, sector_size: int = 512) -> Optional[int]:
    """Search the first `window` bytes for a GPT signature. Returns a byte offset or None."""
    fh.seek(0)
    data = fh.read(window)
    index = data.find(GPT_SIGNATURE)
    if index < 0:
        return None
    # the signature must sit at the start of a sector
    for candidate in (sector_size, 512, 4096):
        if index % candidate == 0:
            return index
    return index


def read_gpt(path: os.PathLike, disk_offset: Optional[int] = None, sector_size: int = 512,
             try_backup: bool = True) -> Gpt:
    p = Path(path)
    size = p.stat().st_size
    with p.open("rb") as fh:
        if disk_offset is None:
            found = find_gpt_offset(fh, sector_size=sector_size)
            if found is None:
                raise GptError("no GPT found in the first 4 MiB of this file. If this is a "
                               "partial dump, pass the sector where the table starts; if the "
                               "table is gone, use `revive dump-scan` to find partitions by "
                               "signature.")
            disk_offset = found - 512 if found >= 512 else 0
            if found <= 4096:
                disk_offset = 0
        fh.seek(0)
        blob = fh.read(min(size, 256 * 1024 * 1024))
        gpt = _parse_header(blob, disk_offset + 512, sector_size, disk_offset, str(p))
        if gpt is not None:
            gpt.disk_sectors = max(0, (size - disk_offset) // sector_size)
            if gpt.header_crc_ok and gpt.entries_crc_ok:
                return gpt
            if not try_backup:
                return gpt
            gpt.findings.append(Finding(
                "warn", "Primary GPT is damaged",
                "header CRC ok" if gpt.header_crc_ok else "header CRC does not match, " +
                ("entries CRC ok" if gpt.entries_crc_ok else "entries CRC does not match"),
                ["`revive gpt-repair` can rebuild it from the backup copy"]))

        if not try_backup:
            raise GptError("the primary partition table is unreadable (and the caller asked not "
                           "to fall back to the backup copy)")
        # The backup header lives in the last sector; its entry array sits just before it.
        last_lba = ((size - disk_offset) // sector_size) - 1
        backup_offset = disk_offset + last_lba * sector_size
        if backup_offset < 0 or backup_offset + GPT_HEADER_SIZE > size:
            raise GptError("no usable GPT header or backup header found")
        window_start = max(disk_offset, backup_offset - (34 * sector_size))
        with p.open("rb") as fh2:
            fh2.seek(window_start)
            tail = fh2.read()
        backup = _parse_backup(tail, window_start, sector_size, disk_offset, str(p))
        if backup is None:
            raise GptError("no usable GPT header or backup header found")
        backup.backup_used = True
        backup.primary_damaged = True
        backup.disk_sectors = max(0, (size - disk_offset) // sector_size)
        backup.findings.append(Finding(
            "warn", "Primary GPT is damaged - using the backup copy instead",
            "The listing below comes from the backup table at the end of the disk. The phone will "
            "not boot from this image as-is.",
            ["Run `revive gpt-repair <dump>` (it is a dry run by default) to rebuild the primary "
             "table from this backup"]))
        return backup


def _parse_backup(tail: bytes, base: int, sector_size: int, disk_offset: int,
                  path: str) -> Optional[Gpt]:
    """Parse the backup table: the header is in the last sector, the entries just before it."""
    index = tail.rfind(GPT_SIGNATURE)
    if index < 0:
        return None
    entry_lba = struct.unpack_from("<Q", tail, index + 72)[0]
    entries_abs = disk_offset + entry_lba * sector_size - base
    if entries_abs < 0 or entries_abs >= len(tail):
        entries_abs = None
    gpt = _parse_header(tail, index, sector_size, disk_offset, path, entries_abs=entries_abs)
    return gpt


def is_protective_mbr(data: bytes) -> bool:
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return False
    for index in range(4):
        entry = data[446 + index * 16: 446 + (index + 1) * 16]
        if entry[4] == 0xEE:
            return True
    return False


# ---------------------------------------------------------------------------
# Building / repairing
# ---------------------------------------------------------------------------

def _pack_utf16(name: str) -> bytes:
    raw = name.encode("utf-16-le")[:72]
    return raw + b"\x00" * (72 - len(raw))


def build_gpt_bytes(partitions: Iterable[PartitionEntry], disk_sectors: int,
                    sector_size: int = 512, disk_guid: Optional[str] = None,
                    entry_count: int = DEFAULT_ENTRY_COUNT) -> Tuple[bytes, bytes, bytes]:
    """Return (protective MBR, primary table, backup table) as bytes.

    ``disk_sectors`` is the size of the device *after* any disk offset.
    """
    entries = list(partitions)
    entry_count = max(entry_count, 128)
    table_bytes = entry_count * GPT_ENTRY_SIZE
    table_sectors = (table_bytes + sector_size - 1) // sector_size
    first_usable = 2 + table_sectors
    last_usable = max(first_usable, disk_sectors - 2 - table_sectors)
    if disk_guid is None:
        disk_guid = str(uuid_mod.uuid4())
    disk_guid_raw = uuid_mod.UUID(disk_guid).bytes_le if disk_guid else uuid_mod.uuid4().bytes_le

    blob = bytearray(table_bytes)
    for index, part in enumerate(entries):
        if index >= entry_count:
            break
        base = index * GPT_ENTRY_SIZE
        struct.pack_into("<16s16sQQQ", blob, base,
                         uuid_mod.UUID(part.type_guid).bytes_le if part.type_guid else b"\x00" * 16,
                         uuid_mod.UUID(part.unique_guid).bytes_le if part.unique_guid
                         else uuid_mod.uuid4().bytes_le,
                         part.first_lba, part.last_lba, part.attributes)
        blob[base + 56:base + 128] = _pack_utf16(part.name)
    entries_crc = zlib.crc32(bytes(blob)) & 0xFFFFFFFF

    def header(current_lba: int, backup_lba: int, entry_lba: int) -> bytes:
        head = bytearray(GPT_HEADER_SIZE)
        struct.pack_into("<8sIIIIQQQQ16sQIII", head, 0,
                         GPT_SIGNATURE, 0x00010000, GPT_HEADER_SIZE, 0, 0, current_lba,
                         backup_lba, first_usable, last_usable, bytes(disk_guid_raw),
                         entry_lba, entry_count, GPT_ENTRY_SIZE, entries_crc)
        crc = zlib.crc32(bytes(head)) & 0xFFFFFFFF
        struct.pack_into("<I", head, 16, crc)
        return bytes(head)

    primary_header = header(1, disk_sectors - 1, 2)
    backup_header = header(disk_sectors - 1, 1, disk_sectors - 1 - table_sectors)

    protective = bytearray(sector_size)
    entry = bytearray(16)
    entry[0] = 0x00
    entry[1:4] = bytes([0x02, 0x00, 0xEE])        # CHS start (unused)
    entry[4] = 0xEE                                # GPT protective type
    entry[5:8] = bytes([0xFF, 0xFF, 0xFF])         # CHS end
    struct.pack_into("<II", entry, 8, 1, min(disk_sectors - 1, 0xFFFFFFFF))
    protective[446:462] = entry
    protective[510:512] = b"\x55\xaa"

    padding = b"\x00" * (table_sectors * sector_size - table_bytes)
    if len(primary_header) < sector_size:
        primary_header = primary_header + b"\x00" * (sector_size - len(primary_header))
    # The entry array starts at LBA 2 (the sector after the primary header) ...
    primary = primary_header + bytes(blob) + padding
    # ... and in the backup copy the header sits in the *last* sector, after the table.
    backup = bytes(blob) + padding + backup_header + b"\x00" * (sector_size - len(backup_header))
    return bytes(protective), primary, backup


def repair_gpt(path: os.PathLike, disk_offset: int = 0, sector_size: int = 512,
               dry_run: bool = True) -> Dict[str, Any]:
    """Recompute the GPT CRCs (and the backup copy) in a dump, in place."""
    p = Path(path)
    size = p.stat().st_size
    if size < 2 * sector_size:
        raise GptError("file is too small to contain a partition table")
    disk_sectors = (size - disk_offset) // sector_size

    try:
        gpt = read_gpt(path, disk_offset=disk_offset, sector_size=sector_size, try_backup=False)
    except GptError as exc:
        raise GptError(f"cannot repair: the primary GPT is unreadable ({exc})")
    if not gpt.partitions and gpt.header_crc_ok:
        # a valid header with an empty table: fall back to the backup copy for the layout
        try:
            gpt = read_gpt(path, disk_offset=disk_offset, sector_size=sector_size)
        except GptError:
            pass
    if not gpt.partitions:
        raise GptError("no GPT to repair was found in this file")

    mbr, primary, backup = build_gpt_bytes(gpt.partitions, disk_sectors, sector_size,
                                           disk_guid=gpt.disk_guid, entry_count=gpt.entry_count)
    changes: List[str] = []
    if not gpt.header_crc_ok:
        changes.append("CRCs recalculated: the header CRC did not match")
    if not gpt.entries_crc_ok:
        changes.append("CRCs recalculated: the partition entry CRC did not match")
    if gpt.backup_used:
        changes.append("layout recovered from the backup table; a new primary table is written")
    changes.append(f"write the protective MBR, the primary table and the backup table "
                   f"for {len(gpt.partitions)} partition(s)")
    report: Dict[str, Any] = {
        "path": str(p), "disk_offset": disk_offset, "sector_size": sector_size,
        "disk_sectors": disk_sectors, "partitions": len(gpt.partitions),
        "header_crc_was_ok": gpt.header_crc_ok, "entries_crc_was_ok": gpt.entries_crc_ok,
        "backup_used": gpt.backup_used, "dry_run": dry_run, "changes": changes,
        "sample": [part.to_dict() for part in gpt.partitions[:10]],
    }
    if dry_run:
        return report
    with p.open("r+b") as fh:
        fh.seek(disk_offset)
        fh.write(mbr)
        fh.write(primary)
        fh.seek(disk_offset + (disk_sectors - 1) * sector_size - len(backup) + sector_size)
        fh.seek(disk_offset + disk_sectors * sector_size - len(backup))
        fh.write(backup)
        fh.flush()
        os.fsync(fh.fileno())
    report["written"] = True
    return report
