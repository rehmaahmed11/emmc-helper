"""Creating and damaging the partition table of a virtual eMMC.

Every function here is a thin, deliberate wrapper around `revive.storage.gpt` - the same reader,
the same CRC recomputation and the same `build_gpt_bytes` that `revive gpt-list` and
`revive gpt-repair` use on a real dump. The lab only adds the *damage*: corrupt a header CRC,
flip a byte in the entry array, or erase a table copy outright.

That matters for the tests. When a lab device with a corrupted table is diagnosed, the verdict
comes from Revive's own GPT reader, so a PASS means the real tool found the real fault.
"""
from __future__ import annotations

import logging
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..storage import gpt as gpt_mod
from ..util import human_size
from .partitions import SECTOR, VirtualPartition

LOG = logging.getLogger("revive.lab.gpt")

# The GPT occupies: MBR (1) + header (1) + entries (32) at the front, entries + header at the back.
ENTRY_SECTORS = (128 * 128 + SECTOR - 1) // SECTOR      # 32 sectors of entry array
PRIMARY_HEADER_OFFSET = SECTOR                          # LBA 1
PRIMARY_ENTRIES_OFFSET = 2 * SECTOR                     # LBA 2
HEADER_CRC_FIELD = PRIMARY_HEADER_OFFSET + 16

# Damage modes for the GPT brick.
MODE_CRC = "crc"            # header and entry CRCs no longer match (interrupted write)
MODE_MISSING = "missing"    # the primary table is gone; the backup copy is intact
MODE_TOTAL = "total"        # both copies are gone: nothing to recover from
GPT_MODES = (MODE_CRC, MODE_MISSING, MODE_TOTAL)


class LabGptError(Exception):
    """Raised when a lab GPT operation cannot be performed."""


@dataclass
class GptState:
    """What Revive's GPT reader says about the image right now."""

    readable: bool = False
    primary_readable: bool = False
    header_crc_ok: bool = False
    entries_crc_ok: bool = False
    backup_used: bool = False
    primary_damaged: bool = False
    partition_count: int = 0
    disk_guid: str = ""
    disk_sectors: int = 0
    error: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_damaged(self) -> bool:
        return (not self.readable or not self.header_crc_ok or not self.entries_crc_ok
                or self.primary_damaged)

    @property
    def signals(self) -> List[str]:
        """Fault signals the diagnosis engine can be checked against.

        A primary header that is *gone* is reported as unreadable, not as a bad CRC: the two
        failures have different repairs, and the lab should not blur them.
        """
        out: List[str] = []
        if not self.readable:
            out.append("gpt_missing")
            return out
        if not self.primary_readable:
            out.append("gpt_primary_unreadable")
        else:
            if not self.header_crc_ok:
                out.append("gpt_header_crc_bad")
            if not self.entries_crc_ok:
                out.append("gpt_entries_crc_bad")
        if self.primary_damaged or self.backup_used:
            out.append("gpt_primary_damaged")
        if self.partition_count == 0:
            out.append("gpt_no_partitions")
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "readable": self.readable, "primary_readable": self.primary_readable,
            "header_crc_ok": self.header_crc_ok,
            "entries_crc_ok": self.entries_crc_ok, "backup_used": self.backup_used,
            "primary_damaged": self.primary_damaged, "partition_count": self.partition_count,
            "disk_guid": self.disk_guid, "disk_sectors": self.disk_sectors,
            "damaged": self.is_damaged, "signals": self.signals, "error": self.error,
            "findings": list(self.findings),
        }


# --------------------------------------------------------------------------------------
# Building
# --------------------------------------------------------------------------------------

def partition_entries(partitions: Sequence[VirtualPartition]) -> List[gpt_mod.PartitionEntry]:
    """Convert lab partitions into the entries `build_gpt_bytes` expects."""
    entries: List[gpt_mod.PartitionEntry] = []
    for part in partitions:
        entries.append(gpt_mod.PartitionEntry(
            index=len(entries), name=part.name,
            type_guid=gpt_mod.TYPE_NAMES and "0fc63daf-8483-4772-8e79-3d69d8477de4",
            unique_guid=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"revive-lab/{part.name}")),
            first_lba=part.first_lba, last_lba=part.last_lba, attributes=0,
        ))
    return entries


def write_gpt(image_path, partitions: Sequence[VirtualPartition], disk_sectors: Optional[int] = None,
              sector_size: int = SECTOR, disk_guid: Optional[str] = None) -> Dict[str, Any]:
    """Write the protective MBR, the primary table and the backup table into the image."""
    path = Path(image_path)
    if not path.exists():
        raise LabGptError(f"cannot write a GPT into {path}: the image does not exist")
    size = path.stat().st_size
    if disk_sectors is None:
        disk_sectors = size // sector_size
    if disk_sectors < (2 + ENTRY_SECTORS) * 2:
        raise LabGptError(f"the image is too small for a GPT: {human_size(size)}")

    guid = disk_guid or str(uuid.uuid4())
    entries = partition_entries(partitions)
    mbr, primary, backup = gpt_mod.build_gpt_bytes(entries, disk_sectors, sector_size,
                                                   disk_guid=guid)
    backup_offset = size - len(backup)
    if backup_offset < PRIMARY_ENTRIES_OFFSET + len(primary):
        raise LabGptError("the image is too small: the primary and backup tables would overlap")

    with path.open("r+b") as fh:
        fh.seek(0)
        fh.write(mbr)
        fh.write(primary)
        fh.seek(backup_offset)
        fh.write(backup)
        fh.flush()
    LOG.debug("wrote a %d partition GPT into %s (%s)", len(entries), path, human_size(size))
    return {
        "path": str(path), "disk_guid": guid, "partitions": len(entries),
        "disk_sectors": disk_sectors, "primary_bytes": len(primary),
        "backup_offset": backup_offset, "mbr_bytes": len(mbr),
    }


def read(image_path, sector_size: int = SECTOR) -> GptState:
    """Read the table the way Revive does, and describe its condition.

    Two reads, because they answer different questions. The first refuses the backup copy, so it
    reports the *primary* table's own CRCs - which is what a phone's bootloader looks at. The
    second is the normal read, which falls back to the backup and therefore reports the layout
    that is still recoverable.
    """
    path = Path(image_path)
    state = GptState()
    if not path.exists():
        state.error = f"{path} does not exist"
        return state

    primary: Optional[gpt_mod.Gpt] = None
    try:
        primary = gpt_mod.read_gpt(path, disk_offset=0, sector_size=sector_size,
                                   try_backup=False)
    except gpt_mod.GptError as exc:
        state.error = str(exc)

    effective = primary
    if primary is None or not (primary.header_crc_ok and primary.entries_crc_ok) \
            or not primary.used:
        # The primary is not good enough to boot from: see what the backup copy still holds.
        # The plain read searches the first 4 MiB for a signature, which will not find a backup
        # sitting at the end of the disk, so an explicit disk offset is tried as well.
        for attempt in (lambda: gpt_mod.read_gpt(path, sector_size=sector_size),
                        lambda: gpt_mod.read_gpt(path, disk_offset=0, sector_size=sector_size)):
            try:
                effective = attempt()
                state.error = ""
                break
            except gpt_mod.GptError as exc:
                if effective is None:
                    state.error = str(exc)
        if effective is None:
            return state

    if effective is None:
        return state

    state.readable = True
    state.primary_readable = primary is not None
    state.header_crc_ok = bool(primary and primary.header_crc_ok)
    state.entries_crc_ok = bool(primary and primary.entries_crc_ok)
    state.backup_used = bool(effective.backup_used)
    state.primary_damaged = bool(primary is None or effective.primary_damaged
                                 or not state.header_crc_ok or not state.entries_crc_ok)
    state.partition_count = len(effective.used)
    state.disk_guid = effective.disk_guid
    state.disk_sectors = effective.disk_sectors
    state.findings = [f.to_dict() for f in effective.findings]
    return state


# --------------------------------------------------------------------------------------
# Damage
# --------------------------------------------------------------------------------------

def corrupt_header_crc(image_path, value: int = 0x00000000) -> Dict[str, Any]:
    """Overwrite the primary header's CRC field: the classic interrupted-write damage."""
    path = Path(image_path)
    _require_image(path)
    with path.open("r+b") as fh:
        fh.seek(HEADER_CRC_FIELD)
        before = struct.unpack("<I", fh.read(4))[0]
        fh.seek(HEADER_CRC_FIELD)
        fh.write(struct.pack("<I", value & 0xFFFFFFFF))
    LOG.debug("corrupted the GPT header CRC (0x%08X -> 0x%08X)", before, value)
    return {"damage": "header_crc", "before": f"0x{before:08X}", "after": f"0x{value & 0xFFFFFFFF:08X}",
            "offset": HEADER_CRC_FIELD}


def corrupt_entries_crc(image_path, byte_offset: int = 40) -> Dict[str, Any]:
    """Overwrite four bytes of the primary entry array.

    The entries stay parseable, so `gpt-repair` can rebuild the table. The damage is written as
    a fixed pattern rather than by XOR, because XOR is its own inverse: bricking a device twice
    would silently undo the corruption and the lab would report a fault it no longer has.
    """
    path = Path(image_path)
    _require_image(path)
    target = PRIMARY_ENTRIES_OFFSET + byte_offset
    pattern = b"\xA5\x5A\xA5\x5A"
    with path.open("r+b") as fh:
        fh.seek(target)
        before = fh.read(4)
        if len(before) < 4:
            raise LabGptError("the entry array is shorter than expected")
        if before == pattern:
            pattern = b"\x5A\xA5\x5A\xA5"
        fh.seek(target)
        fh.write(pattern)
    LOG.debug("corrupted the primary entry array at 0x%x", target)
    return {"damage": "entries", "offset": target, "before": before.hex(),
            "after": pattern.hex()}


def erase_primary(image_path) -> Dict[str, Any]:
    """Zero the protective MBR and the whole primary table. The backup copy survives."""
    path = Path(image_path)
    _require_image(path)
    length = PRIMARY_ENTRIES_OFFSET + ENTRY_SECTORS * SECTOR
    with path.open("r+b") as fh:
        fh.seek(0)
        fh.write(b"\x00" * length)
        fh.flush()
    LOG.debug("erased the primary table (%s)", human_size(length))
    return {"damage": "primary_erased", "bytes_zeroed": length}


def erase_backup(image_path) -> Dict[str, Any]:
    """Zero the backup table at the end of the image."""
    path = Path(image_path)
    _require_image(path)
    length = ENTRY_SECTORS * SECTOR + SECTOR
    size = path.stat().st_size
    if size < length:
        raise LabGptError("the image is too small to hold a backup table")
    with path.open("r+b") as fh:
        fh.seek(size - length)
        fh.write(b"\x00" * length)
        fh.flush()
    LOG.debug("erased the backup table (%s)", human_size(length))
    return {"damage": "backup_erased", "bytes_zeroed": length, "offset": size - length}


def damage(image_path, mode: str = MODE_CRC) -> Dict[str, Any]:
    """Apply one of the GPT damage modes."""
    mode = (mode or MODE_CRC).lower()
    if mode not in GPT_MODES:
        raise LabGptError(f"unknown GPT damage mode {mode!r}; expected one of {', '.join(GPT_MODES)}")
    actions: List[Dict[str, Any]] = []
    if mode == MODE_CRC:
        actions.append(corrupt_header_crc(image_path))
        actions.append(corrupt_entries_crc(image_path))
    elif mode == MODE_MISSING:
        actions.append(erase_primary(image_path))
    else:
        actions.append(erase_primary(image_path))
        actions.append(erase_backup(image_path))
    state = read(image_path)
    return {"mode": mode, "actions": actions, "gpt": state.to_dict()}


def _require_image(path: Path) -> None:
    if not path.exists():
        raise LabGptError(f"{path} does not exist - create the device first")
    if path.stat().st_size < 4 * 1024 * 1024:
        raise LabGptError(f"{path} is too small to be a lab eMMC image")


# --------------------------------------------------------------------------------------
# Repair
# --------------------------------------------------------------------------------------

def repair(image_path, apply: bool = True, sector_size: int = SECTOR,
           layout: Optional[Sequence[VirtualPartition]] = None) -> Dict[str, Any]:
    """Repair the table using Revive's own repair path, falling back to a backup rebuild.

    `revive gpt-repair` recomputes CRCs and rewrites both copies. When the primary header is
    gone entirely it cannot find the table to repair, and the correct next step - the one the
    tool's own findings recommend - is to rebuild the primary table from the backup copy. That
    fallback is done here with `read_gpt` + `build_gpt_bytes`, so it is still Revive code doing
    the work.
    """
    path = Path(image_path)
    _require_image(path)
    before = read(path, sector_size)
    report: Dict[str, Any] = {
        "path": str(path), "apply": apply, "before": before.to_dict(),
        "method": "", "changes": [], "partitions": before.partition_count,
    }
    if not before.is_damaged:
        report["method"] = "none"
        report["changes"].append("the table is already consistent: nothing to repair")
        report["after"] = before.to_dict()
        return report

    try:
        result = gpt_mod.repair_gpt(path, sector_size=sector_size, dry_run=not apply)
        report["method"] = "revive.gpt.repair_gpt"
        report["changes"].extend(result.get("changes", []))
        report["partitions"] = result.get("partitions", before.partition_count)
    except gpt_mod.GptError as exc:
        LOG.info("gpt-repair could not run (%s); rebuilding the primary table", exc)
        report["changes"].append(f"`gpt-repair` could not read the primary table ({exc})")
        try:
            rebuilt = rebuild_primary_from_backup(path, sector_size=sector_size, apply=apply)
        except LabGptError as backup_exc:
            if not layout:
                raise LabGptError(
                    f"{backup_exc}. Both table copies are gone, so there is nothing on the disk "
                    "to rebuild from; supply the device's partition layout (what a scatter or "
                    "rawprogram file provides) to rewrite it.") from backup_exc
            # Both copies are gone. What a technician does then is rewrite the table from the
            # firmware layout, which is exactly what the lab's own partition map is.
            LOG.info("the backup table is gone too; rewriting the table from the device layout")
            info = write_gpt(path, [p for p in layout if p.size > 0],
                             disk_sectors=path.stat().st_size // sector_size,
                             sector_size=sector_size)
            report["method"] = "rewrite_from_layout"
            report["changes"].append(str(backup_exc))
            report["changes"].append("both table copies were gone: the partition table was "
                                     f"rewritten from the device's own layout "
                                     f"({info['partitions']} partitions)")
            report["partitions"] = info["partitions"]
            report["rebuild"] = info
        else:
            report["method"] = "rebuild_from_backup"
            report["changes"].extend(rebuilt["changes"])
            report["partitions"] = rebuilt["partitions"]
            report["rebuild"] = {k: v for k, v in rebuilt.items() if k != "changes"}

    report["after"] = read(path, sector_size).to_dict() if apply else before.to_dict()
    return report


def rebuild_primary_from_backup(image_path, sector_size: int = SECTOR,
                                apply: bool = True) -> Dict[str, Any]:
    """Read the backup table and write a fresh primary table (and MBR) from it."""
    path = Path(image_path)
    _require_image(path)
    size = path.stat().st_size
    disk_sectors = size // sector_size
    changes: List[str] = []
    try:
        parsed = gpt_mod.read_gpt(path, disk_offset=0, sector_size=sector_size, try_backup=True)
    except gpt_mod.GptError as exc:
        raise LabGptError(f"the backup table is unusable too ({exc}); the layout must be rebuilt "
                          "from the device's scatter/rawprogram file") from exc
    if not parsed.used:
        raise LabGptError("the backup table lists no partitions - there is nothing to rebuild from")

    entries = [gpt_mod.PartitionEntry(
        index=index, name=part.name, type_guid=part.type_guid, unique_guid=part.unique_guid,
        first_lba=part.first_lba, last_lba=part.last_lba, attributes=part.attributes)
        for index, part in enumerate(parsed.used)]
    mbr, primary, backup = gpt_mod.build_gpt_bytes(entries, disk_sectors, sector_size,
                                                   disk_guid=parsed.disk_guid or None)
    changes.append(f"layout recovered from the backup table ({len(entries)} partitions)")
    changes.append("protective MBR, primary table and backup table rewritten with fresh CRCs")
    if apply:
        with path.open("r+b") as fh:
            fh.seek(0)
            fh.write(mbr)
            fh.write(primary)
            fh.seek(size - len(backup))
            fh.write(backup)
            fh.flush()
    return {"path": str(path), "apply": apply, "partitions": len(entries),
            "disk_guid": parsed.disk_guid, "changes": changes}


def verify(image_path, expected_partitions: Sequence[str],
           sector_size: int = SECTOR) -> Dict[str, Any]:
    """Check the table against the layout the device is supposed to have."""
    state = read(image_path, sector_size)
    missing: List[str] = []
    found: List[str] = []
    if state.readable:
        try:
            parsed = gpt_mod.read_gpt(Path(image_path), disk_offset=0, sector_size=sector_size)
            names = {p.name.lower() for p in parsed.used}
            for name in expected_partitions:
                (found if name.lower() in names else missing).append(name)
        except gpt_mod.GptError as exc:
            missing = list(expected_partitions)
            state.error = str(exc)
    else:
        missing = list(expected_partitions)
    ok = (not state.is_damaged) and not missing
    return {
        "ok": ok, "gpt": state.to_dict(), "expected": len(expected_partitions),
        "found": found, "missing": missing,
        "signals": state.signals,
        "detail": ("the table is consistent and every expected partition is present" if ok else
                   "; ".join(filter(None, [
                       state.error,
                       ("missing partitions: " + ", ".join(missing)) if missing else "",
                       ("table damage: " + ", ".join(state.signals)) if state.signals else "",
                   ]))),
    }
