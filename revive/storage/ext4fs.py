"""Filesystem identification: ext2/3/4, F2FS and EROFS superblocks.

Knowing that a partition holds a *dirty* ext4 filesystem, or that it is F2FS and therefore not
mountable on a rescue Linux without a module, changes what a repair session should do next. So
Revive parses the superblock instead of only matching a magic number.

Only the superblock is read: nothing here mounts, repairs or writes a filesystem. A dirty
filesystem is reported as a finding, with the safe command line to use if the user wants to
repair the *extracted copy*.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..util import human_size

SUPERBLOCK_OFFSET = 1024
EXT4_MAGIC = 0xEF53
F2FS_MAGIC = 0xF2F52010
EROFS_MAGIC = 0xE0F5E1E2

FS_STATES = {1: "clean", 2: "has errors", 4: "orphan recovery needed"}


@dataclass
class FsInfo:
    kind: str = "unknown"
    label: str = ""
    uuid: str = ""
    size: Optional[int] = None
    block_count: int = 0
    block_size: int = 0
    state: str = ""
    features: Dict[str, Any] = field(default_factory=dict)
    best_effort: bool = False
    notes: List[str] = field(default_factory=list)

    @property
    def is_dirty(self) -> bool:
        return bool(self.state) and self.state != "clean"

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "label": self.label, "uuid": self.uuid,
                "size": self.size, "size_human": human_size(self.size) if self.size else "",
                "block_count": self.block_count, "block_size": self.block_size,
                "state": self.state, "features": dict(self.features),
                "best_effort": self.best_effort, "notes": list(self.notes)}


def _uuid(blob: bytes) -> str:
    if len(blob) < 16:
        return ""
    return "-".join([blob[0:4].hex(), blob[4:6].hex(), blob[6:8].hex(),
                     blob[8:10].hex(), blob[10:16].hex()])


def _ext_superblock(data: bytes, offset: int = SUPERBLOCK_OFFSET) -> Optional[FsInfo]:
    if len(data) < offset + 0x100:
        return None
    sb = data[offset:offset + 1024]
    if struct.unpack_from("<H", sb, 0x38)[0] != EXT4_MAGIC:
        return None
    info = FsInfo(kind="ext2/3/4")
    block_count_lo = struct.unpack_from("<I", sb, 0x04)[0]
    log_block_size = struct.unpack_from("<I", sb, 0x18)[0]
    info.block_size = 1024 << log_block_size
    block_count_hi = 0
    if len(sb) >= 0x158:
        block_count_hi = struct.unpack_from("<I", sb, 0x150)[0] & 0xFFFF
    info.block_count = block_count_lo | (block_count_hi << 32)
    info.size = info.block_count * info.block_size
    info.label = sb[0x78:0x88].split(b"\x00")[0].decode("utf-8", "replace")
    info.uuid = _uuid(sb[0x68:0x78])
    info.state = FS_STATES.get(struct.unpack_from("<H", sb, 0x3A)[0], "unknown")
    feature_compat = struct.unpack_from("<I", sb, 0x5C)[0]
    feature_incompat = struct.unpack_from("<I", sb, 0x60)[0]
    info.features = {
        "journal": bool(feature_compat & 0x0004),
        "extents": bool(feature_incompat & 0x0040),
        "64bit": bool(feature_incompat & 0x0080),
        "compression": bool(feature_incompat & 0x0001),
        "huge_file": bool(feature_incompat & 0x0008),
        "flex_bg": bool(feature_incompat & 0x0200),
    }
    if info.features["extents"]:
        info.notes.append("ext4 (extents enabled)")
    elif info.features["journal"]:
        info.notes.append("ext3-style journaled filesystem")
    else:
        info.notes.append("ext2-style filesystem (no journal)")
    if info.is_dirty:
        info.notes.append("not cleanly unmounted; mount the extracted image read-only first, "
                          "then run `e2fsck -fy` on the copy")
    inodes = struct.unpack_from("<I", sb, 0x00)[0]
    per_group = struct.unpack_from("<I", sb, 0x28)[0]
    if inodes and per_group:
        info.notes.append(f"{inodes} inodes, {info.block_count} blocks of {info.block_size} bytes")
    return info


def _f2fs_superblock(data: bytes, offset: int = SUPERBLOCK_OFFSET) -> Optional[FsInfo]:
    """F2FS layout is only partially documented in public notes; marked best-effort."""
    if len(data) < offset + 256:
        return None
    sb = data[offset:offset + 256]
    if struct.unpack_from("<I", sb, 0)[0] != F2FS_MAGIC:
        return None
    info = FsInfo(kind="f2fs", best_effort=True)
    major, minor = struct.unpack_from("<HH", sb, 4)
    log_sectorsize = struct.unpack_from("<I", sb, 8)[0]
    log_blocksize = struct.unpack_from("<I", sb, 16)[0]
    blocks = struct.unpack_from("<Q", sb, 40)[0]
    info.block_size = 1 << (log_sectorsize + log_blocksize) if log_sectorsize + log_blocksize < 32 \
        else 4096
    if 512 <= info.block_size <= 65536:
        info.block_count = blocks
        info.size = blocks * info.block_size
    else:
        info.block_size = 0
        info.notes.append("the F2FS block-size fields are not plausible; the size is unknown")
    volume = sb[48:64].split(b"\x00")[0].decode("utf-8", "replace")
    info.label = volume if volume.isprintable() else ""
    info.notes.append(f"F2FS {major}.{minor} superblock (best-effort layout)")
    return info


def _erofs_superblock(data: bytes, offset: int = SUPERBLOCK_OFFSET) -> Optional[FsInfo]:
    if len(data) < offset + 64:
        return None
    sb = data[offset:offset + 64]
    if struct.unpack_from("<I", sb, 0)[0] != EROFS_MAGIC:
        return None
    info = FsInfo(kind="erofs", best_effort=True)
    blkszbits = sb[12]
    info.block_size = 1 << blkszbits if 9 <= blkszbits <= 16 else 4096
    inos = struct.unpack_from("<Q", sb, 16)[0]
    info.features = {"read_only": True, "extended_slots": sb[13] > 0}
    info.notes.append(f"read-only EROFS filesystem with {inos} inodes (best-effort layout)")
    return info


def read_fs(data: bytes, offset: int = SUPERBLOCK_OFFSET) -> Optional[FsInfo]:
    """Try each known superblock at `offset`. Returns None when nothing matches."""
    for probe in (_ext_superblock, _f2fs_superblock, _erofs_superblock):
        info = probe(data, offset)
        if info is not None:
            return info
    return None


def identify(data: bytes) -> Optional[FsInfo]:
    """Filesystem detection used by the dump report (kind names match the magic sniffer)."""
    info = read_fs(data)
    if info is None:
        return None
    if info.kind == "ext2/3/4":
        info.kind = "ext4"
    return info


def inspect_file(path, peek: int = 1024 * 1024) -> Optional[FsInfo]:
    """Identify the filesystem inside a partition image (API name used by the web UI)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(peek)
    except OSError:
        return None
    info = read_fs(data)
    if info is None:
        return None
    if not info.size:
        try:
            info.size = Path(path).stat().st_size
        except OSError:
            pass
    return info


def mount_hint(path) -> str:
    """The safest command line for looking inside an extracted image."""
    info = inspect_file(path)
    target = str(path)
    if info is None:
        return f"file {target} is not a filesystem Revive recognises"
    if info.kind == "f2fs":
        return f"sudo mount -t f2fs -o ro,loop {target} /mnt"
    if info.kind == "erofs":
        return f"sudo mount -t erofs -o ro,loop {target} /mnt"
    return f"sudo mount -t ext4 -o ro,noload,loop {target} /mnt"
