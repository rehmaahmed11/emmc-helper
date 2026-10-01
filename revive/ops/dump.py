"""Whole-disk dump surgery: analyse, extract, and recover partitions from a raw read.

A dump is what users actually have when a phone is dead: 16-256 GiB of bytes read out with
whatever tool still worked. Revive's job is to turn that blob into something usable - find the
table (even when the primary copy is gone), say what each partition is, and pull them out with
checksums so the user knows the extraction is trustworthy.

Everything here is read-only towards the dump. Extractions go to new files.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..storage import bootimg, ext4fs, gpt as gpt_mod, magic, superimg
from ..util import (Finding, ProgressFn, SEV_ERROR, SEV_FATAL, SEV_INFO, SEV_OK, SEV_WARN,
                   human_size, null_progress, sha256_file)

PROBE_BYTES = 1024 * 1024
SCAN_CHUNK = 8 * 1024 * 1024
SCAN_OVERLAP = 64 * 1024

# Partitions every phone needs for the tools to be able to do anything.
ESSENTIAL = ("preloader", "boot", "super", "system", "userdata", "nvram", "proinfo")

SCAN_SIGNATURES: List[tuple] = [
    (b"EFI PART", "GPT header", "primary or backup partition table"),
    (b"ANDROID!", "boot image", "Android boot image (boot/recovery)"),
    (b"VNDRBOOT", "vendor_boot image", "Android vendor_boot image"),
    (b"\xed\x26\xff\x3a", "sparse image", "Android sparse image"),
    (b"hsqs", "squashfs", "squashfs filesystem"),
    (b"\x7fELF", "ELF", "ELF binary (loader or firmware)"),
    (b"\x88\x16\x88\x58", "MTK header", "MediaTek image header"),
    (b"PK\x03\x04", "ZIP archive", "ZIP container"),
    (b"\x67\x44\x6c\x61", "super image", "Android super.img (logical partitions)"),
    (b"EMMC_BOOT", "MTK preloader", "MediaTek preloader (stage 1 boot)"),
    (b"MTK_DOWNLOAD_AGENT", "MTK loader", "MediaTek download agent"),
    (b"\x45\x46\x49\x20\x50\x41\x52\x54", "GPT header", "primary or backup partition table"),
]

SCAN_AT_OFFSETS = [
    (0x438, b"\x53\xef", "ext4", "ext4 filesystem superblock"),
    (0x400, None, "f2fs", "F2FS filesystem superblock"),
    (0x400, None, "erofs", "EROFS filesystem superblock"),
]


@dataclass
class DumpPartition:
    name: str = ""
    offset: int = 0
    size: int = 0
    kind: str = "unknown"
    detail: str = ""
    fs_label: str = ""
    issues: List[str] = field(default_factory=list)
    source: str = "gpt"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "offset": self.offset, "offset_hex": f"0x{self.offset:x}",
            "size": self.size, "size_human": human_size(self.size), "kind": self.kind,
            "detail": self.detail, "fs_label": self.fs_label, "issues": list(self.issues),
            "source": self.source,
        }


@dataclass
class DumpReport:
    path: str = ""
    file_size: int = 0
    gpt_offset: Optional[int] = None
    sector_size: int = 512
    header_crc_ok: bool = True
    entries_crc_ok: bool = True
    backup_used: bool = False
    disk_guid: str = ""
    partitions: List[DumpPartition] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    unaccounted: int = 0
    scan_hits: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def accounted(self) -> int:
        return sum(p.size for p in self.partitions)

    def find(self, name: str) -> Optional[DumpPartition]:
        low = name.lower()
        for part in self.partitions:
            if part.name.lower() == low:
                return part
        for part in self.partitions:
            if low in part.name.lower():
                return part
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "file_size": self.file_size,
            "file_size_human": human_size(self.file_size), "gpt_offset": self.gpt_offset,
            "sector_size": self.sector_size, "header_crc_ok": self.header_crc_ok,
            "entries_crc_ok": self.entries_crc_ok, "backup_used": self.backup_used,
            "disk_guid": self.disk_guid, "partition_count": len(self.partitions),
            "total_size": self.accounted, "total_size_human": human_size(self.accounted),
            "unaccounted": self.unaccounted,
            "unaccounted_human": human_size(self.unaccounted),
            "partitions": [p.to_dict() for p in self.partitions],
            "findings": [f.to_dict() for f in self.findings],
            "scan_hits": self.scan_hits,
        }


def _probe(dump_path: Path, part: DumpPartition, file_size: int) -> None:
    """Sample a partition and describe what it holds."""
    if part.size <= 0:
        part.issues.append("zero-length region")
        return
    readable = max(0, min(part.size, file_size - part.offset))
    if readable < part.size:
        part.issues.append(f"only {human_size(readable)} of {human_size(part.size)} is present "
                           "(dump is truncated here)")
    try:
        with dump_path.open("rb") as fh:
            fh.seek(part.offset)
            head = fh.read(min(PROBE_BYTES, max(readable, 0)))
            if len(head) < 512 and readable > 0:
                fh.seek(max(0, part.offset))
                head = fh.read(PROBE_BYTES)
    except OSError as exc:
        part.issues.append(f"could not read: {exc}")
        return
    if not head:
        part.kind, part.detail = "empty", "no data at this offset"
        part.issues.append("nothing to read (the dump ends before this partition)")
        return

    sig = magic.sniff_bytes(head, size=part.size)
    part.kind, part.detail = sig.kind, sig.description
    if sig.kind in ("blank", "empty"):
        part.issues.append("all 0x00/0xFF - either unused on this model, or the read failed here")

    fs = ext4fs.identify(head)
    if fs is not None and fs.kind != "unknown":
        part.kind = "ext4" if fs.kind == "ext2/3/4" else fs.kind
        part.detail = f"{fs.kind} filesystem" + (f", {fs.block_size} byte blocks" if fs.block_size else "")
        part.fs_label = fs.label
        if fs.state and fs.state != "clean":
            part.issues.append(f"filesystem state: {fs.state}")
        if fs.size and part.size and abs(fs.size - part.size) > 64 * 1024 * 1024:
            part.issues.append(
                f"filesystem declares {human_size(fs.size)} but the partition is "
                f"{human_size(part.size)} - one of the two numbers is wrong")
        return

    if sig.kind == "gpt":
        part.issues.append("this region contains another partition table - unusual, check the "
                           "layout before writing here")
    elif sig.kind == "boot_image":
        try:
            image = bootimg.parse(_slice_to_temp(dump_path, part))
            part.detail = (f"boot image v{image.header_version}, kernel "
                           f"{human_size(image.section('kernel').size) if image.section('kernel') else '?'}"
                           f", {image.os_version or 'no Android version field'}")
            if image.mtk_header:
                part.issues.append("MediaTek kernel header present (0x88168858 + 512 byte offset)")
            if image.cmdline:
                part.issues.append(f"cmdline: {image.cmdline[:120]}")
        except Exception as exc:                              # noqa: BLE001
            part.detail = f"boot image (header could not be parsed: {exc})"
    elif sig.kind == "super_image":
        try:
            info = superimg.inspect(_slice_to_temp(dump_path, part))
            part.detail = (f"super image with {len(info.partitions)} logical partitions: "
                           + ", ".join(p.name for p in info.partitions[:8]))
        except Exception:                                     # noqa: BLE001
            part.detail = "Android super image (dynamic partitions)"
    elif sig.kind == "android_sparse":
        part.issues.append("stored as an Android sparse image; convert before mounting or "
                           "patching it")


def _slice_to_temp(dump_path: Path, part: DumpPartition) -> str:
    """Copy a partition region to a temp file so the storage readers can parse it."""
    import tempfile

    handle = tempfile.NamedTemporaryFile(prefix="revive-probe-", suffix=".img", delete=False)
    try:
        with dump_path.open("rb") as src, open(handle.name, "wb") as out:
            src.seek(part.offset)
            remaining = min(part.size, 512 * 1024 * 1024)
            while remaining > 0:
                block = src.read(min(remaining, 4 * 1024 * 1024))
                if not block:
                    break
                out.write(block)
                remaining -= len(block)
    finally:
        handle.close()
    return handle.name


def analyse(path: os.PathLike, deep: bool = True, probe_per_partition: bool = True,
            progress: ProgressFn = null_progress) -> DumpReport:
    p = Path(path)
    report = DumpReport(path=str(p), file_size=p.stat().st_size)
    if not p.is_file():
        raise FileNotFoundError(f"{p} is not a file")

    try:
        parsed = gpt_mod.read_gpt(p)
    except gpt_mod.GptError as exc:
        report.findings.append(Finding(
            SEV_ERROR, "No partition table in this dump", str(exc),
            ["If this is a partial read (a single partition or a region), that is expected - use "
             "`revive dump-scan` or read the region with the tools that made it",
             "If it was supposed to be a full dump, the table region was probably not read: "
             "dumps must start at LBA 0 (offset 0) to include the GPT",
             "Try `revive dump-scan <file>` to locate partitions by content signature instead"]))
        report.unaccounted = report.file_size
        if deep:
            report.scan_hits = scan(p)[:40]
        return report

    report.gpt_offset = parsed.disk_offset
    report.sector_size = parsed.sector_size
    report.header_crc_ok = parsed.header_crc_ok
    report.entries_crc_ok = parsed.entries_crc_ok
    report.backup_used = parsed.backup_used
    report.disk_guid = parsed.disk_guid

    if parsed.backup_used:
        report.findings.append(Finding(
            SEV_WARN, "The primary partition table is damaged - the backup copy was used",
            "The listing below comes from the backup GPT at the end of the dump. The phone will "
            "not boot from this dump as-is.",
            ["Run `revive gpt-repair <dump>` (dry-run first) to rebuild the primary table"]))

    for entry in parsed.used:
        part = DumpPartition(name=entry.name, offset=entry.offset, size=entry.size,
                             source="gpt")
        if part.offset + part.size > report.file_size:
            part.issues.append("extends past the end of the dump file")
        report.partitions.append(part)

    report.partitions.sort(key=lambda item: item.offset)
    if probe_per_partition:
        total = len(report.partitions) or 1
        for index, part in enumerate(report.partitions):
            progress(index + 1, total, f"probing {part.name}")
            _probe(p, part, report.file_size)

    table_overhead = (2 + max(1, (parsed.entry_count * 128) // parsed.sector_size)) * parsed.sector_size
    table_overhead += table_overhead      # primary + backup copy
    report.unaccounted = max(0, report.file_size - report.accounted - table_overhead)

    _dump_findings(report, parsed)
    if deep and (report.unaccounted > 64 * 1024 * 1024 or not report.partitions):
        report.scan_hits = scan(p)[:40]
    return report


def _dump_findings(report: DumpReport, parsed: gpt_mod.Gpt) -> None:
    names = {p.name.lower() for p in report.partitions}
    missing = [name for name in ESSENTIAL if name not in names]
    if missing and report.partitions:
        report.findings.append(Finding(
            SEV_WARN, "Some partitions a phone needs are not in this dump",
            ", ".join(missing),
            ["If you dumped a subset of partitions this is expected",
             "If you dumped everything, the dump is incomplete - re-read it before using it as a "
             "backup"]))

    blank = [p.name for p in report.partitions if p.kind in ("blank", "empty")]
    if blank:
        report.findings.append(Finding(
            SEV_WARN, f"{len(blank)} partition(s) read as blank",
            ", ".join(blank[:10]),
            ["Blank usually means the region was never written, or the read did not reach it",
             "Never restore a blank partition over a working one - check the source first"]))

    bad_fs = [(p.name, issue) for p in report.partitions for issue in p.issues
              if "filesystem state" in issue]
    if bad_fs:
        report.findings.append(Finding(
            SEV_WARN, f"{len(bad_fs)} filesystem(s) were not cleanly unmounted",
            "; ".join(f"{name}: {issue}" for name, issue in bad_fs[:5]),
            ["Mount with `ro` first if you are recovering data: `mount -o ro,loop <file> /mnt`",
             "A phone that died mid-write often leaves a dirty filesystem - it is usually "
             "repairable with `e2fsck -fy` on the extracted image"]))

    truncated = [p.name for p in report.partitions if p.offset + p.size > report.file_size]
    if truncated:
        report.findings.append(Finding(
            SEV_ERROR, f"The dump is truncated: {len(truncated)} partition(s) extend past the "
                       "end of the file",
            ", ".join(truncated[:10]),
            ["The dump is shorter than the layout declares: re-read the missing range or accept "
             "that these partitions cannot be extracted",
             "Do not flash this dump back: the tail of those partitions is missing"]))

    issues = [f for f in report.findings if f.severity in (SEV_ERROR, SEV_FATAL, SEV_WARN)]
    if not issues:
        report.findings.append(Finding(
            SEV_OK, "Dump looks complete and consistent",
            f"{len(report.partitions)} partitions, {human_size(report.accounted)} accounted for, "
            f"both GPT copies readable.", []))
    if report.unaccounted > max(64 * 1024 * 1024, report.file_size // 20):
        report.findings.append(Finding(
            SEV_INFO, f"{human_size(report.unaccounted)} of the dump is not in any partition",
            "That is normal for the space after the last partition, but a big gap can also mean "
            "the layout does not match the dump.",
            ["If you know the device had partitions past this point, the dump may come from a "
             "different model"]))


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _extract_range(dump_path: Path, part: DumpPartition, out_dir: Path,
                   progress: ProgressFn, chunk: int = 8 * 1024 * 1024) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{part.name}.img"
    if target.exists():
        from ..util import unique_path

        target = unique_path(target)
    file_size = dump_path.stat().st_size
    readable = max(0, min(part.size, file_size - part.offset))
    written = 0
    with dump_path.open("rb") as src, target.open("wb") as out:
        src.seek(part.offset)
        remaining = readable
        while remaining > 0:
            block = src.read(min(chunk, remaining))
            if not block:
                break
            out.write(block)
            written += len(block)
            remaining -= len(block)
            progress(written, part.size or readable, f"extracting {part.name}")
    result: Dict[str, Any] = {
        "partition": part.name, "name": part.name, "file": target.name, "output": str(target),
        "size": written, "size_human": human_size(written),
        "declared_size": part.size, "offset": part.offset,
        "sha256": sha256_file(target), "kind": part.kind,
    }
    if written < part.size:
        result["partial"] = True
        result["warning"] = (f"only {human_size(written)} of {human_size(part.size)} was present "
                             "in the dump; the extracted file is short")
    return result


def extract(dump_path: os.PathLike, name: str, out_dir: os.PathLike,
            progress: ProgressFn = null_progress) -> Dict[str, Any]:
    report = analyse(dump_path, deep=False, probe_per_partition=False)
    target = report.find(name)
    if target is None:
        available = ", ".join(p.name for p in report.partitions[:20]) or "none"
        raise ValueError(f"partition {name!r} is not in this dump. Available: {available}")
    return _extract_range(Path(dump_path), target, Path(out_dir), progress)


def extract_all(dump_path: os.PathLike, out_dir: os.PathLike, only: Optional[List[str]] = None,
                progress: ProgressFn = null_progress, max_partitions: int = 250) -> Dict[str, Any]:
    report = analyse(dump_path, deep=True, probe_per_partition=False)
    if not report.partitions:
        raise ValueError(
            "no partition table in this dump, so there is nothing to extract by name. Use "
            "`revive dump-scan <file>` to find partitions by signature instead.")
    wanted = {name.lower() for name in only} if only else None
    out_root = Path(out_dir)
    parts_root = out_root / "partitions"
    results: List[Dict[str, Any]] = []
    total_bytes = 0
    for part in report.partitions[:max_partitions]:
        if wanted is not None and part.name.lower() not in wanted:
            continue
        try:
            result = _extract_range(Path(dump_path), part, parts_root, progress)
        except OSError as exc:
            results.append({"partition": part.name, "error": str(exc)})
            continue
        total_bytes += int(result.get("size", 0))
        results.append(result)

    manifest = {
        "tool": "revive",
        "source": str(dump_path),
        "file_size": report.file_size,
        "gpt_offset": report.gpt_offset,
        "sector_size": report.sector_size,
        "header_crc_ok": report.header_crc_ok,
        "entries_crc_ok": report.entries_crc_ok,
        "partitions": results,
        "total_size": total_bytes,
    }
    manifest_path = out_root / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "out_dir": str(out_root), "manifest": str(manifest_path),
        "partitions": len([r for r in results if "error" not in r]),
        "failed": len([r for r in results if "error" in r]),
        "total_size": total_bytes, "total_size_human": human_size(total_bytes),
        "extracted": results,
    }


# ---------------------------------------------------------------------------
# Signature scan - for dumps with no usable table
# ---------------------------------------------------------------------------

def scan(dump_path: os.PathLike, max_bytes: int = 32 * 1024 * 1024 * 1024,
         alignment: int = 512) -> List[Dict[str, Any]]:
    """Find partitions by content signature in a dump whose partition table is gone."""
    p = Path(dump_path)
    file_size = p.stat().st_size
    limit = min(file_size, max_bytes)
    hits: List[Dict[str, Any]] = []
    seen: set = set()

    def record(offset: int, kind: str, label: str) -> None:
        if offset in seen:
            return
        seen.add(offset)
        hits.append({
            "offset": offset, "offset_hex": f"0x{offset:08x}", "kind": kind, "label": label,
            "aligned": offset % alignment == 0,
            "size_hint": "",
        })

    with p.open("rb") as fh:
        position = 0
        tail = b""
        while position < limit:
            fh.seek(position)
            chunk = fh.read(min(SCAN_CHUNK, limit - position))
            if not chunk:
                break
            buffer = tail + chunk
            base = position - len(tail)
            for needle, kind, label in SCAN_SIGNATURES:
                start = 0
                while True:
                    index = buffer.find(needle, start)
                    if index < 0:
                        break
                    record(base + index, kind, label)
                    start = index + 1
            # filesystem superblocks and LP metadata, at their fixed offsets inside a partition
            for rel_offset, needle, kind, label in SCAN_AT_OFFSETS:
                window = 0
                while rel_offset + window + 4 <= len(buffer):
                    probe_at = rel_offset + window
                    if probe_at + 4 > len(buffer):
                        break
                    magic_bytes = buffer[probe_at:probe_at + 4]
                    start_of_partition = base + probe_at - rel_offset
                    if start_of_partition % alignment == 0 and _matches_fs(magic_bytes, kind):
                        record(start_of_partition, kind, label)
                    window += alignment
            tail = buffer[-SCAN_OVERLAP:]
            position += len(chunk)
    hits.sort(key=lambda item: item["offset"])
    return hits


def _matches_fs(magic_bytes: bytes, kind: str) -> bool:
    import struct

    if kind == "ext4":
        return magic_bytes[:2] == b"\x53\xef"
    if kind == "f2fs":
        return struct.unpack("<I", magic_bytes)[0] == 0xF2F52010
    if kind == "erofs":
        return struct.unpack("<I", magic_bytes)[0] == 0xE0F5E1E2
    if kind == "super_image":
        return struct.unpack("<I", magic_bytes)[0] in (0x414C5030, 0x616C4467)
    return False
