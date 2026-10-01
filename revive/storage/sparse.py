"""Android sparse image support (the format firmware packages ship ``system.img`` in).

Sparse images are chunked: raw data, a repeated fill value, or "don't care" (erased). The
encoder is what matters for repair work - a 4 GiB ``system.img`` becomes a 300 MiB file, which
is the difference between a backup fitting on a phone's SD card or not. The decoder verifies the
declared CRC when asked, which catches truncated downloads before they reach a phone.
"""
from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional

from ..util import ProgressFn, human_size, null_progress

SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4
CHUNK_NAMES = {CHUNK_RAW: "raw", CHUNK_FILL: "fill", CHUNK_DONT_CARE: "don't care",
               CHUNK_CRC32: "crc32", 0x0000: "end"}
HEADER_FMT = "<IHHHHIIII"
HEADER_SIZE = 28
CHUNK_HEADER_SIZE = 12

# The reference file size is roughly 4 GiB; a raw image bigger than this is almost certainly
# not something you want to expand inside a phone repair session, but the limit exists to
# catch corrupted headers rather than to restrict the user.
SANITY_LIMIT = 512 * 1024 * 1024 * 1024


class SparseError(Exception):
    pass


@dataclass
class SparseHeader:
    magic: int = SPARSE_MAGIC
    major: int = 1
    minor: int = 0
    file_hdr_sz: int = HEADER_SIZE
    chunk_hdr_sz: int = CHUNK_HEADER_SIZE
    blk_sz: int = 4096
    total_blks: int = 0
    total_chunks: int = 0
    image_checksum: int = 0
    version: str = ""
    raw_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"magic": f"0x{self.magic:08X}", "version": self.version or f"{self.major}.{self.minor}",
                "block_size": self.blk_sz, "total_blocks": self.total_blks,
                "total_chunks": self.total_chunks, "raw_size": self.raw_size,
                "raw_size_human": human_size(self.raw_size),
                "image_checksum": f"0x{self.image_checksum:08X}" if self.image_checksum else "",
                "crc_present": bool(self.image_checksum)}


@dataclass
class Chunk:
    type: int
    size: int = 0
    total_size: int = 0
    data: bytes = b""
    index: int = 0
    data_offset: int = 0      # file offset of the payload (for streaming RAW chunks)
    payload_size: int = 0
    blocks: int = 0           # taken from the chunk header - FILL/DONT_CARE carry no payload

    @property
    def type_name(self) -> str:
        return CHUNK_NAMES.get(self.type, f"unknown-{self.type:#x}")

    @property
    def block_count(self) -> int:
        if self.blocks:
            return self.blocks
        if self.size <= 0:
            return 0
        return self.total_size // max(self.size, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {"index": self.index, "type": self.type_name, "blocks": self.blocks,
                "payload_bytes": self.payload_size if self.payload_size else len(self.data),
                "blocks": self.block_count}


def parse_header(fh: BinaryIO) -> Optional[SparseHeader]:
    fh.seek(0)
    raw = fh.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        return None
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic != SPARSE_MAGIC:
        return None
    (_, major, minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks,
     checksum) = struct.unpack(HEADER_FMT, raw)
    header = SparseHeader(magic, major, minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks,
                          total_chunks, checksum)
    header.raw_size = total_blks * blk_sz
    return header


def is_sparse_file(path: os.PathLike) -> bool:
    try:
        with open(path, "rb") as fh:
            return parse_header(fh) is not None
    except OSError:
        return False


def read_chunks(fh: BinaryIO, header: SparseHeader, limit: int = 100000) -> List[Chunk]:
    """Read the chunk table. RAW payloads are described, not loaded, so a 4 GiB chunk is fine."""
    chunks: List[Chunk] = []
    offset = header.file_hdr_sz
    fh.seek(0, os.SEEK_END)
    file_size = fh.tell()
    for index in range(min(header.total_chunks, limit)):
        if offset + header.chunk_hdr_sz > file_size:
            break
        fh.seek(offset)
        raw = fh.read(header.chunk_hdr_sz)
        if len(raw) < header.chunk_hdr_sz:
            break
        ctype, _reserved, chunk_blocks, total_size = struct.unpack("<HHII", raw)
        payload_size = max(0, total_size - header.chunk_hdr_sz)
        data_offset = offset + header.chunk_hdr_sz
        chunk = Chunk(ctype, header.blk_sz, total_size, b"", index, data_offset, payload_size,
                      chunk_blocks)
        if ctype in (CHUNK_FILL, CHUNK_CRC32) and payload_size <= 64:
            fh.seek(data_offset)
            chunk.data = fh.read(payload_size)
        chunks.append(chunk)
        if ctype == 0x0000:
            break
        if total_size <= 0:
            break
        offset += total_size
    return chunks


def inspect(path: os.PathLike) -> Dict[str, Any]:
    """Summary of a sparse file: geometry, chunk mix, and whether it can be decoded at all."""
    with open(path, "rb") as fh:
        header = parse_header(fh)
        if header is None:
            raise SparseError(f"{Path(path).name} is not an Android sparse image")
        chunks = read_chunks(fh, header)
    counts: Dict[str, int] = {}
    for chunk in chunks:
        counts[chunk.type_name] = counts.get(chunk.type_name, 0) + 1
    data = header.to_dict()
    data["header"] = dict(data)
    data["chunk_counts"] = dict(counts)
    data.update({
        "chunk_mix": counts,
        "file_size": Path(path).stat().st_size,
        "expansion_ratio": round(header.raw_size / max(Path(path).stat().st_size, 1), 2),
        "complete": "end" in counts,
        "notes": [],
    })
    if header.chunk_hdr_sz != CHUNK_HEADER_SIZE:
        data["notes"].append(f"chunk header size is {header.chunk_hdr_sz}, not the usual 12")
    if not data["complete"]:
        data["notes"].append(
            "no end-of-image chunk found: the file may be truncated. Decoding will still work "
            "up to the last complete chunk, but do not flash a truncated image."
        )
    if header.raw_size > SANITY_LIMIT:
        data["notes"].append("declared raw size is implausibly large - the header may be corrupt")
    return data


def decode(src: os.PathLike, dst: os.PathLike, progress: ProgressFn = null_progress,
           verify_checksum: bool = False) -> Dict[str, Any]:
    """Expand a sparse image to raw bytes. Verifies the image CRC when asked."""
    with open(src, "rb") as fh:
        header = parse_header(fh)
        if header is None:
            raise SparseError(f"{Path(src).name} is not an Android sparse image")
        if header.raw_size > SANITY_LIMIT:
            raise SparseError("refusing to expand: the header declares an implausible raw size")
        chunks = read_chunks(fh, header)

    written = 0
    checksum = zlib.crc32(b"")
    stream_chunk = 4 * 1024 * 1024
    pending_fill: Optional[bytes] = None
    pending_fill_blocks = 0

    def emit(out, payload: bytes) -> None:
        nonlocal written, checksum
        out.write(payload)
        if verify_checksum and header.image_checksum:
            checksum = zlib.crc32(payload, checksum)
        written += len(payload)

    def flush_fill(out) -> None:
        nonlocal pending_fill_blocks
        if pending_fill_blocks and pending_fill is not None:
            remaining = pending_fill_blocks * header.blk_sz
            while remaining > 0:
                size = min(remaining, stream_chunk)
                emit(out, pending_fill * (size // len(pending_fill)))
                remaining -= size
        pending_fill_blocks = 0

    dst_path = Path(dst)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with dst_path.open("wb") as out, open(src, "rb") as fin:
        for chunk in chunks:
            progress(written, header.raw_size, f"expanding {dst_path.name}")
            if chunk.type in (CHUNK_FILL, CHUNK_DONT_CARE):
                if chunk.type == CHUNK_DONT_CARE:
                    value = b"\x00"
                else:
                    if len(chunk.data) != 4:
                        raise SparseError(
                            f"fill chunk {chunk.index} carries {len(chunk.data)} bytes; the "
                            "format requires exactly 4")
                    value = chunk.data
                if pending_fill is not None and value == pending_fill:
                    pending_fill_blocks += chunk.block_count
                else:
                    flush_fill(out)
                    pending_fill = value
                    pending_fill_blocks = chunk.block_count
                continue
            if chunk.type == CHUNK_RAW:
                flush_fill(out)
                fin.seek(chunk.data_offset)
                remaining = chunk.payload_size
                while remaining > 0:
                    block = fin.read(min(remaining, stream_chunk))
                    if not block:
                        break
                    emit(out, block)
                    remaining -= len(block)
                continue
            if chunk.type == CHUNK_CRC32:
                flush_fill(out)
                if len(chunk.data) == 4 and verify_checksum:
                    expected = struct.unpack("<I", chunk.data)[0]
                    actual = checksum & 0xFFFFFFFF
                    if expected and expected != actual:
                        raise SparseError(
                            f"chunk CRC mismatch at chunk {chunk.index}: expected "
                            f"0x{expected:08X}, computed 0x{actual:08X}. The image is corrupt.")
                continue
            if chunk.type == 0x0000:
                break
        flush_fill(out)
        out.flush()
        os.fsync(out.fileno())

    result: Dict[str, Any] = {
        "output": str(dst_path), "raw_size": written, "expected_size": header.raw_size,
        "chunks": len(chunks), "block_size": header.blk_sz,
    }
    if verify_checksum and header.image_checksum:
        result["checksum_ok"] = (checksum & 0xFFFFFFFF) == header.image_checksum
        result["checksum_expected"] = f"0x{header.image_checksum:08X}"
        result["checksum_actual"] = f"0x{checksum & 0xFFFFFFFF:08X}"
        if not result["checksum_ok"] and written:
            raise SparseError(
                f"image CRC mismatch: expected 0x{header.image_checksum:08X}, got "
                f"0x{checksum & 0xFFFFFFFF:08X}. This sparse image is corrupt - re-download it.")
    if written != header.raw_size:
        result["warning"] = (f"decoded {human_size(written)} of the declared "
                             f"{human_size(header.raw_size)}; the sparse file is truncated")
    return result


def _classify(block: bytes) -> tuple:
    """Return (kind, fill_byte) for one block: 'zero', 'fill' or 'raw'."""
    first = block[:1]
    if block == b"\x00" * len(block):
        return "zero", 0
    if block == first * len(block):
        return "fill", first[0]
    return "raw", 0


def encode(src: os.PathLike, dst: os.PathLike, block_size: int = 4096,
           progress: ProgressFn = null_progress, checksum: bool = True,
           max_raw_chunk: int = 8 * 1024 * 1024) -> Dict[str, Any]:
    """Compress a raw image into the sparse format.

    Runs of zero blocks become a single four-byte "don't care" chunk and runs of one other byte
    value become a single "fill" chunk, which is what makes an all-zeros 4 GiB dump collapse to a
    few kilobytes.
    """
    if block_size <= 0 or block_size % 4:
        raise SparseError("block size must be a positive multiple of 4")
    src_path, dst_path = Path(src), Path(dst)
    total = src_path.stat().st_size
    total_blocks = (total + block_size - 1) // block_size

    crc = zlib.crc32(b"") if checksum else 0
    chunk_count = 0
    emitted_blocks = 0

    pending_kind = ""
    pending_fill = 0
    pending_blocks = 0
    raw_buffer: List[bytes] = []
    raw_bytes = 0

    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with src_path.open("rb") as fin, dst_path.open("wb") as out:
        out.write(struct.pack(HEADER_FMT, SPARSE_MAGIC, 1, 0, HEADER_SIZE, CHUNK_HEADER_SIZE,
                              block_size, total_blocks, 0, 0))

        def write_chunk(chunk_type: int, payload: bytes, blocks: int) -> None:
            nonlocal chunk_count, emitted_blocks
            if blocks <= 0:
                return
            out.write(struct.pack("<HHII", chunk_type, 0, blocks,
                                  CHUNK_HEADER_SIZE + len(payload)))
            if payload:
                out.write(payload)
            chunk_count += 1
            emitted_blocks += blocks

        def flush() -> None:
            nonlocal pending_kind, pending_fill, pending_blocks, raw_buffer, raw_bytes
            if pending_kind == "zero":
                write_chunk(CHUNK_DONT_CARE, b"", pending_blocks)
            elif pending_kind == "fill":
                write_chunk(CHUNK_FILL, bytes([pending_fill]) * 4, pending_blocks)
            elif pending_kind == "raw":
                write_chunk(CHUNK_RAW, b"".join(raw_buffer), len(raw_buffer))
            pending_kind = ""
            pending_fill = 0
            pending_blocks = 0
            raw_buffer = []
            raw_bytes = 0

        done = 0
        while True:
            block = fin.read(block_size)
            if not block:
                break
            if len(block) < block_size:
                block = block + b"\x00" * (block_size - len(block))
            if checksum:
                crc = zlib.crc32(block, crc)
            done += block_size
            progress(min(done, total), total, f"packing {dst_path.name}")

            kind, fill = _classify(block)
            if kind != pending_kind or (kind == "fill" and fill != pending_fill):
                flush()
                pending_kind = kind
                pending_fill = fill
            if kind == "raw":
                raw_buffer.append(block)
                raw_bytes += len(block)
                if raw_bytes >= max_raw_chunk:
                    write_chunk(CHUNK_RAW, b"".join(raw_buffer), len(raw_buffer))
                    pending_kind = ""
                    pending_blocks = 0
                    raw_buffer = []
                    raw_bytes = 0
            else:
                pending_blocks += 1

        if pending_kind:
            flush()
        out.write(struct.pack("<HHII", 0x0000, 0, 0, CHUNK_HEADER_SIZE))
        out.seek(0)
        out.write(struct.pack(HEADER_FMT, SPARSE_MAGIC, 1, 0, HEADER_SIZE, CHUNK_HEADER_SIZE,
                              block_size, total_blocks, chunk_count,
                              crc & 0xFFFFFFFF if checksum else 0))
        out.flush()
        os.fsync(out.fileno())

    sparse_size = dst_path.stat().st_size
    return {
        "output": str(dst_path), "raw_size": total, "sparse_size": sparse_size,
        "block_size": block_size, "blocks": total_blocks, "chunks": chunk_count,
        "ratio": round(sparse_size / max(total, 1), 4),
        "image_checksum": f"0x{crc & 0xFFFFFFFF:08X}" if checksum else "",
    }


def verify_checksum(path: os.PathLike, progress: ProgressFn = null_progress) -> Dict[str, Any]:
    """CRC-check a sparse image without expanding it to disk (streams the chunks)."""
    import zlib as _zlib

    with open(path, "rb") as fh:
        header = parse_header(fh)
        if header is None:
            raise SparseError(f"{Path(path).name} is not an Android sparse image")
        chunks = read_chunks(fh, header)
        crc = _zlib.crc32(b"")
        written = 0
        stream = 4 * 1024 * 1024
        for chunk in chunks:
            progress(written, header.raw_size, f"checking {Path(path).name}")
            if chunk.type == CHUNK_RAW:
                fh.seek(chunk.data_offset)
                remaining = chunk.payload_size
                while remaining > 0:
                    block = fh.read(min(remaining, stream))
                    if not block:
                        break
                    crc = _zlib.crc32(block, crc)
                    written += len(block)
                    remaining -= len(block)
            elif chunk.type in (CHUNK_FILL, CHUNK_DONT_CARE):
                fill = chunk.data if chunk.type == CHUNK_FILL else b"\x00"
                if chunk.type == CHUNK_FILL and len(fill) != 4:
                    raise SparseError(f"fill chunk {chunk.index} has {len(fill)} bytes, expected 4")
                remaining = chunk.blocks * header.blk_sz
                while remaining > 0:
                    size = min(remaining, stream)
                    size -= size % len(fill)
                    if size == 0:
                        size = len(fill)
                    crc = _zlib.crc32(fill * (size // len(fill)), crc)
                    written += size
                    remaining -= size
    expected = header.image_checksum
    actual = crc & 0xFFFFFFFF
    result: Dict[str, Any] = {
        "raw_size": written, "declared_size": header.raw_size,
        "expected": f"0x{expected:08X}" if expected else "",
        "actual": f"0x{actual:08X}",
        "checksum_present": bool(expected),
        "ok": (actual == expected) if expected else written == header.raw_size,
    }
    if not expected:
        result["note"] = ("this sparse image carries no image checksum; the check only confirms "
                          "that the chunk structure expands to the declared size")
    if written != header.raw_size:
        result["ok"] = False
        result["note"] = (f"expands to {human_size(written)} but the header declares "
                          f"{human_size(header.raw_size)}: the file is truncated")
    return result


def count_chunks(path: os.PathLike) -> int:
    with open(path, "rb") as fh:
        header = parse_header(fh)
        if header is None:
            return 0
        return len(read_chunks(fh, header))
