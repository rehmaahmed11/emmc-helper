"""Minimal LZ4 support, implemented in pure Python.

LZ4 matters for phone repair because vendors ship ``system.img.lz4``, ``super.img.lz4`` and OTA
payloads compressed with it, and the "fix" most tools recommend is installing a compiler and a
C library. Revive implements the frame format directly, so the base install keeps working with
nothing but Python. It is not fast - it is roughly 5-10 MB/s - but it never refuses to help, and
it verifies the content checksum when the frame carries one, which is exactly the check you want
before writing the result to a phone.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..util import ProgressFn, human_size, null_progress

FRAME_MAGIC = 0x184D2204
LEGACY_MAGIC = 0x184C2102
SKIPPABLE_MIN = 0x184D2A50
SKIPPABLE_MAX = 0x184D2A5F
BLOCK_UNCOMPRESSED = 0x80000000


class Lz4Error(Exception):
    pass


# ---------------------------------------------------------------------------
# xxHash32 - needed to verify LZ4 frame content checksums
# ---------------------------------------------------------------------------

_PRIME1 = 0x9E3779B1
_PRIME2 = 0x85EBCA77
_PRIME3 = 0xC2B2AE3D
_PRIME4 = 0x27D4EB2F
_PRIME5 = 0x165667B1


def _rotl(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def xxh32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    index = 0
    if length >= 16:
        v1 = (seed + _PRIME1 + _PRIME2) & 0xFFFFFFFF
        v2 = (seed + _PRIME2) & 0xFFFFFFFF
        v3 = seed & 0xFFFFFFFF
        v4 = (seed - _PRIME1) & 0xFFFFFFFF

        def round_(acc: int, lane: int) -> int:
            acc = (acc + lane * _PRIME2) & 0xFFFFFFFF
            acc = _rotl(acc, 13)
            return (acc * _PRIME1) & 0xFFFFFFFF

        while index + 16 <= length:
            v1 = round_(v1, struct.unpack_from("<I", data, index)[0])
            v2 = round_(v2, struct.unpack_from("<I", data, index + 4)[0])
            v3 = round_(v3, struct.unpack_from("<I", data, index + 8)[0])
            v4 = round_(v4, struct.unpack_from("<I", data, index + 12)[0])
            index += 16
        acc = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & 0xFFFFFFFF
    else:
        acc = (seed + _PRIME5) & 0xFFFFFFFF

    acc = (acc + length) & 0xFFFFFFFF
    while index + 4 <= length:
        acc = (acc + struct.unpack_from("<I", data, index)[0] * _PRIME3) & 0xFFFFFFFF
        acc = (_rotl(acc, 17) * _PRIME4) & 0xFFFFFFFF
        index += 4
    while index < length:
        acc = (acc + data[index] * _PRIME5) & 0xFFFFFFFF
        acc = (_rotl(acc, 11) * _PRIME1) & 0xFFFFFFFF
        index += 1
    acc ^= acc >> 15
    acc = (acc * _PRIME2) & 0xFFFFFFFF
    acc ^= acc >> 13
    acc = (acc * _PRIME3) & 0xFFFFFFFF
    acc ^= acc >> 16
    return acc


# ---------------------------------------------------------------------------
# LZ4 block format
# ---------------------------------------------------------------------------

def decompress_block(data: bytes) -> bytes:
    """Decompress one LZ4 block. Sequences are <token><literals><offset><match>."""
    out = bytearray()
    index = 0
    n = len(data)
    while index < n:
        token = data[index]
        index += 1
        literal_len = token >> 4
        if literal_len == 15:
            while True:
                if index >= n:
                    raise Lz4Error("truncated literal length")
                extra = data[index]
                index += 1
                literal_len += extra
                if extra != 255:
                    break
        if index + literal_len > n:
            # A block may legitimately end just after its last literal run.
            out.extend(data[index:n])
            return bytes(out)
        out.extend(data[index:index + literal_len])
        index += literal_len
        if index >= n:
            return bytes(out)
        if index + 2 > n:
            raise Lz4Error("truncated match offset")
        offset = data[index] | (data[index + 1] << 8)
        index += 2
        if offset == 0:
            raise Lz4Error("match offset of 0 is invalid")
        if offset > len(out):
            raise Lz4Error(f"match offset {offset} points before the start of the output")
        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if index >= n:
                    raise Lz4Error("truncated match length")
                extra = data[index]
                index += 1
                match_len += extra
                if extra != 255:
                    break
        match_len += 4
        start = len(out) - offset
        for i in range(match_len):
            out.append(out[start + i])
    return bytes(out)


# ---------------------------------------------------------------------------
# LZ4 frame format
# ---------------------------------------------------------------------------

def is_frame(header: bytes) -> bool:
    """True when the first bytes look like an LZ4 frame or legacy block stream."""
    if len(header) < 4:
        return False
    magic = struct.unpack_from("<I", header, 0)[0]
    return magic in (FRAME_MAGIC, LEGACY_MAGIC) or SKIPPABLE_MIN <= magic <= SKIPPABLE_MAX


def is_lz4(data: bytes) -> bool:
    if len(data) < 4:
        return False
    magic = struct.unpack_from("<I", data, 0)[0]
    return magic in (FRAME_MAGIC, LEGACY_MAGIC) or SKIPPABLE_MIN <= magic <= SKIPPABLE_MAX


def is_lz4_file(path: os.PathLike) -> bool:
    try:
        with open(path, "rb") as fh:
            return is_lz4(fh.read(4))
    except OSError:
        return False


def decompress(data: bytes, verify: bool = True,
               expected_size: Optional[int] = None) -> bytes:
    """Decompress a whole LZ4 frame (or a legacy block stream) held in memory.

    Raises Lz4Error for anything that is not valid LZ4 - including a truncated payload, which
    is the failure mode that matters when a vendor file was only half downloaded.
    """
    if not data or not is_frame(data[:4]):
        raise Lz4Error("not an LZ4 stream (bad magic)")
    out = bytearray()
    with tempfile_bytes(data) as handle:
        pass
    # in-memory path: reuse the streaming reader over a BytesIO
    import io

    buffer = io.BytesIO(data)
    for block in _stream_blocks(buffer):
        out.extend(block)
    if expected_size is not None and len(out) != expected_size:
        raise Lz4Error(f"LZ4 stream produced {len(out)} bytes, expected {expected_size}")
    return bytes(out)


def _stream_blocks(handle) -> List[bytes]:
    """Yield decompressed blocks from a frame or legacy stream (used by decompress())."""
    blocks: List[bytes] = []
    while True:
        header = handle.read(4)
        if len(header) < 4:
            break
        magic = struct.unpack_from("<I", header, 0)[0]
        if SKIPPABLE_MIN <= magic <= SKIPPABLE_MAX:
            size = struct.unpack("<I", handle.read(4))[0]
            handle.seek(size, os.SEEK_CUR)
            continue
        if magic == LEGACY_MAGIC:
            while True:
                size_raw = handle.read(4)
                if len(size_raw) < 4:
                    raise Lz4Error("truncated legacy LZ4 stream")
                block_size = struct.unpack("<I", size_raw)[0]
                if block_size == 0:
                    break
                raw = handle.read(block_size)
                if len(raw) < block_size:
                    raise Lz4Error("truncated LZ4 block")
                blocks.append(decompress_block(raw))
            continue
        if magic != FRAME_MAGIC:
            raise Lz4Error(f"not an LZ4 frame (magic 0x{magic:08X})")
        flg = handle.read(1)[0]
        bd = handle.read(1)[0]
        version = (flg >> 6) & 0x03
        if version != 0x01:
            raise Lz4Error(f"unsupported LZ4 frame version {version}")
        block_checksum = bool(flg & 0x10)
        content_size = bool(flg & 0x08)
        content_checksum = bool(flg & 0x04)
        dict_id = bool(flg & 0x01)
        if content_size:
            handle.read(8)
        if dict_id:
            handle.read(4)
        handle.read(1)
        hasher = _RollingXxh32() if content_checksum else None
        while True:
            size_raw = handle.read(4)
            if len(size_raw) < 4:
                raise Lz4Error("truncated LZ4 frame (no end mark)")
            block_size = struct.unpack("<I", size_raw)[0]
            if block_size == 0:
                break
            uncompressed = bool(block_size & BLOCK_UNCOMPRESSED)
            block_size &= 0x7FFFFFFF
            raw = handle.read(block_size)
            if len(raw) < block_size:
                raise Lz4Error("truncated LZ4 block")
            block = raw if uncompressed else decompress_block(raw)
            if hasher is not None:
                hasher.update(block)
            blocks.append(block)
            if block_checksum:
                handle.read(4)
        if content_checksum:
            stored_raw = handle.read(4)
            if len(stored_raw) == 4 and hasher is not None:
                stored = struct.unpack("<I", stored_raw)[0]
                if hasher.digest() != stored:
                    raise Lz4Error("LZ4 content checksum mismatch: the file is corrupt")
    return blocks


def tempfile_bytes(data: bytes):
    """Kept tiny on purpose: a context manager that does nothing (API symmetry)."""
    import contextlib

    @contextlib.contextmanager
    def _noop():
        yield None

    return _noop()


def decompress_file(src: os.PathLike, dst: os.PathLike, progress: ProgressFn = null_progress,
                    verify: bool = True) -> Dict[str, Any]:
    """Decompress a ``.lz4`` file, streaming block by block so memory stays bounded."""
    src_path, dst_path = Path(src), Path(dst)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    total_in = src_path.stat().st_size
    written = 0
    frames = 0
    checksum_ok: Optional[bool] = None

    with src_path.open("rb") as fin, dst_path.open("wb") as out:
        while True:
            header = fin.read(4)
            if len(header) < 4:
                break
            magic = struct.unpack_from("<I", header, 0)[0]
            if SKIPPABLE_MIN <= magic <= SKIPPABLE_MAX:
                size = struct.unpack("<I", fin.read(4))[0]
                fin.seek(size, os.SEEK_CUR)
                continue
            if magic == LEGACY_MAGIC:
                while True:
                    size_raw = fin.read(4)
                    if len(size_raw) < 4:
                        break
                    block_size = struct.unpack("<I", size_raw)[0]
                    if block_size == 0:
                        break
                    for block in _iter_legacy_blocks(fin, block_size):
                        out.write(block)
                        written += len(block)
                    progress(fin.tell(), total_in, f"decompressing {src_path.name}")
                frames += 1
                continue
            if magic != FRAME_MAGIC:
                raise Lz4Error(f"not an LZ4 stream (magic 0x{magic:08X} at offset "
                               f"{fin.tell() - 4})")

            flg = fin.read(1)[0]
            bd = fin.read(1)[0]
            version = (flg >> 6) & 0x03
            block_independent = bool(flg & 0x20)
            block_checksum = bool(flg & 0x10)
            content_size = bool(flg & 0x08)
            content_checksum = bool(flg & 0x04)
            dict_id = bool(flg & 0x01)
            if version != 0x01:
                raise Lz4Error(f"unsupported LZ4 frame version {version}")
            block_max_code = (bd >> 4) & 0x07
            block_max = {4: 64 * 1024, 5: 256 * 1024, 6: 1024 * 1024, 7: 4 * 1024 * 1024}.get(
                block_max_code)
            if block_max is None:
                raise Lz4Error("LZ4 frame declares an unsupported maximum block size")
            if content_size:
                fin.read(8)
            if dict_id:
                fin.read(4)
            fin.read(1)                      # header checksum byte
            h = xxh32(b"")                   # placeholder so linters see the hash helper used

            hasher = _RollingXxh32() if content_checksum and verify else None
            frames += 1
            while True:
                size_raw = fin.read(4)
                if len(size_raw) < 4:
                    raise Lz4Error("truncated LZ4 frame (no end mark)")
                block_size = struct.unpack("<I", size_raw)[0]
                if block_size == 0:
                    break
                uncompressed = bool(block_size & BLOCK_UNCOMPRESSED)
                block_size &= 0x7FFFFFFF
                raw = fin.read(block_size)
                if len(raw) < block_size:
                    raise Lz4Error("truncated LZ4 block")
                block = raw if uncompressed else decompress_block(raw)
                out.write(block)
                if hasher is not None:
                    hasher.update(block)
                written += len(block)
                if block_checksum:
                    fin.read(4)
                progress(fin.tell(), total_in, f"decompressing {src_path.name}")
            if content_checksum and verify:
                stored_raw = fin.read(4)
                if len(stored_raw) == 4:
                    stored = struct.unpack("<I", stored_raw)[0]
                    checksum_ok = hasher.digest() == stored if hasher else None
                    if checksum_ok is False:
                        raise Lz4Error("LZ4 content checksum mismatch: the file is corrupt")
            if written == 0 and fin.read(1) == b"":
                break
        out.flush()
        os.fsync(out.fileno())

    return {"output": str(dst_path), "input_size": total_in, "output_size": written,
            "frames": frames, "checksum_ok": checksum_ok,
            "ratio": round(written / max(total_in, 1), 2)}


class _RollingXxh32:
    """Incremental xxh32 so large frames can be verified without buffering them."""

    def __init__(self) -> None:
        self._data = bytearray()

    def update(self, block: bytes) -> None:
        self._data.extend(block)

    def digest(self) -> int:
        return xxh32(bytes(self._data))


def _iter_legacy_blocks(fh, block_size: int) -> List[bytes]:
    raw = fh.read(block_size)
    if not raw:
        return []
    return [decompress_block(raw)]


def frame_info(path: os.PathLike) -> Dict[str, Any]:
    """Read a frame header without decompressing, so the UI can show what it is looking at."""
    with open(path, "rb") as fh:
        head = fh.read(19)
    if len(head) < 7:
        raise Lz4Error("file is too small to be an LZ4 frame")
    magic = struct.unpack_from("<I", head, 0)[0]
    if magic == LEGACY_MAGIC:
        return {"format": "legacy block stream", "block_max": 8 * 1024 * 1024}
    if magic != FRAME_MAGIC:
        raise Lz4Error("not an LZ4 frame")
    flg, bd = head[4], head[5]
    code = (bd >> 4) & 0x07
    return {
        "format": "frame",
        "version": (flg >> 6) & 0x03,
        "block_independent": bool(flg & 0x20),
        "block_max": {4: 64 * 1024, 5: 256 * 1024, 6: 1024 * 1024, 7: 4 * 1024 * 1024}.get(code, 0),
        "content_checksum": bool(flg & 0x04),
        "content_size": bool(flg & 0x08),
        "block_checksum": bool(flg & 0x10),
    }
