"""Image conversions: raw <-> sparse, LZ4 expansion, trimming, splitting, boot extraction.

Most "the tool refuses my file" problems are one of these five conversions. Revive does them
without a C toolchain, verifies what it can, and always writes to a *new* file so the original
is never at risk.
"""
from __future__ import annotations

import os
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..storage import bootimg, lz4blk, magic, sparse, superimg
from ..util import ProgressFn, human_size, null_progress, sha256_file


def _out_path(src: os.PathLike, out: Optional[os.PathLike], suffix: str) -> Path:
    src_path = Path(src)
    if out is None:
        return src_path.with_name(src_path.stem + suffix)
    target = Path(out)
    if target.is_dir():
        return target / (src_path.stem + suffix)
    return target


def to_raw(src: os.PathLike, out: Optional[os.PathLike] = None,
           progress: ProgressFn = null_progress, verify: bool = True) -> Dict[str, Any]:
    """Expand an Android sparse image (or an LZ4 file) to a plain raw image."""
    src_path = Path(src)
    if lz4blk.is_lz4_file(src_path):
        result = decompress_lz4(src_path, out, progress)
        result["mode"] = "raw"
        return result
    if not sparse.is_sparse_file(src_path):
        raise ValueError(f"{src_path.name} is already raw (or not a sparse image); nothing to do")
    target = _out_path(src_path, out, ".raw.img")
    result = sparse.decode(src_path, target, progress, verify_checksum=verify)
    result.update({"mode": "raw", "sha256": sha256_file(target)})
    return result


def to_sparse(src: os.PathLike, out: Optional[os.PathLike] = None, block_size: int = 4096,
              progress: ProgressFn = null_progress, verify: bool = True) -> Dict[str, Any]:
    src_path = Path(src)
    if sparse.is_sparse_file(src_path):
        raise ValueError(f"{src_path.name} is already an Android sparse image")
    target = _out_path(src_path, out, ".sparse.img")
    result = sparse.encode(src_path, target, block_size=block_size, progress=progress)
    result["mode"] = "sparse"
    if verify:
        check = sparse.verify_checksum(target)
        result["verified"] = bool(check.get("ok"))
        if not check.get("ok"):
            result["warning"] = ("the sparse image failed its own checksum check; do not use it "
                                 f"({check.get('note', 'checksum mismatch')})")
    result["source_size"] = src_path.stat().st_size
    result["ratio"] = round(target.stat().st_size / max(src_path.stat().st_size, 1), 4)
    return result


def decompress_lz4(src: os.PathLike, out: Optional[os.PathLike] = None,
                   progress: ProgressFn = null_progress) -> Dict[str, Any]:
    src_path = Path(src)
    if not lz4blk.is_lz4_file(src_path):
        raise ValueError(f"{src_path.name} is not an LZ4 file")
    target = _out_path(src_path, out, ".raw.img")
    if target.name.endswith(".lz4"):
        target = target.with_suffix("")
    info = lz4blk.frame_info(src_path)
    result = lz4blk.decompress_file(src_path, target, progress)
    result.update({"mode": "raw", "frame": info, "sha256": sha256_file(target)})
    return result


def trim(src: os.PathLike, out: Optional[os.PathLike] = None, block: int = 1024 * 1024,
         progress: ProgressFn = null_progress) -> Dict[str, Any]:
    """Copy an image up to its last non-zero block (dumps are mostly trailing zeros)."""
    src_path = Path(src)
    size = src_path.stat().st_size
    last_nonzero = 0
    with src_path.open("rb") as fh:
        position = size
        while position > 0:
            step = min(block, position)
            position -= step
            fh.seek(position)
            data = fh.read(step)
            if data.strip(b"\x00"):
                last_nonzero = position + len(data.rstrip(b"\x00"))
                break
    if last_nonzero == 0:
        last_nonzero = 0
    target = _out_path(src_path, out, ".trimmed.img")
    written = 0
    with src_path.open("rb") as fh, target.open("wb") as out_fh:
        remaining = last_nonzero
        while remaining > 0:
            data = fh.read(min(block, remaining))
            if not data:
                break
            out_fh.write(data)
            written += len(data)
            remaining -= len(data)
            progress(written, last_nonzero, f"trimming {src_path.name}")
    return {"mode": "trim", "output": str(target), "source_size": size, "output_size": written,
            "original_size": size, "trimmed_size": written,
            "removed": size - written, "removed_human": human_size(size - written),
            "sha256": sha256_file(target) if written else ""}


def split(src: os.PathLike, out_dir: os.PathLike, chunk_size: int,
          progress: ProgressFn = null_progress) -> Dict[str, Any]:
    src_path = Path(src)
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    size = src_path.stat().st_size
    parts: List[Dict[str, Any]] = []
    written = 0
    with src_path.open("rb") as fh:
        index = 0
        while written < size:
            target = out_root / f"{src_path.stem}.part{index:03d}"
            with target.open("wb") as out:
                remaining = min(chunk_size, size - written)
                while remaining > 0:
                    data = fh.read(min(4 * 1024 * 1024, remaining))
                    if not data:
                        break
                    out.write(data)
                    written += len(data)
                    remaining -= len(data)
                    progress(written, size, f"splitting {src_path.name}")
            parts.append(str(target))
            index += 1
    return {"mode": "split", "parts": parts, "part_count": len(parts),
            "output_dir": str(out_root), "total_size": written}


def merge(parts: List[os.PathLike], out: os.PathLike,
          progress: ProgressFn = null_progress) -> Dict[str, Any]:
    target = Path(out)
    total = sum(Path(p).stat().st_size for p in parts)
    written = 0
    with target.open("wb") as out_fh:
        for part in parts:
            with open(part, "rb") as fh:
                while True:
                    data = fh.read(4 * 1024 * 1024)
                    if not data:
                        break
                    out_fh.write(data)
                    written += len(data)
                    progress(written, total, f"merging {len(parts)} parts")
    return {"mode": "merge", "output": str(target), "parts": len(parts), "size": written,
            "sha256": sha256_file(target)}


def extract_boot(src: os.PathLike, out_dir: os.PathLike, what: str = "all") -> Dict[str, Any]:
    if not bootimg.looks_like_boot_image(src):
        raise ValueError(f"{Path(src).name} does not start with an Android boot header")
    image = bootimg.parse(src)
    results = bootimg.extract(image, out_dir, what=what)
    return {"mode": "boot", "output_dir": str(out_dir), "image": image.to_dict(),
            "extracted": results}


def extract_super_partition(src: os.PathLike, name: str, out: os.PathLike,
                            progress: ProgressFn = null_progress) -> Dict[str, Any]:
    result = superimg.extract(src, name, out, progress)
    result["mode"] = "super"
    return result


def list_super(src: os.PathLike) -> Dict[str, Any]:
    return superimg.inspect(src).to_dict()


def convert_auto(path: os.PathLike, out_dir: Optional[os.PathLike] = None,
                 progress: ProgressFn = null_progress) -> Dict[str, Any]:
    """Do the obvious thing for this file and say what that was."""
    src_path = Path(path)
    sig = magic.sniff_file(src_path)
    if sig.kind == "android_sparse":
        return to_raw(src_path, out_dir, progress)
    if sig.kind == "lz4":
        return decompress_lz4(src_path, out_dir, progress)
    if sig.kind == "boot_image":
        return extract_boot(src_path, out_dir or src_path.parent)
    if sig.kind == "super_image":
        info = superimg.inspect(src_path)
        return {"mode": "inspect", "super": info.to_dict(),
                "hint": "use `revive super <file> --partition <name>` to extract one partition"}
    if sig.kind == "gpt":
        raise ValueError(
            f"{src_path.name} is a whole-disk image with a partition table, not a single "
            "partition. Use `revive dump-analyse` and `revive dump-extract` on it.")
    if sig.kind in ("blank", "empty"):
        raise ValueError(f"{src_path.name} is blank - there is nothing to convert")
    raise ValueError(
        f"{src_path.name} looks like {sig.label} ({sig.confidence}): Revive has no automatic "
        "conversion for it. `revive inspect <file>` describes it in detail.")
