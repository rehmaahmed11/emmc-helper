"""Checksum manifests and verification.

"Did the backup work?" is the question every guide answers with "trust me". Revive answers it
with a manifest: SHA-256 per file, written next to the data, verifiable months later. The verify
side is deliberately blunt - a size or hash mismatch is a fatal finding, because a mismatched
image is exactly the thing that bricks a phone when flashed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..storage import sparse
from ..util import (Finding, ProgressFn, SEV_ERROR, SEV_FATAL, SEV_OK, SEV_WARN, human_size,
                   null_progress, sha256_file)

MANIFEST_NAME = "manifest.json"
SCHEMA = "revive-backup-manifest/1"


def create_manifest(folder: os.PathLike, out: Optional[os.PathLike] = None,
                    progress: ProgressFn = null_progress) -> Dict[str, Any]:
    root = Path(folder)
    if not root.is_dir():
        raise NotADirectoryError(f"{root} is not a folder")
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != MANIFEST_NAME)
    total = sum(p.stat().st_size for p in files)
    entries: List[Dict[str, Any]] = []
    done = 0
    for path in files:
        digest = sha256_file(path, lambda d, t: progress(done + d, max(total, 1), path.name))
        done += path.stat().st_size
        entries.append({"path": path.relative_to(root).as_posix(),
                        "size": path.stat().st_size, "sha256": digest})
    manifest = {
        "schema": SCHEMA,
        "tool": "revive",
        "root": str(root),
        "file_count": len(entries),
        "total_size": total,
        "total_size_human": human_size(total),
        "files": entries,
    }
    target = Path(out) if out else root / MANIFEST_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    manifest["manifest"] = str(target)
    return manifest


def verify_manifest(folder: os.PathLike, manifest_path: Optional[os.PathLike] = None,
                    progress: ProgressFn = null_progress) -> Dict[str, Any]:
    root = Path(folder)
    mpath = Path(manifest_path) if manifest_path else root / MANIFEST_NAME
    if not mpath.exists():
        raise FileNotFoundError(f"no manifest at {mpath}; create one with `revive manifest <folder>`")
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    files = manifest.get("files", [])
    total = sum(int(f.get("size", 0)) for f in files) or 1
    missing: List[str] = []
    mismatched: List[Dict[str, Any]] = []
    verified = 0
    done = 0
    for entry in files:
        rel = str(entry.get("path", ""))
        path = root / rel
        if not path.exists():
            missing.append(rel)
            continue
        actual_size = path.stat().st_size
        digest = sha256_file(path, lambda d, t: progress(done + d, total, path.name))
        done += actual_size
        expected = str(entry.get("sha256", ""))
        if digest != expected or (entry.get("size") is not None and actual_size != entry["size"]):
            mismatched.append({"path": rel, "expected": expected, "actual": digest,
                               "declared_size": entry.get("size"), "actual_size": actual_size})
        else:
            verified += 1

    findings: List[Finding] = []
    if missing:
        findings.append(Finding(
            SEV_ERROR, f"{len(missing)} file(s) from the manifest are missing",
            "Missing: " + ", ".join(missing[:10]) + (" ..." if len(missing) > 10 else ""),
            ["Re-copy the backup from the medium it was stored on",
             "If this is a dump folder, re-extract the missing partitions from the dump"]))
    if mismatched:
        findings.append(Finding(
            SEV_FATAL, f"{len(mismatched)} file(s) do not match the recorded checksum",
            "First mismatch: " + mismatched[0]["path"] + ". Either the file changed, the storage "
            "medium is failing, or the copy was interrupted.",
            ["Do NOT flash these images",
             "Copy the files again from a known-good source and verify once more",
             "If the same file keeps failing on the same medium, stop using that medium"]))
    if not missing and not mismatched:
        findings.append(Finding(
            SEV_OK, f"All {verified} files verified",
            f"{human_size(total)} of data, every SHA-256 matches the manifest.", []))

    return {"manifest": str(mpath), "files": len(files), "verified": verified,
            "missing": missing, "mismatched": mismatched,
            "ok": not missing and not mismatched,
            "findings": [f.to_dict() for f in findings]}


def verify_sparse(path: os.PathLike, progress: ProgressFn = null_progress) -> Dict[str, Any]:
    """Verify an Android sparse image without expanding it."""
    return sparse.verify_checksum(path, progress)


def compare_to_manifest(path: os.PathLike, manifest_path: os.PathLike) -> Dict[str, Any]:
    folder = path if Path(path).is_dir() else Path(path).parent
    return verify_manifest(folder, manifest_path)


def compare_folders(a: os.PathLike, b: os.PathLike) -> Dict[str, Any]:
    """Compare two folders (or two images) file by file. Used to check a re-download."""
    root_a, root_b = Path(a), Path(b)

    def index(root: Path) -> Dict[str, Path]:
        if root.is_file():
            return {root.name: root}
        return {p.relative_to(root).as_posix(): p
                for p in sorted(root.rglob("*")) if p.is_file() and p.name != MANIFEST_NAME}

    files_a, files_b = index(root_a), index(root_b)
    only_in_a = sorted(set(files_a) - set(files_b))
    only_in_b = sorted(set(files_b) - set(files_a))
    size_mismatch: List[str] = []
    content_mismatch: List[str] = []
    for name in sorted(set(files_a) & set(files_b)):
        path_a, path_b = files_a[name], files_b[name]
        if path_a.stat().st_size != path_b.stat().st_size:
            size_mismatch.append(name)
            continue
        if sha256_file(path_a) != sha256_file(path_b):
            content_mismatch.append(name)
    findings: List[Finding] = []
    if not (only_in_a or only_in_b or size_mismatch or content_mismatch):
        findings.append(Finding(SEV_OK, f"{len(files_a)} file(s) are identical", "", []))
    else:
        findings.append(Finding(
            SEV_WARN, "The two folders differ",
            f"only in first: {', '.join(only_in_a[:6]) or '-'}; only in second: "
            f"{', '.join(only_in_b[:6]) or '-'}; different sizes: "
            f"{', '.join(size_mismatch[:6]) or '-'}; different content: "
            f"{', '.join(content_mismatch[:6]) or '-'}",
            ["If this is a re-download, use the copy that verifies against the manifest"]))
    return {"match": not (only_in_a or only_in_b or size_mismatch or content_mismatch),
            "only_in_a": only_in_a, "only_in_b": only_in_b, "size_mismatch": size_mismatch,
            "content_mismatch": content_mismatch, "files": len(files_a),
            "findings": [f.to_dict() for f in findings]}


def quick_hash(path: os.PathLike, progress: ProgressFn = null_progress) -> Dict[str, Any]:
    p = Path(path)
    digest = sha256_file(p, lambda d, t: progress(d, t, p.name))
    return {"path": str(p), "size": p.stat().st_size, "size_human": human_size(p.stat().st_size),
            "sha256": digest}
