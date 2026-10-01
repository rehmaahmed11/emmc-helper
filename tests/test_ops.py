"""Tests for dump surgery, conversions and verification."""
from __future__ import annotations

import json
from pathlib import Path

from fixtures import demo_tree
from revive.ops import convert, dump, verify
from revive.storage import sparse


def test_dump_analysis(_tmp):
    report = dump.analyse(demo_tree()["dump"])
    names = [p.name for p in report.partitions]
    assert names[:3] == ["preloader", "boot_a", "system_a"]
    kinds = {p.name: p.kind for p in report.partitions}
    assert kinds["boot_a"] == "boot_image"
    assert kinds["system_a"] == "ext4"
    assert kinds["super"] == "super_image"
    assert kinds["preloader"] == "mtk_preloader"
    assert report.header_crc_ok and report.entries_crc_ok


def test_dump_detects_truncation(_tmp):
    report = dump.analyse(demo_tree()["dump"])
    assert any("truncated" in f.title.lower() for f in report.findings)
    assert any("past the end" in " ".join(p.issues) for p in report.partitions)


def test_dump_extract_and_manifest(tmp):
    out = tmp / "out"
    result = dump.extract_all(demo_tree()["dump"], out)
    assert result["partitions"] == 6
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["gpt_offset"] == 0
    entry = next(e for e in manifest["partitions"] if e["name"] == "boot_a")
    assert entry["sha256"] and Path(out / "partitions" / entry["file"]).exists()
    # The extracted boot image must still parse as a boot image
    from revive.storage import bootimg

    assert bootimg.parse(out / "partitions" / entry["file"]).kernel.size > 0


def test_dump_extract_single_partition(tmp):
    result = dump.extract(demo_tree()["dump"], "userdata", tmp)
    from revive.storage import ext4fs

    info = ext4fs.inspect_file(result["output"])
    assert info is not None and info.kind == "f2fs"


def test_dump_extract_unknown_partition_fails(tmp):
    try:
        dump.extract(demo_tree()["dump"], "nope", tmp)
    except ValueError as exc:
        assert "nope" in str(exc)
        return
    raise AssertionError("expected ValueError")


def test_dump_scan_finds_signatures(_tmp):
    hits = dump.scan(demo_tree()["dump"])
    kinds = {h["kind"] for h in hits}
    assert "boot image" in kinds
    assert hits == sorted(hits, key=lambda h: h["offset"])


def test_manifest_create_and_verify(tmp):
    folder = tmp / "backup"
    (folder / "partitions").mkdir(parents=True)
    (folder / "partitions" / "boot_a.img").write_bytes(b"boot data" * 100)
    (folder / "partitions" / "system_a.img").write_bytes(b"system data" * 100)
    create = verify.create_manifest(folder)
    assert create["file_count"] == 2

    result = verify.verify_manifest(folder)
    assert result["ok"] and result["verified"] == 2

    # tamper with one file -> verification must fail loudly
    (folder / "partitions" / "boot_a.img").write_bytes(b"corrupted")
    broken = verify.verify_manifest(folder)
    assert not broken["ok"] and broken["mismatched"]
    assert broken["mismatched"][0]["path"] == "partitions/boot_a.img"

    # missing file -> flagged separately
    (folder / "partitions" / "system_a.img").unlink()
    missing = verify.verify_manifest(folder)
    assert missing["missing"] == ["partitions/system_a.img"]


def test_compare_folders(tmp):
    a = tmp / "a"
    b = tmp / "b"
    a.mkdir()
    b.mkdir()
    (a / "boot.img").write_bytes(b"1234")
    (b / "boot.img").write_bytes(b"1234")
    assert verify.compare_folders(a, b)["match"]

    (b / "boot.img").write_bytes(b"12345")
    diff = verify.compare_folders(a, b)
    assert not diff["match"] and diff["size_mismatch"] == ["boot.img"]


def test_convert_sparse_round_trip(tmp):
    raw = tmp / "raw.img"
    raw.write_bytes(b"\x33" * (4096 * 16))
    sparse_out = tmp / "sparse.img"
    to_sparse = convert.to_sparse(raw, sparse_out)
    assert to_sparse["output"] == str(sparse_out) and sparse.is_sparse_file(sparse_out)

    back = tmp / "back.img"
    to_raw = convert.to_raw(sparse_out, back)
    assert Path(to_raw["output"]).read_bytes() == raw.read_bytes()


def test_convert_lz4(tmp):
    out = convert.decompress_lz4(demo_tree()["lz4_img"], tmp / "payload.img")
    data = Path(out["output"]).read_bytes()
    assert data.startswith(b"REVIVE LZ4 PAYLOAD")


def test_convert_trim(tmp):
    path = tmp / "dump.bin"
    path.write_bytes(b"DATA" * 1024 + b"\x00" * (1024 * 1024))
    result = convert.trim(path, tmp / "trimmed.bin")
    assert result["trimmed_size"] < result["original_size"]
    assert Path(result["output"]).stat().st_size == result["trimmed_size"]


def test_convert_split_and_merge(tmp):
    path = tmp / "big.img"
    payload = bytes(range(256)) * 4096          # 1 MiB
    path.write_bytes(payload)
    split = convert.split(path, tmp / "parts", chunk_size=200_000)
    assert len(split["parts"]) >= 5
    merged = convert.merge([Path(p) for p in split["parts"]], tmp / "merged.img")
    assert Path(merged["output"]).read_bytes() == payload


def test_convert_auto_detects_sparse(tmp):
    info = demo_tree()
    result = convert.convert_auto(info["sparse_img"], tmp)
    assert result.get("raw_size")
