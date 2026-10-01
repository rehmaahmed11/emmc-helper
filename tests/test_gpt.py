"""GPT parsing, validation, repair and round-trip tests."""
from __future__ import annotations

import struct
import uuid

from revive.storage import gpt

SECTOR = 512
SECTORS = 8192          # 4 MB synthetic disk


def _mk(name, first, last):
    return gpt.PartitionEntry(0, name, "0fc63daf-8483-4772-8e79-3d69d8477de4",
                              str(uuid.uuid4()), first, last, 0)


def _write_disk(path, parts, corrupt=False):
    mbr, primary, backup = gpt.build_gpt_bytes(parts, SECTORS, SECTOR)
    table_sectors = (128 * 128 + SECTOR - 1) // SECTOR
    with path.open("wb") as fh:
        fh.write(mbr)
        fh.write(primary)
        fh.seek(SECTORS * SECTOR - 1)          # make sure the file is exactly disk-sized
        fh.write(b"\x00")
        fh.seek((SECTORS - 1 - table_sectors) * SECTOR)
        fh.write(backup)
    if corrupt:
        with path.open("r+b") as fh:
            fh.seek(SECTOR + 16)
            fh.write(b"\x00\x00\x00\x00")
    return path


def test_round_trip(tmp):
    path = _write_disk(tmp / "disk.img", [_mk("boot_a", 2048, 4095), _mk("userdata", 4096, 6000)])
    parsed = gpt.read_gpt(path)
    assert [p.name for p in parsed.partitions] == ["boot_a", "userdata"]
    assert parsed.header_crc_ok and parsed.entries_crc_ok
    assert parsed.partitions[0].offset == 2048 * SECTOR
    assert parsed.partitions[0].size == (4095 - 2048 + 1) * SECTOR


def test_find_and_slot_helpers(tmp):
    path = _write_disk(tmp / "disk.img",
                       [_mk("boot_a", 2048, 3000), _mk("boot_b", 3001, 3100), _mk("boot", 3101, 3200)])
    parsed = gpt.read_gpt(path)
    assert parsed.find("boot_a").name == "boot_a"
    assert parsed.find("missing") is None
    assert {p.name for p in parsed.by_slot("boot")} == {"boot_a", "boot_b", "boot"}
    assert [p.name for p in parsed.find_all("boot")] == ["boot_a", "boot_b", "boot"]


def test_overlap_detection(tmp):
    path = _write_disk(tmp / "disk.img", [_mk("a", 2048, 3000), _mk("b", 2500, 3500)])
    parsed = gpt.read_gpt(path)
    pairs = parsed.overlaps()
    assert len(pairs) == 1 and pairs[0][0].name == "a" and pairs[0][1].name == "b"


def test_protective_mbr(tmp):
    path = _write_disk(tmp / "disk.img", [_mk("a", 2048, 3000)])
    head = path.read_bytes()[:512]
    assert gpt.is_protective_mbr(head)


def test_corrupt_header_uses_backup(tmp):
    path = _write_disk(tmp / "disk.img", [_mk("boot_a", 2048, 4095)], corrupt=True)
    parsed = gpt.read_gpt(path)
    assert parsed.backup_used is True
    assert parsed.primary_damaged is True
    assert [p.name for p in parsed.partitions] == ["boot_a"]


def test_repair_dry_run_then_apply(tmp):
    path = _write_disk(tmp / "disk.img", [_mk("boot_a", 2048, 4095)], corrupt=True)
    report = gpt.repair_gpt(path, dry_run=True)
    assert report["header_crc_was_ok"] is False
    assert report["partitions"] == 1
    assert any("CRCs recalculated" in c for c in report["changes"])
    assert not report.get("written")

    applied = gpt.repair_gpt(path, dry_run=False)
    assert applied["written"] is True
    parsed = gpt.read_gpt(path)
    assert parsed.header_crc_ok and parsed.entries_crc_ok
    assert [p.name for p in parsed.partitions] == ["boot_a"]


def test_gpt_at_nonzero_offset(tmp):
    """Dumps often start before the user area: the reader must find the table anywhere."""
    parts = [_mk("super", 4096, 6000)]
    mbr, primary, backup = gpt.build_gpt_bytes(parts, SECTORS, SECTOR)
    payload = b"\xAA" * (1024 * 1024)
    blob = payload + mbr + primary
    parsed = gpt.read_gpt_from_bytes(blob, disk_offset=1024 * 1024, sector_size=SECTOR)
    assert parsed is not None
    assert parsed.partitions[0].name == "super"
    assert parsed.disk_offset == 1024 * 1024


def test_bad_geometry_is_rejected(tmp):
    path = tmp / "junk.img"
    path.write_bytes(b"\x00" * (SECTOR * 4))
    try:
        gpt.read_gpt(path)
    except gpt.GptError:
        return
    raise AssertionError("expected GptError for a file with no GPT")


def test_entries_crc_detects_tampering(tmp):
    path = _write_disk(tmp / "disk.img", [_mk("boot_a", 2048, 4095)])
    with path.open("r+b") as fh:
        fh.seek(2 * SECTOR + 56)      # inside the first entry's name field
        fh.write(b"\x41")
    parsed = gpt.read_gpt(path, try_backup=False)
    assert parsed.entries_crc_ok is False
