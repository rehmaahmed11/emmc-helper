"""Tests for the binary format parsers: sparse, boot, super, eMMC, filesystems, lz4."""
from __future__ import annotations

import gzip
import struct
from pathlib import Path

from fixtures import demo_tree
from revive.storage import bootimg, emmc, ext4fs, lz4blk, magic, sparse, superimg


def test_sparse_round_trip(tmp):
    raw = tmp / "raw.img"
    data = bytearray(b"\x11" * 4096 * 8)
    data[4096 * 4:4096 * 5] = b"\x00" * 4096
    raw.write_bytes(bytes(data))
    out = tmp / "sparse.img"
    result = sparse.encode(raw, out, block_size=4096)
    assert result["sparse_size"] < result["raw_size"]
    assert sparse.is_sparse_file(out)

    back = tmp / "back.raw"
    decode = sparse.decode(out, back, verify_checksum=True)
    assert back.read_bytes() == bytes(data)
    assert decode["raw_size"] == len(data)


def test_sparse_header_and_inspect(tmp):
    raw = tmp / "raw.img"
    raw.write_bytes(b"\x22" * 4096 * 4)
    out = tmp / "sparse.img"
    sparse.encode(raw, out, block_size=4096)
    info = sparse.inspect(out)
    assert info["header"]["block_size"] == 4096
    assert info["header"]["total_blocks"] == 4
    assert info["chunk_counts"]


def test_boot_image_parsing(tmp):
    info = demo_tree()
    image = bootimg.parse(info["boot_img"])
    assert image.header_version == 0
    assert image.kernel.size > 0
    assert image.kernel.compressed == "gzip"
    assert image.kind.startswith("boot")
    assert image.cmdline.startswith("console=")
    payload = image.to_dict()
    assert payload["kernel"]["size"] == image.kernel.size


def test_boot_image_extract(tmp):
    info = demo_tree()
    out = tmp / "boot_out"
    written = bootimg.extract(bootimg.parse(info["boot_img"]), out)
    names = {entry["name"] for entry in written}
    assert "kernel" in names
    kernel_entry = next(e for e in written if e["name"] == "kernel")
    assert Path(kernel_entry["decompressed_path"]).exists()
    assert b"SYNTHETIC KERNEL" in Path(kernel_entry["decompressed_path"]).read_bytes()


def test_boot_image_rejects_garbage(tmp):
    bad = tmp / "boot.img"
    bad.write_bytes(b"not an image" * 100)
    try:
        bootimg.parse(bad)
    except bootimg.BootImageError:
        return
    raise AssertionError("expected BootImageError")


def test_super_image_inspect_and_extract(tmp):
    info = demo_tree()
    super_info = superimg.inspect(info["super_img"])
    names = [p.name for p in super_info.partitions]
    assert names == ["system_a", "vendor_a"]
    assert super_info.partitions[0].size == 2 * 1024 * 1024
    assert super_info.version_supported

    out = tmp / "extracted_system.img"
    result = superimg.extract(info["super_img"], "system_a", out)
    assert result["size"] == 2 * 1024 * 1024
    assert out.read_bytes().startswith(b"SUPER-system_a-DATA")


def test_super_extract_refuses_unknown_partition(tmp):
    info = demo_tree()
    try:
        superimg.extract(info["super_img"], "does_not_exist", tmp / "x.img")
    except superimg.SuperError:
        return
    raise AssertionError("expected SuperError")


def test_lz4_frame_decompress(tmp):
    info = demo_tree()
    raw = lz4blk.decompress(Path(info["lz4_img"]).read_bytes())
    assert raw.startswith(b"REVIVE LZ4 PAYLOAD")
    assert lz4blk.is_frame(Path(info["lz4_img"]).read_bytes()[:8])


def test_lz4_block_errors_are_raised(tmp):
    try:
        lz4blk.decompress(b"\xff\xff\xff\xff", expected_size=16)
    except lz4blk.Lz4Error:
        return
    raise AssertionError("expected Lz4Error on malformed block")


def test_emmc_cid_parsing(_tmp):
    cid = bytearray(16)
    cid[0] = 0x15                       # Samsung
    struct.pack_into(">H", cid, 1, 0x0100)
    cid[3:9] = b"8GTF4R"
    cid[9] = 0x01
    cid[10] = 0x02
    struct.pack_into(">I", cid, 10, 0x01234567)
    cid[14] = 0x42                      # year 2004 (2000+4), month 2
    parsed = emmc.parse_cid(bytes(cid))
    assert parsed.manufacturer == "Samsung"
    assert parsed.product_name == "8GTF4R"
    assert parsed.serial == 0x01234567
    assert parsed.manufacture_date == "02/2004"


def test_emmc_csd_size_math(_tmp):
    value = 0
    value |= 3 << 126                   # CSD structure 3 -> MMC v4+
    value |= 9 << 80                    # READ_BL_LEN 512
    value |= (4096 - 1) << 62           # C_SIZE is 12 bits: max (4096) * 512 KB = 2 GB
    value |= 0x32 << 96                 # 100 Mbit/s
    raw = value.to_bytes(16, "big")
    csd = emmc.parse_csd(raw)
    assert csd.structure == 3
    assert csd.size_bytes == 4096 * 512 * 1024
    assert csd.tran_speed == "100 Mbit/s"


def test_emmc_ext_csd_health(_tmp):
    raw = bytearray(512)
    struct.pack_into("<I", raw, 212, 4_000_000)     # SEC_COUNT
    raw[226] = 0x20                                 # BOOT_SIZE_MULT -> 4 MB
    raw[168] = 0x08                                 # RPMB_SIZE_MULT -> 1 MB
    struct.pack_into("<H", raw, 262, 0x51)          # eMMC 5.1
    raw[254:262] = b"FW1.2\x00\x00\x00"      # exactly 8 bytes
    raw[267] = 0x02                                 # PRE_EOL warning
    raw[268] = 0x05                                 # 40-50% life used
    raw[269] = 0x0B                                 # exceeded
    ext = emmc.parse_ext_csd(bytes(raw))
    assert ext.capacity_bytes == 4_000_000 * 512
    assert ext.device_version == "eMMC 5.1"
    assert ext.boot_size == 4 * 1024 * 1024
    assert ext.health == "warning"
    assert ext.warnings
    assert "40-50%" in ext.life_a
    assert "EXCEEDED" in ext.life_b
    summary = emmc.summary(emmc.parse_cid(bytes(16)), None, ext)
    assert summary["capacity"] == ext.capacity_bytes


def test_ext4_superblock(tmp):
    from make_demo import make_ext4_block

    block = make_ext4_block("system_a", blocks=4096)
    info = ext4fs.read_fs(block, 1024)
    assert info is not None
    assert info.kind == "ext2/3/4"
    assert info.label == "system_a"
    assert info.block_count == 4096
    assert info.features["extents"] is True
    assert info.state == "clean"


def test_f2fs_detection(tmp):
    from make_demo import make_f2fs_block

    info = ext4fs.read_fs(make_f2fs_block(), 1024)
    assert info is not None and info.kind == "f2fs"
    assert info.best_effort is True


def test_magic_sniffer(tmp):
    info = demo_tree()
    assert magic.sniff_file(info["boot_img"]).kind == "boot_image"
    assert magic.sniff_file(info["sparse_img"]).kind == "android_sparse"
    assert magic.sniff_file(info["super_img"]).kind == "super_image"
    assert magic.sniff_file(info["lz4_img"]).kind == "lz4"
    assert magic.sniff_file(info["dump"]).kind == "gpt_disk"
    blank = tmp / "blank.bin"
    blank.write_bytes(b"\x00" * 65536)
    assert magic.sniff_file(blank).kind == "blank"
