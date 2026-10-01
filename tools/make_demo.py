"""Build a synthetic phone-data set so Revive can be learned and tested without hardware.

Everything this module writes is fake: a MediaTek firmware folder, a deliberately broken one, a
Qualcomm EDL package, a full disk dump with a GPT, single images (boot/super/sparse/lz4) and a
couple of filesystem superblocks. It is used by the test suite as fixture data, by
``revive demo`` for users, and by the web UI's "Demo data" button.

Run it directly to populate a folder you can point the tool at:

    python tools/make_demo.py --out ~/ReviveDemo
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import sys
import uuid
import zlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from revive.storage import gpt as gpt_mod          # noqa: E402
from revive.storage import sparse, superimg        # noqa: E402

SECTOR = 512
LIST_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
EFI_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


# ---------------------------------------------------------------------------
# Small building blocks
# ---------------------------------------------------------------------------

def make_ext4_block(label: str = "system_a", blocks: int = 4096, block_size: int = 4096,
                    state: int = 1) -> bytes:
    """A valid-enough ext2/3/4 superblock (magic at 0x438) plus a little payload."""
    size = max(blocks * block_size, 8192)
    data = bytearray(size)
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x00, blocks // 4)                 # inodes (plausible)
    struct.pack_into("<I", sb, 0x04, blocks)                      # blocks (low 32)
    struct.pack_into("<I", sb, 0x18, {1024: 0, 2048: 1, 4096: 2}.get(block_size, 2))
    struct.pack_into("<I", sb, 0x20, 32768)                       # blocks per group
    struct.pack_into("<I", sb, 0x28, 8192)                        # inodes per group
    struct.pack_into("<H", sb, 0x38, 0xEF53)                      # magic
    struct.pack_into("<H", sb, 0x3A, state)                       # filesystem state
    struct.pack_into("<I", sb, 0x5C, 0x4)                         # compat: has_journal
    struct.pack_into("<I", sb, 0x60, 0x40 | 0x80)                 # incompat: extents + 64bit
    uuid_bytes = uuid.uuid5(uuid.NAMESPACE_DNS, label).bytes
    sb[0x68:0x78] = uuid_bytes
    sb[0x78:0x88] = label.encode()[:16].ljust(16, b"\x00")
    data[1024:2048] = sb
    # a bit of "filesystem content" so the image is not all zeros
    blob = f"REVIVE EXT4 {label} ".encode() + bytes(range(256)) * 8
    data[8192:8192 + len(blob)] = blob
    return bytes(data)


def make_f2fs_block(label: str = "userdata", blocks: int = 2048) -> bytes:
    """F2FS superblock (magic 0xF2F52010 at offset 1024) plus padding."""
    size = max(blocks * 4096, 8192)
    data = bytearray(size)
    sb = bytearray(256)
    struct.pack_into("<I", sb, 0, 0xF2F52010)
    struct.pack_into("<HH", sb, 4, 1, 15)            # version 1.15
    struct.pack_into("<I", sb, 8, 9)                 # log sector size (512)
    struct.pack_into("<I", sb, 16, 12)               # log block size (4096)
    struct.pack_into("<Q", sb, 40, blocks)           # block count
    sb[48:64] = label.encode()[:16].ljust(16, b"\x00")
    data[1024:1024 + len(sb)] = sb
    blob = b"REVIVE F2FS DATA " + bytes(range(256)) * 4
    data[4096:4096 + len(blob)] = blob
    return bytes(data)


def make_boot_image(path: Path, cmdline: str = "console=ttyMT0,115200n8 androidboot.hardware=mt6768",
                    kernel_label: bytes = b"SYNTHETIC KERNEL v1", page_size: int = 2048,
                    header_version: int = 0) -> Path:
    """Write a boot.img the way a phone would carry it (gzip kernel, 2048-byte pages)."""
    kernel = gzip.compress(kernel_label * 64 + b"\n" + bytes(range(256)) * 128, mtime=0)
    ramdisk = gzip.compress(b"SYNTHETIC RAMDISK\n" + b"init" * 900, mtime=0)
    second = b"SYNTHETIC SECOND STAGE\n" * 8

    def pad(blob: bytes) -> bytes:
        remainder = len(blob) % page_size
        return blob if remainder == 0 else blob + b"\x00" * (page_size - remainder)

    header = bytearray(page_size)
    header[0:8] = b"ANDROID!"
    struct.pack_into("<I", header, 8, len(kernel))
    struct.pack_into("<I", header, 12, 0x10008000)
    struct.pack_into("<I", header, 16, len(ramdisk))
    struct.pack_into("<I", header, 20, 0x11000000)
    struct.pack_into("<I", header, 24, len(second))
    struct.pack_into("<I", header, 28, 0x10F00000)
    struct.pack_into("<I", header, 32, 0x10000100)
    struct.pack_into("<I", header, 36, page_size)
    struct.pack_into("<I", header, 40, header_version)
    struct.pack_into("<I", header, 44, (11 << 25) | (25 << 4) | 3)     # Android 11, 2025-03
    header[48:64] = b"revive-demo".ljust(16, b"\x00")
    header[64:64 + len(cmdline)] = cmdline.encode()

    body = bytearray(pad(bytes(header)) + pad(kernel) + pad(ramdisk) + pad(second))
    # id[8]: a 32-byte field, filled with a sha1 so it is deterministic; only 20 bytes are used.
    body[576:596] = hashlib.sha1(bytes(body[:page_size]) + kernel).digest()
    struct.pack_into("<I", body, 608, len(body))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(body))
    return path


def make_super_image(path: Path, partitions: Sequence[str] = ("system_a", "vendor_a"),
                     sizes_mb: Sequence[int] = (2, 1), block_size: int = 4096,
                     metadata_size: int = 64 * 1024) -> Path:
    """Build a super.img with liblp-style metadata and LINEAR extents."""
    part_entries = bytearray()
    extent_entries = bytearray()
    extern_indices = []
    cursor_sector = ((4096 + metadata_size * 2) // SECTOR) + 8
    data_blobs: List[bytes] = []
    for index, (name, size_mb) in enumerate(zip(partitions, sizes_mb)):
        sectors = (size_mb * 1024 * 1024) // SECTOR
        payload = f"SUPER-{name}-DATA\n".encode() * (size_mb * 64)
        payload = payload[: size_mb * 1024 * 1024]
        payload = payload.ljust(size_mb * 1024 * 1024, b"\x00")
        data_blobs.append(payload)
        extern_indices.append(len(extent_entries) // 24)
        # 20 bytes of data + 4 bytes of alignment padding: liblp pads the record to 24
        extent_entries += struct.pack("<QIII", sectors, superimg.TARGET_LINEAR, cursor_sector,
                                      0) + b"\x00\x00\x00\x00"
        entry = bytearray(52)
        entry[0:36] = name.encode()[:36].ljust(36, b"\x00")
        struct.pack_into("<IIII", entry, 36, 0, extern_indices[-1], 1, 0)
        part_entries += bytes(entry)
        cursor_sector += sectors

    if extern_indices:
        # fix first_extent_index per partition (each partition has exactly one extent here)
        for index in range(len(partitions)):
            struct.pack_into("<I", part_entries, index * 52 + 40, index)

    groups = bytearray(48)
    groups[0:36] = b"qti_dynamic_partitions".ljust(36, b"\x00")
    struct.pack_into("<Q", groups, 36, 0)

    parts_offset = 68
    extents_offset = parts_offset + len(part_entries)
    groups_offset = extents_offset + len(extent_entries)
    devices_offset = groups_offset + len(groups)

    body = bytearray(b"\x00" * max(4096, devices_offset))
    body[0:4] = struct.pack("<I", superimg.LP_GEOMETRY_MAGIC)
    struct.pack_into("<IIII", body, 4, 4096, 0, metadata_size, 2)
    struct.pack_into("<I", body, 20, block_size)

    def descriptor(offset: int, count: int, size: int) -> bytes:
        return struct.pack("<III", offset, count, size)

    header_offset = 4096
    header = bytearray(80)
    struct.pack_into("<IHHHHII", header, 0, superimg.LP_HEADER_MAGIC, 1, 2, 80, 0, 0,
                     zlib.crc32(bytes(body[parts_offset:devices_offset])) & 0xFFFFFFFF)
    header[20:32] = descriptor(parts_offset, len(partitions), 52)
    header[32:44] = descriptor(extents_offset, len(partitions) * 1, 24)
    header[44:56] = descriptor(groups_offset, 1, 48)
    header[56:68] = descriptor(devices_offset, 0, 0)
    struct.pack_into("<H", header, 10, zlib.crc32(bytes(header)) & 0xFFFF)

    blob = bytearray(body)
    blob[header_offset:header_offset + len(header)] = header
    blob[header_offset + parts_offset:header_offset + parts_offset + len(part_entries)] = part_entries
    blob[header_offset + extents_offset:
         header_offset + extents_offset + len(extent_entries)] = extent_entries
    blob[header_offset + groups_offset:header_offset + groups_offset + len(groups)] = groups

    raw_size = max(cursor_sector * SECTOR, len(blob))
    payload = bytearray(raw_size)
    payload[:len(blob)] = blob
    for index, blob_data in enumerate(data_blobs):
        # the offset the extents point at
        offset = struct.unpack_from("<I", extent_entries, index * 24 + 12)[0] * SECTOR
        payload[offset:offset + len(blob_data)] = blob_data
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(payload))
    return path


def make_lz4_file(payload: bytes, path: Path, block_size: int = 64 * 1024) -> Path:
    """Write an LZ4 frame with uncompressed blocks (valid LZ4, no compressor needed)."""
    out = bytearray()
    out += struct.pack("<I", 0x184D2204)
    flags = 0x60      # version 1, block independent
    out += bytes([flags, 0x40])          # BD: block max 64 KiB
    out += bytes([0x00])                 # header checksum placeholder (not verified by readers)
    for start in range(0, len(payload), block_size):
        block = payload[start:start + block_size]
        out += struct.pack("<I", len(block) | 0x80000000)
        out += block
    out += struct.pack("<I", 0)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(out))
    return path


def make_sparse_image(raw_path: Path, out_path: Path, block_size: int = 4096) -> Path:
    sparse.encode(raw_path, out_path, block_size=block_size)
    return out_path


# ---------------------------------------------------------------------------
# Firmware packages
# ---------------------------------------------------------------------------

HEADER = "#" * 100 + "\n"


def _scatter_text(platform: str, project: str, storage: str,
                  entries: Sequence[dict]) -> str:
    out = [HEADER, "#  General Setting\n", HEADER,
           "- general: MTK_PLATFORM_CFG\n",
           "  info:\n",
           "    - config_version: V1.2.3\n",
           f"      platform: {platform}\n",
           f"      project: {project}\n",
           f"      storage: {storage}\n",
           "      boot_channel: MSDC_0\n",
           "      block_size: 0x20000\n",
           HEADER, "#  Layout Setting\n", HEADER]
    for index, entry in enumerate(entries):
        out.append(f"- partition_index: SYS{index}\n")
        out.append(f"  partition_name: {entry['name']}\n")
        out.append(f"  file_name: {entry.get('file', '')}\n")
        out.append(f"  is_download: {'true' if entry.get('download', True) else 'false'}\n")
        out.append(f"  type: {entry.get('type', 'NORMAL_ROM')}\n")
        out.append(f"  linear_start_addr: 0x{entry['start']:x}\n")
        out.append(f"  physical_start_addr: 0x{entry['start']:x}\n")
        out.append(f"  partition_size: 0x{entry['size']:x}\n")
        out.append(f"  region: {entry.get('region', 'EMMC_USER')}\n")
        out.append("  storage: HW_STORAGE_EMMC\n")
        out.append("  boundary_check: true\n")
        out.append("  is_reserved: false\n")
        out.append(f"  operation_type: {entry.get('operation', 'UPDATE')}\n")
        out.append("  reserve: 0x00\n")
    return "".join(out)


def _w(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _pad_to(data: bytes, size: int) -> bytes:
    return data if len(data) >= size else data + b"\x00" * (size - len(data))


def make_firmware_folder(root: Path, platform: str = "MT6768", project: str = "k68v1_64_bsp",
                         broken: bool = False) -> dict:
    """A MediaTek SP Flash Tool style package. `broken=True` plants three real problems."""
    root.mkdir(parents=True, exist_ok=True)
    mb = 1024 * 1024
    entries = [
        dict(name="preloader", file=f"preloader_{project}.bin", start=0x0, size=0x40000,
             region="EMMC_BOOT_1", operation="BOOTLOADERS", type="SV5_BL_BIN"),
        dict(name="pgpt", file="PGPT", start=0x0, size=0x8000, operation="PGPT"),
        dict(name="boot", file="boot.img", start=0x800000, size=16 * mb, operation="UPDATE"),
        dict(name="system", file="system.img", start=0x1800000, size=32 * mb),
        dict(name="vendor", file="vendor.img", start=0x3800000, size=16 * mb),
        dict(name="userdata", file="userdata.img", start=0x4800000, size=24 * mb),
        dict(name="nvram", file="nvram.img", start=0x6000000, size=4 * mb, region="EMMC_USER"),
        dict(name="modem", file="modem.img", start=0x6400000, size=8 * mb),
    ]
    if broken:
        # 1. modem.img is referenced but not shipped
        # 2. vendor overlaps boot
        # 3. oem.img is 1 MB but its partition is 256 KB
        entries[4]["start"] = 0xD00000          # 13 MB: inside boot (8 MB..24 MB)
        entries[4]["size"] = 4 * mb
        entries.append(dict(name="oem", file="oem.img", start=0x6800000, size=0x40000))

    preloader_data = b"EMMC_BOOT" + bytes(range(256)) * 200
    _w(root / f"preloader_{project}.bin", _pad_to(preloader_data, 0x40000))
    _w(root / "PGPT", _pad_to(b"EFI PART" + b"\x00" * 500, 0x8000))
    make_boot_image(root / "boot.img")
    _w(root / "system.img", make_ext4_block("system_a", blocks=4096))
    _w(root / "vendor.img", make_ext4_block("vendor_a", blocks=2048))
    _w(root / "userdata.img", make_f2fs_block("userdata", blocks=2048))
    _w(root / "nvram.img", b"NVRAM-DATA " * 64)
    if broken:
        _w(root / "oem.img", b"OEM-IMAGE" * (1024 * 128))     # 1 MB into a 256 KB partition
    else:
        _w(root / "modem.img", b"MODEM-FIRMWARE " * 128)

    scatter_name = (f"{platform}_Android_scatter.txt" if platform.upper().startswith("MT")
                    else f"MT{platform}_Android_scatter.txt")
    scatter_path = root / scatter_name
    scatter_path.write_text(_scatter_text(platform, project, "EMMC", entries))

    # A DA file the reader can actually identify: marker + chip names + hardware codes.
    da_blob = bytearray()
    da_blob += b"\x00" * 32
    da_blob += b"MTK_AllInOne_DA_v5.2048" + b"\x00" * 8
    for chip, code in (("MT6768", 0x707), ("MT6765", 0x766)):
        packed = bytearray(512)
        struct.pack_into("<I", packed, 0, code)
        packed[16:16 + len(chip)] = chip.encode()
        da_blob += bytes(packed)
    da_blob += b"MTK_DOWNLOAD_AGENT" + b"\x00" * 16
    _w(root / "MTK_AllInOne_DA.bin", bytes(da_blob))

    # Vendor noise files, exactly like real packages ship them.
    (root / "checksum.ini").write_text("[CHECKSUM]\nfile_name = boot.img\nchecksum = 0x12345678\n")
    (root / "ver.cfg").write_text("[VERSION]\nvendor = Revive\nbuild = demo\n")

    return {"root": str(root), "scatter": str(scatter_path), "platform": platform,
            "project": project, "broken": broken}


def make_qualcomm_folder(root: Path, missing: bool = True) -> dict:
    """A Qualcomm EDL package: rawprogram/patch XML, firehose programmer, GPT images."""
    root.mkdir(parents=True, exist_ok=True)
    mb = 1024 * 1024
    _w(root / "prog_firehose_ddr.elf", b"\x7fELF" + b"firehose" * 64)
    _w(root / "gpt_main0.bin", _pad_to(b"EFI PART" + b"\x00" * 500, 34 * 512))
    _w(root / "gpt_backup0.bin", _pad_to(b"\x00" * 512, 33 * 512))
    make_boot_image(root / "boot.img")
    _w(root / "system.img", make_ext4_block("system_a", blocks=4096))
    _w(root / "userdata.img", make_f2fs_block("userdata", blocks=2048))

    programs = [
        ("PrimaryGPT", "gpt_main0.bin", 0, 34, 0),
        ("boot_a", "boot.img", 2048, 16 * 1024, 0),
        ("system_a", "system.img", 2048 + 16 * 1024, 32 * 1024, 0),
        ("userdata", "userdata.img", 2048 + 48 * 1024, 24 * 1024, 0),
    ]
    if missing:
        programs.append(("vendor_a", "vendor.img", 2048 + 72 * 1024, 16 * 1024, 0))
    rows = "".join(
        f'  <program SECTOR_SIZE_IN_BYTES="512" filename="{name}" label="{label}" '
        f'num_partition_sectors="{sectors}" physical_partition_number="0" '
        f'start_sector="{start}" sparse="false" />\n'
        for label, name, start, sectors, _ in programs)
    (root / "rawprogram0.xml").write_text(
        '<?xml version="1.0" ?>\n<data>\n' + rows + "</data>\n")
    (root / "patch0.xml").write_text(
        '<?xml version="1.0" ?>\n<patches>\n'
        '  <patch filename="gpt_main0.bin" start_sector="0" byte_offset="0" '
        'size_in_bytes="8" value="1" what="Backup Header" />\n'
        "</patches>\n")
    (root / "rawprogram_unsparse.xml").write_text(
        '<?xml version="1.0" ?>\n<data>\n' + rows.replace('sparse="false"', 'sparse="true"')
        + "</data>\n")
    return {"root": str(root), "missing_vendor": missing}


# ---------------------------------------------------------------------------
# A full disk dump with a partition table
# ---------------------------------------------------------------------------

DUMP_PARTITIONS = [
    # (name, sectors, kind of content)
    ("preloader", 512, "preloader"),
    ("boot_a", 1024, "boot"),
    ("system_a", 4096, "ext4"),
    ("super", 8192, "super"),
    ("userdata", 2048, "f2fs"),
    ("modem", 1024, "raw"),
]


def make_full_dump(path: Path, corrupt_gpt: bool = False, truncated: bool = False) -> Path:
    """A 4 MiB synthetic eMMC image: protective MBR, GPT, partitions, backup GPT."""
    parts = []
    cursor = 34
    for name, sectors, _kind in DUMP_PARTITIONS:
        parts.append(gpt_mod.PartitionEntry(0, name, LIST_TYPE, str(uuid.uuid4()),
                                            cursor, cursor + sectors - 1, 0))
        cursor += sectors
    total_sectors = max(8192, cursor + 64)
    mbr, primary, backup = gpt_mod.build_gpt_bytes(parts, total_sectors, SECTOR)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(mbr)
        fh.write(primary)
        for entry, (name, sectors, kind) in zip(parts, DUMP_PARTITIONS):
            fh.seek(entry.first_lba * SECTOR)
            if kind == "preloader":
                fh.write(_pad_to(b"EMMC_BOOT" + bytes(range(256)) * 40, sectors * SECTOR)[:sectors * SECTOR])
            elif kind == "boot":
                data = make_boot_image_bytes()
                fh.write(_pad_to(data, sectors * SECTOR)[:sectors * SECTOR])
            elif kind == "ext4":
                fh.write(make_ext4_block("system_a", blocks=2048)[:sectors * SECTOR])
            elif kind == "super":
                data = make_super_image_bytes()
                fh.write(_pad_to(data, sectors * SECTOR)[:sectors * SECTOR])
            elif kind == "f2fs":
                fh.write(make_f2fs_block("userdata", blocks=1024)[:sectors * SECTOR])
            else:
                fh.write(b"MODEM-FIRMWARE " * 64)
        table_sectors = (128 * 128 + SECTOR - 1) // SECTOR
        fh.seek((total_sectors - 1 - table_sectors) * SECTOR)
        fh.write(backup)
        fh.seek(total_sectors * SECTOR - 1)
        fh.write(b"\x00")
    if corrupt_gpt:
        with path.open("r+b") as fh:
            fh.seek(SECTOR + 16)
            fh.write(b"\x00\x00\x00\x00")
    if truncated:
        size = path.stat().st_size
        with path.open("r+b") as fh:
            fh.truncate(size - 64 * 1024)
    return path


def make_boot_image_bytes() -> bytes:
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        target = Path(folder) / "boot.img"
        make_boot_image(target)
        return target.read_bytes()


def make_super_image_bytes() -> bytes:
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        target = Path(folder) / "super.img"
        make_super_image(target)
        return target.read_bytes()


# ---------------------------------------------------------------------------
# The whole tree
# ---------------------------------------------------------------------------

def make_demo_tree(out_dir: Path, corrupt_gpt: bool = False) -> dict:
    """Build every fixture. Returns a dict of paths the tests and the UI use."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    single = out / "single"
    single.mkdir(exist_ok=True)

    mtk = make_firmware_folder(out / "firmware_mtk6768")
    broken = make_firmware_folder(out / "firmware_broken", project="k65v1_64_bsp", broken=True)
    qualcomm = make_qualcomm_folder(out / "firmware_qualcomm")

    dump = make_full_dump(out / "dump_full.bin", corrupt_gpt=corrupt_gpt, truncated=True)
    boot_img = make_boot_image(single / "boot.img")
    super_img = make_super_image(single / "super.img")
    raw = _w(single / "system_a_ext4.img", make_ext4_block("system_a", blocks=1024))
    sparse_img = make_sparse_image(raw, single / "system_a_sparse.img")
    lz4_img = make_lz4_file(b"REVIVE LZ4 PAYLOAD\n" + b"payload data " * 4096,
                            single / "system_a.img.lz4")
    f2fs_img = _w(single / "userdata_f2fs.img", make_f2fs_block("userdata", blocks=1024))

    info = {
        "out": str(out),
        "firmware_mtk": mtk,
        "firmware_broken": broken,
        "firmware_qualcomm": qualcomm,
        "dump": str(dump),
        "corrupt_gpt": corrupt_gpt,
        "boot_img": str(boot_img),
        "super_img": str(super_img),
        "sparse_img": str(sparse_img),
        "lz4_img": str(lz4_img),
        "f2fs_img": str(f2fs_img),
        "single_dir": str(single),
    }
    (out / "index.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic phone data for Revive")
    parser.add_argument("--out", default="demo", help="where to write the demo tree")
    parser.add_argument("--corrupt-gpt", action="store_true",
                        help="damage the primary GPT so repair can be demonstrated")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    info = make_demo_tree(Path(args.out), corrupt_gpt=args.corrupt_gpt)
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(f"demo data written to {info['out']}\n")
    print(f"  MediaTek package (good)   {info['firmware_mtk']['root']}")
    print(f"  MediaTek package (broken) {info['firmware_broken']['root']}")
    print(f"  Qualcomm package          {info['firmware_qualcomm']['root']}")
    print(f"  full dump                 {info['dump']}")
    print(f"  single images             {info['single_dir']}")
    print("\ntry:")
    print(f"  revive inspect {info['firmware_mtk']['root']}")
    print(f"  revive plan {info['firmware_broken']['root']}")
    print(f"  revive dump-analyse {info['dump']}")
    print(f"  revive serve --demo --open")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
