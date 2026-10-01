"""Virtual partition layouts and the synthetic content that goes inside them.

A lab device needs a partition table that behaves like a real phone's, because almost every
fault Revive is asked about is a statement about a partition: it is missing, it is blank, its
filesystem is dirty, its boot header no longer parses. So the layouts here use real partition
names and real *relative* sizes, and each partition is filled with content that Revive's own
parsers recognise (an ext4 superblock, an Android boot header, an F2FS superblock, an NVRAM
header). That is what lets `revive.ops.dump.analyse` say something true about a lab device.

Sizes are nominal (what the partition would be on a 64 GB phone) and are scaled into the much
smaller on-disk lab image. Both numbers are recorded, so a report can show the layout a
technician would recognise next to the bytes that actually exist in the file.
"""
from __future__ import annotations

import hashlib
import logging
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..util import crc32, human_size, sha256_bytes

LOG = logging.getLogger("revive.lab.partitions")

SECTOR = 512

# Smallest partition we are willing to allocate in the lab image, and the floor for the
# partitions that must hold something parseable.
MIN_PARTITION_BYTES = 64 * 1024
BOOT_MIN_BYTES = 512 * 1024

# Partition statuses reported in the partition map and in reports.
ST_OK = "ok"
ST_DAMAGED = "damaged"
ST_BLANK = "blank"
ST_MISSING = "missing"
ST_DIRTY = "dirty"

STATUS_SEVERITY = {
    ST_OK: "ok",
    ST_BLANK: "warn",
    ST_DIRTY: "warn",
    ST_DAMAGED: "error",
    ST_MISSING: "fatal",
}


# --------------------------------------------------------------------------------------
# Layout description
# --------------------------------------------------------------------------------------

@dataclass
class PartitionSpec:
    """One row of a vendor partition layout, in nominal (real phone) bytes."""

    name: str
    nominal_size: int
    kind: str = "raw"                 # how the content is generated: boot/ext4/f2fs/preloader/nvram/raw
    region: str = "user"              # eMMC hardware partition: user / boot1 / boot2 / rpmb
    role: str = ""                    # what breaks if this partition is wrong
    critical: bool = False            # the phone cannot boot / cannot keep its identity without it
    grow: bool = False                # takes the remaining space (userdata does)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "nominal_size": self.nominal_size,
            "nominal_size_human": human_size(self.nominal_size), "kind": self.kind,
            "region": self.region, "role": self.role, "critical": self.critical,
            "grow": self.grow,
        }


def _spec(name: str, size_mb: float, kind: str = "raw", region: str = "user", role: str = "",
          critical: bool = False, grow: bool = False) -> PartitionSpec:
    return PartitionSpec(name=name, nominal_size=int(size_mb * 1024 * 1024), kind=kind,
                         region=region, role=role, critical=critical, grow=grow)


# MediaTek: the layout SP Flash Tool scatter files describe. `super` is included because
# modern MTK phones carry their system/vendor inside it, and `proinfo`/`nvram`/`protect*` are
# the identity partitions Revive warns about before any write.
MTK_LAYOUT: List[PartitionSpec] = [
    _spec("preloader", 0.25, "preloader", "boot1", "stage-1 boot; a bad preloader is a hard brick", True),
    _spec("pgpt", 0.5, "gpt", "user", "the partition table itself", True),
    _spec("nvram", 5, "nvram", "user", "IMEI, Wi-Fi/BT MAC, calibration", True),
    _spec("nvdata", 5, "ext4", "user", "runtime NVRAM (rebuilt from nvram)", True),
    _spec("protect1", 8, "ext4", "user", "DRM keys and sensor calibration"),
    _spec("protect2", 8, "ext4", "user", "DRM keys and sensor calibration (copy)"),
    _spec("proinfo", 3, "nvram", "user", "production info: IMEI copy, serial", True),
    _spec("lk", 4, "raw", "user", "little kernel: the bootloader that loads boot.img", True),
    _spec("boot", 32, "boot", "user", "kernel + ramdisk; the phone boots from here", True),
    _spec("recovery", 32, "boot", "user", "recovery ramdisk"),
    _spec("vbmeta", 1, "raw", "user", "verified boot metadata"),
    _spec("super", 2048, "ext4", "user", "dynamic partitions: system + vendor", True),
    _spec("system", 1024, "ext4", "user", "the Android system", True),
    _spec("vendor", 512, "ext4", "user", "vendor HALs and kernel modules"),
    _spec("userdata", 55000, "f2fs", "user", "everything the user owns", grow=True),
]

# Qualcomm: the layout rawprogram0.xml describes (GPT, xbl/abl boot chain, modem identity).
QUALCOMM_LAYOUT: List[PartitionSpec] = [
    _spec("xbl", 2, "raw", "boot1", "eXtensible Boot Loader; a bad XBL is a hard brick", True),
    _spec("xbl_config", 0.25, "raw", "boot1", "XBL configuration"),
    _spec("abl", 1, "raw", "user", "Android Boot Loader (fastboot lives here)", True),
    _spec("tz", 1, "raw", "user", "TrustZone image"),
    _spec("modemst1", 1, "nvram", "user", "modem identity: IMEI/QCN", True),
    _spec("modemst2", 1, "nvram", "user", "modem identity backup", True),
    _spec("fsg", 1, "nvram", "user", "filesystem golden copy of modem NV"),
    _spec("fsc", 0.05, "raw", "user", "FSG cookie"),
    _spec("boot", 64, "boot", "user", "kernel + ramdisk; the phone boots from here", True),
    _spec("system", 3072, "ext4", "user", "the Android system", True),
    _spec("vendor", 512, "ext4", "user", "vendor HALs"),
    _spec("userdata", 55000, "ext4", "user", "everything the user owns", grow=True),
]

# Unisoc: the partitions inside a .pac. Revive lists and extracts PAC files but does not
# flash them, so the lab mirrors that: these partitions can be read and damaged, never written
# by a simulated flash.
UNISOC_LAYOUT: List[PartitionSpec] = [
    _spec("bootloader", 1, "preloader", "user", "SPL/bootloader; a bad one is a hard brick", True),
    _spec("uboot", 2, "raw", "user", "U-Boot proper", True),
    _spec("fixnv", 1, "nvram", "user", "IMEI and calibration (fixed NV)", True),
    _spec("runtimenv", 1, "nvram", "user", "runtime NV"),
    _spec("prodnv", 1, "nvram", "user", "production NV: serial, IMEI copy", True),
    _spec("boot", 32, "boot", "user", "kernel + ramdisk", True),
    _spec("system", 3072, "ext4", "user", "the Android system", True),
    _spec("vendor", 256, "ext4", "user", "vendor HALs"),
    _spec("userdata", 25000, "ext4", "user", "everything the user owns", grow=True),
]

LAYOUTS: Dict[str, List[PartitionSpec]] = {
    "mtk": MTK_LAYOUT,
    "qualcomm": QUALCOMM_LAYOUT,
    "unisoc": UNISOC_LAYOUT,
}


def layout_for(platform: str) -> List[PartitionSpec]:
    """The partition layout for a platform. Unknown platforms get the MediaTek one."""
    key = (platform or "mtk").lower()
    if key not in LAYOUTS:
        LOG.warning("no lab layout for platform %r; falling back to the MTK layout", platform)
        key = "mtk"
    return [PartitionSpec(**spec.__dict__) for spec in LAYOUTS[key]]


def layout_names(platform: str) -> List[str]:
    return [spec.name for spec in layout_for(platform)]


# --------------------------------------------------------------------------------------
# The live partition, as it exists inside the lab image
# --------------------------------------------------------------------------------------

@dataclass
class VirtualPartition:
    """A partition as it exists in the lab image: real offset, real size, real checksum."""

    name: str = ""
    offset: int = 0
    size: int = 0
    nominal_size: int = 0
    kind: str = "raw"
    region: str = "user"
    role: str = ""
    critical: bool = False
    status: str = ST_OK
    checksum: str = ""
    issues: List[str] = field(default_factory=list)
    faults: List[str] = field(default_factory=list)   # brick ids that have touched this partition

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def first_lba(self) -> int:
        return self.offset // SECTOR

    @property
    def last_lba(self) -> int:
        return max(self.first_lba, (self.end - 1) // SECTOR)

    @property
    def size_human(self) -> str:
        return human_size(self.size)

    @property
    def nominal_size_human(self) -> str:
        return human_size(self.nominal_size)

    @property
    def is_healthy(self) -> bool:
        return self.status == ST_OK

    def mark(self, status: str, issue: str, fault: str = "") -> None:
        """Record damage. The most severe status wins so repeated bricks do not hide each other."""
        if util_severity(status) > util_severity(self.status):
            self.status = status
        if issue and issue not in self.issues:
            self.issues.append(issue)
        if fault and fault not in self.faults:
            self.faults.append(fault)

    def heal(self) -> None:
        self.status = ST_OK
        self.issues = []
        self.faults = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "offset": self.offset, "offset_hex": f"0x{self.offset:x}",
            "size": self.size, "size_human": self.size_human,
            "nominal_size": self.nominal_size, "nominal_size_human": self.nominal_size_human,
            "first_lba": self.first_lba, "last_lba": self.last_lba,
            "kind": self.kind, "region": self.region, "role": self.role,
            "critical": self.critical, "status": self.status,
            "severity": STATUS_SEVERITY.get(self.status, "info"),
            "checksum": self.checksum, "issues": list(self.issues), "faults": list(self.faults),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VirtualPartition":
        part = cls(
            name=str(data.get("name", "")), offset=int(data.get("offset", 0)),
            size=int(data.get("size", 0)), nominal_size=int(data.get("nominal_size", 0)),
            kind=str(data.get("kind", "raw")), region=str(data.get("region", "user")),
            role=str(data.get("role", "")), critical=bool(data.get("critical", False)),
            status=str(data.get("status", ST_OK)), checksum=str(data.get("checksum", "")),
        )
        part.issues = [str(i) for i in data.get("issues", [])]
        part.faults = [str(f) for f in data.get("faults", [])]
        return part


def util_severity(status: str) -> int:
    """Rank a status so `mark` can keep the worst one."""
    from ..util import SEV_ORDER

    return SEV_ORDER.get(STATUS_SEVERITY.get(status, "info"), 0)


# --------------------------------------------------------------------------------------
# Fitting a real layout into a small lab image
# --------------------------------------------------------------------------------------

@dataclass
class LayoutPlan:
    """The result of scaling a nominal layout into a lab image."""

    image_bytes: int = 0
    sector_size: int = SECTOR
    partitions: List[VirtualPartition] = field(default_factory=list)
    scale: float = 1.0
    notes: List[str] = field(default_factory=list)

    def find(self, name: str) -> Optional[VirtualPartition]:
        low = name.lower()
        for part in self.partitions:
            if part.name.lower() == low:
                return part
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_bytes": self.image_bytes, "image_size_human": human_size(self.image_bytes),
            "sector_size": self.sector_size, "scale": self.scale,
            "partition_count": len(self.partitions),
            "partitions": [p.to_dict() for p in self.partitions], "notes": list(self.notes),
        }


def plan_layout(specs: Sequence[PartitionSpec], image_bytes: int,
                sector_size: int = SECTOR) -> LayoutPlan:
    """Scale a nominal layout into ``image_bytes``, keeping the GPT overhead usable.

    The GPT needs a protective MBR, a header sector and 32 entry sectors at the front, and the
    entry array plus a header at the back. Partitions are laid out in between: every one gets a
    floor large enough to hold parseable content, the rest of the space is shared out in
    proportion to the nominal sizes, and the partition marked `grow` (userdata) takes whatever
    is left.
    """
    specs = list(specs)
    if image_bytes < 4 * 1024 * 1024:
        raise ValueError("a lab image must be at least 4 MiB to hold a GPT and its partitions")

    entry_sectors = (128 * 128 + sector_size - 1) // sector_size
    gpt_bytes = (2 + entry_sectors) * sector_size          # MBR + header + entry array
    tail_bytes = (entry_sectors + 1) * sector_size         # backup entries + backup header

    # A partition of kind "gpt" *is* the table region at LBA 0, so it is placed there and is
    # not carved out of the space the other partitions share.
    gpt_specs = [s for s in specs if s.kind == "gpt"]
    allocatable = [s for s in specs if s.kind != "gpt"]
    usable_bytes = max(0, image_bytes - gpt_bytes - tail_bytes)
    nominal_total = sum(s.nominal_size for s in allocatable) or 1
    plan = LayoutPlan(image_bytes=image_bytes, sector_size=sector_size,
                      scale=usable_bytes / nominal_total)

    # 1. Floors: the smallest partition that can still hold something Revive can parse.
    floors: Dict[str, int] = {}
    for spec in allocatable:
        floors[spec.name] = _floor_for(spec, sector_size)
    floor_total = sum(floors.values())
    if floor_total > usable_bytes:
        plan.notes.append(
            f"the layout needs at least {human_size(floor_total)} but the image only leaves "
            f"{human_size(usable_bytes)} for partitions; partitions were shrunk below their "
            "normal minimum and some content may not parse")

    # 2. Share out whatever is left, in proportion to the nominal sizes.
    spare = max(0, usable_bytes - floor_total)
    grow_specs = [s for s in allocatable if s.grow]
    fixed_specs = [s for s in allocatable if not s.grow]
    fixed_nominal = sum(s.nominal_size for s in fixed_specs) or 1

    sizes: Dict[str, int] = {}
    for spec in fixed_specs:
        share = int(spare * spec.nominal_size / fixed_nominal)
        sizes[spec.name] = _align(floors[spec.name] + share, sector_size)
    if grow_specs:
        # Whatever is left goes to the growing partition(s), never below the floor.
        leftover = max(0, usable_bytes - sum(sizes.values()))
        per = _align(max(leftover // len(grow_specs), floors[grow_specs[0].name]), sector_size)
        for spec in grow_specs:
            sizes[spec.name] = per
    else:
        plan.notes.append("this layout has no growing partition, so the tail of the image is "
                          "left unallocated (normal for a partial layout)")

    # 3. Lay them out. The table partition covers LBA 0; everything else follows it.
    placements: Dict[str, int] = {}
    cursor = gpt_bytes          # partitions start after the primary table
    for spec in allocatable:
        placements[spec.name] = cursor
        cursor += sizes.get(spec.name, floors[spec.name])

    for spec in specs:
        if spec.kind == "gpt":
            offset, size = 0, gpt_bytes
        else:
            offset = placements[spec.name]
            size = sizes.get(spec.name, floors[spec.name])
        if offset + size > image_bytes - tail_bytes:
            size = max(0, image_bytes - tail_bytes - offset)
            if size <= 0:
                plan.notes.append(f"{spec.name} did not fit in the lab image and is recorded as "
                                  "missing - increase the image size to simulate it")
                continue
        plan.partitions.append(VirtualPartition(
            name=spec.name, offset=_align(offset, sector_size), size=_align(size, sector_size),
            nominal_size=spec.nominal_size, kind=spec.kind, region=spec.region,
            role=spec.role, critical=spec.critical,
        ))
    plan.partitions.sort(key=lambda part: part.offset)
    return plan


def _floor_for(spec: PartitionSpec, sector_size: int = SECTOR) -> int:
    """The smallest useful size for a partition of this kind."""
    if spec.kind == "boot":
        floor = BOOT_MIN_BYTES
    elif spec.kind in ("ext4", "f2fs"):
        floor = 256 * 1024
    elif spec.kind == "nvram":
        floor = 64 * 1024
    else:
        floor = MIN_PARTITION_BYTES
    return _align(max(floor, sector_size), sector_size)


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        return max(0, value)
    return max(0, (int(value) // alignment) * alignment)


# --------------------------------------------------------------------------------------
# Synthetic partition content
# --------------------------------------------------------------------------------------
#
# Each builder returns the first bytes of a partition. They are deliberately small: the lab
# image is a few tens of MiB, and Revive's parsers only ever look at a partition's head.

NVRAM_MAGIC = b"NVRAM_REVIVE_LAB"
NVRAM_IMEI_COUNT = 4


def build_preloader(chipset: str = "MT6768") -> bytes:
    """A MediaTek-style preloader head: the EMMC_BOOT marker the scanner looks for."""
    body = bytearray(64 * 1024)
    body[0:9] = b"EMMC_BOOT"
    body[16:16 + len(chipset)] = chipset.encode("ascii", "replace")[:16]
    body[512:512 + 32] = b"MTK_DOWNLOAD_AGENT" + b"\x00" * 14
    blob = bytes(range(256)) * 64
    body[1024:1024 + len(blob)] = blob
    return bytes(body)


def build_boot_image(cmdline: str = "console=ttyMT0,115200n8 androidboot.hardware=lab",
                     page_size: int = 2048, kernel_label: bytes = b"LAB KERNEL v1") -> bytes:
    """An Android boot image (header v0) that `revive.storage.bootimg` can actually parse."""
    import gzip

    kernel = gzip.compress(kernel_label * 32 + b"\n" + bytes(range(256)) * 64, mtime=0)
    ramdisk = gzip.compress(b"LAB RAMDISK\n" + b"init" * 400, mtime=0)
    second = b"LAB SECOND STAGE\n" * 8

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
    struct.pack_into("<I", header, 40, 0)                       # header version 0
    struct.pack_into("<I", header, 44, (11 << 25) | (25 << 4) | 3)
    header[48:64] = b"revive-lab".ljust(16, b"\x00")
    header[64:64 + len(cmdline)] = cmdline.encode()[:448]

    body = bytearray(pad(bytes(header)) + pad(kernel) + pad(ramdisk) + pad(second))
    body[576:596] = hashlib.sha1(bytes(body[:page_size]) + kernel).digest()
    struct.pack_into("<I", body, 608, len(body))
    return bytes(body)


def build_ext4_superblock(label: str, size_bytes: int, block_size: int = 4096,
                          state: int = 1) -> bytes:
    """An ext4 superblock whose declared size matches the partition, so no false mismatch."""
    blocks = max(1, size_bytes // block_size)
    data = bytearray(min(size_bytes, 64 * 1024))
    if len(data) < 8192:
        data = bytearray(8192)
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x00, max(1, blocks // 4))
    struct.pack_into("<I", sb, 0x04, blocks & 0xFFFFFFFF)
    struct.pack_into("<I", sb, 0x18, {1024: 0, 2048: 1, 4096: 2}.get(block_size, 2))
    struct.pack_into("<I", sb, 0x20, 32768)
    struct.pack_into("<I", sb, 0x28, 8192)
    struct.pack_into("<H", sb, 0x38, 0xEF53)
    struct.pack_into("<H", sb, 0x3A, state)                     # 1 = cleanly unmounted
    struct.pack_into("<I", sb, 0x5C, 0x4)                       # compat: has_journal
    struct.pack_into("<I", sb, 0x60, 0x40 | 0x80)               # incompat: extents + 64bit
    sb[0x68:0x78] = uuid.uuid5(uuid.NAMESPACE_DNS, "revive-lab/" + label).bytes
    sb[0x78:0x88] = label.encode()[:16].ljust(16, b"\x00")
    data[1024:2048] = sb
    if blocks >> 32:
        struct.pack_into("<I", data, 1024 + 0x150, blocks >> 32)
    blob = f"REVIVE LAB EXT4 {label} ".encode() + bytes(range(256)) * 4
    data[8192:8192 + len(blob)] = blob
    return bytes(data)


def build_f2fs_superblock(label: str, size_bytes: int, block_size: int = 4096) -> bytes:
    """An F2FS superblock: what userdata actually looks like on most MediaTek phones."""
    blocks = max(1, size_bytes // block_size)
    data = bytearray(min(size_bytes, 64 * 1024))
    if len(data) < 8192:
        data = bytearray(8192)
    sb = bytearray(256)
    struct.pack_into("<I", sb, 0, 0xF2F52010)
    struct.pack_into("<HH", sb, 4, 1, 15)
    struct.pack_into("<I", sb, 8, 9)                            # 512 byte sectors
    struct.pack_into("<I", sb, 16, 12)                          # 4096 byte blocks
    struct.pack_into("<Q", sb, 40, blocks)
    sb[48:64] = label.encode()[:16].ljust(16, b"\x00")
    data[1024:1024 + len(sb)] = sb
    blob = b"REVIVE LAB F2FS DATA " + bytes(range(256)) * 4
    data[4096:4096 + len(blob)] = blob
    return bytes(data)


NVRAM_HEADER_BYTES = 64
NVRAM_RECORD_STRIDE = 128
NVRAM_VALUE_OFFSET = 40


def _write_record(data: bytearray, offset: int, lid: int, label: str, value: bytes) -> None:
    """One LID record: id and length, a 36-byte label, then the value."""
    struct.pack_into("<HH", data, offset, lid, len(value) + 1)
    data[offset + 4:offset + 4 + len(label)] = label.encode()[:36]
    data[offset + NVRAM_VALUE_OFFSET:offset + NVRAM_VALUE_OFFSET + len(value)] = value


def _calibration_stream(imei: str, serial: str, lid: int, length: int) -> bytes:
    """Deterministic filler for the RF/calibration LIDs.

    It has to be derived from the identity rather than random, or a device would come out
    different every time it was created and its golden copies would not match.
    """
    seed = f"revive-lab-nvram|{imei}|{serial}|0x{lid:04X}".encode("ascii")
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "little")).digest()
        counter += 1
    # No 0x00 bytes: a record that decodes to an empty string would read as damage.
    return bytes((byte or 0x5A) for byte in out[:length])


def build_nvram(imei: str = "353001100000001", serial: str = "LAB0000001",
                wifi_mac: str = "02:00:00:00:00:01", size: int = 16 * 1024) -> bytes:
    """A lab NVRAM block: magic, a record count, and readable identity strings.

    Real NVRAM is a vendor-private LID/record structure: the identity LIDs come first and the
    rest of the block is RF calibration and vendor data. The lab writes both halves, because a
    block that held nothing but four short records would be more than 99.5% zeroes - and
    Revive's own dump analysis flags a region that empty as "blank", which would make a healthy
    lab device look unwritten.
    """
    data = bytearray(size)
    data[0:16] = NVRAM_MAGIC
    struct.pack_into("<I", data, 20, 0x0102)                    # layout version 1.2
    struct.pack_into("<I", data, 28, size)
    records = [
        (0x0001, "IMEI", imei.encode("ascii")),
        (0x0002, "SERIAL", serial.encode("ascii")),
        (0x0004, "WIFI_MAC", wifi_mac.encode("ascii")),
        (0x0005, "BT_MAC", b"02:00:00:00:00:02"),
    ]
    offset = NVRAM_HEADER_BYTES
    for lid, name, value in records:
        _write_record(data, offset, lid, name, value)
        offset += NVRAM_RECORD_STRIDE
    # The calibration LIDs that fill the rest of the block.
    lid = 0x0100
    count = len(records)
    while offset + NVRAM_RECORD_STRIDE <= size:
        length = min(64, NVRAM_RECORD_STRIDE - NVRAM_VALUE_OFFSET)
        _write_record(data, offset, lid, f"RF_CAL_{lid:04X}",
                      _calibration_stream(imei, serial, lid, length))
        offset += NVRAM_RECORD_STRIDE
        lid += 1
        count += 1
    struct.pack_into("<I", data, 16, count)                     # total record count
    # The checksum covers the record area, so a partially written NVRAM is detectable.
    struct.pack_into("<I", data, 24, crc32(bytes(data[NVRAM_HEADER_BYTES:])) & 0xFFFFFFFF)
    return bytes(data)


def build_raw(label: str, size: int = 16 * 1024) -> bytes:
    """Unstructured content for loaders, tz, vbmeta and friends."""
    data = bytearray(size)
    blob = f"REVIVE LAB RAW {label} ".encode() + bytes(range(256)) * 8
    data[0:len(blob)] = blob[:size]
    return bytes(data)


def content_for(part: VirtualPartition, chipset: str = "MT6768", imei: str = "353001100000001",
                serial: str = "LAB0000001") -> bytes:
    """The bytes that go at the start of a freshly created partition."""
    kind = (part.kind or "raw").lower()
    try:
        if kind == "preloader":
            return build_preloader(chipset)[:part.size] or b"\x00" * min(part.size, 4096)
        if kind == "boot":
            return build_boot_image()[:part.size]
        if kind == "ext4":
            return build_ext4_superblock(part.name, part.size)[:part.size]
        if kind == "f2fs":
            return build_f2fs_superblock(part.name, part.size)[:part.size]
        if kind == "nvram":
            return build_nvram(imei=imei, serial=serial,
                               size=max(1024, min(part.size, 16 * 1024)))[:part.size]
        if kind == "gpt":
            # The pgpt partition mirrors the table at LBA 0; it is written by the GPT writer.
            return b""
        return build_raw(part.name)[:part.size]
    except (ValueError, OSError, struct.error) as exc:                  # pragma: no cover
        LOG.warning("could not build %s content for %s: %s", kind, part.name, exc)
        return b""


def checksum_of(data: bytes) -> str:
    return sha256_bytes(data)
