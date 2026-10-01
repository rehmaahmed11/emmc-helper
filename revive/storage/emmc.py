"""eMMC identity, capacity and health decoding (CID / CSD / EXT_CSD).

An eMMC that is nearly worn out will accept a flash and then corrupt data, so "is this phone's
storage dying?" belongs at the top of a repair session. These three registers answer it, and all
three are plain byte blobs, which means the logic is testable without a phone.

Register layouts are from the JEDEC JESD84 specification. Anything that vendors are known to
implement differently (the manufacturing date, the device-version byte order) is reported as
"best effort" instead of pretending to be certain.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..util import human_size

MANUFACTURERS = {
    0x11: "Toshiba / Kioxia", 0x13: "Micron", 0x15: "Samsung", 0x1B: "Samsung (legacy)",
    0x2C: "Micron (legacy)", 0x45: "SanDisk", 0x90: "SK Hynix", 0x9B: "Kioxia",
    0xAD: "Hynix (legacy)", 0xFE: "Micron / Numonyx",
}

TRAN_SPEED_NAMES = {
    0x0B: "10 Mbit/s", 0x1A: "26 Mbit/s", 0x2A: "50 Mbit/s", 0x32: "100 Mbit/s",
    0x3A: "150 Mbit/s", 0x4A: "200 Mbit/s", 0x5A: "200 Mbit/s (HS200)",
    0x6A: "400 Mbit/s (HS400)", 0x2B: "52 Mbit/s (DDR)",
}

PRE_EOL_STATES = {
    0x00: ("not defined", "info"),
    0x01: ("normal", "ok"),
    0x02: ("warning", "warn"),
    0x03: ("urgent", "fatal"),
}


def _life_text(value: Optional[int]) -> str:
    if value is None:
        return "not reported"
    if value == 0x00:
        return "not defined by this chip"
    if 1 <= value <= 0x0A:
        low = (value - 1) * 10
        return f"{low}-{low + 10}% of rated life used"
    if value == 0x0B:
        return "EXCEEDED the rated life"
    return f"reserved value 0x{value:02X}"


def _life_severity(value: Optional[int]) -> str:
    if value is None:
        return "info"
    if value >= 0x0B:
        return "fatal"
    if value >= 0x09:
        return "warn"
    return "ok"


@dataclass
class CidInfo:
    mid: int = 0
    manufacturer: str = ""
    oem: int = 0
    product_name: str = ""
    revision: str = ""
    serial: int = 0
    manufacture_date: str = "unknown"
    year: Optional[int] = None
    month: Optional[int] = None
    raw: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def serial_hex(self) -> str:
        return f"0x{self.serial:08X}"

    def to_dict(self) -> Dict[str, Any]:
        return {"manufacturer": self.manufacturer or f"unknown (0x{self.mid:02X})",
                "mid": f"0x{self.mid:02X}", "oem": f"0x{self.oem:04X}",
                "product_name": self.product_name, "revision": self.revision,
                "serial": self.serial_hex, "manufacture_date": self.manufacture_date,
                "raw": self.raw, "notes": self.notes}


@dataclass
class CsdInfo:
    structure: int = 0
    structure_name: str = ""
    size_bytes: Optional[int] = None
    c_size: int = 0
    c_size_mult: int = 0
    read_bl_len: int = 0
    tran_speed: str = ""
    raw: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def capacity_bytes(self) -> Optional[int]:
        return self.size_bytes

    def to_dict(self) -> Dict[str, Any]:
        return {"structure": self.structure,
                "structure_name": self.structure_name or f"CSD {self.structure}",
                "size_bytes": self.size_bytes,
                "size_human": human_size(self.size_bytes) if self.size_bytes else "",
                "c_size": self.c_size, "c_size_mult": self.c_size_mult,
                "read_bl_len": self.read_bl_len, "tran_speed": self.tran_speed,
                "raw": self.raw, "notes": self.notes}


@dataclass
class ExtCsdInfo:
    revision: int = 0
    sec_count: Optional[int] = None
    boot_size_mult: Optional[int] = None
    rpmb_size_mult: Optional[int] = None
    pre_eol: Optional[int] = None
    life_a_value: Optional[int] = None
    life_b_value: Optional[int] = None
    device_version_raw: Optional[int] = None
    firmware_version: str = ""
    raw: str = ""
    notes: List[str] = field(default_factory=list)

    # -- derived ----------------------------------------------------------------
    @property
    def capacity_bytes(self) -> Optional[int]:
        return self.sec_count * 512 if self.sec_count else None

    @property
    def boot_size(self) -> int:
        return int(self.boot_size_mult or 0) * 128 * 1024

    @property
    def rpmb_size(self) -> int:
        return int(self.rpmb_size_mult or 0) * 128 * 1024

    @property
    def device_version(self) -> str:
        raw = self.device_version_raw
        if not raw:
            return ""
        major = (raw >> 4) & 0x0F
        minor = raw & 0x0F
        if not major:
            return f"pre-4.x (0x{raw:04X})"
        return f"eMMC {major}.{minor}"

    @property
    def life_a(self) -> str:
        return _life_text(self.life_a_value)

    @property
    def life_b(self) -> str:
        return _life_text(self.life_b_value)

    @property
    def health(self) -> str:
        name, _severity = PRE_EOL_STATES.get(self.pre_eol if self.pre_eol is not None else 0x00,
                                             ("unknown", "info"))
        return name

    @property
    def warnings(self) -> List[str]:
        out: List[str] = []
        if (self.pre_eol or 0) >= 0x02:
            out.append(f"PRE_EOL_INFO reports {self.health}: the chip is near the end of its "
                       "rated write endurance")
        for label, value in (("A", self.life_a_value), ("B", self.life_b_value)):
            if (value or 0) >= 0x09:
                out.append(f"DEVICE_LIFE_TIME_EST_TYP_{label} is 0x{value:02X} ({_life_text(value)})")
        if self.sec_count and self.sec_count > 0xFFFFFFF0:
            out.append("SEC_COUNT reads as erased (all 0xFF): the storage did not initialise")
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "revision": self.revision, "capacity_bytes": self.capacity_bytes,
            "capacity_human": human_size(self.capacity_bytes) if self.capacity_bytes else "",
            "sec_count": self.sec_count,
            "boot_size": self.boot_size,
            "boot_size_human": human_size(self.boot_size) if self.boot_size else "",
            "rpmb_size": self.rpmb_size,
            "rpmb_size_human": human_size(self.rpmb_size) if self.rpmb_size else "",
            "pre_eol": self.health, "life_a": self.life_a, "life_b": self.life_b,
            "device_version": self.device_version, "firmware_version": self.firmware_version,
            "warnings": self.warnings, "notes": self.notes, "raw": self.raw,
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_cid(blob: bytes) -> CidInfo:
    if len(blob) < 16:
        raise ValueError(f"a CID is 16 bytes, got {len(blob)}")
    blob = blob[:16]
    info = CidInfo(raw=blob.hex())
    info.mid = blob[0]
    info.manufacturer = MANUFACTURERS.get(info.mid, "")
    info.oem = struct.unpack_from(">H", blob, 1)[0]
    info.product_name = blob[3:9].decode("ascii", "replace").strip()
    if not info.product_name.isprintable():
        info.product_name = blob[3:9].hex()
    info.revision = f"{blob[9] >> 4}.{blob[9] & 0x0F}"
    info.serial = struct.unpack_from(">I", blob, 10)[0]
    mdt = blob[14]
    year = 2000 + ((mdt >> 4) & 0x0F)
    month = mdt & 0x0F
    if 1 <= month <= 12:
        info.year, info.month = year, month
        info.manufacture_date = f"{month:02d}/{year:04d}"
    else:
        info.notes.append("the manufacturing date byte is not a valid year/month (some vendors "
                          "leave it blank on engineering samples)")
    if not info.manufacturer:
        info.notes.append(f"manufacturer ID 0x{info.mid:02X} is not in the known table; the chip "
                          "is still real, just less common")
    return info


def _legacy_size(c_size: int, c_size_mult: int, read_bl_len: int) -> int:
    if not (7 <= read_bl_len <= 12):
        return 0
    return (c_size + 1) * (1 << (c_size_mult + 2)) * (1 << read_bl_len)


def parse_csd(blob: bytes) -> CsdInfo:
    """Decode a 16-byte CSD. Structure 3 is the eMMC one: (C_SIZE+1) x 512 KiB."""
    if len(blob) < 16:
        raise ValueError(f"a CSD is 16 bytes, got {len(blob)}")
    blob = blob[:16]
    value = int.from_bytes(blob, "big")
    info = CsdInfo(raw=blob.hex())

    def bits(high: int, low: int) -> int:
        return (value >> low) & ((1 << (high - low + 1)) - 1)

    info.structure = bits(127, 126)
    info.tran_speed = TRAN_SPEED_NAMES.get(blob[3], f"{blob[3]:02X}h timing")
    info.read_bl_len = bits(83, 80)
    info.c_size_mult = bits(49, 47)
    if info.structure == 3:
        # eMMC: the datasheet formula is (C_SIZE+1) x 512 KiB, C_SIZE = bits [73:62].
        info.c_size = bits(73, 62)
        info.size_bytes = (info.c_size + 1) * 512 * 1024
        info.structure_name = "3 (eMMC: 512 KiB units)"
        legacy = _legacy_size(info.c_size, info.c_size_mult, info.read_bl_len)
        if legacy and abs(legacy - info.size_bytes) > info.size_bytes * 0.01:
            info.notes.append(
                f"the general CSD formula would give {human_size(legacy)}; for eMMC the "
                "(C_SIZE+1) x 512 KiB reading is the correct one")
    elif info.structure == 1:
        # SD v2.0 (SDHC/SDXC) uses a 22-bit C_SIZE at [69:48] with the 512 KiB unit.
        info.c_size = bits(69, 48)
        info.size_bytes = (info.c_size + 1) * 512 * 1024
        info.structure_name = "1 (SD v2.0)"
    else:
        info.c_size = bits(73, 62)
        info.size_bytes = _legacy_size(info.c_size, info.c_size_mult, info.read_bl_len)
        info.structure_name = f"{info.structure} (legacy CSD v1.x)"
        if not info.size_bytes:
            info.notes.append("the legacy size formula produced no usable value; the CSD is "
                              "probably from a card that uses the newer layout")
    info.notes.append("capacity from the CSD; EXT_CSD SEC_COUNT is the authoritative field when "
                      "the two disagree")
    return info


def parse_ext_csd(blob: bytes) -> ExtCsdInfo:
    """Decode the 512-byte EXT_CSD, including the wear/health bytes."""
    if len(blob) < 512:
        raise ValueError(f"EXT_CSD is 512 bytes, got {len(blob)}")
    blob = blob[:512]
    info = ExtCsdInfo(raw=blob.hex())
    info.revision = blob[192]
    info.sec_count = struct.unpack_from("<I", blob, 212)[0]
    info.boot_size_mult = blob[226]
    info.rpmb_size_mult = blob[168]
    info.pre_eol = blob[267]
    info.life_a_value = blob[268]
    info.life_b_value = blob[269]
    info.device_version_raw = struct.unpack_from("<H", blob, 262)[0]
    firmware = blob[254:262]
    info.firmware_version = firmware.decode("ascii", "replace").strip("\x00") if any(firmware) else ""
    if not info.revision:
        info.notes.append("EXT_CSD revision byte is zero; this chip may predate eMMC 4.1")
    if info.device_version_raw and not (info.device_version_raw & 0xF0):
        info.notes.append("device version byte order looks unusual on this part; treating the "
                          "value as best-effort")
    if info.boot_size_mult:
        info.notes.append(f"BOOT_SIZE_MULT 0x{info.boot_size_mult:02X}: each boot partition is "
                          f"{human_size(info.boot_size)} (there are two)")
    return info


parse_extcsd = parse_ext_csd          # the name it went by in earlier builds


def summary(cid: Optional[CidInfo], csd: Optional[CsdInfo],
            ext: Optional[ExtCsdInfo] = None) -> Dict[str, Any]:
    """One dict with everything a repair session wants to know about the storage."""
    capacity = (ext.capacity_bytes if ext else None) or (csd.size_bytes if csd else None)
    out: Dict[str, Any] = {
        "manufacturer": cid.manufacturer if cid else "",
        "product_name": cid.product_name if cid else "",
        "serial": cid.serial_hex if cid else "",
        "manufactured": cid.manufacture_date if cid else "",
        "capacity": capacity,
        "capacity_human": human_size(capacity) if capacity else "",
        "csd_capacity": csd.size_bytes if csd else None,
        "ext_csd_capacity": ext.capacity_bytes if ext else None,
        "device_version": ext.device_version if ext else "",
        "boot_size": ext.boot_size if ext else 0,
        "rpmb_size": ext.rpmb_size if ext else 0,
        "health": ext.health if ext else "unknown",
        "life_a": ext.life_a if ext else "",
        "life_b": ext.life_b if ext else "",
        "warnings": ext.warnings if ext else [],
        "notes": [],
    }
    if csd and csd.size_bytes and (ext.capacity_bytes if ext else None) and \
            csd.size_bytes != ext.capacity_bytes:
        out["notes"].append(
            f"CSD says {human_size(csd.size_bytes)} but EXT_CSD says "
            f"{human_size(ext.capacity_bytes)}; trust EXT_CSD and check for a re-marked chip")
    if not out["manufacturer"] and cid:
        out["notes"].append(f"unknown manufacturer id 0x{cid.mid:02X}")
    return out


def assess(cid: Optional[CidInfo] = None, csd: Optional[CsdInfo] = None,
           ext: Optional[ExtCsdInfo] = None) -> Dict[str, Any]:
    """Turn the registers into a verdict, with the advice that goes with it."""
    data = summary(cid, csd, ext)
    findings: List[Dict[str, Any]] = []
    verdict = "ok"
    if ext:
        if (ext.pre_eol or 0) >= 0x02:
            verdict = "fatal" if (ext.pre_eol or 0) >= 0x03 else "warn"
            findings.append({
                "severity": "fatal" if (ext.pre_eol or 0) >= 0x03 else "warn",
                "title": f"eMMC wear flag: {ext.health}",
                "detail": "PRE_EOL_INFO is a vendor-provided countdown to the end of the chip's "
                          "rated write endurance. Writes can still succeed and then corrupt.",
                "fixes": ["Dump everything you can now, read-only, before writing anything",
                          "Replace the eMMC if the phone is worth repairing properly",
                          "If it only has to boot once more, flash as little as possible"],
            })
        for label, value in (("A", ext.life_a_value), ("B", ext.life_b_value)):
            if (value or 0) >= 0x0B:
                verdict = "fatal"
                findings.append({
                    "severity": "fatal", "title": f"eMMC rated write life exceeded (type {label})",
                    "detail": f"DEVICE_LIFE_TIME_EST_TYP_{label} reports '{_life_text(value)}'.",
                    "fixes": ["Treat this phone's storage as end-of-life; a reflash will not hold",
                              "Prioritise extracting data over repairing the system"],
                })
            elif (value or 0) == 0x0A:
                verdict = "warn" if verdict == "ok" else verdict
                findings.append({
                    "severity": "warn", "title": f"eMMC is near its write limit (type {label})",
                    "detail": f"DEVICE_LIFE_TIME_EST_TYP_{label} reports '{_life_text(value)}'.",
                    "fixes": ["Avoid repeated full flashes; write only what is needed"],
                })
        if ext.sec_count and ext.sec_count > 0xFFFFFFF0:
            verdict = "fatal"
            findings.append({
                "severity": "fatal", "title": "eMMC did not report a valid capacity",
                "detail": "SEC_COUNT reads as an erased value, which usually means the chip failed "
                          "to initialise rather than that the phone is enormous.",
                "fixes": ["Re-run identification two or three times: an intermittent read points "
                          "at a bad chip or a bad solder joint",
                          "Do not flash against a chip that cannot report its own size"],
            })
    for note in data["notes"]:
        findings.append({"severity": "warn" if "trust EXT_CSD" in note else "info",
                         "title": note.split(";")[0], "detail": note, "fixes": []})
    if not findings:
        findings.append({"severity": "ok", "title": "Storage registers look healthy",
                         "detail": "No wear flags, no capacity mismatch, no erased-register "
                                   "anomalies.", "fixes": []})
    data["verdict"] = verdict
    data["findings"] = findings
    return data


DEBUGFS_HELP = """
Reading these registers without a download agent
-----------------------------------------------
Android (rooted or an engineering build):
    cat /sys/block/mmcblk0/device/cid
    cat /sys/block/mmcblk0/device/csd
    cat /sys/block/mmcblk0/device/life_time        # wear estimate, if the kernel exposes it
    cat /sys/block/mmcblk0/device/pre_eol_info
    cat /sys/block/mmcblk0/device/serial

A card reader on a Linux PC:  sudo apt install mmc-utils
    sudo mmc cid read /dev/mmcblk0
    sudo mmc extcsd read /dev/mmcblk0 | grep -Ei 'life|pre_eol|sec_count|boot'

In download mode both MediaTek's DA and Qualcomm's firehose expose the same registers, which is
what `revive identify` prints when a phone answers.
"""
