"""Fake CID / CSD / EXT_CSD register generation.

The point of this module is that the bytes it produces are *real* register images: they are fed
straight back through `revive.storage.emmc.parse_cid/parse_csd/parse_ext_csd`, so the health
verdict a lab device gets is the verdict Revive's own decoder produces, not one the lab made up.
If the generator drifts away from the JEDEC layout, `selftest()` fails and the test suite says so.

Field offsets are the ones `revive.storage.emmc` reads, which follow JESD84:

    EXT_CSD[168]      RPMB_SIZE_MULT
    EXT_CSD[192]      EXT_CSD_REV
    EXT_CSD[212:216]  SEC_COUNT (little endian)
    EXT_CSD[226]      BOOT_SIZE_MULT
    EXT_CSD[254:262]  FIRMWARE_VERSION (8 ASCII bytes)
    EXT_CSD[262:264]  DEVICE_VERSION
    EXT_CSD[267]      PRE_EOL_INFO
    EXT_CSD[268]      DEVICE_LIFE_TIME_EST_TYP_A
    EXT_CSD[269]      DEVICE_LIFE_TIME_EST_TYP_B
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..storage import emmc as emmc_mod
from ..util import human_size

LOG = logging.getLogger("revive.lab.extcsd")

EXT_CSD_SIZE = 512
CID_SIZE = 16
CSD_SIZE = 16

# Register offsets (byte index into the 512-byte EXT_CSD).
OFF_RPMB_MULT = 168
OFF_REV = 192
OFF_SEC_COUNT = 212
OFF_BOOT_MULT = 226
OFF_FIRMWARE = 254
OFF_DEVICE_VERSION = 262
OFF_PRE_EOL = 267
OFF_LIFE_A = 268
OFF_LIFE_B = 269

# Health states, matching the values a technician sees in PRE_EOL_INFO.
HEALTHY = "healthy"       # PRE_EOL 0x01
WARNING = "warning"       # PRE_EOL 0x02
DEAD = "dead"             # PRE_EOL 0x03
HEALTH_STATES = (HEALTHY, WARNING, DEAD)

PRE_EOL_FOR_STATE = {HEALTHY: 0x01, WARNING: 0x02, DEAD: 0x03}
STATE_FOR_PRE_EOL = {0x00: "unknown", 0x01: HEALTHY, 0x02: WARNING, 0x03: DEAD}

# Life-time estimate presets per health state (type A and type B bytes).
LIFE_FOR_STATE = {
    HEALTHY: (0x02, 0x01),      # 10-20% / 0-10% of rated life used
    WARNING: (0x09, 0x07),      # 80-90% / 60-70%
    DEAD: (0x0B, 0x0B),         # rated life EXCEEDED
}

# Manufacturers from the real table, so a lab chip is recognisable by name.
DEFAULT_MANUFACTURER = "Samsung"


def _mid_for(name: str) -> int:
    """Reverse the manufacturer table in revive.storage.emmc."""
    wanted = (name or "").strip().lower()
    for mid, label in emmc_mod.MANUFACTURERS.items():
        if label.lower() == wanted or label.lower().startswith(wanted + " "):
            return mid
    for mid, label in emmc_mod.MANUFACTURERS.items():
        if wanted and wanted in label.lower():
            return mid
    return 0x15                                     # Samsung, the most common phone eMMC


def manufacturer_names() -> List[str]:
    return sorted({label for label in emmc_mod.MANUFACTURERS.values()})


# --------------------------------------------------------------------------------------
# The spec a virtual chip is built from
# --------------------------------------------------------------------------------------

@dataclass
class RegisterSpec:
    """Everything that decides what a virtual eMMC reports about itself."""

    capacity_bytes: int = 64 * 1024 ** 3
    manufacturer: str = DEFAULT_MANUFACTURER
    product_name: str = "LAB8G52"
    serial: int = 0x1AB2C3D4
    year: int = 2021
    month: int = 6
    revision: str = "1.5"
    health: str = HEALTHY
    pre_eol: Optional[int] = None            # overrides `health` when set
    life_a: Optional[int] = None
    life_b: Optional[int] = None
    boot_size_mult: int = 0x20               # 0x20 -> 4 MiB boot partitions
    rpmb_size_mult: int = 0x01               # 0x01 -> 128 KiB RPMB
    ext_csd_rev: int = 8                     # eMMC 5.1
    device_version: int = 0x51               # eMMC 5.1
    firmware_version: str = "29534c42"
    bad_blocks: List[Dict[str, Any]] = field(default_factory=list)
    write_cycles: int = 1200

    # -- derived ---------------------------------------------------------------------
    @property
    def sec_count(self) -> int:
        return max(0, self.capacity_bytes // 512)

    @property
    def pre_eol_value(self) -> int:
        if self.pre_eol is not None:
            return int(self.pre_eol) & 0xFF
        return PRE_EOL_FOR_STATE.get((self.health or HEALTHY).lower(), 0x01)

    @property
    def life_a_value(self) -> int:
        if self.life_a is not None:
            return int(self.life_a) & 0xFF
        return LIFE_FOR_STATE.get((self.health or HEALTHY).lower(), LIFE_FOR_STATE[HEALTHY])[0]

    @property
    def life_b_value(self) -> int:
        if self.life_b is not None:
            return int(self.life_b) & 0xFF
        return LIFE_FOR_STATE.get((self.health or HEALTHY).lower(), LIFE_FOR_STATE[HEALTHY])[1]

    @property
    def state(self) -> str:
        return STATE_FOR_PRE_EOL.get(self.pre_eol_value, "unknown")

    def __post_init__(self) -> None:
        """Normalise the fields whose hardware representation is smaller than a Python int.

        The CID's PNM field holds six ASCII bytes and its MDT year is four bits counting from
        2000, so a longer name or a date after 2015 simply cannot be stored. Clamping here, at
        construction, keeps the raw registers and the lab's own device card in agreement -
        otherwise the card would claim 2021 while the CID the phone reports says 2015.
        """
        self.firmware_version = _normalise_firmware(self.firmware_version)
        self.product_name = str(self.product_name or "LAB")[:CID_PNM_LEN]
        try:
            self.year = max(CID_YEAR_MIN, min(CID_YEAR_MAX, int(self.year)))
            self.month = max(1, min(12, int(self.month)))
        except (TypeError, ValueError):
            self.year, self.month = CID_YEAR_MAX, 6
        try:
            self.serial = int(self.serial) & 0xFFFFFFFF
        except (TypeError, ValueError):
            self.serial = 0x1AB2C3D4

    def updated(self, **changes: Any) -> "RegisterSpec":
        """A copy with some fields changed, re-normalised on the way through.

        Setters go through this rather than assigning to `spec.<field>`, so a value can never
        end up in the registers in a form that construction would have rejected.
        """
        data = {k: (list(v) if isinstance(v, list) else v) for k, v in self.__dict__.items()}
        data.update(changes)
        return RegisterSpec(**data)

    def with_health(self, health: str) -> "RegisterSpec":
        """A copy with a different health state (and the life estimates that go with it)."""
        health = (health or HEALTHY).lower()
        if health not in HEALTH_STATES:
            raise ValueError(f"unknown health state {health!r}; expected one of "
                             f"{', '.join(HEALTH_STATES)}")
        clone = RegisterSpec(**{k: (list(v) if isinstance(v, list) else v)
                                for k, v in self.__dict__.items()})
        clone.health = health
        clone.pre_eol = None
        clone.life_a = None
        clone.life_b = None
        return clone

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capacity_bytes": self.capacity_bytes, "capacity_human": human_size(self.capacity_bytes),
            "sec_count": self.sec_count, "manufacturer": self.manufacturer,
            "manufacturer_id": f"0x{_mid_for(self.manufacturer):02X}",
            "product_name": self.product_name, "serial": f"0x{self.serial:08X}",
            "manufacture_date": f"{self.month:02d}/{self.year:04d}",
            "revision": self.revision, "health": self.state, "pre_eol": f"0x{self.pre_eol_value:02X}",
            "life_a": f"0x{self.life_a_value:02X}", "life_b": f"0x{self.life_b_value:02X}",
            "boot_size_mult": f"0x{self.boot_size_mult:02X}",
            "rpmb_size_mult": f"0x{self.rpmb_size_mult:02X}",
            "ext_csd_rev": self.ext_csd_rev,
            "device_version": f"0x{self.device_version:04X}",
            "firmware_version": self.firmware_version,
            "write_cycles": self.write_cycles,
            "bad_blocks": list(self.bad_blocks), "bad_block_count": len(self.bad_blocks),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegisterSpec":
        known = {f for f in cls.__dataclass_fields__}                      # noqa: SLF001
        clean = {k: v for k, v in (data or {}).items() if k in known}
        for key in ("capacity_bytes", "serial", "year", "month", "boot_size_mult",
                    "rpmb_size_mult", "ext_csd_rev", "device_version", "write_cycles"):
            if clean.get(key) is not None:
                try:
                    clean[key] = int(clean[key], 0) if isinstance(clean[key], str) else int(clean[key])
                except (TypeError, ValueError):
                    clean.pop(key, None)
        for key in ("pre_eol", "life_a", "life_b"):
            raw = clean.get(key)
            if raw is None:
                continue
            try:
                clean[key] = int(raw, 0) if isinstance(raw, str) else int(raw)
            except (TypeError, ValueError):
                clean.pop(key, None)
        if not isinstance(clean.get("bad_blocks"), list):
            clean.pop("bad_blocks", None)
        return cls(**clean)


# --------------------------------------------------------------------------------------
# Building the raw registers
# --------------------------------------------------------------------------------------

# Hardware limits the fields above have to live inside.
CID_PNM_LEN = 6          # PNM: six ASCII bytes
CID_YEAR_MIN = 2000      # MDT: four bits of year, counting from 2000
CID_YEAR_MAX = 2015
FIRMWARE_LEN = 8         # FIRMWARE_VERSION: eight ASCII bytes


def _normalise_firmware(value: Any) -> str:
    """Squeeze a firmware version into the eight ASCII bytes EXT_CSD gives it.

    A ``0x29534c42``-style string is ten characters and cannot be stored verbatim; the hex
    digits are what a chip prints, so the prefix goes rather than the value being silently
    truncated on the way back out.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        # A 32-bit version number, which is what `--opt firmware_version=0x4c414231` becomes once
        # the CLI parses it: print it the way vendor tools do, as eight hex digits.
        return f"{value & 0xFFFFFFFF:0{FIRMWARE_LEN}X}"
    text = str(value if value is not None else "").strip()
    if text.lower().startswith("0x"):
        body = text[2:]
        # Hex digits only: keep the canonical upper-case form so "0x4c414231" typed at the CLI
        # and "0x4c414231" sent to the API produce the same register.
        if body and all(char in "0123456789abcdefABCDEF" for char in body):
            text = body.upper()
    if len(text) > FIRMWARE_LEN:
        LOG.warning("FIRMWARE_VERSION is an %d-byte field; %r was shortened to %r",
                    FIRMWARE_LEN, value, text[:FIRMWARE_LEN])
    return text[:FIRMWARE_LEN]


def _crc7(data: bytes) -> int:
    """The 7-bit CRC the CID/CSD carry in their last byte (bit 0 is the end bit)."""
    crc = 0
    for byte in data:
        for bit in range(7, -1, -1):
            bit_val = (byte >> bit) & 1
            crc = ((crc << 1) | bit_val) & 0xFF
            if crc & 0x80:
                crc ^= 0x09
    return (crc & 0x7F) << 1 | 1


def build_cid(spec: RegisterSpec) -> bytes:
    """A 16-byte CID that `revive.storage.emmc.parse_cid` reads back correctly."""
    blob = bytearray(CID_SIZE)
    blob[0] = _mid_for(spec.manufacturer)
    struct.pack_into(">H", blob, 1, 0x0100)                              # OEM id
    name = (spec.product_name or "LAB")[:CID_PNM_LEN].encode("ascii", "replace")
    blob[3:3 + len(name)] = name
    try:
        major, minor = str(spec.revision).split(".", 1)
        blob[9] = ((int(major) & 0x0F) << 4) | (int(minor) & 0x0F)
    except (ValueError, AttributeError):
        blob[9] = 0x15
    struct.pack_into(">I", blob, 10, spec.serial & 0xFFFFFFFF)
    year = max(CID_YEAR_MIN, min(CID_YEAR_MAX, int(spec.year)))          # already clamped
    month = min(12, max(1, int(spec.month)))
    blob[14] = (((year - 2000) & 0x0F) << 4) | (month & 0x0F)
    blob[15] = _crc7(bytes(blob[:15]))
    return bytes(blob)


def build_csd(spec: RegisterSpec) -> bytes:
    """A 16-byte structure-3 CSD: capacity is (C_SIZE+1) x 512 KiB."""
    # C_SIZE occupies bits [73:62]: twelve bits, so a structure-3 CSD can only express 2 GiB.
    # Real chips above that leave the field short and report their capacity in EXT_CSD
    # SEC_COUNT, which is what Revive's summary() tells the reader to trust.
    units = max(1, spec.capacity_bytes // (512 * 1024))
    c_size = max(0, units - 1) & 0xFFF
    value = 0
    value |= 3 << 126                                                  # CSD_STRUCTURE = 3
    value |= 0x0E << 122                                               # spec version
    value |= 0x0B << 80                                                # TRAN_SPEED: 26 MHz base
    value |= 9 << 80                                                   # READ_BL_LEN = 9 (512 B)
    value |= c_size << 62
    value |= 7 << 47                                                   # C_SIZE_MULT
    blob = bytearray(value.to_bytes(CSD_SIZE, "big"))
    blob[3] = 0x0B                                                     # what parse_csd reads for timing
    blob[15] = _crc7(bytes(blob[:15]))
    return bytes(blob)


def build_ext_csd(spec: RegisterSpec) -> bytes:
    """The 512-byte EXT_CSD, including the wear and health bytes Revive warns about."""
    blob = bytearray(EXT_CSD_SIZE)
    blob[OFF_REV] = spec.ext_csd_rev & 0xFF
    struct.pack_into("<I", blob, OFF_SEC_COUNT, spec.sec_count & 0xFFFFFFFF)
    blob[OFF_BOOT_MULT] = spec.boot_size_mult & 0xFF
    blob[OFF_RPMB_MULT] = spec.rpmb_size_mult & 0xFF
    struct.pack_into("<H", blob, OFF_DEVICE_VERSION, spec.device_version & 0xFFFF)
    firmware = _normalise_firmware(spec.firmware_version).encode("ascii", "replace")
    blob[OFF_FIRMWARE:OFF_FIRMWARE + 8] = firmware.ljust(8, b"\x00")
    blob[OFF_PRE_EOL] = spec.pre_eol_value
    blob[OFF_LIFE_A] = spec.life_a_value
    blob[OFF_LIFE_B] = spec.life_b_value
    # Fields Revive does not read but a real chip fills in; they keep the blob plausible when
    # somebody hexdumps it.
    blob[0] = 0x00                                                     # S_CMD_SET
    struct.pack_into("<H", blob, 160, 0x0001)                          # EXT_SECURITY_ERR (unused)
    blob[222] = 0x01                                                   # HS_TIMING default
    return bytes(blob)


def build_registers(spec: RegisterSpec) -> Dict[str, bytes]:
    return {"cid": build_cid(spec), "csd": build_csd(spec), "ext_csd": build_ext_csd(spec)}


# --------------------------------------------------------------------------------------
# Decoding them again with the real parser
# --------------------------------------------------------------------------------------

def decode(spec: RegisterSpec) -> Dict[str, Any]:
    """Run the lab's registers through Revive's real decoder and return the summary + verdict."""
    cid = emmc_mod.parse_cid(build_cid(spec))
    csd = emmc_mod.parse_csd(build_csd(spec))
    ext = emmc_mod.parse_ext_csd(build_ext_csd(spec))
    assessment = emmc_mod.assess(cid=cid, csd=csd, ext=ext)
    return {
        "cid": cid.to_dict(), "csd": csd.to_dict(), "ext_csd": ext.to_dict(),
        "summary": emmc_mod.summary(cid, csd, ext), "assessment": assessment,
        "verdict": assessment.get("verdict", "ok"),
        "findings": assessment.get("findings", []),
    }


def life_estimate(spec: RegisterSpec) -> Dict[str, Any]:
    """A technician-facing life-time estimate: wear flags, cycles and what they mean."""
    used_a = _life_percent(spec.life_a_value)
    used_b = _life_percent(spec.life_b_value)
    worst = max(used_a[0], used_b[0])
    remaining = max(0, 100 - worst)
    cycles_used = max(0, int(spec.write_cycles))
    rated = 3000                                     # typical TLC program/erase rating
    cycles_left = max(0, rated - cycles_used)
    return {
        "life_a": f"0x{spec.life_a_value:02X}", "life_b": f"0x{spec.life_b_value:02X}",
        "life_a_text": used_a[1], "life_b_text": used_b[1],
        "used_percent_estimate": worst, "remaining_percent_estimate": remaining,
        "write_cycles": cycles_used, "rated_cycles_estimate": rated,
        "cycles_left_estimate": cycles_left,
        "pre_eol": f"0x{spec.pre_eol_value:02X}", "pre_eol_text": spec.state,
        "bad_blocks": len(spec.bad_blocks),
        "verdict": ("dead" if spec.pre_eol_value >= 0x03 or worst >= 100 else
                    "worn" if spec.pre_eol_value >= 0x02 or worst >= 80 else "healthy"),
    }


def _life_percent(value: Optional[int]) -> Tuple[int, str]:
    """The upper bound of the wear band, and its text.

    0x01 -> (10, '0-10% of rated life used'); 0x0B -> (100, 'EXCEEDED the rated life').
    """
    if value is None or value == 0x00:
        return (0, "not reported by this chip")
    if 1 <= value <= 0x0A:
        low = (value - 1) * 10
        return (low + 10, f"{low}-{low + 10}% of rated life used")
    if value == 0x0B:
        return (100, "EXCEEDED the rated life")
    return (0, f"reserved value 0x{value:02X}")


def add_bad_block(spec: RegisterSpec, offset: int, size: int = 4096,
                  state: str = "unreadable") -> Dict[str, Any]:
    """Record a bad block on the chip and update the wear flags to match."""
    block = {"offset": int(offset), "size": int(size), "state": state,
             "offset_hex": f"0x{int(offset):x}"}
    spec.bad_blocks.append(block)
    # Real chips start advertising wear long before they die; so does this one.
    count = len(spec.bad_blocks)
    if count >= 8 and (spec.life_a_value < 0x0B):
        spec.life_a = max(spec.life_a_value, 0x09)
        if spec.pre_eol_value < 0x02:
            spec.pre_eol = 0x02
            spec.health = WARNING
    elif count >= 24 and spec.pre_eol_value < 0x03:
        spec.life_a = 0x0B
        spec.life_b = 0x0B
        spec.pre_eol = 0x03
        spec.health = DEAD
    LOG.debug("recorded bad block at 0x%x (%d total)", offset, count)
    return block


def selftest() -> Dict[str, Any]:
    """Round-trip every health state through the real decoder.

    Returns the decoded results so the test suite can assert that the generator and
    `revive.storage.emmc` still agree. This is the guard against the generator drifting.
    """
    out: Dict[str, Any] = {}
    for state in HEALTH_STATES:
        spec = RegisterSpec().with_health(state)
        decoded = decode(spec)
        ext = decoded["ext_csd"]
        out[state] = {
            "generated_pre_eol": f"0x{spec.pre_eol_value:02X}",
            "decoded_health": ext["pre_eol"],
            "decoded_capacity": ext["capacity_bytes"],
            "expected_capacity": spec.capacity_bytes,
            "verdict": decoded["verdict"],
            "life_estimate": life_estimate(spec),
        }
    return out
