"""Chip identification: hardware code -> SoC, plus what we know about that SoC.

Two rules keep this honest:

1. We only claim a name when the code is confirmed. Unconfirmed codes are returned with
   confidence="reported" or the tool says "unknown" instead of guessing.
2. Many older MediaTek SoCs use their own part number as the hardware code (0x6572 is
   MT6572). That convention is applied explicitly and labelled "derived" so nobody treats
   a derivation as a vendor-confirmed fact.

The best source of truth is always the device itself and the vendor's own DA/scatter file;
`revive.firmware.da` reads DA files and feeds extra codes back into this table at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

CONFIRMED = "confirmed"
REPORTED = "reported"
DERIVED = "derived"
UNKNOWN = "unknown"


@dataclass
class Chip:
    hwcode: int
    name: str
    family: str = ""
    vendor: str = "MediaTek"
    arch: str = ""
    released: str = ""
    da_mode: int = 5           # 3 legacy, 5 xflash, 6 xml (per MTK Download Agent modes)
    da_mode_name: str = "xflash"
    storage: str = ""          # typical storage in devices using this SoC
    da_code: int = 0           # dacode used to select an entry inside a DA file
    notes: str = ""
    confidence: str = CONFIRMED
    source: str = ""
    extra_codes: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "hwcode": f"0x{self.hwcode:04X}",
            "hwcode_int": self.hwcode,
            "name": self.name,
            "family": self.family,
            "vendor": self.vendor,
            "arch": self.arch,
            "released": self.released,
            "da_mode": self.da_mode,
            "da_mode_name": self.da_mode_name,
            "storage": self.storage,
            "da_code": f"0x{self.da_code:04X}" if self.da_code else "",
            "notes": self.notes,
            "confidence": self.confidence,
            "source": self.source,
        }


# --------------------------------------------------------------------------------------
# Confirmed table (codes we have seen documented for the specific SoC)
# --------------------------------------------------------------------------------------

_CHIPS: List[Chip] = [
    Chip(0x6572, "MT6572", "MT6572", arch="Cortex-A7 (32-bit)", released="2013",
         da_mode=3, da_mode_name="legacy", storage="eMMC/NAND", da_code=0x6572,
         notes="Dual-core budget SoC; many devices use NAND rather than eMMC.",
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x6580, "MT6580", "MT6580", arch="Cortex-A7 (32-bit)", released="2015",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6580,
         notes="Very common in 2015-2017 budget phones; scatter v1 layout.",
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x6582, "MT6582", "MT6582", arch="Cortex-A7 (32-bit)", released="2013",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6582,
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x6592, "MT6592", "MT6592", arch="Cortex-A7 x8 (32-bit)", released="2013",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6592,
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x6595, "MT6595", "MT6595", arch="Cortex-A17/A7 (32-bit)", released="2014",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6595,
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x6752, "MT6752", "MT6752", arch="Cortex-A53 x8 (64-bit)", released="2014",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6752,
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x6757, "MT6757", "MT6757", arch="Cortex-A53 x8 (64-bit)", released="2016",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6757,
         notes="Also sold as Helio P20/P25. Common in 2016-2018 mid-range phones.",
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x6795, "MT6795", "MT6795", arch="Cortex-A53 x8 (64-bit)", released="2015",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6795,
         notes="Helio X10.",
         confidence=CONFIRMED, source="MediaTek DA/efuse tables (code equals part number)"),
    Chip(0x8695, "MT8695", "MT8695", arch="Cortex-A53 (64-bit)", released="2018",
         da_mode=3, da_mode_name="legacy", storage="eMMC",
         notes="MediaTek streaming-stick SoC (Fire TV Stick 4K generation).",
         confidence=CONFIRMED, source="MediaTek DA/efuse tables"),
    Chip(0x0335, "MT6735 / MT6737 class", "MT6735", arch="Cortex-A53 x4 (64-bit)", released="2015",
         da_mode=3, da_mode_name="legacy", storage="eMMC", da_code=0x6735,
         notes="Code is shared across the 6735/6737 series in several tools; confirm with the "
               "scatter file name if precision matters.",
         confidence=REPORTED, source="Field reports from vendor flashing tools"),
    Chip(0x0707, "MT6768 / MT6769 (Helio G85, G81, G80, G70)", "MT6768", arch="Cortex-A75/A55 (64-bit)",
         released="2019-2021", da_mode=5, da_mode_name="xflash", storage="eMMC or UFS (model dependent)",
         da_code=0x6768,
         notes="Extremely common (Redmi 9/10/12/13 series, Infinix/Realme budget, many others). "
               "Reports MT6769 under the same hardware code; the model's firmware decides which name is used.",
         confidence=CONFIRMED, source="Verified device logs (hwcode 0x707 reported on MT6768/MT6769 devices)"),
    Chip(0x0766, "MT6765 / MT8768T (Helio P35, G35)", "MT6765", arch="Cortex-A53 x8 (64-bit)",
         released="2018-2020", da_mode=5, da_mode_name="xflash", storage="eMMC",
         da_code=0x6765,
         notes="Massive installed base (Redmi 9A/9C, Nokia, Realme C series, tablets).",
         confidence=CONFIRMED, source="Verified device logs (hwcode 0x766, MT6765/MT8768t)"),
    Chip(0x1066, "MT6781 (Helio G96, G88)", "MT6781", arch="Cortex-A76/A55 (64-bit)", released="2021",
         da_mode=6, da_mode_name="xml", storage="eMMC or UFS 2.x",
         da_code=0x6781,
         notes="Recent Xiaomi MTK models need the V6 (XML) DA path; stock DA files advertise "
               "MTK_DA_v6 and carry their own hw_code table.",
         confidence=CONFIRMED, source="Vendor DA v6 headers and field reports (hwcode 0x1066)"),
]

# Hardware codes that are widely reported but that we have NOT confirmed against a
# vendor source. The tool names them with a '?' marker so nobody trusts them blindly.
_REPORTED: Dict[int, str] = {
    0x1208: "MT6785 / MT6789 class (Helio G9x) - generation guess",
    0x1209: "MT6779 / MT6789 class (Helio P90/G99) - generation guess",
    0x0690: "MT6873 / MT6877 class (Dimensity 700-900) - generation guess",
    0x0551: "MT6833 class (Dimensity 700/6080) - generation guess",
    0x0850: "MT6833 / MT6853 class - generation guess",
    0x0601: "MT6739 class - generation guess",
    0x0326: "MT6737 class - generation guess",
    0x0688: "MT6771 class (Helio P60/P70) - generation guess",
    0x0717: "MT6771 / MT6779 class - generation guess",
}

_BY_CODE: Dict[int, Chip] = {}
for _c in _CHIPS:
    _BY_CODE[_c.hwcode] = _c
    for _x in _c.extra_codes:
        _BY_CODE.setdefault(_x, _c)

_EXTRA_FROM_DA: Dict[int, Chip] = {}


def register_from_da(code: int, name: str, source: str = "vendor DA file") -> Chip:
    """Called when a DA file reveals its own hw_code -> name table. Wins over guesses."""
    chip = Chip(code, name, family=name, confidence=REPORTED, source=source)
    _EXTRA_FROM_DA[code] = chip
    return chip


def _derived_name(code: int) -> Optional[str]:
    """Older MediaTek parts use their own number as the hardware code."""
    if 0x6000 <= code <= 0x8999:
        return f"MT{code:04X}"
    return None


def lookup(hwcode: Optional[int]) -> Optional[Chip]:
    """Return the best information we have, or None if we truly do not know."""
    if hwcode is None:
        return None
    code = int(hwcode)
    if code in _EXTRA_FROM_DA:
        return _EXTRA_FROM_DA[code]
    if code in _BY_CODE:
        return _BY_CODE[code]
    derived = _derived_name(code)
    if derived:
        modern = code in _REPORTED
        return Chip(
            hwcode=code, name=derived, family=derived,
            da_mode=3 if code < 0x6600 else 5,
            da_mode_name="legacy" if code < 0x6600 else "xflash (assumed)",
            confidence=REPORTED if modern else DERIVED,
            source="derived from hardware code pattern - confirm with the device's scatter/DA file",
            notes="The name is the hardware code read as a MediaTek part number; this convention is "
                  "correct for most pre-2018 parts but is not vendor-confirmed for this specific code.",
        )
    if code in _REPORTED:
        return Chip(hwcode=code, name=f"unconfirmed ({_REPORTED[code]})", confidence=REPORTED,
                    source="field reports only - not verified")
    return None


def describe(hwcode: Optional[int]) -> str:
    chip = lookup(hwcode)
    if not chip:
        return f"unknown hardware code 0x{int(hwcode):04X}" if hwcode is not None else "unknown"
    tag = "" if chip.confidence == CONFIRMED else f"  [{chip.confidence}]"
    return f"{chip.name} (hw code 0x{chip.hwcode:04X}, {chip.da_mode_name} DA mode){tag}"


def all_chips() -> List[Chip]:
    out = list(_CHIPS)
    seen = {c.hwcode for c in out}
    for chip in _EXTRA_FROM_DA.values():
        if chip.hwcode not in seen:
            out.append(chip)
    return out


def parse_hwcode(text: str) -> Optional[int]:
    """'0x707', '707', 'hw code: 0x766' -> int."""
    import re

    if text is None:
        return None
    m = re.search(r"0x([0-9a-fA-F]{1,8})", str(text))
    if m:
        return int(m.group(1), 16)
    m = re.search(r"\b(\d{3,5})\b", str(text))
    if m:
        return int(m.group(1))
    return None


# Storage-type hints used by the planner ------------------------------------------------

def storage_kind_from_name(name: str) -> str:
    """Guess eMMC/UFS from a firmware or file name - advisory only."""
    low = (name or "").lower()
    if "ufs" in low:
        return "UFS"
    if "emmc" in low:
        return "eMMC"
    if "nand" in low:
        return "NAND"
    return ""
