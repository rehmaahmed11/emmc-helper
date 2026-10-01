"""Virtual phone models, the simulated boot process, and the lab device database.

A lab device is a folder. Everything about it is on disk - the registers, the user area image,
the partition map, the golden copies and the event log - so a device can be created, bricked,
repaired and inspected across separate CLI invocations, exactly like a phone on the bench.

The transport is the real `MockBackend`, subclassed so that a Qualcomm or Unisoc profile reports
its own download mode instead of MediaTek BROM. Nothing in `revive/backends` is modified: the
lab only adds a subclass of its own.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .. import util
from ..backends.mock import MockBackend, MockProfile
from ..core import chips, usbmodes
from ..util import human_size
from . import extcsd_virtual as regs
from . import gpt_virtual
from . import partitions as parts
from .emmc_virtual import DEFAULT_IMAGE_BYTES, MIN_IMAGE_BYTES, VirtualEMMC
from .partitions import SECTOR, ST_OK, VirtualPartition, content_for, plan_layout

LOG = logging.getLogger("revive.lab.device")

DEFAULT_LAB_ROOT = "lab_devices"
SCHEMA = "revive-lab-device/1"

# Device states shown on the dashboard.
STATE_HEALTHY = "healthy"
STATE_BRICKED = "bricked"
STATE_RECOVERED = "recovered"

# Boot modes a virtual phone can be in.
MODE_NORMAL = "normal"
MODE_OFF = "off"
MODE_MTK_BROM = "mtk_brom"
MODE_QC_EDL = "qc_edl"
MODE_UNISOC_DL = "unisoc_dl"
MODE_FASTBOOT = "fastboot"
MODE_RECOVERY = "recovery"

# Platforms.
PLATFORM_MTK = "mtk"
PLATFORM_QUALCOMM = "qualcomm"
PLATFORM_UNISOC = "unisoc"


# --------------------------------------------------------------------------------------
# Device profiles
# --------------------------------------------------------------------------------------

@dataclass
class DeviceProfile:
    """What a virtual phone is: chipset, vendor, storage and the mode it is sitting in."""

    chipset: str = "MT6768"
    platform: str = PLATFORM_MTK
    vendor: str = "MediaTek"
    model: str = "Virtual device"
    interface: str = "eMMC"
    storage: str = "64GB"
    boot_mode: str = MODE_NORMAL
    hwcode: Optional[int] = None
    usb_id: str = "0e8d:0003"
    notes: str = ""

    @property
    def name(self) -> str:
        return f"Virtual {self.model} ({self.chipset})"

    @property
    def storage_bytes(self) -> int:
        try:
            return util.parse_size(self.storage)
        except (TypeError, ValueError):
            return 64 * 1024 ** 3

    @property
    def download_mode(self) -> str:
        """The USB download mode this platform's brick presents as."""
        if self.platform == PLATFORM_QUALCOMM:
            return usbmodes.MODE_QC_EDL
        if self.platform == PLATFORM_UNISOC:
            return usbmodes.MODE_UNISOC
        return usbmodes.MODE_MTK_BROM

    @property
    def identity_partitions(self) -> List[str]:
        """The partitions that hold IMEI / MAC / calibration for this platform."""
        if self.platform == PLATFORM_QUALCOMM:
            return ["modemst1", "modemst2", "fsg"]
        if self.platform == PLATFORM_UNISOC:
            return ["fixnv", "runtimenv", "prodnv"]
        return ["nvram", "nvdata", "proinfo", "protect1", "protect2"]

    @property
    def bootloader_partitions(self) -> List[str]:
        if self.platform == PLATFORM_QUALCOMM:
            return ["xbl", "xbl_config", "abl", "tz"]
        if self.platform == PLATFORM_UNISOC:
            return ["bootloader", "uboot"]
        return ["preloader", "lk"]

    @property
    def boot_partitions(self) -> List[str]:
        return ["boot", "recovery"] if self.platform == PLATFORM_MTK else ["boot"]

    @property
    def system_partitions(self) -> List[str]:
        if self.platform == PLATFORM_MTK:
            return ["super", "system", "vendor", "vbmeta"]
        if self.platform == PLATFORM_QUALCOMM:
            return ["system", "vendor"]
        return ["system", "vendor"]

    def to_dict(self) -> Dict[str, Any]:
        """Exactly the profile shape the lab dashboard shows."""
        return {
            "name": self.name, "chipset": self.chipset, "platform": self.platform,
            "vendor": self.vendor, "model": self.model, "storage": self.storage,
            "storage_bytes": self.storage_bytes,
            "storage_human": human_size(self.storage_bytes),
            "interface": self.interface, "boot_mode": self.boot_mode,
            "hwcode": f"0x{int(self.hwcode):04X}" if self.hwcode not in (None, "") else "",
            "usb_id": self.usb_id, "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceProfile":
        known = set(cls.__dataclass_fields__)                                # noqa: SLF001
        clean = {k: v for k, v in (data or {}).items() if k in known}
        # hwcode is serialised as "0x0707" and is None for platforms (Qualcomm, Unisoc) that
        # have no MediaTek-style hardware code; an empty string must round-trip back to None.
        raw = clean.get("hwcode")
        if raw in ("", None):
            clean["hwcode"] = None
        else:
            try:
                clean["hwcode"] = int(raw, 0) if isinstance(raw, str) else int(raw)
            except (TypeError, ValueError):
                clean["hwcode"] = None
        return cls(**clean)


PROFILES: Dict[str, DeviceProfile] = {
    "MT6765": DeviceProfile(
        chipset="MT6765", platform=PLATFORM_MTK, vendor="Xiaomi", model="Redmi 9A",
        storage="32GB", hwcode=0x0766,
        notes="Helio P35/G35. Huge installed base in budget phones; scatter v1/v2 packages."),
    "MT6768": DeviceProfile(
        chipset="MT6768", platform=PLATFORM_MTK, vendor="Xiaomi", model="Redmi Note 9",
        storage="64GB", hwcode=0x0707,
        notes="Helio G85. The single most common MediaTek repair device right now."),
    "MT6877": DeviceProfile(
        chipset="MT6877", platform=PLATFORM_MTK, vendor="Xiaomi", model="Redmi Note 11 Pro 5G",
        storage="128GB", hwcode=0x0690,
        notes="Dimensity 900. hwcode is a generation guess in Revive's chip table, and the lab "
              "says so rather than pretending it is confirmed."),
    "SDM450": DeviceProfile(
        chipset="Snapdragon 450", platform=PLATFORM_QUALCOMM, vendor="Samsung",
        model="Galaxy J7 (2017)", storage="32GB", usb_id="05c6:9008",
        notes="SDM450. EDL 9008 recovery with a firehose programmer."),
    "SDM660": DeviceProfile(
        chipset="Snapdragon 660", platform=PLATFORM_QUALCOMM, vendor="Xiaomi",
        model="Redmi Note 7 Pro", storage="64GB", usb_id="05c6:9008",
        notes="SDM660. Sahara + firehose; needs the loader for this exact model."),
    "SDM7XX": DeviceProfile(
        chipset="Snapdragon 7 series", platform=PLATFORM_QUALCOMM, vendor="OnePlus",
        model="Nord (SDM765G)", storage="128GB", interface="eMMC", usb_id="05c6:9008",
        notes="SDM710/730/765 class. UFS on some models; the lab keeps it on eMMC so the "
              "storage tools apply."),
    "UNISOC": DeviceProfile(
        chipset="Unisoc SC9863A", platform=PLATFORM_UNISOC, vendor="Nokia",
        model="C20 (PAC)", storage="32GB", usb_id="1782:4d00",
        notes="Basic PAC simulation. Revive lists and extracts PAC files but never flashes "
              "them, so this profile is read-and-damage only - matching the real tool."),
}

PROFILE_ALIASES: Dict[str, str] = {
    "mt6765": "MT6765", "helio p35": "MT6765", "helio g35": "MT6765", "mt8768": "MT6765",
    "mt6768": "MT6768", "helio g85": "MT6768", "helio g80": "MT6768", "mt6769": "MT6768",
    "mt6877": "MT6877", "dimensity 900": "MT6877",
    "sdm450": "SDM450", "snapdragon 450": "SDM450", "450": "SDM450",
    "sdm660": "SDM660", "snapdragon 660": "SDM660", "660": "SDM660",
    "sdm7xx": "SDM7XX", "sdm710": "SDM7XX", "sdm730": "SDM7XX", "sdm765": "SDM7XX",
    "snapdragon 7": "SDM7XX", "snapdragon 7 series": "SDM7XX", "7 series": "SDM7XX",
    "unisoc": "UNISOC", "sprd": "UNISOC", "sc9863a": "UNISOC", "pac": "UNISOC",
}


def profile_keys() -> List[str]:
    return sorted(PROFILES)


def get_profile(chip: str) -> DeviceProfile:
    """Resolve a profile by exact key, alias or free text. Unknown chips get a derived profile."""
    text = str(chip or "").strip()
    if not text:
        raise ValueError("a chipset is required (try --list-profiles)")
    if text.upper() in PROFILES:
        return DeviceProfile(**PROFILES[text.upper()].__dict__)
    key = PROFILE_ALIASES.get(text.lower())
    if key:
        return DeviceProfile(**PROFILES[key].__dict__)
    upper = text.upper()
    for candidate in PROFILES:
        if upper in candidate or candidate in upper:
            return DeviceProfile(**PROFILES[candidate].__dict__)
    # An unlisted MediaTek code: derive it the way revive.core.chips does, and say it is derived.
    code = chips.parse_hwcode(text)
    if code is not None:
        info = chips.lookup(code)
        profile = DeviceProfile(chipset=info.name if info else f"MT{code:04X}",
                                platform=PLATFORM_MTK, vendor="MediaTek",
                                model=f"unknown device (hw 0x{code:04X})",
                                hwcode=code, usb_id="0e8d:0003",
                                notes="Not a lab preset: the chipset was derived from the "
                                      "hardware code, the way `revive chips` does it.")
        return profile
    raise ValueError(f"no lab profile for {chip!r}. Known profiles: {', '.join(profile_keys())}")


# --------------------------------------------------------------------------------------
# The simulated boot process
# --------------------------------------------------------------------------------------

@dataclass
class BootStage:
    """One step of the boot chain, and whether the device got through it."""

    name: str = ""
    ok: bool = False
    detail: str = ""
    partitions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail,
                "partitions": list(self.partitions)}


@dataclass
class BootResult:
    """How far the phone got before it stopped."""

    booted: bool = False
    reached: str = "power_on"
    reason: str = ""
    stages: List[BootStage] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    boot_mode: str = MODE_NORMAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "booted": self.booted, "reached": self.reached, "reason": self.reason,
            "boot_mode": self.boot_mode,
            "stages": [s.to_dict() for s in self.stages], "warnings": list(self.warnings),
            "summary": (f"booted to Android ({len(self.stages)} stages)" if self.booted else
                        f"stopped at {self.reached}: {self.reason}"),
        }


# --------------------------------------------------------------------------------------
# The transport: MockBackend, relabelled for the lab
# --------------------------------------------------------------------------------------

class LabTransport(MockBackend):
    """The real simulated backend, pointed at a lab device's image.

    `MockBackend` gives us genuine read/write/erase/list_partitions against a file-backed eMMC
    with a real GPT. This subclass only changes what the device *says it is*, so a Qualcomm
    profile presents as EDL 9008 instead of MediaTek BROM.
    """

    name = "lab"
    label = "Lab virtual device"
    vendor = "Revive lab"
    protocol = "in-process simulation (lab_testing)"
    notes = [
        "This backend is the lab simulator: it never touches USB or real storage.",
        "Every read and write goes to the lab device's emmc.img on disk.",
    ]

    def __init__(self, device: "VirtualDevice", progress=None, verbose: bool = False):
        from ..util import null_progress

        emmc = device.emmc
        profile = MockProfile(
            hwcode=device.profile.hwcode if device.profile.hwcode is not None else 0x707,
            storage=device.profile.interface,
            sectors=max(1, emmc.sectors),
            pre_eol=emmc.spec.pre_eol_value,
            life_a=emmc.spec.life_a_value,
            name=device.profile.name,
        )
        super().__init__(progress=progress or null_progress, verbose=verbose,
                         profile=profile, storage_path=emmc.path)
        self.lab_device = device

    def open(self) -> None:
        super().open()
        mode = self.lab_device.profile.boot_mode
        self.info.mode = mode if mode != MODE_NORMAL else self.lab_device.profile.download_mode
        self.info.vendor = f"{self.lab_device.profile.vendor} (simulated)"
        self.info.usb_id = self.lab_device.profile.usb_id
        self.info.serial = f"LAB{self.lab_device.id[-8:].upper()}"
        self.info.notes.append("Lab virtual device: nothing here came from real hardware.")

    def identify(self):
        info = super().identify()
        emmc = self.lab_device.emmc
        # Replace the mock's rough health string with what Revive's real decoder says.
        health = emmc.health()
        info.extras["lab"] = {
            "device": self.lab_device.id, "chipset": self.lab_device.profile.chipset,
            "platform": self.lab_device.profile.platform,
            "status": self.lab_device.status,
            "faults": [f.id for f in self.lab_device.faults if not f.repaired],
            "boot_mode": self.lab_device.profile.boot_mode,
        }
        info.extras["ext_csd_health"] = health["pre_eol_text"]
        info.extras["life_time_est"] = health["life_a_text"]
        info.extras["registers"] = emmc.registers()
        info.extras["capacity"] = human_size(emmc.spec.capacity_bytes)
        info.notes.extend(health["warnings"])
        return info


# --------------------------------------------------------------------------------------
# The virtual device
# --------------------------------------------------------------------------------------

@dataclass
class Fault:
    """One brick that has been applied."""

    id: str = ""
    label: str = ""
    applied_at: str = ""
    detail: str = ""
    partitions: List[str] = field(default_factory=list)
    repaired: bool = False
    repaired_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "label": self.label, "applied_at": self.applied_at,
                "detail": self.detail, "partitions": list(self.partitions),
                "repaired": self.repaired, "repaired_at": self.repaired_at}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Fault":
        return cls(id=str(data.get("id", "")), label=str(data.get("label", "")),
                   applied_at=str(data.get("applied_at", "")),
                   detail=str(data.get("detail", "")),
                   partitions=[str(p) for p in data.get("partitions", [])],
                   repaired=bool(data.get("repaired", False)),
                   repaired_at=str(data.get("repaired_at", "")))


class VirtualDevice:
    """A phone that only exists on disk: profile + eMMC + partitions + faults + boot state."""

    def __init__(self, folder, profile: Optional[DeviceProfile] = None,
                 device_id: Optional[str] = None, image_bytes: int = DEFAULT_IMAGE_BYTES):
        self.folder = Path(folder)
        self.id = device_id or self.folder.name
        self.profile = profile or DeviceProfile()
        self.created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.status = STATE_HEALTHY
        self.image_bytes = max(MIN_IMAGE_BYTES, int(image_bytes))
        self.imei = "353001100000001"
        self.serial_number = f"LAB{uuid.uuid4().hex[:10].upper()}"
        self.faults: List[Fault] = []
        self.events: List[Dict[str, Any]] = []
        self.layout_notes: List[str] = []
        self.partitions: List[VirtualPartition] = []
        self.emmc = VirtualEMMC(self.folder / "emmc.img",
                                spec=regs.RegisterSpec(capacity_bytes=self.profile.storage_bytes),
                                golden_dir=self.folder / "golden")
        self._log_handler: Optional[logging.FileHandler] = None

    # -- paths -------------------------------------------------------------------------
    @property
    def image_path(self) -> Path:
        return self.folder / "emmc.img"

    @property
    def logs_dir(self) -> Path:
        return self.folder / "logs"

    @property
    def reports_dir(self) -> Path:
        return self.folder / "reports"

    @property
    def golden_dir(self) -> Path:
        return self.folder / "golden"

    @property
    def is_bricked(self) -> bool:
        return any(not fault.repaired for fault in self.faults)

    @property
    def active_faults(self) -> List[Fault]:
        return [fault for fault in self.faults if not fault.repaired]

    def partition(self, name: str) -> Optional[VirtualPartition]:
        low = name.lower()
        for part in self.partitions:
            if part.name.lower() == low:
                return part
        return None

    # -- creation ----------------------------------------------------------------------
    def create_storage(self) -> Dict[str, Any]:
        """Build the user area: partition content, golden copies and a real GPT."""
        self.folder.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.emmc.recreate_image(self.image_bytes)

        specs = parts.layout_for(self.profile.platform)
        plan = plan_layout(specs, self.emmc.image_bytes, self.emmc.sector_size)
        self.layout_notes = list(plan.notes)
        self.partitions = plan.partitions
        planned = {p.name for p in self.partitions}
        for spec in specs:
            if spec.name not in planned:
                self.partitions.append(VirtualPartition(
                    name=spec.name, offset=0, size=0, nominal_size=spec.nominal_size,
                    kind=spec.kind, region=spec.region, role=spec.role,
                    critical=spec.critical, status=parts.ST_MISSING,
                    issues=["the lab image was too small for this partition"]))

        written = 0
        for part in self.partitions:
            if part.size <= 0:
                continue
            blob = content_for(part, chipset=self.profile.chipset, imei=self.imei,
                               serial=self.serial_number)
            if blob:
                self.emmc.write(part.offset, blob.ljust(part.size, b"\x00")[:part.size])
                written += len(blob)
            self.emmc.save_golden(part)
            part.checksum = self.emmc.partition_checksum(part)

        gpt_info = gpt_virtual.write_gpt(self.image_path, self.partitions,
                                         disk_sectors=self.emmc.sectors,
                                         sector_size=self.emmc.sector_size)
        for part in self.partitions:
            if part.kind == "gpt":
                part.checksum = self.emmc.partition_checksum(part)
        self.status = STATE_HEALTHY
        self.log("created", f"virtual {self.profile.chipset} device with "
                            f"{len(self.partitions)} partitions")
        return {
            "device": self.id, "image": str(self.image_path),
            "image_bytes": self.emmc.image_bytes,
            "image_size_human": human_size(self.emmc.image_bytes),
            "partitions": len(self.partitions), "bytes_written": written,
            "gpt": gpt_info, "notes": self.layout_notes,
        }

    def replace_storage(self) -> Dict[str, Any]:
        """Swap the chip: blank image, healthy registers, everything restored from the goldens.

        This is the only repair for a dead eMMC, and the lab models it properly rather than
        pretending a software fix exists: the new chip arrives blank, so every partition has to
        be written back from the backups taken before the brick.
        """
        from .extcsd_virtual import HEALTHY

        old = {"pre_eol": f"0x{self.emmc.spec.pre_eol_value:02X}",
               "bad_blocks": len(self.emmc.bad_blocks)}
        self.emmc.set_health(HEALTHY)
        self.emmc.spec.bad_blocks = []
        self.emmc.bad_blocks = []
        self.emmc.notes = []
        self.emmc.counters.writes = 0
        self.emmc.counters.failed_reads = 0
        self.emmc.recreate_image(self.emmc.image_bytes)

        restored: List[str] = []
        for part in self.partitions:
            if part.size <= 0:
                continue
            try:
                self.emmc.restore_golden(part)
            except Exception as exc:                                    # noqa: BLE001
                LOG.warning("could not restore %s onto the new chip: %s", part.name, exc)
                continue
            part.status = ST_OK
            part.issues = []
            part.faults = []
            part.checksum = self.emmc.partition_checksum(part)
            restored.append(part.name)
        gpt_info = gpt_virtual.write_gpt(self.image_path,
                                         [p for p in self.partitions if p.size > 0],
                                         disk_sectors=self.emmc.sectors,
                                         sector_size=self.emmc.sector_size)
        for part in self.partitions:
            if part.kind == "gpt" and part.size > 0:
                part.checksum = self.emmc.partition_checksum(part)
        self.log("storage_replaced",
                 f"eMMC replaced; {len(restored)} partitions restored from the golden copies")
        return {"old_chip": old, "new_chip": self.emmc.health(),
                "restored_partitions": restored, "gpt": gpt_info}

    # -- faults ------------------------------------------------------------------------
    def apply_fault(self, fault_id: str, label: str = "", detail: str = "",
                    partition_names: Sequence[str] = ()) -> Fault:
        fault = Fault(id=fault_id, label=label or fault_id,
                      applied_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      detail=detail, partitions=[str(p) for p in partition_names])
        self.faults.append(fault)
        self.status = STATE_BRICKED
        self.log("brick", f"applied {label or fault_id}" +
                 (f" to {', '.join(fault.partitions)}" if fault.partitions else ""))
        return fault

    def mark_repaired(self, fault_id: str) -> Optional[Fault]:
        for fault in self.faults:
            if fault.id == fault_id:
                fault.repaired = True
                fault.repaired_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not self.active_faults:
            self.status = STATE_RECOVERED
            self.log("recovered", "every applied brick has been repaired")
            return None
        self.status = STATE_BRICKED
        return self.active_faults[0]

    def reset(self) -> Dict[str, Any]:
        """Rebuild the device from scratch: the same profile, no faults."""
        before = [f.id for f in self.active_faults]
        self.faults = []
        self.emmc.spec = self.emmc.spec.with_health(regs.HEALTHY)
        self.emmc.spec.bad_blocks = []
        self.emmc.bad_blocks = []
        self.emmc.notes = []
        self.profile.boot_mode = MODE_NORMAL
        info = self.create_storage()
        self.log("reset", f"device rebuilt (cleared {', '.join(before) or 'nothing'})")
        return {"device": self.id, "cleared": before, **info}

    # -- the simulated boot ------------------------------------------------------------
    def boot(self) -> BootResult:
        """Walk the boot chain and stop at the first thing that is broken.

        The checks are the ones that actually decide whether a phone boots: is the table
        readable, is the stage-1 loader intact, does the boot image still parse, is the system
        present, and is the storage healthy enough to hold any of it.
        """
        result = BootResult(boot_mode=self.profile.boot_mode)
        if self.profile.boot_mode != MODE_NORMAL:
            result.reached = "power_on"
            result.reason = (f"the device is sitting in {self.profile.boot_mode} download mode: "
                             "it does not try to boot Android")
            result.stages.append(BootStage("power_on", True, "power applied"))
            result.stages.append(BootStage("download_mode", True,
                                           f"enumerated as {self.profile.download_mode}",
                                           [self.profile.boot_mode]))
            return result

        # 1. The partition table.
        state = gpt_virtual.read(self.image_path, self.emmc.sector_size)
        stage = BootStage("partition_table", not state.is_damaged,
                          state.error or f"{state.partition_count} partitions, "
                          f"header CRC {'ok' if state.header_crc_ok else 'BAD'}, "
                          f"entries CRC {'ok' if state.entries_crc_ok else 'BAD'}",
                          ["pgpt"])
        result.stages.append(stage)
        if not state.readable:
            result.reached, result.reason = "partition_table", \
                "no readable partition table - the bootloader cannot find any partition"
            return result

        # 2. Stage-1 loader (preloader / xbl / bootloader).
        first = self.profile.bootloader_partitions[:1]
        stage = self._check_partitions("stage1_loader", first,
                                       "the stage-1 loader is missing or damaged")
        result.stages.append(stage)
        if not stage.ok:
            result.reached, result.reason = "stage1_loader", stage.detail
            return result

        # 3. Bootloader proper (lk / abl / uboot).
        stage = self._check_partitions("bootloader", self.profile.bootloader_partitions[1:],
                                       "the bootloader is missing or damaged")
        result.stages.append(stage)
        if not stage.ok:
            result.reached, result.reason = "bootloader", stage.detail
            return result

        # 4. Kernel + ramdisk.
        boot_part = self.partition("boot")
        boot_ok, boot_detail = False, "no boot partition in this layout"
        if boot_part is not None:
            boot_ok, boot_detail = self._boot_image_ok(boot_part)
        stage = BootStage("kernel", boot_ok, boot_detail, ["boot"])
        result.stages.append(stage)
        if not boot_ok:
            result.reached, result.reason = "kernel", boot_detail
            return result

        # 5. System.
        stage = self._check_partitions("system", self.profile.system_partitions,
                                       "the system partition is missing or damaged")
        result.stages.append(stage)
        if not stage.ok:
            result.reached, result.reason = "system", stage.detail
            return result

        # 6. Storage health. A chip at PRE_EOL urgent boots once and then loses the write.
        health = self.emmc.health()
        storage_ok = self.emmc.spec.pre_eol_value < 0x03
        stage = BootStage("storage", storage_ok,
                          f"PRE_EOL {health['pre_eol']} ({health['pre_eol_text']}), "
                          f"{health['life_a_text']}", [])
        result.stages.append(stage)
        if not storage_ok:
            result.warnings.append("the eMMC reports urgent end-of-life: it may boot once and "
                                   "then lose data on the next write")

        # 7. userdata: a dirty filesystem does not stop the boot, it triggers a repair pass.
        userdata = self.partition("userdata")
        if userdata is not None and userdata.status != ST_OK:
            result.warnings.append(f"userdata is {userdata.status}: "
                                   f"{'; '.join(userdata.issues) or 'a factory reset will follow'}")

        result.booted = storage_ok
        result.reached = "android" if storage_ok else "storage"
        result.reason = "" if storage_ok else \
            "the storage is at the end of its life: the write that boots it will not hold"
        if result.booted:
            self.log("boot", f"booted to Android through {len(result.stages)} stages")
        else:
            self.log("boot", f"boot failed at {result.reached}: {result.reason}")
        return result

    def _check_partitions(self, name: str, names: Sequence[str], failure: str) -> BootStage:
        names = [n for n in names if n]
        if not names:
            return BootStage(name, True, "nothing to check at this stage", [])
        problems: List[str] = []
        for part_name in names:
            part = self.partition(part_name)
            if part is None:
                problems.append(f"{part_name} is not in the layout")
                continue
            if part.size <= 0:
                problems.append(f"{part_name} is missing from the image")
                continue
            if part.status != ST_OK:
                problems.append(f"{part_name} is {part.status}")
                continue
            try:
                head = self.emmc.read(part.offset, min(part.size, 4096))
            except Exception as exc:                                    # noqa: BLE001
                problems.append(f"{part_name} could not be read: {exc}")
                continue
            if not head.strip(b"\x00\xff"):
                problems.append(f"{part_name} is blank")
        return BootStage(name, not problems,
                         failure + ": " + "; ".join(problems) if problems else
                         f"{', '.join(names)} present and readable", list(names))

    def _boot_image_ok(self, part: VirtualPartition):
        """Parse the boot partition with Revive's real boot image parser."""
        from ..storage import bootimg

        if part.size <= 0:
            return False, "the boot partition is missing from the image"
        try:
            head = self.emmc.read(part.offset, min(part.size, 4096))
        except Exception as exc:                                        # noqa: BLE001
            return False, f"the boot partition could not be read: {exc}"
        if head[:8] != b"ANDROID!":
            return False, ("the boot image magic is gone - the kernel cannot be located "
                           f"(partition reads as {head[:8].hex() or 'blank'})")
        try:
            tmp = self._slice(part)
            image = bootimg.parse(tmp)
        except Exception as exc:                                        # noqa: BLE001
            return False, f"the boot image header no longer parses: {exc}"
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return True, (f"boot image v{image.header_version}, kernel "
                      f"{human_size(image.section('kernel').size) if image.section('kernel') else '?'}")

    def _slice(self, part: VirtualPartition) -> str:
        import tempfile

        handle = tempfile.NamedTemporaryFile(prefix="revive-lab-", suffix=".img", delete=False)
        handle.close()
        with open(handle.name, "wb") as out:
            out.write(self.emmc.read(part.offset, part.size))
        return handle.name

    # -- the backend -------------------------------------------------------------------
    def backend(self, verbose: bool = False) -> LabTransport:
        """A real DeviceBackend wired to this device, for read/write/list_partitions."""
        return LabTransport(self, verbose=verbose)

    def verify(self) -> Dict[str, Any]:
        """[VERIFY RESULT]: is this device healthy right now? The dashboard's PASS/FAIL."""
        # The table partition (pgpt) starts at LBA 0, and Revive's GPT reader deliberately
        # leaves LBA-0 entries out of the used list - its integrity is what the CRC checks
        # measure, so it is not expected back by name.
        expected = [p.name for p in self.partitions if p.size > 0 and p.first_lba > 0]
        gpt = gpt_virtual.verify(self.image_path, expected, self.emmc.sector_size)
        boot_result = self.boot()
        damaged = [p.to_dict() for p in self.partitions if p.status != ST_OK]
        health = self.emmc.health()
        faults = [f.to_dict() for f in self.active_faults]
        ok = gpt["ok"] and boot_result.booted and not damaged and not faults
        return {
            "ok": ok, "verdict": "PASS" if ok else "FAIL",
            "status": self.status,
            "gpt": gpt, "boot": boot_result.to_dict(),
            "damaged_partitions": damaged, "active_faults": faults,
            "health": {k: health[k] for k in ("state", "pre_eol", "pre_eol_text", "verdict",
                                              "life_a_text", "bad_blocks")},
            "emmc_signals": self.emmc.signals(),
            "checks": [
                {"name": "partition table", "ok": gpt["ok"], "detail": gpt["detail"]},
                {"name": "boot", "ok": boot_result.booted, "detail": boot_result.to_dict()["summary"]},
                {"name": "partitions", "ok": not damaged,
                 "detail": (", ".join(p["name"] for p in damaged) if damaged else
                            f"all {len(self.partitions)} partitions healthy")},
                {"name": "storage health", "ok": health["verdict"] != "fatal",
                 "detail": f"{health['state']} ({health['pre_eol']}), {health['life_a_text']}"},
                {"name": "faults", "ok": not faults,
                 "detail": (", ".join(f["label"] for f in faults) if faults else
                            "no unrepaired bricks")},
            ],
        }

    # -- logging -----------------------------------------------------------------------
    def log(self, kind: str, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Append to the device's event log, and to the file log."""
        event = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "device": self.id, "kind": kind, "message": message, "data": data or {}}
        self.events.append(event)
        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            with (self.logs_dir / "events.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
            self._file_handler()
            LOG.info("[%s] %s: %s", self.id, kind, message)
        except OSError as exc:                                          # pragma: no cover
            LOG.warning("could not write the lab log for %s: %s", self.id, exc)
        return event

    def attach_log(self) -> Optional[logging.FileHandler]:
        """Start writing this device's log file, and return the handler.

        Public because the web UI wants every API call to land in the device's own `lab.log`,
        the same file the CLI writes.
        """
        return self._file_handler()

    def _file_handler(self) -> Optional[logging.FileHandler]:
        if self._log_handler is not None:
            return self._log_handler
        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            self._log_handler = logging.FileHandler(self.logs_dir / "lab.log", encoding="utf-8")
            self._log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logging.getLogger("revive.lab").addHandler(self._log_handler)
            return self._log_handler
        except OSError as exc:                                          # pragma: no cover
            LOG.warning("could not open a lab log file: %s", exc)
            return None

    def close(self) -> None:
        if self._log_handler is not None:
            logging.getLogger("revive.lab").removeHandler(self._log_handler)
            self._log_handler.close()
            self._log_handler = None

    # -- serialisation -----------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA, "id": self.id, "folder": str(self.folder),
            "created_at": self.created_at, "status": self.status,
            "profile": self.profile.to_dict(), "imei": self.imei,
            "serial_number": self.serial_number,
            "image_bytes": self.image_bytes,
            "partitions": [p.to_dict() for p in self.partitions],
            "faults": [f.to_dict() for f in self.faults],
            "active_faults": [f.id for f in self.active_faults],
            "layout_notes": list(self.layout_notes),
            "events": self.events[-50:],
        }

    def save(self) -> Dict[str, Any]:
        """Write device.json, partition_map.json and extcsd.json."""
        self.folder.mkdir(parents=True, exist_ok=True)
        util.atomic_write(self.folder / "device.json",
                          util.to_json(self.to_dict()).encode("utf-8"))
        util.atomic_write(self.folder / "partition_map.json", util.to_json({
            "schema": "revive-lab-partitions/1", "device": self.id,
            "platform": self.profile.platform, "image": str(self.image_path),
            "image_bytes": self.emmc.image_bytes,
            "image_size_human": human_size(self.emmc.image_bytes),
            "sector_size": self.emmc.sector_size, "gpt": gpt_virtual.read(
                self.image_path, self.emmc.sector_size).to_dict(),
            "partitions": [p.to_dict() for p in self.partitions],
            "notes": list(self.layout_notes),
        }).encode("utf-8"))
        self.emmc.save(self.folder / "extcsd.json")
        return {"device": str(self.folder / "device.json"),
                "partition_map": str(self.folder / "partition_map.json"),
                "extcsd": str(self.folder / "extcsd.json")}

    @classmethod
    def load(cls, folder) -> "VirtualDevice":
        """Reopen a device from its folder."""
        root = Path(folder)
        meta_path = root / "device.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"{meta_path} does not exist: not a lab device folder")
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"{meta_path} is not readable as JSON: {exc}") from exc

        device = cls(root, profile=DeviceProfile.from_dict(data.get("profile", {})),
                     device_id=str(data.get("id") or root.name),
                     image_bytes=int(data.get("image_bytes", DEFAULT_IMAGE_BYTES)))
        device.created_at = str(data.get("created_at", device.created_at))
        device.status = str(data.get("status", STATE_HEALTHY))
        device.imei = str(data.get("imei", device.imei))
        device.serial_number = str(data.get("serial_number", device.serial_number))
        device.layout_notes = [str(n) for n in data.get("layout_notes", [])]
        device.faults = [Fault.from_dict(f) for f in data.get("faults", [])]
        device.events = [dict(e) for e in data.get("events", [])]
        device.partitions = [VirtualPartition.from_dict(p) for p in data.get("partitions", [])]

        ext_path = root / "extcsd.json"
        spec_data = None
        if ext_path.exists():
            try:
                spec_data = json.loads(ext_path.read_text(encoding="utf-8")).get("spec")
            except (OSError, ValueError) as exc:
                LOG.warning("could not read %s: %s", ext_path, exc)
        if not device.partitions:
            # Older or partially written device: rebuild the map from the image itself.
            plan = plan_layout(parts.layout_for(device.profile.platform),
                               max(MIN_IMAGE_BYTES, device.image_bytes), SECTOR)
            device.partitions = plan.partitions
        device.emmc = VirtualEMMC(root / "emmc.img",
                                  spec=regs.RegisterSpec.from_dict(spec_data or {}),
                                  golden_dir=root / "golden")
        if spec_data and spec_data.get("capacity_bytes"):
            device.profile.storage = human_size(int(spec_data["capacity_bytes"]), precision=0)
        return device


# --------------------------------------------------------------------------------------
# The lab: the device database
# --------------------------------------------------------------------------------------

class LabBench:
    """The `lab_devices/` database: create, list, load and track test history."""

    def __init__(self, root=None):
        self.root = Path(root or DEFAULT_LAB_ROOT).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        self._index_store = util.JsonStore(self.root / "index.json",
                                           {"schema": "revive-lab-index/1", "devices": {},
                                            "active": ""})
        self._history_path = self.root / "history.jsonl"

    # -- index -------------------------------------------------------------------------
    def _index(self) -> Dict[str, Any]:
        return self._index_store.load()

    def _save_index(self, index: Dict[str, Any]) -> None:
        self._index_store.save(index)

    def list_devices(self) -> List[Dict[str, Any]]:
        """Every device in the lab, newest first."""
        index = self._index()
        out: List[Dict[str, Any]] = []
        for device_id, entry in index.get("devices", {}).items():
            folder = self.root / device_id
            if not (folder / "device.json").exists():
                continue
            record = dict(entry)
            record["id"] = device_id
            record["folder"] = str(folder)
            out.append(record)
        out.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
        return out

    def get(self, device_id: Optional[str] = None) -> VirtualDevice:
        """Load a device by id, or the active one."""
        index = self._index()
        device_id = device_id or index.get("active") or ""
        if not device_id:
            devices = self.list_devices()
            if not devices:
                raise FileNotFoundError(
                    f"the lab is empty: create a device first "
                    f"(`python -m revive.lab_testing create --chip MT6768`)")
            device_id = devices[0]["id"]
        folder = self.root / device_id
        return VirtualDevice.load(folder)

    def set_active(self, device_id: str) -> None:
        index = self._index()
        index["active"] = device_id
        self._save_index(index)

    def delete(self, device_id: str) -> Dict[str, Any]:
        import shutil

        folder = self.root / device_id
        if not folder.is_dir():
            raise FileNotFoundError(f"no lab device named {device_id}")
        shutil.rmtree(folder, ignore_errors=True)
        index = self._index()
        index.get("devices", {}).pop(device_id, None)
        if index.get("active") == device_id:
            index["active"] = ""
        self._save_index(index)
        return {"deleted": device_id, "folder": str(folder)}

    # -- creation ----------------------------------------------------------------------
    def create(self, chip: str = "MT6768", storage: Optional[str] = None,
               image_bytes: int = DEFAULT_IMAGE_BYTES, vendor: Optional[str] = None,
               model: Optional[str] = None, device_id: Optional[str] = None) -> VirtualDevice:
        """Create a new virtual phone and register it in the lab index."""
        profile = get_profile(chip)
        if storage:
            profile.storage = str(storage)
        if vendor:
            profile.vendor = str(vendor)
        if model:
            profile.model = str(model)

        stamp = time.strftime("%Y%m%d_%H%M%S")
        size_tag = util.safe_filename(str(profile.storage).replace(" ", ""), "storage")
        device_id = device_id or util.safe_filename(
            f"{stamp}_{profile.chipset}_{size_tag}", "device")
        device_id = self._unique_id(device_id)

        device = VirtualDevice(self.root / device_id, profile=profile, device_id=device_id,
                               image_bytes=image_bytes)
        info = device.create_storage()
        device.save()

        index = self._index()
        index.setdefault("devices", {})[device_id] = {
            "created_at": device.created_at, "chipset": profile.chipset,
            "platform": profile.platform, "vendor": profile.vendor, "model": profile.model,
            "storage": profile.storage, "interface": profile.interface,
            "status": device.status, "partitions": len(device.partitions),
            "image_bytes": info["image_bytes"],
        }
        index["active"] = device_id
        self._save_index(index)
        LOG.info("created lab device %s (%s, %s)", device_id, profile.chipset, profile.storage)
        return device

    def _unique_id(self, device_id: str) -> str:
        candidate, index = device_id, 2
        while (self.root / candidate / "device.json").exists():
            candidate = f"{device_id}-{index}"
            index += 1
        return candidate

    def update_status(self, device_id: str, status: str,
                      extra: Optional[Dict[str, Any]] = None) -> None:
        index = self._index()
        entry = index.get("devices", {}).get(device_id)
        if entry is None:
            return
        entry["status"] = status
        entry["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry.update(extra or {})
        self._save_index(index)

    # -- history -----------------------------------------------------------------------
    def record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Every test gets a history line: timestamp, device, scenario, result."""
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "device": record.get("device", ""),
            "scenario": record.get("scenario", ""),
            "result": record.get("result", ""),
            "detection": record.get("detection", ""),
            "repair": record.get("repair", ""),
            "verification": record.get("verification", ""),
            "detail": record.get("detail", ""),
        }
        try:
            with self._history_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
            with (self.root / "logs" / "history.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:                                          # pragma: no cover
            LOG.warning("could not write lab history: %s", exc)
        return entry

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not self._history_path.exists():
            return []
        lines: List[Dict[str, Any]] = []
        try:
            with self._history_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        lines.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError as exc:                                          # pragma: no cover
            LOG.warning("could not read lab history: %s", exc)
            return []
        return lines[-max(1, int(limit)):][::-1]

    def summary(self) -> Dict[str, Any]:
        devices = self.list_devices()
        history = self.history(500)
        return {
            "root": str(self.root), "device_count": len(devices),
            "active": self._index().get("active", ""),
            "devices": devices, "history": history[:50],
            "runs": len(history),
            "passed": sum(1 for h in history if h.get("result") == "PASS"),
            "failed": sum(1 for h in history if h.get("result") == "FAIL"),
        }
