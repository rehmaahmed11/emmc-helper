"""A fully working simulated device.

Uses:

  * the UI's demo mode, so a technician can learn the workflow with no phone plugged in
  * tests, so the flash/backup code paths are exercised end to end
  * support, so a user can reproduce a problem and send the log

It implements the real backend interface against an in-memory eMMC image (backed by a file),
including a genuine GPT so partition listing, reading and writing all behave like the real thing.
The simulated device also reports a realistic eMMC EXT_CSD health value, and can be told to
report a dying eMMC so the "back up now" warnings can be demonstrated.
"""
from __future__ import annotations

import os
import random
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core import chips, usbmodes
from ..storage import gpt as gpt_mod
from ..util import ProgressFn, human_size, null_progress
from .base import BackendError, DeviceBackend, DeviceInfo, Partition

DEFAULT_SECTORS = 4096 * 512      # 2 GB simulated eMMC


@dataclass
class MockProfile:
    hwcode: int = 0x707
    storage: str = "eMMC"
    sectors: int = DEFAULT_SECTORS
    pre_eol: int = 0x01
    life_a: int = 0x02
    secure_boot: bool = True
    sla: bool = True
    daa: bool = True
    latency: float = 0.0          # simulated per-operation delay, for demos
    name: str = "Simulated phone (MT6768 / Helio G85)"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "hwcode": f"0x{self.hwcode:04X}", "storage": self.storage,
            "capacity": self.sectors * 512, "secure_boot": self.secure_boot,
            "pre_eol": self.pre_eol, "life_a": self.life_a,
        }


class MockBackend(DeviceBackend):
    name = "mock"
    label = "Simulated device (no hardware)"
    vendor = "Revive"
    modes = ["simulated"]
    capability_read = True
    capability_write = True
    capability_erase = True
    capability_partitions = True
    tested = True
    protocol = "in-process simulation"
    notes = [
        "This backend never touches USB: it is for learning the workflow, demos and tests.",
        "Writes go to a scratch file, not to a phone.",
    ]

    def __init__(self, progress: ProgressFn = null_progress, verbose: bool = False,
                 profile: Optional[MockProfile] = None, storage_path: Optional[Path] = None):
        super().__init__(progress, verbose)
        self.profile = profile or MockProfile()
        self.storage_path = Path(storage_path) if storage_path else None
        self.da_loaded = False
        self._created_storage = False

    # -- connection -------------------------------------------------------------------
    def open(self) -> None:
        if self.profile.latency:
            time.sleep(self.profile.latency)
        self.info.usb_id = f"{0x0E8D:04x}:{0x0003:04x}"
        self.info.mode = usbmodes.MODE_MTK_BROM
        self.info.vendor = "MediaTek (simulated)"
        self._ensure_storage()
        self.log_line(f"simulated device ready: {self.profile.name}")

    def _ensure_storage(self) -> None:
        if not self.storage_path:
            return
        if not self.storage_path.exists():
            self._created_storage = True
            self._create_storage()

    def _create_storage(self) -> None:
        """Write a realistic eMMC user area: MBR + GPT + a few real partitions."""
        size = self.profile.sectors * 512
        parts = [
            gpt_mod.PartitionEntry(0, "preloader", "0fc63daf-8483-4772-8e79-3d69d8477de4",
                                   str(uuid.uuid4()), 2048, 3072, 0),
            gpt_mod.PartitionEntry(0, "boot_a", "0fc63daf-8483-4772-8e79-3d69d8477de4",
                                   str(uuid.uuid4()), 4096, 8192, 0),
            gpt_mod.PartitionEntry(0, "system_a", "0fc63daf-8483-4772-8e79-3d69d8477de4",
                                   str(uuid.uuid4()), 16384, 32768, 0),
            gpt_mod.PartitionEntry(0, "userdata", "0fc63daf-8483-4772-8e79-3d69d8477de4",
                                   str(uuid.uuid4()), 32769, self.profile.sectors - 34, 0),
        ]
        mbr, primary, backup = gpt_mod.build_gpt_bytes(parts, self.profile.sectors, 512)
        table_sectors = (128 * 128 + 511) // 512
        with self.storage_path.open("wb") as fh:
            fh.write(mbr)
            fh.write(primary)
            fh.seek(4096 * 512)                       # a little "boot image" content
            fh.write(b"ANDROID!" + b"\x00" * 2040 + b"MOCK KERNEL" * 200)
            fh.seek(32769 * 512)
            fh.write(b"\x00" * min(1024 * 1024, max(0, size - 32769 * 512)))
            fh.seek((self.profile.sectors - 1 - table_sectors) * 512)
            fh.write(backup)
            fh.truncate(size)

    # -- operations -------------------------------------------------------------------
    def identify(self) -> DeviceInfo:
        chip = chips.lookup(self.profile.hwcode)
        self.info.hwcode = self.profile.hwcode
        self.info.chip = chip.name if chip else "unknown"
        self.info.chip_confidence = chip.confidence if chip else chips.UNKNOWN
        self.info.storage = self.profile.storage
        self.info.storage_size = self.profile.sectors * 512
        self.info.security = {
            "secure_boot": self.profile.secure_boot, "sla": self.profile.sla,
            "daa": self.profile.daa,
        }
        self.info.extras = {
            "simulated": True,
            "ext_csd_health": {0x01: "normal", 0x02: "warning", 0x03: "urgent"}.get(
                self.profile.pre_eol, "unknown"),
            "life_time_est": f"{(self.profile.life_a - 1) * 10}-{self.profile.life_a * 10}%",
            "capacity": human_size(self.info.storage_size),
        }
        self.info.notes.append("Simulated device: nothing here was read from real hardware.")
        if self.profile.pre_eol >= 0x02:
            self.info.notes.append(
                "Simulated eMMC reports wear (PRE_EOL warning) - the real tool would tell you to "
                "back up immediately."
            )
        return self.info

    def list_partitions(self) -> List[Partition]:
        if not self.storage_path or not self.storage_path.exists():
            return []
        try:
            parsed = gpt_mod.read_gpt(self.storage_path)
        except gpt_mod.GptError:
            return []
        return [Partition(p.name, p.offset, p.size) for p in parsed.partitions]

    def read_flash(self, offset: int, length: int, out_path, chunk: int = 1024 * 1024) -> Dict[str, Any]:
        if not self.storage_path:
            raise BackendError("the simulated device has no storage file",
                               detail="Pass --storage <file> or use the default.")
        total = self.profile.sectors * 512
        if offset + length > total:
            raise BackendError(
                f"read past the end of the simulated device "
                f"(0x{offset:x} + 0x{length:x} > 0x{total:x})", code="3167")
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with self.storage_path.open("rb") as fin, out.open("wb") as fout:
            fin.seek(offset)
            while written < length:
                block = fin.read(min(chunk, length - written))
                if not block:
                    block = b"\x00" * min(chunk, length - written)
                fout.write(block)
                written += len(block)
                self.progress(written, length, "reading")
                if self.profile.latency:
                    time.sleep(self.profile.latency / 10)
        return {"output": str(out), "bytes": written, "offset": offset, "simulated": True}

    def write_flash(self, offset: int, data_path, length: Optional[int] = None) -> Dict[str, Any]:
        if not self.storage_path:
            raise BackendError("the simulated device has no storage file")
        path = Path(data_path)
        total = length if length is not None else path.stat().st_size
        capacity = self.profile.sectors * 512
        if offset + total > capacity:
            raise BackendError(
                f"image does not fit: writing {human_size(total)} at 0x{offset:x} exceeds the "
                f"{human_size(capacity)} simulated device", code="plan_size_mismatch")
        written = 0
        with path.open("rb") as fin, self.storage_path.open("r+b") as fout:
            fout.seek(offset)
            while written < total:
                block = fin.read(min(4 * 1024 * 1024, total - written))
                if not block:
                    break
                fout.write(block)
                written += len(block)
                self.progress(written, total, "writing")
                if self.profile.latency:
                    time.sleep(self.profile.latency / 10)
        return {"source": str(path), "bytes": written, "offset": offset, "simulated": True}

    def erase_flash(self, offset: int, length: int) -> Dict[str, Any]:
        if not self.storage_path:
            raise BackendError("the simulated device has no storage file")
        with self.storage_path.open("r+b") as fh:
            fh.seek(offset)
            remaining = length
            block = b"\x00" * (1024 * 1024)
            while remaining > 0:
                n = min(remaining, len(block))
                fh.write(block[:n])
                remaining -= n
                self.progress(length - remaining, length, "erasing")
        return {"offset": offset, "bytes": length, "simulated": True}


def demo_backend(storage: Optional[Path] = None, **kwargs) -> MockBackend:
    """A ready-to-use simulated backend, used by `revive serve --demo` and the UI."""
    return MockBackend(storage_path=storage, **kwargs)
