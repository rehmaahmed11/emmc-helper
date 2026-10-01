"""Fastboot backend - the easy case.

If a phone still reaches its bootloader, none of the dramatic recovery machinery is needed:
fastboot can read variables, flash partitions and (with the right token) unlock bootloaders.
This backend implements the fastboot USB protocol directly, so it works without the `fastboot`
binary being installed, and it reports the phone's state in the same shape as the other
backends. The protocol is simple and stable:

    host: "command:argument"          (ASCII, no NUL)
    host: reads 4 bytes -> "OKAY" | "FAIL" | "INFO" | "DATA"
    FAIL is followed by a human-readable reason
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core import usbmodes
from ..util import ProgressFn, human_size, null_progress
from . import usbfinder
from .base import BackendError, BackendUnavailable, DeviceBackend, DeviceInfo, Partition

VID_GOOGLE = 0x18D1
FASTBOOT_PIDS = (0x4EE0, 0xD00D, 0x4EE7)

MAX_DOWNLOAD = 256 * 1024 * 1024


class FastbootBackend(DeviceBackend):
    name = "fastboot"
    label = "Android fastboot"
    vendor = "Android"
    modes = [usbmodes.MODE_FASTBOOT]
    capability_read = False       # `fastboot getvar` only; no partition streaming
    capability_write = True
    capability_erase = True
    capability_partitions = False
    tested = False
    protocol = "Android fastboot USB protocol 0.4 (public specification)"
    notes = [
        "Fastboot is the safest path: the bootloader is running, so nothing here is desperate.",
        "`fastboot getvar all` output is parsed into a readable summary.",
        "Flashing uses the image you choose and targets the partition name you choose - Revive "
        "shows both before writing.",
    ]

    def __init__(self, progress: ProgressFn = null_progress, verbose: bool = False,
                 timeout: float = 30.0):
        super().__init__(progress, verbose)
        self.timeout = timeout
        self.endpoints = {"out": 0x01, "in": 0x81}
        self.variables: Dict[str, str] = {}

    def open(self, device: Any = None) -> None:
        if device is None:
            devices, warnings = usbfinder.find_devices()
            candidates = [d for d in devices
                          if usbmodes.classify(int(d.idVendor), int(d.idProduct))[0] == usbmodes.MODE_FASTBOOT]
            if not candidates:
                raise BackendUnavailable(
                    "No device in fastboot mode. " + (warnings[0] if warnings else ""),
                    code="no_device",
                    detail="Boot the phone to its bootloader (usually Power + Volume Down) and "
                           "check `revive detect`.",
                )
            device = candidates[0]
        self.device = device
        self.info.usb_id = f"{int(device.idVendor):04x}:{int(device.idProduct):04x}"
        self.info.mode = usbmodes.MODE_FASTBOOT
        usbfinder.open_device(device)
        self.log_line("fastboot interface opened")

    # -- protocol ---------------------------------------------------------------------
    def _read_status(self) -> Dict[str, Any]:
        raw = bytes(self.device.read(self.endpoints["in"], 64, self.timeout * 1000))[:4]
        status = raw.decode("ascii", "replace")
        if status not in ("OKAY", "FAIL", "INFO", "DATA"):
            raise BackendError(f"unexpected fastboot status {status!r}", code="2005",
                               detail="The device answered something that is not fastboot. Check "
                                      "`revive detect` - it may be in a different mode.")
        info = ""
        if status in ("INFO", "FAIL"):
            info = self._read_string()
        return {"status": status, "text": info}

    def _read_string(self) -> str:
        chunks = []
        while True:
            raw = bytes(self.device.read(self.endpoints["in"], 64, self.timeout * 1000))
            for byte in raw:
                if byte == 0:
                    return "".join(chunks)
                chunks.append(chr(byte))
            if not raw or len(chunks) > 8192:
                return "".join(chunks)

    def _send(self, command: str) -> None:
        self.device.write(self.endpoints["out"], command.encode("ascii"), self.timeout * 1000)

    def run(self, command: str) -> Dict[str, Any]:
        self._send(command)
        result = self._read_status()
        # Collect any INFO lines that follow a successful command.
        infos: List[str] = []
        while result["status"] == "INFO":
            infos.append(result["text"])
            result = self._read_status()
        result["info"] = infos
        if result["status"] == "FAIL":
            raise BackendError(f"fastboot refused '{command}': {result['text']}", code="2005",
                               detail="The message above comes straight from the bootloader.",
                               data=result)
        return result

    def getvar(self, name: str) -> str:
        self._send(f"getvar:{name}")
        parts: List[str] = []
        while True:
            result = self._read_status()
            if result["status"] == "FAIL":
                return ""
            if result["status"] == "OKAY":
                break
            parts.append(result["text"])
            if len(parts) > 64:
                break
        value = "\n".join(p for p in parts if p).strip()
        self.variables[name] = value
        return value

    def get_all(self, limit: int = 120) -> Dict[str, str]:
        """Parse `getvar all` - the fastest way to identify a phone and its firmware."""
        self._send("getvar:all")
        collected: Dict[str, str] = {}
        count = 0
        while count < limit:
            result = self._read_status()
            if result["status"] in ("OKAY", "FAIL"):
                break
            count += 1
            text = result["text"]
            if text.startswith("(bootloader) "):
                text = text[len("(bootloader) "):]
            if ":" in text:
                key, value = text.split(":", 1)
                collected[key.strip()] = value.strip()
        self.variables.update(collected)
        return collected

    # -- operations -------------------------------------------------------------------
    def identify(self) -> DeviceInfo:
        all_vars = self.get_all()
        product = all_vars.get("product", "")
        variant = all_vars.get("variant", "")
        self.info.chip = all_vars.get("cpu") or all_vars.get("soc") or product
        self.info.serial = all_vars.get("serialno", "")
        self.info.usb_id = self.info.usb_id
        self.info.extras = {
            "product": product, "variant": variant,
            "unlocked": all_vars.get("unlocked", all_vars.get("secure", "?")),
            "bootloader_version": all_vars.get("version-bootloader", ""),
            "baseband": all_vars.get("version-baseband", ""),
            "battery_voltage": all_vars.get("battery-voltage", ""),
            "slot_count": all_vars.get("slot-count", ""),
            "current_slot": all_vars.get("current-slot", ""),
            "partition_type": all_vars.get("partition-type:boot", ""),
            "variables": len(all_vars),
        }
        state = all_vars.get("unlocked", "")
        if state and state.lower() in ("no", "false", "0"):
            self.info.notes.append(
                "Bootloader is LOCKED: flashing will be refused until it is unlocked. Unlocking "
                "erases userdata - back up first."
            )
        self.info.notes.extend(self.guard_tested())
        return self.info

    def flash(self, partition: str, image_path) -> Dict[str, Any]:
        path = Path(image_path)
        size = path.stat().st_size
        if size > MAX_DOWNLOAD:
            raise BackendError(
                f"image is {human_size(size)}; fastboot downloads over RAM and this is too large "
                "for one transfer", code="plan_size_mismatch",
                detail="Use the vendor's flashing tool for partitions this big, or flash a sparse "
                       "image if the device supports it.")
        self.run(f"flash:{partition}")      # readies the device (or fails cleanly)
        self._send(f"download:{size:08x}")
        status = self._read_status()
        if status["status"] != "DATA":
            raise BackendError(f"device refused the download: {status.get('text', '')}",
                               code="plan_size_mismatch")
        sent = 0
        with path.open("rb") as fh:
            while sent < size:
                block = fh.read(1024 * 1024)
                if not block:
                    break
                self.device.write(self.endpoints["out"], block, self.timeout * 1000)
                sent += len(block)
                self.progress(sent, size, f"flashing {partition}")
        result = self._read_status()
        if result["status"] != "OKAY":
            raise BackendError(f"flash failed: {result.get('text', '')}", code="4008")
        return {"partition": partition, "bytes": sent, "source": str(path)}

    def erase(self, partition: str) -> Dict[str, Any]:
        return self.run(f"erase:{partition}")

    def reboot(self, target: str = "") -> Dict[str, Any]:
        return self.run(f"reboot{':' + target if target else ''}")

    def list_partitions(self) -> List[Partition]:
        parts: List[Partition] = []
        for key, value in self.variables.items():
            if key.startswith("partition-size:"):
                parts.append(Partition(key.split(":", 1)[1], 0, int(value, 16) if value else 0))
        return parts
