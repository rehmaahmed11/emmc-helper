"""Backend registry: what can this machine talk to, and what should the user do next?"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core import usbmodes
from .base import BackendError, BackendUnavailable, DeviceBackend, DeviceInfo, Partition
from .fastboot import FastbootBackend
from .mock import MockBackend, MockProfile, demo_backend
from .mtk_brom import MtkBromBackend
from .qualcomm_edl import QualcommEdlBackend
from .unisoc import UnisocBackend

BACKENDS: Dict[str, type] = {
    "mtk": MtkBromBackend,
    "qualcomm": QualcommEdlBackend,
    "unisoc": UnisocBackend,
    "fastboot": FastbootBackend,
    "mock": MockBackend,
}

# Which backend handles which USB mode (mock is always offered as a learning option).
MODE_TO_BACKEND = {
    usbmodes.MODE_MTK_BROM: "mtk",
    usbmodes.MODE_MTK_PRELOADER: "mtk",
    usbmodes.MODE_MTK_DA: "mtk",
    usbmodes.MODE_QC_EDL: "qualcomm",
    usbmodes.MODE_UNISOC: "unisoc",
    usbmodes.MODE_FASTBOOT: "fastboot",
}

__all__ = [
    "BACKENDS", "MODE_TO_BACKEND", "BackendError", "BackendUnavailable", "DeviceBackend",
    "DeviceInfo", "Partition", "MtkBromBackend", "QualcommEdlBackend", "UnisocBackend",
    "FastbootBackend", "MockBackend", "MockProfile", "demo_backend",
    "get_backend", "describe_backends", "detect", "suggest_next_steps",
]


def get_backend(name: str, **kwargs) -> DeviceBackend:
    cls = BACKENDS.get(str(name).lower())
    if cls is None:
        raise BackendError(
            f"unknown backend {name!r}. Available: {', '.join(sorted(BACKENDS))}", code="unknown_chip")
    return cls(**kwargs)


def describe_backends() -> List[Dict[str, Any]]:
    out = []
    for name, cls in sorted(BACKENDS.items()):
        instance = cls()
        entry = instance.capabilities()
        entry["name"] = name
        entry["available"] = True
        if name in ("mtk", "qualcomm", "unisoc", "fastboot"):
            entry["available"] = usbmodes.libusb_available()
            if not entry["available"]:
                entry["install"] = usbmodes.install_hint()
        out.append(entry)
    return out


@dataclass
class DetectionResult:
    devices: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggested_backend: Optional[str] = None
    suggested_actions: List[str] = field(default_factory=list)
    serial_ports: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "devices": self.devices, "warnings": self.warnings,
            "suggested_backend": self.suggested_backend,
            "suggested_actions": self.suggested_actions,
            "serial_ports": self.serial_ports,
        }


def detect() -> DetectionResult:
    """Enumerate USB, map what we find to a backend, and say what to do next."""
    result = DetectionResult()
    devices, warnings = usbmodes.enumerate_devices()
    result.warnings.extend(warnings)
    result.serial_ports = usbmodes.serial_ports()

    for device in devices:
        entry = device.to_dict()
        info = usbmodes.mode_info(device.mode)
        entry["description"] = info.description
        entry["advice"] = info.advice
        entry["power_hint"] = info.power_hint
        result.devices.append(entry)

    # Prefer the deepest recovery mode available.
    priority = [usbmodes.MODE_MTK_BROM, usbmodes.MODE_QC_EDL, usbmodes.MODE_UNISOC,
                usbmodes.MODE_MTK_PRELOADER, usbmodes.MODE_ROCKCHIP_MASKROM,
                usbmodes.MODE_FASTBOOT, usbmodes.MODE_MTK_DA]
    modes = {d["mode"] for d in result.devices}
    for mode in priority:
        if mode in modes:
            result.suggested_backend = MODE_TO_BACKEND.get(mode)
            break

    result.suggested_actions = suggest_next_steps(result)
    return result


def suggest_next_steps(result: DetectionResult) -> List[str]:
    """Plain, ordered next steps - the thing every flashtool forgets to tell you."""
    steps: List[str] = []
    if not result.devices:
        steps.append("No phone detected. Power it off, then plug it in while holding the volume keys.")
        steps.append("Run `revive drivers` if the device also does not appear in Device Manager.")
        steps.append("You can still work on firmware files: `revive inspect <firmware_folder>`.")
        return steps

    for device in result.devices:
        if device["mode"] == usbmodes.MODE_MTK_BROM:
            steps.append(
                "MediaTek BROM is answering - the strongest position for a hard brick. "
                "Run `revive identify --backend mtk` to read the chip and security state."
            )
            steps.append(
                "Do that BEFORE flashing: the security flags decide whether you need an auth file."
            )
            break
        if device["mode"] == usbmodes.MODE_MTK_PRELOADER:
            steps.append(
                "The preloader is running, so the boot area is intact. Run "
                "`revive identify --backend mtk`, then `revive plan <firmware>` before flashing."
            )
            break
        if device["mode"] == usbmodes.MODE_QC_EDL:
            steps.append(
                "Qualcomm EDL detected. You need the firehose loader for this exact model, then: "
                "`revive identify --backend qualcomm --loader <prog_*.mbn>`."
            )
            break
        if device["mode"] == usbmodes.MODE_UNISOC:
            steps.append(
                "Unisoc download mode detected. Revive can identify it but flashing is left to the "
                "vendor tool by design - check `revive inspect <file.pac>` first."
            )
            break
        if device["mode"] == usbmodes.MODE_FASTBOOT:
            steps.append(
                "The bootloader is alive: `revive identify --backend fastboot` lists model, slot and "
                "lock state. This phone is not bricked - try a normal flash before anything drastic."
            )
            break
        if device["mode"] == usbmodes.MODE_ADB:
            steps.append(
                "Android is running. Back up first (`revive backup-adb`) and record the exact "
                "model/build so you download the right firmware."
            )
            break
        if device["mode"] == usbmodes.MODE_ODIN:
            steps.append("Samsung download mode: use Odin/Heimdall for this device.")
            break
        if device["mode"] in (usbmodes.MODE_ROCKCHIP, usbmodes.MODE_ROCKCHIP_MASKROM,
                              usbmodes.MODE_ALLWINNER_FEL):
            steps.append(
                f"{usbmodes.mode_info(device['mode']).label} detected: this is not a "
                "MediaTek/Qualcomm device - use the platform's own tool (rkdeveloptool / sunxi-fel)."
            )
            break

    unknown = [d for d in result.devices if d["mode"] == usbmodes.MODE_UNKNOWN]
    if unknown and not result.suggested_backend:
        steps.append(
            "A USB device is present but its ID is not a known download mode. Note the id "
            f"({unknown[0]['id']}) and the product name, and add it to the mode table."
        )
    steps.append("Nothing is written to a phone without a validated plan and an explicit confirm.")
    return steps
