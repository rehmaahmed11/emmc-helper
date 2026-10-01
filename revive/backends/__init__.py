"""Backend registry: what can this machine talk to, and what should the user do next?"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..core import usbmodes
from .base import BackendError, BackendUnavailable, DeviceBackend, DeviceInfo, Partition
from .fastboot import FastbootBackend
from .interceptor import DOWNLOAD_TARGET_MODES, InterceptEvent, InterceptResult, UsbInterceptor
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
    "UsbInterceptor", "InterceptResult", "InterceptEvent",
    "get_backend", "describe_backends", "detect", "suggest_next_steps",
    "intercept_and_capture",
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
        steps.append("Or run `revive intercept --force` to catch a sub-ms handshake and force BROM/EDL.")
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


def intercept_and_capture(
    backend_name: str = "auto",
    timeout: float = 20.0,
    force_entry: bool = True,
    force_brom: bool = False,
    out_dir: Optional[str] = "revive_handshakes",
    demo: bool = False,
    storage_path: Optional[Path] = None,
    verbose: bool = False,
    injected_device: Any = None,
) -> Dict[str, Any]:
    """Run the sub-ms interceptor, identify the device, and save the full handshake + scatter dossier."""
    from ..ops import dossier

    if demo or backend_name == "mock":
        mock_b = MockBackend(storage_path=storage_path, verbose=verbose)
        mock_b.open()
        info = mock_b.identify()
        parts = mock_b.list_partitions()
        sim_res = InterceptResult(
            ok=True,
            mode=usbmodes.MODE_MTK_BROM,
            backend="mock",
            usb_id="0e8d:0003",
            vid=0x0E8D,
            pid=0x0003,
            capture_latency_ms=0.12,
            handshake_duration_ms=0.45,
            poll_iterations=1,
            sync_bytes=[
                {"tx": "0xA0", "rx": "0x5F", "expected": "0x5F"},
                {"tx": "0x0A", "rx": "0xF5", "expected": "0xF5"},
                {"tx": "0x50", "rx": "0xAF", "expected": "0xAF"},
                {"tx": "0x05", "rx": "0xFA", "expected": "0xFA"},
            ],
            wdt_disabled=True,
            wdt_address=0x10007000,
            telemetry={"hwcode": f"0x{mock_b.profile.hwcode:04X}", "hwcode_int": mock_b.profile.hwcode,
                       "chip": info.chip, "simulated": True},
        )
        dossier_info = None
        if out_dir:
            dossier_info = dossier.save_device_dossier(
                out_dir=out_dir,
                device_info=info,
                intercept_result=sim_res,
                partitions=parts,
                backend_log=mock_b.log,
            )
        mock_b.close()
        return {
            "ok": True,
            "interception": sim_res.to_dict(),
            "device": info.to_dict(),
            "partitions": [p.to_dict() for p in parts],
            "dossier": dossier_info,
        }

    # Map backend_name filter to target modes
    mode_map: Dict[str, Set[str]] = {
        "mtk": {usbmodes.MODE_MTK_BROM, usbmodes.MODE_MTK_PRELOADER, usbmodes.MODE_MTK_DA},
        "qualcomm": {usbmodes.MODE_QC_EDL},
        "unisoc": {usbmodes.MODE_UNISOC},
        "fastboot": {usbmodes.MODE_FASTBOOT},
    }
    wanted_modes = mode_map.get((backend_name or "").lower(), DOWNLOAD_TARGET_MODES)

    engine = UsbInterceptor(
        target_modes=wanted_modes,
        force_entry=force_entry,
        force_brom=force_brom,
        verbose=verbose,
    )
    res = engine.intercept(timeout=timeout, injected_device=injected_device)
    if not res.ok:
        return {
            "ok": False,
            "error": res.error or "Handshake interception timed out.",
            "interception": res.to_dict(),
            "dossier": None,
        }

    # Build DeviceInfo from the intercepted telemetry + backend identify if possible
    resolved_backend = res.backend or MODE_TO_BACKEND.get(res.mode, "mtk")
    dev_info = DeviceInfo(
        backend=resolved_backend,
        mode=res.mode,
        vendor=usbmodes.mode_info(res.mode).vendor,
        usb_id=res.usb_id,
        serial=str(res.device_details.get("serial") or ""),
    )
    if "hwcode_int" in res.telemetry:
        from ..core import chips

        code = int(res.telemetry["hwcode_int"])
        chip_obj = chips.lookup(code)
        dev_info.hwcode = code
        dev_info.chip = chip_obj.name if chip_obj else str(res.telemetry.get("chip") or f"0x{code:04X}")
        dev_info.chip_confidence = chip_obj.confidence if chip_obj else chips.UNKNOWN
        dev_info.storage = chip_obj.storage if chip_obj else "eMMC"
    dev_info.security = {
        k: res.telemetry[k]
        for k in ("target_config", "sbc_enabled", "sla_enabled", "daa_enabled")
        if k in res.telemetry
    }
    dev_info.extras["interception"] = {
        "capture_latency_ms": round(res.capture_latency_ms, 4),
        "handshake_duration_ms": round(res.handshake_duration_ms, 4),
        "wdt_disabled": res.wdt_disabled,
        "forced_from_mode": res.forced_from_mode,
        "preloader_crashed_to_brom": res.preloader_crashed_to_brom,
    }

    dossier_info = None
    if out_dir:
        dossier_info = dossier.save_device_dossier(
            out_dir=out_dir,
            device_info=dev_info,
            intercept_result=res,
            partitions=[],
        )

    return {
        "ok": True,
        "interception": res.to_dict(),
        "device": dev_info.to_dict(),
        "partitions": [],
        "dossier": dossier_info,
    }
