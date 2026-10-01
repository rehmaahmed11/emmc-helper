"""What mode is this phone in, and what does that mean?

This module is deliberately dependency-free: it works with no libusb installed (it then
reports "cannot enumerate" together with the exact install line) and turns each USB ID into
a human statement: what the device is doing, whether it is a good time to flash, and which
revive backend applies.
"""
from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------------------
# USB identification
# --------------------------------------------------------------------------------------

# mode ids used across the tool
MODE_ADB = "adb"
MODE_FASTBOOT = "fastboot"
MODE_MTK_BROM = "mtk_brom"
MODE_MTK_PRELOADER = "mtk_preloader"
MODE_MTK_DA = "mtk_da"
MODE_QC_EDL = "qc_edl"
MODE_QC_DIAG = "qc_diag"
MODE_UNISOC = "unisoc"
MODE_UNISOC_DIAG = "unisoc_diag"
MODE_ODIN = "odin"
MODE_ROCKCHIP = "rockchip"
MODE_ROCKCHIP_MASKROM = "rockchip_maskrom"
MODE_ALLWINNER_FEL = "allwinner_fel"
MODE_RECOVERY = "recovery"
MODE_UNKNOWN = "unknown"


@dataclass
class UsbMode:
    mode: str
    label: str
    vendor: str
    backend: Optional[str]          # revive backend that handles it
    flashable: bool
    description: str
    advice: List[str] = field(default_factory=list)
    power_hint: str = ""


@dataclass
class UsbId:
    vid: int
    pid: int
    mode: str
    label: str
    notes: str = ""
    confidence: str = "confirmed"


USB_IDS: List[UsbId] = [
    # MediaTek
    UsbId(0x0E8D, 0x0003, MODE_MTK_BROM, "MediaTek Boot ROM (BROM)",
          "The lowest level MediaTek mode: no preloader needed. This is the mode you want for a "
          "hard-bricked phone. Also where the BROM exploit paths live."),
    UsbId(0x0E8D, 0x2000, MODE_MTK_PRELOADER, "MediaTek Preloader (VCOM)",
          "The preloader (SPL) is running from eMMC. Fast path for a phone whose preloader is intact."),
    UsbId(0x0E8D, 0x2001, MODE_MTK_PRELOADER, "MediaTek Preloader (VCOM, alternate)"),
    UsbId(0x0E8D, 0x2008, MODE_MTK_DA, "MediaTek Download Agent mode",
          "A download agent has been loaded and is running.", confidence="reported"),
    UsbId(0x0E8D, 0x201C, MODE_MTK_DA, "MediaTek DA / V6 (XML) mode", confidence="reported"),
    UsbId(0x0E8D, 0x201D, MODE_MTK_DA, "MediaTek DA / V6 (XML) mode", confidence="reported"),

    # Qualcomm
    UsbId(0x05C6, 0x9008, MODE_QC_EDL, "Qualcomm EDL (9008)",
          "Emergency Download mode: the Qualcomm boot ROM is listening for a firehose programmer. "
          "This is the recovery mode for Qualcomm bricks."),
    UsbId(0x05C6, 0x900E, MODE_QC_EDL, "Qualcomm EDL (900E)",
          "EDL variant used by some newer SoCs.", confidence="reported"),
    UsbId(0x05C6, 0x9006, MODE_QC_DIAG, "Qualcomm diagnostic (9006)",
          "Diagnostic port, not EDL. Usually means the phone booted something; try to get to 9008 instead."),
    UsbId(0x05C6, 0x901D, MODE_QC_EDL, "Qualcomm EDL (901D)", confidence="reported"),

    # Unisoc / Spreadtrum
    UsbId(0x1782, 0x4D00, MODE_UNISOC, "Unisoc (Spreadtrum) download mode",
          "Unisoc bootloader download mode (BSL). Used for pac-based flashing."),
    UsbId(0x1782, 0x5D05, MODE_UNISOC_DIAG, "Unisoc diagnostic mode", confidence="reported"),

    # Android normal modes
    UsbId(0x18D1, 0x4EE0, MODE_FASTBOOT, "Android Fastboot",
          "Bootloader/fastboot is running: the boot chain works, so this phone is not hard-bricked."),
    UsbId(0x18D1, 0x4EE7, MODE_ADB, "Android ADB",
          "Android is running with USB debugging on."),
    UsbId(0x18D1, 0xD00D, MODE_FASTBOOT, "Android Fastboot (d00d)"),

    # Samsung
    UsbId(0x04E8, 0x685D, MODE_ODIN, "Samsung Download (Odin) mode",
          "Samsung's own download mode. Handled by Heimdall/Odin style tools, not by the "
          "MediaTek/Qualcomm backends."),

    # Rockchip
    UsbId(0x2207, 0x110A, MODE_ROCKCHIP, "Rockchip Loader (rockusb)"),
    UsbId(0x2207, 0x0006, MODE_ROCKCHIP_MASKROM, "Rockchip MaskROM",
          "Rockchip recovery mode, similar in spirit to MediaTek BROM."),

    # Allwinner
    UsbId(0x1F3A, 0xEFE8, MODE_ALLWINNER_FEL, "Allwinner FEL mode",
          "Allwinner boot ROM recovery mode (used by sunxi-fel style tools)."),
]

_LOOKUP: Dict[Tuple[int, int], UsbId] = {(u.vid, u.pid): u for u in USB_IDS}

MODES: Dict[str, UsbMode] = {
    MODE_MTK_BROM: UsbMode(
        MODE_MTK_BROM, "MediaTek BROM", "MediaTek", "mtk", True,
        "Boot ROM: the SoC's own hard-coded loader. Present only when the phone cannot run its "
        "preloader, or when you force it with test points / key combos.",
        [
            "BROM appears for roughly a second after power-up - start the operation first, then plug in",
            "Secure devices (SBC/SLA/DAA) need a matching DA + auth file, or an exploit path",
            "This is the BEST mode for recovering a dead phone: nothing on the eMMC is required to work",
        ],
        power_hint="Plug in with the phone fully off, holding Volume Up + Volume Down.",
    ),
    MODE_MTK_PRELOADER: UsbMode(
        MODE_MTK_PRELOADER, "MediaTek Preloader", "MediaTek", "mtk", True,
        "The vendor preloader is running, which means the eMMC's preloader area is readable and "
        "the boot chain is not completely gone.",
        [
            "This is the mode SP Flash Tool normally uses",
            "If the preloader is corrupt you will not see this mode - use BROM instead",
        ],
        power_hint="Plug in while the phone is off; do not hold Power.",
    ),
    MODE_MTK_DA: UsbMode(
        MODE_MTK_DA, "MediaTek DA running", "MediaTek", "mtk", True,
        "A download agent is loaded and the device is ready for read/write commands.",
        ["A previous session may still be open - restart the tool if commands behave oddly"],
    ),
    MODE_QC_EDL: UsbMode(
        MODE_QC_EDL, "Qualcomm EDL 9008", "Qualcomm", "qualcomm", True,
        "Qualcomm's emergency download mode: the boot ROM accepts a signed firehose programmer "
        "which can then read/write storage.",
        [
            "You must supply the firehose loader that matches this exact model",
            "For hard bricks on Qualcomm, this is usually the only way in",
            "Do not loop a broken loader: a bad session can leave the device needing a battery pull",
        ],
        power_hint="Plug in with the phone off, or short the EDL test points / use the EDL cable.",
    ),
    MODE_QC_DIAG: UsbMode(
        MODE_QC_DIAG, "Qualcomm diagnostic", "Qualcomm", "qualcomm", False,
        "Diagnostic interface, not the EDL loader interface.",
        ["Not useful for storage repair - reach EDL (9008) instead"],
    ),
    MODE_UNISOC: UsbMode(
        MODE_UNISOC, "Unisoc download", "Unisoc", "unisoc", True,
        "Unisoc/Spreadtrum bootloader download mode (BSL), used for .pac flashing.",
        ["Unisoc flashing uses .pac packages rather than scatter files", "Connect speed is low until the device answers"],
        power_hint="Hold Volume Down while plugging in on most models.",
    ),
    MODE_UNISOC_DIAG: UsbMode(
        MODE_UNISOC_DIAG, "Unisoc diagnostic", "Unisoc", "unisoc", False,
        "Diagnostic port; the download protocol runs on the other interface."),
    MODE_FASTBOOT: UsbMode(
        MODE_FASTBOOT, "Android Fastboot", "Android", "fastboot", True,
        "The bootloader is alive and talking fastboot. Best case: partitions can be flashed "
        "normally, and there is usually no need for BROM/EDL tools at all.",
        [
            "`fastboot devices` should list it",
            "Use fastboot flashing/unlock commands; keep BROM as a fallback only",
        ],
    ),
    MODE_ADB: UsbMode(
        MODE_ADB, "Android ADB", "Android", None, False,
        "Android booted normally. This is where you take an adb backup and read build info "
        "before doing anything risky.",
        ["Back up first: `revive backup-adb --out <folder>` (uses adb if installed)",
         "Read the exact model/build so you download the right firmware next time"],
    ),
    MODE_ODIN: UsbMode(
        MODE_ODIN, "Samsung Download (Odin)", "Samsung", None, True,
        "Samsung's download mode. On Snapdragon models this is the normal recovery path; on "
        "Exynos models, Odin/Heimdall is the tool.",
        ["Not a MediaTek/Qualcomm EDL device: use Odin/Heimdall for flashing"], ),
    MODE_ROCKCHIP: UsbMode(
        MODE_ROCKCHIP, "Rockchip Loader", "Rockchip", None, True,
        "Rockchip loader mode, flashable with rkdeveloptool/uphgrade style tools."),
    MODE_ROCKCHIP_MASKROM: UsbMode(
        MODE_ROCKCHIP_MASKROM, "Rockchip MaskROM", "Rockchip", None, True,
        "Rockchip's lowest-level mode: the equivalent of MediaTek BROM."),
    MODE_ALLWINNER_FEL: UsbMode(
        MODE_ALLWINNER_FEL, "Allwinner FEL", "Allwinner", None, True,
        "Allwinner boot ROM mode, used by sunxi-fel style tools for tablet/TV-box recovery."),
    MODE_RECOVERY: UsbMode(
        MODE_RECOVERY, "Android recovery", "Android", None, False,
        "Recovery is running (usually ADB-only). Good for sideloading updates.",
        ["adb sideload needs a signed OTA zip matching the device"]),
    MODE_UNKNOWN: UsbMode(
        MODE_UNKNOWN, "Unknown", "?", None, False,
        "A USB device is connected but we cannot map it to a known download mode."),
}


def match(vid: int, pid: int) -> Optional[UsbId]:
    return _LOOKUP.get((int(vid), int(pid)))


def mode_info(mode: str) -> UsbMode:
    return MODES.get(mode, MODES[MODE_UNKNOWN])


def backend_for_mode(mode: str) -> Optional[str]:
    return mode_info(mode).backend


def classify(vid: int, pid: int) -> Tuple[str, str]:
    hit = match(vid, pid)
    if hit:
        return hit.mode, hit.label
    return MODE_UNKNOWN, f"Unknown USB device {vid:04x}:{pid:04x}"


# --------------------------------------------------------------------------------------
# Enumeration
# --------------------------------------------------------------------------------------

def libusb_available() -> bool:
    try:
        import usb.core  # noqa: F401

        return True
    except Exception:
        return False


def pyserial_available() -> bool:
    try:
        import serial  # noqa: F401

        return True
    except Exception:
        return False


def install_hint() -> str:
    return f"{sys.executable} -m pip install pyusb pyserial"


@dataclass
class UsbDevice:
    vid: int
    pid: int
    bus: Optional[int] = None
    address: Optional[int] = None
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    mode: str = MODE_UNKNOWN
    label: str = ""
    backend: Optional[str] = None
    flashable: bool = False

    def id_string(self) -> str:
        return f"{self.vid:04x}:{self.pid:04x}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vid": f"{self.vid:04x}",
            "pid": f"{self.pid:04x}",
            "id": self.id_string(),
            "bus": self.bus,
            "address": self.address,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "serial": self.serial,
            "mode": self.mode,
            "label": self.label,
            "backend": self.backend,
            "flashable": self.flashable,
        }


def enumerate_devices(include_unknown: bool = True) -> Tuple[List[UsbDevice], List[str]]:
    """Returns (devices, warnings). Never raises: missing libusb is a warning, not a crash."""
    warnings: List[str] = []
    devices: List[UsbDevice] = []
    if not libusb_available():
        warnings.append(
            "pyusb/libusb is not installed, so USB enumeration is unavailable. "
            f"Install it with: {install_hint()}"
        )
        return devices, warnings

    import usb.core
    import usb.util

    try:
        found = list(usb.core.find(find_all=True))
    except Exception as exc:  # pragma: no cover - depends on host
        warnings.append(f"libusb could not enumerate USB devices: {exc}")
        return devices, warnings

    for dev in found:
        vid, pid = int(dev.idVendor), int(dev.idProduct)
        hit = match(vid, pid)
        if not hit and not include_unknown:
            continue
        mode, label = classify(vid, pid)
        manufacturer = product = serial = ""
        try:
            manufacturer = usb.util.get_string(dev, dev.iManufacturer) or ""
            product = usb.util.get_string(dev, dev.iProduct) or ""
            serial = usb.util.get_string(dev, dev.iSerialNumber) or ""
        except Exception:
            pass
        info = mode_info(mode)
        devices.append(UsbDevice(
            vid, pid,
            bus=getattr(dev, "bus", None), address=getattr(dev, "address", None),
            manufacturer=manufacturer, product=product, serial=serial,
            mode=mode, label=hit.label if hit else label,
            backend=info.backend, flashable=info.flashable,
        ))

    order = {MODE_MTK_BROM: 0, MODE_MTK_PRELOADER: 1, MODE_QC_EDL: 2, MODE_MTK_DA: 3,
             MODE_UNISOC: 4, MODE_ROCKCHIP_MASKROM: 5, MODE_FASTBOOT: 6, MODE_ODIN: 7,
             MODE_ROCKCHIP: 8, MODE_ALLWINNER_FEL: 9, MODE_ADB: 10, MODE_UNKNOWN: 99}
    devices.sort(key=lambda d: (order.get(d.mode, 50), d.vid, d.pid))
    return devices, warnings


def serial_ports() -> List[Dict[str, str]]:
    """MediaTek VCOM and Unisoc devices often show up as COM ports on Windows."""
    out: List[Dict[str, str]] = []
    if not pyserial_available():
        return out
    try:
        from serial.tools import list_ports

        for p in list_ports.comports():
            out.append({
                "port": p.device,
                "description": p.description or "",
                "hwid": p.hwid or "",
                "vid_pid": f"{p.vid:04x}:{p.pid:04x}" if p.vid and p.pid else "",
                "likely": "MTK VCOM" if (p.description or "").lower().find("mediatek") >= 0
                else ("Unisoc" if "sprd" in (p.description or "").lower() else ""),
            })
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------------------
# Driver guidance
# --------------------------------------------------------------------------------------

def current_os() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s.startswith("darwin"):
        return "macos"
    return "linux"


def driver_help() -> Dict[str, Any]:
    """OS-specific driver instructions, including a ready-to-install udev rule for Linux."""
    osname = current_os()
    info: Dict[str, Any] = {
        "os": osname,
        "python": sys.version.split()[0],
        "libusb": libusb_available(),
        "pyserial": pyserial_available(),
        "install": install_hint(),
    }

    if osname == "windows":
        info["summary"] = (
            "Windows needs a driver matched to the download mode. This is the single most common "
            "reason a flashing tool sees nothing."
        )
        info["steps"] = [
            "MediaTek: install the MediaTek USB VCOM driver (the one that ships inside SP Flash "
            "Tool packages). Device Manager should then show 'MediaTek USB Port' or 'MediaTek PreLoader'.",
            "Qualcomm EDL: install the Qualcomm HS-USB QDLoader 9008 driver. The device should appear "
            "as 'Qualcomm HS-USB QDLoader 9008 (COMxx)'.",
            "If the device shows with a yellow '!': right-click -> Update driver -> Browse -> Let me "
            "pick from a list -> Have Disk -> point at the .inf file.",
            "Unsigned .inf rejected? Reboot with Shift held -> Troubleshoot -> Advanced -> Startup "
            "Settings -> Restart -> press 7 to disable driver signature enforcement, then reinstall.",
            "Still nothing: try a rear USB 2.0 port (USB 3 controllers and hubs drop BROM devices "
            "far more often), and remove 'Unknown Device' entries from Device Manager.",
        ]
        info["where_to_get"] = [
            "MediaTek VCOM: ships inside official SP Flash Tool archives (Driver folder).",
            "Qualcomm QDLoader: ships with Qualcomm-based stock firmware packages and repair tools.",
            "Both are also mirrored by the community; keep a local copy in your repair folder - "
            "drivers downloaded automatically by Windows Update are usually the wrong ones.",
        ]
    elif osname == "linux":
        info["summary"] = "Linux needs module access + udev rules; no vendor drivers are necessary."
        info["steps"] = [
            "Install the runtime: sudo apt install libusb-1.0-0 python3-usb  (or your distro's equivalent)",
            "Install python extras: " + install_hint(),
            "Install the udev rule below so you do not need root for every operation",
            "reload: sudo udevadm control --reload-rules && sudo udevadm trigger",
            "Replug the phone, then verify with `revive detect`",
            "If the device keeps resetting, unload the modem manager: sudo systemctl stop ModemManager",
            "Blacklist the kernel driver if it grabs the device: echo 'blacklist mtk_usb' > /etc/modprobe.d/blacklist-mtk.conf",
        ]
        info["udev_rule_path"] = "/etc/udev/rules.d/99-revive-mtk-qualcomm.rules"
        info["udev_rules"] = udev_rules_text()
    elif osname == "macos":
        info["summary"] = "macOS needs no vendor drivers; you only need libusb."
        info["steps"] = [
            "brew install libusb",
            "Install python extras: " + install_hint(),
            "Approve USB access if macOS prompts (System Settings -> Privacy & Security)",
            "Apple-silicon Macs: use a powered USB-A adapter or a known-good hub for BROM devices",
        ]
    else:  # pragma: no cover
        info["summary"] = "Unknown OS; use libusb 1.x and run `revive detect` to check visibility."
        info["steps"] = [f"Install python extras: {install_hint()}"]

    info["universal_tips"] = [
        "Charge the phone before any write operation: a brown-out mid-flash turns a repairable "
        "phone into a dead one.",
        "Data cable, not charge cable. If it has never transferred a file, it cannot flash a phone.",
        "Rear USB 2.0 ports are the most reliable for BROM/EDL; front panels and hubs are the worst.",
        "Only one tool may hold the port: close SP Flash Tool, other flashers, serial monitors, adb.",
        "Keep a full backup of a working device before you change anything.",
    ]
    return info


def udev_rules_text() -> str:
    vids = sorted({u.vid for u in USB_IDS})
    lines = [
        "# Revive - allow user access to phone download-mode USB devices",
        "# install: sudo cp this-file /etc/udev/rules.d/99-revive-mtk-qualcomm.rules",
        "#          sudo udevadm control --reload-rules && sudo udevadm trigger",
        "",
        'SUBSYSTEM!="usb", GOTO="revive_end"',
        "ACTION!=\"add\", GOTO=\"revive_end\"",
        "",
    ]
    names = {
        0x0E8D: "MediaTek (BROM/Preloader/DA)",
        0x05C6: "Qualcomm (EDL/diag)",
        0x1782: "Unisoc / Spreadtrum",
        0x2207: "Rockchip",
        0x1F3A: "Allwinner",
        0x18D1: "Google / Android (fastboot, adb)",
        0x04E8: "Samsung (download mode)",
    }
    for vid in vids:
        lines.append(f"# {names.get(vid, 'unknown vendor')}")
        lines.append(
            f'ATTR{{idVendor}}=="{vid:04x}", MODE="0666", GROUP="plugdev", '
            f'TAG+="uaccess", TAG+="udev-acl", SYMLINK+="revive/%k"'
        )
    lines += ["", 'LABEL="revive_end"', ""]
    return "\n".join(lines)
