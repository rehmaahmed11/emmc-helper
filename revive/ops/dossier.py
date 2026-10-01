"""Device Handshake & Recovery Dossier Folder Builder.

Whenever Revive intercepts, handshakes, or identifies a connected phone (in BROM, Preloader,
EDL 9008, Unisoc BSL, Fastboot, or simulated mode), this module creates a structured workspace
folder containing every artifact a repair technician needs for that device:

    <root_dir>/
      index.json                             # Master registry of all connected/handshaked devices
      SUMMARY.txt                            # Human-readable table of all captured sessions
      <timestamp>_<mode>_<chip>_<usb_id>/
        device_details.json                  # Full USB, mode, chip, storage & environment identity
        handshake_log.json                   # Nanosecond interception timeline, sync bytes, WDT state
        handshake_trace.txt                  # Human-readable packet & stage trace
        security_and_chip.json               # SBC/SLA/DAA flags, target_config, Sahara HW_ID/PK_HASH
        MTXXXX_Android_scatter.txt           # Auto-generated SP Flash Tool scatter for this chip/layout
        rawprogram0.xml                      # Auto-generated Qualcomm Firehose rawprogram XML layout
        patch0.xml                           # Companion Qualcomm GPT patch template
        partitions_and_backup_plan.json      # Partition map + priority NVRAM/calibration backup plan
        udev_and_driver_info.txt             # OS driver guide + Linux udev rules for this VID:PID
        recovery_checklist.txt               # Tailored step-by-step repair & flashing instructions
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .. import util
from ..backends.base import DeviceInfo, Partition
from ..backends.interceptor import InterceptResult, wdt_base_for_hwcode
from ..core import chips, usbmodes
from ..firmware import scatter as scatter_mod

DEFAULT_DOSSIER_DIR = "revive_handshakes"

# Standard partition template when a device is caught in BROM/Preloader/EDL before GPT is read.
# Aligned to 0x20000 (128 KiB) so it passes scatter.validate() cleanly.
STANDARD_MTK_LAYOUT: List[Dict[str, Any]] = [
    {"name": "preloader", "file": "preloader.bin", "download": True, "type": "SV5_BL_BIN",
     "start": 0x0, "size": 0x40000, "region": "EMMC_BOOT_1", "op": "BOOTLOADERS"},
    {"name": "pgpt", "file": "pgpt.bin", "download": False, "type": "NORMAL_ROM",
     "start": 0x0, "size": 0x80000, "region": "EMMC_USER", "op": "PGPT"},
    {"name": "nvram", "file": "nvram.bin", "download": False, "type": "NORMAL_ROM",
     "start": 0x80000, "size": 0x4000000, "region": "EMMC_USER", "op": "BINREGION"},
    {"name": "nvdata", "file": "nvdata.img", "download": False, "type": "EXT4_IMG",
     "start": 0x4080000, "size": 0x4000000, "region": "EMMC_USER", "op": "PROTECTED"},
    {"name": "persist", "file": "persist.img", "download": False, "type": "EXT4_IMG",
     "start": 0x8080000, "size": 0x3000000, "region": "EMMC_USER", "op": "PROTECTED"},
    {"name": "protect1", "file": "protect1.img", "download": False, "type": "EXT4_IMG",
     "start": 0xB080000, "size": 0x800000, "region": "EMMC_USER", "op": "PROTECTED"},
    {"name": "protect2", "file": "protect2.img", "download": False, "type": "EXT4_IMG",
     "start": 0xB880000, "size": 0x800000, "region": "EMMC_USER", "op": "PROTECTED"},
    {"name": "proinfo", "file": "proinfo.bin", "download": False, "type": "NORMAL_ROM",
     "start": 0xC080000, "size": 0x300000, "region": "EMMC_USER", "op": "PROTECTED"},
    {"name": "seccfg", "file": "seccfg.bin", "download": False, "type": "NORMAL_ROM",
     "start": 0xC380000, "size": 0x80000, "region": "EMMC_USER", "op": "NORMAL"},
    {"name": "lk", "file": "lk.img", "download": True, "type": "NORMAL_ROM",
     "start": 0xC400000, "size": 0x400000, "region": "EMMC_USER", "op": "UPDATE"},
    {"name": "boot", "file": "boot.img", "download": True, "type": "NORMAL_ROM",
     "start": 0xC800000, "size": 0x4000000, "region": "EMMC_USER", "op": "UPDATE"},
    {"name": "vbmeta", "file": "vbmeta.img", "download": True, "type": "NORMAL_ROM",
     "start": 0x10800000, "size": 0x800000, "region": "EMMC_USER", "op": "UPDATE"},
    {"name": "dtbo", "file": "dtbo.img", "download": True, "type": "NORMAL_ROM",
     "start": 0x11000000, "size": 0x800000, "region": "EMMC_USER", "op": "UPDATE"},
    {"name": "tee1", "file": "tee.img", "download": True, "type": "NORMAL_ROM",
     "start": 0x11800000, "size": 0x800000, "region": "EMMC_USER", "op": "UPDATE"},
    {"name": "md1img", "file": "md1img.img", "download": True, "type": "NORMAL_ROM",
     "start": 0x12000000, "size": 0x8000000, "region": "EMMC_USER", "op": "UPDATE"},
    {"name": "super", "file": "super.img", "download": True, "type": "EXT4_IMG",
     "start": 0x1A000000, "size": 0x100000000, "region": "EMMC_USER", "op": "UPDATE"},
    {"name": "userdata", "file": "userdata.img", "download": True, "type": "EXT4_IMG",
     "start": 0x11A000000, "size": 0x100000000, "region": "EMMC_USER", "op": "UPDATE"},
]


def _platform_code(device_info: Optional[DeviceInfo],
                   intercept_res: Optional[InterceptResult]) -> str:
    """Resolve a clean platform token like 'MT6768', 'MT6765', 'SM6115', or 'MT0000'."""
    hwcode = None
    chip_text = ""
    if device_info:
        hwcode = device_info.hwcode
        chip_text = device_info.chip or ""
    if not hwcode and intercept_res:
        hwcode = intercept_res.telemetry.get("hwcode_int")
        chip_text = chip_text or str(intercept_res.telemetry.get("chip") or "")

    import re

    m = re.search(r"\b(MT\d{4}[A-Z]?|SM\d{4}|SDM\d{3}|MSM\d{4}|SC\d{4}[A-Z]?|T\d{3})\b",
                  chip_text.upper())
    if m:
        return m.group(1)
    if hwcode:
        chip_obj = chips.lookup(hwcode)
        if chip_obj and chip_obj.family:
            return util.safe_filename(chip_obj.family.split()[0].upper(), "MT0000")
        return f"MT{int(hwcode):04X}"
    return "MT6768"


def generate_scatter_text(platform_name: str,
                          storage_kind: str = "EMMC",
                          partitions: Optional[Sequence[Partition]] = None,
                          project: str = "revive_captured_device") -> str:
    """Generate a complete, valid MediaTek scatter file for the captured device."""
    storage_upper = "UFS" if "ufs" in (storage_kind or "").lower() else "EMMC"
    hw_storage = "HW_STORAGE_UFS" if storage_upper == "UFS" else "HW_STORAGE_EMMC"
    user_region = "UFS_LU2" if storage_upper == "UFS" else "EMMC_USER"
    boot_region = "UFS_LU0" if storage_upper == "UFS" else "EMMC_BOOT_1"
    block_size = 0x20000

    lines: List[str] = [
        "############################################################################################################",
        "#",
        f"#  General Setting - Auto-generated by Revive for {platform_name}",
        "#",
        "############################################################################################################",
        "- general: MTK_PLATFORM_CFG",
        "  info:",
        "    - config_version: V1.1.2",
        f"      platform: {platform_name}",
        f"      project: {project}",
        f"      storage: {storage_upper}",
        "      boot_channel: MSDC_0",
        f"      block_size: 0x{block_size:x}",
        "############################################################################################################",
        "#",
        "#  Layout Setting",
        "#",
        "############################################################################################################",
    ]

    entries: List[Dict[str, Any]] = []
    if partitions:
        # Always include preloader in BOOT_1 if not explicitly in the GPT user list
        has_pl = any(p.name.lower() == "preloader" for p in partitions)
        if not has_pl:
            entries.append({
                "name": "preloader", "file": "preloader.bin", "download": True,
                "type": "SV5_BL_BIN", "start": 0x0, "size": 0x40000,
                "region": boot_region, "op": "BOOTLOADERS",
            })
        for part in partitions:
            pname = part.name
            low = pname.lower()
            is_prot = low in scatter_mod.PROTECTED_PARTITIONS
            is_pl = low == "preloader"
            aligned_start = util.align_up(max(0, int(part.offset)), block_size) if not is_pl else 0
            aligned_size = max(block_size, util.align_up(max(block_size, int(part.size)), block_size))
            entries.append({
                "name": pname,
                "file": f"{pname}.bin" if is_pl or low in ("nvram", "proinfo") else f"{pname}.img",
                "download": not is_prot,
                "type": "SV5_BL_BIN" if is_pl else ("EXT4_IMG" if low in ("system", "system_a", "userdata", "super", "vendor", "nvdata", "persist") else "NORMAL_ROM"),
                "start": aligned_start,
                "size": aligned_size,
                "region": boot_region if is_pl else user_region,
                "op": "BOOTLOADERS" if is_pl else ("PROTECTED" if is_prot else "UPDATE"),
            })
    else:
        for item in STANDARD_MTK_LAYOUT:
            copy_item = dict(item)
            if copy_item["region"] == "EMMC_BOOT_1":
                copy_item["region"] = boot_region
            else:
                copy_item["region"] = user_region
            entries.append(copy_item)

    # Ensure monotonically non-overlapping addresses per region
    cursor_by_region: Dict[str, int] = {}
    for idx, entry in enumerate(entries):
        reg = entry["region"]
        start = int(entry["start"])
        if reg in cursor_by_region and start < cursor_by_region[reg]:
            start = util.align_up(cursor_by_region[reg], block_size)
        size = max(block_size, util.align_up(int(entry["size"]), block_size))
        cursor_by_region[reg] = start + size
        dl_str = "true" if entry["download"] else "false"
        fname = entry["file"] if entry["download"] else "NONE"
        lines.extend([
            f"- partition_index: SYS{idx}",
            f"  partition_name: {entry['name']}",
            f"  file_name: {fname}",
            f"  is_download: {dl_str}",
            f"  type: {entry['type']}",
            f"  linear_start_addr: 0x{start:x}",
            f"  physical_start_addr: 0x{start:x}",
            f"  partition_size: 0x{size:x}",
            f"  region: {reg}",
            f"  storage: {hw_storage}",
            "  boundary_check: true",
            "  is_reserved: false",
            f"  operation_type: {entry['op']}",
            "  reserve: 0x00",
            "",
        ])
    return "\n".join(lines)


def generate_rawprogram_xml(storage_kind: str = "eMMC",
                            partitions: Optional[Sequence[Partition]] = None) -> Tuple[str, str]:
    """Generate Qualcomm `rawprogram0.xml` and `patch0.xml` templates for the captured device."""
    sector_size = 4096 if "ufs" in (storage_kind or "").lower() else 512
    lines = [
        '<?xml version="1.0" ?>',
        "<data>",
        f"  <!-- Auto-generated by Revive for {storage_kind or 'eMMC'} (sector_size={sector_size}) -->",
    ]
    if partitions:
        cursor_sector = 34
        for p in partitions:
            start_sec = max(cursor_sector, int(p.offset) // sector_size) if p.offset else cursor_sector
            num_sec = max(64, int(p.size) // sector_size) if p.size else 2048
            cursor_sector = start_sec + num_sec
            low = p.name.lower()
            is_prot = low in scatter_mod.PROTECTED_PARTITIONS or low in ("modemst1", "modemst2", "fsg", "fsc")
            fname = "" if is_prot else f"{p.name}.img"
            lines.append(
                f'  <program SECTOR_SIZE_IN_BYTES="{sector_size}" file_sector_offset="0" '
                f'filename="{fname}" label="{p.name}" num_partition_sectors="{num_sec}" '
                f'partofsingleimage="false" physical_partition_number="0" '
                f'readbackverify="false" sparse="false" start_sector="{start_sec}" />'
            )
    else:
        default_qc = [
            ("sbl1", "sbl1.mbn", 34, 1024),
            ("rpm", "rpm.mbn", 1058, 1024),
            ("tz", "tz.mbn", 2082, 4096),
            ("devcfg", "devcfg.mbn", 6178, 512),
            ("aboot", "emmc_appsboot.mbn", 6690, 2048),
            ("boot", "boot.img", 8738, 131072),
            ("vbmeta", "vbmeta.img", 139810, 128),
            ("dtbo", "dtbo.img", 139938, 16384),
            ("modemst1", "", 156322, 4096),
            ("modemst2", "", 160418, 4096),
            ("fsg", "", 164514, 4096),
            ("persist", "", 168610, 65536),
            ("super", "super.img", 234146, 4194304),
            ("userdata", "userdata.img", 4428450, 4194304),
        ]
        for label, fname, start_sec, num_sec in default_qc:
            lines.append(
                f'  <program SECTOR_SIZE_IN_BYTES="{sector_size}" file_sector_offset="0" '
                f'filename="{fname}" label="{label}" num_partition_sectors="{num_sec}" '
                f'partofsingleimage="false" physical_partition_number="0" '
                f'readbackverify="false" sparse="false" start_sector="{start_sec}" />'
            )
    lines.append("</data>\n")

    patch_xml = (
        '<?xml version="1.0" ?>\n'
        "<patches>\n"
        f'  <patch SECTOR_SIZE_IN_BYTES="{sector_size}" byte_offset="48" '
        'filename="DISK" physical_partition_number="0" size_in_bytes="8" '
        'start_sector="1" value="NUM_DISK_SECTORS-34." '
        'what="Update Primary Header with LastUseableLBA." />\n'
        "</patches>\n"
    )
    return "\n".join(lines), patch_xml


def _format_handshake_trace(intercept_res: Optional[InterceptResult],
                            backend_log: Optional[Sequence[str]] = None) -> str:
    lines = [
        "==============================================================================",
        "  Revive - Captured USB Handshake & Interception Trace",
        "==============================================================================",
        "",
    ]
    if intercept_res:
        lines.extend([
            f"Status              : {'LOCKED' if intercept_res.ok else 'INCOMPLETE / TIMEOUT'}",
            f"USB ID              : {intercept_res.usb_id or 'n/a'}",
            f"Mode                : {intercept_res.mode or 'n/a'}",
            f"Backend             : {intercept_res.backend or 'n/a'}",
            f"Capture Latency     : {intercept_res.capture_latency_ms:.4f} ms ({intercept_res.poll_iterations} poll cycles)",
            f"Handshake Duration  : {intercept_res.handshake_duration_ms:.4f} ms",
            f"WDT Disabled        : {intercept_res.wdt_disabled}"
            + (f" (at 0x{intercept_res.wdt_address:08X})" if intercept_res.wdt_address else ""),
            f"Forced From Mode    : {intercept_res.forced_from_mode or 'direct catch'}",
            f"Preloader -> BROM   : crash payload sent={intercept_res.preloader_crashed_to_brom}, "
            f"BROM re-captured={intercept_res.brom_recaptured}",
            "",
        ])
        if intercept_res.sync_bytes:
            lines.append("MediaTek 4-Byte Inverse Sync Sequence:")
            for idx, item in enumerate(intercept_res.sync_bytes):
                lines.append(
                    f"  Byte #{idx}: TX {item.get('tx')} -> RX {item.get('rx')} "
                    f"(expected {item.get('expected')})"
                )
            lines.append("")
        if intercept_res.escalation_actions:
            lines.append("Force-Entry / Escalation Actions Executed:")
            for act in intercept_res.escalation_actions:
                lines.append(f"  * {act}")
            lines.append("")
        if intercept_res.usb_bounces:
            lines.append("Kernel USB Enumeration Bounces Detected:")
            for b in intercept_res.usb_bounces:
                lines.append(f"  ! [{b.get('kind')}] port={b.get('port')} err={b.get('error')} | {b.get('raw')}")
            lines.append("")
        lines.append("Nanosecond Event Timeline:")
        lines.append("-" * 78)
        for ev in intercept_res.events:
            io_str = ""
            if ev.tx_hex:
                io_str += f" TX={ev.tx_hex[:48]}"
            if ev.rx_hex:
                io_str += f" RX={ev.rx_hex[:48]}"
            lines.append(f"  +{ev.elapsed_ms:9.4f} ms  [{ev.stage:<20}] {ev.detail}{io_str}")
        lines.append("")

    if backend_log:
        lines.append("Backend Session Log:")
        lines.append("-" * 78)
        for line in backend_log:
            lines.append(f"  {line}")
        lines.append("")
    return "\n".join(lines)


def _force_entry_summary(intercept_res: Optional[InterceptResult]) -> str:
    """One line that never confuses 'crash payload sent' with 'BROM actually captured'."""
    if intercept_res is None:
        return "not recorded"
    if intercept_res.brom_recaptured:
        return "Preloader crash sent and BROM (0e8d:0003) re-captured + handshaken"
    if intercept_res.preloader_crashed_to_brom:
        return ("Preloader crash sent, but BROM did NOT re-appear - retry while holding "
                "Volume Up + Volume Down, or power-cycle first")
    if intercept_res.forced_from_mode:
        return f"escalated from {intercept_res.forced_from_mode} (no direct catch)"
    return "not requested / direct catch"


def _format_recovery_checklist(platform_name: str,
                               device_info: Optional[DeviceInfo],
                               intercept_res: Optional[InterceptResult],
                               scatter_filename: str,
                               folder_path: Path) -> str:
    mode = (device_info.mode if device_info else "") or (intercept_res.mode if intercept_res else "") or "unknown"
    sec = (device_info.security if device_info else {}) or (intercept_res.telemetry if intercept_res else {})
    sbc = bool(sec.get("secure_boot") or sec.get("sbc_enabled"))
    sla = bool(sec.get("sla") or sec.get("sla_enabled"))
    daa = bool(sec.get("daa") or sec.get("daa_enabled"))
    wdt_base = wdt_base_for_hwcode(device_info.hwcode if device_info else intercept_res.telemetry.get("hwcode_int") if intercept_res else None)

    lines = [
        "==============================================================================",
        f"  Revive Recovery & Flashing Checklist for {platform_name} ({mode})",
        "==============================================================================",
        "",
        f"Dossier Folder : {folder_path}",
        f"Detected Chip  : {device_info.chip if device_info and device_info.chip else platform_name}",
        f"Detected Mode  : {mode}",
        f"Watchdog Base  : 0x{wdt_base:08X} (WDT freeze {'ACTIVE' if (intercept_res and intercept_res.wdt_disabled) else 'ready'})",
        f"Security Flags : SBC={sbc}, SLA={sla}, DAA={daa}",
        f"Force Entry    : {_force_entry_summary(intercept_res)}",
        "",
        "1. PRIORITY BACKUP (BEFORE WRITING ANYTHING)",
        "   Always back up this specific phone's radio/identity calibration partitions first:",
        "   - MediaTek : nvram, nvdata, persist, protect1, protect2, proinfo, seccfg",
        "   - Qualcomm : modemst1, modemst2, fsg, fsc, persist, sec",
        "",
        "2. GENERATED SCATTER & XML FILES IN THIS FOLDER",
        f"   - MediaTek Scatter : {scatter_filename}",
        "   - Qualcomm XML     : rawprogram0.xml + patch0.xml",
        "   Validate any firmware package against this device before flashing:",
        "     revive inspect <firmware_folder>",
        "     revive plan <firmware_folder>",
        "",
        "3. SECURITY & AUTH REQUIREMENTS",
    ]
    if sbc or sla or daa:
        lines.extend([
            "   [!] SECURE BOOT IS ENABLED (SBC/SLA/DAA):",
            "       - If captured in Preloader (0e8d:2000), re-run with `--force-brom` so Revive",
            "         crashes Preloader into BROM (0e8d:0003) where BROM-level recovery operates.",
            "       - Pair the Download Agent (DA) with the vendor auth file from stock firmware.",
        ])
    else:
        lines.extend([
            "   [OK] No SLA/DAA lock flags reported. Standard matched DA or Firehose programmer",
            "        for this chip can be loaded directly.",
        ])

    lines.extend([
        "",
        "4. IF THE PHONE DOES NOT HANDSHAKE ON NEXT PLUG-IN (BATTERY ATTACHED OR DETACHED)",
        "   - Run: `revive intercept --force --force-brom --out " + str(folder_path.parent) + "`",
        "   - Keep the cable plugged in and hold Power + Vol Up + Vol Down for 8-12 seconds.",
        "   - The PMIC will hard-reset the SoC and Revive's sub-ms spin-interceptor will",
        "     catch the 0xA0/Sahara window and disable the hardware watchdog before the battery",
        "     can boot the charging logo.",
        "",
    ])
    return "\n".join(lines)


def save_device_dossier(
    out_dir: os.PathLike = DEFAULT_DOSSIER_DIR,
    device_info: Optional[DeviceInfo] = None,
    intercept_result: Optional[InterceptResult] = None,
    partitions: Optional[Sequence[Partition]] = None,
    backend_log: Optional[Sequence[str]] = None,
    extra_devices: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Create a complete per-device handshake & scatter folder and update the master index."""
    root = util.ensure_dir(Path(out_dir).expanduser())
    stamp = time.strftime("%Y%m%d_%H%M%S")
    platform_name = _platform_code(device_info, intercept_result)

    mode = (
        (device_info.mode if device_info and device_info.mode else "")
        or (intercept_result.mode if intercept_result and intercept_result.mode else "")
        or "device"
    )
    usb_id = (
        (device_info.usb_id if device_info and device_info.usb_id else "")
        or (intercept_result.usb_id if intercept_result and intercept_result.usb_id else "")
        or "0000:0000"
    )
    serial = (
        (device_info.serial if device_info and device_info.serial else "")
        or (intercept_result.device_details.get("serial", "") if intercept_result else "")
        or ""
    )
    storage_kind = (device_info.storage if device_info and device_info.storage else "eMMC")

    folder_slug = util.safe_filename(
        f"{stamp}_{mode}_{platform_name}_{usb_id.replace(':', '-')}"
        + (f"_{serial[:12]}" if serial else "")
    )
    device_dir = util.unique_path(root / folder_slug)
    util.ensure_dir(device_dir)

    # 1) Generate MediaTek scatter file (MTXXXX_Android_scatter.txt)
    scatter_filename = f"{platform_name}_Android_scatter.txt"
    scatter_path = device_dir / scatter_filename
    scatter_text = generate_scatter_text(
        platform_name=platform_name,
        storage_kind=storage_kind,
        partitions=partitions,
    )
    util.atomic_write(scatter_path, scatter_text.encode("utf-8"))

    # 2) Generate Qualcomm rawprogram0.xml + patch0.xml
    rawprogram_text, patch_text = generate_rawprogram_xml(
        storage_kind=storage_kind,
        partitions=partitions,
    )
    rawprogram_path = device_dir / "rawprogram0.xml"
    patch_path = device_dir / "patch0.xml"
    util.atomic_write(rawprogram_path, rawprogram_text.encode("utf-8"))
    util.atomic_write(patch_path, patch_text.encode("utf-8"))

    # 3) Write device_details.json
    hwcode_int = (
        (device_info.hwcode if device_info and device_info.hwcode is not None else None)
        or (intercept_result.telemetry.get("hwcode_int") if intercept_result else None)
    )
    chip_entry = chips.lookup(hwcode_int) if hwcode_int is not None else None
    details_payload: Dict[str, Any] = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "folder": str(device_dir),
        "platform": platform_name,
        "usb_id": usb_id,
        "mode": mode,
        "device_info": device_info.to_dict() if device_info else {},
        "chip_table_entry": chip_entry.to_dict() if chip_entry else None,
        "usb_descriptor": intercept_result.device_details if intercept_result else {},
        "connected_devices_snapshot": list(extra_devices or []),
        "files_generated": {
            "scatter": scatter_filename,
            "rawprogram": "rawprogram0.xml",
            "patch": "patch0.xml",
            "handshake_log": "handshake_log.json",
            "handshake_trace": "handshake_trace.txt",
            "security_and_chip": "security_and_chip.json",
            "partitions_and_backup_plan": "partitions_and_backup_plan.json",
            "udev_and_driver_info": "udev_and_driver_info.txt",
            "recovery_checklist": "recovery_checklist.txt",
        },
    }
    util.atomic_write(
        device_dir / "device_details.json",
        json.dumps(details_payload, indent=2, default=str).encode("utf-8"),
    )

    # 4) Write handshake_log.json and handshake_trace.txt
    handshake_payload = intercept_result.to_dict() if intercept_result else {
        "ok": True,
        "mode": mode,
        "usb_id": usb_id,
        "note": "captured via direct backend identify/detect",
        "log": list(backend_log or []),
    }
    util.atomic_write(
        device_dir / "handshake_log.json",
        json.dumps(handshake_payload, indent=2, default=str).encode("utf-8"),
    )
    trace_text = _format_handshake_trace(intercept_result, backend_log)
    util.atomic_write(device_dir / "handshake_trace.txt", trace_text.encode("utf-8"))

    # 5) Write security_and_chip.json
    security_payload: Dict[str, Any] = {
        "platform": platform_name,
        "hwcode": f"0x{int(hwcode_int):04X}" if hwcode_int is not None else None,
        "chip": (device_info.chip if device_info else "") or (chip_entry.name if chip_entry else platform_name),
        "da_mode": chip_entry.da_mode_name if chip_entry else "unknown",
        "wdt_register_base": f"0x{wdt_base_for_hwcode(hwcode_int):08X}",
        "wdt_disabled": bool(intercept_result and intercept_result.wdt_disabled),
        "security_flags": (device_info.security if device_info else {}),
        "interceptor_telemetry": (intercept_result.telemetry if intercept_result else {}),
    }
    util.atomic_write(
        device_dir / "security_and_chip.json",
        json.dumps(security_payload, indent=2, default=str).encode("utf-8"),
    )

    # 6) Write partitions_and_backup_plan.json
    part_dicts = [p.to_dict() for p in (partitions or [])]
    backup_first = [
        "nvram", "nvdata", "persist", "protect1", "protect2", "proinfo", "seccfg",
        "modemst1", "modemst2", "fsg", "fsc",
    ]
    partitions_payload: Dict[str, Any] = {
        "storage_type": storage_kind,
        "storage_size": device_info.storage_size if device_info else None,
        "partition_count": len(part_dicts),
        "partitions": part_dicts,
        "priority_backup_partitions": backup_first,
        "scatter_file": str(scatter_path),
        "rawprogram_file": str(rawprogram_path),
    }
    util.atomic_write(
        device_dir / "partitions_and_backup_plan.json",
        json.dumps(partitions_payload, indent=2, default=str).encode("utf-8"),
    )

    # 7) Write udev_and_driver_info.txt
    drv = usbmodes.driver_help()
    udev_text = "\n".join([
        f"OS: {drv.get('os')} | libusb: {drv.get('libusb')} | pyserial: {drv.get('pyserial')}",
        "",
        drv.get("summary", ""),
        "",
        "Steps:",
        *[f"  - {s}" for s in drv.get("steps", [])],
        "",
        "Linux udev rules (/etc/udev/rules.d/99-revive.rules):",
        usbmodes.udev_rules_text(),
    ])
    util.atomic_write(device_dir / "udev_and_driver_info.txt", udev_text.encode("utf-8"))

    # 8) Write recovery_checklist.txt
    checklist_text = _format_recovery_checklist(
        platform_name, device_info, intercept_result, scatter_filename, device_dir
    )
    util.atomic_write(device_dir / "recovery_checklist.txt", checklist_text.encode("utf-8"))

    # 9) Update master index.json and SUMMARY.txt in root
    index_path = root / "index.json"
    existing_entries: List[Dict[str, Any]] = []
    if index_path.exists():
        try:
            loaded = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(loaded.get("devices"), list):
                existing_entries = loaded["devices"]
        except Exception:
            existing_entries = []

    summary_entry = {
        "timestamp": details_payload["captured_at"],
        "folder": str(device_dir),
        "folder_name": device_dir.name,
        "usb_id": usb_id,
        "mode": mode,
        "platform": platform_name,
        "chip": security_payload["chip"],
        "hwcode": security_payload["hwcode"],
        "serial": serial,
        "storage": storage_kind,
        "wdt_disabled": security_payload["wdt_disabled"],
        "forced_from_mode": intercept_result.forced_from_mode if intercept_result else "",
        "preloader_crashed_to_brom": bool(intercept_result and intercept_result.preloader_crashed_to_brom),
        "brom_recaptured": bool(intercept_result and intercept_result.brom_recaptured),
        "capture_latency_ms": round(intercept_result.capture_latency_ms, 4) if intercept_result else 0.0,
        "scatter_file": str(scatter_path),
        "rawprogram_file": str(rawprogram_path),
    }
    existing_entries.append(summary_entry)

    master_index = {
        "tool": util.TOOL_NAME,
        "version": util.__version__,
        "root": str(root),
        "updated_at": details_payload["captured_at"],
        "device_count": len(existing_entries),
        "devices": existing_entries,
    }
    util.atomic_write(index_path, json.dumps(master_index, indent=2, default=str).encode("utf-8"))

    summary_lines = [
        "========================================================================================",
        "  Revive - Connected Handshakes & Device Dossier Index",
        "========================================================================================",
        f"Root Folder   : {root}",
        f"Total Captures: {len(existing_entries)}",
        "",
        f"{'TIMESTAMP':<22} {'USB ID':<11} {'MODE':<16} {'PLATFORM':<10} {'WDT OFF':<8} {'SCATTER FILE'}",
        "-" * 104,
    ]
    for item in existing_entries:
        summary_lines.append(
            f"{item['timestamp']:<22} {item['usb_id']:<11} {item['mode'][:15]:<16} "
            f"{item['platform'][:9]:<10} {str(item['wdt_disabled']):<8} "
            f"{Path(item['scatter_file']).name} ({item['folder_name']})"
        )
    summary_lines.append("")
    util.atomic_write(root / "SUMMARY.txt", "\n".join(summary_lines).encode("utf-8"))

    if intercept_result is not None:
        intercept_result.dossier_path = str(device_dir)

    return {
        "ok": True,
        "root": str(root),
        "dossier_dir": str(device_dir),
        "index_file": str(index_path),
        "summary_file": str(root / "SUMMARY.txt"),
        "scatter_file": str(scatter_path),
        "rawprogram_file": str(rawprogram_path),
        "patch_file": str(patch_path),
        "device_details_file": str(device_dir / "device_details.json"),
        "handshake_log_file": str(device_dir / "handshake_log.json"),
        "handshake_trace_file": str(device_dir / "handshake_trace.txt"),
        "security_file": str(device_dir / "security_and_chip.json"),
        "partitions_file": str(device_dir / "partitions_and_backup_plan.json"),
        "recovery_checklist_file": str(device_dir / "recovery_checklist.txt"),
        "entry": summary_entry,
    }


def list_dossiers(out_dir: os.PathLike = DEFAULT_DOSSIER_DIR) -> Dict[str, Any]:
    """Read the master index of all captured device handshakes in `out_dir`."""
    root = Path(out_dir).expanduser()
    index_path = root / "index.json"
    if not index_path.exists():
        return {"ok": True, "root": str(root), "device_count": 0, "devices": []}
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
        data["ok"] = True
        return data
    except Exception as exc:
        return {"ok": False, "root": str(root), "error": str(exc), "devices": []}
