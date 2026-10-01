"""Error decoding - the heart of the "plain English instead of cryptic codes" promise.

SP Flash Tool, MTK BROM/DA, Qualcomm Sahara/Firehose, and Revive's own detections all
raise the same kinds of questions: "what happened, and what do I do now?". This module
turns a code or a raw log line into:

    symbol      the official name, e.g. S_BROM_CMD_STARTCMD_FAIL
    meaning     one sentence a human can act on
    causes      the realistic reasons, most likely first
    fixes       concrete numbered actions, cheapest first
    phase       where in the boot/flash chain it happened
    severity    info | warn | fatal

Everything here is data, not logic, so it is easy to extend with new codes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

SEV_INFO = "info"
SEV_WARN = "warn"
SEV_ERROR = "error"
SEV_FATAL = "fatal"

PH_CONNECT = "connect"      # finding/enumerating the device
PH_PRELOADER = "preloader"  # preloader handshake
PH_BROM = "brom"            # bootrom protocol / DA upload
PH_AUTH = "auth"            # SLA / DAA / secure boot
PH_DA = "da"                # download agent running
PH_STORAGE = "storage"      # eMMC / UFS access
PH_FLASH = "flash"          # writing image data
PH_VERIFY = "verify"        # read-back / checksum
PH_POST = "post"            # after flashing


@dataclass
class ErrorInfo:
    code: str
    symbol: str
    phase: str
    severity: str
    meaning: str
    causes: List[str] = field(default_factory=list)
    fixes: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    notes: str = ""

    def headline(self) -> str:
        code = f"{self.code} " if self.code else ""
        return f"{code}{self.symbol} - {self.meaning}"

    def to_dict(self) -> Dict[str, object]:
        return {
            "code": self.code,
            "symbol": self.symbol,
            "aliases": list(self.aliases),
            "phase": self.phase,
            "severity": self.severity,
            "meaning": self.meaning,
            "causes": list(self.causes),
            "fixes": list(self.fixes),
            "notes": self.notes,
        }


# --------------------------------------------------------------------------------------
# The database
# --------------------------------------------------------------------------------------

_DB: List[ErrorInfo] = [
    # ---------------------------------------------------------------- connect / device
    ErrorInfo(
        code="no_device", symbol="DEVICE_NOT_FOUND", phase=PH_CONNECT, severity=SEV_FATAL,
        meaning="No phone on USB in any mode we recognise.",
        causes=[
            "Cable is charge-only, or the port is dead/dirty",
            "Phone is off and not being woken: BROM only appears for a moment at power-up",
            "USB drivers missing (Windows shows 'Unknown device' or nothing at all)",
            "Phone powered on normally into Android instead of download mode",
        ],
        fixes=[
            "Use a known-good DATA cable, straight into a rear USB 2.0 port (no hub, no front panel)",
            "With the phone fully off, hold Volume Up + Volume Down and plug the cable in; keep holding 5 s",
            "If it boots to Android instead, `adb reboot edl` (Qualcomm) or power off and retry",
            "Install the drivers: run `revive drivers` for the exact files and steps",
            "Still nothing: open the back and use test points (see `revive guide testpoint`)",
        ],
    ),
    ErrorInfo(
        code="driver_missing", symbol="USB_DRIVER_MISSING", phase=PH_CONNECT, severity=SEV_FATAL,
        meaning="The chip is on USB, but Windows has no driver bound to it so no tool can open it.",
        causes=[
            "MediaTek VCOM / Qualcomm HS-USB QDLoader drivers not installed",
            "Driver installed but bound to the wrong device instance after replugging",
            "Windows driver signature enforcement rejected the INF",
        ],
        fixes=[
            "Run `revive drivers` - it prints per-OS steps and can write a udev rule for Linux",
            "Windows: Device Manager -> the device with a yellow '!' -> Update driver -> pick from list -> have disk",
            "Windows: disable driver signature enforcement if the INF is unsigned, then reinstall",
            "Linux: install the generated udev rule and replug so it applies",
            "macOS: no drivers needed for libusb, but you must install libusb via Homebrew",
        ],
    ),
    ErrorInfo(
        code="port_busy", symbol="USB_PORT_BUSY", phase=PH_CONNECT, severity=SEV_WARN,
        meaning="Another program is holding the port, so this tool cannot talk to the phone.",
        causes=["Another flashtool is open", "adb server grabbed the device", "A serial monitor is attached"],
        fixes=[
            "Close SP Flash Tool / Xiaomi tools / other flashers",
            "`adb kill-server` (or stop the adb service in Task Manager)",
            "Unplug, wait 5 s, replug; on Linux check `lsof /dev/ttyUSB0`",
        ],
    ),
    ErrorInfo(
        code="unknown_chip", symbol="UNKNOWN_HW_CODE", phase=PH_BROM, severity=SEV_WARN,
        meaning="We read a hardware code that is not in our table, so we will not guess at a DA or layout.",
        causes=[
            "Very new SoC that this build predates",
            "Preloader/DA you supplied reports a custom or vendor-locked code",
            "The device answered with garbage because the USB link is unstable",
        ],
        fixes=[
            "Load the firmware folder or a stock DA/loader in Revive so the chip table can be read from it",
            "Search the printed hw_code online together with the phone model to confirm the SoC",
            "Send us the code + model so the table grows (`revive report`) - nothing else is harmed by a wrong guess",
        ],
    ),

    # ---------------------------------------------------------------- preloader / BROM
    ErrorInfo(
        code="2005", symbol="S_BROM_CMD_STARTCMD_FAIL", phase=PH_BROM, severity=SEV_FATAL,
        meaning="The phone switched itself on or left BROM before the tool could take control.",
        aliases=["0x7D5", "0xC0060001", "2005", "STATUS_BROM_CMD_STARTCMD_FAIL"],
        causes=[
            "Phone was not fully powered off before plugging in (BROM only waits ~1 s)",
            "Correct driver was not ready yet at power-up",
            "Wrong/mismatched Download Agent for this SoC",
            "Battery too low or PMIC brownout resetting the phone mid-handshake",
            "Device is a secure-boot unit that needs a signed DA",
        ],
        fixes=[
            "Fully power off (not restart). Unplug, wait 10 s, then plug in while holding Volume keys",
            "Charge the phone for 15+ minutes first if the battery is flat",
            "Try a direct rear USB 2.0 port and a short, thick cable",
            "Use the DA that came with the phone's own firmware, not a random AllInOne DA",
            "Retry 3-5 times: this error is often a timing race, not a real fault",
            "If it persists on a secure device, supply the matching auth file (`revive flash --auth`)",
        ],
    ),
    ErrorInfo(
        code="2004", symbol="S_BROM_DOWNLOAD_DA_FAIL", phase=PH_BROM, severity=SEV_FATAL,
        meaning="The boot ROM accepted us but refused to run the Download Agent we sent.",
        aliases=["STATUS_BROM_DOWNLOAD_DA_FAIL", "0xC0060004"],
        causes=[
            "DA does not match the SoC (dacode mismatch)",
            "Secure boot (SBC/SLA/DAA) is on and the DA is unsigned for this device",
            "USB link dropped partway through the DA upload",
            "Truncated or corrupt DA file",
        ],
        fixes=[
            "Use the DA from the phone's stock firmware folder (it is SoC-matched by the vendor)",
            "Verify the DA file: `revive verify <da_file>` (checks size and header sanity)",
            "Re-plug and retry on a different port; DA upload is sensitive to cable EMI",
            "If the device reports SBC/SLA/DAA enabled, pair the DA with its `auth` file, or fall back to an exploit path for your SoC if one exists",
        ],
    ),
    ErrorInfo(
        code="2003", symbol="S_BROM_CMD_JUMP_DA_FAIL", phase=PH_BROM, severity=SEV_FATAL,
        meaning="The DA was uploaded but the boot ROM refused to jump to it.",
        aliases=["S_BROM_CMD_JUMP_DA_FAIL", "STATUS_BROM_CMD_JUMP_DA_FAIL"],
        causes=[
            "DA is not signed for this device (SLA/DAA enforced)",
            "Wrong dacode for this SoC revision",
            "Memory (DRAM) not initialised, so the DA has nowhere to load",
        ],
        fixes=[
            "Supply the matching signed DA + auth file from stock firmware",
            "Try the DA that vendors ship as 'DA_BR.bin' / 'DA_PL.bin' for this exact model",
            "For older SoCs, a patched/exploit DA may be needed instead",
        ],
    ),
    ErrorInfo(
        code="auth_required", symbol="SECURE_BOOT_AUTH_REQUIRED", phase=PH_AUTH, severity=SEV_FATAL,
        meaning="This device enforces secure boot: it will only run MediaTek-signed code.",
        causes=[
            "SBC/SLA/DAA enabled in the eFuses (normal on phones from ~2015 onwards)",
            "Vendor-locked bootloader with verified boot enabled",
        ],
        fixes=[
            "Load the phone's own auth/DA files - vendors ship them inside the firmware package",
            "Check what the device reports: `revive identify --verbose` prints SBC/SLA/DAA flags",
            "On supported SoCs, use an exploit-based entry (Revive lists it per chip) instead of a signed DA",
            "Do not 'just try' random auth files: a wrong one can hang the device until the battery is removed",
        ],
    ),
    ErrorInfo(
        code="1042", symbol="S_TIMEOUT", phase=PH_BROM, severity=SEV_FATAL,
        meaning="The phone stopped answering within the time limit.",
        aliases=["0x412", "STATUS_TIMEOUT"],
        causes=["Cable/port problem", "Phone reset or powered off mid-operation", "Driver stalled", "Device hung on a bad command"],
        fixes=[
            "Unplug, remove the battery if removable, wait 10 s, replug",
            "Try another cable and a rear USB 2.0 port",
            "Lower the USB speed in settings if the tool offers it",
            "If it always hangs at the same stage, that stage is the actual problem (check the last log line)",
        ],
    ),
    ErrorInfo(
        code="8100", symbol="S_FT_CANNOT_FIND_USB_PORT", phase=PH_CONNECT, severity=SEV_FATAL,
        meaning="The tool could not open a USB port for the device (SP Flash Tool error 8100).",
        aliases=["Error 8100", "CANNOT_FIND_USB_PORT"],
        causes=["Port in use by another program", "Driver not bound", "Device disconnected between scans"],
        fixes=[
            "Close every other flashing tool and any serial terminal",
            "Reinstall the VCOM/QDLoader driver, then replug",
            "Try another USB port/PC; avoid virtual machines and USB hubs",
        ],
    ),

    # ---------------------------------------------------------------- storage / eMMC
    ErrorInfo(
        code="3144", symbol="S_DA_EMMC_FLASH_NOT_FOUND", phase=PH_STORAGE, severity=SEV_FATAL,
        meaning="The DA ran but could not see the eMMC: the phone's storage did not answer.",
        aliases=["0xC48", "S_DA_NAND_FLASH_NOT_FOUND", "S_DA_UFS_FLASH_NOT_FOUND"],
        causes=[
            "eMMC/UFS is dead or its power rails are not coming up",
            "Storage bus (CMD/CLK/DATA) damaged - common after water or a bad drop",
            "Soldering/BGA problem between SoC and storage",
            "Wrong storage type selected (UFS firmware flashed to an eMMC phone, or vice versa)",
        ],
        fixes=[
            "Confirm the firmware targets the right storage type: `revive inspect <firmware_folder>`",
            "Try a different DA; some DA builds have a different storage driver",
            "Physically inspect the board for corrosion or cracks around the storage chip",
            "If the storage is genuinely dead, a replacement chip or a full board is the only real fix - do not keep flashing",
        ],
    ),
    ErrorInfo(
        code="3149", symbol="S_DA_SDMMC_WRITE_FAILED", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="A write to the storage failed mid-flash.",
        aliases=["0xC4D", "S_DA_SDMMC_WRITE_FAILED"],
        causes=[
            "eMMC/UFS wearing out (bad blocks, CRC errors) - very common on older phones",
            "Power dip during write (weak battery, bad cable, hub)",
            "USB link errors corrupting the transfer",
        ],
        fixes=[
            "Read the health first: `revive identify` prints eMMC life/health when the DA can read it",
            "Charge the battery and use a direct rear USB port with a short cable",
            "Flash fewer partitions at a time to lower sustained load",
            "Back up everything you can read NOW - if the storage is dying, it gets worse, not better",
        ],
    ),
    ErrorInfo(
        code="3154", symbol="S_DA_SDMMC_READ_FAILED", phase=PH_VERIFY, severity=SEV_FATAL,
        meaning="A read-back after writing did not match what was written.",
        aliases=["0xC52", "S_DA_SDMMC_READ_FAILED"],
        causes=["Dying storage (bad blocks)", "Unstable USB/power", "Wrong offsets in the scatter"],
        fixes=[
            "Re-read the same region: if it fails at the same offset every time, that block is bad",
            "Retry with a shorter cable / different port / lower speed",
            "Use the firmware's own scatter offsets rather than hand-edited ones",
        ],
    ),
    ErrorInfo(
        code="3167", symbol="S_STORAGE_NOT_MATCH", phase=PH_STORAGE, severity=SEV_FATAL,
        meaning="The firmware's storage layout does not match the phone.",
        aliases=["3182", "S_CHIP_TYPE_NOT_MATCH", "S_STORAGE_NOT_MATCH"],
        causes=[
            "Firmware for a different storage size (e.g. 64 GB file on a 32 GB device)",
            "eMMC firmware being flashed to a UFS device or the reverse",
            "The image carries a storage-type flag that mismatches the DA's report",
        ],
        fixes=[
            "Double-check the model number in the firmware name against the phone's model",
            "Do NOT use 'format all' to force it through - you will brick a working phone",
            "Get the firmware built for this exact model and storage variant",
            "If you must restore a differently-built ROM, restore only system-level partitions, not preloader/partition table",
        ],
    ),
    ErrorInfo(
        code="3179", symbol="S_CHIP_TYPE_NOT_MATCH", phase=PH_STORAGE, severity=SEV_FATAL,
        meaning="The firmware was built for a different SoC than the one answering.",
        aliases=["3183", "S_CHIP_TYRE_NOT_MATCH", "S_CHIP_TYPE_NOT_MATCH"],
        causes=["Wrong firmware package for the model", "Rebadged/clone device with an unexpected chip"],
        fixes=[
            "Read the SoC first (`revive identify`) and only then pick firmware",
            "Check the model printed under the battery / in fastboot: `revive detect`",
            "Never force it: a mismatched preloader bricks the device permanently in most cases",
        ],
    ),
    ErrorInfo(
        code="0xC0050003", symbol="STATUS_BROM_CHKSUM16_MEM_RESULT_DIFF", phase=PH_VERIFY, severity=SEV_FATAL,
        meaning="Data written to memory did not read back the same (checksum mismatch).",
        aliases=["2020", "S_BROM_CHKSUM16_MEM_RESULT_DIFF_EXCEPTION"],
        causes=["Cable/USB corruption", "eMMC errors on those blocks", "Unstable power", "DRAM problems"],
        fixes=[
            "Try a different cable and port first - this is the most common cause",
            "Run a full read-back verify of the region you just wrote",
            "If reads at the same offset always differ, treat the storage as failing",
        ],
    ),
    ErrorInfo(
        code="0xC0050005", symbol="STATUS_EXT_RAM_EXCEPTION", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="The DA hit an invalid memory range while loading/writing.",
        aliases=["STATUS_EXT_RAM_EXCEPTION"],
        causes=[
            "Scatter offsets overlap or point past the end of a partition",
            "Hand-edited scatter with bad addresses",
            "The DA's memory map does not fit this device revision",
        ],
        fixes=[
            "Use the scatter exactly as it shipped: `revive inspect <folder>` flags overlapping ranges",
            "Do not merge scatter files from different firmware versions",
            "Match the DA revision to the firmware revision",
        ],
    ),

    # ---------------------------------------------------------------- flashing layer
    ErrorInfo(
        code="4032", symbol="S_FT_ENABLE_DRAM_FAIL", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="Could not enable DRAM: the tool could not bring up the phone's RAM.",
        aliases=["0xFC0", "S_FT_ENABLE_DRAM_FAIL"],
        causes=[
            "Wrong preloader / DA for this exact board (DRAM is configured by the preloader)",
            "RAM chip variant not covered by the preloader (vendors ship several variants per model)",
            "Dead DRAM or a BGA/solder fault",
        ],
        fixes=[
            "Use the preloader from your phone's own firmware build, not another version",
            "If the phone is already bricked and you must use another build, prefer a DA-only flash (skip preloader)",
            "Check for board-level damage before assuming a firmware fault",
        ],
    ),
    ErrorInfo(
        code="4008", symbol="S_FT_DOWNLOAD_FAIL", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="The transfer of image data failed partway through.",
        aliases=["0xFA8", "2004", "S_FT_DOWNLOAD_FAIL"],
        causes=["Cable/port/hub trouble", "Power dip", "Antivirus or a background tool interfering", "Storage errors"],
        fixes=[
            "Retry once - transient USB errors are common, especially on long cables",
            "Move to a rear USB 2.0 port, unplug hubs, close heavy apps",
            "Add a temporary antivirus exclusion for the firmware folder and the tool",
            "Flash partitions in smaller groups to isolate the failing one",
        ],
    ),
    ErrorInfo(
        code="4010", symbol="S_FT_FORMAT_FAIL", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="The format step failed (usually before downloading).",
        aliases=["S_FT_FORMAT_FAIL"],
        causes=["Storage protection flags set on the eMMC (boot area protect)", "Dying storage", "Wrong storage type"],
        fixes=[
            "Use 'Download only' instead of 'Format All + Download' unless the partition table really must change",
            "If a previous flash set write protection, erase the whole user area once, then flash",
            "Check the eMMC health report - repeated format failures often mean failing storage",
        ],
    ),
    ErrorInfo(
        code="8038", symbol="S_DL_PMT_ERR", phase=PH_FLASH, severity=SEV_WARN,
        meaning="Partition layout (PMT) differs from what the firmware expects: the tool wants to rebuild it.",
        aliases=["PMT changed for the ROM", "S_DL_PMT_ERR", "Error 8038"],
        causes=["Firmware from a different firmware version/region", "Partition table previously modified", "Downgrading to an older build"],
        fixes=[
            "Back up every important partition first - rebuilding the layout wipes userdata and often the whole device",
            "Prefer a firmware whose version matches your phone's existing build",
            "If you accept the wipe, use Format All + Download only after a full backup",
        ],
    ),
    ErrorInfo(
        code="1002", symbol="S_INVALID_ARGUMENTS", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="The tool rejected its own inputs - almost always a bad or mismatched scatter file.",
        aliases=["S_INVALID_ARGUMENTS"],
        causes=["Scatter corrupt or edited in the wrong editor (line endings/encoding)", "Scatter from a different firmware"],
        fixes=[
            "Re-extract the firmware archive from scratch",
            "Validate it here first: `revive inspect <folder>`",
            "Never edit scatter files in Windows Notepad; if you must edit, keep LF or CRLF consistent and keep the original encoding",
        ],
    ),
    ErrorInfo(
        code="5011", symbol="S_DL_SCAT_INCORRECT_FORMAT", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="The scatter file format is wrong for this tool version.",
        aliases=["S_DL_SCAT_INCORRECT_FORMAT"],
        causes=["Scatter version mismatch (v1 vs v2/v3)", "File truncated by a bad extraction"],
        fixes=["Use the scatter from the same firmware package as the images", "Re-download/re-extract the firmware, then re-run `revive inspect`"],
    ),
    ErrorInfo(
        code="6104", symbol="S_SECURITY_SECURE_USB_DL_DA_RETURN_INVALID_TYPE", phase=PH_AUTH, severity=SEV_FATAL,
        meaning="Secure USB download rejected the DA we sent: the signature did not match this device.",
        aliases=["S_SECURITY_SECURE_USB_DL_DA_RETURN_INVALID_TYPE"],
        causes=["Auth file does not belong to this device's key set", "DA from a different vendor build", "eFuse key revision changed by an update"],
        fixes=[
            "Use the DA + auth pair from the phone's own firmware, same build number",
            "Check the device's security state first (`revive identify --verbose`)",
            "Do not loop retries with wrong auth: it can lock you out until a battery pull",
        ],
    ),
    ErrorInfo(
        code="1040", symbol="S_UNSUPPORTED_OPERATION", phase=PH_FLASH, severity=SEV_FATAL,
        meaning="The operation is not meaningful for this file/scatter combination (e.g. boot file vs scatter mismatch).",
        aliases=["S_UNSUPPORTED_OPERATION"],
        causes=["Mixing files from different firmware builds", "Tick boxes selected for files that are not present"],
        fixes=["Re-select the files that actually exist in the folder - `revive plan` shows exactly what will be written and where"],
    ),

    # ---------------------------------------------------------------- Qualcomm EDL
    ErrorInfo(
        code="sahara_error", symbol="SAHARA_PROTOCOL_ERROR", phase=PH_BROM, severity=SEV_FATAL,
        meaning="The Qualcomm EDL bootloader (Sahara) rejected the loader handshake.",
        causes=[
            "Wrong firehose loader for this SoC (loader and SoC must match exactly)",
            "Loader file truncated/corrupt",
            "Device not actually in EDL 9008 mode",
            "Secure boot: device only accepts signed loaders",
        ],
        fixes=[
            "Get the firehose loader that belongs to this exact model (usually prog_emmc_firehose_*.mbn / .elf)",
            "Verify the device is in 9008: `revive detect` prints the USB ID it sees",
            "Replug and retry; use a USB 2.0 port",
            "For signed-only devices, use the vendor loader from the stock firmware",
        ],
    ),
    ErrorInfo(
        code="firehose_nak", symbol="FIREHOSE_NAK", phase=PH_DA, severity=SEV_FATAL,
        meaning="The firehose programmer answered NAK to a command.",
        causes=["Command not supported by this loader version", "Bad XML (rawprogram/patch) arguments", "Loader already in error state"],
        fixes=[
            "Re-run with the rawprogram/patch XML that came with the firmware",
            "Reboot the device back into EDL and start a fresh session (state can be sticky after an error)",
            "Check the printed log for the exact failing tag (e.g. program, configure, read) - Revive names it",
        ],
    ),
    ErrorInfo(
        code="qc_unsupported", symbol="EDL_OPERATION_UNSUPPORTED", phase=PH_DA, severity=SEV_WARN,
        meaning="This device's loader does not allow the requested operation.",
        causes=["Vendor restricted firehose (no read/erase)", "Secure boot configuration"],
        fixes=["Try only the operations the loader supports (Revive lists capabilities after handshake)", "Use a vendor-signed loader that permits it"],
    ),

    # ---------------------------------------------------------------- Unisoc / other
    ErrorInfo(
        code="unisoc_no_response", symbol="BSL_NO_RESPONSE", phase=PH_BROM, severity=SEV_FATAL,
        meaning="The Unisoc (Spreadtrum) bootloader did not answer the connect frames.",
        causes=["Device not in download mode (needs the button combo or a test point)", "Wrong baud rate/port", "Driver issue"],
        fixes=[
            "Hold the specific key combo for your model (many need Vol Down while plugging in)",
            "On Windows, the port appears as 'SPRD U2S Diag' or a COM port - check `revive detect`",
            "Try a different baud rate; Unisoc connects at low speed first",
        ],
    ),

    # ---------------------------------------------------------------- Revive's own checks
    ErrorInfo(
        code="firmware_missing_files", symbol="FIRMWARE_INCOMPLETE", phase=PH_FLASH, severity=SEV_ERROR,
        meaning="The firmware folder is missing image files that the scatter/XML plan expects.",
        causes=["Incomplete download or partial extraction", "Files still inside a zip", "Renamed files"],
        fixes=["Re-extract the archive and re-run `revive inspect`", "Do not rename image files: plain names are matched case-insensitively, but extensions matter"],
    ),
    ErrorInfo(
        code="plan_overlap", symbol="PARTITION_OVERLAP", phase=PH_FLASH, severity=SEV_ERROR,
        meaning="Two entries in the plan would write over the same storage range.",
        causes=["Scatter from one build combined with images from another", "Hand-edited scatter"],
        fixes=["Use one consistent firmware package", "Let Revive re-validate: `revive plan <folder>` prints the conflicting entries side by side"],
    ),
    ErrorInfo(
        code="plan_size_mismatch", symbol="IMAGE_LARGER_THAN_PARTITION", phase=PH_FLASH, severity=SEV_ERROR,
        meaning="An image is bigger than the partition it targets, so it cannot fit.",
        causes=["Image from a different build/model", "Scatter from another firmware"],
        fixes=["Match the firmware to the model", "If this is deliberate (e.g. a bigger system on the same layout), resize the partition table first - that wipes data"],
    ),
    ErrorInfo(
        code="storage_type_mismatch", symbol="STORAGE_TYPE_MISMATCH", phase=PH_STORAGE, severity=SEV_ERROR,
        meaning="The firmware targets a different storage technology than the device reports (eMMC vs UFS).",
        causes=["Flashing a UFS package to an eMMC device (or the reverse)"],
        fixes=["Get the firmware built for this exact variant, or extract only shared partitions", "Check the phone's storage with `revive identify`"],
    ),
    ErrorInfo(
        code="dump_no_gpt", symbol="NO_VALID_PARTITION_TABLE", phase=PH_STORAGE, severity=SEV_WARN,
        meaning="No valid GPT was found in the dump, so partitions cannot be listed by name.",
        causes=["Dump starts at the boot area, not the user area", "Partition table erased or corrupted", "Device used an MTK/PMT style layout instead"],
        fixes=[
            "For a full-dump file, tell Revive the start offset if you know it",
            "Try `revive dump-scan` - it recovers partitions by looking for known filesystem and boot-image signatures instead",
            "If the table is truly gone, recovery relies on the dump's signatures and on your own backups",
        ],
    ),
]

# Fast lookup structures ---------------------------------------------------------------

_BY_KEY: Dict[str, ErrorInfo] = {}
for _e in _DB:
    _BY_KEY[_e.code.lower()] = _e
    for _a in _e.aliases:
        _BY_KEY.setdefault(str(_a).lower(), _e)


def _norm(token: str) -> str:
    t = str(token).strip().lower()
    t = t.replace("error:", "").replace("brom error", "").strip()
    t = t.strip("[](){}:,;\"' ")
    return t


def _spacify(text: str) -> str:
    """'SAHARA_PROTOCOL_ERROR' and 'sahara protocol error' must match each other."""
    return re.sub(r"[^a-z0-9]+", " ", str(text).lower()).strip()


# Pre-computed normalised keys so symbol matching is separator-insensitive.
_NORM_KEYS: List[Tuple[str, "ErrorInfo"]] = []
for _e in _DB:
    for _n in (_e.symbol, _e.code, *_e.aliases):
        _key = _spacify(_n)
        if len(_key) >= 6:
            _NORM_KEYS.append((_key, _e))


def _code_variants(token: str) -> List[str]:
    """'C0060001' and '0xC0060001' and '2005' should all resolve."""
    out = [token]
    t = token
    if t.startswith("0x"):
        out.append(t[2:])
        try:
            out.append(str(int(t, 16)))
        except ValueError:
            pass
    else:
        try:
            value = int(t, 10)
            out.append(hex(value))
            out.append(f"0x{value:08X}".lower())
        except ValueError:
            pass
        if len(t) == 8:
            out.append("0x" + t)
    return out


def decode(text: str) -> Optional[ErrorInfo]:
    """Best-effort: find the ErrorInfo for a raw log line, symbol, or numeric code."""
    if text is None:
        return None
    raw = str(text)
    low = raw.lower()
    flat = _spacify(raw)

    # 1) direct symbol match anywhere in the line (separator-insensitive)
    for key, info in _NORM_KEYS:
        if key in flat:
            return info

    # 2) numeric codes: 0x1234ABCD, 1234ABCD, 2005
    for pattern in (r"0x[0-9a-fA-F]{2,8}", r"\((\d{2,5})\)", r"\b(\d{4,5})\b", r"\b([0-9a-fA-F]{8})\b"):
        for match in re.findall(pattern, raw):
            token = _norm(match)
            for variant in _code_variants(token):
                if variant in _BY_KEY:
                    return _BY_KEY[variant]
    return None


def get(code: str) -> Optional[ErrorInfo]:
    token = _norm(code)
    if token in _BY_KEY:
        return _BY_KEY[token]
    for variant in _code_variants(token):
        if variant in _BY_KEY:
            return _BY_KEY[variant]
    return None


def search(query: str) -> List[ErrorInfo]:
    q = str(query).lower().strip()
    if not q:
        return list(_DB)
    hits = []
    for info in _DB:
        haystack = " ".join([info.code, info.symbol, info.meaning, *info.aliases]).lower()
        if q in haystack:
            hits.append(info)
    return hits


def all_errors() -> List[ErrorInfo]:
    return list(_DB)


def triage(text: str) -> Dict[str, object]:
    """Full answer for a pasted log or a code: matched error + generic next steps if not found."""
    info = decode(text)
    if info:
        return {
            "matched": True,
            "error": info.to_dict(),
            "advice": generic_advice(info.phase),
        }
    return {
        "matched": False,
        "error": None,
        "query": str(text)[:400],
        "advice": generic_advice(None),
        "note": (
            "This code is not in the table yet. The log line itself still tells you the phase: "
            "if it happened while waiting for the phone, it is a cable/driver/timing issue; if it "
            "happened after the DA started, it is a storage or firmware-mismatch issue."
        ),
    }


_GENERIC = {
    PH_CONNECT: [
        "Confirm the phone is visible at all: `revive detect`",
        "Change cable, then port, then PC - in that order",
        "Close every other tool that could hold the port",
    ],
    PH_BROM: [
        "Power the phone fully off, then replug while holding the volume keys",
        "Retry 3-5 times; timing races are the most common cause",
        "Confirm the DA/auth files match this exact SoC and build",
    ],
    PH_AUTH: [
        "Load the auth/DA files that shipped with this phone's firmware",
        "Print the security state with `revive identify --verbose`",
        "Do not retry with mismatched auth files - it can hang the device",
    ],
    PH_STORAGE: [
        "Check the storage's health read-out before any further writes",
        "Verify the firmware matches the storage type (eMMC vs UFS) and size",
        "Back up everything readable now, while it still reads",
    ],
    PH_FLASH: [
        "Retry once on a different USB port with a shorter cable",
        "Verify the firmware package first: `revive inspect <folder>`",
        "Flash in smaller groups to isolate the failing partition",
    ],
    PH_VERIFY: [
        "Re-read the region to see if the mismatch is repeatable (a repeatable mismatch means bad blocks)",
        "If repeatable, stop writing and prioritise data extraction",
    ],
    PH_POST: [
        "Power-cycle the phone and check whether it boots to fastboot/recovery before reflashing anything",
        "Re-read the partition you just wrote to confirm the content",
    ],
    None: [
        "Identify what the phone is doing first: `revive detect`",
        "Verify the firmware folder: `revive inspect <folder>`",
        "Then follow the phase printed in the log (connect -> BROM -> DA -> flash -> verify)",
    ],
}


def generic_advice(phase: Optional[str]) -> List[str]:
    return list(_GENERIC.get(phase, _GENERIC[None]))
