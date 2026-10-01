"""Qualcomm EDL backend (Sahara + Firehose).

Qualcomm's recovery path has two stages:

  1. **Sahara** - the boot ROM speaks a tiny packet protocol. The host uploads a signed
     "firehose programmer" (`prog_emmc_firehose_*.mbn`), and that is the whole handshake.
  2. **Firehose** - the programmer accepts XML commands over bulk USB: `<configure>`,
     `<program>`, `<read>`, `<erase>`, each answered with `<response value="ACK"/>` or a NAK
     that often carries a human-readable reason. Those reasons are fed straight into Revive's
     error decoder.

Provenance: the Sahara packet format and the firehose XML dialect are documented in Qualcomm's
own open tooling and in many public security write-ups; the implementation below follows that
structure. Like the MediaTek backend, it is marked untested-here: the value it adds even before
first hardware contact is (a) exact, readable failures instead of silence and (b) a validated
plan for what to write where.
"""
from __future__ import annotations

import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core import errors, usbmodes
from ..storage import gpt as gpt_mod
from ..util import ProgressFn, human_size, null_progress
from . import usbfinder
from .base import BackendError, BackendUnavailable, DeviceBackend, DeviceInfo, Partition

VID_QC = 0x05C6
PID_EDL = 0x9008

# Sahara
SAHARA_HELLO = 0x01
SAHARA_HELLO_RESPONSE = 0x02
SAHARA_READ_DATA = 0x03
SAHARA_END_OF_IMAGE = 0x04
SAHARA_DONE = 0x05
SAHARA_DONE_RESPONSE = 0x06
SAHARA_RESET = 0x07
SAHARA_RESET_RESPONSE = 0x08

SAHARA_NAMES = {
    0x01: "HELLO", 0x02: "HELLO_RESPONSE", 0x03: "READ_DATA", 0x04: "END_OF_IMAGE",
    0x05: "DONE", 0x06: "DONE_RESPONSE", 0x07: "RESET", 0x08: "RESET_RESPONSE",
}

SAHARA_STATUS = {
    0x00: "success", 0x01: "invalid command", 0x02: "protocol error",
    0x03: "invalid target protocol", 0x04: "invalid host protocol", 0x05: "invalid packet size",
    0x06: "unexpected image ID", 0x07: "invalid data size", 0x08: "invalid image header",
    0x09: "invalid image data", 0x0A: "invalid image type", 0x0B: "invalid transmission",
    0x0C: "invalid reception", 0x0D: "NAK",
}

EDL_MODES = {0: "image transmission (normal)", 1: "command mode", 2: "memory dump", 3: "reset"}


@dataclass
class SaharaHello:
    version: int = 0
    min_version: int = 0
    max_packet: int = 0
    mode: int = 0
    raw: bytes = b""

    @property
    def mode_name(self) -> str:
        return EDL_MODES.get(self.mode, f"mode {self.mode}")

    def to_dict(self) -> Dict[str, Any]:
        return {"version": self.version, "min_version": self.min_version,
                "max_packet_size": self.max_packet, "mode": self.mode,
                "mode_name": self.mode_name}


@dataclass
class FirehoseResponse:
    ack: bool = False
    raw: str = ""
    log: str = ""
    value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ack": self.ack, "log": self.log, "value": self.value, "raw": self.raw[:2000]}


class QualcommEdlBackend(DeviceBackend):
    name = "qualcomm"
    label = "Qualcomm EDL (9008)"
    vendor = "Qualcomm"
    modes = [usbmodes.MODE_QC_EDL]
    capability_read = True
    capability_write = True
    capability_erase = True
    capability_partitions = True
    tested = False
    protocol = "Sahara packet protocol + firehose XML dialect (public documentation)"
    notes = [
        "You must supply the firehose programmer that matches this exact model - a wrong loader "
        "fails the Sahara handshake.",
        "Secure-boot devices only accept vendor-signed loaders; there is no way around that "
        "without the vendor's file.",
        "Firehose NAK messages are parsed and translated into plain English by Revive.",
    ]

    def __init__(self, progress: ProgressFn = null_progress, verbose: bool = False,
                 timeout: float = 20.0, memory: str = "", sector_size: int = 512):
        super().__init__(progress, verbose)
        self.timeout = timeout
        self.memory = memory                 # eMMC / UFS / nand - auto-detected when possible
        self.sector_size = sector_size
        self.hello: Optional[SaharaHello] = None
        self.firehose_ready = False
        self.endpoints = {"cmd_out": 0x01, "cmd_in": 0x81, "data_out": 0x01, "data_in": 0x81}

    # -- connection -------------------------------------------------------------------
    def open(self, device: Any = None) -> None:
        if device is None:
            devices, warnings = usbfinder.find_devices(VID_QC, PID_EDL)
            if not devices:
                raise BackendUnavailable(
                    "No Qualcomm EDL (9008) device on USB. " + (warnings[0] if warnings else ""),
                    code="no_device",
                    detail="Power off, then connect - on most phones EDL needs a key combo or a "
                           "test point. `revive detect` shows what USB ids are actually present.",
                )
            device = devices[0]
        self.device = device
        self.info.usb_id = f"{VID_QC:04x}:{PID_EDL:04x}"
        self.info.mode = usbmodes.MODE_QC_EDL
        self.info.vendor = "Qualcomm"
        usbfinder.open_device(device)
        self.log_line("opened EDL interface")

    # -- Sahara -----------------------------------------------------------------------
    def _read_exact(self, length: int) -> bytes:
        data = self.device.read(self.endpoints["cmd_in"], length, self.timeout * 1000)
        return bytes(data) if data else b""

    def read_sahara_packet(self) -> Dict[str, Any]:
        header = self._read_exact(8)
        if len(header) < 8:
            raise BackendError("EDL closed the connection before sending a packet", code="sahara_error",
                              detail="A failed previous session can leave the device like this; "
                                     "unplug, wait, replug (a long press on power also resets it).")
        command, length = struct.unpack("<II", header)
        if length > 1024 * 1024:
            raise BackendError(f"implausible Sahara packet length {length}", code="sahara_error")
        payload = self._read_exact(length) if length else b""
        return {"command": command, "name": SAHARA_NAMES.get(command, f"0x{command:02x}"),
                "length": length, "payload": payload}

    def sahara_hello(self) -> SaharaHello:
        packet = self.read_sahara_packet()
        if packet["command"] != SAHARA_HELLO:
            raise BackendError(
                f"expected a Sahara HELLO, got {packet['name']}",
                code="sahara_error",
                detail="The device is in EDL but not talking Sahara: either another tool opened "
                       "it first, or the port is a diagnostic interface rather than 9008.",
                data={"packet": packet["name"]},
            )
        payload = packet["payload"]
        if len(payload) >= 16:
            version, min_version, max_packet, mode = struct.unpack_from("<IIII", payload, 0)
        else:  # very old boot ROMs send only 20 bytes of payload
            version = min_version = mode = 0
            max_packet = 1024
        self.hello = SaharaHello(version, min_version, max_packet, mode, payload)
        self.log_line(f"Sahara HELLO: v{version} (min {min_version}), mode {self.hello.mode_name}")
        # Echo the parameters back (HELLO_RESPONSE) - identical layout, host's limits.
        response = struct.pack("<IIII", version, min_version, max_packet, mode) + b"\x00" * 32
        self.device.write(self.endpoints["cmd_out"],
                          struct.pack("<II", SAHARA_HELLO_RESPONSE, len(response)) + response,
                          self.timeout * 1000)
        return self.hello

    def upload_loader(self, loader_path, progress: ProgressFn = null_progress) -> Dict[str, Any]:
        """The core of EDL: serve the programmer to the boot ROM as it asks for byte ranges."""
        path = Path(loader_path)
        blob = path.read_bytes()
        if not blob:
            raise BackendError("the firehose loader file is empty", code="sahara_error")
        if self.hello is None:
            self.sahara_hello()

        if self.hello.mode != 0:
            raise BackendError(
                f"the device is not in image-transmission mode ({self.hello.mode_name})",
                code="sahara_error",
                detail="A device that already has a firehose session open must be reset first: "
                       "unplug it, wait 10 seconds, then plug it back in.",
            )

        served = 0
        while True:
            packet = self.read_sahara_packet()
            command = packet["command"]
            if command == SAHARA_READ_DATA:
                payload = packet["payload"]
                if len(payload) < 20:
                    raise BackendError("malformed READ_DATA packet", code="sahara_error")
                image_id, offset, length = struct.unpack_from("<IQQ", payload, 0)
                if offset >= len(blob):
                    self.log_line("device asked past the end of the loader: sending END_OF_IMAGE")
                    self._send_end_of_image()
                    break
                chunk = blob[offset:offset + length]
                self.device.write(self.endpoints["data_out"], chunk, self.timeout * 1000)
                served += len(chunk)
                progress(served, len(blob), "uploading firehose programmer")
            elif command == SAHARA_END_OF_IMAGE:
                break
            elif command == SAHARA_DONE:
                self.device.write(self.endpoints["cmd_out"],
                                  struct.pack("<II", SAHARA_DONE_RESPONSE, 0), self.timeout * 1000)
                break
            elif command == SAHARA_RESET:
                self.device.write(self.endpoints["cmd_out"],
                                  struct.pack("<II", SAHARA_RESET_RESPONSE, 0), self.timeout * 1000)
                raise BackendError("the device reset itself during the loader upload",
                                   code="sahara_error",
                                   detail="Typical causes: unsigned/incorrect loader, unstable port, "
                                          "or a loader built for a different SoC revision.")
            else:
                self.log_line(f"ignoring unexpected Sahara packet {packet['name']}")

        self.firehose_ready = True
        self.log_line(f"firehose programmer loaded ({human_size(served)})")
        return {"loader": str(path), "bytes": served, "firehose_ready": True}

    def _send_end_of_image(self) -> None:
        self.device.write(self.endpoints["cmd_out"],
                          struct.pack("<II", SAHARA_END_OF_IMAGE, 0), self.timeout * 1000)

    # -- Firehose ---------------------------------------------------------------------
    def send_xml(self, xml: str, timeout: Optional[float] = None) -> FirehoseResponse:
        """Send one firehose command and parse the device's response."""
        if not self.firehose_ready:
            raise BackendError("no firehose session: upload a programmer first", code="sahara_error")
        if not xml.endswith("\n"):
            xml += "\n"
        self.device.write(self.endpoints["cmd_out"], xml.encode("utf-8"),
                          int((timeout or self.timeout) * 1000))
        return self.read_response(timeout)

    def read_response(self, timeout: Optional[float] = None) -> FirehoseResponse:
        deadline = time.time() + (timeout or self.timeout)
        buffer = ""
        while time.time() < deadline:
            try:
                chunk = self.device.read(self.endpoints["cmd_in"], 4096,
                                         int(min(2.0, max(0.2, deadline - time.time())) * 1000))
            except Exception:
                continue
            if not chunk:
                continue
            buffer += bytes(chunk).decode("utf-8", "replace")
            if "</response>" in buffer or "/>" in buffer:
                break
        return self._parse_response(buffer)

    def _parse_response(self, text: str) -> FirehoseResponse:
        response = FirehoseResponse(raw=text)
        value_match = re.search(r'value\s*=\s*"([^"]+)"', text)
        if value_match:
            response.value = value_match.group(1)
        log_match = re.search(r'<log[^>]*value\s*=\s*"([^"]*)"', text)
        if log_match:
            response.log = log_match.group(1)
        response.ack = response.value.upper() == "ACK"
        if not response.ack and text.strip():
            raise BackendError(
                f"firehose refused the command: {response.log or response.value or text[:200]}",
                code="firehose_nak",
                detail="The NAK text above names the failing step. Common causes: a command the "
                       "loader does not implement, or an XML argument it cannot satisfy (sector "
                       "range, memory name, or missing patch step).",
                data=response.to_dict(),
            )
        return response

    def configure(self, memory: Optional[str] = None, sector_size: Optional[int] = None,
                  verbose: bool = False) -> FirehoseResponse:
        """The mandatory first firehose command: it pins down storage type and sector size."""
        memory = memory or self.memory or self._guess_memory()
        size = sector_size or self.sector_size
        self.memory, self.sector_size = memory, size
        xml = (f'<?xml version="1.0" ?><data><configure MemoryName="{memory}" '
               f'SECTOR_SIZE_IN_BYTES="{size}" NUM_PARTITION_SECTORS="4" '
               f'ZLPAsSECTORINBYTES="1" verbose="{1 if verbose else 0}" '
               f'AlwaysValidate="0" MaxPayloadSizeToTargetInBytes="1048576" '
               f'ZlPAsSectorInBytes="1" /></data>')
        self.log_line(f"configure: memory={memory}, sector size={size}")
        return self.send_xml(xml)

    def _guess_memory(self) -> str:
        """eMMC vs UFS cannot be read before configure; try the common name and let the user override."""
        hint = (self.info.storage or "").lower()
        if "ufs" in hint:
            return "UFS"
        return "eMMC"

    def program(self, entry, root) -> Dict[str, Any]:
        """Write one rawprogram entry (used by `revive flash --confirm`)."""
        path = Path(root) / entry.filename
        if not path.exists():
            raise BackendError(f"missing image {entry.filename}", code="firmware_missing_files")
        size = path.stat().st_size
        xml = (f'<?xml version="1.0" ?><data><program SECTOR_SIZE_IN_BYTES="{entry.sector_size}" '
               f'filename="{entry.filename}" label="{entry.label}" '
               f'num_partition_sectors="{entry.num_sectors}" physical_partition_number='
               f'"{entry.physical_partition}" start_sector="{entry.start_sector}" '
               f'sparse="{"true" if entry.sparse else "false"}" /></data>')
        self.send_xml(xml)
        sent = 0
        with path.open("rb") as fh:
            while sent < size:
                block = fh.read(1024 * 1024)
                if not block:
                    break
                self.device.write(self.endpoints["data_out"], block, self.timeout * 1000)
                sent += len(block)
                self.progress(sent, size, f"flashing {entry.label}")
        self.read_response()
        return {"label": entry.label, "bytes": sent}

    def read_sectors(self, start_sector: int, num_sectors: int, out_path, lun: int = 0
                     ) -> Dict[str, Any]:
        """`<read>` a sector range - used to pull a partition or the partition table."""
        xml = (f'<?xml version="1.0" ?><data><read SECTOR_SIZE_IN_BYTES="{self.sector_size}" '
               f'num_partition_sectors="{num_sectors}" physical_partition_number="{lun}" '
               f'start_sector="{start_sector}" /></data>')
        self.send_xml(xml)
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        remaining = num_sectors * self.sector_size
        written = 0
        with out.open("wb") as fh:
            while written < remaining:
                try:
                    chunk = self.device.read(self.endpoints["data_in"],
                                             min(1024 * 1024, remaining - written),
                                             self.timeout * 1000)
                except Exception:
                    break
                if not chunk:
                    break
                fh.write(bytes(chunk))
                written += len(chunk)
                self.progress(written, remaining, "reading")
        self.read_response()
        return {"output": str(out), "bytes": written, "start_sector": start_sector}

    def list_partitions(self, lun: int = 0) -> List[Partition]:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            gpt_path = Path(tmp) / "gpt.bin"
            try:
                self.read_sectors(0, 34, gpt_path, lun)
                parsed = gpt_mod.read_gpt(gpt_path)
            except Exception as exc:
                self.log_line(f"could not read the partition table: {exc}")
                return []
        return [Partition(p.name, p.offset, p.size, f"lun{lun}") for p in parsed.partitions]

    # -- identification ---------------------------------------------------------------
    def identify(self) -> DeviceInfo:
        if self.hello is None:
            self.sahara_hello()
        assert self.hello is not None
        self.info.extras["sahara"] = self.hello.to_dict()
        self.info.serial = str(getattr(self.device, "serial_number", "") or "")
        # The serial number of a Qualcomm EDL device encodes the SoC as the first 8 hex digits.
        if self.info.serial and len(self.info.serial) >= 8:
            try:
                soc_id = int(self.info.serial[:8], 16)
                self.info.extras["soc_id"] = f"0x{soc_id:08X}"
                self.info.hwcode = soc_id & 0xFFFF
            except ValueError:
                pass
        self.info.chip = "Qualcomm SoC (name requires the loader or the model number)"
        self.info.notes.append(
            "Qualcomm EDL does not expose a friendly chip name over Sahara: match the firehose "
            "loader file name and the phone's model instead."
        )
        self.info.notes.extend(self.guard_tested())
        return self.info
