"""Backend contract shared by every chip family.

Each backend talks to one kind of download mode (MediaTek BROM/preloader, Qualcomm EDL,
Unisoc BSL, fastboot, ...). They all expose the same small surface so the CLI, the web UI and
the planner never need to know which chip they are dealing with.

Two flags matter for honesty:

    tested      True only for backends verified against real hardware by this project
    protocol    where the framing knowledge comes from (vendor docs, public RE notes, ...)

A backend with tested=False is still usable - it just tells the user to report what happens.
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..util import ProgressFn, null_progress


class BackendError(Exception):
    """Raised by backends. `code` maps into revive.core.errors for plain-English advice."""

    def __init__(self, message: str, code: str = "", detail: str = "", data: Any = None):
        super().__init__(message)
        self.code = code
        self.detail = detail
        self.data = data


class BackendUnavailable(BackendError):
    """The environment cannot run this backend (missing library, no device, no permission)."""


@dataclass
class DeviceInfo:
    """What we learned by talking to a device."""

    backend: str = ""
    mode: str = ""
    vendor: str = ""
    hwcode: Optional[int] = None
    chip: str = ""
    chip_confidence: str = ""
    storage: str = ""
    storage_size: Optional[int] = None
    usb_id: str = ""
    serial: str = ""
    security: Dict[str, Any] = field(default_factory=dict)
    extras: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend, "mode": self.mode, "vendor": self.vendor,
            "hwcode": f"0x{self.hwcode:04X}" if self.hwcode is not None else None,
            "hwcode_int": self.hwcode, "chip": self.chip,
            "chip_confidence": self.chip_confidence, "storage": self.storage,
            "storage_size": self.storage_size, "usb_id": self.usb_id,
            "serial": self.serial, "security": self.security,
            "extras": self.extras, "notes": list(self.notes),
        }


@dataclass
class Partition:
    name: str
    offset: int = 0
    size: int = 0
    region: str = "user"

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "offset": self.offset, "size": self.size,
                "region": self.region}


@dataclass
class Endpoints:
    """USB endpoint numbers a bulk-transfer protocol will use. Overridable per device."""

    out_ep: int = 0x01
    in_ep: int = 0x81
    interface: int = 0

    def swapped(self) -> "Endpoints":
        return Endpoints(self.in_ep, self.out_ep, self.interface)


class DeviceBackend(abc.ABC):
    """Base class for all device backends."""

    name = "base"
    label = "Generic backend"
    vendor = ""
    modes: List[str] = []
    capability_read = False
    capability_write = False
    capability_erase = False
    capability_partitions = False
    tested = False
    protocol = "unknown"
    notes: List[str] = []

    def __init__(self, progress: ProgressFn = null_progress, verbose: bool = False):
        self.progress = progress
        self.verbose = verbose
        self.log: List[str] = []
        self.device: Any = None
        self.info = DeviceInfo(backend=self.name)

    # -- lifecycle --------------------------------------------------------------------
    def open(self) -> None:
        """Claim the USB device. Must raise BackendUnavailable when it cannot."""

    def close(self) -> None:
        self.device = None

    def __enter__(self) -> "DeviceBackend":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def log_line(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log.append(f"[{stamp}] {text}")
        if self.verbose:
            print(f"[{stamp}] {text}")

    # -- capabilities -----------------------------------------------------------------
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name, "label": self.label, "vendor": self.vendor,
            "modes": list(self.modes), "read": self.capability_read,
            "write": self.capability_write, "erase": self.capability_erase,
            "partitions": self.capability_partitions, "tested": self.tested,
            "protocol": self.protocol, "notes": list(self.notes),
        }

    # -- operations (override what the protocol supports) ------------------------------
    @abc.abstractmethod
    def identify(self) -> DeviceInfo:
        """Read chip/security/storage information."""

    def read_flash(self, offset: int, length: int, out_path, chunk: int = 1024 * 1024) -> Dict[str, Any]:
        raise BackendError("this backend cannot read storage", code="qc_unsupported")

    def write_flash(self, offset: int, data_path, length: Optional[int] = None) -> Dict[str, Any]:
        raise BackendError("this backend cannot write storage", code="qc_unsupported")

    def erase_flash(self, offset: int, length: int) -> Dict[str, Any]:
        raise BackendError("this backend cannot erase storage", code="qc_unsupported")

    def list_partitions(self) -> List[Partition]:
        return []

    # -- helpers ----------------------------------------------------------------------
    def require(self, capability: str) -> None:
        if not getattr(self, f"capability_{capability}", False):
            raise BackendError(
                f"The {self.label} backend does not support {capability} in this build.",
                code="qc_unsupported",
                detail="Backends grow capability by capability; this operation is not implemented yet.",
            )

    def guard_tested(self) -> List[str]:
        """Warnings the UI must show before a user relies on this backend."""
        warnings = []
        if not self.tested:
            warnings.append(
                f"{self.label} is not verified against real hardware by this project. "
                "Protocol details come from published reverse-engineering notes; the framing and "
                "error decoding are implemented, but expect to iterate on a real device."
            )
        return warnings

    def status(self) -> Dict[str, Any]:
        return {
            "backend": self.name, "capabilities": self.capabilities(),
            "device": self.info.to_dict(), "log": self.log[-200:],
        }
