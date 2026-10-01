"""Shared helpers: sizes, hashing, hexdump, atomic writes, job progress.

Nothing in here touches the network or the filesystem outside the paths you give it.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------------------
# Version / identity
# --------------------------------------------------------------------------------------

__version__ = "0.1.0"
TOOL_NAME = "Revive"

BANNER = r"""
  ____            _
 |  _ \ _____   _(_)_   _____
 | |_) / _ \ \ / / \ \ / / _ \
 |  _ <  __/\ V /| |\ V /  __/
 |_| \_\___| \_/ |_| \_/ \___|   repair-first phone toolkit
"""


# --------------------------------------------------------------------------------------
# Sizes and formatting
# --------------------------------------------------------------------------------------

_UNITS = [
    ("TB", 1024 ** 4),
    ("GB", 1024 ** 3),
    ("MB", 1024 ** 2),
    ("KB", 1024),
    ("B", 1),
]


def human_size(n: Optional[int], precision: int = 2) -> str:
    """1_073_741_824 -> '1.00 GB'. Also accepts None."""
    if n is None:
        return "?"
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    neg = n < 0
    n = abs(n)
    for suffix, factor in _UNITS:
        if n >= factor or factor == 1:
            val = n / factor
            if suffix == "B":
                return f"{'-' if neg else ''}{n} B"
            return f"{'-' if neg else ''}{val:.{precision}f} {suffix}"
    return f"{n} B"


_SIZE_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*([kKmMgGtT]?)[bB]?\s*$")


def parse_size(text: str) -> int:
    """'4G', '512 mb', '1024' -> bytes."""
    m = _SIZE_RE.match(str(text))
    if not m:
        raise ValueError(f"cannot parse size: {text!r}")
    value = float(m.group(1))
    unit = m.group(2).upper()
    mult = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[unit]
    return int(value * mult)


def human_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, sec = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


# --------------------------------------------------------------------------------------
# Hashing / checksums
# --------------------------------------------------------------------------------------

CHUNK = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike, progress: Optional[Callable[[int, int], None]] = None) -> str:
    """Streaming sha256. `progress(done, total)` is called as it reads."""
    p = Path(path)
    total = p.stat().st_size
    h = hashlib.sha256()
    done = 0
    with p.open("rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            h.update(block)
            done += len(block)
            if progress:
                progress(done, total)
    return h.hexdigest()


def crc32(data: bytes, seed: int = 0) -> int:
    import zlib

    return zlib.crc32(data, seed) & 0xFFFFFFFF


def checksum16(data: bytes) -> int:
    """The 16-bit additive checksum MTK BROM uses for memory result checks."""
    total = 0
    for b in data:
        total = (total + b) & 0xFFFF
    return total


# --------------------------------------------------------------------------------------
# Integer helpers for binary formats
# --------------------------------------------------------------------------------------

def u8(data: bytes, off: int) -> int:
    return data[off]


def u16le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def u32le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def u64le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")


def puts(data: bytes, off: int, length: int) -> str:
    """NUL-padded fixed-length ASCII field, stripped."""
    return data[off:off + length].decode("ascii", "replace").replace("\x00", "").strip()


# --------------------------------------------------------------------------------------
# Hexdump
# --------------------------------------------------------------------------------------

def hexdump(data: bytes, base: int = 0, limit: int = 512, width: int = 16) -> str:
    """Classic hex+ascii dump, truncated to `limit` bytes."""
    lines: List[str] = []
    view = data[:limit]
    for row in range(0, len(view), width):
        chunk = view[row:row + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = f"{hexpart:<{width * 3 - 1}}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + row:08x}  {hexpart}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"... truncated ({human_size(len(data))} total)")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Filesystem
# --------------------------------------------------------------------------------------

def ensure_dir(path: os.PathLike) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def atomic_write(path: os.PathLike, data: bytes) -> Path:
    """Write without ever leaving a half-written file behind."""
    p = Path(path)
    ensure_dir(p.parent)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix="." + p.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


def unique_path(path: os.PathLike) -> Path:
    """If the path exists, append ' (2)', ' (3)' ... so we never clobber user data."""
    p = Path(path)
    if not p.exists():
        return p
    stem, suffix, parent = p.stem, p.suffix, p.parent
    i = 2
    while True:
        candidate = parent / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
        i += 1


def safe_filename(name: str, fallback: str = "unnamed") -> str:
    """Turn a partition/file name from firmware into something safe for a filesystem."""
    name = str(name).strip().replace("\\", "_").replace("/", "_")
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name)
    name = name.strip(" .")
    return name or fallback


# --------------------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------------------

class JsonStore:
    """Tiny JSON file store used for settings and history."""

    def __init__(self, path: os.PathLike, default: Optional[Dict[str, Any]] = None):
        self.path = Path(path)
        self.default = default if default is not None else {}

    def load(self) -> Dict[str, Any]:
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                merged = dict(self.default)
                merged.update(data)
                return merged
        except (OSError, ValueError):
            pass
        return dict(self.default)

    def save(self, data: Dict[str, Any]) -> None:
        atomic_write(self.path, json.dumps(data, indent=2).encode("utf-8"))


def to_json(obj: Any, indent: Optional[int] = 2) -> str:
    return json.dumps(to_dict(obj), indent=indent, default=str)


def to_dict(obj: Any) -> Any:
    """dataclasses / paths / bytes -> JSON-friendly structures (recursive)."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_dict(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return f"<{len(obj)} bytes>"
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


# --------------------------------------------------------------------------------------
# Results, findings and progress
# --------------------------------------------------------------------------------------

@dataclasses.dataclass
class Result:
    """Uniform return value for operations, so the CLI and the web UI share one shape."""

    ok: bool
    message: str = ""
    data: Any = None
    error_code: str = ""

    @classmethod
    def success(cls, message: str = "", data: Any = None) -> "Result":
        return cls(True, message, data)

    @classmethod
    def failure(cls, message: str, error_code: str = "", data: Any = None) -> "Result":
        return cls(False, message, data, error_code)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "message": self.message, "error_code": self.error_code, "data": to_dict(self.data)}


# Severity levels used by every report in the tool.
SEV_OK = "ok"
SEV_INFO = "info"
SEV_WARN = "warn"
SEV_ERROR = "error"
SEV_FATAL = "fatal"
SEV_ORDER = {SEV_FATAL: 4, SEV_ERROR: 3, SEV_WARN: 2, SEV_INFO: 1, SEV_OK: 0}


@dataclasses.dataclass
class Finding:
    """One thing the tool noticed, with the reason and what to do about it."""

    severity: str
    title: str
    detail: str = ""
    fixes: List[str] = dataclasses.field(default_factory=list)
    code: str = ""
    where: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "fixes": list(self.fixes),
            "code": self.code,
            "where": self.where,
        }


@dataclasses.dataclass
class Step:
    """A single stage of an operation, for progress reporting."""

    name: str
    status: str = "pending"          # pending | running | done | failed | skipped | warning
    detail: str = ""
    result: Optional[Result] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "result": self.result.to_dict() if self.result else None,
        }


ProgressFn = Callable[[int, int, str], None]


def null_progress(done: int, total: int, label: str = "") -> None:  # pragma: no cover
    return None


class Reporter:
    """Collects findings and lines while an operation runs. Used by CLI + UI."""

    def __init__(self, name: str = ""):
        self.name = name
        self.findings: List[Finding] = []
        self.log: List[str] = []
        self.started = time.time()

    def line(self, text: str) -> None:
        self.log.append(text)

    def add(self, severity: str, title: str, detail: str = "",
            fixes: Optional[Iterable[str]] = None, code: str = "", where: str = "") -> Finding:
        f = Finding(severity, title, detail, list(fixes or []), code, where)
        self.findings.append(f)
        return f

    def ok(self, title: str, detail: str = "", where: str = "") -> Finding:
        return self.add(SEV_OK, title, detail, where=where)

    def info(self, title: str, detail: str = "", fixes: Optional[Iterable[str]] = None, where: str = "") -> Finding:
        return self.add(SEV_INFO, title, detail, fixes, where=where)

    def warn(self, title: str, detail: str = "", fixes: Optional[Iterable[str]] = None,
             code: str = "", where: str = "") -> Finding:
        return self.add(SEV_WARN, title, detail, fixes, code, where)

    def error(self, title: str, detail: str = "", fixes: Optional[Iterable[str]] = None,
              code: str = "", where: str = "") -> Finding:
        return self.add(SEV_ERROR, title, detail, fixes, code, where)

    def fatal(self, title: str, detail: str = "", fixes: Optional[Iterable[str]] = None,
              code: str = "", where: str = "") -> Finding:
        return self.add(SEV_FATAL, title, detail, fixes, code, where)

    @property
    def worst(self) -> str:
        if not self.findings:
            return SEV_OK
        return max((f.severity for f in self.findings), key=lambda s: SEV_ORDER.get(s, 0))

    @property
    def ok_to_proceed(self) -> bool:
        return self.worst not in (SEV_ERROR, SEV_FATAL)

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def summary(self) -> str:
        c = self.counts()
        parts = [f"{c[k]} {k}" for k in (SEV_FATAL, SEV_ERROR, SEV_WARN, SEV_INFO) if c.get(k)]
        return ", ".join(parts) if parts else "all checks passed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "elapsed": round(time.time() - self.started, 3),
            "worst": self.worst,
            "ok_to_proceed": self.ok_to_proceed,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "log": list(self.log),
        }


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() and os.environ.get("TERM", "") not in ("dumb", "")


def colorize(text: str, color: str) -> str:
    if not supports_color():
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
             "cyan": "36", "bold": "1", "dim": "2"}
    return f"\033[{codes.get(color, '0')}m{text}\033[0m"


SEVERITY_ICON = {
    SEV_OK: "OK  ",
    SEV_INFO: "info",
    SEV_WARN: "WARN",
    SEV_ERROR: "FAIL",
    SEV_FATAL: "STOP",
}

SEVERITY_COLOR = {
    SEV_OK: "green",
    SEV_INFO: "cyan",
    SEV_WARN: "yellow",
    SEV_ERROR: "red",
    SEV_FATAL: "magenta",
}
