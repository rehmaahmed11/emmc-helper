"""Device Archive — Rule 1 of RULES.md.

Every time the app reads a connected device's hardware (``revive detect``, ``revive
identify``, ``revive intercept``, or the web UI), the read info is saved as a timestamped
file inside a per-device folder. The archive keeps one folder for every device that ever
connected, named after the device:

    <archive root>/                    # default: ~/.revive/devices (env REVIVE_DEVICE_ARCHIVE)
      Infinix Hot 8 X650B/             # one folder per unique device
        device.json                    # identity record: name, hash, first/last seen, counts
        read_info/                     # one file per hardware read — NEVER overwritten
          read_info_20261001_194503.json
          read_info_20261001_194504.json
        full_dump/                     # full flash dumps (hard link or copy, timestamped)
          dump_20261001_195012.bin
        partitions/                    # captured partition tables
          partitions_20261001_194503.json
        notes/                         # free-form technician notes

The rules (full text in RULES.md):

* A device folder is keyed by the read info. Two read infos that match 100 percent on every
  stable hardware field (USB id, vendor/product/serial strings, chip, hwcode, storage type
  and size, backend) belong to the same device and share one folder.
* Variants of the same model (e.g. Infinix Hot 8: X650 vs X650B vs X650C) report different
  hardware fields, so each variant gets its own folder.
* The same device connecting multiple times never overwrites: every file name carries a
  timestamp that includes the seconds, and if that name is already taken a suffix is
  appended instead.
* Session-only fields (mode, bus/address, capture time, security flags) are stored in the
  file but do not change the device's identity.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .. import util

ARCHIVE_ENV_VAR = "REVIVE_DEVICE_ARCHIVE"
DEFAULT_ARCHIVE_DIR = "~/.revive/devices"
MAX_NAME_LEN = 120

#: Sub-folders every device folder gets (Rule 1).
SUBFOLDERS = ("read_info", "full_dump", "partitions", "notes")

#: The stable hardware fields of a read info. "100 percent match" is computed over exactly
#: these fields; anything else (mode, bus, address, timestamps, security flags, notes) is
#: session data and never splits one physical device into two folders.
IDENTITY_FIELDS = (
    "usb_id", "vid", "pid", "manufacturer", "product", "serial",
    "backend", "chip", "hwcode", "storage", "storage_size", "simulated",
)


# --------------------------------------------------------------------------------------
# Roots and naming
# --------------------------------------------------------------------------------------

def default_archive_root() -> Path:
    """Where the device archive lives: $REVIVE_DEVICE_ARCHIVE or ~/.revive/devices."""
    raw = os.environ.get(ARCHIVE_ENV_VAR) or DEFAULT_ARCHIVE_DIR
    return Path(raw).expanduser()


def _resolve_root(root: Optional[os.PathLike]) -> Path:
    return Path(str(root)).expanduser() if root else default_archive_root()


def _slug(name: str) -> str:
    """Filesystem-safe folder name, spaces kept, unsafe chars replaced, length capped."""
    name = util.safe_filename(str(name), "device")
    name = re.sub(r"\s+", " ", name).strip()
    if len(name) > MAX_NAME_LEN:
        cut = name[:MAX_NAME_LEN]
        if " " in cut:
            cut = cut.rsplit(" ", 1)[0]
        name = cut.strip()
    return name or "device"


def device_name_from_info(info: Mapping[str, Any]) -> str:
    """Pick the human name of a device from its read info.

    Preference: product string (fastboot ``product``/USB iProduct) -> "manufacturer chip"
    -> chip -> usb_id. Variants of a model (X650 / X650B / X650C) usually differ in the
    product string or hwcode, which is exactly what makes their folders separate.
    """
    info = normalize_read_info(info)
    product = info.get("product") or ""
    manufacturer = info.get("manufacturer") or ""
    chip = info.get("chip") or ""
    usb_id = info.get("usb_id") or ""
    for candidate in (
        product,
        f"{manufacturer} {chip}" if manufacturer and chip else "",
        f"{manufacturer} {product}" if manufacturer and product else "",
        chip,
        usb_id.replace(":", "-") if usb_id else "",
    ):
        if candidate:
            return _slug(candidate)
    return "device"


# --------------------------------------------------------------------------------------
# Read-info normalisation + identity
# --------------------------------------------------------------------------------------

def _hex4(value: Any) -> str:
    """123 / '0x0e8d' / '0e8d' -> '0e8d'."""
    if value is None or value == "":
        return ""
    if isinstance(value, int):
        return f"{value:04x}"
    text = str(value).strip().lower()
    text = text[2:] if text.startswith("0x") else text
    try:
        return f"{int(text, 16):04x}"
    except ValueError:
        return text


def _hwcode(value: Any, hwcode_int: Any = None) -> str:
    """Normalise hwcode to uppercase '0xXXXX' (or '' when unknown)."""
    if value is None and hwcode_int is None:
        return ""
    if hwcode_int is not None:
        try:
            return f"0x{int(hwcode_int):04X}"
        except (TypeError, ValueError):
            pass
    if isinstance(value, int):
        return f"0x{int(value):04X}"
    text = str(value).strip().upper()
    if not text:
        return ""
    if text.startswith("0X"):
        return f"0x{int(text, 16):04X}" if _looks_hex(text[2:]) else text
    if _looks_hex(text):
        return f"0x{int(text, 16):04X}"
    return text


def _looks_hex(text: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Fa-f]+", text or ""))


def normalize_read_info(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Reduce any read-info shape (USB detect entry, DeviceInfo dict, intercept telemetry)
    to one canonical record. Extra keys are ignored; missing keys become ''/None."""
    raw = raw or {}
    extras = raw.get("extras") if isinstance(raw.get("extras"), Mapping) else {}
    telemetry = raw.get("telemetry") if isinstance(raw.get("telemetry"), Mapping) else {}

    vid = _hex4(raw.get("vid", telemetry.get("vid")))
    pid = _hex4(raw.get("pid", telemetry.get("pid")))
    usb_id = str(raw.get("usb_id") or raw.get("id") or "").strip().lower().replace("-", ":")
    if not usb_id and (vid or pid):
        usb_id = f"{vid or '0000'}:{pid or '0000'}"
    if not vid and ":" in usb_id:            # read infos that only carry the combined id
        vid, _, split_pid = usb_id.partition(":")
        if not pid:
            pid = split_pid

    storage = str(raw.get("storage") or "").strip().casefold()
    storage_size = raw.get("storage_size")
    if storage_size is not None:
        try:
            storage_size = int(storage_size)
        except (TypeError, ValueError):
            storage_size = None

    simulated = bool(
        raw.get("simulated")
        or extras.get("simulated")
        or telemetry.get("simulated")
        or "simulated" in str(raw.get("backend") or "")
    )

    return {
        "usb_id": usb_id,
        "vid": vid,
        "pid": pid,
        "manufacturer": str(raw.get("manufacturer") or raw.get("vendor") or "").strip(),
        "product": str(raw.get("product") or raw.get("model") or "").strip(),
        "serial": str(raw.get("serial") or "").strip(),
        "backend": str(raw.get("backend") or "").strip().lower(),
        "chip": str(raw.get("chip") or "").strip(),
        "hwcode": _hwcode(raw.get("hwcode"), raw.get("hwcode_int", telemetry.get("hwcode_int"))),
        "storage": storage,
        "storage_size": storage_size,
        "simulated": simulated,
        # session fields, stored for reference but NOT part of the identity:
        "mode": str(raw.get("mode") or "").strip(),
        "label": str(raw.get("label") or "").strip(),
    }


def identity_of(raw: Mapping[str, Any]) -> str:
    """SHA-256 over the stable hardware fields of a read info (Rule 1's "100 percent match")."""
    fields = {key: normalize_read_info(raw).get(key) for key in IDENTITY_FIELDS}
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------
# Folder lookup / creation
# --------------------------------------------------------------------------------------

def _read_device_json(device_dir: Path) -> Optional[Dict[str, Any]]:
    marker = device_dir / "device.json"
    if not marker.exists():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def find_device_dir(root: Path, identity: str) -> Optional[Path]:
    """The existing device folder whose identity matches 100 percent, if any."""
    if not root.exists():
        return None
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        record = _read_device_json(child)
        if record and record.get("identity") == identity:
            return child
    return None


def _unique_device_name(root: Path, name: str, identity: str) -> str:
    """A folder name that no *other* device already uses ('name', 'name 2', 'name 3', ...)."""
    candidate = name
    n = 2
    while True:
        folder = root / candidate
        if not folder.exists():
            return candidate
        record = _read_device_json(folder)
        if record and record.get("identity") == identity:
            return candidate
        candidate = f"{name} {n}"
        n += 1


def _unique_in_dir(directory: Path, stem: str, suffix: str) -> Path:
    """A file path that does not exist yet. Never overwrites: stem_02, stem_03, ..."""
    candidate = directory / f"{stem}{suffix}"
    n = 2
    while candidate.exists():
        candidate = directory / f"{stem}_{n:02d}{suffix}"
        n += 1
    return candidate


def _resolve_device_dir(root: Path, norm: Dict[str, Any], ident: str) -> tuple[Path, bool]:
    """Find the folder for this identity or create it (returns (dir, created))."""
    existing = find_device_dir(root, ident)
    if existing is not None:
        return existing, False
    name = _unique_device_name(root, device_name_from_info(norm), ident)
    folder = root / name
    return folder, True


def resolve_device_dir(root: Optional[os.PathLike], device: str) -> Path:
    """Resolve a device folder by exact name or unambiguous prefix (for the CLI)."""
    base = _resolve_root(root)
    if not base.exists():
        raise ValueError(f"no device archive at {base} (no devices archived yet)")
    exact = base / device
    if exact.is_dir():
        return exact
    low = str(device).strip().lower()
    dirs = [d for d in sorted(base.iterdir()) if d.is_dir()]
    matches = [d for d in dirs if d.name.lower().startswith(low)]
    if len(matches) == 1:
        return matches[0]
    if not matches:                          # fall back to a unique substring ("X650B" ...)
        matches = [d for d in dirs if low in d.name.lower()]
        if len(matches) == 1:
            return matches[0]
    if not matches:
        names = ", ".join(d.name for d in dirs) or "(empty)"
        raise ValueError(f"no device folder matching {device!r}; archive has: {names}")
    raise ValueError(
        f"device {device!r} is ambiguous: " + ", ".join(d.name for d in matches)
    )


def _update_device_json(device_dir: Path, norm: Dict[str, Any], ident: str,
                        now: datetime, source: str, *,
                        read_info: bool = False, dump: Optional[str] = None) -> None:
    record = _read_device_json(device_dir) or {"name": device_dir.name}
    iso = now.isoformat(timespec="seconds")
    record.update({
        "name": record.get("name") or device_dir.name,
        "identity": ident,
        "usb_id": norm.get("usb_id") or "",
        "vid": norm.get("vid") or "",
        "pid": norm.get("pid") or "",
        "manufacturer": norm.get("manufacturer") or "",
        "product": norm.get("product") or "",
        "serial": norm.get("serial") or "",
        "backend": norm.get("backend") or "",
        "chip": norm.get("chip") or "",
        "hwcode": norm.get("hwcode") or "",
        "storage": norm.get("storage") or "",
        "storage_size": norm.get("storage_size"),
        "simulated": norm.get("simulated", False),
        "first_seen": record.get("first_seen") or iso,
        # last_seen tracks the device, not our bookkeeping: placing a dump file later
        # must not pretend the device re-connected.
        "last_seen": iso if read_info else (record.get("last_seen") or iso),
        "connects": int(record.get("connects") or 0) + (1 if read_info else 0),
        "read_info_files": int(record.get("read_info_files") or 0) + (1 if read_info else 0),
        "full_dumps": int(record.get("full_dumps") or 0) + (1 if dump else 0),
        "last_source": source,
        "updated_at": iso,
    })
    if dump:
        record["last_dump_file"] = dump
        record["last_dump_at"] = iso
    counts = record.get("source_counts")
    if not isinstance(counts, dict):
        counts = {}
    counts[source] = int(counts.get(source) or 0) + 1
    record["source_counts"] = counts
    util.atomic_write(device_dir / "device.json",
                      json.dumps(record, indent=2, default=str).encode("utf-8"))


# --------------------------------------------------------------------------------------
# The archive operations (Rule 1)
# --------------------------------------------------------------------------------------

def _as_datetime(when: Any) -> datetime:
    if when is None:
        return datetime.now()
    if isinstance(when, datetime):
        return when
    try:
        return datetime.fromisoformat(str(when))
    except ValueError:
        return datetime.now()


def archive_read_info(
    read_info: Mapping[str, Any],
    *,
    root: Optional[os.PathLike] = None,
    source: str = "detect",
    partitions: Optional[List[Dict[str, Any]]] = None,
    when: Any = None,
) -> Dict[str, Any]:
    """Save one hardware read of a device (Rule 1).

    Creates the per-device folder (named after the device, found by 100-percent identity
    match) and writes ``read_info/read_info_<YYYYmmdd_HHMMSS>.json``. Nothing is ever
    overwritten: a taken file name gets a ``_02``/``_03`` suffix instead.
    """
    base = _resolve_root(root)
    now = _as_datetime(when)
    ts = now.strftime("%Y%m%d_%H%M%S")

    norm = normalize_read_info(read_info)
    ident = identity_of(norm)
    device_dir, created = _resolve_device_dir(base, norm, ident)
    util.ensure_dir(device_dir)
    for sub in SUBFOLDERS:
        util.ensure_dir(device_dir / sub)

    payload = {
        "captured_at": now.isoformat(timespec="seconds"),
        "captured_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "source": source,
        "device": norm,
        "identity": ident,
        "read_info": dict(read_info or {}),
    }
    file = _unique_in_dir(device_dir / "read_info", f"read_info_{ts}", ".json")
    util.atomic_write(file, json.dumps(payload, indent=2, default=str).encode("utf-8"))

    partitions_file: Optional[Path] = None
    if partitions:
        pfile = _unique_in_dir(device_dir / "partitions", f"partitions_{ts}", ".json")
        util.atomic_write(pfile, json.dumps(
            {"captured_at": now.isoformat(timespec="seconds"), "partitions": list(partitions)},
            indent=2, default=str,
        ).encode("utf-8"))
        partitions_file = pfile

    _update_device_json(device_dir, norm, ident, now, source, read_info=True)

    return {
        "ok": True,
        "root": str(base),
        "device_folder": str(device_dir),
        "device_name": device_dir.name,
        "identity": ident,
        "file": str(file),
        "partitions_file": str(partitions_file) if partitions_file else None,
        "created": created,
        "when": now.isoformat(timespec="seconds"),
    }


def archive_dump_file(
    src: os.PathLike,
    *,
    root: Optional[os.PathLike] = None,
    read_info: Optional[Mapping[str, Any]] = None,
    device: Optional[str] = None,
    when: Any = None,
) -> Dict[str, Any]:
    """Place a full-flash dump file into a device's ``full_dump/`` folder (Rule 1).

    Prefers a hard link (zero extra disk space, same machine) and falls back to a copy.
    The file is timestamped and never overwritten.
    """
    base = _resolve_root(root)
    source = Path(str(src)).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"dump file not found: {source}")
    if read_info is None and not device:
        raise ValueError("pass read_info (dict) or device (folder name) to place the dump")

    now = _as_datetime(when)
    ts = now.strftime("%Y%m%d_%H%M%S")

    if read_info is not None:
        norm = normalize_read_info(read_info)
        ident = identity_of(norm)
        device_dir, _ = _resolve_device_dir(base, norm, ident)
    else:
        device_dir = resolve_device_dir(base, str(device))
        record0 = _read_device_json(device_dir) or {}
        norm = normalize_read_info(record0)
        ident = record0.get("identity") or ""
    util.ensure_dir(device_dir / "full_dump")

    suffix = source.suffix or ".bin"
    dest = _unique_in_dir(device_dir / "full_dump", f"dump_{ts}", suffix)
    linked = False
    try:
        os.link(str(source), str(dest))          # hard link first: zero extra disk space
        linked = True
    except OSError:
        shutil.copy2(str(source), str(dest))     # cross-filesystem fallback

    _update_device_json(device_dir, norm, ident, now, "full_dump", dump=dest.name)
    return {
        "ok": True,
        "root": str(base),
        "device_folder": str(device_dir),
        "device_name": device_dir.name,
        "file": str(dest),
        "linked": linked,
        "size": source.stat().st_size,
        "when": now.isoformat(timespec="seconds"),
    }


def list_devices(root: Optional[os.PathLike] = None) -> Dict[str, Any]:
    """List every device folder in the archive with its identity record + file counts."""
    base = _resolve_root(root)
    out: List[Dict[str, Any]] = []
    if base.exists():
        for child in sorted(base.iterdir()):
            if not child.is_dir():
                continue
            record = _read_device_json(child)
            if record is None:
                continue
            entry = dict(record)
            entry["name"] = child.name
            entry["folder"] = str(child)
            entry["read_info_count"] = len(list((child / "read_info").glob("*.json"))) \
                if (child / "read_info").is_dir() else 0
            entry["full_dump_count"] = len(list((child / "full_dump").glob("*"))) \
                if (child / "full_dump").is_dir() else 0
            out.append(entry)
    return {"ok": True, "root": str(base), "device_count": len(out), "devices": out}
