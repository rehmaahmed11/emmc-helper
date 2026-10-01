"""JSON API used by the web UI (and by anyone who wants to script Revive).

Every function here returns a plain dict so the HTTP layer stays trivial. Long operations are
handed to the job manager by the server; this module keeps the *what* (inspect, plan, extract)
separate from the *how it is served*.
"""
from __future__ import annotations

import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .. import util
from ..backends import describe_backends, get_backend
from ..core import chips, errors, usbmodes
from ..firmware import detect as fw_detect
from ..ops import convert, dump, plan, verify
from ..storage import bootimg, ext4fs, gpt, lz4blk, magic, sparse, superimg


def info(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tool": util.TOOL_NAME,
        "version": util.__version__,
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()}",
        "libusb": usbmodes.libusb_available(),
        "pyserial": usbmodes.pyserial_available(),
        "install_hint": usbmodes.install_hint(),
        "demo": bool(ctx.get("demo")),
        "backends": describe_backends(),
        "error_codes": len(errors.all_errors()),
        "chips": len(chips.all_chips()),
    }


# --------------------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------------------

def chips_list(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    query = str(payload.get("q", "")).strip().lower()
    out = []
    for chip in chips.all_chips():
        entry = chip.to_dict()
        if query and query not in chip.name.lower() and query not in entry["hwcode"].lower():
            continue
        out.append(entry)
    return {"chips": out, "count": len(out)}


def modes_list(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "modes": [
            {
                "mode": mode.mode, "label": mode.label, "vendor": mode.vendor,
                "backend": mode.backend, "flashable": mode.flashable,
                "description": mode.description, "advice": mode.advice,
                "power_hint": mode.power_hint,
            }
            for mode in usbmodes.MODES.values()
        ],
        "usb_ids": [
            {"vid": f"{u.vid:04x}", "pid": f"{u.pid:04x}", "mode": u.mode,
             "label": u.label, "notes": u.notes, "confidence": u.confidence}
            for u in usbmodes.USB_IDS
        ],
    }


def errors_list(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {"errors": [e.to_dict() for e in errors.all_errors()], "count": len(errors.all_errors())}


def errors_decode(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    text = str(payload.get("text", ""))
    return errors.triage(text)


def drivers(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    return usbmodes.driver_help()


# --------------------------------------------------------------------------------------
# Device work
# --------------------------------------------------------------------------------------

def detect(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from ..backends import detect as backend_detect

    result = backend_detect()
    data = result.to_dict()
    if ctx.get("demo"):
        data["demo"] = True
        data["devices"].insert(0, {
            "vid": "0e8d", "pid": "0003", "id": "0e8d:0003", "mode": usbmodes.MODE_MTK_BROM,
            "label": "MediaTek Boot ROM (BROM) [simulated]",
            "backend": "mtk", "flashable": True, "manufacturer": "MediaTek (simulated)",
            "product": "Simulated phone", "serial": "MOCK0001", "simulated": True,
            "description": "A simulated BROM device, so you can learn the workflow with no phone.",
            "advice": ["This is Demo mode: no hardware is involved."],
            "power_hint": "No cable needed in demo mode.",
        })
        data["suggested_backend"] = data.get("suggested_backend") or "mock"
    return data


def identify(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Open a backend and read chip/security/storage info."""
    backend_name = str(payload.get("backend") or "").strip()
    if ctx.get("demo") and not backend_name:
        backend_name = "mock"
    if not backend_name:
        detection = detect({}, ctx)
        backend_name = detection.get("suggested_backend") or ""
        if not backend_name:
            return {"ok": False, "error": "no device detected",
                    "hint": "Plug the phone in, or run in demo mode.",
                    "actions": detection.get("suggested_actions", [])}
    kwargs: Dict[str, Any] = {}
    if backend_name == "mock":
        kwargs["storage_path"] = ctx.get("demo_storage")
    backend = get_backend(backend_name, **kwargs)
    try:
        backend.open()
        info_obj = backend.identify()
        return {"ok": True, "backend": backend_name, "device": info_obj.to_dict(),
                "capabilities": backend.capabilities(), "log": backend.log,
                "warnings": backend.guard_tested()}
    except Exception as exc:
        return _error(exc)
    finally:
        try:
            backend.close()
        except Exception:
            pass


# --------------------------------------------------------------------------------------
# Firmware
# --------------------------------------------------------------------------------------

def inspect(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    package = fw_detect.detect(path)
    result = package.to_dict()
    result["ok"] = True

    # Extra detail for the UI: what is inside each image file.
    detail = []
    for entry in package.images[:40]:
        sig = magic.sniff_file(entry["path"])
        item = dict(entry)
        item["detected"] = sig.label
        item["confidence"] = sig.confidence
        if sig.kind in ("ext4", "f2fs", "erofs"):
            fs = ext4fs.inspect_file(entry["path"])
            if fs:
                item["filesystem"] = fs.to_dict()
        elif sig.kind == "super_image":
            try:
                sup = superimg.inspect(entry["path"])
                item["super"] = sup.to_dict()
            except Exception as exc:
                item["super_error"] = str(exc)
        elif sig.kind == "boot_image":
            try:
                item["boot"] = bootimg.parse(entry["path"]).to_dict()
            except Exception as exc:
                item["boot_error"] = str(exc)
        elif sig.kind == "android_sparse":
            try:
                item["sparse"] = sparse.inspect(entry["path"])
            except Exception as exc:
                item["sparse_error"] = str(exc)
        detail.append(item)
    result["images_detail"] = detail
    return result


def plan_flash(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    flash_plan = plan.plan_for_path(path)
    data = flash_plan.to_dict()
    data["ok"] = True
    data["rendered"] = plan.render_text(flash_plan)
    return data


# --------------------------------------------------------------------------------------
# Dump surgery and file tools
# --------------------------------------------------------------------------------------

def dump_analyse(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    report = dump.analyse(path, deep=bool(payload.get("deep", True)),
                         probe_per_partition=bool(payload.get("probe", True)))
    data = report.to_dict()
    data["ok"] = True
    return data


def dump_extract(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    out = payload.get("out") or str(Path(path).parent / (Path(path).stem + "_extracted"))
    only = payload.get("only")
    if isinstance(only, str):
        only = [item.strip() for item in only.split(",") if item.strip()]
    try:
        if payload.get("partition"):
            result = dump.extract(path, str(payload["partition"]), out)
        else:
            result = dump.extract_all(path, out, only=only or None)
        result["ok"] = True
        return result
    except Exception as exc:
        return _error(exc)


def dump_scan(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    hits = dump.scan(path)
    return {"ok": True, "hits": hits, "count": len(hits)}


def gpt_repair(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    apply_changes = bool(payload.get("apply"))
    report = gpt.repair_gpt(path, dry_run=not apply_changes)
    report["ok"] = True
    return report


def gpt_list(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    try:
        parsed = gpt.read_gpt(path)
        data = parsed.to_dict()
        data["ok"] = True
        return data
    except Exception as exc:
        return _error(exc)


def convert_file(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    mode = str(payload.get("mode") or "auto")
    out = payload.get("out")
    try:
        if mode == "sparse":
            result = convert.to_sparse(path, out)
        elif mode == "raw":
            result = convert.to_raw(path, out)
        elif mode == "lz4":
            result = convert.decompress_lz4(path, out)
        elif mode == "trim":
            result = convert.trim(path, out)
        elif mode == "boot":
            result = convert.extract_boot(path, out or str(Path(path).parent))
        else:
            result = convert.convert_auto(path, out)
        result["ok"] = True
        return result
    except Exception as exc:
        return _error(exc)


def super_list(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    try:
        return {"ok": True, **superimg.inspect(path).to_dict()}
    except Exception as exc:
        return _error(exc)


def super_extract(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    name = str(payload.get("partition") or "")
    if path is None or not name:
        return {"ok": False, "error": "path and partition are required"}
    out = payload.get("out") or str(Path(path).parent / f"{name}.img")
    try:
        return {"ok": True, **superimg.extract(path, name, out)}
    except Exception as exc:
        return _error(exc)


def manifest_create(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    try:
        return {"ok": True, **verify.create_manifest(path, payload.get("out"))}
    except Exception as exc:
        return _error(exc)


def manifest_verify(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    try:
        return {"ok": True, **verify.verify_manifest(path, payload.get("manifest"))}
    except Exception as exc:
        return _error(exc)


def verify_sparse(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    path = _require_path(payload)
    if path is None:
        return {"ok": False, "error": "a path is required"}
    try:
        result = verify.verify_sparse(path)
        return {"ok": bool(result.get("ok", True)), **result}
    except Exception as exc:
        return _error(exc)


def build_demo(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Create the synthetic firmware + dump so the UI can be explored with no phone."""
    out = Path(payload.get("out") or (Path.home() / "ReviveDemo"))
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
        import make_demo

        info_map = make_demo.make_demo_tree(out, corrupt_gpt=bool(payload.get("corrupt_gpt")))
        return {"ok": True, "paths": info_map}
    except Exception as exc:
        return _error(exc)


# --------------------------------------------------------------------------------------
# Routes table + helpers
# --------------------------------------------------------------------------------------

ROUTES: Dict[str, Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]] = {
    "info": info,
    "chips": chips_list,
    "modes": modes_list,
    "errors": errors_list,
    "errors.decode": errors_decode,
    "drivers": drivers,
    "detect": detect,
    "identify": identify,
    "inspect": inspect,
    "plan": plan_flash,
    "dump.analyse": dump_analyse,
    "dump.extract": dump_extract,
    "dump.scan": dump_scan,
    "gpt.list": gpt_list,
    "gpt.repair": gpt_repair,
    "convert": convert_file,
    "super.list": super_list,
    "super.extract": super_extract,
    "manifest.create": manifest_create,
    "manifest.verify": manifest_verify,
    "sparse.verify": verify_sparse,
    "demo.build": build_demo,
}

# Routes that touch the filesystem or a device - the UI asks for confirmation on these.
MUTATING = {"dump.extract", "gpt.repair", "convert", "super.extract", "manifest.create",
            "demo.build"}


def dispatch(route: str, payload: Optional[Dict[str, Any]] = None,
             ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = payload or {}
    ctx = ctx or {}
    handler = ROUTES.get(route)
    if handler is None:
        return {"ok": False, "error": f"unknown route {route!r}",
                "routes": sorted(ROUTES)}
    try:
        result = handler(payload, ctx)
        result.setdefault("ok", True)
        result["route"] = route
        result["elapsed"] = round(time.time() - ctx.get("started", time.time()), 4)
        return result
    except Exception as exc:
        return _error(exc)


def _require_path(payload: Dict[str, Any]) -> Optional[str]:
    raw = payload.get("path") or payload.get("folder")
    if not raw:
        return None
    return str(Path(str(raw)).expanduser())


def _error(exc: Exception) -> Dict[str, Any]:
    detail = getattr(exc, "detail", "")
    code = getattr(exc, "code", "")
    out: Dict[str, Any] = {
        "ok": False,
        "error": f"{type(exc).__name__}: {exc}",
        "error_code": code,
        "detail": detail,
        "traceback": None,
    }
    if code:
        info_obj = errors.get(code) or errors.decode(str(code))
        if info_obj:
            out["explanation"] = info_obj.to_dict()
    if not out["detail"] and isinstance(exc, (OSError, ValueError)):
        out["detail"] = "Check the path and that the file is not still being copied or downloaded."
    return out
