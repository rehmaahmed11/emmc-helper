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
from ..backends import describe_backends, get_backend, intercept_and_capture
from ..core import chips, errors, usbmodes
from ..firmware import detect as fw_detect
from ..ops import convert, dossier, dump, plan, verify
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
        out_dir = payload.get("out")
        dossier_info = None
        if out_dir:
            parts = []
            try:
                parts = backend.list_partitions()
            except Exception:
                parts = []
            dossier_info = dossier.save_device_dossier(
                out_dir=out_dir,
                device_info=info_obj,
                intercept_result=getattr(backend, "intercept_result", None),
                partitions=parts,
                backend_log=backend.log,
            )
        res = {"ok": True, "backend": backend_name, "device": info_obj.to_dict(),
               "capabilities": backend.capabilities(), "log": backend.log,
               "warnings": backend.guard_tested()}
        if dossier_info:
            res["dossier"] = dossier_info
        return res
    except Exception as exc:
        return _error(exc)
    finally:
        try:
            backend.close()
        except Exception:
            pass


def intercept(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Run the sub-ms handshake interceptor + force-entry engine and build the device dossier."""
    backend_name = str(payload.get("backend") or "auto").strip()
    demo_mode = bool(ctx.get("demo") or payload.get("demo") or backend_name == "mock")
    out_dir = payload.get("out", dossier.DEFAULT_DOSSIER_DIR)
    if payload.get("no_save"):
        out_dir = None
    return intercept_and_capture(
        backend_name=backend_name,
        timeout=float(payload.get("timeout", 15.0)),
        force_entry=bool(payload.get("force", True)),
        force_brom=bool(payload.get("force_brom", False)),
        out_dir=out_dir,
        demo=demo_mode,
        storage_path=ctx.get("demo_storage"),
    )


def dossier_list(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """List all connected/handshaked devices recorded in the dossier folder."""
    out_dir = payload.get("out") or payload.get("path") or dossier.DEFAULT_DOSSIER_DIR
    return dossier.list_dossiers(out_dir)


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
# LAB TESTING - virtual devices (revive.lab_testing). Nothing here touches hardware.
# --------------------------------------------------------------------------------------

from ..lab_testing import SPEC_OPTIONS as SPEC_OPTION_NAMES      # noqa: E402  (used by lab.*)


def _lab(payload: Dict[str, Any], ctx: Dict[str, Any]):
    """The lab database, rooted where the server was told (or ./lab_devices)."""
    from ..lab_testing import LabBench

    root = payload.get("lab") or ctx.get("lab_root") or None
    return LabBench(root)


def _lab_device(payload: Dict[str, Any], ctx: Dict[str, Any]):
    bench = _lab(payload, ctx)
    device = bench.get(payload.get("device"))
    device.attach_log()
    return bench, device


def lab_info(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Everything the LAB TESTING tab needs to populate itself."""
    from ..lab_testing import brick_types
    from ..lab_testing.device import PROFILES
    from ..lab_testing.scenarios import all_scenarios

    bench = _lab(payload, ctx)
    return {
        "ok": True, "root": str(bench.root),
        "profiles": [p.to_dict() for p in PROFILES.values()],
        "scenarios": [s.to_dict() for s in all_scenarios()],
        "brick_types": brick_types(),
        "devices": bench.list_devices(),
        "active": bench.summary().get("active", ""),
        "health_states": ["healthy", "warning", "dead"],
    }


def lab_list(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    bench = _lab(payload, ctx)
    return {"ok": True, **bench.summary()}


def _chip_options(payload: Dict[str, Any]) -> Dict[str, Any]:
    """The chip settings a request carries, either as `options` or as flat keys."""
    options = dict(payload.get("options") or {})
    for key in ("manufacturer", "size", "capacity", "health", "pre_eol", "firmware_version",
                "product_name", "serial", "write_cycles", "bad_blocks"):
        if payload.get(key) not in (None, "") and key not in options:
            options[key] = payload[key]
    return options


def lab_create(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from ..lab_testing import apply_options

    bench = _lab(payload, ctx)
    device = bench.create(chip=str(payload.get("chip") or "MT6768"),
                          storage=payload.get("storage"),
                          image_bytes=int(payload.get("image_bytes") or 32 * 1024 * 1024),
                          vendor=payload.get("vendor"), model=payload.get("model"))
    try:
        applied = apply_options(device.emmc, _chip_options(payload))
        if applied:
            device.save()
        return {"ok": True, "device": device.to_dict(),
                "partitions": [p.to_dict() for p in device.partitions],
                "health": device.emmc.health(), "boot": device.boot().to_dict(),
                "applied": applied, "chip_options": sorted(SPEC_OPTION_NAMES)}
    finally:
        device.close()


def lab_set(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Change what the active device's eMMC reports: maker, size, health, firmware version."""
    from ..lab_testing import apply_options

    bench, device = _lab_device(payload, ctx)
    try:
        applied = apply_options(device.emmc, _chip_options(payload))
        device.save()
        bench.update_status(device.id, device.status)
        decoded = device.emmc.registers_decoded()
        return {"ok": True, "device": device.id, "applied": applied,
                "health": device.emmc.health(), "verdict": decoded["verdict"],
                "summary": decoded["summary"], "signals": device.emmc.signals(),
                "chip_options": sorted(SPEC_OPTION_NAMES)}
    finally:
        device.close()


def lab_status(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from ..lab_testing import collect_signals

    bench, device = _lab_device(payload, ctx)
    try:
        return {"ok": True, "device": device.to_dict(), "verify": device.verify(),
                "signals": collect_signals(device)["signals"],
                "health": device.emmc.health(), "boot": device.boot().to_dict(),
                "ext_csd": device.emmc.registers(),
                "partitions": [p.to_dict() for p in device.partitions]}
    finally:
        device.close()


def lab_brick(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from ..lab_testing import BrickEngine

    bench, device = _lab_device(payload, ctx)
    try:
        options = payload.get("options") or {}
        if isinstance(options, str):
            options = {k: v for k, v in (item.split("=", 1)
                                         for item in options.split(",") if "=" in item)}
        result = BrickEngine(device).apply(str(payload.get("type") or "gpt"), options)
        bench.update_status(device.id, device.status)
        return {"ok": True, **result}
    finally:
        device.close()


def lab_repair(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from ..lab_testing import BrickEngine

    bench, device = _lab_device(payload, ctx)
    try:
        result = BrickEngine(device).repair(payload.get("type"),
                                            payload.get("options") or {})
        bench.update_status(device.id, device.status)
        return {"ok": bool(result.get("repaired")), **result}
    finally:
        device.close()


def lab_verify(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    bench, device = _lab_device(payload, ctx)
    try:
        check = device.verify()
        bench.update_status(device.id, device.status)
        return {"ok": check["ok"], **check}
    finally:
        device.close()


def lab_reset(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from ..lab_testing import BrickEngine

    bench, device = _lab_device(payload, ctx)
    try:
        info = BrickEngine(device).reset()
        bench.update_status(device.id, device.status)
        return {"ok": True, **info}
    finally:
        device.close()


def lab_run(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """The graded workflow: brick -> diagnose -> repair -> verify."""
    from ..lab_testing import RecoveryTester
    from ..lab_testing import lab_report as lab_report_mod

    bench, device = _lab_device(payload, ctx)
    try:
        tester = RecoveryTester(device, bench=bench)
        scenarios = payload.get("scenarios")
        if isinstance(scenarios, str):
            scenarios = [item.strip() for item in scenarios.split(",") if item.strip()]
        if not scenarios:
            scenarios = ([str(payload["scenario"])] if payload.get("scenario")
                         else tester.engine.available_ids())
        options = payload.get("options") or {}
        results = []
        for scenario_id in scenarios:
            if len(scenarios) > 1:
                device.reset()
                device.save()
            results.append(tester.run(scenario_id, options,
                                      repair=not payload.get("no_repair")))
        report = lab_report_mod.build_report(results, bench.summary())
        paths = lab_report_mod.write_reports(report, device.reports_dir)
        from ..util import atomic_write, to_json

        atomic_write(bench.root / "last_report.json", to_json(report).encode("utf-8"))
        return {"ok": all(r.result == "PASS" for r in results),
                "result": report.get("result"), "runs": [r.to_dict() for r in results],
                "report": report, "paths": paths,
                "passed": sum(1 for r in results if r.result == "PASS"),
                "total": len(results)}
    finally:
        device.close()


def lab_report(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from ..lab_testing import lab_report as lab_report_mod

    bench, device = _lab_device(payload, ctx)
    try:
        report = lab_report_mod.build_from_device(device, bench)
        paths = lab_report_mod.write_reports(report, device.reports_dir)
        html = ""
        try:
            html = Path(paths["html"]).read_text(encoding="utf-8")
        except OSError:
            pass
        # `paths` keeps the two filenames; the rendered document travels separately, because
        # `paths["html"]` and the document cannot both own the "html" key.
        return {"ok": True, **paths, "paths": paths, "report": report, "html_content": html}
    finally:
        device.close()


def lab_history(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    bench = _lab(payload, ctx)
    return {"ok": True, "history": bench.history(int(payload.get("limit") or 50)),
            **{k: v for k, v in bench.summary().items() if k != "devices"}}


def lab_delete(payload: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    bench = _lab(payload, ctx)
    name = str(payload.get("device") or "")
    if not name:
        return {"ok": False, "error": "a device id is required"}
    return {"ok": True, **bench.delete(name)}


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
    "intercept": intercept,
    "dossier.list": dossier_list,
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
    # LAB TESTING
    "lab.info": lab_info,
    "lab.list": lab_list,
    "lab.create": lab_create,
    "lab.status": lab_status,
    "lab.brick": lab_brick,
    "lab.repair": lab_repair,
    "lab.verify": lab_verify,
    "lab.set": lab_set,
    "lab.reset": lab_reset,
    "lab.run": lab_run,
    "lab.report": lab_report,
    "lab.history": lab_history,
    "lab.delete": lab_delete,
}

# Routes that touch the filesystem or a device - the UI asks for confirmation on these.
MUTATING = {"dump.extract", "gpt.repair", "convert", "super.extract", "manifest.create",
            "demo.build", "intercept",
            # The lab writes files (virtual device images) but never touches hardware.
            "lab.create", "lab.brick", "lab.repair", "lab.reset", "lab.run", "lab.report",
            "lab.delete", "lab.set"}


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
