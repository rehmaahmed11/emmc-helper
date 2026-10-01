"""Revive command line interface.

Design rules:
  * read-only operations are the default; anything that writes needs `--apply` / `--confirm`
  * every command can print `--json` for scripting
  * when something fails, the failure explains itself and the next step
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import util
from .backends import describe_backends, get_backend
from .core import chips, errors, usbmodes
from .firmware import detect as fw_detect
from .ops import convert, dump, plan as plan_mod, verify
from .storage import bootimg, gpt, magic, sparse, superimg
from .util import human_size

C = util.colorize
ICON = {util.SEV_OK: "OK", util.SEV_INFO: "--", util.SEV_WARN: "!!", util.SEV_ERROR: "XX",
        util.SEV_FATAL: "STOP"}


# --------------------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------------------

def print_findings(findings: List[Dict[str, Any]], verbose: bool = False) -> None:
    for finding in findings:
        severity = finding.get("severity", util.SEV_INFO)
        if severity == util.SEV_OK and not verbose:
            continue
        tag = ICON.get(severity, "--")
        color = {util.SEV_WARN: "yellow", util.SEV_ERROR: "red", util.SEV_FATAL: "magenta",
                 util.SEV_OK: "green", util.SEV_INFO: "cyan"}.get(severity, "dim")
        print(f"  [{C(tag, color)}] {finding.get('title', '')}")
        if finding.get("detail"):
            for line in str(finding["detail"]).splitlines():
                print(f"        {line}")
        for fix in finding.get("fixes", []):
            print(f"        -> {fix}")


def print_kv(data: Dict[str, Any], indent: str = "  ") -> None:
    for key, value in data.items():
        if value in ("", None, [], {}):
            continue
        if isinstance(value, dict):
            print(f"{indent}{key}:")
            print_kv(value, indent + "  ")
        elif isinstance(value, list):
            if all(not isinstance(v, (dict, list)) for v in value):
                print(f"{indent}{key}: {', '.join(str(v) for v in value)}")
            else:
                print(f"{indent}{key}:")
                for item in value:
                    print(f"{indent}  - {item}")
        else:
            print(f"{indent}{key}: {value}")


def fail(message: str, code: str = "", detail: str = "") -> int:
    print(C(f"error: {message}", "red"), file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    if code:
        info = errors.get(code) or errors.decode(str(code))
        if info:
            print(f"\n{info.headline()}", file=sys.stderr)
            for fix in info.fixes[:4]:
                print(f"  -> {fix}", file=sys.stderr)
    return 1


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------

def cmd_info(args) -> int:
    pay = {
        "tool": util.TOOL_NAME, "version": util.__version__,
        "python": sys.version.split()[0], "platform": f"{sys.platform}",
        "usb_support": usbmodes.libusb_available(),
        "serial_support": usbmodes.pyserial_available(),
        "install_usb": usbmodes.install_hint() if not usbmodes.libusb_available() else "",
        "known_error_codes": len(errors.all_errors()),
        "known_chips": len(chips.all_chips()),
    }
    if args.json:
        print(json.dumps(pay, indent=2))
        return 0
    print(util.BANNER)
    print_kv(pay)
    print("\n  Backends:")
    for backend in describe_backends():
        flags = []
        for cap in ("read", "write", "erase", "partitions"):
            if backend.get(cap):
                flags.append(cap)
        state = "verified" if backend.get("tested") else "unverified on hardware"
        available = "" if backend.get("available", True) else "  (needs USB libraries)"
        print(f"    {backend['name']:<10} {backend['label']:<28} {state:<24}"
              f"{','.join(flags) or '-':<28}{available}")
    if not pay["usb_support"]:
        print(f"\n  USB is not available yet. Install it with:\n    {pay['install_usb']}")
        print("  Everything that operates on files already works:")
        print("    revive inspect <firmware folder>   revive plan <folder>   revive dump-analyse <dump>")
    return 0


def cmd_detect(args) -> int:
    from .backends import detect as backend_detect

    result = backend_detect()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0
    if not result.devices:
        print(C("No phone detected on USB.", "yellow"))
    for device in result.devices:
        print(f"{C(device['id'], 'bold')}  {device['label']}")
        print(f"    mode: {device['mode']}   backend: {device.get('backend') or 'n/a'}")
        if device.get("description"):
            print(f"    {device['description']}")
        if device.get("power_hint"):
            print(f"    plug-in: {device['power_hint']}")
    for warning in result.warnings:
        print(C(warning, "yellow"))
    if result.serial_ports:
        print("\nSerial/COM ports that may be download interfaces:")
        for port in result.serial_ports:
            print(f"    {port['port']:<16} {port['description'][:50]:<50} {port.get('likely','')}")
    print("\nNext steps:")
    for step in result.suggested_actions:
        print(f"  - {step}")
    return 0


def cmd_identify(args) -> int:
    backend_name = args.backend
    if not backend_name:
        if args.demo:
            backend_name = "mock"
        else:
            from .backends import detect as backend_detect

            backend_name = backend_detect().suggested_backend or ""
            if not backend_name:
                return fail("no device detected; pass --backend or plug a phone in",
                            code="no_device")
    kwargs: Dict[str, Any] = {}
    if backend_name == "mock":
        kwargs["storage_path"] = Path(args.storage) if args.storage else None
    backend = get_backend(backend_name, **kwargs)
    try:
        backend.open()
        info = backend.identify()
        if args.loader and hasattr(backend, "upload_loader"):
            backend.upload_loader(args.loader)
            info = backend.identify()
        if args.json:
            print(json.dumps({"device": info.to_dict(),
                              "capabilities": backend.capabilities(),
                              "log": backend.log}, indent=2))
            return 0
        print(f"{C(info.chip or 'Device', 'bold')}  ({backend.label})")
        print_kv(info.to_dict(), "  ")
        for note in info.notes:
            print(C(f"  note: {note}", "yellow"))
        return 0
    except Exception as exc:
        return fail(str(exc), code=getattr(exc, "code", ""),
                    detail=getattr(exc, "detail", ""))
    finally:
        try:
            backend.close()
        except Exception:
            pass


def cmd_drivers(args) -> int:
    info = usbmodes.driver_help()
    if args.udev_rule:
        rule = usbmodes.udev_rules_text()
        if args.write:
            target = Path("/etc/udev/rules.d/99-revive.rules")
            try:
                target.write_text(rule)
                print(f"wrote {target}\nrun: sudo udevadm control --reload-rules && sudo udevadm trigger")
            except OSError as exc:
                print(rule)
                return fail(f"could not write {target}: {exc} (try sudo)")
        else:
            print(rule)
        return 0
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(C(f"Drivers for {info['os']}", "bold"))
    print(f"  {info['summary']}\n")
    for step in info["steps"]:
        print(f"  - {step}")
    for item in info.get("where_to_get", []):
        print(f"  * {item}")
    print("\n  Universal rules that fix most failures:")
    for tip in info["universal_tips"]:
        print(f"  - {tip}")
    return 0


def cmd_chips(args) -> int:
    query = (args.search or "").lower()
    rows = []
    for chip in chips.all_chips():
        if query and query not in chip.name.lower() and query not in f"0x{chip.hwcode:04x}":
            continue
        rows.append(chip)
    if args.json:
        print(json.dumps([c.to_dict() for c in rows], indent=2))
        return 0
    print(f"{'hw code':<10} {'chip':<44} {'DA mode':<14} {'confidence':<10} storage")
    print("-" * 100)
    for chip in sorted(rows, key=lambda c: c.hwcode):
        print(f"0x{chip.hwcode:04X}    {chip.name[:44]:<44} {chip.da_mode_name[:14]:<14}"
              f"{chip.confidence:<10} {chip.storage[:24]}")
    print(f"\n{len(rows)} chips. Confidence 'derived'/'reported' entries are not vendor-confirmed -")
    print("always check the scatter file or the device itself before flashing.")
    return 0


def cmd_err(args) -> int:
    text = " ".join(args.text)
    if getattr(args, "log", None):
        try:
            text = Path(args.log).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return fail(f"cannot read {args.log}: {exc}")
        if args.text:
            text += " " + " ".join(args.text)
    if not text.strip():
        return fail("give me an error code, a symbol like S_BROM_CMD_STARTCMD_FAIL, or --log <file>")
    result = errors.triage(text)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    if not result["matched"]:
        print(C("That code is not in the table yet.", "yellow"))
        print(result.get("note", ""))
        print("\nGeneral next steps:")
        for step in result["advice"]:
            print(f"  - {step}")
        return 1
    info = result["error"]
    color = {"fatal": "magenta", "warn": "yellow", "info": "cyan"}.get(info["severity"], "red")
    print(C(f"{info['code']} {info['symbol']}", "bold") + C(f"   [{info['phase']}]", "dim"))
    print(f"\n{info['meaning']}\n")
    print(C("Why it happens (most likely first):", "bold"))
    for cause in info["causes"]:
        print(f"  - {cause}")
    print(C("\nWhat to do (cheapest first):", "bold"))
    for i, fix in enumerate(info["fixes"], 1):
        print(f"  {i}. {fix}")
    if info.get("notes"):
        print(C(f"\nnote: {info['notes']}", "dim"))
    print(C("\nThen:", "bold"))
    for step in result["advice"]:
        print(f"  - {step}")
    return 0


def cmd_inspect(args) -> int:
    pkg = fw_detect.detect(args.path)
    if args.json:
        print(json.dumps(pkg.to_dict(), indent=2))
        return 0 if pkg.ok_to_flash else 1
    print(C(pkg.label, "bold"))
    print(f"  path: {pkg.root}")
    print_kv({"platform": pkg.platform, "storage": pkg.storage,
              "images": len(pkg.images), "total_size": human_size(pkg.total_size),
              "scatter": pkg.scatter, "rawprogram": pkg.rawprogram_files,
              "patch": pkg.patch_files, "pac": pkg.pac_files, "da": pkg.da_files,
              "loaders": pkg.loaders, "archives": pkg.archives}, "  ")
    print()
    print_findings([f.to_dict() for f in pkg.findings], verbose=args.verbose)
    if pkg.images and args.verbose:
        print("\n  Contents by file detection:")
        for entry in pkg.images[:30]:
            sig = magic.sniff_file(entry["path"])
            print(f"    {entry['name'][:40]:<40} {human_size(entry['size']):>10}  {sig.label}")
    print()
    print("  OK to flash" if pkg.ok_to_flash else C("  NOT safe to flash - fix the items above", "red"))
    return 0 if pkg.ok_to_flash else 1


def cmd_plan(args) -> int:
    flash_plan = plan_mod.plan_for_path(args.path)
    if args.json:
        print(json.dumps(flash_plan.to_dict(), indent=2))
        return 0 if flash_plan.ok_to_proceed else 1
    print(plan_mod.render_text(flash_plan))
    return 0 if flash_plan.ok_to_proceed else 1


def cmd_dump_analyse(args) -> int:
    report = dump.analyse(args.path, deep=not args.fast)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0
    print(f"{C('Dump report', 'bold')}  {report.path}")
    print_kv({"file_size": human_size(report.file_size), "gpt_offset": report.gpt_offset,
              "sector_size": report.sector_size,
              "header_crc": "ok" if report.header_crc_ok else "BAD",
              "entries_crc": "ok" if report.entries_crc_ok else "BAD",
              "backup_used": report.backup_used,
              "partitions": len(report.partitions),
              "unaccounted": human_size(report.unaccounted)}, "  ")
    print()
    print(f"  {'partition':<22} {'offset':>12} {'size':>11}  {'content':<20} issues")
    print("  " + "-" * 100)
    for part in report.partitions:
        print(f"  {part.name[:22]:<22} 0x{part.offset:010x} {human_size(part.size):>11}  "
              f"{part.kind[:20]:<20} {', '.join(part.issues)}")
    if not report.partitions:
        print(C("  no partition table found in this file.", "yellow"))
        print("  If this is a partial read or the table was wiped, try:")
        print(f"    revive dump-scan {report.path}      # find partitions by signature")
    print()
    print_findings([f.to_dict() for f in report.findings], verbose=args.verbose)
    return 0


def cmd_dump_extract(args) -> int:
    out = Path(args.out) if args.out else Path(args.path).parent / (Path(args.path).stem + "_extracted")
    if args.partition:
        result = dump.extract(args.path, args.partition, out)
        print(f"extracted {result['partition']} -> {result['output']} ({human_size(result['size'])})")
        print(f"sha256: {result['sha256']}")
        return 0
    only = [x.strip() for x in args.only.split(",")] if args.only else None
    result = dump.extract_all(args.path, out, only=only)
    print(f"extracted {result['partitions']} partitions to {result['manifest']}")
    print(f"total: {human_size(result['total_size'])}")
    print(f"verify later with: revive verify {result['out_dir']}")
    return 0


def cmd_dump_scan(args) -> int:
    hits = dump.scan(args.path)
    if args.json:
        print(json.dumps(hits, indent=2))
        return 0
    print(f"{len(hits)} signatures found")
    for hit in hits:
        print(f"  0x{hit['offset']:010x}  {hit['kind']:<28} {'aligned' if hit['aligned'] else ''}")
    return 0


def cmd_gpt_list(args) -> int:
    try:
        parsed = gpt.read_gpt(args.path)
    except gpt.GptError as exc:
        return fail(str(exc), code="dump_no_gpt")
    if args.json:
        print(json.dumps(parsed.to_dict(), indent=2))
        return 0
    print(f"sector size {parsed.sector_size}, table at 0x{parsed.disk_offset:x}, "
          f"CRCs {'ok' if parsed.header_crc_ok and parsed.entries_crc_ok else 'BAD'}"
          + ("  (backup table used)" if parsed.backup_used else ""))
    for part in parsed.partitions:
        print(f"  {part.name[:26]:<26} LBA {part.first_lba:>10}-{part.last_lba:<10} "
              f"{human_size(part.size):>10}  {part.type_name}")
    return 0


def cmd_gpt_repair(args) -> int:
    try:
        report = gpt.repair_gpt(args.path, dry_run=not args.apply)
    except gpt.GptError as exc:
        return fail(str(exc))
    print(f"header CRC was {'ok' if report['header_crc_was_ok'] else 'BAD'}, "
          f"entries CRC was {'ok' if report['entries_crc_was_ok'] else 'BAD'}, "
          f"partitions: {report['partitions']}")
    for change in report["changes"]:
        print(f"  - {change}")
    if not args.apply:
        print("\nThis was a dry run. Re-run with --apply to write the repaired table.")
    else:
        print("\nRepaired. Verify with: revive gpt-list <dump>")
    return 0


def cmd_convert(args) -> int:
    mode = args.mode
    try:
        if mode == "raw":
            result = convert.to_raw(args.path, args.out)
        elif mode == "sparse":
            result = convert.to_sparse(args.path, args.out)
        elif mode == "lz4":
            result = convert.decompress_lz4(args.path, args.out)
        elif mode == "trim":
            result = convert.trim(args.path, args.out)
        elif mode == "boot":
            result = convert.extract_boot(args.path, args.out or str(Path(args.path).parent))
        else:
            result = convert.convert_auto(args.path, args.out)
    except Exception as exc:
        return fail(str(exc))
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print_kv({k: (human_size(v) if k.endswith("size") and isinstance(v, int) else v)
              for k, v in result.items()})
    return 0


def cmd_super(args) -> int:
    try:
        if args.partition:
            result = superimg.extract(args.path, args.partition, args.out or f"{args.partition}.img")
            print(f"extracted {result['partition']} -> {result['output']} "
                  f"({human_size(result['size'])})")
            return 0
        info = superimg.inspect(args.path)
    except Exception as exc:
        return fail(str(exc))
    if args.json:
        print(json.dumps(info.to_dict(), indent=2))
        return 0
    total = info.total_size() if callable(info.total_size) else info.total_size
    print(f"super image: metadata {info.major}.{info.minor}, "
          f"{len(info.partitions)} partitions, {human_size(total)} of payload")
    for part in info.partitions:
        print(f"  {part.name:<24} {human_size(part.size):>12}  group={part.group or '-'}")
    for note in info.notes:
        print(C(f"  note: {note}", "dim"))
    return 0


def cmd_manifest(args) -> int:
    manifest = verify.create_manifest(args.path, args.out)
    target = Path(args.out) if args.out else Path(args.path) / verify.MANIFEST_NAME
    print(f"wrote {target}: {manifest['file_count']} files, {human_size(manifest['total_size'])}")
    return 0


def cmd_verify(args) -> int:
    path = Path(args.path)
    if path.is_dir():
        try:
            result = verify.verify_manifest(path)
        except FileNotFoundError as exc:
            return fail(str(exc), detail="Create one first with: revive manifest <folder>")
        if args.json:
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
        print(f"{result['verified']}/{result['files']} files verified against the manifest")
        print_findings(result["findings"])
        return 0 if result["ok"] else 1
    if sparse.is_sparse_file(path):
        result = verify.verify_sparse(path)
        if args.json:
            print(json.dumps(result, indent=2))
            return 0 if result.get("ok") else 1
        if result.get("ok"):
            print(C(f"sparse image checksum OK ({human_size(result.get('raw_size'))} expanded)", "green"))
            return 0
        return fail(f"checksum mismatch: expected {result.get('expected')}, got {result.get('actual')}",
                    code="0xC0050003")
    if bootimg.looks_like_boot_image(path):
        image = bootimg.parse(path)
        if args.json:
            print(json.dumps(image.to_dict(), indent=2))
        else:
            print_kv(image.to_dict())
        return 0
    return fail("nothing to verify: expected a folder with a manifest, a sparse image, or a boot image")


def cmd_demo(args) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import make_demo

    info = make_demo.make_demo_tree(Path(args.out), corrupt_gpt=args.corrupt_gpt)
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(f"demo data written to {info['out']}")
    print(f"  firmware (good)     {info['firmware_mtk']['root']}")
    print(f"  firmware (broken)   {info['firmware_broken']['root']}")
    print(f"  qualcomm package    {info['firmware_qualcomm']['root']}")
    print(f"  full dump           {info['dump']}")
    print(f"  single images       {Path(info['boot_img']).parent}")
    print("\ntry:")
    print(f"  revive inspect {info['firmware_mtk']['root']}")
    print(f"  revive plan {info['firmware_broken']['root']}")
    print(f"  revive dump-analyse {info['dump']}")
    return 0


def cmd_serve(args) -> int:
    from .ui import server

    return server.serve(args.host, args.port, args.demo, args.open, args.verbose,
                        args.storage, args.token)


def cmd_guide(args) -> int:
    topic = (args.topic or "workflow").lower()
    if topic == "drivers":
        return cmd_drivers(argparse.Namespace(json=False, udev_rule=False, write=False))
    if topic == "safety":
        print(GUIDE_SAFETY)
        return 0
    if topic == "testpoint":
        print(GUIDE_TESTPOINT)
        return 0
    if topic == "backup":
        print(GUIDE_BACKUP)
        return 0
    print(GUIDE_WORKFLOW)
    return 0


GUIDE_WORKFLOW = """
The workflow that does not brick phones
---------------------------------------
1. Back up what still reads (before anything else).
      revive dump-analyse <existing dump>       # if you already have one
      revive identify --backend mtk             # storage health: dying eMMC decides your plan
2. Identify the chip and the security state.
      revive identify                           # hw code, SBC/SLA/DAA flags, storage
3. Verify the firmware matches the model.
      revive inspect <firmware folder>          # missing files, oversize images, overlaps
4. Read the plan before writing anything.
      revive plan <firmware folder>             # every write, target, size and the risk verdict
5. Flash, then verify.
      verify the read-back checksum of what you wrote before you declare it fixed

If a step fails, paste the error into `revive err "<log line>"` and follow what it says.
"""

GUIDE_SAFETY = """
Safety rules this tool enforces, and the reasons behind them
-----------------------------------------------------------
* Nothing is written without an explicit confirmation, and never without a validated plan.
* Unknown chip codes are reported as unknown. Revive will not guess DA parameters - a wrong
  DA/preloader write is the difference between a repairable phone and a dead one.
* Preloader and partition-table writes are always labelled high risk in the plan.
* IMEI/NVRAM rewriting is not implemented: altering IMEI is illegal in most countries,
  including Pakistan. Restoring a phone's own original NVRAM backup is a different thing and is
  supported through plain partition backup/restore.
* Backups get SHA-256 manifests so "the backup is fine" is a provable statement.
* Unisoc flashing is deliberately left to the vendor tool: its container and command set are
  not documented reliably enough to risk a write.
"""

GUIDE_TESTPOINT = """
Test points - when the battery and buttons are not enough
---------------------------------------------------------
A hard-bricked phone often does not enter download mode from the buttons. The fallback is to
pull the relevant pin to ground at power-up, which forces the SoC into BROM/MaskROM.

How to approach it (no shortcuts - every board differs):
  1. Search for your exact model + "test point" to find the board's labelled pads or a photo.
  2. Disconnect the battery. Connect the USB cable to the PC.
  3. Short the two pads (or pad to ground) with tweezers, keep them shorted, then connect the
     battery / plug in the cable.
  4. Watch `revive detect` in another window: you are looking for `0e8d:0003` (MediaTek BROM) or
     `05c6:9008` (Qualcomm EDL).
  5. Release the short as soon as the device answers, and start your operation immediately -
     BROM only waits about a second.
Warnings: some boards need the short held for the whole operation; some need the battery
disconnected first. Doing this wrong can short a rail - use a current-limited supply if you have
one, and never short random pads.
"""

GUIDE_BACKUP = """
Backing up a phone that still answers
-------------------------------------
fastboot is running (best case):
    revive identify --backend fastboot      # model, slot, lock state
    (unpack and keep the stock firmware for this exact build - it is your recovery image)

Android is running, USB debugging on:
    adb backup -apk -shared -all -system -f full.ab       # app+data snapshot
    adb pull /sdcard sdcard_backup                        # internal storage
    adb shell "dd if=/dev/block/by-name/nvram of=/sdcard/nvram.img"   # calibration (root/eng only)

Download mode only (BROM/EDL):
    read partitions in this order, stopping if anything errors twice:
      nvram/nvdata, persist, frp, keystore, proinfo, protect1/2, modem/md1img,
      boot/boot_a, vbmeta, dtbo, then the rest of the table
    A read that fails at the same offset twice is a bad block: note it, keep going with the
    rest, and treat that dump as evidence rather than as a future source of truth.
"""


# --------------------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revive",
        description="Revive - a repair-first phone toolkit (MediaTek, Qualcomm, Unisoc, fastboot)",
        epilog="Start with: revive info   |   revive detect   |   revive demo   |   revive serve",
    )
    parser.add_argument("--version", action="version", version=f"revive {util.__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("info", help="environment, backends and what to install")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("detect", help="what is connected, and what to do next")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("identify", help="read chip / security / storage from a device")
    p.add_argument("--backend", choices=["mtk", "qualcomm", "unisoc", "fastboot", "mock"])
    p.add_argument("--loader", help="firehose loader to upload first (Qualcomm)")
    p.add_argument("--storage", help="storage file for the simulated backend")
    p.add_argument("--demo", action="store_true", help="use the simulated device")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_identify)

    p = sub.add_parser("drivers", help="driver instructions per OS (+ udev rule for Linux)")
    p.add_argument("--udev-rule", action="store_true", help="print the Linux udev rule")
    p.add_argument("--write", action="store_true", help="write it to /etc/udev/rules.d (needs sudo)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_drivers)

    p = sub.add_parser("chips", help="the chip table (hardware code -> SoC)")
    p.add_argument("--search")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_chips)

    p = sub.add_parser("err", help="explain an error code or a log line")
    p.add_argument("text", nargs="*", help="code(s) or the log line")
    p.add_argument("--log", help="read the codes out of this log file instead")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_err)

    p = sub.add_parser("inspect", help="check a firmware package or a single image")
    p.add_argument("path")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("plan", help="dry-run flash plan with a risk verdict")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("dump-analyse", help="analyse a full-flash dump")
    p.add_argument("path")
    p.add_argument("--fast", action="store_true", help="skip per-partition content probing")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_dump_analyse)

    p = sub.add_parser("dump-extract", help="extract partitions from a dump")
    p.add_argument("path")
    p.add_argument("--partition", help="single partition name")
    p.add_argument("--only", help="comma separated list of partitions")
    p.add_argument("--out", help="output folder")
    p.set_defaults(func=cmd_dump_extract)

    p = sub.add_parser("dump-scan", help="find partitions by signature when the table is gone")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_dump_scan)

    p = sub.add_parser("gpt-list", help="list the partition table of a dump")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_gpt_list)

    p = sub.add_parser("gpt-repair", help="rebuild a damaged partition table (CRCs and backup copy)")
    p.add_argument("path")
    p.add_argument("--apply", action="store_true", help="write the repair (default is a dry run)")
    p.set_defaults(func=cmd_gpt_repair)

    p = sub.add_parser("convert", help="sparse/raw/lz4/trim/boot conversions")
    p.add_argument("path")
    p.add_argument("--mode", default="auto",
                   choices=["auto", "raw", "sparse", "lz4", "trim", "boot"])
    p.add_argument("--out")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("super", help="list or extract a super.img (dynamic partitions)")
    p.add_argument("path")
    p.add_argument("--partition", help="extract this partition")
    p.add_argument("--out")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_super)

    p = sub.add_parser("manifest", help="write a SHA-256 manifest for a folder")
    p.add_argument("path")
    p.add_argument("--out")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("verify", help="verify a manifest, a sparse image or a boot image")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("demo", help="create synthetic firmware/dump data to learn on")
    p.add_argument("--out", default="demo")
    p.add_argument("--corrupt-gpt", action="store_true", help="damage the GPT on purpose")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("serve", help="run the web UI")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--demo", action="store_true")
    p.add_argument("--open", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--storage", type=Path)
    p.add_argument("--token", default=None)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("guide", help="workflow / safety / testpoints / backup / drivers")
    p.add_argument("topic", nargs="?", default="workflow",
                   choices=["workflow", "safety", "testpoint", "backup", "drivers"])
    p.set_defaults(func=cmd_guide)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        print("\nNew here? Run:  revive demo   then   revive serve --demo --open")
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
