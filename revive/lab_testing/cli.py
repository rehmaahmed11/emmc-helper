"""Command line interface for the lab.

    python -m revive.lab_testing create --chip MT6768 --storage 64GB
    python -m revive.lab_testing brick  --type gpt
    python -m revive.lab_testing run
    python -m revive.lab_testing report

The same commands are reachable as `revive lab <command>`; this module owns the argument
parsing so `revive/cli.py` stays a thin delegator.

The lab never touches hardware, so unlike the rest of Revive nothing here needs `--apply` or
`--confirm`. It does still default to read-only where that makes sense: `brick` damages,
`run --no-repair` diagnoses without fixing, and `report` writes nothing unless asked.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import brick_engine as brick_mod
from . import emmc_virtual as emmc_mod
from . import recovery_test as rt
from .device import DEFAULT_LAB_ROOT, PROFILES, LabBench, VirtualDevice
from .emmc_virtual import DEFAULT_IMAGE_BYTES
from .extcsd_virtual import HEALTH_STATES, selftest as register_selftest
from .partitions import LAYOUTS
from .reports import lab_report
from ..util import human_size
from .scenarios import ScenarioError, all_scenarios, for_platform

C_OK, C_FAIL, C_WARN, C_DIM, C_OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _c(text: str, colour: str, enabled: bool) -> str:
    return f"{colour}{text}{C_OFF}" if enabled else text


def _verdict(value: str, colour: bool) -> str:
    if value == "PASS":
        return _c("PASS", C_OK, colour)
    if value == "FAIL":
        return _c("FAIL", C_FAIL, colour)
    return _c(value or "-", C_DIM, colour)


# --------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------

def _bench(args) -> LabBench:
    return LabBench(getattr(args, "lab", None) or DEFAULT_LAB_ROOT)


def _device(args) -> VirtualDevice:
    bench = _bench(args)
    device = bench.get(getattr(args, "device", None))
    device._file_handler()
    return device


def _options(pairs: Optional[Sequence[str]]) -> Dict[str, Any]:
    """`--opt mode=total --opt bad_blocks=24` -> {'mode': 'total', 'bad_blocks': 24}."""
    out: Dict[str, Any] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"--opt expects name=value, got {pair!r}")
        key, value = pair.split("=", 1)
        key = key.strip().replace("-", "_")
        text = value.strip()
        if text.lower() in ("true", "false"):
            out[key] = text.lower() == "true"
        else:
            try:
                out[key] = int(text, 0)
            except ValueError:
                out[key] = text
    return out


def _print_json(payload: Any) -> None:
    from ..util import to_dict

    print(json.dumps(to_dict(payload), indent=2, default=str))


def _print_result(result: rt.TestResult, colour: bool, verbose: bool = False) -> None:
    print()
    print(f"  scenario      {result.scenario_label} ({result.scenario})")
    print(f"  device        {result.device_id} / {result.chipset}")
    print(f"  detection     {_verdict(result.detection.verdict, colour)}"
          f"  {_c(result.detection.detail, C_DIM, colour)}")
    if verbose or result.detection.missing:
        print(f"    expected    {', '.join(result.detection.expected) or '-'}")
        print(f"    found       {', '.join(result.detection.found) or '-'}")
        if result.detection.missing:
            print(f"    {_c('missing', C_FAIL, colour)}    "
                  f"{', '.join(result.detection.missing)}")
    print(f"  repair        {_verdict(result.repair.verdict, colour)}"
          f"  {_c(result.repair.detail, C_DIM, colour)}")
    print(f"  verification  {_verdict(result.verification.verdict, colour)}"
          f"  {_c(result.verification.detail, C_DIM, colour)}")
    if result.error:
        print(f"  {_c('error', C_FAIL, colour)}        {result.error}")
    print(f"  {_c('RESULT', C_DIM, colour)}        {_verdict(result.result, colour)}"
          f"  {_c(f'({result.duration:.2f}s)', C_DIM, colour)}")


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------

def _apply_chip_options(device, options: Dict[str, Any]) -> Dict[str, Any]:
    """Change the virtual chip's registers, reporting what actually moved."""
    try:
        return emmc_mod.apply_options(device.emmc, options)
    except emmc_mod.VirtualEmmcError as exc:
        raise ValueError(str(exc)) from exc


def cmd_set(args) -> int:
    device = _device(args)
    options = _options(args.opt)
    if not options:
        print("nothing to set. The chip settings are:")
        for name, meaning in sorted(emmc_mod.SPEC_OPTIONS.items()):
            print(f"  --opt {name}=...   {meaning}")
        return 1
    try:
        applied = _apply_chip_options(device, options)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    device.save()
    if args.json:
        _print_json({"ok": True, "device": device.id, "applied": applied,
                     "health": device.emmc.health(),
                     "registers": device.emmc.registers_decoded()["summary"]})
        return 0
    colour = not args.no_color
    print(f"{_c('chip updated', C_OK, colour)} on {device.id}")
    for key, value in applied.items():
        print(f"  {key:<17} {value}")
    summary = device.emmc.registers_decoded()["summary"]
    health = device.emmc.health()
    print(f"  {'now reports':<17} {summary.get('manufacturer', '')} {summary.get('product_name', '')} "
          f"{summary.get('capacity_human', '')}")
    print(f"  {'health':<17} {health['state']} (PRE_EOL {health['pre_eol']}) - "
          f"{device.emmc.registers_decoded()['verdict']}")
    return 0


def cmd_create(args) -> int:
    bench = _bench(args)
    try:
        device = bench.create(chip=args.chip, storage=args.storage,
                              image_bytes=args.image_bytes, vendor=args.vendor,
                              model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(f"known profiles: {', '.join(sorted(PROFILES))}", file=sys.stderr)
        return 1
    applied: Dict[str, Any] = {}
    try:
        applied = _apply_chip_options(device, _options(getattr(args, "opt", None)))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if applied:
        device.save()
    if args.json:
        _print_json({"ok": True, "device": device.to_dict(),
                     "partitions": [p.to_dict() for p in device.partitions]})
        return 0
    colour = not args.no_color
    print(f"{_c('created', C_OK, colour)} {device.id}")
    print(f"  folder      {device.folder}")
    print(f"  chipset     {device.profile.chipset} ({device.profile.platform})")
    print(f"  vendor      {device.profile.vendor} / {device.profile.model}")
    print(f"  storage     {device.profile.storage} "
          f"({device.emmc.health()['capacity_human']} nominal)")
    print(f"  interface   {device.profile.interface}")
    print(f"  image       {device.emmc.path} "
          f"({device.emmc.image_bytes // 1024 // 1024} MiB on disk)")
    print(f"  partitions  {len(device.partitions)}")
    for part in device.partitions:
        print(f"    {part.name:<14} {part.size_human:>11}   "
              f"(nominal {human_size(part.nominal_size)})")
    for key, value in applied.items():
        print(f"  {key:<11} {value}")
    print(f"  boot        {device.boot().to_dict()['summary']}")
    print(f"\nnext:  python -m revive.lab_testing brick --type gpt")
    return 0


def cmd_list(args) -> int:
    bench = _bench(args)
    summary = bench.summary()
    if args.json:
        _print_json(summary)
        return 0
    colour = not args.no_color
    print(f"lab root: {summary['root']}")
    if not summary["devices"]:
        print("  (empty - create a device with: python -m revive.lab_testing create --chip MT6768)")
        return 0
    print(f"  {'ACTIVE':<7} {'DEVICE':<38} {'CHIPSET':<10} {'STORAGE':<8} {'STATUS':<10} PARTS")
    for entry in summary["devices"]:
        marker = "*" if entry["id"] == summary["active"] else ""
        status = entry.get("status", "")
        painted = (_c(status, C_FAIL, colour) if status == "bricked"
                   else _c(status, C_OK, colour) if status == "recovered" else status)
        print(f"  {marker:<7} {entry['id']:<38} {entry.get('chipset',''):<10} "
              f"{entry.get('storage',''):<8} {painted:<19} {entry.get('partitions','')}")
    print(f"\n  {summary['runs']} test run(s): {summary['passed']} passed, "
          f"{summary['failed']} failed")
    return 0


def cmd_status(args) -> int:
    device = _device(args)
    check = device.verify()
    if args.json:
        _print_json({"ok": check["ok"], "device": device.to_dict(),
                     "verify": check, "signals": rt.collect_signals(device)["signals"],
                     "health": device.emmc.health()})
        return 0
    colour = not args.no_color
    health = device.emmc.health()
    boot = device.boot().to_dict()
    print(f"{device.id}")
    print(f"  chipset     {device.profile.chipset} ({device.profile.platform}) / "
          f"{device.profile.vendor} {device.profile.model}")
    print(f"  storage     {device.profile.storage} nominal, "
          f"{device.emmc.image_bytes // 1024 // 1024} MiB image, "
          f"{device.profile.interface}")
    print(f"  boot mode   {device.profile.boot_mode}")
    print(f"  status      {device.status}")
    print(f"  health      {health['state']} (PRE_EOL {health['pre_eol']} = "
          f"{health['pre_eol_text']}), {health['life_a_text']}, "
          f"{health['bad_blocks']} bad block(s)")
    print(f"  boot        {boot['summary']}")
    faults = device.active_faults
    print(f"  faults      {', '.join(f.label for f in faults) if faults else 'none'}")
    signals = rt.collect_signals(device)["signals"]
    print(f"  signals     {', '.join(signals) if signals else 'none'}")
    print(f"  verify      {_verdict(check['verdict'], colour)}")
    for item in check["checks"]:
        print(f"    [{_verdict('PASS' if item['ok'] else 'FAIL', colour)}] "
              f"{item['name']:<16} {item['detail'][:70]}")
    return 0


def cmd_scenarios(args) -> int:
    platform = (args.platform or "").lower()
    items = for_platform(platform) if platform else all_scenarios()
    if args.json:
        _print_json([s.to_dict() for s in items])
        return 0
    for scenario in items:
        short = ", ".join(sorted(k for k, v in brick_mod.BRICK_TYPES.items()
                                 if v == scenario.id))
        print(f"{scenario.id}")
        print(f"  label       {scenario.label}   [--type {short.split(', ')[0]}]")
        print(f"  platforms   {', '.join(scenario.platforms)}")
        print(f"  severity    {scenario.severity}"
              f"{'' if scenario.repairable else '   (no software repair)'}")
        print(f"  effect      {scenario.effect}")
        print(f"  repair      {scenario.repair_summary}")
        print(f"  expects     {', '.join(scenario.expected_signals())}")
        if scenario.options:
            print(f"  options     {', '.join(scenario.options)}")
        print()
    return 0


def cmd_profiles(args) -> int:
    if args.json:
        _print_json([p.to_dict() for p in PROFILES.values()])
        return 0
    print(f"{'KEY':<9} {'CHIPSET':<22} {'PLATFORM':<11} {'VENDOR':<10} {'STORAGE':<8} LAYOUT")
    for key, profile in sorted(PROFILES.items()):
        print(f"{key:<9} {profile.chipset:<22} {profile.platform:<11} {profile.vendor:<10} "
              f"{profile.storage:<8} {len(LAYOUTS.get(profile.platform, []))} partitions")
        if profile.notes:
            print(f"{'':9} {_c(profile.notes, C_DIM, not args.no_color)}")
    return 0


def cmd_brick(args) -> int:
    device = _device(args)
    engine = brick_mod.BrickEngine(device)
    try:
        result = engine.apply(args.type, _options(args.opt))
    except brick_mod.BrickError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        _print_json({"ok": True, **result})
        return 0
    colour = not args.no_color
    print(f"{_c('bricked', C_FAIL, colour)} {device.id} with {result['label']}")
    print(f"  scenario    {result.get('scenario_id')}")
    print(f"  effect      {result.get('effect')}")
    for key in ("partition", "partitions", "mode_text", "imei_after", "boot_mode", "usb_id",
                "bad_blocks", "health"):
        value = result.get(key)
        if value not in (None, "", [], {}):
            print(f"  {key:<11} {value}")
    if result.get("symptom"):
        print(f"  symptom     {result['symptom']}")
    if result.get("write_behaviour"):
        print(f"  writes      {result['write_behaviour']}")
    for line in result.get("advice", []):
        print(f"    -> {line}")
    print(f"  {_c('expects', C_DIM, colour)}     {', '.join(result.get('expected_signals', []))}")
    print(f"\nnext:  python -m revive.lab_testing run")
    return 0


def cmd_run(args) -> int:
    bench = _bench(args)
    device = _device(args)
    tester = rt.RecoveryTester(device, bench=bench)
    options = _options(args.opt)
    colour = not args.no_color

    scenarios: List[str] = []
    if args.scenario:
        scenarios = [tester.engine.resolve(args.scenario).id]
    elif args.all:
        scenarios = tester.engine.available_ids()
    elif device.active_faults:
        scenarios = [device.active_faults[-1].id]
    else:
        scenarios = tester.engine.available_ids()

    results: List[rt.TestResult] = []
    try:
        for index, scenario_id in enumerate(scenarios):
            if args.all or len(scenarios) > 1:
                device.reset()
                device.save()
            results.append(tester.run(scenario_id, options, repair=not args.no_repair))
    except brick_mod.BrickError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ScenarioError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _print_json([r.to_dict() for r in results])
        return _exit_code(results)

    for result in results:
        _print_result(result, colour, verbose=args.verbose)
    if len(results) > 1:
        passed = sum(1 for r in results if r.result == "PASS")
        print()
        print(f"  {_c('SUMMARY', C_DIM, colour)}       "
              f"{_verdict('PASS' if passed == len(results) else 'FAIL', colour)}  "
              f"{passed}/{len(results)} scenarios passed")

    if not args.no_report:
        _write_reports(bench, device, results, args.out, args.json, quiet=True)
    return _exit_code(results)


def _exit_code(results: Sequence[rt.TestResult]) -> int:
    return 0 if all(r.result == "PASS" for r in results) else 1


def cmd_repair(args) -> int:
    device = _device(args)
    engine = brick_mod.BrickEngine(device)
    try:
        result = engine.repair(args.type, _options(args.opt))
    except brick_mod.BrickError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        _print_json({"ok": bool(result.get("repaired")), **result})
        return 0 if result.get("repaired") else 1
    colour = not args.no_color
    state = _c("repaired", C_OK, colour) if result.get("repaired") else _c("not repaired", C_FAIL, colour)
    print(f"{state} {device.id} ({result.get('label')})")
    for key in ("method", "note", "imei_restored"):
        if result.get(key):
            print(f"  {key:<11} {result[key]}")
    for change in result.get("changes", []):
        print(f"    - {change}")
    for item in result.get("written", []):
        print(f"    - wrote {item['partition']}: {item.get('bytes')} bytes, "
              f"read-back {'verified' if item.get('verified') else 'MISMATCH'}")
    for stage in result.get("handshake", []):
        print(f"    - {stage['stage']}: {stage['detail']}")
    for failure in result.get("failures", []):
        print(f"    {_c('!', C_FAIL, colour)} {failure}")
    return 0 if result.get("repaired") else 1


def cmd_verify(args) -> int:
    device = _device(args)
    check = device.verify()
    if args.json:
        _print_json(check)
        return 0 if check["ok"] else 1
    colour = not args.no_color
    print(f"{_verdict(check['verdict'], colour)}  {device.id} is "
          f"{'healthy' if check['ok'] else 'not healthy'}")
    for item in check["checks"]:
        print(f"  [{_verdict('PASS' if item['ok'] else 'FAIL', colour)}] "
              f"{item['name']:<16} {item['detail'][:76]}")
    return 0 if check["ok"] else 1


def cmd_reset(args) -> int:
    device = _device(args)
    engine = brick_mod.BrickEngine(device)
    info = engine.reset()
    if args.json:
        _print_json({"ok": True, **info})
        return 0
    print(f"{_c('reset', C_OK, not args.no_color)} {device.id}: "
          f"{len(info['restored_partitions']) if 'restored_partitions' in info else len(device.partitions)} "
          f"partitions rebuilt, faults cleared "
          f"({', '.join(info.get('cleared', [])) or 'none were active'})")
    return 0


def cmd_report(args) -> int:
    bench = _bench(args)
    device = _device(args)
    colour = not args.no_color

    cached = _load_last_report(bench)
    if cached is not None and not args.refresh and cached.get("device") == device.id:
        report = cached
        source = "the last recorded run"
    else:
        results = _load_device_runs(device)
        if results:
            report = lab_report.build_report(results, bench.summary())
            source = f"{len(results)} recorded run(s) for this device"
        else:
            report = lab_report.build_from_device(device, bench)
            source = "a live status snapshot (no graded run recorded yet)"

    out_dir = Path(args.out) if args.out else device.reports_dir
    paths = lab_report.write_reports(report, out_dir)
    if args.json:
        _print_json({"ok": True, "source": source, **paths, "report": report})
        return 0
    print(lab_report.render_text(report))
    print()
    print(f"  source    {source}")
    print(f"  {_c('json', C_DIM, colour)}      {paths['json']}")
    print(f"  {_c('html', C_DIM, colour)}      {paths['html']}")
    return 0


def _load_last_report(bench: LabBench) -> Optional[Dict[str, Any]]:
    path = bench.root / "last_report.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _load_device_runs(device: VirtualDevice) -> List[Any]:
    """Rebuild TestResult-shaped payloads from the run files the tester writes."""
    folder = device.reports_dir
    if not folder.is_dir():
        return []
    runs: List[Any] = []
    for path in sorted(folder.glob("run_*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        runs.append(_RunProxy(data))
    return runs


class _RunProxy:
    """Minimal stand-in so `build_report` can render saved runs without re-running them."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def to_dict(self) -> Dict[str, Any]:
        return self._data


def _write_reports(bench: LabBench, device: VirtualDevice, results: Sequence[rt.TestResult],
                   out: Optional[str], as_json: bool, quiet: bool = False) -> Dict[str, str]:
    report = lab_report.build_report(list(results), bench.summary())
    out_dir = Path(out) if out else device.reports_dir
    paths = lab_report.write_reports(report, out_dir)
    from ..util import atomic_write, to_json

    atomic_write(bench.root / "last_report.json", to_json(report).encode("utf-8"))
    for result in results:
        stem = f"run_{result.scenario}_{result.timestamp.replace(':', '').replace('-', '')}"
        atomic_write(out_dir / f"{stem}.json",
                     to_json(result.to_dict()).encode("utf-8"))
    if not quiet:
        print(f"  report      {paths['html']}")
    return paths


def cmd_selftest(args) -> int:
    """Round-trip the register generator through Revive's real decoder."""
    results = register_selftest()
    if args.json:
        _print_json(results)
        return 0
    ok = True
    print("EXT_CSD round-trip through revive.storage.emmc")
    for state, data in results.items():
        generated = data["generated_pre_eol"]
        decoded = data["decoded_health"]
        capacity_ok = data["decoded_capacity"] == data["expected_capacity"]
        good = capacity_ok
        ok = ok and good
        print(f"  {state:<8} generated PRE_EOL {generated} -> decoded '{decoded}', "
              f"capacity {'ok' if capacity_ok else 'MISMATCH'}, "
              f"verdict {data['verdict']}")
    print(_c("PASS" if ok else "FAIL", C_OK if ok else C_FAIL, not args.no_color))
    return 0 if ok else 1


def cmd_history(args) -> int:
    bench = _bench(args)
    rows = bench.history(args.limit)
    if args.json:
        _print_json(rows)
        return 0
    if not rows:
        print("no test runs recorded yet")
        return 0
    print(f"  {'TIMESTAMP':<21} {'DEVICE':<36} {'SCENARIO':<22} {'DET':<5} {'REP':<5} "
          f"{'VER':<5} RESULT")
    for row in rows:
        colour = not args.no_color
        print(f"  {row.get('timestamp',''):<21} {row.get('device','')[:36]:<36} "
              f"{row.get('scenario','')[:22]:<22} {row.get('detection',''):<5} "
              f"{row.get('repair',''):<5} {row.get('verification',''):<5} "
              f"{_verdict(row.get('result',''), colour)}")
    return 0


def cmd_delete(args) -> int:
    bench = _bench(args)
    if not args.device:
        print("error: --device is required", file=sys.stderr)
        return 1
    try:
        info = bench.delete(args.device)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"deleted {info['deleted']} ({info['folder']})")
    return 0


# --------------------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------------------

def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lab", default=None,
                        help=f"lab database folder (default: {DEFAULT_LAB_ROOT})")
    parser.add_argument("--device", default=None,
                        help="device id (default: the active device)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m revive.lab_testing",
        description="Revive LAB TESTING: create virtual phones, brick them, run Revive's "
                    "repair logic against them, and verify that they came back. "
                    "No hardware is touched.",
        epilog="examples:\n"
               "  python -m revive.lab_testing create --chip MT6768 --storage 64GB\n"
               "  python -m revive.lab_testing brick --type gpt\n"
               "  python -m revive.lab_testing run\n"
               "  python -m revive.lab_testing report\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--log", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="lab log level")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("create", help="create a virtual device")
    p.add_argument("--chip", default="MT6768", help="chipset or profile key (see `profiles`)")
    p.add_argument("--storage", default=None, help="storage size, e.g. 64GB / 128G / 32GB")
    p.add_argument("--vendor", default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--image-bytes", type=int, default=DEFAULT_IMAGE_BYTES,
                   help=f"on-disk image size in bytes (default {DEFAULT_IMAGE_BYTES})")
    p.add_argument("--opt", action="append", metavar="NAME=VALUE",
                   help="chip setting: manufacturer=Micron, size=128GB, health=dead, "
                        "firmware_version=4c414231, bad_blocks=8 (repeatable)")
    _common(p)
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("set", help="change what the active device's eMMC reports about itself")
    p.add_argument("--opt", action="append", metavar="NAME=VALUE",
                   help=f"one of: {', '.join(sorted(emmc_mod.SPEC_OPTIONS))} (repeatable)")
    _common(p)
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("list", help="list the devices in the lab")
    _common(p)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("status", help="the active device, its health and its current faults")
    _common(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("profiles", help="the supported virtual device profiles")
    _common(p)
    p.set_defaults(func=cmd_profiles)

    p = sub.add_parser("scenarios", help="the faults the lab can inject")
    p.add_argument("--platform", default=None, choices=[None, "mtk", "qualcomm", "unisoc"],
                   help="only show scenarios for this platform")
    _common(p)
    p.set_defaults(func=cmd_scenarios)

    p = sub.add_parser("brick", help="damage the active device")
    p.add_argument("--type", required=True,
                   help="gpt | boot | userdata | emmc | nvram | edl | brom")
    p.add_argument("--opt", action="append", metavar="NAME=VALUE",
                   help="scenario option, repeatable (e.g. --opt mode=total)")
    _common(p)
    p.set_defaults(func=cmd_brick)

    p = sub.add_parser("run", help="run the test workflow: brick -> diagnose -> repair -> verify")
    p.add_argument("--scenario", default=None, help="one scenario id (see `scenarios`)")
    p.add_argument("--all", action="store_true",
                   help="run every scenario that applies to this device")
    p.add_argument("--opt", action="append", metavar="NAME=VALUE")
    p.add_argument("--no-repair", action="store_true",
                   help="diagnose only: prove the fault is detected, then stop")
    p.add_argument("--no-report", action="store_true", help="do not write report files")
    p.add_argument("--out", default=None, help="report output folder")
    _common(p)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("test", help="alias of `run`")
    p.add_argument("--scenario", default=None)
    p.add_argument("--all", action="store_true")
    p.add_argument("--opt", action="append", metavar="NAME=VALUE")
    p.add_argument("--no-repair", action="store_true")
    p.add_argument("--no-report", action="store_true")
    p.add_argument("--out", default=None)
    _common(p)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("repair", help="repair the most recent brick (or a named one)")
    p.add_argument("--type", default=None)
    p.add_argument("--opt", action="append", metavar="NAME=VALUE")
    _common(p)
    p.set_defaults(func=cmd_repair)

    p = sub.add_parser("verify", help="is the device healthy right now?")
    _common(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("reset", help="rebuild the device from scratch (same profile, no faults)")
    _common(p)
    p.set_defaults(func=cmd_reset)

    p = sub.add_parser("report", help="write the HTML + JSON lab report")
    p.add_argument("--out", default=None, help="output folder (default: the device's reports/)")
    p.add_argument("--refresh", action="store_true",
                   help="rebuild from the recorded runs instead of using the cached report")
    _common(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("history", help="the lab's test history")
    p.add_argument("--limit", type=int, default=25)
    _common(p)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("delete", help="delete a lab device")
    # --device comes from _common(); it is required here, which cmd_delete enforces.
    _common(p)
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("selftest", help="round-trip the fake registers through Revive's decoder")
    _common(p)
    p.set_defaults(func=cmd_selftest)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    level = getattr(logging, str(getattr(args, "log", "WARNING")).upper(), logging.WARNING)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    if not getattr(args, "command", None):
        parser.print_help()
        print("\nquick start:")
        print("  python -m revive.lab_testing create --chip MT6768 --storage 64GB")
        print("  python -m revive.lab_testing brick --type gpt")
        print("  python -m revive.lab_testing run")
        print("  python -m revive.lab_testing report")
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (brick_mod.BrickError, ScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
