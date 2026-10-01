"""Lab reports: JSON for machines, HTML for the technician.

The HTML is a single self-contained file with inline CSS and no CDN, matching the rest of
Revive's UI: a repair shop machine is often offline, and a report that needs the internet to
render is not a report.

The headline block is the one from the task description - device, scenario, and the three
verdicts - and everything below it is the evidence those verdicts were made from.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ... import util
from ...util import human_size

LOG = logging.getLogger("revive.lab.report")

SCHEMA = "revive-lab-report/1"


# --------------------------------------------------------------------------------------
# Building the report payload
# --------------------------------------------------------------------------------------

def build_report(result, bench_summary: Optional[Dict[str, Any]] = None,
                 diagnosis_extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Turn a TestResult (or a list of them) into the report payload."""
    results = result if isinstance(result, (list, tuple)) else [result]
    payloads = [r.to_dict() for r in results]
    passed = sum(1 for p in payloads if p["result"] == "PASS")
    first = payloads[0] if payloads else {}
    report = {
        "schema": SCHEMA,
        "title": "LAB TEST REPORT",
        "tool": util.TOOL_NAME,
        "version": util.__version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_at_local": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device": first.get("device", ""),
        "chipset": first.get("chipset", ""),
        "platform": first.get("platform", ""),
        "scenario": first.get("scenario", ""),
        "scenario_label": first.get("scenario_label", ""),
        "detection": first.get("detection", {}).get("verdict", "SKIP"),
        "repair": first.get("repair", {}).get("verdict", "SKIP"),
        "verification": first.get("verification", {}).get("verdict", "SKIP"),
        "result": "PASS" if payloads and passed == len(payloads) else "FAIL",
        "scenario_count": len(payloads),
        "scenarios_passed": passed,
        "scenarios_failed": len(payloads) - passed,
        "runs": payloads,
        "lab": bench_summary or {},
    }
    if diagnosis_extra:
        report["diagnosis"] = diagnosis_extra
    return report


def build_from_device(device, bench=None) -> Dict[str, Any]:
    """A report for a device that has not been through a graded run (status snapshot)."""
    from .. import recovery_test

    diagnosis = recovery_test.diagnose(device)
    check = device.verify()
    return {
        "schema": SCHEMA, "title": "LAB DEVICE REPORT", "tool": util.TOOL_NAME,
        "version": util.__version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_at_local": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device": device.id, "chipset": device.profile.chipset,
        "platform": device.profile.platform, "scenario": "(status snapshot)",
        "scenario_label": "Status snapshot", "detection": "SKIP", "repair": "SKIP",
        "verification": check["verdict"],
        "result": "PASS" if check["ok"] else "FAIL",
        "scenario_count": 0, "scenarios_passed": 0, "scenarios_failed": 0,
        "runs": [], "diagnosis": diagnosis.to_dict(), "device_check": check,
        "device_info": device.to_dict(),
        "lab": bench.summary() if bench is not None else {},
    }


# --------------------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------------------

def to_json(report: Dict[str, Any], indent: int = 2) -> str:
    return json.dumps(util.to_dict(report), indent=indent, default=str)


def write_json(report: Dict[str, Any], path) -> Path:
    target = Path(path)
    util.atomic_write(target, to_json(report).encode("utf-8"))
    return target


# --------------------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------------------

_VERDICT_CLASS = {"PASS": "pass", "FAIL": "fail", "SKIP": "skip"}

_CSS = """
:root{--bg:#0e1116;--panel:#161b22;--panel2:#1c2230;--line:#2a3240;--fg:#e6edf3;--dim:#8b949e;
--acc:#4da3ff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--fatal:#db61a2;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:22px}
header{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;
border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:18px}
h1{margin:0;font-size:19px;letter-spacing:.6px}
h1 span{color:var(--acc)}
h2{font-size:15px;margin:26px 0 8px}
h3{font-size:13px;margin:16px 0 6px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.sub{color:var(--dim);font-size:12.5px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;
margin-bottom:14px}
.headline{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.metric{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.metric .label{color:var(--dim);font-size:11.5px;text-transform:uppercase;letter-spacing:.5px}
.metric .value{font-size:16px;font-weight:600;margin-top:2px;word-break:break-word}
.verdict{display:inline-block;padding:2px 10px;border-radius:99px;font-weight:700;font-size:12.5px}
.verdict.pass{background:#0f2415;color:var(--ok)}
.verdict.fail{background:#33121f;color:var(--fatal)}
.verdict.skip{background:var(--panel2);color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600}
td.mono,th.mono{font-family:var(--mono);font-size:12px}
ul{margin:6px 0 0;padding-left:20px}
li{margin:2px 0}
pre{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;
font-family:var(--mono);font-size:12px;max-height:340px}
code{font-family:var(--mono);font-size:12.5px}
.kv{display:grid;grid-template-columns:230px 1fr;gap:4px 14px;font-size:13px}
.kv div:nth-child(odd){color:var(--dim)}
.finding{border-left:3px solid var(--line);background:var(--panel2);border-radius:0 8px 8px 0;
padding:9px 12px;margin-bottom:7px}
.finding.ok{border-left-color:var(--ok)}.finding.info{border-left-color:var(--acc)}
.finding.warn{border-left-color:var(--warn)}.finding.error{border-left-color:var(--err)}
.finding.fatal{border-left-color:var(--fatal)}
.finding b{display:block}
.finding .fix{margin:5px 0 0;padding-left:18px;color:var(--dim);font-size:12.5px}
footer{color:var(--dim);font-size:12px;margin-top:26px;border-top:1px solid var(--line);
padding-top:10px}
.sig{display:inline-block;background:var(--panel2);border:1px solid var(--line);
border-radius:99px;padding:2px 9px;margin:2px 4px 2px 0;font-family:var(--mono);font-size:11.5px}
"""


def _esc(value: Any) -> str:
    text = "" if value is None else str(value)
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _verdict(value: str) -> str:
    return f'<span class="verdict {_VERDICT_CLASS.get(value, "skip")}">{_esc(value)}</span>'


def _kv(rows: Sequence[Any]) -> str:
    out = ['<div class="kv">']
    for item in rows:
        if len(item) != 2:
            continue
        key, value = item
        if value in ("", None, [], {}):
            continue
        out.append(f"<div>{_esc(key)}</div><div>{value if isinstance(value, str) and '<' in value else _esc(value)}</div>")
    out.append("</div>")
    return "".join(out)


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]],
           mono_columns: Sequence[int] = ()) -> str:
    if not rows:
        return '<p class="sub">nothing to show</p>'
    out = ["<table><tr>" + "".join(f"<th>{_esc(h)}</th>" for h in headers) + "</tr>"]
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            cls = ' class="mono"' if index in mono_columns else ""
            value = cell if isinstance(cell, str) and "<" in cell else _esc(cell)
            cells.append(f"<td{cls}>{value}</td>")
        out.append("<tr>" + "".join(cells) + "</tr>")
    out.append("</table>")
    return "".join(out)


def _findings_html(findings: Sequence[Dict[str, Any]], limit: int = 40) -> str:
    if not findings:
        return '<p class="sub">no findings</p>'
    out: List[str] = []
    for finding in list(findings)[:limit]:
        severity = finding.get("severity", "info")
        fixes = "".join(f"<li>{_esc(f)}</li>" for f in finding.get("fixes", []))
        out.append(
            f'<div class="finding {_esc(severity)}"><b>{_esc(finding.get("title", ""))}</b>'
            f'<div>{_esc(finding.get("detail", ""))}</div>'
            + (f'<ul class="fix">{fixes}</ul>' if fixes else "") + "</div>")
    return "".join(out)


def _signals_html(signals: Sequence[str]) -> str:
    if not signals:
        return '<span class="sub">none</span>'
    return "".join(f'<span class="sig">{_esc(s)}</span>' for s in signals)


def _run_html(run: Dict[str, Any], index: int) -> str:
    detection, repair, verification = (run.get("detection", {}), run.get("repair", {}),
                                       run.get("verification", {}))
    before = run.get("before") or {}
    after = run.get("after") or {}
    baseline = run.get("baseline") or {}
    brick = run.get("brick") or {}
    detail = run.get("repair_detail") or {}

    stage_rows = [
        ("Detection", detection.get("verdict", "SKIP"), detection.get("detail", ""),
         ", ".join(detection.get("expected", [])) or "-",
         ", ".join(detection.get("missing", [])) or "-"),
        ("Repair", repair.get("verdict", "SKIP"), repair.get("detail", ""), "-", "-"),
        ("Verification", verification.get("verdict", "SKIP"), verification.get("detail", ""),
         "device boots, table verifies, storage healthy",
         ", ".join(verification.get("missing", [])) or "-"),
    ]

    checks = (verification.get("data") or {}).get("checks", [])
    written = detail.get("written") or []
    handshake = detail.get("handshake") or []

    parts = [
        f'<div class="card"><h2>Scenario {index}: {_esc(run.get("scenario_label") or run.get("scenario"))} '
        f'{_verdict(run.get("result", "SKIP"))}</h2>',
        _kv([("Scenario id", run.get("scenario")), ("Device", run.get("device")),
             ("Chipset", run.get("chipset")), ("Timestamp", run.get("timestamp")),
             ("Duration", f'{run.get("duration", 0)} s'),
             ("Effect", (brick or {}).get("effect", "")),
             ("Error", run.get("error", ""))]),
        "<h3>Stages</h3>",
        _table(["Stage", "Verdict", "Detail", "Expected", "Missing"], stage_rows),
        "<h3>What the brick did</h3>",
        _signals_html(before.get("signals", [])),
    ]
    if baseline.get("signals"):
        parts.append('<p class="sub">baseline (before the brick): '
                     + _signals_html(baseline["signals"]) + "</p>")
    else:
        parts.append('<p class="sub">baseline before the brick: clean</p>')

    if brick:
        parts.append("<h3>Damage applied</h3>")
        parts.append(_kv([("Scenario", brick.get("scenario") or brick.get("scenario_id")),
                          ("Mode", brick.get("mode") or brick.get("mode_text")),
                          ("Partition(s)", ", ".join(brick.get("partitions", []) or
                                                     ([brick["partition"]] if brick.get("partition") else []))),
                          ("IMEI before", brick.get("imei_before")),
                          ("IMEI after", brick.get("imei_after")),
                          ("Health before", (brick.get("before") or {}).get("state")),
                          ("Health after", (brick.get("after") or {}).get("state")),
                          ("Bad blocks", brick.get("bad_blocks")),
                          ("Symptom", brick.get("symptom")),
                          ("Write behaviour", brick.get("write_behaviour"))]))
        advice = brick.get("advice") or []
        if advice:
            parts.append("<ul>" + "".join(f"<li>{_esc(a)}</li>" for a in advice) + "</ul>")

    if run.get("expected_signals"):
        parts.append("<h3>Expected fault signals</h3>")
        parts.append(_signals_html(run["expected_signals"]))

    if before.get("findings"):
        parts.append("<h3>What Revive's diagnosis engine reported</h3>")
        parts.append(_findings_html(before["findings"]))

    dump_report = before.get("dump_report") or {}
    if dump_report:
        parts.append("<h3>Dump analysis</h3>")
        parts.append(_kv([("File", dump_report.get("path")),
                          ("Size", dump_report.get("file_size_human")),
                          ("Partitions", dump_report.get("partition_count")),
                          ("Header CRC ok", dump_report.get("header_crc_ok")),
                          ("Entries CRC ok", dump_report.get("entries_crc_ok")),
                          ("Backup table used", dump_report.get("backup_used")),
                          ("Accounted", dump_report.get("total_size_human")),
                          ("Unaccounted", dump_report.get("unaccounted_human"))]))

    if handshake:
        parts.append("<h3>Repair: handshake</h3>")
        parts.append(_table(["Stage", "Detail"],
                            [(h.get("stage", ""), h.get("detail", "")) for h in handshake]))
    if written:
        parts.append("<h3>Repair: what was written</h3>")
        parts.append(_table(["Partition", "Bytes", "Verified", "SHA-256"],
                            [(w.get("partition", ""), human_size(w.get("bytes")),
                              "yes" if w.get("verified") else "NO",
                              str(w.get("sha256", ""))[:24] + "…") for w in written],
                            mono_columns=(3,)))
    if detail.get("changes"):
        parts.append("<h3>Repair: changes</h3><ul>"
                     + "".join(f"<li>{_esc(c)}</li>" for c in detail["changes"]) + "</ul>")
    restored = [r for r in (detail.get("restored") or []) if isinstance(r, dict)]
    if restored:
        parts.append("<h3>Repair: restored</h3>")
        parts.append(_table(["Partition", "Bytes", "SHA-256", "Identity"],
                            [(r.get("partition", ""), human_size(r.get("bytes")),
                              str(r.get("sha256", ""))[:24] + ("…" if r.get("sha256") else ""),
                              (r.get("identity") or {}).get("imei", "")) for r in restored],
                            mono_columns=(2,)))
    if detail.get("restored_partitions"):
        parts.append("<h3>Repair: partitions rewritten onto the new chip</h3><p class=\"sub\">"
                     + _esc(", ".join(detail["restored_partitions"])) + "</p>")
    if detail.get("note"):
        parts.append(f'<p class="sub">{_esc(detail["note"])}</p>')
    if detail.get("failures"):
        parts.append("<h3>Repair: failures</h3><ul>"
                     + "".join(f"<li>{_esc(f)}</li>" for f in detail["failures"]) + "</ul>")

    if checks:
        parts.append("<h3>Verification checks</h3>")
        parts.append(_table(["Check", "Result", "Detail"],
                            [(c.get("name", ""),
                              _verdict("PASS" if c.get("ok") else "FAIL"),
                              c.get("detail", "")) for c in checks]))

    if after.get("signals"):
        parts.append("<h3>Signals remaining after the repair</h3>")
        parts.append(_signals_html(after["signals"]))
    else:
        parts.append('<h3>Signals remaining after the repair</h3><p class="sub">none</p>')

    damaged = after.get("damaged_partitions") or []
    if damaged:
        parts.append("<h3>Partitions still damaged</h3>")
        parts.append(_table(["Partition", "Status", "Issues"],
                            [(p.get("name"), p.get("status"), "; ".join(p.get("issues", [])))
                             for p in damaged]))
    parts.append("</div>")
    return "".join(parts)


def to_html(report: Dict[str, Any]) -> str:
    """Render the report as a standalone HTML page."""
    runs = report.get("runs") or []
    health = ((runs[0].get("before") or {}).get("health") if runs else None) or {}
    lab = report.get("lab") or {}

    parts: List[str] = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(report.get('title', 'LAB TEST REPORT'))} - {_esc(report.get('device', ''))}</title>",
        f"<style>{_CSS}</style></head><body><main>",
        f"<header><h1>REVIVE <span>{_esc(report.get('title', 'LAB TEST REPORT'))}</span></h1>"
        f'<div class="sub">{_esc(report.get("tool", ""))} v{_esc(report.get("version", ""))} · '
        f'{_esc(report.get("generated_at_local", ""))}</div></header>',
        '<div class="card"><div class="headline">',
        f'<div class="metric"><div class="label">Device</div>'
        f'<div class="value">{_esc(report.get("device", ""))}</div></div>',
        f'<div class="metric"><div class="label">Chipset</div>'
        f'<div class="value">{_esc(report.get("chipset", ""))}</div></div>',
        f'<div class="metric"><div class="label">Scenario</div>'
        f'<div class="value">{_esc(report.get("scenario_label") or report.get("scenario", ""))}</div></div>',
        f'<div class="metric"><div class="label">Detection</div>'
        f'<div class="value">{_verdict(report.get("detection", "SKIP"))}</div></div>',
        f'<div class="metric"><div class="label">Repair</div>'
        f'<div class="value">{_verdict(report.get("repair", "SKIP"))}</div></div>',
        f'<div class="metric"><div class="label">Verification</div>'
        f'<div class="value">{_verdict(report.get("verification", "SKIP"))}</div></div>',
        f'<div class="metric"><div class="label">Result</div>'
        f'<div class="value">{_verdict(report.get("result", "SKIP"))}</div></div>',
        "</div>",
        _kv([("Scenarios run", report.get("scenario_count")),
             ("Passed", report.get("scenarios_passed")),
             ("Failed", report.get("scenarios_failed")),
             ("Platform", report.get("platform")),
             ("Generated at (UTC)", report.get("generated_at"))]),
        "</div>",
    ]

    if health:
        parts.append('<div class="card"><h2>Storage at the time of the brick</h2>')
        parts.append(_kv([("State", health.get("state")), ("PRE_EOL", health.get("pre_eol")),
                          ("PRE_EOL meaning", health.get("pre_eol_text")),
                          ("Life (type A)", health.get("life_a_text")),
                          ("Life (type B)", health.get("life_b_text")),
                          ("Capacity", health.get("capacity_human")),
                          ("Bad blocks", health.get("bad_blocks")),
                          ("Write cycles", health.get("write_cycles")),
                          ("Verdict", health.get("verdict"))]))
        parts.append("</div>")

    device_check = report.get("device_check")
    if device_check:
        parts.append('<div class="card"><h2>Device verification</h2>')
        parts.append(_table(["Check", "Result", "Detail"],
                            [(c.get("name", ""),
                              _verdict("PASS" if c.get("ok") else "FAIL"), c.get("detail", ""))
                             for c in device_check.get("checks", [])]))
        parts.append("</div>")

    diagnosis = report.get("diagnosis")
    if diagnosis:
        parts.append('<div class="card"><h2>Diagnosis</h2>')
        parts.append("<p>" + _signals_html(diagnosis.get("signals", [])) + "</p>")
        parts.append(_findings_html(diagnosis.get("findings", [])))
        parts.append("</div>")

    for index, run in enumerate(runs, start=1):
        parts.append(_run_html(run, index))

    if lab.get("history"):
        parts.append('<div class="card"><h2>Recent lab history</h2>')
        parts.append(_table(["Timestamp", "Device", "Scenario", "Detection", "Repair",
                             "Verification", "Result"],
                            [(h.get("timestamp", ""), h.get("device", ""),
                              h.get("scenario", ""), h.get("detection", ""),
                              h.get("repair", ""), h.get("verification", ""),
                              _verdict(h.get("result", "")))
                             for h in lab["history"][:25]]))
        parts.append("</div>")

    parts.append(
        '<footer>Generated by the Revive lab testing module. Every device, brick and repair in '
        'this report is simulated: no hardware was touched. The diagnosis and repair logic are '
        'the same code paths Revive uses on a real phone.</footer></main></body></html>')
    return "".join(parts)


def write_html(report: Dict[str, Any], path) -> Path:
    target = Path(path)
    util.atomic_write(target, to_html(report).encode("utf-8"))
    return target


def write_reports(report: Dict[str, Any], out_dir, stem: Optional[str] = None) -> Dict[str, str]:
    """Write both formats next to each other and return their paths."""
    folder = Path(out_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    name = stem or util.safe_filename(
        f"lab_report_{report.get('scenario') or 'device'}_{stamp}", "lab_report")
    json_path = write_json(report, folder / f"{name}.json")
    html_path = write_html(report, folder / f"{name}.html")
    LOG.info("wrote lab reports: %s, %s", json_path, html_path)
    return {"json": str(json_path), "html": str(html_path)}


def render_text(report: Dict[str, Any]) -> str:
    """The plain-text version the CLI prints."""
    lines = [
        "LAB TEST REPORT",
        "-" * 60,
        f"Device:        {report.get('device', '')}",
        f"Chipset:       {report.get('chipset', '')}",
        f"Scenario:      {report.get('scenario_label') or report.get('scenario', '')}",
        f"Detection:     {report.get('detection', '')}",
        f"Repair:        {report.get('repair', '')}",
        f"Verification:  {report.get('verification', '')}",
        f"RESULT:        {report.get('result', '')}",
    ]
    for run in report.get("runs", []):
        if report.get("scenario_count", 0) <= 1:
            continue
        lines.append(f"  - {run.get('scenario_label', run.get('scenario'))}: "
                     f"detection {run['detection']['verdict']}, "
                     f"repair {run['repair']['verdict']}, "
                     f"verification {run['verification']['verdict']} -> {run.get('result')}")
    return "\n".join(lines)
