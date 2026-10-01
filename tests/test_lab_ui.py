"""Tests for the LAB TESTING tab: its API routes and the page that drives them.

The UI is a stdlib http.server, so it can be started in-process on an ephemeral port and driven
with urllib. These tests walk the tab's whole journey - create, brick, run, report - over real
HTTP, including the job polling the browser does, because that is the path a technician takes.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from revive.ui import api, server

SMALL = 8 * 1024 * 1024
PAGE = Path(__file__).resolve().parent.parent / "revive" / "ui" / "static" / "index.html"
TOKEN = "lab-test-token"


def _lab_routes():
    return sorted(route for route in api.ROUTES if route.startswith("lab."))


def _ctx(tmp: Path) -> dict:
    return {"demo": False, "demo_storage": None, "started": time.time(),
            "lab_root": str(tmp / "lab")}


def _boot(ctx):
    httpd = server.ReviveServer(("127.0.0.1", 0), server.ReviveHandler, ctx, TOKEN, False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{httpd.server_address[1]}", httpd


def _request(url, payload=None, token=TOKEN, timeout=120):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    if data:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("X-Revive-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            try:
                return response.status, json.loads(body)
            except json.JSONDecodeError:
                return response.status, {"raw": body}          # the page itself is HTML
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"raw": body}


def _call(base, route, payload=None, sync=True):
    """POST /api/call the way the page does, then poll the job for the routes that queue.

    The server merges the route's payload into the response, so the body *is* the result - a
    route is free to carry a `result` key of its own (`lab.run` reports PASS/FAIL under it).
    """
    status, body = _request(base + "/api/call",
                            {"route": route, "payload": payload or {}, "sync": sync})
    assert status == 200, (route, status, body)
    job = body.get("job")
    if not job:
        return body
    job_id = job["id"]
    deadline = time.time() + 180
    while time.time() < deadline:
        _, state = _request(f"{base}/api/job?id={job_id}")
        job = state.get("job") or {}
        if job.get("status") not in ("running", "queued"):
            result = job.get("result")
            assert result is not None, (route, job.get("error"))
            return result
        time.sleep(0.05)
    raise AssertionError(f"{route}: the job never finished")


# --------------------------------------------------------------------------------------
# The page and the route table
# --------------------------------------------------------------------------------------

def test_every_lab_route_is_wired_to_a_button():
    """A route the page never calls is a button that cannot work, or dead code."""
    page = PAGE.read_text(encoding="utf-8")
    uncalled = [route for route in _lab_routes()
                if f"'{route}'" not in page and f'"{route}"' not in page]
    assert not uncalled, f"index.html never calls: {uncalled}"


def test_the_lab_tab_is_reachable_from_the_navigation():
    page = PAGE.read_text(encoding="utf-8")
    assert 'data-tab="lab"' in page, "there is no LAB TESTING nav button"
    assert 'id="tab-lab"' in page, "there is no LAB TESTING section"
    assert "LAB TESTING" in page


def test_the_page_shows_the_four_buttons_the_task_names():
    page = PAGE.read_text(encoding="utf-8")
    for button in ("btn-lab-create", "btn-lab-run", "btn-lab-repair", "btn-lab-chip",
                   "btn-lab-verify", "btn-lab-report", "btn-lab-reset", "btn-lab-delete"):
        assert f'id="{button}"' in page, f"the lab tab is missing {button}"
    for label in ("Create device", "Run Revive", "Verify result", "Generate report"):
        assert label in page, f"the lab tab is missing a {label!r} control"


def test_the_page_needs_no_network_to_render_the_lab_tab():
    """The bench may be offline: no CDN, no absolute URL, nothing but local assets."""
    page = PAGE.read_text(encoding="utf-8")
    assert "http://" not in page and "https://" not in page


def test_the_long_lab_routes_queue_as_jobs():
    for route in ("lab.run", "lab.create", "lab.report"):
        assert route in server.JOB_ROUTES, f"{route} can take a while; it should queue"


# --------------------------------------------------------------------------------------
# The routes, through dispatch
# --------------------------------------------------------------------------------------

def test_lab_info_describes_the_whole_lab(tmp: Path):
    ctx = _ctx(tmp)
    result = api.dispatch("lab.info", {}, ctx)
    assert result["ok"] is True
    assert result["root"].endswith("lab")
    chipsets = {p["chipset"] for p in result["profiles"]}
    assert {"MT6765", "MT6768", "MT6877", "Snapdragon 450", "Snapdragon 660",
            "Snapdragon 7 series", "Unisoc SC9863A"} == chipsets, chipsets
    platforms = {p["platform"] for p in result["profiles"]}
    assert platforms == {"mtk", "qualcomm", "unisoc"}, platforms
    for profile in result["profiles"]:
        for key in ("name", "chipset", "vendor", "storage", "interface", "boot_mode"):
            assert profile.get(key), f"{profile.get('name')} has no {key}"
    assert len(result["scenarios"]) == 7
    assert result["health_states"] == ["healthy", "warning", "dead"]
    assert {b["id"] for b in result["brick_types"]} == {s["id"] for s in result["scenarios"]}


def test_lab_create_status_brick_run_report(tmp: Path):
    """The tab's whole journey, one route at a time."""
    ctx = _ctx(tmp)

    created = api.dispatch("lab.create", {"chip": "MT6768", "storage": "64GB",
                                          "image_bytes": SMALL}, ctx)
    assert created["ok"] is True, created.get("error")
    device = created["device"]["id"]
    assert created["device"]["profile"]["chipset"] == "MT6768"
    assert created["health"]["state"] == "healthy"
    assert created["boot"]["booted"] is True

    listed = api.dispatch("lab.list", {}, ctx)
    assert [d["id"] for d in listed["devices"]] == [device]

    status = api.dispatch("lab.status", {"device": device}, ctx)
    assert status["verify"]["ok"] is True
    assert status["signals"] == []

    brick = api.dispatch("lab.brick", {"device": device, "type": "gpt"}, ctx)
    assert brick["ok"] is True and brick["expected_signals"]
    assert "gpt_header_crc_bad" in brick["expected_signals"]

    status = api.dispatch("lab.status", {"device": device}, ctx)
    assert set(brick["expected_signals"]) <= set(status["signals"])

    run = api.dispatch("lab.run", {"device": device, "scenario": "gpt_corruption"}, ctx)
    assert run["ok"] is True, run.get("error")
    assert run["passed"] == run["total"] == 1
    assert run["runs"][0]["result"] == "PASS"

    report = api.dispatch("lab.report", {"device": device}, ctx)
    assert report["ok"] is True
    assert Path(report["paths"]["html"]).exists()
    assert Path(report["paths"]["json"]).exists()
    assert report["html"] == report["paths"]["html"], "html must be a path, not the document"
    # lab.report snapshots the device as it stands; the graded run report comes from lab.run.
    assert "LAB DEVICE REPORT" in report["html_content"]
    assert "LAB TEST REPORT" in Path(run["paths"]["html"]).read_text(encoding="utf-8")

    history = api.dispatch("lab.history", {"device": device}, ctx)
    assert history["ok"] is True and history["runs"], "nothing was recorded"

    deleted = api.dispatch("lab.delete", {"device": device}, ctx)
    assert deleted["ok"] is True
    assert api.dispatch("lab.list", {}, ctx)["devices"] == []


def test_a_route_failure_is_an_error_payload_not_an_exception(tmp: Path):
    ctx = _ctx(tmp)
    result = api.dispatch("lab.status", {"device": "no-such-device"}, ctx)
    assert result["ok"] is False
    assert "no-such-device" in json.dumps(result)


def test_a_brick_that_does_not_fit_the_device_is_refused(tmp: Path):
    ctx = _ctx(tmp)
    created = api.dispatch("lab.create", {"chip": "SDM660", "image_bytes": SMALL}, ctx)
    device = created["device"]["id"]
    result = api.dispatch("lab.brick", {"device": device, "type": "brom"}, ctx)
    assert result["ok"] is False
    assert "does not apply" in result["error"]


def test_lab_verify_reports_a_bricked_device_as_failed(tmp: Path):
    ctx = _ctx(tmp)
    device = api.dispatch("lab.create", {"chip": "MT6768", "image_bytes": SMALL}, ctx)["device"]["id"]
    api.dispatch("lab.brick", {"device": device, "type": "boot"}, ctx)
    before = api.dispatch("lab.verify", {"device": device}, ctx)
    assert before["ok"] is False and before["verdict"] == "FAIL"
    api.dispatch("lab.repair", {"device": device}, ctx)
    after = api.dispatch("lab.verify", {"device": device}, ctx)
    assert after["ok"] is True and after["verdict"] == "PASS", after


def test_lab_reset_returns_the_device_to_healthy(tmp: Path):
    ctx = _ctx(tmp)
    device = api.dispatch("lab.create", {"chip": "MT6768", "image_bytes": SMALL}, ctx)["device"]["id"]
    api.dispatch("lab.brick", {"device": device, "type": "gpt"}, ctx)
    reset = api.dispatch("lab.reset", {"device": device}, ctx)
    assert reset["ok"] is True
    assert reset["device"] == device
    assert reset["status"] == "healthy", reset
    assert api.dispatch("lab.status", {"device": device}, ctx)["signals"] == []


def test_lab_set_changes_the_chip_and_lab_create_can_preset_it(tmp: Path):
    ctx = _ctx(tmp)
    created = api.dispatch("lab.create",
                           {"chip": "MT6768", "image_bytes": SMALL,
                            "options": {"manufacturer": "Micron", "health": "warning"}}, ctx)
    device = created["device"]["id"]
    assert created["applied"]["manufacturer"] == "Micron"
    assert created["health"]["state"] == "warning"

    changed = api.dispatch("lab.set", {"device": device,
                                       "options": {"health": "dead", "size": "128GB",
                                                   "firmware_version": "0x4c414231"}}, ctx)
    assert changed["ok"] is True
    assert changed["health"]["state"] == "dead"
    assert changed["summary"]["capacity_human"].startswith("128")
    assert changed["verdict"] == "fatal"
    assert "emmc_pre_eol_urgent" in changed["signals"]

    # The same settings also work as flat keys, which is what a hand-written request looks like.
    flat = api.dispatch("lab.set", {"device": device, "manufacturer": "SanDisk"}, ctx)
    assert flat["applied"]["manufacturer"] == "SanDisk"

    bad = api.dispatch("lab.set", {"device": device, "options": {"nope": "1"}}, ctx)
    assert bad["ok"] is False and "unknown option" in bad["error"]


def test_the_server_uses_the_lab_root_it_was_started_with(tmp: Path):
    """`serve --lab <folder>` must mean the tab writes there, not to ./lab_devices."""
    result = api.dispatch("lab.info", {}, _ctx(tmp))
    assert result["root"] == str(tmp / "lab")


# --------------------------------------------------------------------------------------
# Over real HTTP, including the job queue
# --------------------------------------------------------------------------------------

def test_the_lab_tab_works_over_http(tmp: Path):
    base, httpd = _boot(_ctx(tmp))
    try:
        info = _call(base, "lab.info")
        assert info["ok"] is True and len(info["profiles"]) >= 6

        created = _call(base, "lab.create",
                        {"chip": "MT6768", "storage": "64GB", "image_bytes": SMALL})
        device = created["device"]["id"]
        assert created["partitions"], "the create job returned no partitions"

        status = _call(base, "lab.status", {"device": device})
        assert status["device"]["profile"]["chipset"] == "MT6768"

        brick = _call(base, "lab.brick", {"device": device, "type": "gpt"})
        assert brick["label"] == "GPT corruption"

        run = _call(base, "lab.run", {"device": device, "scenario": "gpt_corruption"})
        assert run["runs"][0]["result"] == "PASS", run["runs"][0]["summary"]

        report = _call(base, "lab.report", {"device": device})
        assert "LAB DEVICE REPORT" in report["html_content"]
        assert Path(report["html"]).exists()

        history = _call(base, "lab.history", {"limit": 10})
        assert [h["scenario"] for h in history["history"]], "the run was not recorded"

        # The page itself is served without a token, and it is what drives every call above.
        status_code, body = _request(base + "/", token=None)
        assert status_code == 200
        assert "LAB TESTING" in body.get("raw", ""), "the served page has no lab tab"
    finally:
        httpd.shutdown()


def test_the_lab_routes_need_the_token(tmp: Path):
    base, httpd = _boot(_ctx(tmp))
    try:
        status, _ = _request(base + "/api/call", {"route": "lab.info", "payload": {}}, token=None)
        assert status == 401
    finally:
        httpd.shutdown()
