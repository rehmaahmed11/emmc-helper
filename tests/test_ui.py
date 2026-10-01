"""Tests for the web UI: the job runner and the HTTP layer.

The UI is a stdlib http.server, so it can be started in-process on an ephemeral port and driven
with urllib - no browser, no third-party HTTP client. These tests cover the contract the
JavaScript depends on, not the look of the page.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from fixtures import demo_tree
from revive.ui import api, server


def _boot(demo=False, token="test-token"):
    ctx = {"demo": demo, "demo_storage": None, "started": time.time()}
    httpd = server.ReviveServer(("127.0.0.1", 0), server.ReviveHandler, ctx, token, False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    return base, httpd, thread


def _request(url, payload=None, token=None, timeout=30):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    if data:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("X-Revive-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"raw": body}


def _call(base, route, payload=None, token="test-token", sync=True):
    return _request(base + "/api/call",
                    {"route": route, "payload": payload or {}, "sync": sync}, token=token)


def test_job_runs_a_route_and_reports_the_result():
    info = demo_tree()
    ctx = {"demo": False, "started": time.time()}
    jobs = server.JobManager(ctx)
    job = jobs.submit("dump.scan", {"path": info["dump"]})
    deadline = time.time() + 30
    state = None
    while time.time() < deadline:
        state = jobs.get(job.id).to_dict()
        if state["status"] in ("done", "failed"):
            break
        time.sleep(0.05)
    assert state and state["status"] == "done", state
    assert state["result"]["ok"] is True
    assert state["result"]["hits"], "the demo dump has signatures to find"
    assert state["progress"] == 1.0


def test_job_runner_surfaces_errors():
    ctx = {"demo": False, "started": time.time()}
    jobs = server.JobManager(ctx)
    job = jobs.submit("dump.analyse", {"path": "/no/such/dump.bin"})
    deadline = time.time() + 20
    state = None
    while time.time() < deadline:
        state = jobs.get(job.id).to_dict()
        if state["status"] in ("done", "failed"):
            break
        time.sleep(0.05)
    assert state and state["status"] == "failed"
    assert state["error"]


def test_index_is_served_without_a_token():
    base, httpd, thread = _boot()
    try:
        status, _ = _request(base + "/healthz")
        assert status == 200
        with urllib.request.urlopen(base + "/", timeout=10) as response:
            page = response.read().decode("utf-8")
        assert response.status == 200
        assert "<title>" in page and "fetch(" in page
        # The shell must not depend on a CDN: previews and offline benches both matter.
        assert "http://" not in page and "https://" not in page
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def test_api_requires_the_token():
    base, httpd, thread = _boot()
    try:
        status, body = _call(base, "info", {}, token="")
        assert status == 401 and "token" in json.dumps(body).lower()
        status, body = _call(base, "info")
        assert status == 200 and body["ok"] is True
        assert body["tool"]
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def test_api_plan_and_inspect_round_trip():
    info = demo_tree()
    base, httpd, thread = _boot()
    try:
        status, body = _call(base, "plan", {"path": info["firmware_mtk"]["root"]})
        assert status == 200 and body["ok"] is True
        assert body["kind"] == "mtk_spflash"
        status, body = _call(base, "inspect", {"path": info["firmware_broken"]["root"]})
        assert status == 200 and body["ok"] is True
        assert body["kind"] == "mtk_spflash"
        assert body["findings"], "the broken package must report findings"
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def test_api_rejects_bad_requests():
    base, httpd, thread = _boot()
    try:
        status, body = _call(base, "inspect", {})
        assert status == 200 and body["ok"] is False and "path" in json.dumps(body).lower()
        status, body = _call(base, "does.not.exist", {})
        assert body["ok"] is False and "routes" in body
        status, body = _request(base + "/api/call", {"route": "info"}, token="test-token")
        assert status == 200 and body["ok"] is True
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def test_static_path_traversal_is_refused():
    base, httpd, thread = _boot()
    try:
        request = urllib.request.Request(base + "/static/../server.py")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status in (400, 403, 404)
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def test_demo_mode_advertises_simulated_hardware():
    base, httpd, thread = _boot(demo=True)
    try:
        status, body = _call(base, "detect", {})
        assert status == 200 and body["ok"] is True
        assert body.get("demo") is True
        assert any(device.get("simulated") for device in body["devices"])
    finally:
        httpd.shutdown()
        thread.join(timeout=5)
