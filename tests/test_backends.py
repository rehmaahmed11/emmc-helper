"""Tests for the connection layer: the backend registry, capabilities and the UI contract.

No hardware is available in CI, so these tests check the parts that can be checked offline:
that every backend advertises a sane capability set, that the ones which have never been
verified against a real phone say so loudly, and that the web UI's API surface still matches
what the JavaScript calls.
"""
from __future__ import annotations

import json
from pathlib import Path

from fixtures import demo_tree
from revive import backends
from revive.ui import api

CAPABILITY_KEYS = {"name", "label", "vendor", "modes", "read", "write", "erase", "partitions",
                   "tested", "protocol", "notes"}

# Every route the front end calls; the UI must keep working when this list changes.
UI_ROUTES = {
    "info", "chips", "modes", "errors", "errors.decode", "drivers", "detect", "identify",
    "inspect", "plan", "dump.analyse", "dump.extract", "dump.scan", "gpt.list", "gpt.repair",
    "convert", "super.list", "super.extract", "manifest.create", "manifest.verify",
    "sparse.verify", "demo.build",
}


def _caps_by_name() -> dict:
    return {cap["name"]: cap for cap in backends.describe_backends()}


def test_every_backend_advertises_capabilities():
    caps = backends.describe_backends()
    assert caps, "the registry must not be empty"
    for cap in caps:
        missing = CAPABILITY_KEYS - set(cap)
        assert not missing, f"{cap.get('name')} is missing {sorted(missing)}"
        assert isinstance(cap["modes"], list) and cap["modes"]
        assert isinstance(cap["notes"], list)


def test_unverified_backends_say_so():
    caps = _caps_by_name()
    assert "mock" in caps and caps["mock"]["tested"] is True
    for name in ("mtk", "qualcomm", "unisoc", "fastboot"):
        assert name in caps, f"{name} backend is missing from the registry"
        assert caps[name]["tested"] is False, f"{name} must not claim to be hardware-verified"
    warnings = backends.get_backend("mtk").guard_tested()
    assert warnings, "an untested backend must produce a warning"
    assert any("hardware" in w.lower() or "verified" in w.lower() for w in warnings)


def test_backend_labels_are_human_readable():
    for cap in backends.describe_backends():
        assert cap["label"] and cap["vendor"]
        assert cap["label"] != cap["name"]


def test_ui_route_table_is_complete():
    assert set(api.ROUTES) == UI_ROUTES, (set(UI_ROUTES) - set(api.ROUTES),
                                          set(api.ROUTES) - set(UI_ROUTES))
    assert api.MUTATING, "the UI needs to know which routes write to disk"
    assert api.MUTATING <= set(api.ROUTES)


def test_dispatch_returns_errors_instead_of_raising():
    result = api.dispatch("no.such.route", {})
    assert result["ok"] is False
    assert "no.such.route" in json.dumps(result)


def test_api_inspect_is_read_only():
    info = demo_tree()
    root = Path(info["firmware_mtk"]["root"])
    before = sorted((p.name, p.stat().st_size) for p in root.iterdir())
    result = api.dispatch("inspect", {"path": str(root)})
    assert result["ok"] is True
    assert result["kind"] == "mtk_spflash"
    assert any(item.get("detected") for item in result["images_detail"])
    after = sorted((p.name, p.stat().st_size) for p in root.iterdir())
    assert before == after, "inspect must not modify the package it looks at"


def test_api_plan_and_dump_json_contract():
    info = demo_tree()
    plan = api.dispatch("plan", {"path": info["firmware_broken"]["root"]})
    assert plan["ok"] is True
    assert plan["risk"] == "blocked"
    assert plan["entries"] and all("action" in e for e in plan["entries"])
    assert "RISK" in plan["rendered"] and "PARTITION" in plan["rendered"]
    dump = api.dispatch("dump.analyse", {"path": info["dump"]})
    assert dump["ok"] is True
    assert dump["partition_count"] == 6
    assert dump["gpt_offset"] == 0
    assert "unaccounted" in dump and dump["findings"]
    assert dump["partitions"][0]["offset_hex"].startswith("0x")


def test_api_identify_uses_the_mock_backend_offline():
    result = api.dispatch("identify", {"backend": "mock"}, {"demo_storage": None})
    assert result["ok"] is True
    assert result["device"] and result["capabilities"]
    assert result["warnings"] == [] or isinstance(result["warnings"], list)
