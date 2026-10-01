"""Tests for the shared helpers."""
from __future__ import annotations

import json
from pathlib import Path

from fixtures import read  # noqa: F401
from revive import util


def test_size_formatting(_tmp):
    assert util.human_size(0) == "0 B"
    assert util.human_size(1023) == "1023 B"
    assert util.human_size(1024) == "1.00 KB"
    assert util.human_size(1024 ** 3) == "1.00 GB"
    assert util.human_size(None) == "?"


def test_parse_size(_tmp):
    assert util.parse_size("512") == 512
    assert util.parse_size("4G") == 4 * 1024 ** 3
    assert util.parse_size(" 2 mb ") == 2 * 1024 ** 2
    try:
        util.parse_size("nonsense")
    except ValueError:
        pass
    else:
        raise AssertionError("parse_size should reject non-sizes")


def test_hashing_and_checksums(tmp):
    path = tmp / "x.bin"
    path.write_bytes(b"revive")
    assert util.sha256_file(path) == util.sha256_bytes(b"revive")
    assert util.checksum16(b"\x01\x02") == 3
    assert util.crc32(b"") == 0


def test_atomic_write_and_unique_path(tmp):
    target = tmp / "nested" / "file.bin"
    util.atomic_write(target, b"one")
    assert target.read_bytes() == b"one"
    second = util.unique_path(target)
    assert second.name != target.name and not second.exists()


def test_safe_filename(_tmp):
    assert util.safe_filename("system_a") == "system_a"
    assert "/" not in util.safe_filename("we/ird:name?")
    assert util.safe_filename("") == "unnamed"
    assert util.safe_filename("...") == "unnamed"


def test_align_and_hexdump(_tmp):
    assert util.align_up(5, 4096) == 4096
    assert util.align_up(4096, 4096) == 4096
    dump = util.hexdump(b"ABCD", limit=4)
    assert "41 42 43 44" in dump and "|ABCD|" in dump


def test_reporter_and_result(tmp):
    reporter = util.Reporter("demo")
    reporter.info("note")
    reporter.warn("careful")
    assert reporter.ok_to_proceed
    reporter.error("broken")
    assert not reporter.ok_to_proceed
    assert reporter.worst == util.SEV_ERROR
    payload = reporter.to_dict()
    assert payload["summary"].startswith("1 error")
    json.dumps(payload)  # must be serialisable for the web UI

    result = util.Result.failure("nope", error_code="2005")
    assert not result.ok and result.to_dict()["error_code"] == "2005"
    assert util.Result.success("yes", data={"a": 1}).to_dict()["data"] == {"a": 1}


def test_finding_and_progress_types(_tmp):
    finding = util.Finding(util.SEV_WARN, "title", "detail", ["fix"], code="X")
    assert finding.to_dict()["fixes"] == ["fix"]
    step = util.Step("connect")
    step.status = "done"
    assert step.to_dict()["status"] == "done"
    util.null_progress(1, 2)


def test_json_store(tmp):
    store = util.JsonStore(tmp / "settings.json", {"port": 8765})
    assert store.load()["port"] == 8765
    store.save({"port": 9000, "extra": True})
    loaded = store.load()
    assert loaded["port"] == 9000 and loaded["extra"] is True


def test_to_dict_handles_paths_and_bytes(tmp):
    payload = util.to_dict({"path": Path("/tmp/x"), "blob": b"1234", "n": None})
    assert payload["path"] == "/tmp/x"
    assert payload["blob"] == "<4 bytes>"
    assert payload["n"] is None
