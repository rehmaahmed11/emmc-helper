"""Device archive tests — Rule 1 of RULES.md.

One folder per device that ever connected, named after the device; every hardware read
saves a timestamped read-info file (seconds precision); nothing is ever overwritten;
variants of the same model get separate folders.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path

from revive import cli
from revive.backends import DetectionResult, intercept_and_capture
from revive.backends.base import DeviceInfo
from revive.ops import device_archive
from revive.ui import api

T0 = datetime(2026, 10, 1, 19, 45, 3)
T1 = T0.replace(second=4)          # one second later
T2 = T0.replace(second=5)


def usb_read_info(**overrides) -> dict:
    """A read-info dict in the exact shape `revive detect` emits (usbmodes.UsbDevice)."""
    base = {
        "vid": "1a56",
        "pid": "1046",
        "id": "1a56:1046",
        "bus": 3,
        "address": 5,
        "manufacturer": "Infinix",
        "product": "Infinix Hot 8 X650B",
        "serial": "INFINIX12345",
        "mode": "mtk_brom",
        "label": "MediaTek Boot ROM (BROM)",
        "backend": "mtk",
        "flashable": True,
        "description": "the boot ROM of the phone",
        "advice": ["power off first"],
        "power_hint": "hold vol up + down",
    }
    base.update(overrides)
    return base


def read_info_files(folder: Path):
    return sorted(p.name for p in (folder / "read_info").glob("*.json"))


def test_folder_layout_and_subfolders(tmp: Path):
    res = device_archive.archive_read_info(usb_read_info(), root=tmp, source="detect", when=T0)
    assert res["ok"] and res["created"]
    folder = Path(res["device_folder"])
    assert folder.name == "Infinix Hot 8 X650B"
    for sub in ("read_info", "full_dump", "partitions", "notes"):
        assert (folder / sub).is_dir(), sub
    assert (folder / "device.json").exists()
    assert read_info_files(folder) == ["read_info_20261001_194503.json"]
    record = json.loads((folder / "device.json").read_text(encoding="utf-8"))
    assert record["identity"] == res["identity"]
    assert record["connects"] == 1
    assert record["usb_id"] == "1a56:1046"


def test_filename_timestamp_includes_seconds(tmp: Path):
    res = device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    name = Path(res["file"]).name
    assert re.fullmatch(r"read_info_\d{8}_\d{6}\.json", name)
    assert name == "read_info_20261001_194503.json"


def test_same_device_twice_same_folder_no_overwrite(tmp: Path):
    first = device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    second = device_archive.archive_read_info(usb_read_info(), root=tmp, when=T1)
    assert second["device_folder"] == first["device_folder"]
    assert not second["created"]
    folder = Path(first["device_folder"])
    assert read_info_files(folder) == ["read_info_20261001_194503.json",
                                       "read_info_20261001_194504.json"]
    record = json.loads((folder / "device.json").read_text(encoding="utf-8"))
    assert record["connects"] == 2
    assert record["read_info_files"] == 2


def test_same_second_never_overwrites(tmp: Path):
    device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    folder = next(tmp.iterdir())
    assert read_info_files(folder) == ["read_info_20261001_194503.json",
                                       "read_info_20261001_194503_02.json"]


def test_model_variants_get_separate_folders(tmp: Path):
    a = device_archive.archive_read_info(
        usb_read_info(product="Infinix Hot 8 X650"), root=tmp, when=T0)
    b = device_archive.archive_read_info(
        usb_read_info(product="Infinix Hot 8 X650B"), root=tmp, when=T0)
    c = device_archive.archive_read_info(
        usb_read_info(product="Infinix Hot 8 X650C"), root=tmp, when=T0)
    folders = {a["device_name"], b["device_name"], c["device_name"]}
    assert folders == {"Infinix Hot 8 X650", "Infinix Hot 8 X650B", "Infinix Hot 8 X650C"}
    listed = device_archive.list_devices(tmp)
    assert listed["device_count"] == 3


def test_session_fields_do_not_split_the_device(tmp: Path):
    first = device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    # Same hardware, different session data: other mode, other port, security flags.
    second = device_archive.archive_read_info(
        usb_read_info(mode="fastboot", bus=7, address=9,
                      security={"secure_boot": False, "sla": False}),
        root=tmp, when=T1)
    assert second["device_folder"] == first["device_folder"]
    assert not second["created"]
    assert len(read_info_files(Path(first["device_folder"]))) == 2


def test_identity_is_canonical(tmp: Path):
    base = usb_read_info()
    reordered = dict(reversed(list(base.items())))
    assert device_archive.identity_of(base) == device_archive.identity_of(reordered)

    info = DeviceInfo(
        backend="mtk", mode="mtk_brom", vendor="Infinix", hwcode=0x5D20, chip="MT6768",
        storage="eMMC", storage_size=64 * 1024 ** 3, usb_id="1a56:1046", serial="INFINIX12345",
    )
    from_dict = device_archive.normalize_read_info(info.to_dict())
    from_raw = device_archive.normalize_read_info({
        "vid": "0x1a56", "pid": 0x1046, "usb_id": "1A56:1046", "vendor": "Infinix ",
        "chip": " MT6768 ", "hwcode": "0x5d20", "hwcode_int": 0x5D20, "storage": "EMMC",
        "storage_size": "68719476736", "serial": "INFINIX12345", "backend": "MTK",
        "mode": "brom",
    })
    for key in ("usb_id", "vid", "pid", "manufacturer", "chip", "hwcode",
                "storage", "storage_size", "backend", "serial"):
        assert from_dict[key] == from_raw[key], key
    assert from_dict["hwcode"] == "0x5D20"
    assert from_dict["storage"] == "emmc"
    assert from_dict["storage_size"] == 64 * 1024 ** 3
    # and therefore the same identity
    assert device_archive.identity_of(info.to_dict()) == device_archive.identity_of(from_raw)


def test_full_dump_archiving(tmp: Path):
    first = device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    src = tmp / "mydump.bin"
    src.write_bytes(b"\x00" * 4096 + b"dumpdata")
    res = device_archive.archive_dump_file(src, root=tmp, read_info=usb_read_info(), when=T1)
    assert res["ok"]
    dest = Path(res["file"])
    assert dest.parent == Path(first["device_folder"]) / "full_dump"
    assert dest.name == "dump_20261001_194504.bin"
    assert dest.read_bytes() == src.read_bytes()
    # another dump in the same second must not overwrite the first
    res2 = device_archive.archive_dump_file(src, root=tmp, read_info=usb_read_info(), when=T1)
    assert Path(res2["file"]).name == "dump_20261001_194504_02.bin"
    record = json.loads((Path(first["device_folder"]) / "device.json").read_text(encoding="utf-8"))
    assert record["full_dumps"] == 2
    assert record["last_dump_file"] == "dump_20261001_194504_02.bin"


def test_full_dump_by_device_name(tmp: Path):
    device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    src = tmp / "full.bin"
    src.write_bytes(b"1234")
    res = device_archive.archive_dump_file(src, root=tmp, device="Infinix", when=T1)  # unique prefix
    assert res["ok"] and Path(res["file"]).parent.name == "full_dump"
    # ambiguous prefix across two variants must fail with a helpful error
    device_archive.archive_read_info(
        usb_read_info(product="Infinix Hot 8 X650C"), root=tmp, when=T0)
    try:
        device_archive.archive_dump_file(src, root=tmp, device="Infinix", when=T2)
        raise AssertionError("expected ValueError for ambiguous device name")
    except ValueError as exc:
        assert "ambiguous" in str(exc)
    # unknown device must fail too
    try:
        device_archive.archive_dump_file(src, root=tmp, device="Nokia", when=T2)
        raise AssertionError("expected ValueError for unknown device")
    except ValueError:
        pass
    # missing file must fail too
    try:
        device_archive.archive_dump_file(tmp / "nope.bin", root=tmp, device="X650B", when=T2)
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError:
        pass


def test_list_devices(tmp: Path):
    a = device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    device_archive.archive_read_info(usb_read_info(), root=tmp, when=T1)
    src = tmp / "d.bin"
    src.write_bytes(b"xx")
    device_archive.archive_dump_file(src, root=tmp, read_info=usb_read_info(), when=T2)
    data = device_archive.list_devices(tmp)
    assert data["ok"] and data["device_count"] == 1
    entry = data["devices"][0]
    assert entry["name"] == Path(a["device_folder"]).name
    assert entry["read_info_count"] == 2
    assert entry["full_dump_count"] == 1
    assert entry["connects"] == 2
    assert entry["last_seen"] == T1.isoformat(timespec="seconds")
    # empty root
    empty = tmp / "empty-root"
    assert device_archive.list_devices(empty)["device_count"] == 0


def test_env_var_root(tmp: Path):
    old = os.environ.get(device_archive.ARCHIVE_ENV_VAR)
    os.environ[device_archive.ARCHIVE_ENV_VAR] = str(tmp)
    try:
        assert device_archive.default_archive_root() == tmp
        res = device_archive.archive_read_info(usb_read_info(), when=T0)  # no root arg
        assert res["root"] == str(tmp)
    finally:
        if old is None:
            os.environ.pop(device_archive.ARCHIVE_ENV_VAR, None)
        else:
            os.environ[device_archive.ARCHIVE_ENV_VAR] = old


def test_cli_devices_commands(tmp: Path):
    device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    src = tmp / "flash.bin"
    src.write_bytes(b"binary")

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(["devices", "--archive-root", str(tmp), "list"])
    assert rc == 0
    assert "Infinix Hot 8 X650B" in out.getvalue()

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(["devices", "--archive-root", str(tmp),
                       "dump", "Infinix", str(src)])
    assert rc == 0
    assert "full_dump" in out.getvalue()
    assert (Path(tmp) / "Infinix Hot 8 X650B" / "full_dump").glob("*.bin")

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(["devices", "--archive-root", str(tmp), "show", "X650B", "--json"])
    assert rc == 0
    record = json.loads(out.getvalue())
    assert record["usb_id"] == "1a56:1046"
    assert any(p.startswith("read_info/") for p in record["files"])

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(["devices", "--archive-root", str(tmp), "list", "--json"])
    assert rc == 0
    assert json.loads(out.getvalue())["device_count"] == 1

    # bare `revive devices` (no subcommand) lists as well
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(["devices", "--archive-root", str(tmp)])
    assert rc == 0
    assert "Infinix Hot 8 X650B" in out.getvalue()

    # unknown device is a clean failure, not a traceback
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = cli.main(["devices", "--archive-root", str(tmp), "dump", "Nope", str(src)])
    assert rc != 0


def test_cli_detect_saves_read_info(tmp: Path):
    import revive.backends as backends_pkg

    fake = DetectionResult(
        devices=[usb_read_info()],
        warnings=[],
        suggested_backend="mtk",
        suggested_actions=["connect the download agent"],
    )
    original = backends_pkg.detect
    backends_pkg.detect = lambda: fake
    try:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["detect", "--archive-root", str(tmp)])
        assert rc == 0
        assert "Infinix Hot 8 X650B" in out.getvalue()
        assert len(list((tmp / "Infinix Hot 8 X650B" / "read_info").glob("*.json"))) == 1

        # --no-archive disables Rule 1 saving
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["detect", "--archive-root", str(tmp), "--no-archive"])
        assert rc == 0
        assert len(list((tmp / "Infinix Hot 8 X650B" / "read_info").glob("*.json"))) == 1
    finally:
        backends_pkg.detect = original


def test_cli_identify_demo_saves_read_info(tmp: Path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(["identify", "--demo", "--archive-root", str(tmp)])
    assert rc == 0
    folders = [d for d in tmp.iterdir() if d.is_dir()]
    assert len(folders) == 1
    assert list((folders[0] / "read_info").glob("*.json"))
    record = json.loads((folders[0] / "device.json").read_text(encoding="utf-8"))
    assert record["backend"] == "mock"
    assert record["simulated"] is True


def test_ui_detect_archives_on_connect(tmp: Path):
    old = os.environ.get(device_archive.ARCHIVE_ENV_VAR)
    os.environ[device_archive.ARCHIVE_ENV_VAR] = str(tmp)
    api.reset_seen_devices()
    try:
        ctx = {"demo": True, "started": time.time()}
        first = api.dispatch("detect", {}, ctx)
        assert first["device_archive"]["saved"] == 1
        folder = next(tmp.iterdir())
        assert len(read_info_files(folder)) == 1

        # device still connected -> polling does NOT create new files
        second = api.dispatch("detect", {}, ctx)
        assert "device_archive" not in second or second["device_archive"]["saved"] == 0
        assert len(read_info_files(folder)) == 1

        # device unplugged, then re-plugged -> a fresh timestamped file
        api.reset_seen_devices()
        third = api.dispatch("detect", {}, ctx)
        assert third["device_archive"]["saved"] == 1
        assert len(read_info_files(folder)) == 2

        # no_archive payload flag disables it
        api.reset_seen_devices()
        fourth = api.dispatch("detect", {"no_archive": True}, ctx)
        assert "device_archive" not in fourth
        assert len(read_info_files(folder)) == 2
    finally:
        api.reset_seen_devices()
        if old is None:
            os.environ.pop(device_archive.ARCHIVE_ENV_VAR, None)
        else:
            os.environ[device_archive.ARCHIVE_ENV_VAR] = old


def test_ui_identify_archives(tmp: Path):
    old = os.environ.get(device_archive.ARCHIVE_ENV_VAR)
    os.environ[device_archive.ARCHIVE_ENV_VAR] = str(tmp)
    try:
        ctx = {"demo": True, "started": time.time()}
        res = api.dispatch("identify", {"backend": "mock"}, ctx)
        assert res["ok"]
        arch = res["device_archive"]
        assert arch["ok"]
        folder = Path(arch["device_folder"])
        assert (folder / "read_info" / Path(arch["file"]).name).exists()
        record = json.loads((folder / "device.json").read_text(encoding="utf-8"))
        assert record["chip"].startswith("MT676")
    finally:
        if old is None:
            os.environ.pop(device_archive.ARCHIVE_ENV_VAR, None)
        else:
            os.environ[device_archive.ARCHIVE_ENV_VAR] = old


def test_ui_devices_list_route(tmp: Path):
    device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    res = api.dispatch("devices.list", {"root": str(tmp)}, {})
    assert res["ok"] and res["device_count"] == 1
    assert res["devices"][0]["name"] == "Infinix Hot 8 X650B"


def test_ui_devices_dump_route(tmp: Path):
    device_archive.archive_read_info(usb_read_info(), root=tmp, when=T0)
    src = tmp / "full.bin"
    src.write_bytes(b"abcdef")
    res = api.dispatch("devices.dump",
                       {"root": str(tmp), "device": "Infinix", "file": str(src)}, {})
    assert res["ok"]
    assert re.fullmatch(r"dump_\d{8}_\d{6}\.bin", Path(res["file"]).name)
    assert Path(res["file"]).parent.name == "full_dump"
    bad = api.dispatch("devices.dump", {"root": str(tmp), "device": "Infinix"}, {})
    assert not bad["ok"]
    missing = api.dispatch("devices.dump",
                           {"root": str(tmp), "device": "Infinix", "file": str(tmp / "nope.bin")}, {})
    assert not missing["ok"]


def test_intercept_demo_archives(tmp: Path):
    old = os.environ.get(device_archive.ARCHIVE_ENV_VAR)
    os.environ[device_archive.ARCHIVE_ENV_VAR] = str(tmp)
    try:
        res = intercept_and_capture(backend_name="mock", out_dir=None, demo=True, archive=True)
        assert res["ok"]
        arch = res["device_archive"]
        assert arch["ok"] and Path(arch["file"]).is_file()
        assert Path(arch["file"]).parent.name == "read_info"
        # and archiving can be switched off
        res2 = intercept_and_capture(backend_name="mock", out_dir=None, demo=True, archive=False)
        assert res2["device_archive"] is None
    finally:
        if old is None:
            os.environ.pop(device_archive.ARCHIVE_ENV_VAR, None)
        else:
            os.environ[device_archive.ARCHIVE_ENV_VAR] = old


def test_name_collision_with_different_identity(tmp: Path):
    """Two different devices that want the same folder name get 'name 2'."""
    a = device_archive.archive_read_info(
        usb_read_info(product="X650"), root=tmp, when=T0)
    b = device_archive.archive_read_info(
        usb_read_info(product="X650", usb_id="1a56:1047", serial="OTHER999"),
        root=tmp, when=T0)
    assert a["device_name"] == "X650"
    assert b["device_name"] == "X650 2"
    assert a["device_folder"] != b["device_folder"]


def test_long_names_are_capped(tmp: Path):
    res = device_archive.archive_read_info(
        usb_read_info(product="P" * 400), root=tmp, when=T0)
    assert len(res["device_name"]) <= device_archive.MAX_NAME_LEN
