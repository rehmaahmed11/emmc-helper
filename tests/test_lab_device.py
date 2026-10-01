"""Tests for the LAB TESTING device model: profiles, layout, boot, persistence, the lab DB.

These tests only ever create virtual devices inside the temp dir the runner hands them, so they
never touch hardware and never write outside the sandbox.
"""
from __future__ import annotations

import json
from pathlib import Path

from revive.lab_testing import (DeviceProfile, LabBench, VirtualDevice, get_profile,
                                layout_for, profile_keys)
from revive.lab_testing.device import (MODE_MTK_BROM, MODE_NORMAL, MODE_QC_EDL,
                                       STATE_BRICKED, STATE_HEALTHY, STATE_RECOVERED)
from revive.lab_testing.partitions import ST_OK, plan_layout

SMALL = 8 * 1024 * 1024


def _bench(tmp: Path) -> LabBench:
    return LabBench(tmp / "lab")


def test_profiles_cover_every_platform_the_task_names():
    keys = profile_keys()
    for expected in ("MT6765", "MT6768", "MT6877", "SDM450", "SDM660", "SDM7XX", "UNISOC"):
        assert expected in keys, f"missing profile {expected}"
    platforms = {get_profile(k).platform for k in keys}
    assert platforms == {"mtk", "qualcomm", "unisoc"}, platforms


def test_profile_resolves_aliases_and_free_text():
    assert get_profile("mt6768").chipset == "MT6768"
    assert get_profile("Helio G85").chipset == "MT6768"
    assert get_profile("snapdragon 660").chipset == "Snapdragon 660"
    assert get_profile("7 series").platform == "qualcomm"
    assert get_profile("pac").platform == "unisoc"


def test_profile_shape_matches_the_documented_profile():
    profile = get_profile("MT6768")
    data = profile.to_dict()
    # The task specifies these exact keys for a device profile.
    for key in ("name", "chipset", "vendor", "storage", "interface", "boot_mode"):
        assert key in data, f"profile is missing {key}"
    assert data["boot_mode"] == MODE_NORMAL
    assert data["interface"] == "eMMC"
    assert data["storage_bytes"] == 64 * 1024 ** 3


def test_unknown_chip_code_is_derived_and_labelled_as_such():
    profile = get_profile("0x0335")
    assert profile.hwcode == 0x0335
    assert profile.platform == "mtk"
    assert "derived" in profile.notes.lower()


def test_unknown_chip_without_a_code_is_refused():
    try:
        get_profile("totally-unknown-chip")
    except ValueError as exc:
        assert "no lab profile" in str(exc)
    else:
        raise AssertionError("an unknown chipset should be refused, not guessed")


def test_creating_a_device_writes_the_documented_lab_folder(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", storage="64GB", image_bytes=SMALL)
    try:
        for name in ("device.json", "emmc.img", "partition_map.json", "extcsd.json"):
            assert (device.folder / name).exists(), f"{name} was not written"
        assert (device.folder / "logs").is_dir()
        assert (device.folder / "golden").is_dir()
        assert (device.folder / "logs" / "events.jsonl").exists()
        assert device.status == STATE_HEALTHY
    finally:
        device.close()


def test_mtk_layout_contains_every_partition_the_task_lists(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        names = {p.name for p in device.partitions}
        for expected in ("preloader", "boot", "vendor", "system", "userdata", "nvram",
                         "nvdata", "protect1", "protect2"):
            assert expected in names, f"the MTK layout is missing {expected}"
    finally:
        device.close()


def test_qualcomm_layout_contains_every_partition_the_task_lists(tmp: Path):
    device = _bench(tmp).create(chip="SDM660", image_bytes=SMALL)
    try:
        names = {p.name for p in device.partitions}
        for expected in ("xbl", "abl", "boot", "system", "vendor", "modemst1", "modemst2", "fsg"):
            assert expected in names, f"the Qualcomm layout is missing {expected}"
    finally:
        device.close()


def test_every_partition_has_a_name_size_checksum_and_status(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        for part in device.partitions:
            assert part.name, "a partition without a name"
            assert part.size > 0, f"{part.name} has no size"
            assert len(part.checksum) == 64, f"{part.name} has no SHA-256"
            assert part.status == ST_OK, f"{part.name} starts as {part.status}"
        # The layout must not overlap itself or run past the image.
        ordered = sorted((p for p in device.partitions if p.size > 0), key=lambda p: p.offset)
        for a, b in zip(ordered, ordered[1:]):
            assert a.end <= b.offset, f"{a.name} and {b.name} overlap"
        assert ordered[-1].end <= device.emmc.image_bytes
    finally:
        device.close()


def test_the_table_partition_sits_at_lba_zero(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        pgpt = device.partition("pgpt")
        assert pgpt is not None and pgpt.offset == 0
        assert device.emmc.read(512, 8) == b"EFI PART"
    finally:
        device.close()


def test_a_healthy_device_boots_to_android(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        result = device.boot()
        assert result.booted is True, result.reason
        assert result.reached == "android"
        stages = [s.name for s in result.stages]
        assert "kernel" in stages and "system" in stages, stages
    finally:
        device.close()


def test_boot_stops_in_download_mode_instead_of_booting(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        device.profile.boot_mode = MODE_MTK_BROM
        result = device.boot()
        assert result.booted is False
        assert "download mode" in result.reason
    finally:
        device.close()


def test_verify_passes_on_a_healthy_device_and_names_its_checks(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        check = device.verify()
        assert check["ok"] is True and check["verdict"] == "PASS", check
        names = {c["name"] for c in check["checks"]}
        assert {"partition table", "boot", "partitions", "storage health", "faults"} <= names
    finally:
        device.close()


def test_device_survives_a_save_and_reload_round_trip(tmp: Path):
    bench = _bench(tmp)
    device = bench.create(chip="SDM660", storage="32GB", image_bytes=SMALL)
    device_id = device.id
    checksums = {p.name: p.checksum for p in device.partitions}
    device.close()

    reloaded = bench.get(device_id)
    try:
        assert reloaded.profile.chipset == "Snapdragon 660"
        assert reloaded.profile.platform == "qualcomm"
        assert reloaded.profile.hwcode is None, "Qualcomm profiles have no MediaTek hwcode"
        assert reloaded.imei == device.imei
        assert {p.name: p.checksum for p in reloaded.partitions} == checksums
        assert reloaded.verify()["ok"] is True
        # And the profile can be serialised again after the reload.
        assert reloaded.profile.to_dict()["hwcode"] == ""
    finally:
        reloaded.close()


def test_bench_indexes_devices_and_tracks_the_active_one(tmp: Path):
    bench = _bench(tmp)
    first = bench.create(chip="MT6768", image_bytes=SMALL)
    second = bench.create(chip="MT6765", image_bytes=SMALL)
    first_id, second_id = first.id, second.id
    first.close()
    second.close()

    listed = {d["id"] for d in bench.list_devices()}
    assert {first_id, second_id} <= listed
    assert bench.get().id == second_id, "the most recently created device should be active"
    bench.set_active(first_id)
    assert bench.get().id == first_id

    bench.delete(second_id)
    assert second_id not in {d["id"] for d in bench.list_devices()}
    assert not (bench.root / second_id).exists()


def test_history_records_timestamp_device_scenario_and_result(tmp: Path):
    bench = _bench(tmp)
    bench.record({"device": "d1", "scenario": "gpt_corruption", "result": "PASS",
                  "detection": "PASS", "repair": "PASS", "verification": "PASS"})
    rows = bench.history()
    assert len(rows) == 1
    for key in ("timestamp", "device", "scenario", "result"):
        assert rows[0].get(key), f"history row has no {key}"


def test_reset_rebuilds_the_device_and_clears_faults(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        device.apply_fault("test_brick", label="test")
        assert device.status == STATE_BRICKED and device.active_faults
        device.reset()
        assert device.status == STATE_HEALTHY
        assert not device.active_faults
        assert device.verify()["ok"] is True
    finally:
        device.close()


def test_marking_the_last_fault_repaired_moves_the_device_to_recovered(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        device.apply_fault("a", label="A")
        device.apply_fault("b", label="B")
        device.mark_repaired("a")
        assert device.status == STATE_BRICKED
        device.mark_repaired("b")
        assert device.status == STATE_RECOVERED
        assert [f.id for f in device.faults] == ["a", "b"]
        assert all(f.repaired for f in device.faults)
    finally:
        device.close()


def test_layout_planner_keeps_partitions_inside_the_image():
    for size in (4 * 1024 * 1024, 8 * 1024 * 1024, 32 * 1024 * 1024):
        for platform in ("mtk", "qualcomm", "unisoc"):
            plan = plan_layout(layout_for(platform), size)
            assert plan.partitions, f"no partitions planned for {platform} at {size}"
            for part in plan.partitions:
                assert part.offset >= 0 and part.size > 0
                assert part.end <= size, f"{part.name} runs past the image at {size}"
            ordered = sorted(plan.partitions, key=lambda p: p.offset)
            for a, b in zip(ordered, ordered[1:]):
                assert a.end <= b.offset, f"{a.name}/{b.name} overlap at {size}"


def test_layout_planner_refuses_an_image_too_small_for_a_gpt():
    try:
        plan_layout(layout_for("mtk"), 1024 * 1024)
    except ValueError as exc:
        assert "4 MiB" in str(exc)
    else:
        raise AssertionError("a 1 MiB image cannot hold a GPT and its partitions")


def test_the_backend_transport_reports_the_device_platform(tmp: Path):
    device = _bench(tmp).create(chip="SDM660", image_bytes=SMALL)
    try:
        backend = device.backend()
        backend.open()
        try:
            info = backend.identify()
            assert info.mode == MODE_QC_EDL, info.mode
            assert "simulated" in info.vendor.lower()
            assert info.extras["lab"]["platform"] == "qualcomm"
            partitions = backend.list_partitions()
        finally:
            backend.close()
        assert len(partitions) > 0
        # LBA-0 entries are excluded by Revive's reader, so pgpt is not in the list.
        assert "pgpt" not in {p.name for p in partitions}
    finally:
        device.close()


def test_backend_read_and_write_reach_the_same_image_file(tmp: Path):
    import tempfile

    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        # `lk` holds unstructured loader content, so its head is recognisable; the filesystem
        # partitions keep their first KiB empty, the way a real ext4 does.
        part = device.partition("lk")
        backend = device.backend()
        backend.open()
        try:
            probe = Path(tempfile.mkdtemp()) / "probe.bin"
            backend.read_flash(part.offset, 4096, probe)
            assert probe.read_bytes()[:13] == b"REVIVE LAB RA"
            # A write through the backend must land in the same file the device reads.
            payload = Path(tempfile.mkdtemp()) / "payload.bin"
            payload.write_bytes(b"BACKEND WRITE" * 16)
            backend.write_flash(part.offset + 8192, payload)
        finally:
            backend.close()
        assert device.emmc.read(part.offset + 8192, 13) == b"BACKEND WRITE"
    finally:
        device.close()


def test_device_json_is_valid_and_carries_the_partition_map(tmp: Path):
    device = _bench(tmp).create(chip="MT6768", image_bytes=SMALL)
    try:
        meta = json.loads((device.folder / "device.json").read_text(encoding="utf-8"))
        assert meta["schema"] == "revive-lab-device/1"
        assert meta["profile"]["chipset"] == "MT6768"
        mapping = json.loads((device.folder / "partition_map.json").read_text(encoding="utf-8"))
        assert mapping["schema"] == "revive-lab-partitions/1"
        assert len(mapping["partitions"]) == len(device.partitions)
        assert mapping["gpt"]["header_crc_ok"] is True
        ext = json.loads((device.folder / "extcsd.json").read_text(encoding="utf-8"))
        assert ext["schema"] == "revive-lab-extcsd/1"
        assert ext["verdict"] == "ok"
    finally:
        device.close()


def test_a_device_profile_defaults_to_something_usable():
    profile = DeviceProfile()
    assert profile.chipset and profile.storage and profile.interface
    assert profile.storage_bytes == 64 * 1024 ** 3


def test_virtual_device_refuses_to_load_a_folder_that_is_not_a_device(tmp: Path):
    try:
        VirtualDevice.load(tmp)
    except FileNotFoundError as exc:
        assert "not a lab device folder" in str(exc)
    else:
        raise AssertionError("loading a non-device folder should fail loudly")
