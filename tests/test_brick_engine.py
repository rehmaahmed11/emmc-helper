"""Tests for the brick engine: fault injection, platform guards, and honest damage.

Each brick must actually produce the fault signals it declares. A brick that silently does
nothing would make every downstream PASS meaningless, so these tests read the device back and
check the damage is real - through Revive's own parsers where there is one.
"""
from __future__ import annotations

from pathlib import Path

from revive.lab_testing import BrickEngine, BrickError, LabBench, brick_types, collect_signals
from revive.lab_testing import gpt_virtual
from revive.lab_testing.device import MODE_MTK_BROM, MODE_NORMAL, MODE_QC_EDL
from revive.lab_testing.partitions import ST_DAMAGED, ST_DIRTY, ST_OK
from revive.lab_testing.scenarios import nvram_damage

SMALL = 8 * 1024 * 1024


def _device(tmp: Path, chip: str = "MT6768"):
    return LabBench(tmp / "lab").create(chip=chip, image_bytes=SMALL)


def test_the_catalogue_exposes_the_seven_faults_the_task_names():
    ids = {entry["id"] for entry in brick_types()}
    assert ids == {
        "gpt_corruption", "boot_corruption", "userdata_failure", "bad_emmc",
        "nvram_damage", "qualcomm_edl_failure", "mtk_brom_failure",
    }, ids


def test_short_brick_names_resolve_to_scenarios(tmp: Path):
    device = _device(tmp)
    engine = BrickEngine(device)
    try:
        assert engine.resolve("gpt").id == "gpt_corruption"
        assert engine.resolve("boot").id == "boot_corruption"
        assert engine.resolve("nvram").id == "nvram_damage"
        assert engine.resolve("emmc").id == "bad_emmc"
        assert engine.resolve("brom").id == "mtk_brom_failure"
        assert engine.resolve("edl").id == "qualcomm_edl_failure"
        assert engine.resolve("userdata").id == "userdata_failure"
    finally:
        device.close()


def test_an_unknown_brick_type_lists_what_is_available(tmp: Path):
    device = _device(tmp)
    try:
        try:
            BrickEngine(device).resolve("make-coffee")
        except BrickError as exc:
            assert "no lab scenario" in str(exc)
        else:
            raise AssertionError("an unknown brick type should be refused")
    finally:
        device.close()


def test_a_healthy_device_has_no_signals(tmp: Path):
    device = _device(tmp)
    try:
        assert collect_signals(device)["signals"] == []
    finally:
        device.close()


# --------------------------------------------------------------------------------------
# Each brick does what it says
# --------------------------------------------------------------------------------------

def test_gpt_corruption_breaks_both_crcs(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("gpt")
        state = gpt_virtual.read(device.image_path)
        assert state.header_crc_ok is False
        assert state.entries_crc_ok is False
        assert state.readable is True, "the backup copy should still hold the layout"
        signals = collect_signals(device)["signals"]
        assert {"gpt_header_crc_bad", "gpt_entries_crc_bad", "gpt_primary_damaged"} <= set(signals)
        assert device.partition("pgpt").status == ST_DAMAGED
        assert device.status == "bricked"
    finally:
        device.close()


def test_gpt_corruption_can_erase_the_primary_table_entirely(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("gpt", {"mode": "missing"})
        state = gpt_virtual.read(device.image_path)
        assert state.primary_readable is False
        assert state.readable is True, "the backup copy survives in 'missing' mode"
        assert state.partition_count > 0
        assert "gpt_primary_unreadable" in collect_signals(device)["signals"]
    finally:
        device.close()


def test_gpt_corruption_can_destroy_both_table_copies(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("gpt", {"mode": "total"})
        state = gpt_virtual.read(device.image_path)
        assert state.readable is False
        assert "gpt_missing" in collect_signals(device)["signals"]
        assert device.boot().booted is False
    finally:
        device.close()


def test_gpt_corruption_is_idempotent(tmp: Path):
    """Bricking twice must not undo the damage - a real fault does not repair itself."""
    device = _device(tmp)
    try:
        engine = BrickEngine(device)
        engine.apply("gpt")
        first = set(collect_signals(device)["signals"])
        engine.apply("gpt")
        second = set(collect_signals(device)["signals"])
        assert "gpt_entries_crc_bad" in second, "the second brick undid the first"
        assert first == second, (first, second)
    finally:
        device.close()


def test_an_unknown_gpt_mode_is_refused(tmp: Path):
    device = _device(tmp)
    try:
        try:
            BrickEngine(device).apply("gpt", {"mode": "sideways"})
        except BrickError as exc:
            assert "unknown GPT damage mode" in str(exc)
        else:
            raise AssertionError("an unknown damage mode should be refused")
    finally:
        device.close()


def test_boot_corruption_removes_the_android_magic(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("boot")
        boot = device.partition("boot")
        assert device.emmc.read(boot.offset, 8) != b"ANDROID!"
        assert boot.status == ST_DAMAGED
        signals = collect_signals(device)["signals"]
        assert "boot_image_invalid" in signals and "boot_fails" in signals
        result = device.boot()
        assert result.booted is False and result.reached == "kernel", result.reached
    finally:
        device.close()


def test_userdata_failure_marks_the_filesystem_dirty(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("userdata")
        userdata = device.partition("userdata")
        assert userdata.status == ST_DIRTY
        assert "userdata_fs_dirty" in collect_signals(device)["signals"]
        assert device.boot().booted is True, "a dirty userdata boots, then offers a reset"
    finally:
        device.close()


def test_bad_emmc_moves_the_registers_and_the_write_behaviour(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("emmc")
        assert device.emmc.spec.pre_eol_value == 0x03
        assert len(device.emmc.bad_blocks) > 0
        signals = collect_signals(device)["signals"]
        assert {"emmc_pre_eol_urgent", "emmc_life_exceeded", "emmc_bad_blocks",
                "emmc_health_fatal"} <= set(signals)
        assert device.emmc.assess()["verdict"] == "fatal"
    finally:
        device.close()


def test_bad_emmc_warning_state_is_a_warning_not_a_death(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("emmc", {"health": "warning"})
        assert device.emmc.spec.pre_eol_value == 0x02
        signals = collect_signals(device)["signals"]
        assert "emmc_pre_eol_warning" in signals
        assert "emmc_pre_eol_urgent" not in signals
        assert device.emmc.assess()["verdict"] == "warn"
    finally:
        device.close()


def test_nvram_damage_destroys_the_imei_and_only_the_identity_partitions(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("nvram")
        identity = nvram_damage.identity_partitions(device)
        assert "nvram" in identity
        for name in identity:
            assert nvram_damage.read_identity(device, name)["valid"] is False
        assert nvram_damage.read_identity(device, "nvram")["imei"] == ""
        assert "nvram_invalid" in collect_signals(device)["signals"]
        # Filesystem partitions that merely sit near the identity data must not be touched.
        assert device.partition("nvdata").status == ST_OK
        assert device.partition("protect1").status == ST_OK
    finally:
        device.close()


def test_nvram_damage_on_qualcomm_hits_the_modem_identity(tmp: Path):
    device = _device(tmp, chip="SDM660")
    try:
        BrickEngine(device).apply("nvram")
        for name in ("modemst1", "modemst2", "fsg"):
            assert nvram_damage.read_identity(device, name)["valid"] is False
        assert "nvram_invalid" in collect_signals(device)["signals"]
    finally:
        device.close()


def test_mtk_brom_failure_puts_the_device_in_download_mode(tmp: Path):
    device = _device(tmp)
    try:
        BrickEngine(device).apply("brom")
        assert device.profile.boot_mode == MODE_MTK_BROM
        assert device.emmc.read(device.partition("preloader").offset, 9) != b"EMMC_BOOT"
        signals = collect_signals(device)["signals"]
        assert {"device_in_brom", "preloader_damaged", "boot_fails"} <= set(signals)
        backend = device.backend()
        backend.open()
        try:
            assert backend.identify().mode == MODE_MTK_BROM
        finally:
            backend.close()
    finally:
        device.close()


def test_qualcomm_edl_failure_reports_9008(tmp: Path):
    device = _device(tmp, chip="SDM660")
    try:
        BrickEngine(device).apply("edl")
        assert device.profile.boot_mode == MODE_QC_EDL
        signals = collect_signals(device)["signals"]
        assert {"device_in_edl", "bootloader_damaged", "boot_fails"} <= set(signals)
        assert device.profile.usb_id == "05c6:9008"
    finally:
        device.close()


# --------------------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------------------

def test_a_mediatek_brick_is_refused_on_a_qualcomm_device(tmp: Path):
    device = _device(tmp, chip="SDM660")
    try:
        try:
            BrickEngine(device).apply("brom")
        except BrickError as exc:
            assert "does not apply" in str(exc) and "mtk" in str(exc)
        else:
            raise AssertionError("BROM is not a Qualcomm download mode")
        assert device.profile.boot_mode == MODE_NORMAL
    finally:
        device.close()


def test_a_qualcomm_brick_is_refused_on_a_mediatek_device(tmp: Path):
    device = _device(tmp)
    try:
        try:
            BrickEngine(device).apply("edl")
        except BrickError as exc:
            assert "does not apply" in str(exc)
        else:
            raise AssertionError("EDL is not a MediaTek download mode")
    finally:
        device.close()


def test_available_scenarios_are_filtered_by_platform(tmp: Path):
    mtk = _device(tmp, chip="MT6768")
    qualcomm = _device(tmp, chip="SDM450")
    try:
        mtk_ids = set(BrickEngine(mtk).available_ids())
        qc_ids = set(BrickEngine(qualcomm).available_ids())
        assert "mtk_brom_failure" in mtk_ids and "mtk_brom_failure" not in qc_ids
        assert "qualcomm_edl_failure" in qc_ids and "qualcomm_edl_failure" not in mtk_ids
        assert {"gpt_corruption", "boot_corruption", "bad_emmc"} <= mtk_ids & qc_ids
    finally:
        mtk.close()
        qualcomm.close()


def test_repair_without_a_brick_is_refused(tmp: Path):
    device = _device(tmp)
    try:
        try:
            BrickEngine(device).repair()
        except BrickError as exc:
            assert "no unrepaired brick" in str(exc)
        else:
            raise AssertionError("repairing a healthy device should say so")
    finally:
        device.close()


def test_applying_a_brick_records_it_on_the_device(tmp: Path):
    device = _device(tmp)
    try:
        result = BrickEngine(device).apply("boot")
        assert result["expected_signals"], "a brick must declare what it should look like"
        faults = device.active_faults
        assert len(faults) == 1 and faults[0].id == "boot_corruption"
        assert faults[0].partitions == ["boot"]
        assert faults[0].applied_at
    finally:
        device.close()
