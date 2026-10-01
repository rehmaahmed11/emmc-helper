"""Tests for the virtual eMMC: registers, health, bad blocks, user-area IO.

The point of these tests is that the registers the lab generates are fed back through
`revive.storage.emmc` - Revive's real JEDEC decoder. If the generator ever drifts away from the
register layout the decoder reads, these tests fail rather than the lab quietly lying.
"""
from __future__ import annotations

from pathlib import Path

from revive.lab_testing import LabBench, RegisterSpec, VirtualEMMC, register_selftest
from revive.lab_testing import extcsd_virtual as regs
from revive.lab_testing.emmc_virtual import BadBlock, VirtualEmmcError
from revive.lab_testing.extcsd_virtual import DEAD, HEALTHY, WARNING
from revive.storage import emmc as emmc_mod

SMALL = 8 * 1024 * 1024


def _emmc(tmp: Path, **kwargs) -> VirtualEMMC:
    return VirtualEMMC.create(tmp / "emmc.img", capacity_bytes=64 * 1024 ** 3,
                              image_bytes=SMALL, golden_dir=tmp / "golden", **kwargs)


# --------------------------------------------------------------------------------------
# Registers
# --------------------------------------------------------------------------------------

def test_generated_ext_csd_round_trips_through_revives_real_decoder():
    spec = RegisterSpec(capacity_bytes=64 * 1024 ** 3)
    info = emmc_mod.parse_ext_csd(regs.build_ext_csd(spec))
    assert info.capacity_bytes == 64 * 1024 ** 3, info.capacity_bytes
    assert info.sec_count == spec.sec_count
    assert info.boot_size == spec.boot_size_mult * 128 * 1024
    assert info.rpmb_size == spec.rpmb_size_mult * 128 * 1024
    assert info.revision == spec.ext_csd_rev
    assert info.firmware_version == spec.firmware_version


def test_generated_cid_round_trips_and_names_the_manufacturer():
    spec = RegisterSpec(manufacturer="Samsung", product_name="LAB8G5", serial=0x1AB2C3D4,
                        year=2015, month=6)
    cid = emmc_mod.parse_cid(regs.build_cid(spec))
    assert cid.manufacturer == "Samsung", cid.manufacturer
    assert cid.product_name == "LAB8G5"
    assert cid.serial == 0x1AB2C3D4
    assert cid.manufacture_date == "06/2015", cid.manufacture_date
    # The device card the lab shows and the CID the phone reports must not disagree.
    assert cid.manufacture_date == spec.to_dict()["manufacture_date"]
    assert cid.product_name == spec.to_dict()["product_name"]


def test_fields_bigger_than_their_hardware_field_are_clamped_up_front():
    """PNM is six bytes and the MDT year is four bits from 2000 - neither can hold more."""
    spec = RegisterSpec(product_name="TOOLONGNAME99", year=2024, month=13, firmware_version="0x414243444546")
    assert spec.product_name == "TOOLON"
    assert spec.year == 2015 and spec.month == 12
    assert len(spec.firmware_version) <= 8
    cid = emmc_mod.parse_cid(regs.build_cid(spec))
    assert cid.product_name == spec.product_name, "the CID disagrees with the device card"
    assert cid.manufacture_date == spec.to_dict()["manufacture_date"]


def test_a_small_chip_reports_its_capacity_in_the_csd_and_a_big_one_in_ext_csd():
    """C_SIZE is twelve bits, so a structure-3 CSD tops out at 2 GiB - just like real silicon."""
    small = RegisterSpec(capacity_bytes=2 * 1024 ** 3)
    assert emmc_mod.parse_csd(regs.build_csd(small)).size_bytes == 2 * 1024 ** 3

    big = RegisterSpec(capacity_bytes=64 * 1024 ** 3)
    csd = emmc_mod.parse_csd(regs.build_csd(big))
    ext = emmc_mod.parse_ext_csd(regs.build_ext_csd(big))
    assert csd.c_size == 0xFFF, "C_SIZE should be saturated, not silently wrong"
    assert ext.capacity_bytes == 64 * 1024 ** 3
    # Revive must be able to tell the reader which of the two to believe.
    notes = emmc_mod.summary(emmc_mod.parse_cid(regs.build_cid(big)), csd, ext)["notes"]
    assert any("trust EXT_CSD" in note for note in notes), notes


def test_the_three_health_states_decode_to_the_right_verdict():
    results = register_selftest()
    assert results[HEALTHY]["verdict"] == "ok"
    assert results[WARNING]["verdict"] == "warn"
    assert results[DEAD]["verdict"] == "fatal"
    for state, data in results.items():
        assert data["decoded_capacity"] == data["expected_capacity"], state


def test_pre_eol_bytes_are_exactly_the_ones_the_task_specifies():
    assert regs.PRE_EOL_FOR_STATE[HEALTHY] == 0x01
    assert regs.PRE_EOL_FOR_STATE[WARNING] == 0x02
    assert regs.PRE_EOL_FOR_STATE[DEAD] == 0x03
    assert RegisterSpec().with_health(DEAD).pre_eol_value == 0x03


def test_changing_health_moves_the_life_time_estimate_with_it():
    healthy = regs.life_estimate(RegisterSpec().with_health(HEALTHY))
    dead = regs.life_estimate(RegisterSpec().with_health(DEAD))
    assert healthy["verdict"] == "healthy"
    assert dead["verdict"] == "dead"
    assert dead["used_percent_estimate"] > healthy["used_percent_estimate"]
    assert "EXCEEDED" in dead["life_a_text"]


def test_life_estimate_reports_a_plausible_cycle_budget():
    estimate = regs.life_estimate(RegisterSpec(write_cycles=2900))
    assert estimate["cycles_left_estimate"] == 100
    assert estimate["write_cycles"] == 2900
    assert 0 <= estimate["remaining_percent_estimate"] <= 100


def test_an_unknown_health_state_is_refused():
    try:
        RegisterSpec().with_health("sparkling")
    except ValueError as exc:
        assert "unknown health state" in str(exc)
    else:
        raise AssertionError("an unknown health state should be refused")


# --------------------------------------------------------------------------------------
# The controller
# --------------------------------------------------------------------------------------

def test_manufacturer_can_be_changed_and_is_reported_by_the_real_decoder(tmp: Path):
    emmc = _emmc(tmp)
    result = emmc.set_manufacturer("Micron")
    assert result["manufacturer"] == "Micron"
    assert emmc.registers_decoded()["cid"]["manufacturer"] == "Micron"


def test_an_unknown_manufacturer_is_accepted_but_noted(tmp: Path):
    emmc = _emmc(tmp)
    result = emmc.set_manufacturer("NoName NAND")
    assert result["note"], "an unlisted MID should be called out"
    assert any("not in Revive's manufacturer table" in note for note in emmc.notes)


def test_capacity_size_and_firmware_version_can_all_be_changed(tmp: Path):
    emmc = _emmc(tmp)
    emmc.set_size("128GB")
    assert emmc.spec.capacity_bytes == 128 * 1024 ** 3
    assert emmc.registers_decoded()["ext_csd"]["capacity_bytes"] == 128 * 1024 ** 3
    emmc.set_firmware_version("0x4c414231")
    assert emmc.spec.firmware_version == "4C414231"
    assert emmc.registers_decoded()["ext_csd"]["firmware_version"] == "4C414231"
    emmc.set_product_name("NEWE51")
    assert emmc.registers_decoded()["cid"]["product_name"] == "NEWE51"


def test_an_absurd_capacity_is_refused(tmp: Path):
    emmc = _emmc(tmp)
    try:
        emmc.set_capacity(512)
    except VirtualEmmcError as exc:
        assert "not a plausible eMMC" in str(exc)
    else:
        raise AssertionError("a 512-byte eMMC should be refused")


def test_health_signals_follow_the_registers(tmp: Path):
    emmc = _emmc(tmp)
    assert emmc.signals() == [], emmc.signals()
    emmc.set_health(WARNING)
    assert "emmc_pre_eol_warning" in emmc.signals()
    emmc.set_health(DEAD)
    signals = emmc.signals()
    assert "emmc_pre_eol_urgent" in signals and "emmc_life_exceeded" in signals
    assert "emmc_health_fatal" in signals


def test_a_dying_chip_is_diagnosed_fatal_by_revives_own_assessment(tmp: Path):
    emmc = _emmc(tmp)
    emmc.set_health(DEAD)
    assessment = emmc.assess()
    assert assessment["verdict"] == "fatal", assessment["verdict"]
    titles = " ".join(f["title"] for f in assessment["findings"]).lower()
    assert "wear" in titles or "life" in titles


def test_bad_blocks_are_recorded_and_eventually_move_the_wear_flags(tmp: Path):
    emmc = _emmc(tmp)
    assert emmc.spec.pre_eol_value == 0x01
    emmc.add_random_bad_blocks(10)
    assert len(emmc.bad_blocks) == 10
    assert emmc.spec.pre_eol_value >= 0x02, "enough bad blocks should trip the wear flag"
    assert "emmc_bad_blocks" in emmc.signals()
    assert emmc.is_bad(emmc.bad_blocks[0].offset) is not None


def test_a_read_that_hits_a_bad_block_fails(tmp: Path):
    emmc = _emmc(tmp)
    emmc.add_bad_block(64 * 1024)
    try:
        emmc.read(64 * 1024, 512)
    except VirtualEmmcError as exc:
        assert "bad block" in str(exc).lower() or "unreadable" in str(exc)
    else:
        raise AssertionError("reading a bad block should fail the way real silicon does")
    assert emmc.counters.failed_reads == 1


def test_writes_are_corrupted_while_pre_eol_is_urgent(tmp: Path):
    """The failure that makes a reflash look like it worked and then lose the data."""
    emmc = _emmc(tmp)
    marker = b"REVIVE WRITE TEST" * 32
    offset = 1024 * 1024
    emmc.write(offset, marker)
    assert emmc.read(offset, len(marker)) == marker

    emmc.set_health(DEAD)
    emmc.write(offset, marker)
    assert emmc.read(offset, len(marker)) != marker, "a dying chip should not hold the write"
    assert any("PRE_EOL_INFO is urgent" in note for note in emmc.notes)


def test_reads_and_writes_outside_the_user_area_are_refused(tmp: Path):
    emmc = _emmc(tmp)
    for offset, length in ((-1, 16), (emmc.image_bytes, 16)):
        try:
            emmc.read(offset, length)
        except VirtualEmmcError:
            pass
        else:
            raise AssertionError(f"read at {offset} should be refused")
    try:
        emmc.write(emmc.image_bytes - 8, b"\x00" * 64)
    except VirtualEmmcError as exc:
        assert "does not fit" in str(exc)
    else:
        raise AssertionError("a write past the end should be refused")


def test_counters_track_the_work_the_chip_has_done(tmp: Path):
    emmc = _emmc(tmp)
    emmc.write(2048, b"\x01" * 4096)
    emmc.read(2048, 4096)
    assert emmc.counters.writes == 1 and emmc.counters.reads == 1
    assert emmc.counters.bytes_written == 4096
    assert emmc.counters.bytes_read == 4096


def test_golden_copies_are_taken_and_can_be_restored(tmp: Path):
    from revive.lab_testing.partitions import VirtualPartition

    emmc = _emmc(tmp)
    part = VirtualPartition(name="probe", offset=1024 * 1024, size=8192, kind="raw")
    emmc.write(part.offset, b"ORIGINAL" * 1024)
    saved = emmc.save_golden(part)
    assert saved is not None and saved.exists()

    emmc.write(part.offset, b"\x00" * 8192)
    assert emmc.read(part.offset, 8) == b"\x00" * 8
    result = emmc.restore_golden(part)
    assert result["ok"] is True
    assert emmc.read(part.offset, 8) == b"ORIGINAL"


def test_restoring_without_a_golden_copy_fails_loudly(tmp: Path):
    from revive.lab_testing.partitions import VirtualPartition

    emmc = _emmc(tmp)
    part = VirtualPartition(name="never-saved", offset=1024 * 1024, size=4096)
    try:
        emmc.restore_golden(part)
    except VirtualEmmcError as exc:
        assert "no golden copy" in str(exc)
    else:
        raise AssertionError("restoring a partition that was never backed up should fail")


def test_the_image_can_be_resized(tmp: Path):
    emmc = _emmc(tmp)
    assert emmc.image_bytes == SMALL
    emmc.resize_image(12 * 1024 * 1024)
    assert emmc.image_bytes == 12 * 1024 * 1024
    emmc.resize_image(6 * 1024 * 1024)
    assert emmc.image_bytes == 6 * 1024 * 1024


def test_a_missing_image_is_reported_rather_than_assumed(tmp: Path):
    emmc = VirtualEMMC(Path("/nonexistent/emmc.img"))
    try:
        emmc.read(0, 16)
    except VirtualEmmcError as exc:
        assert "does not exist" in str(exc)
    else:
        raise AssertionError("reading a chip with no image should fail")


def test_registers_are_saved_and_can_be_reloaded(tmp: Path):
    from revive.lab_testing.extcsd_virtual import RegisterSpec as Spec

    emmc = _emmc(tmp, manufacturer="SanDisk", product_name="SDNAND")
    emmc.set_health(WARNING)
    path = emmc.save(tmp / "extcsd.json")
    assert path.exists()

    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    reloaded = VirtualEMMC.load(tmp / "emmc.img", spec_data=data["spec"])
    assert reloaded.spec.manufacturer == "SanDisk"
    assert reloaded.spec.product_name == "SDNAND"
    assert reloaded.spec.pre_eol_value == 0x02
    assert reloaded.registers_decoded()["verdict"] == "warn"


def test_bad_blocks_survive_serialisation(tmp: Path):
    emmc = _emmc(tmp)
    emmc.add_bad_block(1234 * 4096, state="unstable")
    data = emmc.to_dict()
    assert any(b["offset"] == 1234 * 4096 for b in data["bad_blocks"])
    assert data["bad_blocks"][0]["state"] in ("unreadable", "unstable")


def test_bad_block_from_dict_round_trips():
    block = BadBlock.from_dict({"offset": 4096, "size": 8192, "state": "unstable"})
    assert block.offset == 4096 and block.size == 8192 and block.state == "unstable"
    assert block.offset_hex == "0x1000"


def test_health_summary_exposes_what_a_technician_asks_for(tmp: Path):
    emmc = _emmc(tmp)
    health = emmc.health()
    for key in ("state", "pre_eol", "pre_eol_text", "life_a_text", "capacity_human",
                "verdict", "bad_blocks", "manufacturer", "serial"):
        assert key in health, f"health is missing {key}"
    assert health["state"] == HEALTHY


def test_every_documented_chip_setting_can_be_changed(tmp: Path):
    """The task asks for a chip whose maker, size, health and firmware can be changed.

    `apply_options` is the one path the CLI, the API and the UI all use, so testing it here
    covers all three.
    """
    from revive.lab_testing import SPEC_OPTIONS, apply_options

    emmc = _emmc(tmp)
    applied = apply_options(emmc, {
        "manufacturer": "Micron", "size": "128GB", "health": "warning",
        "firmware_version": "0x4c414231", "product_name": "MT128G", "serial": "0xA1B2C3",
        "write_cycles": "2500", "bad_blocks": "4", "pre_eol": "0x02", "capacity": "34359738368",
    })
    assert set(applied) == set(SPEC_OPTIONS), sorted(set(SPEC_OPTIONS) ^ set(applied))

    decoded = emmc.registers_decoded()
    assert decoded["cid"]["manufacturer"] == "Micron"
    assert decoded["cid"]["product_name"] == "MT128G"
    assert decoded["ext_csd"]["firmware_version"] == "4C414231"
    assert decoded["ext_csd"]["capacity_bytes"] == 32 * 1024 ** 3
    assert emmc.spec.pre_eol_value == 0x02
    assert len(emmc.bad_blocks) == 4
    assert emmc.spec.write_cycles == 2500


def test_an_unknown_chip_setting_is_refused_not_ignored(tmp: Path):
    from revive.lab_testing import apply_options

    emmc = _emmc(tmp)
    try:
        apply_options(emmc, {"manufaturer": "Micron"})
    except VirtualEmmcError as exc:
        assert "unknown option" in str(exc) and "manufacturer" in str(exc)
    else:
        raise AssertionError("a misspelled setting must be reported, not silently skipped")


def test_the_lab_device_reports_a_realistic_chip(tmp: Path):
    device = LabBench(tmp / "lab").create(chip="MT6768", storage="64GB", image_bytes=SMALL)
    try:
        registers = device.emmc.registers()
        assert len(registers["cid"]) == 32, "a CID is 16 bytes = 32 hex chars"
        assert len(registers["csd"]) == 32
        assert len(registers["ext_csd"]) == 1024, "EXT_CSD is 512 bytes = 1024 hex chars"
        assert device.emmc.spec.capacity_bytes == 64 * 1024 ** 3
    finally:
        device.close()
