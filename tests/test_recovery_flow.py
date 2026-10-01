"""Tests for the recovery workflow: diagnose -> repair -> verify, and the grading around it.

The important tests here are the negative ones. A lab that reports PASS no matter what is worse
than no lab at all, so this module checks that:

* a brick that is not repaired fails verification;
* a diagnosis engine that finds nothing is graded as a detection failure;
* a repair that does not actually restore the data fails verification.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

from revive.lab_testing import (BrickEngine, LabBench, RecoveryTester, collect_signals,
                                diagnose, lab_report)
from revive.lab_testing.extcsd_virtual import DEAD
from revive.lab_testing import recovery_test as rt
from revive.lab_testing.cli import main as lab_main
from revive.lab_testing.scenarios import nvram_damage

SMALL = 8 * 1024 * 1024


def _tester(tmp: Path, chip: str = "MT6768"):
    bench = LabBench(tmp / "lab")
    device = bench.create(chip=chip, image_bytes=SMALL)
    return bench, device, RecoveryTester(device, bench=bench)


# --------------------------------------------------------------------------------------
# The baseline
# --------------------------------------------------------------------------------------

def test_a_fresh_device_diagnoses_clean(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        diagnosis = diagnose(device)
        assert diagnosis.signals == [], diagnosis.signals
        assert diagnosis.verdict != "fatal"
        assert diagnosis.partitions and diagnosis.dump_report
        titles = [f.get("title", "") for f in diagnosis.findings]
        assert any("complete and consistent" in t for t in titles), titles
        # Nothing may read as unwritten: Revive calls a region that is >99.5% zero "blank".
        assert not any("blank" in t for t in titles), titles
    finally:
        device.close()


def test_a_device_whose_csd_can_hold_its_capacity_diagnoses_fully_ok(tmp: Path):
    """The one warning a 64 GB lab device carries is the JEDEC C_SIZE limit, not damage.

    C_SIZE is twelve bits, so a structure-3 CSD tops out at 2 GiB and Revive rightly points the
    reader at EXT_CSD SEC_COUNT. Give the lab a chip small enough for the CSD to express its
    own capacity and the diagnosis comes back clean - which is what proves the note above is
    about the format and not about a fault the lab injected.
    """
    bench, device, tester = _tester(tmp, chip="MT6768")
    try:
        device.close()
        device = bench.create(chip="MT6768", storage="2GB", image_bytes=SMALL)
        diagnosis = diagnose(device)
        assert diagnosis.verdict == "ok", (diagnosis.verdict,
                                          [f.get("title") for f in diagnosis.findings])
    finally:
        device.close()


def test_diagnosis_uses_revives_own_dump_analysis(tmp: Path):
    """The report must come from revive.ops.dump, not from something the lab invented."""
    bench, device, tester = _tester(tmp)
    try:
        BrickEngine(device).apply("gpt")
        diagnosis = diagnose(device)
        assert diagnosis.dump_report.get("path") == str(device.image_path)
        # With the primary CRC broken, Revive falls back to the backup table - so the layout is
        # still readable and the damage shows up as a finding rather than as an empty table.
        assert diagnosis.dump_report.get("backup_used") is True
        assert diagnosis.dump_report.get("partition_count") > 0
        titles = [f.get("title", "") for f in diagnosis.findings]
        assert any("primary partition table is damaged" in t for t in titles), titles
    finally:
        device.close()


# --------------------------------------------------------------------------------------
# Every scenario, end to end
# --------------------------------------------------------------------------------------

def test_every_mtk_scenario_passes_end_to_end(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        for scenario in tester.engine.available():
            device.reset()
            result = tester.run(scenario.id)
            assert result.result == "PASS", (
                f"{scenario.id}: {result.summary}; "
                f"missing={result.detection.missing}; error={result.error}; "
                f"verify={result.verification.detail}")
            assert result.detection.verdict == "PASS"
            assert result.repair.verdict == "PASS"
            assert result.verification.verdict == "PASS"
    finally:
        device.close()


def test_every_qualcomm_scenario_passes_end_to_end(tmp: Path):
    bench, device, tester = _tester(tmp, chip="SDM660")
    try:
        for scenario in tester.engine.available():
            device.reset()
            result = tester.run(scenario.id)
            assert result.result == "PASS", f"{scenario.id}: {result.summary} {result.error}"
    finally:
        device.close()


def test_every_unisoc_scenario_passes_end_to_end(tmp: Path):
    bench, device, tester = _tester(tmp, chip="UNISOC")
    try:
        assert "qualcomm_edl_failure" not in tester.engine.available_ids()
        assert "mtk_brom_failure" not in tester.engine.available_ids()
        for scenario in tester.engine.available():
            device.reset()
            result = tester.run(scenario.id)
            assert result.result == "PASS", f"{scenario.id}: {result.summary} {result.error}"
    finally:
        device.close()


def test_run_all_resets_between_scenarios(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        results = tester.run_all()
        assert len(results) == len(tester.engine.available())
        assert all(r.result == "PASS" for r in results), [r.summary for r in results]
    finally:
        device.close()


def test_the_task_example_runs_end_to_end(tmp: Path):
    """create MT6768 64GB -> brick GPT -> diagnose -> expect damage -> repair -> PASS."""
    from revive.lab_testing import run_workflow

    bench = LabBench(tmp / "lab")
    result = run_workflow(bench, chip="MT6768", storage="64GB", scenario_id="gpt_corruption")
    try:
        assert result.result == "PASS", result.summary
        assert result.chipset == "MT6768"
        assert "gpt_header_crc_bad" in result.detection.found
    finally:
        bench.get(result.device_id).close()


# --------------------------------------------------------------------------------------
# The grading is not vacuous
# --------------------------------------------------------------------------------------

def test_an_unrepaired_brick_fails_verification(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        for brick in ("gpt", "boot", "nvram", "userdata", "emmc", "brom"):
            device.reset()
            result = tester.run(brick, repair=False)
            assert result.detection.verdict == "PASS", f"{brick}: the fault was not detected"
            assert result.verification.verdict == "FAIL", f"{brick}: verification passed a brick"
            assert result.result == "FAIL"
            assert result.repair.verdict == "SKIP"
    finally:
        device.close()


def test_a_blind_diagnosis_engine_is_graded_as_a_detection_failure(tmp: Path):
    """If Revive's engine reported nothing, the lab must not claim it found the fault."""
    bench, device, tester = _tester(tmp)
    original = rt.collect_signals
    rt.collect_signals = lambda d: {"signals": [], "evidence": {
        "gpt": {}, "emmc": {}, "boot": {}, "partitions": [], "boot_mode": "normal"}}
    try:
        device.reset()
        result = tester.run("gpt")
        assert result.detection.verdict == "FAIL"
        assert result.detection.missing, "the missed signals must be named"
        assert result.result == "FAIL"
    finally:
        rt.collect_signals = original
        device.close()


def test_a_repair_that_does_not_restore_the_data_fails(tmp: Path):
    """Delete the golden copy so the restore cannot work: the lab must report FAIL."""
    bench, device, tester = _tester(tmp)
    try:
        (device.golden_dir / "boot.img").unlink()
        result = tester.run("boot_corruption")
        assert result.repair.verdict == "FAIL", result.repair.detail
        assert result.result == "FAIL"
    finally:
        device.close()


def test_detection_names_the_signals_it_expected_and_found(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        result = tester.run("gpt")
        assert set(result.detection.expected) <= set(result.detection.found)
        assert result.detection.missing == []
        assert result.detection.data["verdict"]
    finally:
        device.close()


def test_verification_lists_the_checks_it_ran(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        result = tester.run("gpt")
        names = {c["name"] for c in result.verification.data["checks"]}
        assert "device" in names and "faults cleared" in names
        assert "partition table" in names and "boot" in names
    finally:
        device.close()


def test_the_documented_brick_then_run_sequence_passes(tmp: Path):
    """`brick` and then `run` - no reset in between - is the workflow the README shows."""
    bench, device, tester = _tester(tmp)
    try:
        BrickEngine(device).apply("gpt")
        result = tester.run("gpt_corruption")
        assert result.brick.get("already_applied") is True, result.brick
        assert result.result == "PASS", result.summary
    finally:
        device.close()


def test_a_brick_the_lab_applied_is_not_reported_as_unexplained_damage(tmp: Path):
    """Damage the lab injected itself is expected; damage nobody declared is not."""
    bench, device, tester = _tester(tmp)
    try:
        BrickEngine(device).apply("gpt")
        found = set(collect_signals(device)["signals"])
        assert found, "the brick produced no signals"
        missing = found - tester._declared_signals()
        assert not missing, f"the lab did not recognise its own brick: {sorted(missing)}"

        device.emmc.set_health(DEAD)
        undeclared = set(collect_signals(device)["signals"]) - tester._declared_signals()
        assert "emmc_pre_eol_urgent" in undeclared, sorted(undeclared)
    finally:
        device.close()


def test_verify_only_grades_the_device_as_it_stands(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        assert tester.verify_only().result == "PASS"
        BrickEngine(device).apply("boot")
        assert tester.verify_only().result == "FAIL"
    finally:
        device.close()


def test_an_unknown_scenario_is_reported_not_raised(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        result = tester.run("not_a_scenario")
        assert result.result == "FAIL"
        assert "no lab scenario" in result.error
    finally:
        device.close()


# --------------------------------------------------------------------------------------
# Recording and reporting
# --------------------------------------------------------------------------------------

def test_a_run_is_recorded_in_the_lab_history(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        result = tester.run("gpt")
        rows = bench.history()
        assert rows, "the run was not recorded"
        assert rows[0]["scenario"] == "gpt_corruption"
        assert rows[0]["result"] == result.result
        for key in ("timestamp", "device", "detection", "repair", "verification"):
            assert rows[0].get(key), f"history row has no {key}"
        assert bench.summary()["runs"] >= 1
    finally:
        device.close()


def test_the_report_carries_the_documented_headline(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        result = tester.run("gpt_corruption")
        report = lab_report.build_report(result, bench.summary())
        assert report["title"] == "LAB TEST REPORT"
        assert report["device"] == device.id
        assert report["scenario_label"] == "GPT corruption"
        for key in ("detection", "repair", "verification", "result"):
            assert report[key] == "PASS", (key, report[key])
    finally:
        device.close()


def test_the_report_renders_to_self_contained_html(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        result = tester.run("bad_emmc")
        report = lab_report.build_report([result], bench.summary())
        html = lab_report.to_html(report)
        assert "<!DOCTYPE html>" in html and "</html>" in html
        assert "LAB TEST REPORT" in html
        assert "http://" not in html and "https://" not in html, "the report must not need a CDN"
        assert "PASS" in html
        # The evidence, not just the verdicts.
        assert "PRE_EOL" in html
    finally:
        device.close()


def test_reports_are_written_next_to_each_other(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        result = tester.run("gpt_corruption")
        report = lab_report.build_report([result], bench.summary())
        paths = lab_report.write_reports(report, device.reports_dir)
        assert Path(paths["json"]).exists() and Path(paths["html"]).exists()
        saved = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        assert saved["schema"] == "revive-lab-report/1"
        assert saved["runs"][0]["scenario"] == "gpt_corruption"
    finally:
        device.close()


def test_a_snapshot_report_works_for_a_device_with_no_run(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        report = lab_report.build_from_device(device, bench)
        assert report["title"] == "LAB DEVICE REPORT"
        assert report["result"] == "PASS"
        assert report["device_check"]["ok"] is True
        assert lab_report.render_text(report)
    finally:
        device.close()


def test_a_multi_scenario_report_counts_passes_and_failures(tmp: Path):
    bench, device, tester = _tester(tmp)
    try:
        results = [tester.run("gpt_corruption"), tester.run("boot_corruption")]
        report = lab_report.build_report(results, bench.summary())
        assert report["scenario_count"] == 2
        assert report["scenarios_passed"] == 2
        assert report["result"] == "PASS"
        text = lab_report.render_text(report)
        assert "GPT corruption" in text and "Boot corruption" in text
    finally:
        device.close()


# --------------------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------------------

def _cli(tmp: Path, *argv: str) -> str:
    """Run the lab CLI. `--lab` is a per-subcommand flag, so it goes after the command."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = lab_main([*argv, "--lab", str(tmp / "lab"), "--no-color"])
    assert code == 0, f"`lab {' '.join(argv)}` exited {code}\n{buffer.getvalue()}"
    return buffer.getvalue()


def test_the_documented_cli_sequence_works(tmp: Path):
    out = _cli(tmp, "create", "--chip", "MT6768", "--storage", "64GB")
    assert "created" in out and "MT6768" in out

    out = _cli(tmp, "brick", "--type", "gpt")
    assert "bricked" in out and "GPT corruption" in out

    out = _cli(tmp, "status")
    assert "bricked" in out

    out = _cli(tmp, "run")
    assert "RESULT" in out and "PASS" in out, out

    out = _cli(tmp, "report")
    assert "LAB TEST REPORT" in out and ".html" in out

    out = _cli(tmp, "history")
    assert "gpt_corruption" in out

    out = _cli(tmp, "list")
    assert "MT6768" in out


def test_the_cli_refuses_a_brick_that_does_not_fit_the_device(tmp: Path):
    _cli(tmp, "create", "--chip", "SDM660")
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = lab_main(["brick", "--type", "brom", "--lab", str(tmp / "lab"), "--no-color"])
    assert code == 1, "BROM does not apply to a Qualcomm device"


def test_the_cli_can_run_a_single_scenario_with_options(tmp: Path):
    _cli(tmp, "create", "--chip", "MT6768")
    out = _cli(tmp, "run", "--scenario", "gpt_corruption", "--opt", "mode=total")
    assert "PASS" in out, out


def test_the_cli_creates_a_device_with_a_chosen_chip(tmp: Path):
    out = _cli(tmp, "create", "--chip", "MT6768",
               "--opt", "manufacturer=Micron", "--opt", "firmware_version=0x4c414231")
    assert "Micron" in out, out
    # The registers the chip now reports are written with the device, decoded by Revive.
    device_id = json.loads(_cli(tmp, "list", "--json"))["devices"][0]["id"]
    saved = json.loads((tmp / "lab" / device_id / "extcsd.json").read_text(encoding="utf-8"))
    assert saved["cid"]["manufacturer"] == "Micron", saved["cid"]
    assert saved["ext_csd"]["firmware_version"] == "4C414231"

    # `set --json` reads them back through the same decoder.
    again = json.loads(_cli(tmp, "set", "--opt", "pre_eol=0x02", "--json"))
    assert again["applied"]["pre_eol"] == "0x02"
    assert again["health"]["state"] == "warning"


def test_the_cli_set_command_changes_what_the_chip_reports(tmp: Path):
    _cli(tmp, "create", "--chip", "MT6768")
    out = _cli(tmp, "set", "--opt", "health=dead", "--opt", "size=128GB")
    assert "dead" in out and "128" in out
    data = json.loads(_cli(tmp, "status", "--json"))
    assert data["health"]["state"] == "dead"
    assert data["health"]["pre_eol"] == "0x03"
    assert "emmc_pre_eol_urgent" in data["signals"]


def test_the_cli_set_with_no_options_lists_what_can_be_set(tmp: Path):
    _cli(tmp, "create", "--chip", "MT6768")
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = lab_main(["set", "--lab", str(tmp / "lab"), "--no-color"])
    assert code == 1
    for name in ("manufacturer", "size", "health", "firmware_version"):
        assert name in buffer.getvalue()


def test_the_cli_lists_profiles_and_scenarios(tmp: Path):
    out = _cli(tmp, "profiles")
    assert "MT6768" in out and "Snapdragon 660" in out and "unisoc" in out
    out = _cli(tmp, "scenarios")
    assert "gpt_corruption" in out and "mtk_brom_failure" in out
    out = _cli(tmp, "scenarios", "--platform", "qualcomm")
    assert "qualcomm_edl_failure" in out and "mtk_brom_failure" not in out


def test_the_cli_selftest_proves_the_registers_round_trip(tmp: Path):
    out = _cli(tmp, "selftest")
    assert "PASS" in out and "healthy" in out and "dead" in out


def test_the_cli_json_output_is_parseable(tmp: Path):
    _cli(tmp, "create", "--chip", "MT6768", "--json")
    out = _cli(tmp, "status", "--json")
    data = json.loads(out)
    assert data["ok"] is True
    assert data["device"]["profile"]["chipset"] == "MT6768"
    assert data["verify"]["verdict"] == "PASS"


def test_the_cli_verify_exits_non_zero_for_a_bricked_device(tmp: Path):
    _cli(tmp, "create", "--chip", "MT6768")
    _cli(tmp, "brick", "--type", "boot")
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = lab_main(["verify", "--lab", str(tmp / "lab"), "--no-color"])
    assert code == 1, "verify must fail for a bricked device"
    assert "FAIL" in buffer.getvalue()


def test_the_cli_reset_brings_the_device_back(tmp: Path):
    _cli(tmp, "create", "--chip", "MT6768")
    _cli(tmp, "brick", "--type", "nvram")
    _cli(tmp, "reset")
    out = _cli(tmp, "verify")
    assert "PASS" in out


def test_the_cli_delete_removes_a_device(tmp: Path):
    _cli(tmp, "create", "--chip", "MT6768")
    listing = json.loads(_cli(tmp, "list", "--json"))
    device_id = listing["devices"][0]["id"]
    _cli(tmp, "delete", "--device", device_id)
    after = json.loads(_cli(tmp, "list", "--json"))
    assert device_id not in {d["id"] for d in after["devices"]}


def test_the_cli_with_no_command_prints_the_quick_start(tmp: Path):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = lab_main([])
    assert code == 0
    assert "quick start" in buffer.getvalue()
