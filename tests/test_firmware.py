"""Tests for firmware package parsing, validation and flashing plans."""
from __future__ import annotations

from fixtures import demo_tree
from revive.firmware import da, detect, pac, rawprogram, scatter
from revive.ops import plan
from revive.util import SEV_ERROR, SEV_FATAL, SEV_WARN


def test_scatter_parse(_tmp):
    info = demo_tree()
    parsed = scatter.parse(info["firmware_mtk"]["scatter"])
    assert parsed.platform == "MT6768"
    assert parsed.storage == "EMMC"
    names = [e.name for e in parsed.entries]
    assert "preloader" in names and "boot" in names
    preloader = parsed.find("preloader")
    assert preloader.wants_file and preloader.region == "EMMC_BOOT_1"
    assert parsed.download_entries
    assert parsed.total_download_size() > 0


def test_scatter_validates_missing_and_overlap(_tmp):
    info = demo_tree()
    parsed = scatter.parse(info["firmware_broken"]["scatter"])
    codes = {f.code for f in parsed.findings}
    assert "firmware_missing_files" in codes     # modem.img is not present
    assert "plan_overlap" in codes               # vendor overlaps boot
    assert any(f.severity in (SEV_ERROR, SEV_FATAL) for f in parsed.findings)
    assert not scatter.summarise(parsed)["ok_to_flash"]


def test_scatter_detects_oversized_image(tmp):
    info = demo_tree()
    parsed = scatter.parse(info["firmware_broken"]["scatter"])
    oversized = [f for f in parsed.findings if f.code == "plan_size_mismatch"]
    assert oversized, "expected an oversize finding (oem partition is 256 KB, image is 1 MB)"


def test_plan_for_good_package(_tmp):
    info = demo_tree()
    flash_plan = plan.plan_for_path(info["firmware_mtk"]["root"])
    assert flash_plan.kind == "mtk_spflash"
    assert flash_plan.entries
    assert flash_plan.total_bytes > 0
    writes = [e for e in flash_plan.entries if e.action == "write"]
    assert any(e.name == "preloader" and e.critical for e in writes)
    text = plan.render_text(flash_plan)
    assert "PARTITION" in text and "RISK" in text


def test_plan_blocks_on_missing_files(_tmp):
    info = demo_tree()
    flash_plan = plan.plan_for_path(info["firmware_broken"]["root"])
    assert not flash_plan.ok_to_proceed
    assert flash_plan.risk == "blocked"
    assert any(e.action == "skip" for e in flash_plan.entries)


def test_plan_risk_is_high_for_preloader(_tmp):
    info = demo_tree()
    flash_plan = plan.plan_for_path(info["firmware_mtk"]["root"])
    assert flash_plan.risk in ("medium", "high")
    assert any("preloader" in reason for reason in flash_plan.risk_reasons)


def test_qualcomm_plan(_tmp):
    info = demo_tree()
    qplan = rawprogram.parse(info["firmware_qualcomm"]["root"])
    labels = [e.label for e in qplan.entries]
    assert "PrimaryGPT" in labels and "boot_a" in labels
    assert qplan.patches and "Backup Header" in qplan.patches[0].what
    # vendor.img is referenced but missing -> must be flagged
    assert any(f.code == "firmware_missing_files" for f in qplan.findings)

    flash_plan = plan.plan_for_path(info["firmware_qualcomm"]["root"])
    assert flash_plan.kind == "qualcomm_edl"
    assert any(e.action == "patch" for e in flash_plan.entries)
    assert not flash_plan.ok_to_proceed


def test_qualcomm_missing_patch_is_flagged(tmp):
    import tempfile
    from pathlib import Path

    root = Path(tempfile.mkdtemp())
    (root / "boot.img").write_bytes(b"\x00" * 4096)
    (root / "prog_firehose_ddr.elf").write_bytes(b"\x7fELF firehose")
    (root / "gpt_main0.bin").write_bytes(b"\x00" * 512)
    (root / "rawprogram0.xml").write_text(
        '<?xml version="1.0" ?><data>'
        '<program SECTOR_SIZE_IN_BYTES="512" filename="gpt_main0.bin" label="PrimaryGPT" '
        'num_partition_sectors="34" physical_partition_number="0" start_sector="0"/></data>')
    parsed = rawprogram.parse(root)
    assert any("patch" in f.title.lower() for f in parsed.findings if f.severity == SEV_WARN)


def test_da_file_parsing(_tmp):
    info = demo_tree()
    da_path = None
    from pathlib import Path

    for candidate in Path(info["firmware_mtk"]["root"]).glob("*DA*.bin"):
        da_path = candidate
    assert da_path is not None
    parsed = da.parse(da_path)
    assert parsed.markers and parsed.generation == "MTK_DA_v5"
    assert 0x707 in parsed.hardware_codes and 0x766 in parsed.hardware_codes
    assert "MT6768" in parsed.chip_names


def test_pac_inventory(tmp):
    from pathlib import Path

    pac_file = Path(demo_tree()["firmware_mtk"]["root"]) / "demo.pac"
    pac_file.write_bytes(
        b"\x50\x41\x43\x00" + b"\x00" * 60
        + b"fdl1-sign.bin\x00" + (4096).to_bytes(4, "little")
        + b"boot.img\x00" + (8192).to_bytes(4, "little")
        + b"\x00" * 1024)
    assert pac.looks_like_pac(pac_file)
    parsed = pac.parse(pac_file)
    names = {e.name for e in parsed.entries}
    assert "fdl1-sign.bin" in names and "boot.img" in names
    assert parsed.parse_confidence == "inventory-only"


def test_detect_package_kinds(_tmp):
    info = demo_tree()
    mtk = detect.detect(info["firmware_mtk"]["root"])
    assert mtk.kind == detect.KIND_MTK
    assert mtk.scatter and mtk.platform == "MT6768"
    assert mtk.images and mtk.total_size > 0

    qualcomm = detect.detect(info["firmware_qualcomm"]["root"])
    assert qualcomm.kind == detect.KIND_QUALCOMM
    assert qualcomm.loaders

    single = detect.detect(info["boot_img"])
    assert single.kind == detect.KIND_IMAGES
    assert "boot" in single.label.lower()


def test_detect_warns_about_archives(tmp):
    import tempfile
    import zipfile
    from pathlib import Path

    root = Path(tempfile.mkdtemp())
    with zipfile.ZipFile(root / "firmware.zip", "w") as zf:
        zf.writestr("Android_scatter.txt", "- general: MTK_PLATFORM_CFG\n")
    pkg = detect.detect(root)
    assert pkg.archives
    assert any("archive" in f.title.lower() for f in pkg.findings)


def test_empty_folder_is_unknown(_tmp):
    import tempfile
    from pathlib import Path

    pkg = detect.detect(Path(tempfile.mkdtemp()))
    assert pkg.kind == detect.KIND_UNKNOWN
    assert pkg.findings and not pkg.images
