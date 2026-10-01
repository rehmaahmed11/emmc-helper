"""Tests for error decoding and chip identification - the tool's reference data."""
from __future__ import annotations

from revive.core import chips, errors


def test_decode_numeric_code(_tmp):
    info = errors.decode("ERROR: S_BROM_CMD_STARTCMD_FAIL (2005)")
    assert info is not None and info.symbol == "S_BROM_CMD_STARTCMD_FAIL"
    assert info.phase == "brom"
    assert any("fully power off" in fix.lower() or "power off" in fix.lower() for fix in info.fixes)


def test_decode_hex_and_aliases(_tmp):
    for text in ("0xC0060001", "0x7D5", "C0060001", "BROM ERROR: (2005)"):
        info = errors.decode(text)
        assert info is not None, text
        assert info.symbol == "S_BROM_CMD_STARTCMD_FAIL", text


def test_decode_symbol_with_spaces(_tmp):
    info = errors.decode("sahara protocol error")
    assert info is not None and info.code == "sahara_error"


def test_decode_raw_log_line(_tmp):
    log = ("[12:00:01]: Status: Waiting for PreLoader VCOM\n"
           "[12:00:40]: ERROR: STATUS_EXT_RAM_EXCEPTION (0xC0050005)\n")
    info = errors.decode(log)
    assert info is not None
    assert info.symbol == "STATUS_EXT_RAM_EXCEPTION"
    assert "scatter" in " ".join(info.causes).lower()


def test_decode_unknown_returns_none(_tmp):
    assert errors.decode("everything is fine") is None
    assert errors.decode("") is None
    assert errors.decode(None) is None


def test_triage_gives_advice_for_unknown(_tmp):
    result = errors.triage("some brand new error we have never seen")
    assert result["matched"] is False
    assert result["advice"] and result["note"]


def test_all_entries_are_well_formed(_tmp):
    for info in errors.all_errors():
        assert info.code and info.symbol and info.meaning, info
        assert info.phase in {
            "connect", "preloader", "brom", "auth", "da", "storage", "flash", "verify", "post",
        }, info
        assert info.severity in ("info", "warn", "error", "fatal"), info
        assert info.fixes, f"{info.code} has no suggested actions"


def test_search(_tmp):
    hits = errors.search("storage")
    assert hits and all("storage" in (h.code + h.symbol + h.meaning).lower() for h in hits)


def test_confirmed_chip_lookup(_tmp):
    chip = chips.lookup(0x707)
    assert chip is not None and "MT6768" in chip.name
    assert chip.confidence == chips.CONFIRMED
    assert chips.lookup(0x1066).da_mode_name == "xml"


def test_derived_and_unknown_chips(_tmp):
    derived = chips.lookup(0x6752)
    assert derived is not None and derived.name == "MT6752"
    unknown = chips.lookup(0x9999)
    assert unknown is None
    assert "unknown" in chips.describe(0x9999)


def test_chip_registration_from_da(_tmp):
    before = chips.lookup(0x1BBB)
    assert before is None
    chips.register_from_da(0x1BBB, "MT1BBB", source="test")
    after = chips.lookup(0x1BBB)
    assert after is not None and after.name == "MT1BBB"
    assert after.confidence == chips.REPORTED


def test_parse_hwcode(_tmp):
    assert chips.parse_hwcode("hw code: 0x766") == 0x766
    assert chips.parse_hwcode("0x1066") == 0x1066
    assert chips.parse_hwcode("nothing here") is None
