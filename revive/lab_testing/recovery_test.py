"""Running Revive's recovery logic against a virtual device, and grading the result.

This is the part that makes the lab a *test* rather than a toy. The workflow is the one from
the task description:

    create device -> apply brick -> run Revive diagnosis -> check what it found
    -> run the repair -> verify the device actually came back

Every stage is graded against something external:

* **Detection** is graded against the signals the scenario declared *before* it ran. The signals
  themselves come from Revive's own code - `revive.ops.dump.analyse`, `revive.storage.gpt`,
  `revive.storage.emmc.assess`, `revive.storage.bootimg`, `revive.storage.ext4fs` - so a PASS
  means the real tool found the real fault.
* **Verification** is graded against the device's own state afterwards: does the table verify,
  does the boot walk reach Android, is the storage healthy, does a write actually hold.

Nothing here grades itself. If the diagnosis engine misses a fault, detection fails.
"""
from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

from ..ops import dump as dump_mod
from ..storage import bootimg, ext4fs
from ..util import human_size
from . import gpt_virtual
from . import scenarios as scenario_mod
from .brick_engine import BrickEngine, BrickError
from .device import (MODE_MTK_BROM, MODE_NORMAL, MODE_QC_EDL, MODE_UNISOC_DL,
                     VirtualDevice)
from .partitions import ST_OK
from .scenarios import Scenario, ScenarioError

LOG = logging.getLogger("revive.lab.recovery")

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


# --------------------------------------------------------------------------------------
# Signals: what is wrong with this device, according to Revive's own code
# --------------------------------------------------------------------------------------

def collect_signals(device: VirtualDevice) -> Dict[str, Any]:
    """Ask the real parsers what is wrong, and return the fault signals they imply."""
    signals: Set[str] = set()
    evidence: Dict[str, Any] = {}

    # -- the partition table -----------------------------------------------------------
    gpt = gpt_virtual.read(device.image_path, device.emmc.sector_size)
    signals.update(gpt.signals)
    evidence["gpt"] = gpt.to_dict()

    # -- the storage registers ---------------------------------------------------------
    signals.update(device.emmc.signals())
    evidence["emmc"] = device.emmc.health()

    # -- partition content -------------------------------------------------------------
    partition_signals: List[str] = []
    for part in device.partitions:
        if part.size <= 0:
            continue
        name = part.name.lower()
        if name in ("boot", "recovery"):
            if not _boot_image_ok(device, part):
                signals.add("boot_image_invalid")
                partition_signals.append(f"{part.name}: no parseable boot image")
        if (part.kind or "").lower() == "nvram":
            from .scenarios import nvram_damage

            info = nvram_damage.read_identity(device, part.name)
            if not info.get("valid"):
                signals.add("nvram_invalid")
                partition_signals.append(f"{part.name}: {info.get('reason', 'identity unreadable')}")
        if name in ("userdata",) or (part.kind or "").lower() in ("ext4", "f2fs"):
            dirty, detail = _filesystem_dirty(device, part)
            if dirty:
                signals.add("userdata_fs_dirty")
                partition_signals.append(f"{part.name}: {detail}")
        if name in ("preloader", "bootloader") and _head_blank(device, part):
            signals.add("preloader_damaged")
            partition_signals.append(f"{part.name}: stage-1 loader is erased")
        if part.name in device.profile.bootloader_partitions and _head_blank(device, part):
            signals.add("bootloader_damaged")
            partition_signals.append(f"{part.name}: boot chain partition is erased")
    evidence["partitions"] = partition_signals

    # -- what mode the device is sitting in --------------------------------------------
    mode = device.profile.boot_mode
    if mode == MODE_MTK_BROM:
        signals.update({"device_in_brom", "device_in_download_mode"})
    elif mode == MODE_QC_EDL:
        signals.update({"device_in_edl", "device_in_download_mode"})
    elif mode == MODE_UNISOC_DL:
        signals.update({"device_in_unisoc_dl", "device_in_download_mode"})
    evidence["boot_mode"] = mode

    # -- the boot walk -----------------------------------------------------------------
    boot = device.boot()
    if not boot.booted:
        signals.add("boot_fails")
    evidence["boot"] = boot.to_dict()

    return {"signals": sorted(signals), "evidence": evidence}


def _head_blank(device: VirtualDevice, part) -> bool:
    """True when the start of a partition has been erased (all 0x00 / 0xFF)."""
    try:
        head = device.emmc.read(part.offset, min(part.size, 4096))
    except Exception:                                                   # noqa: BLE001
        return True
    return not head.strip(b"\x00\xff")


def _boot_image_ok(device: VirtualDevice, part) -> bool:
    """Does Revive's boot parser accept this partition?"""
    try:
        head = device.emmc.read(part.offset, min(part.size, 16))
    except Exception:                                                   # noqa: BLE001
        return False
    if head[:8] != b"ANDROID!":
        return False
    tmp = None
    try:
        tmp = device._slice(part)
        bootimg.parse(tmp)
        return True
    except Exception:                                                   # noqa: BLE001
        return False
    finally:
        if tmp:
            import os

            try:
                os.unlink(tmp)
            except OSError:
                pass


def _filesystem_dirty(device: VirtualDevice, part):
    """Read the superblock the way `revive.storage.ext4fs` does and report a dirty state."""
    try:
        blob = device.emmc.read(part.offset, min(part.size, 4096))
    except Exception as exc:                                            # noqa: BLE001
        return False, f"unreadable: {exc}"
    info = ext4fs.identify(blob)
    if info is None or info.kind == "unknown":
        return False, ""
    if info.kind in ("ext4", "ext2/3/4"):
        # ext4fs.identify() renames "ext2/3/4" to "ext4" to match the magic sniffer.
        if info.state and info.state != "clean":
            return True, f"ext4 state is '{info.state}'"
        return False, ""
    if info.kind.lower().startswith("f2fs"):
        # F2FS has no dirty bit Revive reads; a block count of all-ones is what a failed
        # superblock write leaves behind, and it is checked from the raw bytes.
        try:
            blocks = struct.unpack_from("<Q", blob, 1024 + 40)[0]
        except struct.error:
            return False, ""
        if blocks == 0xFFFFFFFFFFFFFFFF:
            return True, "the F2FS superblock's block count is an erased value"
    return False, ""


# --------------------------------------------------------------------------------------
# The diagnosis
# --------------------------------------------------------------------------------------

@dataclass
class Diagnosis:
    """What Revive says about a device right now."""

    device: str = ""
    signals: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    dump_report: Dict[str, Any] = field(default_factory=dict)
    gpt: Dict[str, Any] = field(default_factory=dict)
    health: Dict[str, Any] = field(default_factory=dict)
    boot: Dict[str, Any] = field(default_factory=dict)
    partitions: List[Dict[str, Any]] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def verdict(self) -> str:
        """The worst thing the diagnosis found, in Revive's own severity order."""
        severities = [f.get("severity", "info") for f in self.findings]
        for level in ("fatal", "error", "warn", "info"):
            if level in severities:
                return level
        return "ok"

    def summary(self) -> str:
        if not self.signals:
            return f"no faults found ({len(self.partitions)} partitions, table consistent)"
        return "detected: " + ", ".join(self.signals)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device, "signals": list(self.signals),
            "signal_count": len(self.signals), "verdict": self.verdict,
            "findings": list(self.findings), "summary": self.summary(),
            "dump_report": {k: v for k, v in self.dump_report.items()
                            if k not in ("partitions", "scan_hits")},
            "gpt": self.gpt, "health": self.health, "boot": self.boot,
            "damaged_partitions": [p for p in self.partitions if p.get("status") != ST_OK],
            "elapsed": self.elapsed,
        }


def diagnose(device: VirtualDevice, deep: bool = True) -> Diagnosis:
    """Run Revive's diagnosis engine over the device and collect what it reports."""
    started = time.time()
    collected = collect_signals(device)
    diagnosis = Diagnosis(device=device.id, signals=collected["signals"])
    diagnosis.gpt = collected["evidence"]["gpt"]
    diagnosis.health = collected["evidence"]["emmc"]
    diagnosis.boot = collected["evidence"]["boot"]
    diagnosis.partitions = [p.to_dict() for p in device.partitions]

    try:
        report = dump_mod.analyse(device.image_path, deep=deep, probe_per_partition=True)
        diagnosis.dump_report = report.to_dict()
        diagnosis.findings = [f.to_dict() for f in report.findings]
    except Exception as exc:                                            # noqa: BLE001
        # A diagnosis that cannot run is itself the finding.
        LOG.warning("revive.ops.dump.analyse failed on %s: %s", device.image_path, exc)
        diagnosis.dump_report = {"error": str(exc)}
        diagnosis.findings = [{
            "severity": "error", "title": "The diagnosis engine could not read this device",
            "detail": f"{type(exc).__name__}: {exc}", "fixes": [],
        }]

    # The eMMC assessment findings join the dump findings, so one list holds the whole verdict.
    for finding in diagnosis.health.get("findings", []):
        if finding.get("severity") in ("warn", "error", "fatal"):
            diagnosis.findings.append(finding)

    diagnosis.elapsed = round(time.time() - started, 4)
    return diagnosis


# --------------------------------------------------------------------------------------
# Grading
# --------------------------------------------------------------------------------------

@dataclass
class StageResult:
    """One graded stage of a test run."""

    name: str = ""
    verdict: str = SKIP
    expected: List[str] = field(default_factory=list)
    found: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.verdict == PASS

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "verdict": self.verdict, "ok": self.ok,
                "expected": list(self.expected), "found": list(self.found),
                "missing": list(self.missing), "detail": self.detail, "data": self.data}


@dataclass
class TestResult:
    """The whole run: detection, repair, verification and the overall verdict."""

    device_id: str = ""
    chipset: str = ""
    platform: str = ""
    scenario: str = ""
    scenario_label: str = ""
    timestamp: str = ""
    duration: float = 0.0
    baseline: Optional[Diagnosis] = None
    detection: StageResult = field(default_factory=lambda: StageResult("detection"))
    repair: StageResult = field(default_factory=lambda: StageResult("repair"))
    verification: StageResult = field(default_factory=lambda: StageResult("verification"))
    before: Optional[Diagnosis] = None
    after: Optional[Diagnosis] = None
    brick: Dict[str, Any] = field(default_factory=dict)
    repair_detail: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def result(self) -> str:
        """The overall verdict: every stage that actually ran has to have passed.

        Skipped stages do not count either way. A `verify` run grades nothing but the
        verification, and a run with `--no-repair` grades detection and verification - counting
        a SKIP as a failure there would report a clean device as broken.
        """
        if self.error:
            return FAIL
        stages = [s for s in (self.detection, self.repair, self.verification)
                  if s.verdict != SKIP]
        if not stages:
            return FAIL
        return PASS if all(s.ok for s in stages) else FAIL

    @property
    def summary(self) -> str:
        return (f"{self.scenario}: detection {self.detection.verdict}, "
                f"repair {self.repair.verdict}, verification {self.verification.verdict} "
                f"-> {self.result}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device_id, "chipset": self.chipset, "platform": self.platform,
            "scenario": self.scenario, "scenario_label": self.scenario_label,
            "timestamp": self.timestamp, "duration": round(self.duration, 4),
            "result": self.result, "summary": self.summary, "error": self.error,
            "detection": self.detection.to_dict(), "repair": self.repair.to_dict(),
            "verification": self.verification.to_dict(),
            "expected_signals": self.detection.expected,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "brick": self.brick, "repair_detail": self.repair_detail,
        }

    @property
    def flat(self) -> Dict[str, Any]:
        """The shape the lab history file stores."""
        return {
            "device": self.device_id, "scenario": self.scenario, "result": self.result,
            "detection": self.detection.verdict, "repair": self.repair.verdict,
            "verification": self.verification.verdict, "detail": self.summary,
        }


# --------------------------------------------------------------------------------------
# The tester
# --------------------------------------------------------------------------------------

class RecoveryTester:
    """Runs the create -> brick -> diagnose -> repair -> verify workflow on one device."""

    def __init__(self, device: VirtualDevice, bench=None, verbose: bool = False):
        self.device = device
        self.engine = BrickEngine(device)
        self.bench = bench
        self.verbose = verbose

    # -- single scenario ---------------------------------------------------------------
    def run(self, scenario_id: str, options: Optional[Dict[str, Any]] = None,
            repair: bool = True) -> TestResult:
        """The full automated workflow for one scenario."""
        options = dict(options or {})
        result = TestResult(
            device_id=self.device.id, chipset=self.device.profile.chipset,
            platform=self.device.profile.platform,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        started = time.time()
        try:
            scenario = self.engine.resolve(scenario_id)
        except BrickError as exc:
            result.error = str(exc)
            result.duration = time.time() - started
            self._record(result)
            return result
        result.scenario = scenario.id
        result.scenario_label = scenario.label
        self.device.log("test_start", f"scenario {scenario.id}")

        # 0. A baseline, so "the lab found a fault" cannot be an artefact of a dirty device.
        result.baseline = diagnose(self.device)
        if result.baseline.signals:
            unexpected = [sig for sig in result.baseline.signals
                          if sig not in self._declared_signals()]
            if not unexpected:
                # `brick` and then `run` is the documented workflow, so a device that arrives
                # already carrying the brick it was given is exactly what was asked for.
                LOG.info("the device already carries the brick it was given: %s",
                         ", ".join(result.baseline.signals))
            else:
                LOG.warning("device %s has damage nobody asked for before the test: %s",
                            self.device.id, ", ".join(unexpected))

        # 1. Break it - unless it is already broken this way, which is what `brick` followed by
        #    `run` looks like. Re-applying would damage an already damaged device and hide
        #    whether the diagnosis can find the fault a technician actually left behind.
        already = [f for f in self.device.active_faults if f.id == scenario.id]
        try:
            if already:
                result.brick = {
                    "scenario_id": scenario.id, "already_applied": True,
                    "detail": already[-1].detail, "partitions": already[-1].partitions,
                    "effect": scenario.effect,
                    "note": "the device already carried this brick, so it was tested as found "
                            "rather than re-damaged",
                }
                self.device.log("brick", f"{scenario.label} was already applied; testing as found")
            else:
                result.brick = self.engine.apply(scenario.id, options)
        except BrickError as exc:
            result.error = str(exc)
            result.detection = StageResult("detection", FAIL, detail=str(exc))
            result.duration = time.time() - started
            self._record(result)
            return result

        # 2. Diagnose, and grade against what the scenario declared.
        result.before = diagnose(self.device)
        expected = scenario.expected_signals(options)
        found = result.before.signals
        missing = [s for s in expected if s not in found]
        result.detection = StageResult(
            name="detection",
            verdict=PASS if not missing else FAIL,
            expected=list(expected), found=list(found), missing=missing,
            detail=("Revive's diagnosis engine reported every expected fault"
                    if not missing else
                    "the diagnosis engine missed: " + ", ".join(missing)),
            data={"verdict": result.before.verdict,
                  "findings": [f.get("title", "") for f in result.before.findings],
                  "dump_findings": len(result.before.findings),
                  "elapsed": result.before.elapsed})
        self.device.log("detect", result.detection.detail,
                        {"expected": expected, "found": found, "missing": missing})

        # 3. Repair.
        if repair:
            result.repair, result.repair_detail = self._repair_stage(scenario, options)

        # 4. Verify.
        result.after = diagnose(self.device)
        result.verification = self._verification_stage(scenario, expected, result.after)
        self.device.log("verify", result.verification.detail,
                        {"verdict": result.verification.verdict})

        result.duration = time.time() - started
        self.device.log("test_end", result.summary, {"result": result.result})
        self.device.save()
        self._record(result)
        return result

    def _repair_stage(self, scenario: Scenario,
                      options: Dict[str, Any]) -> "tuple[StageResult, Dict[str, Any]]":
        if scenario.repair is None or not scenario.repairable:
            return (StageResult(
                name="repair", verdict=SKIP,
                detail="no software repair exists for this fault: " + scenario.repair_summary,
                data={"repairable": False}), {"repairable": False})
        try:
            detail = self.engine.repair(scenario.id, options)
        except BrickError as exc:
            return (StageResult("repair", FAIL, detail=str(exc)), {"error": str(exc)})
        except Exception as exc:                                # noqa: BLE001
            # A repair that cannot be carried out (no backup to restore from, a chip that will
            # not take the write) is a failed repair, not a crash: the technician needs the
            # reason, and the run still has to be graded.
            LOG.error("the repair stage for %s could not run: %s", scenario.id, exc)
            return (StageResult("repair", FAIL,
                                detail=f"the repair could not be carried out: {exc}"),
                    {"error": str(exc), "repaired": False})
        repaired = bool(detail.get("repaired"))
        note = detail.get("note") or detail.get("method") or ""
        stage = StageResult(
            name="repair", verdict=PASS if repaired else FAIL,
            detail=(f"{scenario.label} repaired: {note}" if repaired else
                    f"the repair did not complete: {note or 'see the repair detail'}"),
            data={k: v for k, v in detail.items()
                  if k in ("method", "changes", "written", "failures", "restored",
                           "handshake", "new_chip", "software_repair_possible",
                           "note", "state_after")})
        self.device.log("repair", stage.detail, {"repaired": repaired})
        return stage, detail

    def _verification_stage(self, scenario: Scenario, expected: Sequence[str],
                            after: Diagnosis) -> StageResult:
        """The device must be clean again, and the faults it had must be gone."""
        checks: List[Dict[str, Any]] = []
        device_check = self.device.verify()
        checks.append({"name": "device", "ok": device_check["ok"],
                       "detail": device_check["verdict"]})
        checks.extend(device_check["checks"])

        cleared = [s for s in expected if s in after.signals]
        checks.append({"name": "faults cleared", "ok": not cleared,
                       "detail": ("no expected fault signal remains" if not cleared else
                                  "still present: " + ", ".join(cleared))})

        scenario_check: Dict[str, Any] = {}
        if scenario.verify is not None:
            try:
                scenario_check = scenario.verify(self.device, {})
            except ScenarioError as exc:
                scenario_check = {"ok": False, "detail": str(exc)}
            except Exception as exc:                                    # noqa: BLE001
                scenario_check = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
            checks.append({"name": f"scenario ({scenario.id})",
                           "ok": bool(scenario_check.get("ok", True)),
                           "detail": str(scenario_check.get("detail", ""))})

        failed = [c for c in checks if not c["ok"]]
        return StageResult(
            name="verification",
            verdict=PASS if not failed else FAIL,
            expected=["no fault signals", "device boots", "table verifies",
                      "storage healthy"],
            found=[c["name"] for c in checks if c["ok"]],
            missing=[c["name"] for c in failed],
            detail=("the device is healthy again: " + "; ".join(c["detail"] for c in checks[:3])
                    if not failed else
                    "verification failed: " + "; ".join(f"{c['name']}: {c['detail']}"
                                                        for c in failed)),
            data={"checks": checks, "remaining_signals": after.signals,
                  "scenario_check": {k: v for k, v in scenario_check.items()
                                     if k != "boot"}})

    # -- batches -----------------------------------------------------------------------
    def run_all(self, options: Optional[Dict[str, Any]] = None,
                only: Optional[Sequence[str]] = None) -> List[TestResult]:
        """Run every applicable scenario, resetting the device between them."""
        results: List[TestResult] = []
        for scenario in self.engine.available():
            if only and scenario.id not in only:
                continue
            self.device.reset()
            results.append(self.run(scenario.id, options))
        return results

    def verify_only(self) -> TestResult:
        """Grade the device as it stands, without applying anything."""
        result = TestResult(device_id=self.device.id, chipset=self.device.profile.chipset,
                            platform=self.device.profile.platform, scenario="(none)",
                            scenario_label="verify only",
                            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        started = time.time()
        result.detection = StageResult("detection", SKIP, detail="no brick was applied")
        result.repair = StageResult("repair", SKIP, detail="no brick was applied")
        after = diagnose(self.device)
        result.after = after
        device_check = self.device.verify()
        ok = device_check["ok"]
        result.verification = StageResult(
            "verification", PASS if ok else FAIL, detail=device_check["verdict"],
            data={"checks": device_check["checks"], "signals": after.signals})
        result.duration = time.time() - started
        self._record(result)
        return result

    # -- internals ---------------------------------------------------------------------
    def _declared_signals(self) -> set:
        """The signals the device's own unrepaired bricks say they will produce.

        Damage the lab applied itself is expected. What deserves a warning is damage nobody
        asked for, because that is the case where a PASS could be an artefact of the device
        having been dirty before the test started.
        """
        declared: set = set()
        for fault in self.device.active_faults:
            try:
                declared.update(self.engine.resolve(fault.id).expected_signals(None))
            except BrickError:
                continue
        return declared

    def _record(self, result: TestResult) -> None:
        if self.bench is not None:
            try:
                self.bench.record(result.flat)
                self.bench.update_status(result.device_id, self.device.status)
            except Exception as exc:                                    # noqa: BLE001
                LOG.warning("could not record the lab history: %s", exc)


def run_workflow(bench, chip: str = "MT6768", storage: Optional[str] = None,
                 scenario_id: str = "gpt_corruption",
                 options: Optional[Dict[str, Any]] = None) -> TestResult:
    """The example from the task, end to end: create a device, brick it, repair it, verify.

        create Virtual MT6768 64GB -> apply GPT corruption -> run Revive diagnosis
        -> expect "GPT damaged" -> run repair -> PASS / FAIL
    """
    device = bench.create(chip=chip, storage=storage)
    try:
        return RecoveryTester(device, bench=bench).run(scenario_id, options)
    finally:
        device.close()
