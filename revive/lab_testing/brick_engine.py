"""The brick engine: one-call fault injection.

This is the layer the UI buttons and the CLI talk to. It resolves a short name ("gpt", "boot",
"nvram", "edl", "brom") to a scenario, refuses to apply a scenario that does not fit the
device's platform, and keeps the device's own log and index in step with what happened.

It deliberately does no diagnosis and no repair of its own: `apply` damages, `repair` delegates
to the scenario, and `recovery_test` decides whether either of them worked.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from . import scenarios as scenario_mod
from .device import VirtualDevice
from .scenarios import Scenario, ScenarioError

LOG = logging.getLogger("revive.lab.brick")

# The short names the UI buttons and `--type` use, mapped to scenario ids.
BRICK_TYPES: Dict[str, str] = {
    "gpt": "gpt_corruption",
    "boot": "boot_corruption",
    "userdata": "userdata_failure",
    "emmc": "bad_emmc",
    "bad_emmc": "bad_emmc",
    "nvram": "nvram_damage",
    "edl": "qualcomm_edl_failure",
    "qualcomm": "qualcomm_edl_failure",
    "brom": "mtk_brom_failure",
    "mtk": "mtk_brom_failure",
}


class BrickError(Exception):
    """Raised when a brick cannot be applied."""


class BrickEngine:
    """Applies and repairs faults on one virtual device."""

    def __init__(self, device: VirtualDevice):
        self.device = device

    # -- catalogue ---------------------------------------------------------------------
    def available(self) -> List[Scenario]:
        """The scenarios that make sense for this device's platform."""
        return scenario_mod.for_platform(self.device.profile.platform)

    def available_ids(self) -> List[str]:
        return [s.id for s in self.available()]

    def describe(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.available()]

    def resolve(self, brick_type: str) -> Scenario:
        """'gpt' / 'gpt_corruption' / 'GPT corruption' -> a Scenario."""
        key = (brick_type or "").strip().lower().replace(" ", "_").replace("-", "_")
        if not key:
            raise BrickError("a brick type is required. Available: "
                             + ", ".join(sorted(BRICK_TYPES)))
        target = BRICK_TYPES.get(key, key)
        try:
            return scenario_mod.get(target)
        except KeyError as exc:
            raise BrickError(str(exc)) from exc

    # -- actions -----------------------------------------------------------------------
    def apply(self, brick_type: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """[BRICK DEVICE]: damage the device."""
        options = dict(options or {})
        scenario = self.resolve(brick_type)
        self._check_platform(scenario)
        if scenario.apply is None:                                        # pragma: no cover
            raise BrickError(f"scenario {scenario.id} has no apply function")
        LOG.info("applying brick %s to %s", scenario.id, self.device.id)
        try:
            result = scenario.apply(self.device, options)
        except ScenarioError as exc:
            self.device.log("brick_failed", f"{scenario.label}: {exc}")
            raise BrickError(f"{scenario.label}: {exc}") from exc
        except Exception as exc:                                          # noqa: BLE001
            self.device.log("brick_failed", f"{scenario.label} raised {type(exc).__name__}: {exc}")
            raise BrickError(f"{scenario.label} failed: {exc}") from exc
        result.setdefault("scenario_id", scenario.id)
        result["label"] = scenario.label
        result["effect"] = scenario.effect
        result["expected_signals"] = scenario.expected_signals(options)
        result["device"] = self.device.id
        result["status"] = self.device.status
        return result

    def repair(self, brick_type: Optional[str] = None,
               options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Repair one brick (by name) or the most recent unrepaired one."""
        options = dict(options or {})
        scenario = self._resolve_for_repair(brick_type)
        if scenario.repair is None:
            return {"scenario_id": scenario.id, "label": scenario.label, "repaired": False,
                    "repairable": False,
                    "note": "this fault cannot be repaired by software: " + scenario.repair_summary}
        try:
            result = scenario.repair(self.device, options)
        except ScenarioError as exc:
            raise BrickError(f"{scenario.label} repair: {exc}") from exc
        result.setdefault("scenario_id", scenario.id)
        result["label"] = scenario.label
        result["device"] = self.device.id
        result["status"] = self.device.status
        return result

    def verify(self, brick_type: Optional[str] = None) -> Dict[str, Any]:
        """[VERIFY RESULT]: scenario-specific checks plus the device-wide health check."""
        options: Dict[str, Any] = {}
        scenario = self._resolve_for_repair(brick_type)
        detail: Dict[str, Any] = {}
        if scenario.verify is not None:
            try:
                detail = scenario.verify(self.device, options)
            except ScenarioError as exc:
                detail = {"ok": False, "detail": str(exc)}
        overall = self.device.verify()
        ok = bool(detail.get("ok", True)) and overall["ok"]
        return {
            "ok": ok, "verdict": "PASS" if ok else "FAIL",
            "scenario_id": scenario.id, "label": scenario.label,
            "scenario_check": detail, "device_check": overall,
        }

    def reset(self) -> Dict[str, Any]:
        """Rebuild the device from scratch: same profile, no faults."""
        info = self.device.reset()
        self.device.save()
        return {"device": self.device.id, "status": self.device.status, **info}

    # -- internals ---------------------------------------------------------------------
    def _check_platform(self, scenario: Scenario) -> None:
        if not scenario.applies_to(self.device.profile.platform):
            raise BrickError(
                f"{scenario.label} does not apply to a {self.device.profile.platform} device "
                f"({self.device.profile.chipset}). It is for: "
                f"{', '.join(scenario.platforms)}. Applicable bricks here: "
                f"{', '.join(self.available_ids())}")

    def _resolve_for_repair(self, brick_type: Optional[str]) -> Scenario:
        if brick_type:
            return self.resolve(brick_type)
        active = self.device.active_faults
        if not active:
            raise BrickError("this device has no unrepaired brick. Apply one first, or name "
                             "the scenario explicitly.")
        return self.resolve(active[-1].id)


def brick_types() -> List[Dict[str, Any]]:
    """The full catalogue, for the CLI and the UI dropdown."""
    out: List[Dict[str, Any]] = []
    for scenario in scenario_mod.all_scenarios():
        entry = scenario.to_dict()
        entry["short_names"] = sorted(k for k, v in BRICK_TYPES.items() if v == scenario.id)
        out.append(entry)
    return out


def apply_to(device: VirtualDevice, brick_type: str,
             options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convenience wrapper: `brick_engine.apply_to(device, 'gpt')`."""
    return BrickEngine(device).apply(brick_type, options)
