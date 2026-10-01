"""The scenario registry: every fault the lab can inject, and how to repair it.

A scenario is a small, self-describing unit:

    id / label / description    what the technician sees in the UI and the CLI
    platforms                   which chip families it applies to
    apply(device, options)      damage the device
    expects(options)            the fault signals Revive's diagnosis *must* find
    repair(device, options)     fix it (or explain honestly why software cannot)
    verify(device)              optional extra checks on top of the shared verification

Keeping `expects` next to `apply` is what makes the lab a test of Revive rather than a test of
itself: the damage declares up front which signals it should produce, and
`recovery_test` only reports PASS when the real diagnosis engine found exactly those.
"""
from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

LOG = logging.getLogger("revive.lab.scenarios")

ALL_PLATFORMS = ("mtk", "qualcomm", "unisoc")

# Modules in this package, in the order the UI lists them.
_MODULE_NAMES = (
    "gpt_corruption",
    "boot_corruption",
    "userdata_failure",
    "bad_emmc",
    "nvram_damage",
    "qualcomm_edl_failure",
    "mtk_brom_failure",
)


@dataclass
class Scenario:
    """One injectable fault."""

    id: str = ""
    label: str = ""
    description: str = ""
    effect: str = ""
    platforms: Tuple[str, ...] = ALL_PLATFORMS
    severity: str = "error"
    repairable: bool = True
    repair_summary: str = ""
    options: Tuple[str, ...] = ()
    apply: Optional[Callable[..., Dict[str, Any]]] = None
    expects: Optional[Callable[..., Sequence[str]]] = None
    repair: Optional[Callable[..., Dict[str, Any]]] = None
    verify: Optional[Callable[..., Dict[str, Any]]] = None
    module: str = ""
    tags: Tuple[str, ...] = ()

    def applies_to(self, platform: str) -> bool:
        return not self.platforms or (platform or "").lower() in self.platforms

    def expected_signals(self, options: Optional[Dict[str, Any]] = None) -> List[str]:
        if self.expects is None:
            return []
        try:
            return [str(s) for s in self.expects(options or {})]
        except Exception as exc:                                        # noqa: BLE001
            LOG.warning("scenario %s could not declare its expected signals: %s", self.id, exc)
            return []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "label": self.label, "description": self.description,
            "effect": self.effect, "platforms": list(self.platforms),
            "severity": self.severity, "repairable": self.repairable,
            "repair_summary": self.repair_summary, "options": list(self.options),
            "expected_signals": self.expected_signals(), "tags": list(self.tags),
        }


class ScenarioError(Exception):
    """Raised when a scenario cannot be applied (wrong platform, missing partition, ...)."""


# --------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------

SCENARIOS: Dict[str, Scenario] = {}


def _register(scenario: Scenario) -> Scenario:
    if scenario.id in SCENARIOS:
        raise ValueError(f"duplicate lab scenario id {scenario.id!r}")
    SCENARIOS[scenario.id] = scenario
    return scenario


def load_scenarios(force: bool = False) -> Dict[str, Scenario]:
    """Import every scenario module and collect its SCENARIO object."""
    if SCENARIOS and not force:
        return SCENARIOS
    for name in _MODULE_NAMES:
        module = importlib.import_module(f"{__name__}.{name}")
        scenario = getattr(module, "SCENARIO", None)
        if scenario is None:
            LOG.warning("scenario module %s does not export SCENARIO", name)
            continue
        scenario.module = name
        _register(scenario)
    return SCENARIOS


def all_scenarios() -> List[Scenario]:
    return list(load_scenarios().values())


def get(scenario_id: str) -> Scenario:
    load_scenarios()
    key = (scenario_id or "").strip().lower()
    if key in SCENARIOS:
        return SCENARIOS[key]
    # Tolerate the short names the UI buttons use: "gpt", "boot", "nvram", "edl", "brom".
    matches = [s for s in SCENARIOS.values()
               if s.id.startswith(key) or key in s.id or key in " ".join(s.tags)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise KeyError(f"no lab scenario named {scenario_id!r}. "
                       f"Available: {', '.join(sorted(SCENARIOS))}")
    raise KeyError(f"{scenario_id!r} is ambiguous: {', '.join(s.id for s in matches)}")


def ids() -> List[str]:
    return sorted(load_scenarios())


def for_platform(platform: str) -> List[Scenario]:
    return [s for s in load_scenarios().values() if s.applies_to(platform)]


def describe() -> List[Dict[str, Any]]:
    return [s.to_dict() for s in load_scenarios().values()]


# --------------------------------------------------------------------------------------
# Helpers the scenarios share
# --------------------------------------------------------------------------------------

def require_partition(device, name: str):
    """Return a partition that exists in the image, or raise a clear error."""
    part = device.partition(name)
    if part is None or part.size <= 0:
        raise ScenarioError(f"this device has no usable {name!r} partition "
                            f"(platform {device.profile.platform})")
    return part


def zero_head(device, part, length: int = 4096) -> Dict[str, Any]:
    """Erase the head of a partition: the damage an interrupted write leaves behind."""
    from ...util import human_size

    length = min(int(length), part.size)
    device.emmc.write(part.offset, b"\x00" * length)
    return {"partition": part.name, "offset": part.offset,
            "bytes_zeroed": length, "bytes_zeroed_human": human_size(length)}


def corrupt_bytes(device, part, offset: int, blob: bytes) -> Dict[str, Any]:
    device.emmc.write(part.offset + int(offset), blob)
    return {"partition": part.name, "offset": part.offset + int(offset),
            "bytes_written": len(blob)}
