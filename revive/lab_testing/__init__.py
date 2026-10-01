"""Revive LAB TESTING - a virtual device laboratory for testing repair logic.

What this is
------------
A complete simulated phone bench. Create a virtual MediaTek, Qualcomm or Unisoc phone, brick it
in a specific way, run Revive's real diagnosis engine against it, repair it, and verify that it
came back - without touching hardware.

Why it exists
-------------
The phone-writing backends in Revive are implemented but not verified against physical devices,
and a repair shop cannot afford to brick phones to test a code path. The lab gives every repair
path a device to run against. Crucially it does **not** reimplement the diagnosis: a virtual
eMMC is a real file with a real GPT and real partition content, so `revive.ops.dump.analyse`,
`revive.storage.gpt`, `revive.storage.emmc`, `revive.storage.bootimg` and
`revive.backends.mock.MockBackend` all run against it unchanged. A PASS in the lab means the
real tool found the real fault.

The four buttons
----------------
    create   ->  LabBench.create()
    brick    ->  BrickEngine.apply()
    repair   ->  BrickEngine.repair()   (through RecoveryTester)
    verify   ->  VirtualDevice.verify() (through RecoveryTester)

Typical use
-----------
    from revive.lab_testing import LabBench, RecoveryTester

    bench = LabBench("lab_devices")
    device = bench.create(chip="MT6768", storage="64GB")
    result = RecoveryTester(device, bench=bench).run("gpt_corruption")
    print(result.summary)          # detection PASS, repair PASS, verification PASS -> PASS

Or from the command line::

    python -m revive.lab_testing create --chip MT6768 --storage 64GB
    python -m revive.lab_testing brick --type gpt
    python -m revive.lab_testing run
    python -m revive.lab_testing report

This package is self-contained: nothing outside `revive/lab_testing` imports it, and it modifies
nothing in `revive/core`, `revive/storage`, `revive/firmware`, `revive/ops` or
`revive/backends`.
"""
from __future__ import annotations

import logging

from .brick_engine import BRICK_TYPES, BrickEngine, BrickError, brick_types
from .device import (DEFAULT_LAB_ROOT, DeviceProfile, LabBench, VirtualDevice,
                     get_profile, profile_keys)
from .emmc_virtual import SPEC_OPTIONS, VirtualEMMC, VirtualEmmcError, apply_options
from .extcsd_virtual import (DEAD, HEALTHY, HEALTH_STATES, RegisterSpec, WARNING,
                             selftest as register_selftest)
from .gpt_virtual import GPT_MODES, LabGptError
from .partitions import LAYOUTS, layout_for, layout_names
from .recovery_test import (Diagnosis, RecoveryTester, TestResult, collect_signals,
                            diagnose, run_workflow)
from .reports import lab_report
from .scenarios import SCENARIOS, Scenario, ScenarioError, all_scenarios, load_scenarios

__all__ = [
    # lab + devices
    "LabBench", "VirtualDevice", "DeviceProfile", "DEFAULT_LAB_ROOT",
    "get_profile", "profile_keys",
    # storage
    "VirtualEMMC", "apply_options", "SPEC_OPTIONS", "VirtualEmmcError", "RegisterSpec", "HEALTHY", "WARNING", "DEAD",
    "HEALTH_STATES", "register_selftest",
    # gpt + partitions
    "GPT_MODES", "LabGptError", "LAYOUTS", "layout_for", "layout_names",
    # bricks + testing
    "BrickEngine", "BrickError", "BRICK_TYPES", "brick_types",
    "RecoveryTester", "TestResult", "Diagnosis", "diagnose", "collect_signals",
    "run_workflow",
    # scenarios
    "SCENARIOS", "Scenario", "ScenarioError", "all_scenarios", "load_scenarios",
    # reports
    "lab_report",
]

# The lab logs to the standard logging tree; a NullHandler keeps "no handler" warnings away
# for library users who have not configured logging.
logging.getLogger("revive.lab").addHandler(logging.NullHandler())
