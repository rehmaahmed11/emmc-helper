# Audit: dead-device handshake capture & forced BROM/EDL entry

**Scope:** `revive/backends/interceptor.py`, `revive/backends/mtk_brom.py`,
`revive/backends/qualcomm_edl.py`, `revive/backends/usbfinder.py`, plus the CLI/dossier surfaces
that report the outcome.
**Base commit:** `e4186da` (branch `arena/01a0f828-emmc-helper`).
**Method:** fault-injection simulation of hard-bricked phones — no physical hardware was available,
so every claim below is about what the *code does under a given device behaviour*, not about what a
specific phone model does on a bench.

---

## TL;DR

* Added **37 adversarial tests** (`tests/test_dead_device_audit.py`); suite total is now **129
  tests, all passing**, still zero third-party dependencies (`python3 tests/run_tests.py`).
* The tests **condition** damaged devices: boot ROMs that ignore the sync hammer, answer garbage,
  refuse WDT writes, drop out mid-handshake, dribble USB packets, or never re-enumerate as BROM
  after a Preloader crash.
* **8 defects found and fixed.** The two critical ones were *false success claims*: a handshake
  could be reported as "locked" when only one of four sync bytes matched, and `force_brom` reported
  success when the phone never came back as BROM (while handing the caller a dead USB handle).
* Every fix is covered by a test that fails against the pre-fix code. A probe run against pristine
  `HEAD` vs. the fixed tree is reproduced below.

---

## How the audit conditions a "dead" device

All transports are in-process fakes with nanosecond-stamped transfer logs
(`tests/test_dead_device_audit.py`), so malformed behaviour is deterministic and reproducible:

| Simulation | Models |
| --- | --- |
| `BromScript` / `ScriptedBrom` | MediaTek BROM/Preloader: scripted answers per hammer attempt, broken sync plans, junk/refused status words, ACK/NAK for WDT writes |
| `ScriptedSahara` | Qualcomm EDL 9008: arbitrary packet sequences, configurable short-read chunking |
| `ScriptedFastboot`, `ScriptedDiag` | fastboot EDL transitions, QCDM 9006 switch frames |
| `ScriptedSerialPort` | OS-bound VCOM (Windows COM / Linux ttyACM) via `SerialTransportAdapter` |
| `dead_finder`, patched `scan_usb_bounces` | No enumeration at all; kernel `error -71` contact bounces |
| `patched(wait_for_device=…)` | Preloader crash followed by BROM re-enumeration — or by nothing |

Invariants the tests enforce:

1. `ok=True` is only reported when a real handshake locked on the wire.
2. Every captured byte (4-byte MTK sync, Sahara HELLO) is verified, never assumed.
3. `preloader_crashed_to_brom` = crash payload sent; `brom_recaptured` = phone actually re-caught
   as `0e8d:0003` and re-handshaken. They are **separate fields**.
4. Dead devices end in an actionable message, never in a phantom success and never in a traceback.
5. The hot path (sync hammer) never touches USB string descriptors before the lock.

---

## Findings

| # | Severity | Finding | Fixed | Covering test |
| --- | --- | --- | --- | --- |
| F-01 | **Critical** | MTK sync accepted any reply (or even partial/noise); `ok=True` with 1 of 4 bytes | yes | `test_mtk_sync_requires_all_four_exact_bytes`, `test_mtk_sync_rejects_wrong_byte_mid_sequence` |
| F-02 | **Critical** | `force_brom` reported success when BROM never re-appeared; stale dead handle returned | yes | `test_force_brom_without_a_reappearing_brom_is_not_reported_as_success` |
| F-03 | High | Watchdog reported "disabled" without an acknowledged write | yes | `test_mtk_wdt_disable_requires_an_acknowledged_zero_status` |
| F-04 | High | EDL handshake accepted *any* Sahara packet; no short-read reassembly; no lock write = still `ok` | yes | `test_sahara_dribbled_hello_is_reassembled_and_locked`, `test_sahara_non_hello_first_packet_is_rejected` |
| F-05 | High | Chip identity fabricated from a refused `GET_HW_CODE` response | yes | `test_mtk_probe_refuses_to_fabricate_a_chip_from_an_error_status` |
| F-06 | Medium | Backend Sahara reader had the same single-read/truncation defect and accepted `length < 8` | yes | `test_qualcomm_backend_sahara_reader_tolerates_short_reads_and_rejects_truncation` |
| F-07 | Medium | Status accepted from a 10–11 byte reply (partial status word); stale error kept after a successful retry | yes | `test_intercept_keeps_spinning_after_a_failed_handshake_until_one_locks` |
| F-08 | Low | Fastboot escalation that accomplished nothing left no failure record | yes | `test_fastboot_escalation_records_failure_when_nothing_is_accepted` |

### F-01 — Phantom MediaTek handshake (critical)

The hammer loop treated *any* first byte as "got_first" and only required the remaining three sync
bytes when that byte happened to be `0x5F`. A stale session, a CDC echo or a dying port that
answered `0x42` therefore produced `ok=True` with a single "sync pair" — and the caller proceeded
to identify the chip and report a frozen BROM.

**Fix:** the lock requires the exact 4-byte inverse sync (`A0→5F`, `0A→F5`, `50→AF`, `05→FA`).
A mismatch mid-sequence aborts with `BackendError(code=2005)`, the partial trace is preserved in
`result.sync_bytes`, and the error names the byte that broke.

### F-02 — `force_brom` success without a BROM re-catch (critical)

`_crash_preloader_into_brom()` set `preloader_crashed_to_brom = True` immediately after the
poison/WDT-reset writes and the port reset. When no `0e8d:0003` device re-appeared, the capture was
still returned as `ok=True`, `mode=mtk_preloader`, **with the dead Preloader handle attached** —
so `revive intercept --force-brom` printed "HANDSHAKE LOCKED … preloader_crashed_to_brom: true" and
any follow-up read would have gone to a handle that no longer exists.

**Fix:** new `brom_recaptured` field, set only after the re-enumerated device completes a *full*
sync + probe. `preloader_crashed_to_brom` now means "crash payload was delivered" and remains true
for the trace. When `force_brom` was requested and BROM does not come back, the capture returns
`ok=False`, clears the dead handle, and carries an actionable error; the interceptor keeps spinning
until its timeout instead of ending the run on the first crashed Preloader. The crash payload is
attempted **once** per run. CLI, dossier trace, checklist and summary index all show the two facts
separately (`_force_entry_summary`).

### F-03 — "Watchdog disabled" without an acknowledgement (high)

`disable_mtk_watchdog()` returned `True` and set `result.wdt_disabled = True` whenever the writes
did not raise — including when the boot ROM refused with `0x02000000` or answered nothing. That
directly contradicts the promise that the phone is frozen in BROM (without the WDT disable it drops
out within seconds).

**Fix:** both ACKs are decoded with the shared `parse_brom_status()` (tries both byte orders, only an
exact zero counts as OK). A refusal sets `wdt_disabled=False`, records `telemetry["wdt_error"]` and
emits a `wdt_disable_refused` event naming the status.

### F-04 — EDL: any packet was a "captured handshake" (high)

`qualcomm_sahara_intercept()` did one `read(64)`:
* a short read (normal on USB) left `payload` empty, yet the result was `ok=True`, no telemetry and
  **no `HELLO_RESPONSE` sent** — the Sahara session was never locked;
* a `DONE`/`RESET` packet from a device that another tool had already opened was also `ok=True`;
* a write failure on the lock packet was swallowed.

**Fix:** exact-length reads with a deadline plus an overflow buffer for coalescing transports,
`length` sanity (`8 ≤ length ≤ 1 MiB`), explicit rejection of non-`HELLO` first packets, legacy
(short) HELLO support with a `sahara_legacy_hello` marker, and an error when the `HELLO_RESPONSE`
cannot be written. `sahara_session_locked` is only set when the lock packet actually went out.

### F-05 — Fabricated chip identity (high)

`_mtk_probe_and_freeze()` unpacked `hwcode`/`target_config` without checking the status word. On a
refusing device the junk `[6:8]` field became a chip name in the telemetry and dossier — the user
could then download firmware for a chip that was never identified. The `0xD4` fallback also
bypassed an explicit `0xFC` refusal.

**Fix:** the `0xFC` reply is trusted only with an `ok` status; a refusal is recorded as
`hwcode_refused` with the decoded verdict and no chip is reported. The `0xD4` hwcode fallback is
disabled when `0xFC` was refused.

### F-06 … F-08 — Smaller correctness items

* `QualcommEdlBackend._read_exact()` now loops to a deadline; `read_sahara_packet()` rejects
  `length < 8` and truncated payloads instead of parsing a half-frame.
* `MtkBromBackend._parse_status()` requires 12 bytes before reading a status word; a successful
  lock clears any error string left by an earlier failed attempt in the same run.
* A fastboot escalation where no command is accepted records
  `fastboot: none of the EDL/reboot transition commands was accepted` in the trace and actions.

---

## Evidence: same scenarios, pre-fix vs post-fix

Probe run against a pristine `git archive HEAD` checkout and the fixed tree (identical fake devices):

| Scenario | Pre-fix (`e4186da`) | Post-fix |
| --- | --- | --- |
| BROM only answers `0x42` | `ok=True`, `sync=[A0→0x42]`, `wdt_disabled=True` | `ok=False`, no sync pairs, error names `0x5F` and the attempt count |
| WDT write refused (`0x02000000`) | `wdt_disabled=True`, no error | `wdt_disabled=False`, `wdt_error="write command: status 0x02000000 (security); …"` |
| `GET_HW_CODE` refused, junk `0xDEAD` | `chip="unknown (0xDEAD)"` | no chip claimed, `hwcode_refused="status 0x02000000 (security)"` |
| `force_brom`, BROM never re-appears | `ok=True`, `mode=mtk_preloader`, live dead handle, no error | `ok=False`, `device=None`, `brom_recaptured=False`, actionable error |
| EDL first packet is `DONE` | `ok=True`, no error, no telemetry | `ok=False`, `expected a Sahara HELLO (0x01) from EDL, got DONE` |
| Sahara HELLO dribbled in 8-byte reads | `ok=True` but `telemetry={}` and **no `HELLO_RESPONSE` sent** | `ok=True`, `version=2`, `session_locked=True`, `HELLO_RESPONSE (2,48)` sent |

---

## What the tests confirm *does* work

* Exact 4-byte inverse sync byte ordering and the retry-until-lock behaviour (including recovering
  from noise and honouring the attempt budget without stalling).
* No USB string-descriptor reads on the hot path (records 0 accesses during the hammer).
* WDT target `0x10007000 ← 0x22000000` for the simulated code, with per-family base lookup.
* Crash payload bytes: `0xD0 + u32(0)` poison, `0xD7 + addr(0x10007014) + len(4)`, value `0x1209`,
  then a port reset — and only once per run.
* A device already in BROM is never sent the crash payload.
* Retry-after-failure inside one `intercept()` run locks the later good device, keeping the earlier
  failure in the trace and clearing the stale error.
* OS-bound VCOM path: the same handshake runs over `SerialTransportAdapter` (baud 115200 applied,
  DTR/RTS asserted).
* Escalation frames: fastboot `oem edl` → `reboot-edl` ordering, QCDM `4b650100540f7e` and
  `3aa16e7e`, `adb reboot edl`, and failure recording when nothing is accepted.
* Dead bus: 50 ms timeout returns in well under a second with the power/volume-key guidance;
  kernel `error -71`/`-110` bounce lines are parsed into `usb_bounces` and shown by the CLI.
* Every result is JSON-safe; live USB handles never leak into `to_dict()`.

## Residual risk (cannot be closed without hardware)

1. **Sub-millisecond timing.** The fakes prove ordering and that the hammer is zero-sleep; they
   cannot prove real capture probability against a 15–80 ms BROM window. The 25 ms per-attempt
   read timeout is still an untested assumption on real silicon.
2. **Exact BROM response layout.** `hwcode` at `[6:8]`, `target_config` at `[8:10]` and the status
   word at `[8:12]` overlap in the same 16-byte frame. The code now refuses ambiguous data rather
   than guessing, but the offsets themselves remain from public RE notes and must be confirmed on
   a device (the docstring in `mtk_brom.py` already asks for field reports).
3. **WDT base table.** Entries beyond the documented families are placeholders
   (`0x10007000`); a wrong base means a write to the wrong register on that SoC.
4. **Secure boot.** SBC/SLA/DAA devices still need a signed DA + auth file; nothing here bypasses
   that, and forced BROM entry does not defeat it.
5. **Crash-payload efficacy / QCDM frames.** That `WDT_SWRST=0x1209` reliably re-enters BROM, and
   that the QCDM frames flip `05c6:9006 → 9008`, is unverifiable offline.
6. **Firehose upload path** was not re-audited beyond packet framing; `program()`/`read_sectors()`
   behaviour on a live EDL device is untested here.

## Files changed

| File | Change |
| --- | --- |
| `revive/backends/interceptor.py` | status decoder, exact sync, honest force-BROM, WDT ACK validation, Sahara reassembly/validation, fastboot failure record, overflow buffer |
| `revive/backends/mtk_brom.py` | `crash_preloader_to_brom()` returns the real re-capture; backend notes when force-BROM failed; 12-byte status minimum |
| `revive/backends/qualcomm_edl.py` | deadline-based exact reads, packet length/truncation sanity |
| `revive/cli.py`, `revive/ops/dossier.py` | report `brom_recaptured` separately from `preloader_crashed_to_brom` in CLI, trace, checklist, index |
| `tests/test_dead_device_audit.py` *(new)* | 37 fault-injection tests |
| `tests/fixtures.py`, `tests/test_backends.py`, `tests/run_tests.py` | shared `patched()` helper, honest force-BROM expectations, module registration |

## Running it

```bash
python3 tests/run_tests.py                 # 129 tests, zero dependencies
python3 tests/run_tests.py dead_device     # just this audit (37 tests)
```
