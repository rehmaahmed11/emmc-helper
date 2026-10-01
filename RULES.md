# Revive Rule Book

This file is the **living rule book** of the project. It is the single place where every
rule the owner has given Revive lives.

**How this file is maintained (itself a standing rule):**

1. **Whenever the owner asks to add a new rule**, it is written into this file as the next
   `Rule N` **before/while it is implemented** — the implementation in the code follows the
   wording here, and both land in the same PR.
2. **After every PR**, this file is updated: the [Changelog](#changelog) gets a dated entry,
   and every existing rule is re-read against the new code to make sure it is still described
   accurately (rules that changed get their text updated, not deleted — the old text moves to
   the changelog entry).
3. `README.md` is updated after every PR in the same way (user-facing docs), while this file
   keeps the binding rules.
4. A rule only changes when the owner says so. Agents implementing work never weaken a rule
   silently; if a rule conflicts with reality, the conflict is pointed out and the rule text
   is corrected after agreement.

---

## Rules

### Rule 1 — Device archive: one folder per device, a read-info file per connection

**Trigger.** Whenever *any* device connects and the app reads its hardware — `revive detect`,
`revive identify`, `revive intercept`, or the web UI reading a connected device — the read
info is saved to a file. This is the *device archive*.

**Where.** Under the archive root (default `~/.revive/devices`; override with the
`REVIVE_DEVICE_ARCHIVE` environment variable or the `--archive-root` flag on
`detect` / `identify` / `intercept` / `devices`):

```
<archive root>/
  <Device Name>/                    # ONE folder per unique device that ever connected
    device.json                     # identity record: name, identity hash, usb id, chip,
                                    # first/last seen, connect count, file counts
    read_info/                      # every hardware read of this device, newest is a file
      read_info_20261001_194503.json
      read_info_20261001_194504.json
    full_dump/                      # full flash dumps of this device
      dump_20261001_195012.bin
    partitions/                     # captured partition tables
      partitions_20261001_194503.json
    notes/                          # free-form technician notes
```

**The folder is named after the device** — its product/model string when the read info has
one (e.g. `Infinix Hot 8 X650B`), otherwise `manufacturer + chip`, otherwise the USB id.

**Same device = 100 percent read-info match.** A connection belongs to an existing device
folder exactly when the read info matches that device 100 percent on all *stable hardware
fields*: USB id, vendor/product/serial strings, chip, hwcode, storage type and size, and
backend. The match is computed as a hash over those fields (stored in `device.json` as
`identity`).

*Session-only* fields — mode (BROM vs fastboot), bus/address, capture time, security flags,
labels — are recorded inside the read-info file but never split one physical device into two
folders: the same phone connecting in a different mode still goes to the same folder.

**Variants are separate devices.** Variants of the same model report different hardware
fields (product string / hwcode / USB id), so they never match 100 percent and each gets its
own folder — e.g. an Infinix Hot 8 that exists as `X650`, `X650B` and `X650C` produces three
folders, one per variant.

**Never overwrite.** If the same device's hardware connects multiple times, previous files
are kept. Every file name carries a **timestamp that includes the seconds**
(`YYYYmmdd_HHMMSS`); if that exact name is already taken (two reads within one second), a
`_02`, `_03`, … suffix is appended instead of overwriting. This applies to read-info files,
full dumps and partition captures alike.

**Full dumps.** A full flash dump for a device lives in that device's `full_dump/` folder
(`revive devices dump <device> <file>`, or the web API `devices.dump`). Archiving a dump
prefers a hard link (zero extra disk space) and falls back to a copy across filesystems.

**Web UI behaviour.** The UI polls detection continuously, so it archives a read-info file
when a device *connects* (a new device identity appears) or *re-connects* — not on every
poll. CLI runs of `detect` / `identify` / `intercept` always save (disable with
`--no-archive`).

**Inspection.** `revive devices list` lists every archived device; `revive devices show
<name>` shows one device's identity record and files; the web API routes are `devices.list`
and `devices.dump`.

Implemented in `revive/ops/device_archive.py` (wired into `revive/cli.py`, `revive/ui/api.py`
and `revive/backends/__init__.py`); covered by `tests/test_device_archive.py`.

---

## Changelog

- **2026-10-01** — Rule 1 added and implemented (this PR): `revive/ops/device_archive.py`
  with per-device folders, sub-folders (`read_info/`, `full_dump/`, `partitions/`, `notes/`),
  100-percent-identity matching, second-precision timestamps that never overwrite, variant
  folders, `revive devices list/show/dump` CLI commands, `devices.list` / `devices.dump`
  web routes, and auto-saving on `detect` / `identify` / `intercept` (CLI + web UI, where a
  new connection — not every poll — triggers the save). 21 new tests in
  `tests/test_device_archive.py`.
- **2026-10-01** — Rule Book created. Standing maintenance rules above; `README.md` is
  updated after every PR as well.
