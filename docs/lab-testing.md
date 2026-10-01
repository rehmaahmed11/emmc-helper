# LAB TESTING — the virtual device laboratory

Revive's real job is hardware: a dead phone on the bench, a dump on a card reader, a chip that
will not answer. That is hard to develop against, and impossible to test against — you cannot
break a customer's phone to prove the repair logic works.

LAB TESTING is the other half of the tool: a simulated bench. It builds virtual phones with
virtual eMMC storage, breaks them in the ways phones actually break, and then runs **Revive's
own diagnosis and repair code** against them and grades the result.

```
python3 -m revive.lab_testing create --chip MT6768 --storage 64GB
python3 -m revive.lab_testing brick --type gpt
python3 -m revive.lab_testing run
python3 -m revive.lab_testing report
```

or the same thing in the browser: **LAB TESTING** tab → *Create device* → *Brick GPT* →
*Run Revive (test)* → *Generate report*.

---

## What is simulated, and what is not

| Simulated | Real (unchanged Revive code) |
|---|---|
| The phone: chipset profile, boot chain, download modes | `revive.ops.dump.analyse` — the diagnosis engine |
| The eMMC: CID, CSD, EXT_CSD, wear, bad blocks | `revive.storage.gpt` — table parsing and repair |
| The partitions and their contents | `revive.storage.emmc` — JEDEC register decoding |
| The failures: GPT damage, dead boot, lost NVRAM, worn flash | `revive.storage.ext4fs`, `revive.storage.bootimg` |
| The transport: a `LabTransport` backend over a file | `revive.ops.verify`, `revive.backends.mock` |

The virtual eMMC is a real file on disk (`lab_devices/<device>/emmc.img`) containing an MBR, a
real GPT built by `revive.storage.gpt.build_gpt_bytes`, and per-partition payloads with real
magic numbers. So when the lab says "the partition table is damaged", it is because
`read_gpt()` read the bytes and found the CRC broken — not because a flag was set.

Nothing here touches USB, and nothing here can write to a phone.

---

## Device profiles

| Profile key | Chipset | Platform | Notes |
|---|---|---|---|
| `MT6765` | MT6765 (Helio P35) | mtk | hwcode `0x0706`, BROM download mode |
| `MT6768` | MT6768 (Helio G85) | mtk | hwcode `0x0707`, BROM download mode |
| `MT6877` | MT6877 (Dimensity 900) | mtk | hwcode `0x0990`, BROM download mode |
| `SDM450` | Snapdragon 450 | qualcomm | EDL `05c6:9008` |
| `SDM660` | Snapdragon 660 | qualcomm | EDL `05c6:9008` |
| `SDM7XX` | Snapdragon 7 series | qualcomm | EDL `05c6:9008` |
| `UNISOC` | Unisoc SC9863A | unisoc | basic PAC/sprd download simulation |

Each profile carries `name`, `chipset`, `vendor`, `model`, `storage`, `interface`, `boot_mode`,
`hwcode`, `usb_id` and `identity_partitions`. Free text works too: `--chip "helio g85"` and
`--chip snapdragon660` both resolve.

**Partition layouts.** MediaTek: `pgpt`, `preloader`, `lk`, `boot`, `recovery`, `vendor`,
`system`, `userdata`, `nvram`, `nvdata`, `protect1`, `protect2`, `proinfo`, `flashinfo`,
`otp`. Qualcomm: `pgpt`, `xbl`, `abl`, `boot`, `system`, `vendor`, `modemst1`, `modemst2`,
`fsg`, `modem`, `userdata`. Unisoc: `pgpt`, `sml`, `ubl`, `boot`, `system`, `vendor`, `fixnv`,
`runtimenv`, `prodnv`, `userdata`. The nine MediaTek and eight Qualcomm partitions the spec
names are all there; the extras are the neighbours a real layout has, because the diagnosis
engine reasons about a whole table.

`--storage 64GB` sets the **nominal** capacity reported in CID/CSD/EXT_CSD. The image on disk
is small (`--image-bytes`, default 32 MiB) — the lab does not fill 64 GB to test a partition
table. The registers say 64 GB; the geometry says what fits.

---

## The virtual eMMC

`revive/lab_testing/extcsd_virtual.py` generates the registers; `emmc_virtual.py` is the
controller around the image file.

* **CID** — MID/OID/PNM/PRV/PSN/MDT with a CRC7 in the last byte. `PNM` is six ASCII bytes and
  the manufacturing year is four bits from 2000, so a longer name or a date after 2015 is
  clamped at construction. The lab's device card and the CID never disagree.
* **CSD** — structure 3, capacity `(C_SIZE+1) × 512 KiB`. `C_SIZE` is twelve bits, so a
  structure-3 CSD cannot express more than 2 GiB; above that the field saturates and Revive's
  summary points the reader at EXT_CSD `SEC_COUNT`, exactly as it does for real chips.
* **EXT_CSD** — revision 8 (eMMC 5.1), `SEC_COUNT`, boot/RPMB sizes, `DEVICE_VERSION`,
  `FIRMWARE_VERSION` (eight ASCII bytes), and the three health bytes:

  | `PRE_EOL_INFO` | state | `DEVICE_LIFE_TIME_EST` A/B | what Revive says |
  |---|---|---|---|
  | `0x01` | healthy | 0x01 / 0x01 | ok |
  | `0x02` | warning | 0x0B / 0x09 | warn — plan the migration, back everything up |
  | `0x03` | dead | 0x0B / 0x0B | fatal — do not flash this chip |

* **Health is behaviour, not a label.** At `PRE_EOL_INFO == 0x03` a write is accepted and then
  does not hold, which is the failure that makes a reflash look like it worked. Reads that hit
  a bad block fail. Enough bad blocks move the wear bytes on their own.
* **Changeable** — one code path (`apply_options`) behind the CLI, the API and the UI:

  ```bash
  python3 -m revive.lab_testing create --chip MT6768 --opt manufacturer=Micron --opt size=128GB
  python3 -m revive.lab_testing set --opt health=dead --opt firmware_version=0x4c414231
  ```

  `manufacturer`, `size` / `capacity`, `health`, `pre_eol`, `firmware_version`, `product_name`,
  `serial`, `write_cycles` and `bad_blocks` are the settings; an unknown name is an error, not a
  silent no-op. A `0x........` firmware version becomes the eight hex digits a chip actually
  prints, whichever of the three interfaces you used.
* **Golden copies.** Before a brick, the lab keeps a known-good copy of every partition it is
  about to damage (`<device>/golden/<part>.img`). Repairs restore from those copies and verify
  by SHA-256. That is why the lab never "invents" data — the same rule Revive applies to real
  devices, including IMEI.

`python3 -m revive.lab_testing selftest` builds all three health states, decodes them with
Revive's real parser, and checks the verdict each one produces.

---

## The seven faults

| Brick | Short name | What it does to the image | Signals Revive must find | Repair |
|---|---|---|---|---|
| GPT corruption | `gpt` | breaks the primary header and entry CRCs (`mode=missing` erases the primary, `mode=total` destroys both copies) | `gpt_header_crc_bad`, `gpt_entries_crc_bad`, `gpt_primary_damaged` | `revive.gpt.repair_gpt` → `rebuild_from_backup` → `rewrite_from_layout` |
| Boot corruption | `boot` | destroys the `ANDROID!` magic and header | `boot_image_invalid`, `boot_fails` | re-flash boot from the golden copy |
| Bad eMMC | `emmc` | `PRE_EOL_INFO 0x03`, life estimates exhausted, bad blocks | `emmc_pre_eol_urgent`, `emmc_life_exceeded`, `emmc_bad_blocks`, `emmc_health_fatal` | simulated chip replacement (`software_repair_possible: false`) |
| NVRAM damage | `nvram` | erases the identity block: `nvram`/`proinfo` (MTK), `modemst1/2`+`fsg` (QC), `fixnv`/`prodnv` (Unisoc) | `nvram_invalid` | restore the device's own backup — never rewrite an IMEI |
| userdata failure | `userdata` | marks the ext4 superblock dirty/errored | `userdata_fs_dirty` | clear the state, offer a reset |
| MTK BROM mode | `brom` | kills the preloader, device enumerates `0e8d:0003` | `device_in_brom`, `preloader_damaged`, `boot_fails` | re-flash the preloader, leave download mode |
| Qualcomm EDL 9008 | `edl` | kills the bootloader, device enumerates `05c6:9008` | `device_in_edl`, `bootloader_damaged`, `boot_fails` | firehose programmer path |

Platform guards are enforced: `brom` on a Snapdragon and `edl` on a MediaTek both refuse with
the list of bricks that *do* apply. Bricking twice does not undo the damage.

---

## How a run is graded

`RecoveryTester.run(scenario)` does five things and grades four of them:

1. **Baseline** — diagnose the untouched device, so a PASS cannot be an artefact of a device
   that was already dirty. Damage the lab did not apply is a warning; damage it did apply (the
   documented `brick` → `run` order) is expected.
2. **Brick** — apply the fault, unless the device already carries it.
3. **Detection** — run `revive.ops.dump.analyse` and collect signals.
   **PASS ⟺ every signal the scenario declared is present.** Extras are allowed; a diagnosis
   that reports nothing is graded FAIL, not PASS.
4. **Repair** — run the scenario's repair, which calls the same functions Revive uses on real
   devices. A repair that cannot run (no backup, a chip that will not take the write) is a FAIL
   with a reason, not an exception.
5. **Verification** — **PASS ⟺ the expected signals are gone AND `device.verify()` passes AND
   the device boots to Android AND the scenario's own check passes.**

Overall result: every stage that ran must have passed; skipped stages do not count either way.

**Negative controls**, in the test suite, prove the grading is not vacuous:

* `--no-repair` → every scenario reports `verification FAIL`;
* a blinded diagnosis (signals replaced with `[]`) → `detection FAIL`;
* deleting a golden copy → `repair FAIL`.

---

## What is written where

```
lab_devices/
├── index.json              device registry + which one is active
├── history.jsonl           one line per run: timestamp, device, scenario, result
├── last_report.json        the most recent report
└── 20261001_173236_MT6768_64GB/
    ├── device.json         profile, faults, partition map, status     revive-lab-device/1
    ├── emmc.img            the storage: MBR + GPT + partitions
    ├── partition_map.json  offsets, sizes, checksums, status          revive-lab-partitions/1
    ├── extcsd.json         CID/CSD/EXT_CSD as Revive decoded them     revive-lab-extcsd/1
    ├── golden/             known-good copy of every brickable partition
    ├── logs/lab.log        human-readable log
    ├── logs/events.jsonl   one line per event, for post-mortems
    └── reports/            lab_report_<scenario>_<ts>.{html,json}
```

Reports are self-contained HTML (no CDN, no network) plus JSON with the same data. Both show
Device, Scenario, Detection, Repair, Verification and the overall result, each PASS/FAIL, with
the evidence behind the verdict.

---

## CLI

```
python3 -m revive.lab_testing <command> [flags]        # --lab/--device/--json go AFTER the command

  create    --chip MT6768 --storage 64GB [--image-bytes N] [--opt manufacturer=Micron]
  set       --opt health=dead --opt size=128GB          change what the chip reports
  brick     --type gpt|boot|nvram|emmc|userdata|brom|edl [--opt mode=total]
  repair    [--type gpt]            repair the active brick
  verify                            grade the device as it stands
  reset                             rebuild the device, faults cleared
  run       [--scenario ID|--all] [--no-repair] [--no-report] [--out DIR]
  test      [--scenario ID]         brick + run in one step
  report                            write/refresh the device report
  list | status | history | profiles | scenarios | delete | selftest
```

`python3 -m revive.cli lab <the same subcommands>` works too, including `lab --help`.

`--opt NAME=VALUE` passes scenario options: `mode=crc|missing|total` for GPT,
`health=warning|dead` and `bad_blocks=N` for the eMMC, `bytes=N` for NVRAM.

Note for shell chains: `verify` exits 1 for an unhealthy device, so use `;` rather than `&&`.

## Web UI

The **LAB TESTING** tab has the buttons the workflow needs — *Create device*, *Apply chip
settings*, one per brick, *Run Revive (test)*, *Repair*, *Verify result*, *Generate report*,
*Reset device*, *Delete device* — plus the device's registers, partitions, fault signals and
test history. It talks to thirteen `lab.*` API routes; the long-running ones (`lab.create`,
`lab.run`, `lab.report`) go through the same job queue as the rest of the UI.

```
python3 -m revive.cli serve --lab ./lab_devices
```

## Tests

| Module | Covers |
|---|---|
| `tests/test_lab_device.py` | profiles, layout planning, the image, boot, save/reload, bench |
| `tests/test_virtual_emmc.py` | registers round-tripped through Revive's decoder, health, bad blocks, IO |
| `tests/test_brick_engine.py` | each fault does what it declares; platform guards; idempotence |
| `tests/test_recovery_flow.py` | the graded workflow, the negative controls, reports, the CLI |
| `tests/test_lab_ui.py` | the twelve routes over real HTTP, and that the page calls all of them |

```
python3 tests/run_tests.py lab
```
