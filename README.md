# Revive

**A repair-first toolkit for dead and bricked phones.** Revive does the job SP Flash Tool,
mtkclient and QFIL do — but it explains what it found in plain English, checks the firmware
*before* writing anything, and never touches a partition without a backup plan.

```
  ____            _
 |  _ \ _____   _(_)_   _____
 | |_) / _ \ \ / / \ \ / / _ \
 |  _ <  __/\ V /| |\ V /  __/
 |_| \_\___| \_/ |_| \_/ \___|   repair-first phone toolkit
```

- **MediaTek** (BROM / preloader / DA, SP Flash Tool scatter packages)
- **Qualcomm** (EDL 9008, rawprogram/patch XML, firehose)
- **Unisoc** (PAC containers, read-only by design — see [Scope](#scope-and-honesty))
- **Fastboot** (device info, partitions, flashing A/B images)
- Plus file-level work on any vendor's images: dumps, sparse, super.img, boot images,
  ext4/F2FS/EROFS, eMMC health.

> **Status:** the whole tool runs with **zero third-party dependencies** (Python 3.8+ standard
> library only). The phone-writing backends are implemented but have **not** been verified
> against physical hardware yet, and Revive says so, loudly, in the UI and on the CLI before
> every write. Everything that works on *files* — inspection, validation, planning, dumps,
> conversions, verification — is fully usable today.

> **Rules:** the project's binding rules live in [RULES.md](RULES.md) — the rule book that is
> updated whenever a new rule is added and after every PR. Rule 1 is the **device archive**:
> every connected device gets its own folder and every hardware read a timestamped file.

---

## Why another flashing tool?

| The usual problem | What Revive does instead |
| --- | --- |
| `S_BROM_CMD_STARTCMD_FAIL (2005)` — no idea what that means | Decodes 34 MediaTek/Qualcomm/Unisoc codes and log lines into a numbered, cheapest-first checklist |
| You flash the wrong scatter and only find out at boot time | Validates the package first: missing images, overlaps, wrong sizes, mismatched storage type, protected partitions |
| The tool starts writing immediately | Prints a **dry-run flash plan** with a risk verdict (`LOW`/`MEDIUM`/`HIGH`/`BLOCKED`) and refuses to proceed when something is wrong |
| You lose IMEI, Wi-Fi MAC or sensor calibration | Names the partitions that hold identity data and tells you to back them up **before** anything is written |
| A dump is analysed with guesswork | Parses the GPT, probes every partition (ext4/F2FS/EROFS/boot/super), reports blank/truncated/overlapping regions and unaccounted space |
| A "repaired" GPT still doesn't boot | Recomputes header **and** entries CRCs, rebuilds the backup copy, and verifies the result — dry-run by default |
| Firmware folders are opaque | `revive inspect` classifies the folder and every image in it, with a confidence level |

## Install

```bash
git clone <this repo> && cd emmc-helper
python3 -m revive.cli --help          # runs from the checkout, no install needed
# or install it:
python3 -m pip install -e .           # `revive` command on your PATH
```

Optional extras (only for talking to real hardware; every file operation works without them):

```bash
python3 -m pip install -e ".[usb,serial]"    # pyusb + pyserial
```

Windows, Linux and macOS are all supported. On Linux you also want the udev rules:

```bash
revive drivers            # prints this for your OS, plus the exact udev rule
```

## Quick start

### Try it with no phone at all

```bash
revive demo --out /tmp/revive-demo      # builds synthetic firmware packages, a full dump,
                                        # boot/super/sparse/lz4/f2fs images and a broken package
revive inspect /tmp/revive-demo/firmware_mtk6768
revive plan    /tmp/revive-demo/firmware_broken      # see a BLOCKED plan and why
revive dump-analyse /tmp/revive-demo/dump_full.bin
revive serve --demo --open                            # the web UI with a simulated device
```

### Test the repair logic on a virtual phone (no hardware)

```bash
python3 -m revive.lab_testing create --chip MT6768 --storage 64GB   # a virtual 64 GB MediaTek phone
python3 -m revive.lab_testing brick  --type gpt                     # damage its partition table
python3 -m revive.lab_testing run                                   # diagnose -> repair -> verify: PASS
python3 -m revive.lab_testing report                                # HTML + JSON lab report
```

Seven faults, seven device profiles, MediaTek/Qualcomm/Unisoc. The diagnosis and the repairs are
the same code Revive runs on a real phone, pointed at a simulated eMMC. See
[docs/lab-testing.md](docs/lab-testing.md).

### Find out what is wrong

```bash
revive detect                     # is anything connected, and in which mode?
revive chips --search MT6768      # hardware code → SoC, DA mode, storage
revive err 0x7D5                  # explain an error code
revive err --log brom.log         # read the codes out of a log file and explain them
revive inspect ./firmware         # classify a firmware folder or a single image
```

### Device archive (Rule 1 of [RULES.md](RULES.md))

Every time a device connects and its hardware is read (`detect`, `identify`, `intercept`, or
the web UI), Revive saves the read info into a **per-device archive** — one folder per
device that ever connected, named after the device:

```
~/.revive/devices/                          # or $REVIVE_DEVICE_ARCHIVE / --archive-root
  Infinix Hot 8 X650B/                      # variants (X650 / X650B / X650C) = separate folders
    device.json                             # identity record + connect count + timestamps
    read_info/read_info_20261001_194503.json   # one per hardware read — never overwritten
    read_info/read_info_20261001_194504.json   # (timestamp includes the seconds)
    full_dump/dump_20261001_195012.bin       # full flash dumps (hard link or copy)
    partitions/partitions_20261001_194503.json
    notes/
```

A device is "the same device" when its read info matches a previous one **100 percent** on
the stable hardware fields (USB id, vendor/product/serial, chip, hwcode, storage). Session
fields (mode, bus, time, security flags) don't split a device; model variants do.

```bash
revive devices list                          # every device that ever connected
revive devices show Infinix                  # identity record + files (name or unique prefix)
revive devices dump "Infinix Hot 8 X650B" dump.bin   # place a full dump in its full_dump/
```

### Work safely

```bash
revive plan ./firmware                       # dry run: every write, its risk, and the verdict
revive dump-extract dump.bin --out backup    # extract by partition name + write a manifest
revive manifest backup                       # SHA-256 manifest for anything you extracted
revive verify backup                         # verify it later (tamper/loss detection)
revive gpt-list dump.bin                     # read the partition table
revive gpt-repair dump.bin                   # dry run; add --apply to rewrite CRCs + backup GPT
```

### Convert and inspect images

```bash
revive convert system.img --mode sparse --out system.sparse.img
revive convert system.sparse.img --mode raw
revive convert boot.img --mode boot --out boot_parts/
revive convert dump.bin --mode trim --out dump-trimmed.bin
revive super super.img                                   # list logical partitions
revive super super.img --partition system_a --out system_a.img
```

### The web UI

```bash
revive serve                      # http://127.0.0.1:8765/?token=... (the URL is printed)
revive serve --host 0.0.0.0       # reachable from another machine on the bench
revive serve --demo               # simulated device; nothing touches hardware
```

The UI is a single self-contained HTML page served by Python's standard library, with no CDN
and no build step. It binds to `0.0.0.0` for bench/LAN use, so every API call requires the
session token that the launcher prints (and puts in the URL).

```bash
revive serve --lab ./lab_devices    # where the LAB TESTING tab keeps its virtual devices
```

The **LAB TESTING** tab is the browser half of the laboratory: create a virtual phone, brick it
with one click per fault, run Revive against it, verify the result and generate a report.

## What each part does

| Area | Highlights |
| --- | --- |
| **Diagnosis** | 34-code error dictionary with causes/fixes; USB mode table (BROM/preloader/DA/EDL/fastboot); OS-specific driver + udev help; eMMC CID/CSD/EXT_CSD health (wear flags, PRE_EOL, capacity cross-check) |
| **Packages** | MTK scatter (v1/v2/v3) and Qualcomm rawprogram/patch XML and Unisoc PAC inventory; DA/preloader string analysis; folder classification with confidence |
| **Planning** | Dry-run plan per entry, risk verdict, backup-first list, "nothing is written until you say so" |
| **Dumps** | GPT parse/repair, per-partition probing, signature scan when the table is gone, extraction with SHA-256 manifest |
| **Images** | sparse ↔ raw (streaming, 4 GiB-safe), LZ4 (decompress + verify), boot v0–v4/vendor_boot, super.img (liblp 1.0–1.2+), ext4/F2FS/EROFS superblocks |
| **Verification** | Folder manifests, sparse checksum verification, boot image checks, eMMC health verdict |
| **Backends** | `mock` (always available), `mtk`, `qualcomm`, `unisoc`, `fastboot` — each advertises exactly what it can do and whether it has been verified on hardware |
| **Device archive** | Rule 1 of RULES.md: per-device folders named after the device, `read_info/` file per hardware read (second-precision timestamps, never overwritten), `full_dump/` + `partitions/` + `notes/` sub-folders, 100-percent-identity matching so model variants get their own folders |
| **LAB TESTING** | Virtual devices (MT6765/6768/6877, Snapdragon 450/660/7-series, Unisoc), a simulated eMMC with CID/CSD/EXT_CSD and wear, seven injectable faults, and a graded diagnose → repair → verify loop with HTML + JSON reports |

## Scope and honesty

- **Unisoc PAC flashing is deliberately not implemented.** The container has no public,
  verifiable specification for the write path, so Revive lists and extracts PAC contents and
  tells you to use the vendor tool to flash. A wrong write is worse than no write.
- **The device backends are labelled "unverified on hardware".** The protocol code follows
  public documentation and is exercised against a simulated device in the test suite, but a
  repair tool that claims more than it has proved is dangerous. Verify on a device you can
  afford to lose, and read the plan first.
- **Read-only by default is a feature.** `gpt-repair` needs `--apply`; extraction and
  inspection never modify their input.
- **LAB TESTING is a simulation, and says so in every report it writes.** The virtual devices
  exercise the real diagnosis and repair code against a simulated eMMC; a PASS there means the
  logic handled that fault correctly, not that a given phone will survive the procedure.
- Revive cannot recover data from a physically dead NAND/eMMC without a working download mode
  — no software tool can. What it can do is tell you which failure you have.

## Development

```bash
python3 tests/run_tests.py              # 279 tests, no pytest required
python3 tests/run_tests.py gpt sparse   # filter by module name
python3 tests/run_tests.py device_archive  # the device archive (Rule 1)
python3 tests/run_tests.py lab          # just the LAB TESTING modules
python3 tools/make_demo.py --out /tmp/revive-demo    # rebuild the fixtures
```

The test suite is plain Python on purpose: repair shops run old machines where installing
pytest is a nuisance. Every parser is tested against synthetic data built by
`tools/make_demo.py`, including deliberately broken packages (missing images, overlaps,
oversized images, corrupted GPT CRCs, truncated dumps).

Layout:

```
revive/
  core/      errors, chip table, USB modes
  storage/   gpt, sparse, lz4blk, bootimg, magic, ext4fs, emmc, superimg, fsinfo
  firmware/  scatter, rawprogram, pac, da, detect
  ops/       plan, dump, verify, convert, dossier, device_archive
  backends/  base, mtk_brom, qualcomm_edl, unisoc, fastboot, mock, usbfinder
  lab_testing/   the virtual device laboratory: profiles, virtual eMMC, brick engine,
                 scenarios, recovery grading, reports, its own CLI
  ui/        api.py, server.py, static/index.html
  cli.py     the `revive` command
tools/       make_demo.py (synthetic fixtures)
tests/       zero-dependency test suite
docs/        lab-testing.md, dead-device-handshake-audit.md
```

## License

MIT.
