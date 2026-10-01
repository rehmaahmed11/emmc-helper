# Revive — Termux Variant

Revive running on a plain **Termux** install on an Android phone. Use your phone to inspect firmware,
plan flashes, analyse dumps, fix GPTs, and talk to a second phone over a USB-OTG cable.

**Nothing to compile or pip-install.** It's pure Python standard library. You don't need
`pyusb`, `libusb`, `pyserial`, `clang`, `rust` or `make`. The only packages are prebuilt
Termux packages: `python` (required) and `termux-api` (optional, only for USB).

## Install (copy and paste in Termux)

```bash
pkg update -y && pkg install -y git python
git clone https://github.com/rehmaahmed11/emmc-helper
cd emmc-helper/termux-variant
bash install.sh             # add --no-usb to skip termux-api
termux-setup-storage        # optional: lets Revive read ~/storage/downloads
```

For USB phone access, also install the **Termux:API app**. Get it from the same place you got
Termux (F-Droid or GitHub). Don't mix it with the Play Store build.

You can also skip the installer and run `sh termux-variant/bin/revive-termux <command>` directly.

## Use

Every normal Revive command works. `revive` and `revive-termux` are the same thing:

```bash
revive doctor                               # check this Termux setup
revive demo                                 # sample firmware + dump to learn on
revive inspect ~/storage/downloads/firmware
revive plan    ~/storage/downloads/firmware
revive dump-analyse dump.bin
revive err 2005                             # explain an error code
revive serve --demo --open                  # web UI in your phone's browser
```

### Talking to another phone over USB-OTG (no root)

Android doesn't let apps open USB devices directly. `termux-usb` asks for permission, then passes
Revive an open file descriptor. Revive drives it with raw Linux `usbdevfs` ioctls, using
only `fcntl` and `ctypes` from the standard library.

```bash
revive usb-list                      # what Android sees on the OTG port
revive usb detect                    # attach a device (accept the dialog), then run `detect`
revive usb identify                  # any Revive command can follow `usb`
revive usb --wait 30 identify        # wait for a NEW device to appear, then attach it
revive usb --device /dev/bus/usb/001/004 identify
```

## What is different from the desktop version

| Area | Desktop | Termux variant |
| --- | --- | --- |
| USB access | pyusb + libusb | `termux-usb` fd + raw usbdevfs ioctls (stdlib only) |
| Serial / COM / ttyACM | pyserial | not available (Android blocks it without root) |
| sysfs re-enumeration, dmesg bounce scan | yes | off (needs root); USB reset via fd still works |
| `serve --open` | desktop browser | `termux-open-url` |
| File tools (inspect, plan, dumps, GPT, super, sparse, manifest, …) | yes | yes, identical |

### Honest limits

- **MediaTek BROM timing:** BROM mode only lasts about 1–2 seconds. You have to accept the Android
  permission dialog before it disappears, which is hard. **Preloader** mode (the phone plugged in
  while powered off) and **Qualcomm EDL 9008** both stay connected long enough. On BROM, tick
  "always open Termux for this device" so the next try skips the dialog.
- OTG power: some dead phones need more current than your phone's OTG port gives. If the device
  doesn't appear, use a powered OTG hub.
- Revive warns on every write that the hardware backends haven't been tested on real devices.
  That warning applies here too.

## Layout

```
termux-variant/
├── install.sh                 # pkg-only installer, links `revive` + `revive-termux`
├── bin/revive-termux          # launcher (finds the repo, sets PYTHONPATH)
├── revive_termux/
│   ├── __main__.py            # usb / usb-list / doctor + passthrough to revive.cli
│   ├── usbdevfs.py            # stdlib-only USB: usbfs ioctls on a termux-usb fd
│   └── patch.py               # points Revive's USB layer at termux-usb (no core file edited)
└── test_termux_variant.py     # python3 termux-variant/test_termux_variant.py
```

The main `revive/` package isn't modified or copied. The variant reuses it and only swaps the
USB layer at runtime, so fixes to the main tool apply here automatically.
