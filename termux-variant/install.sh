#!/data/data/com.termux/files/usr/bin/bash
# Revive - Termux edition installer.
# Installs ONLY Termux packages (prebuilt binaries). No pip, no compiler, no Rust, no clang.
set -e
cd "$(dirname "$0")"
VARIANT_DIR=$(pwd)
PREFIX=${PREFIX:-/data/data/com.termux/files/usr}

echo "==> Revive Termux edition installer"
if [ ! -d "$PREFIX" ] || ! command -v pkg >/dev/null 2>&1; then
  echo "This does not look like Termux (no 'pkg'). It will still run with any Python 3.8+:"
  echo "    $VARIANT_DIR/bin/revive-termux --help"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "==> Installing python (prebuilt Termux package)"
  pkg install -y python
fi

if [ "${1:-}" != "--no-usb" ] && ! command -v termux-usb >/dev/null 2>&1; then
  echo "==> Installing termux-api (for USB-OTG phone access; optional)"
  pkg install -y termux-api || echo "   (skipped - file tools work without it)"
fi

chmod +x "$VARIANT_DIR/bin/revive-termux"
ln -sf "$VARIANT_DIR/bin/revive-termux" "$PREFIX/bin/revive-termux"
ln -sf "$VARIANT_DIR/bin/revive-termux" "$PREFIX/bin/revive"
echo "==> Linked: revive-termux and revive -> $PREFIX/bin"

if [ ! -d "$HOME/storage" ]; then
  echo "==> Tip: run 'termux-setup-storage' to reach firmware in your Download folder"
fi
echo
revive-termux doctor || true
echo
echo "Try:  revive demo && revive serve --demo --open"
