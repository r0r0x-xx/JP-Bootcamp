#!/usr/bin/env bash
#
# install.sh -- from a fresh Ubuntu to a working bench.
#
# Everything this does is also written out by hand in docs/01-ubuntu-setup.md.
# Read that if you would rather not run a script you have not read, which is a
# reasonable position on a security course.
#
# Safe to run more than once.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m  %s\n' "$*"; }
warn() { printf '    \033[33m!!\033[0m  %s\n' "$*"; }

# ---------------------------------------------------------------- 0. sanity
if [ ! -f /etc/os-release ]; then
    echo "This installer is for Ubuntu. On macOS, see docs/01-ubuntu-setup.md." >&2
    exit 1
fi
. /etc/os-release
say "Ubuntu check"
ok "${PRETTY_NAME:-unknown}"
case "${VERSION_ID:-}" in
    26.04|24.04|22.04) ;;
    *) warn "written for 26.04, 24.04 and 22.04; yours is ${VERSION_ID:-unknown}. Carrying on." ;;
esac
ok "python3 $(python3 -c 'import sys;print(".".join(map(str,sys.version_info[:2])))' 2>/dev/null || echo '?')"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' || {
    echo "    this needs Python 3.10 or newer; 3.9 cannot parse several files" >&2
    exit 1
}

# ------------------------------------------------------------ 1. system packages
say "System packages"
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-venv python3-pip git usbutils
ok "python3 $(python3 --version 2>&1 | cut -d' ' -f2), git, usbutils"

# ------------------------------------------------------------ 2. python packages
say "Python environment"
if [ ! -d .venv ]; then
    python3 -m venv .venv
    ok "created .venv"
else
    ok ".venv already there"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
# Confirm the activation took. Installing into the system Python because a
# venv silently failed is the kind of thing nobody notices until a lab breaks.
[ "${VIRTUAL_ENV:-}" = "$HERE/.venv" ] || { echo "the venv did not activate" >&2; exit 1; }
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
ok "$(pip list 2>/dev/null | wc -l) packages installed"

# --------------------------------------------------- 3. permission to open the port
say "Serial port permissions"
# $USER is not set under `sudo -i` or a bare `su`, so ask the system instead.
WHO="$(id -un)"
if [ "$WHO" = root ]; then
    warn "running as root. The bench runs as an ordinary user; re-run this as"
    warn "the account that will use the board, or the dialout step is useless."
fi
if id -nG "$WHO" | tr ' ' '\n' | grep -qx dialout; then
    ok "$WHO is already in the dialout group"
else
    sudo usermod -aG dialout "$WHO"
    warn "added $WHO to dialout. LOG OUT AND BACK IN before the port will open."
fi

# A udev rule is not strictly required once you are in dialout, but it gives the
# board a stable name and makes the failure mode obvious when it is missing.
RULE=/etc/udev/rules.d/99-flatsat.rules
if [ -f "$RULE" ]; then
    ok "udev rule already installed"
else
    sudo tee "$RULE" >/dev/null <<'RULEEOF'
# FlatSat (RP2040, TinyUSB CDC). Two interfaces enumerate with the same serial
# number; which one carries frames is not stable across replugs, so the tools
# probe rather than trusting the order. This rule only grants access.
SUBSYSTEM=="tty", ATTRS{idVendor}=="239a", ATTRS{idProduct}=="cafe", MODE="0660", GROUP="dialout"
# RP2040 in bootloader mode (BOOTSEL held), for flashing.
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0003", MODE="0660", GROUP="dialout"
RULEEOF
    sudo udevadm control --reload-rules
    sudo udevadm trigger
    ok "installed $RULE"
fi

# ------------------------------------------------------------ 4. does it work
say "Checking the install"
python3 -c "import serial, fastapi, uvicorn; print('    imports ok')"
run_suite() {   # report, never abort: the install is already done by here
    local where="$1" what="$2"
    if ( cd "$where" && python3 -m pytest "$what" -q >/tmp/jp-suite.$$ 2>&1 ); then
        ok "$where  $(tail -1 /tmp/jp-suite.$$)"
    else
        warn "$where  $(tail -1 /tmp/jp-suite.$$)"
        warn "  full output: /tmp/jp-suite.$$"
        return 0
    fi
    rm -f /tmp/jp-suite.$$
}
run_suite ids tests/
run_suite c3  backend/tests

say "Is a board attached?"
if lsusb 2>/dev/null | grep -qi "239a:cafe"; then
    ok "a FlatSat is on the bus"
    ( cd ids && ./run.sh boards 2>&1 | head -6 ) || warn "could not list it; see docs/05-troubleshooting.md"
else
    warn "no FlatSat on USB. Plug one in; nothing above needed it."
fi

say "Done"
cat <<'DONEEOF'
    If this is the first run, LOG OUT AND BACK IN now. The dialout group does
    not apply to a session that was already open, and the serial port will
    refuse to open until you do.

    Then:   docs/02-firmware.md     flash the board
            docs/03-running-the-bench.md    start the sensor and the console
DONEEOF
