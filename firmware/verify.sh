#!/usr/bin/env bash
# Builds every variant and reports, from the binaries themselves, what each one
# can do. Run it instead of taking anyone's word.
#
# Only the course binary is written to binaries/. The stock build is inspected
# and left in .pio/build/, because a transmitting image sitting next to the one
# people flash is how the wrong one gets flashed.
set -euo pipefail
cd "$(dirname "$0")/Firmware"
PIO="${PIO:-$HOME/.platformio/penv/bin/pio}"
OUT="../binaries"; mkdir -p "$OUT"

probe() {                      # $1 = env, $2 = label, $3 = uf2 name or "-"
  "$PIO" run -e "$1" >/dev/null 2>&1 || { echo "    build FAILED: $1"; exit 1; }
  local elf=".pio/build/$1/firmware.elf"
  local drv tx rst marker size
  # The driver itself, not only this firmware's wrappers around it. A build can
  # have every wrapper compiled out and still carry SX126x::transmit.
  drv=$(nm -C "$elf" | grep -c 'SX126' || true)
  tx=$(nm -C "$elf" | grep -c 'SX126x::transmit\|SX126x::startTransmit' || true)
  rst=$(nm -C "$elf" | grep -ci 'radioHoldInReset' || true)
  marker=$(strings "$elf" | grep -cm1 'held in reset, course build' || true)
  # stat takes different flags on the two platforms the bench runs on, and the
  # BSD spelling fails silently into an empty column on Ubuntu.
  size=$(stat -f%z "$elf" 2>/dev/null || stat -c%s "$elf")
  printf "%-30s %-10s %-9s %-11s %-10s %s\n" "$2" "$size" "$drv" "$tx" \
         "$([ "$rst" -eq 0 ] && echo absent || echo present)" \
         "$([ "$marker" -eq 0 ] && echo no || echo yes)"
  [ "$3" = "-" ] || cp ".pio/build/$1/firmware.uf2" "$OUT/$3"
}

printf "\n%-30s %-10s %-9s %-11s %-10s %s\n" \
       BUILD ELF-BYTES SX126x TRANSMIT HOLD-RESET BANNER
printf -- '%.0s-' {1..86}; echo
probe pico_tinyusb        "stock, radio enabled"          -
probe pico_tinyusb_noflag "no flag passed at all"         -
probe pico_tinyusb_norf   "driver linked, held in reset"  -
probe pico_tinyusb_nolib  "COURSE BUILD, no driver"       flatsat-course-noradio-v1.0.5.uf2
echo
cat <<'NOTE'
Read the table this way.

  SX126x     symbols from the radio driver present in the binary
  TRANSMIT   functions that can key a transceiver
  HOLD-RESET the call that drives both RESET lines low at boot
  BANNER     the line the board prints on its console

The course build is the only row with zero in both radio columns. There is no
code in it that can transmit, which is a stronger statement than code that is
present and uncalled.

The other three are inspected and left in .pio/build/. Only the course image is
written to binaries/.
NOTE
echo "course uf2 -> $(cd "$OUT" && pwd)/flatsat-course-noradio-v1.0.5.uf2"
