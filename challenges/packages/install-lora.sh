#!/usr/bin/env bash
# Install the LoRa receiver blocks lab 1.6 needs.
#
# gr-lora_sdr is not in the Ubuntu archive, so the course ships it built. It
# links against GNU Radio's runtime library, and every Ubuntu release carries
# a different one, so there is one package per release and architecture and
# this picks yours. Nothing is compiled on your machine.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Most people run this as themselves and need sudo. Some run it as root in a
# container or a freshly built virtual machine, where sudo is often not even
# installed, and calling it there fails for a reason that has nothing to do
# with the package.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

REL="$(. /etc/os-release && echo "${VERSION_ID:-unknown}")"
ARCH="$(dpkg --print-architecture)"
DEB="$(ls "$HERE"/gr-lora-sdr_*ubuntu"${REL}"_"${ARCH}".deb 2>/dev/null | head -1 || true)"

if [ -z "$DEB" ]; then
  echo "No package here for Ubuntu ${REL} on ${ARCH}." >&2
  echo "What is available:" >&2
  ls -1 "$HERE"/*.deb 2>/dev/null | sed 's|.*/|  |' >&2
  echo >&2
  echo "Build it from source instead, which takes a few minutes:" >&2
  echo "  git clone https://github.com/tapparelj/gr-lora_sdr.git" >&2
  echo "  cd gr-lora_sdr && mkdir build && cd build" >&2
  echo "  cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DGR_PYTHON_DIR=/usr/lib/python3/dist-packages" >&2
  echo "  make -j\$(nproc) && sudo make install && sudo ldconfig" >&2
  exit 1
fi

echo "Ubuntu ${REL} on ${ARCH}"
echo "Installing $(basename "$DEB")"

# GNU Radio itself comes from the archive. apt pulls it in as a dependency of
# the package, so this works on a machine that has never seen GNU Radio.
$SUDO apt-get update
$SUDO apt-get install -y "$DEB"
$SUDO ldconfig

echo
echo "Checking it loads:"
python3 - <<'PY'
from gnuradio import lora_sdr
need = ("frame_sync", "fft_demod", "gray_mapping", "deinterleaver",
        "hamming_dec", "header_decoder", "dewhitening", "crc_verif")
missing = [n for n in need if not hasattr(lora_sdr, n)]
if missing:
    raise SystemExit(f"  installed, but these blocks are missing: {missing}")
print(f"  ok, the receive chain is there ({len(need)} blocks checked)")
PY
