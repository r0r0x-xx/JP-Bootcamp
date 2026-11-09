# Changelog

## v1.0 — 9 November 2026

The bench for the two-day workshop, verified on both architectures the room
will bring.

### Verified

| | |
|---|---|
| Ubuntu arm64 | 26.04, VMware Fusion on Apple Silicon, 8 November 2026 |
| Ubuntu amd64 | a virtual machine on a Windows host, 9 November 2026 |

Install, flashing, the radio-off banner, the eighteen sensor tests, labs 1.5
and 1.6 from capture to frames, the three components in line, the ten attacks,
and PWNSAT-C3. The counts quoted in `README.md` come from the arm64 run; the
amd64 column records that the same steps completed.

The course firmware is frozen as
`firmware/binaries/flatsat-course-noradio-v1.0.5.uf2`, SHA-256 `650c363a…`.
Neither radio transceiver can transmit: the driver is not in the binary, which
`firmware/verify.sh` checks by counting symbols rather than by assertion.

### What this release fixed

**Three labs looked broken and were not.** The board refuses in plain words
inside an `ERROR` frame, APID `0x09`, ASCII, and the scripts were discarding
it. Lab 2.2 was polling the wrong packet for its own result. Lab 2.4 cannot
run from the default state, because the gate checks range before identity.
Attacks `01`, `02` and `04` now print what the board said.

**PWNSAT-C3 was packaged from the wrong source copy.** `ids_link.py` and five
changes to `app.py` were missing, which is the transport that connects the
console to the sensor. Without it C3 fell back to `radio` and the three
components could not run at once.

**Every rule now has a capture that proves it.** There were fifteen rules and
eleven captures, so `unauthenticated-tc`, `runt-frame` and
`sequence-regression` could not be demonstrated without a board.
`ids/tests/test_replay_coverage.py` fails if that gap reopens.

**The LoRa receiver ships built**, six `.deb` packages, one per Ubuntu release
and architecture, because the module links against the GNU Radio runtime and
each release carries a different soname. Each one was installed into a clean
container of its own release and made to decode the capture to the twenty-eight
packets known to be in it. Students compile nothing.

### Known and open

- `install.sh` accepts a broken `.venv`, because it only checks whether the
  directory exists. If `source .venv/bin/activate` reports a missing file,
  delete the directory and run it again.
- `install.sh` warns when run as root and then continues, which puts *root* in
  `dialout` and builds the environment as root. Run it as the account that
  will use the board.
- Seven of the ten attacks still discard the board's `ERROR` text. Doing it in
  `lib/flatsat.py` would fix all ten at once.
- The board has stuck twice with no root cause, once answering nothing and once
  heartbeating but ignoring commands. A power cycle recovers it every time.

### Not in this repository

The final exercise. Its answer key is in it, its two images are 60 MB each and
over GitHub's file limit, and its source tree vendors the whole of cFS and
CryptoLib. It travels on the USB stick.
