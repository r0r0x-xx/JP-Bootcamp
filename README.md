# JP-Bootcamp: Satellite Red Team / Blue Team

The complete bench for the two-day workshop: a vulnerable spacecraft you own, a
ground console, a detector between them, and ten attacks to run across it.

```
   FlatSat  --USB-->  [ Space IDS ]  -->  PWNSAT-C3
   the target          the detector        the ground console
       ^                                         |
       |                                         |
       +------------------ you ------------------+
                        the attacks
```

Everything happens over a USB cable. **Nothing transmits on any radio band at
any point**, the course firmware holds both radio transceivers in reset, which
is a control you can verify from the boot banner, not a promise.

---

## What is in here

| Directory | What it is | Needs |
|---|---|---|
| [`firmware/`](firmware/) | The FlatSat firmware, source and a ready-to-flash `.uf2` | nothing to run it |
| [`ids/`](ids/) | **Space IDS**, the sensor that sits between board and console | Python 3 + `pyserial` |
| [`c3/`](c3/) | **PWNSAT-C3**, the ground console, a web dashboard | Python 3 + its `requirements.txt` |
| [`attacks/`](attacks/) | The ten attacks, all over USB | Python 3 + `pyserial`, `pycryptodomex` |
| [`challenges/`](challenges/) | The RF captures labs 1.5 and 1.6 work on, `rx.py` to demodulate them, and the LoRa blocks built for each Ubuntu | `inspectrum` and GNU Radio, both from `apt` |

---

## Start here

Read these in order. They assume you have never seen any of this before.

| | Document | What it gets you |
|---|---|---|
| 1 | [**Ubuntu setup**](docs/01-ubuntu-setup.md) | From a fresh Ubuntu to every dependency installed and the USB port openable. Also: installing with no internet, updating, uninstalling, and working without a board |
| 2 | [**Flashing the firmware**](docs/02-firmware.md) | The course build on the board, verified |
| 3 | [**Running the bench**](docs/03-running-the-bench.md) | Start, stop, restart, status, logs, by hand and as a service |
| 4 | [**Running the attacks**](docs/04-attacks.md) | All ten, what each one does, and how to reset between them |
| 5 | [**Troubleshooting**](docs/05-troubleshooting.md) | Every failure we have actually hit, and what it means |
| 6 | [**How it fits together**](docs/06-how-it-fits-together.md) | The protocol, the ports, and why the sensor is a process |

**In a hurry?** [`docs/01-ubuntu-setup.md`](docs/01-ubuntu-setup.md) has a
single install script. It takes about three minutes on a clean machine.

---

## The shortest possible path

On a fresh Ubuntu 26.04, 24.04 or 22.04, with a FlatSat plugged in:

```sh
git clone https://github.com/r0r0x-xx/JP-Bootcamp.git
cd JP-Bootcamp
./install.sh                         # one venv, the udev rule, the dialout group
# log out and back in, so the dialout group applies

# terminal 1, the sensor. It takes the serial port for itself.
cd ids && ./run.sh run

# terminal 2, the ground console, pointed at the sensor
cd c3 && source ../.venv/bin/activate
PWNSAT_C3_IDS_ENDPOINT=127.0.0.1:5010 uvicorn backend.app:app --port 8000

# terminal 3, your first attack, sent through the sensor
cd attacks && source ../.venv/bin/activate
FLATSAT_HOST=1 python3 00_recon_apid_enum/00_recon_apid_enum_usb.py
```

Then open:

| | |
|---|---|
| **http://127.0.0.1:5011** | the sensor's console, what the detector saw |
| **http://127.0.0.1:8000** | the ground console, log in as `operator` / `pwnsat` |

---

## What has actually been tested

Being specific about this matters more than claiming coverage.

The Ubuntu column is **26.04 on arm64**, in a VMware Fusion virtual machine on
Apple Silicon, 8 November 2026.

| | macOS | Ubuntu |
|---|---|---|
| `install.sh` on a clean machine | n/a | ✅ |
| Flashing, and the radio-off banner read back | ✅ board `fsat-20004E46` | ✅ |
| Radio absent from the binary, checked against the `.uf2` | ✅ 0 SX126x symbols, 0 transmit | n/a |
| Space IDS test suite | ✅ | ✅ 18/18 |
| LoRa receiver packages, installed and decoding | n/a | ✅ **all six**, see below |
| Labs 1.5 and 1.6, capture to frames | ✅ | ✅ 661 octets, 28 packets |
| **The three in line**: board, sensor, console | ✅ | ✅ |
| The ten attacks | ✅ 7 Nov, board `fsat-200052E9`, 116 alerts, 11 rules | ✅ |
| PWNSAT-C3 | ✅ | ✅ |

**Not yet tested on amd64.** Every Ubuntu result above is arm64. The packages
exist for both and were each checked in a container of their own
architecture, but the bench as a whole has only been run on one.

**What the Ubuntu run cost, and what it found.** Three labs looked broken and
were not: the board refuses in plain words inside an `ERROR` frame, and the
scripts were throwing that message away. Lab 2.2 was polling the wrong packet
for its own result. Lab 2.4 cannot run from the default state at all, because
the gate checks range before identity. Those three are fixed; the finding
underneath them is that **a refusal nobody prints reads exactly like a broken
lab.**

**The LoRa packages.** Each of the six in
[`challenges/packages/`](challenges/packages/) was installed into a clean
container of its own Ubuntu release and architecture, and made to decode
`challenges/02_downlink_916MHz_decode.cf32` to the **28 CCSDS packets** known
to be in that file. A package that compiles is not a package that decodes, so
the check is the decode.

---

## Ground rules for the workshop

These are not style preferences. They are the terms the course is delivered
under.

- **Nothing radiates**, on any band, at any power, at any moment. Everything is
  over USB. RF exercises run on recorded captures.
- **No third-party system is touched.** Every target is hardware you own.
- **Nothing ITAR/EAR controlled.** Open sources only: SPARTA, CCSDS,
  NIST IR 8401.
- **Every attack comes with its defence, in the same block.** The sensor's
  console shows the fix beside the alert for exactly this reason.

---

## Licence and provenance

`c3/` is MIT (see [`c3/LICENSE`](c3/LICENSE)). The firmware and the course
material are Starsec's and are **private**. This repository is private and is
not to be redistributed.

SPARTA technique identifiers are The Aerospace Corporation's. Mapping an
observation to one of them is this project's analysis, not an official
classification, and the sensor's console says so on every alert.
