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
| [`challenges/`](challenges/) | The RF captures labs 1.5 and 1.6 work on, and the LoRa receiver built for each Ubuntu | `inspectrum` and GNU Radio, both from `apt` |

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
./install.sh                         # dependencies, venvs, udev rule, dialout group
# log out and back in, so the dialout group applies

# terminal 1, the sensor. It takes the serial port for itself.
cd ids && ./run.sh run

# terminal 2, the ground console, pointed at the sensor
cd c3 && source .venv/bin/activate
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

| | macOS | Ubuntu |
|---|---|---|
| Firmware, flashed and verified on hardware | ✅ 8 Nov 2026, board `fsat-20004E46` | not yet |
| Radio absent from the binary, checked against the `.uf2` | ✅ 0 SX126x symbols, 0 transmit | n/a |
| Space IDS test suite | ✅ 15/15 | not yet |
| LoRa receiver packages, installed and decoding | n/a | ✅ 8 Nov 2026, **all six**, see below |
| Space IDS in line, rules firing | ✅ 6 rules on a short pass, 0 on clean traffic | not yet |
| Lab 2.9, key off the board | ✅ 165 octets ending `PWNsatLabKey1234` | not yet |
| All ten attacks in one pass | ✅ 7 Nov, board `fsat-200052E9`, 116 alerts, 11 rules | not yet |
| PWNSAT-C3 | ✅ | **never run on Ubuntu** |

The ten-attack pass was run on the previous board and the previous firmware.
The firmware changed on 8 November, when the radio driver was removed outright
rather than left uncalled, so that row is the one still owed a repeat.

**The LoRa packages are the exception, and the only one.** Each of the six in
[`challenges/packages/`](challenges/packages/) was installed into a clean
container of its own Ubuntu release and architecture, and made to decode
`challenges/02_downlink_916MHz_decode.cf32` to the **28 CCSDS packets** known
to be in that file. A package that compiles is not a package that decodes, so
the check is the decode.

**Everything else in this repository exists to be tested on Ubuntu and has
not been.** Where a step is a reasoned translation from the macOS procedure
rather than something we watched work, the document says so in those words.

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
