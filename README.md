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
