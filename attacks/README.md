# The attacks, ten of them, all over USB

Self-contained. Nothing here imports anything outside this directory, so the
kit works on a laptop that has never seen the rest of the project.

```sh
python3 00_recon_apid_enum/00_recon_apid_enum_usb.py
python3 02_command_injection/02_command_injection_usb.py --restore
python3 06_resetc/06_resetc_usb.py --yes
```

| # | Attack | Lab | What it breaks |
|---|---|---|---|
| `00` | Recon and APID enumeration | `1.8` | There is no command dictionary, so you build one |
| `01` | Fuzzing and the underflow crash | `2.1` | `msg_len = payload_total - 2`, unsigned |
| `02` | Command injection | `2.2` | `SET_THRUSTER` never asks who you are and never acknowledges |
| `03` | Position spoofing | `2.3` | A position nothing authenticates, and a permission that depends on it |
| `04` | Ground-station spoofing | `2.4` | The challenge-response is an XOR with a constant shipped in the client |
| `05` | Replay | `1.10` | The cryptography proves origin, not freshness |
| `06` | RESETC | `2.5` | Detectable, and too late |
| `07` | Secure-link downgrade | `2.6` | A one-octet telecommand turns AES off |
| `08` | Flash dump from the ground | `2.7` | The unlock tag ships inside the ground software |
| `09` | Gate exemption chain | `2.8` | `DEBUG_CONFIG` is exempt and opens the way |

**Numbered 00–09 with no gaps.** This does not match the public repository,
where the same attacks run 00–07 and `01` is passive eavesdropping. Listening
has no cable variant, because listening to a cable you own is a different exercise,
and in this course `07` and `08` carry its lesson.

## Two things that had to be fixed in the firmware

**`03` did not exist over USB.** The real position attack is over the air,
against the u-blox receiver, and has no cable equivalent because it attacks a
different piece of hardware. The repository's scripts pointed at
`GPS_OVERRIDE` (APID `0x14`) in a debug build, `firmware/gps-debug-demo/`,
**which exists nowhere on disk**. Without it, lab `2.3` could not run.

`GPS_OVERRIDE` is now implemented in the **course build**, behind its own flag
(`FLATSAT_GPS_OVERRIDE`), and stays out of the public firmware. The lesson does
not change and was never about radio: navigation and authorisation get wired
together because it is convenient, and then a wrong position becomes a
permission.

**`06` is the reversible stand-in for lab `2.5`.** RESETC reboots, and a reboot
undoes itself. No script here sends the irreversible command, and what the lab
measures, the gap between being detectable and being too late, a reboot shows
faithfully.

## `lib/flatsat.py`

Its own transport: port probing with a PING, the `0xAA 0x55 <len> <SPP>`
framing, the firmware's AES-128-ECB wrapper and the APIDs from `mission.h`.

**It shares no codec with the IDS, deliberately.** A detector that parses with
the attacker's parser cannot catch a frame that parser gets wrong.

One detail that bites anyone rewriting it: `FLASH_READ` carries **two
endiannesses in the same six octets**, the offset little endian, the unlock
tag big endian. And a single-octet cleartext command needs a companion octet,
because the firmware only copies the payload when the length field is above
zero.

## State

All ten ran against board `fsat-200052E9` on 7 November 2026, with the sensor
in line and the ground console on top: 116 alerts, eleven rules represented,
zero on nominal traffic.

**Do not run all ten back to back.** `01` is a fuzzer and can leave the board
unresponsive; `06` reboots it. Run them one at a time, and use
`lib/reset_bench.py` between labs.

**`00` turns USB debug on.** The sweep probes `DEBUG_CONFIG` like any other
identifier, which sets `mission_ctx.usbDebugEnabled`. While that is set the
board bypasses the secure link (`worker.cpp:707`) and reads encrypted payloads
as cleartext, so `08` reports `FLASH WINDOW LOCKED` with a window id that is
perfectly correct, and position telemetry reads as impossible values.
`reset_bench.py` clears it, last, after `GS_MODE` so the reset does not itself
trip `gate-exemption-chain`.

## Any FlatSat, and Ubuntu

No script carries a device path any more. The port is found by the board's
**USB identity** (`239a:cafe`), not by the name of the node, so the same call
works against `/dev/ttyACM*` on Ubuntu and `/dev/cu.usbmodem*` on macOS without
either name appearing in the code.

```sh
python3 00_recon_apid_enum/00_recon_apid_enum_usb.py      # takes whichever board is there

export FLATSAT_SERIAL=fsat-200052E2                       # with several connected
export FLATSAT_PORT=/dev/ttyACM1                          # or by hand, if you must
```

Both variables are read by `lib/flatsat.py`, so they work for all ten attacks
without any of them growing a new flag.

**The board exposes two CDC interfaces with the same serial number**, and which
of the two carries frames is not stable across replugs. Discovery probes and
keeps the one that answers, rather than trusting enumeration order.
`ids/run.sh boards` lists them with a column saying which is the console and
which carries frames.

### Sending attacks through the sensor

```sh
FLATSAT_HOST=1 python3 00_recon_apid_enum/00_recon_apid_enum_usb.py
```

`FLATSAT_HOST=1` sends the traffic through the sensor instead of straight at
the board, so everything you do is classified on the way past. That is the
mode every lab uses. Without it the sensor never sees the attack, and an empty
alert list looks like a rule that does not work.

### On Ubuntu, before the first run

```sh
sudo usermod -aG dialout "$USER"     # then log out and back in
pip3 install pyserial pycryptodomex
```

Without the `dialout` group the port exists but will not open. The error says
so in those words, rather than reporting "no board found", which is what it
used to say and sent people off to change the cable.
