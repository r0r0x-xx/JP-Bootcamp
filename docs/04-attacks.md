# 4. Running the attacks

Ten attacks, all over USB, all against a board you own.

**Read this page before running anything.** Two of the ten change the state of
the board in ways that make the next lab fail for reasons that look like bugs.

---

## The one thing to get right

```sh
cd attacks
source ../.venv/bin/activate
FLATSAT_HOST=1 python3 00_recon_apid_enum/00_recon_apid_enum_usb.py
```

**`FLATSAT_HOST=1` routes the attack through the sensor.** Without it the
script opens the board directly, the sensor never sees the traffic, and nothing
fires. If your alert list stays empty while an attack clearly worked, this is
why, nine times out of ten.

---

## The ten

| # | Attack | Lab | What it breaks |
|---|---|---|---|
| `00` | Recon and APID enumeration | `1.8` | There is no command dictionary, so you build one |
| `01` | Fuzzing and the underflow crash | `2.1` | `msg_len = payload_total - 2`, unsigned |
| `02` | Command injection | `2.2` | `SET_THRUSTER` never asks who you are |
| `03` | Position spoofing | `2.3` | A position nothing authenticates, and a permission that trusts it |
| `04` | Ground-station spoofing | `2.4` | The challenge-response is an XOR with a constant in the client |
| `05` | Replay | `1.10` | The cryptography proves origin, not freshness |
| `06` | RESETC | `2.5` | Detectable, and too late |
| `07` | Secure-link downgrade | `2.6` | A one-octet telecommand turns AES off |
| `08` | Flash dump from the ground | `2.7` | The unlock tag ships inside the ground software |
| `09` | Gate exemption chain | `2.8` | `DEBUG_CONFIG` is exempt and opens the way |

Each lives in its own directory with a single `*_usb.py` script.

---

## 🔴 Two that need care

**`01` is a fuzzer.** It is supposed to crash the board, that is the lesson.
It can leave it unresponsive, and sometimes it leaves it unresponsive in a way
that needs a power cycle rather than a reset. Run it on its own, and expect to
unplug the cable afterwards.

**`06` reboots the board.** It asks before it does:

```
Continue? [y/N]
```

If you run it from a script with no terminal attached it will sit there
forever waiting for an answer that cannot arrive. Pass `--yes` when you mean
it.

**Do not run all ten in sequence.** They were built to be run one at a time
with a reset between, and a loop over the directory will wedge the board part
way through.

---

## Resetting between labs

Several labs leave state behind **on purpose**: `03` leaves the spacecraft at a
spoofed position, `04` leaves the gate closed, `07` leaves the secure link off.
A lab that starts on the previous lab's leftovers fails in ways that look like
bugs in the lab.

```sh
cd attacks
FLATSAT_HOST=1 python3 lib/reset_bench.py
```

That puts the board back to a known state: position in Tokyo, gate open,
secure link on, **USB debug off**. It also recovers a board that has locked
itself out, by performing the lab `04` handshake to reopen a session.

### 🔴 Why USB debug matters, and why recon turns it on

**The `00` sweep enables USB debug as a side effect**, and the consequences
land two labs later.

The sweep probes every identifier in a range, and `DEBUG_CONFIG` (`0x10`) is
one of them. Probing it flips `mission_ctx.usbDebugEnabled` on. While that
flag is set, `worker.cpp:707` makes the board **bypass the secure link
entirely**: every encrypted command after the sweep is read as cleartext, so
the payload the handler sees is ciphertext.

What you see is not an error about encryption. You see:

```
[!] FLASH WINDOW LOCKED -- the window id or the unlock tag is wrong.
```

The window id and the unlock tag are fine. The board never decrypted them.
The same cause makes position telemetry read as impossible values, which looks
like a broken sensor.

**`lib/reset_bench.py` clears it**, so running the reset between labs is
enough. If you skip the reset after `00`, expect `08` to fail in exactly that
way.

One detail worth knowing if you ever reorder the reset: it clears the flag
**last**, after `GS_MODE`. The `gate-exemption-chain` rule fires on
`DEBUG_CONFIG` followed by `GS_MODE` inside a window, which is lab `2.8`'s
finding. Clearing it first would raise a critical alert on every reset and
teach the room to ignore one.

If it reports the board is locked out and cannot get in: **unplug the USB
cable, count to three, plug it back in.** The board comes back in about eight
seconds. That recovers every state we have managed to get it into.

---

## Useful flags

Every script takes `--port` to skip auto-detection. Beyond that:

| Script | Flag | What it does |
|---|---|---|
| `00` | `--start`, `--end` | The APID range to sweep |
| `00` | `--quiet` | Just the findings, no frame-by-frame |
| `01` | `--sweep` | Walk a range of lengths instead of one |
| `02` | `--restore` | Put the thruster back when done |
| `02` | `--power`, `--thruster-id` | What to set |
| `03` | `--lat`, `--lon`, `--alt` | Where to claim to be |
| `03` | `--ramp` | Move there gradually instead of jumping |
| `04` | `--inside-window` | Use the legitimate timing window |
| `05` | `--times` | How many times to replay |
| `06` | `--yes` | Skip the confirmation. **Read the warning above** |
| `07` | `--restore` | Turn the secure link back on |
| `08` | `--start`, `--end`, `--chunk` | The flash range and read size |
| `08` | `--out` | Write the dump to a file |
| `09` | `--restore` | Undo the thruster change |

`--cleartext` appears on most of them. It sends the command unencrypted, which
is what you want **after** lab 2.8 has turned the secure link off, and what
you do not want before it.

---

## Watching it land

Keep two things open while you work:

**The sensor's console, http://127.0.0.1:5011.** Every alert opens: the frame
that raised it as a hexdump, what the board said about that frame, why it
matters, and how the fault is fixed with the firmware file and line. Its second
tab lists all fifteen rules, and the two attacks on the syllabus the sensor
cannot catch. That is the half that makes the rest worth trusting.

**The ground console, http://127.0.0.1:8000.** This is the operator's view: the
spacecraft as the ground believes it to be. The interesting moments are the
ones where it disagrees with what you just did.

---

## What should happen

Run on board `fsat-200052E9` on 7 November 2026, with the sensor in line and
C3 on top:

- **116 alerts** across the ten attacks
- **eleven of the fifteen rules** represented
- **zero alerts on nominal traffic**

That last number is the one to care about. If the bench raises an alert while
nothing is attacking it, something is wrong with the bench, not with the
spacecraft.

---

## If nothing fires

In order of how often it is the cause:

1. **`FLATSAT_HOST=1` missing.** The attack went straight to the board.
2. **The sensor is not running**, so there is nothing in the middle.
3. **C3 took the serial port first.** Stop C3, start the sensor, start C3.
4. **The attack did not actually land.** Read its own output; most of them say
   plainly whether the board accepted the command.

More in [troubleshooting](05-troubleshooting.md).

---

Next: [**5. Troubleshooting**](05-troubleshooting.md)
