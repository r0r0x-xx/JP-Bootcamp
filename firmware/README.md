# Course firmware: FlatSat with the radio off

A separate build of **v1.0.5**. Same source, one compile flag. The public
FlatSat firmware does not change: it is still a radio platform. This build
cannot transmit on any band.

## 🔴 The course binary

```
binaries/flatsat-course-noradio-v1.0.5.uf2
SHA-256  650c363ab65afec89ca06da2936a14e8423b8bf8f15548d0428af8597a75ef0f
size     320,000 bytes
```

**It is the only image here, and that is deliberate.** A transmitting build
sitting next to the one people flash is how the wrong one gets flashed.
`verify.sh` builds the stock firmware to compare against and leaves it in
`.pio/build/`.

### There is no radio code in it

Not disabled. Absent. `ruplink.cpp` and `rdownlink.cpp` are the only files
that include RadioLib or construct an `SX1262`, and the course build excludes
both, so the linker has no transmit code to keep.

Checked against the `.uf2` payload rather than an intermediate object:

| Looked for | Result |
|---|---|
| `SX126` anywhere in the image | **absent** |
| `RadioLib` anywhere in the image | **absent** |
| `SX126x::transmit`, `startTransmit` | **0 symbols** |
| `held in reset, course build` | present |

### Verified on hardware

Board `fsat-20004E46`, 8 November 2026, after flashing this image:

| Check | Result |
|---|---|
| Boot banner on the text console | `[INFO] Radio: disabled (held in reset, course build)` |
| Enumeration | two CDC interfaces, one serial number |
| Board event channel | 42 events parsed, so the stubbed RSSI/SNR/CRC accessors did not break it |
| Clean traffic through the sensor | zero alerts |
| Lab 1.8, identifier sweep | 10 of 20 identifiers mapped |
| Lab 2.7, flash read | 165 octets, ending `PWNsatLabKey1234` |
| Lab 2.2, command injection | runs, restores |
| Rules firing | six of fifteen on a short pass |

The ten-attack pass in one sitting was last run against board
`fsat-200052E9` and the previous firmware. It is owed a repeat on this image.

## Why it exists

Training runs on hardware that students control, in rooms the instructor does
not own, often under a licence regime nobody present is qualified to read. The
simplest answer is a build that **cannot** transmit, rather than one that is
asked not to.

The difference matters because it is checkable. "We will not transmit" is a
statement about intent. "The radio functions are not in this binary and both
transceivers are held in reset" is a property anyone can verify without
trusting the people who built it, and the rest of this file is how.

## What it does

Three layers, because one is not enough.

**1. It compiles out the seven call sites.** These were all of them:

| Where | What it did |
|---|---|
| `firmware.ino` setup | `uplinkRadioConfigure()`, brings radio0 up and leaves it listening |
| `firmware.ino` setup | `downlinkRadioConfigure()`, brings radio1 up |
| `firmware.ino` setup | `uplinkRadioRegisterCb()`, where RF telecommands came in |
| `firmware.ino` loop | `uplinkRadioCheckPacketReceived()` |
| `firmware.ino` loop | `downlinkRadioCheckTransmition()` |
| `worker.cpp` | `transmitPacketRadioUSB/Block()`, every TM went out over USB **and** radio |
| `worker.cpp` | `downlinkRadioTransmitBroadcast()`, the relay in attack 02 |

**2. It holds both SX1262 in reset.** `radioHoldInReset()` runs before anything
else in `setup()`: RESET low on both (GPIO 27 and 11), antenna switches low
(GPIO 28 and 29) and the chip selects high. The modules never come out of reset
while the board has power, so **they cannot modulate a carrier whatever the
firmware above them does**.

**3. It says so at boot.** `[INFO] Radio: disabled (held in reset, course
build)` on the text console, so it can be read from a terminal instead of taken
on trust.

## What does NOT change

- **Every vulnerability is still there.** Attacks 00–09 are the lesson and are
  untouched.
- **The relay in attack 02 still accepts the command**: unauthenticated, no
  length check, and the IDS still sees it. The only thing that does not happen
  is the transmission, and the board says so with `BROADCAST RADIO DISABLED`.
- **No telemetry is lost.** `transmitPacketRadioUSB()` already sent over USB
  *and* radio; the USB path was complete and independent before this. The radio
  half was removed.
- **The SPP format is untouched.** Putting the radio state into `SEND_FW` was
  considered and dropped: every lab compares captures against v1.0.5, and
  moving a telemetry format to carry a build flag is a bad trade. That is why
  the state goes out on the text console.

## Verification

`verify.sh` builds four variants and reads each binary back:

| Build | ELF | SX126x | transmit() | hold-reset | banner |
|---|---|---|---|---|---|
| stock, radio enabled | 1,132,376 | 107 | 3 | absent | no |
| no flag passed at all | 1,121,476 | 87 | 3 | present | yes |
| driver linked, held in reset | 1,121,740 | 87 | 3 | present | yes |
| **COURSE BUILD, no driver** | **1,094,984** | **0** | **0** | present | yes |

Two rows carry the argument.

**The second** is what a careless rebuild produces: no radio flag at all, and
the board still comes out with both transceivers held in reset. Forgetting a
flag fails safe.

**The fourth** is what ships. Zero symbols from the radio driver and zero
entry points that could key a transceiver, because the two translation units
that include RadioLib are not compiled in. That is a stronger statement than
code that is present and uncalled, which is what the third row describes and
what this firmware used to be.

```sh
./verify.sh          # builds every variant and says what each binary carries
```

## Files

| File | What it is |
|---|---|
| `Firmware/` | The source with the change applied |
| `binaries/flatsat-course-noradio-v1.0.5.uf2` | **The course binary, and the only one here.** This is the one you flash |
| `course-no-radio.patch` | The diff against `FlatSat-Bulk2/firmware-v1.0.5/Firmware/` |
| `verify.sh` | Compiles both and says what each one carries |

To take it back to the upstream repository:

```sh
cd FlatSat-Bulk2/firmware-v1.0.5/Firmware
patch -p1 < .../course-no-radio.patch
```

## Building it yourself

See [`../docs/02-firmware.md`](../docs/02-firmware.md). You do not need to
build anything to run the course, the `.uf2` in `binaries/` is ready to flash.
