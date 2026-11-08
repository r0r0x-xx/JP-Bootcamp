# 2. Flashing the firmware

The board has to be running the **course build** before any lab works. That
build is the one with the radio held in reset, and it is what makes "nothing
radiates" a control you can check rather than a promise you have to believe.

You do **not** need to compile anything. The ready image is in the repository.

---

## The image you want

```
firmware/binaries/flatsat-course-noradio-v1.0.5.uf2
SHA-256  650c363ab65afec89ca06da2936a14e8423b8bf8f15548d0428af8597a75ef0f
size     320,000 bytes
```

**It is the only image in that directory, and that is deliberate.** A
transmitting build sitting next to the one people flash is how the wrong one
gets flashed. `verify.sh` still builds the stock firmware to compare against,
but leaves it in `.pio/build/` where it reads as a build artifact.

### There is no radio code in it

Not disabled. Not held back. Absent.

`ruplink.cpp` and `rdownlink.cpp` are the only files that include RadioLib or
construct an `SX1262`, and the course build excludes both, so the linker has
no transmit code to keep. Checked against the `.uf2` payload itself rather
than the intermediate object:

| Looked for | Result |
|---|---|
| `SX126` anywhere in the image | **absent** |
| `RadioLib` anywhere in the image | **absent** |
| `SX126x::transmit`, `startTransmit` | **0 symbols** |
| `held in reset, course build` | present |

Two further layers remain on top of that, because one control is not enough:
every call site that would drive a radio is compiled out, and
`radioHoldInReset()` drives both RESET lines low as the first statement of
`setup()`, so the parts stay in reset while the board has power.

## Flashing, step by step

The RP2040 presents itself as a USB mass-storage device when you hold its
BOOTSEL button. You copy a file onto it and it reboots into that firmware.
There is no flashing tool to install.

**1. Unplug the board.**

**2. Hold down the BOOTSEL button** and keep holding it.

**3. Plug the USB cable back in**, still holding BOOTSEL.

**4. Let go.** A drive called `RPI-RP2` appears.

On Ubuntu desktop it usually mounts automatically at
`/media/$USER/RPI-RP2`. If it does not:

```sh
lsblk -o NAME,LABEL,MOUNTPOINT | grep -i rpi
sudo mkdir -p /mnt/rpi
sudo mount /dev/sdX1 /mnt/rpi      # the device lsblk showed
```

**5. Copy the image onto it:**

```sh
cp firmware/binaries/flatsat-course-noradio-v1.0.5.uf2 /media/$USER/RPI-RP2/
sync
```

**6. The board reboots on its own.** The drive disappears, which is what
success looks like. It is not an error.

Give it about eight seconds, then confirm it came back:

```sh
lsusb | grep -i 239a
```

---

## Verify what you flashed

This is the part that matters, and it takes ten seconds.

Open the board's text console and read the boot banner. The console is one of
the two ports the board exposes. `./run.sh boards` from `ids/` tells you which
one is marked `console`.

```sh
cd ids && ./run.sh boards
```

Then attach to it with any serial terminal:

```sh
# screen comes with Ubuntu; Ctrl-A then K to quit
screen /dev/ttyACM0 921600

# or, if you prefer not to install anything:
python3 -c "import serial,sys; s=serial.Serial('/dev/ttyACM0',921600,timeout=5); sys.stdout.write(s.read(2000).decode(errors='replace'))"
```

Press the board's reset button, or replug it, and look for:

```
[INFO] Radio: disabled (held in reset, course build)
```

**If that line is there, the radio cannot transmit.** The two SX1262
transceivers are held in reset before anything else runs in `setup()`, and the
functions that would configure them are not even linked into the binary.

**If it is not there, the board is not on the course build.** There is only one image in `firmware/binaries/`, so the usual cause is an older firmware still on the board. Flash it again.

The sensor checks this too, continuously: its `radio-origin-frame` rule fires
if the board ever reports a frame that arrived over the air. On a correctly
flashed board that rule can never fire, which is exactly why it is worth
having.

---

## Building it yourself

Only if you are changing the firmware. For the workshop, skip this.

```sh
sudo apt install -y python3-pip
pip install platformio

cd firmware/Firmware
pio run                             # the course build, and only that
```

### The radio is off by default, not by flag

This matters most on Day 2, where students edit this source and rebuild.

`#if FLATSAT_NO_RADIO` treats an undefined macro as zero, so a build that
forgets the flag used to produce a binary that could key both transceivers.
A bare `pio run` is exactly what somebody would type.

Two changes close that:

1. **The source defaults to radio-off.** `mission.h` and `radio_off.h` both
   carry `#ifndef FLATSAT_NO_RADIO / #define FLATSAT_NO_RADIO 1`, so every
   translation unit that tests the macro sees the safe value first. Turning
   the radio on now takes an explicit `-DFLATSAT_NO_RADIO=0`.
2. **`default_envs = pico_tinyusb_norf`.** A bare `pio run` builds the course
   environment and nothing else, so no transmitting `.uf2` is left in
   `.pio/build/` for somebody to flash by mistake.

Proven rather than asserted. `platformio.ini` carries a third environment,
`pico_tinyusb_noflag`, that passes **no radio flag at all**: it is what a
careless build produces, and it is there so the property can be rebuilt and
re-checked at any time.

```sh
pio run -e pico_tinyusb_norf -e pico_tinyusb -e pico_tinyusb_noflag
```

| Build | radio config linked | hold-in-reset | boot banner |
|---|---|---|---|
| `pico_tinyusb` (explicit `-DFLATSAT_NO_RADIO=0`) | **present** | absent | no |
| `pico_tinyusb_norf` (the course build) | absent | **present** | yes |
| `pico_tinyusb_noflag` (**no flag at all**) | **absent** | **present** | **yes** |

The third row is the answer to "what happens if somebody rebuilds and forgets":
they get a board that cannot transmit.

It does not get them the course build, which also needs
`-DFLATSAT_GPS_OVERRIDE=1` for lab 2.5. A forgetful build is safe, not
complete.

`verify.sh` does both and then reads the two binaries back, reporting what each
one actually contains:

```sh
cd firmware && ./verify.sh
```

It builds four variants, reads each binary back, and writes only the course
image to `binaries/`:

| Build | ELF | SX126x symbols | transmit() | hold-reset | banner |
|---|---|---|---|---|---|
| stock, radio enabled | 1,132,376 | 107 | 3 | absent | no |
| no flag passed at all | 1,121,476 | 87 | 3 | present | yes |
| driver linked, held in reset | 1,121,740 | 87 | 3 | present | yes |
| **COURSE BUILD, no driver** | **1,094,984** | **0** | **0** | present | yes |

The second row is the one to understand: a student who rebuilds and forgets
every flag still gets a board that cannot transmit. The fourth is what ships,
and it has no radio code at all.

See [`firmware/README.md`](../firmware/README.md) for the seven call sites that
are compiled out and why the state is reported on the text console rather than
in telemetry.

---

## If something went wrong

**No `RPI-RP2` drive appears.** You let go of BOOTSEL too early, or the cable
is charge-only. Try again, holding the button while you plug in. If `lsusb`
shows nothing at all in either mode, change the cable before anything else.

**The drive appears but the copy fails.** Some file managers do not flush
before unmounting. Use `cp` plus `sync` from a terminal, as above, rather than
dragging the file in a GUI.

**The board does not come back.** Unplug, count to five, plug back in. The
RP2040 has no way to be bricked by a bad `.uf2`, BOOTSEL always gets you back
to mass storage.

More in [troubleshooting](05-troubleshooting.md).

---

Next: [**3. Running the bench**](03-running-the-bench.md)
