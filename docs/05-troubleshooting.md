# 5. Troubleshooting

Every failure below is one we have actually hit, in roughly the order it
happens to people.

---

## The board

### `lsusb` shows nothing at all

**Your cable is charge-only.** This is the single most common cause, it
produces no error message anywhere, and it sends people looking at software for
an hour.

Many USB cables carry power and no data. Try a different one, ideally the one
that came with a phone you sync, or any cable you have used for data before.

```sh
lsusb | grep -i 239a       # expect: ID 239a:cafe ... Pwnsat - Flatsat
```

If a different cable does not fix it, try a different USB port, then a
different machine, in that order.

### `lsusb` sees it, the guest does not

You are in a virtual machine and the host has the device. See
[§6 of the setup guide](01-ubuntu-setup.md#6-if-you-are-in-a-virtual-machine).

### Permission denied on `/dev/ttyACM0`

You are not in the `dialout` group, or you are but have not logged out since.

```sh
groups | grep dialout
```

Nothing? `sudo usermod -aG dialout "$USER"`, then **log out and back in**. A
new terminal is not enough. Neither is `su - $USER`, reliably.

### Two ports appear for one board

Correct, not a fault. The FlatSat exposes two CDC interfaces with the same
serial number: one prints log lines, the other carries frames. **Which is which
is not stable across replugs**, so nothing asks you to decide, the tools probe
and keep the one that answers.

```sh
cd ids && ./run.sh boards     # the KIND column says which is which
```

### The board stops answering

Two different things look the same here.

**After the fuzzing lab (`01`)**, this is the lesson working. Unplug, count to
three, plug back in.

**At other times**, we have seen the board wedge twice without an identified
cause: once beaconing but not answering commands, once completely silent while
still enumerated. A power cycle has always recovered it. **There is no root
cause for this yet.** If you hit it, note what you had just run, that is the
information we are missing.

### The board disappears after a reset lab

Lab `2.5` reboots the board, which takes it off the bus for about eight
seconds. The sensor waits that out by itself and reopens the port, including
under a different device name.

In a **virtual machine**, the device may not be reattached to the guest
automatically when it comes back. That is a VM passthrough setting, not a bench
fault.

---

## The sensor

### "could not open the board" / "no FlatSat found"

In order:

1. Is it on the bus? `lsusb | grep -i 239a`
2. Are you in `dialout`, and have you logged out since? `groups | grep dialout`
3. **Is something else holding the port?** This is usually C3, or a `screen`
   you forgot about.

```sh
sudo lsof /dev/ttyACM*        # who has it
```

Stop whatever that is, start the sensor, then start C3.

### It starts, but no alert ever fires

**You are almost certainly missing `FLATSAT_HOST=1` on the attack.** Without
it the attack goes straight to the board and the sensor never sees it.

```sh
FLATSAT_HOST=1 python3 00_recon_apid_enum/00_recon_apid_enum_usb.py
```

To prove the rules themselves work, with no hardware at all:

```sh
cd ids && ./run.sh replay all
```

That runs fourteen captures against the rule set, between them firing all
fifteen rules. If those fire and your live
bench does not, the problem is the path the traffic takes, not the rules.

### "FLASH WINDOW LOCKED", and the window id is right

The board is in USB debug mode, so it is not decrypting your command.

The `00` recon sweep probes `DEBUG_CONFIG` like any other identifier, and that
turns `usbDebugEnabled` on. With it set, the board bypasses the secure link
(`worker.cpp:707`) and reads encrypted payloads as cleartext, so the handler
sees ciphertext where it expects a window id.

```sh
cd attacks && FLATSAT_HOST=1 python3 lib/reset_bench.py
```

The same cause produces position telemetry with impossible values, such as a
latitude above 90. If you see either symptom after running recon, reset first
and try again.

### `radio-origin-frame` fires

The board is reporting a frame that arrived over the air. On the course build
that is impossible, so one of two things is true:

- **The board is running the stock firmware.** Reflash
  `flatsat-course-noradio-v1.0.5.uf2` and check the boot banner.
- **The event stream is not coming from the board.**

Do not reach for `--stock-firmware` to silence it. That flag is for when you
have deliberately flashed the radio build, and using it to quieten a surprise
throws away the one rule that keeps "nothing radiates" checkable.

### `duplicate-frame` fires constantly on clean traffic

**Known issue.** The CCSDS sequence counter is 14 bits and wraps at 16,384
frames. The replay rule's `_seen` set never forgets, so after a wrap every
subsequent frame looks like a duplicate.

At the rate an idle board emits, this is hundreds of hours away. At one beacon
per second it is 4.6 hours, which fits inside a workshop day. Restarting the
sensor clears it. The real fix is to bound `_seen` to the anti-replay window.

### The console at :5010 shows nothing

`:5010` is the **frame stream**, not a web page, that is where C3 attaches.
The console is **:5011**.

---

## The ground console

### It will not start: "address already in use"

Something is on `:8000`.

```sh
sudo lsof -i :8000
```

Either stop it, or run C3 somewhere else: `uvicorn backend.app:app --port 8001`.

### It starts but shows no telemetry

Check `PWNSAT_C3_IDS_ENDPOINT` is set:

```sh
PWNSAT_C3_IDS_ENDPOINT=127.0.0.1:5010 uvicorn backend.app:app --port 8000
```

Without it, C3 tries to open the serial port directly. The sensor already has
it, so C3 finds nothing, and if C3 wins the race instead, the sensor is the
one left with nothing.

### Login fails

Default credentials are `operator` / `pwnsat`. Override with
`PWNSAT_C3_USERNAME` and `PWNSAT_C3_PASSWORD`.

### Everyone gets logged out when it restarts

Expected. `PWNSAT_C3_SECRET_KEY` is random at every start unless you set it.
Set it to keep sessions across restarts.

### It starts, but the source is `radio` and USB shows as off

The sensor holds the serial port, so the console has to come in through it.
`PWNSAT_C3_IDS_ENDPOINT` is what does that, and without it C3 probes for a
port it will never get, finds nothing, and falls back to `radio`, which has
nothing publishing to it either.

```sh
PWNSAT_C3_IDS_ENDPOINT=127.0.0.1:5010 uvicorn backend.app:app --port 8000
```

On startup you should see `Space IDS transport configured: 127.0.0.1:5010`,
and the active source should be `ids`.

### `sudo: 'uvicorn': command not found`

`sudo` resets `PATH`, so it cannot see the virtual environment. **C3 does not
need root**: port 8000 is unprivileged, and with the sensor in line C3 never
touches the serial port. Drop the `sudo`.

### From `c3/`, the virtual environment is one level up

There is one `.venv`, at the root of the repository:

```sh
cd c3 && source ../.venv/bin/activate
```

---

## The Python environment

### `ModuleNotFoundError: No module named 'serial'`

The virtual environment is not active. Your prompt should start with
`(.venv)`.

```sh
cd JP-Bootcamp && source .venv/bin/activate
```

Every new terminal needs this.

### `ModuleNotFoundError` for something else

The environment is active but incomplete:

```sh
pip install -r requirements.txt
```

### Syntax errors in files you have not touched

Your Python is too old. This needs **3.10 or newer**:

```sh
python3 --version
```

The errors you get on 3.9 point at the line, never at the version, which makes
this one slow to spot.

---

## In a virtual machine

### `inspectrum` prints EGL and MESA warnings

```
libEGL warning: failed to get driver name for fd -1
MESA: error: ZINK: failed to choose pdev
QSocketNotifier: Can only be used with threads started with QThread
```

**Noise, not failure.** There is no GPU to accelerate with, so Mesa falls back
to software. If the window opens, carry on. If it does not, or the spectrum
panel stays black:

```sh
sudo apt install -y libgl1-mesa-dri
QT_QPA_PLATFORM=xcb LIBGL_ALWAYS_SOFTWARE=1 inspectrum challenges/01_downlink_916MHz.cf32
```

`QT_QPA_PLATFORM=xcb` is there because Ubuntu 26.04 starts on Wayland, which
is where the `QSocketNotifier` line comes from. The real fix is the host's:
**VMware Fusion → Settings → Display → Accelerate 3D Graphics**. On Apple
Silicon with an arm64 guest that may not be available at all, in which case
software rendering is the only path and the waterfall will be slow but usable.

### The board vanishes when you press BOOTSEL

It re-enumerates as a different USB device, so the hypervisor stops passing it
through. Reconnect it: **VMware → Removable Devices**. This happens at exactly
the moment you are trying to flash.

### `lsusb` shows `2e8a:0003` and there is no serial port

That is the board in BOOTSEL. It is a mass-storage device in that state and
exposes no console. Unplug and replug without touching the button, and it
comes back as `239a:cafe`.

---

## When none of this helps

Collect these before asking:

```sh
python3 --version
lsusb | grep -i 239a
groups | grep dialout
sudo lsof /dev/ttyACM* 2>/dev/null
cd ids && python3 -m pytest tests/ -q 2>&1 | tail -3
```

Plus: what you ran, what you expected, and what happened instead.

---

Next: [**6. How it fits together**](06-how-it-fits-together.md)
