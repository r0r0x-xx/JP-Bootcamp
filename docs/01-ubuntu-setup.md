# 1. Ubuntu setup

From a machine that has never seen this project to one that can run the whole
bench. About three minutes on a clean install.

Written for Ubuntu **26.04**, which is what the course machines run. It works
the same on **24.04** and **22.04**. Desktop or server. A virtual
machine is fine, with one condition: **the USB device has to be passed through
to the guest**, and that is the single most common reason a lab does not start.
See [§6](#6-if-you-are-in-a-virtual-machine) below.

---

## The short way

```sh
git clone https://github.com/r0r0x-xx/JP-Bootcamp.git
cd JP-Bootcamp
./install.sh
```

Then **log out and log back in**. Skip to [§5](#5-check-it-worked).

Everything the script does is written out by hand below. If you would rather
not run a script you have not read, a reasonable position on a security
course, do these six steps instead.

---

## 1. System packages

```sh
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git usbutils
```

| Package | Why |
|---|---|
| `python3` | Everything here is Python. 3.10 or newer |
| `python3-venv` | The isolated environment, so nothing touches your system Python |
| `python3-pip` | Installs the dependencies |
| `git` | To clone this repository |
| `usbutils` | Gives you `lsusb`, which is how you prove the board is attached |

For the Day 1 radio labs only:

```sh
sudo apt install -y inspectrum gnuradio
./challenges/packages/install-lora.sh
```

`inspectrum` is the spectrum and waterfall viewer for lab 1.5 and `gnuradio`
is what lab 1.6 runs on. Both are in the archive.

The LoRa receiver blocks are not, so they ship built in
[`challenges/packages/`](../challenges/packages/), one per Ubuntu release and
architecture. The script picks yours. **Nothing is compiled here**, and the
whole thing takes seconds, so it can wait until the morning of Day 1 without
costing anybody an hour.

Check what you got:

```sh
python3 --version     # 3.10 or newer
```

| Ubuntu | System Python |
|---|---|
| 26.04 | 3.14 |
| 24.04 | 3.12 |
| 22.04 | 3.10 |

Any of those is fine. If it is older than 3.10, stop and upgrade: several
files use syntax that does not parse on 3.9, and the error you get will point
at a line rather than at the version.

**On 26.04, nothing compiles.** Python 3.14 is new enough that it is worth
saying explicitly: every dependency here installs from a prebuilt wheel.
`pycryptodome` ships an `abi3` wheel covering CPython 3.9 and up, `pyserial`
is pure Python, and `numpy`, `pyzmq`, `pydantic-core`, `uvloop`, `httptools`
and `watchfiles` all publish `cp314` Linux wheels. You do not need
`build-essential` or `python3-dev`.

---

## 2. Get the code

```sh
git clone https://github.com/r0r0x-xx/JP-Bootcamp.git
cd JP-Bootcamp
```

This repository is private. If the clone asks for a password, you need a GitHub
token rather than your account password: `gh auth login`, or a personal access
token with `repo` scope.

---

## 3. The Python environment

**One environment for all four parts.** The sensor needs only `pyserial`, the
attacks need an AES implementation too, and C3 needs the rest. Keeping them
together means one `activate` instead of three.

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Your prompt should now start with `(.venv)`. **Every terminal you open needs
that line**, `source .venv/bin/activate`, before running anything here. A
missing `(.venv)` is the second most common reason something does not start.

What gets installed and who needs it:

| Package | Needed by |
|---|---|
| `pyserial` | the sensor, the attacks, C3, everything that opens the board |
| `pycryptodome` | the attacks and C3, for the AES-128-ECB link |
| `fastapi`, `uvicorn`, `pydantic`, `itsdangerous` | C3's web dashboard |
| `pyzmq`, `pyusb`, `numpy` | C3's radio bridge and PWNCUBE transports |
| `pytest` | the test suites |

---

## 4. Permission to open the serial port

This is the step that catches everybody.

On Linux a USB serial device appears as `/dev/ttyACM0` and belongs to the
`dialout` group. Your user is not in that group by default, so the device
exists and refuses to open.

```sh
sudo usermod -aG dialout "$USER"
```

**Now log out and log back in.** Group membership does not apply to a session
that was already open. A reboot works too. `su - $USER` does not, reliably.

Confirm it took:

```sh
groups | grep dialout
```

If `dialout` is not in that output, you have not logged out yet.

### The udev rule

Not strictly required once you are in `dialout`, but it makes the failure
obvious when something is wrong, and it covers the board in bootloader mode for
flashing.

Create `/etc/udev/rules.d/99-flatsat.rules` with these two lines:

```
SUBSYSTEM=="tty", ATTRS{idVendor}=="239a", ATTRS{idProduct}=="cafe", MODE="0660", GROUP="dialout"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0003", MODE="0660", GROUP="dialout"
```

The first is the FlatSat running normally. The second is an RP2040 in
bootloader mode, which is what you get holding BOOTSEL, see
[flashing](02-firmware.md).

Then reload and replug:

```sh
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Unplug and replug the board afterwards. A rule does not apply to a device that
was already enumerated.

---

## 5. Check it worked

### The software, with no board attached

```sh
source .venv/bin/activate

cd ids && python3 -m pytest tests/ -q        # expect: 15 passed
cd ../c3 && python3 -m pytest backend/tests -q
cd ..
```

Both suites run without hardware. They exercise the framing logic against
synthetic data. If these pass, the install is good, and anything that fails
later is about the board or the cable rather than the code.

### With a board attached

Plug the FlatSat in, then:

```sh
lsusb | grep -i 239a
```

Expect something like:

```
Bus 001 Device 007: ID 239a:cafe Adafruit Industries Pwnsat - Flatsat
```

**Nothing at all?** Your cable is probably charge-only. That is the single most
common cause, it gives no error message, and swapping the cable fixes it. See
[troubleshooting](05-troubleshooting.md).

Then ask the sensor what it can see:

```sh
cd ids && ./run.sh boards
```

```
PORT                             SERIAL             KIND      PRODUCT
/dev/ttyACM0                     fsat-200052E9      console   Pwnsat - Flatsat v1.0.5
/dev/ttyACM1                     fsat-200052E9      frames    Pwnsat - Flatsat v1.0.5

the sensor would take /dev/ttyACM1
```

**One board shows up as two ports.** That is correct and not a fault: the
FlatSat exposes two CDC interfaces with the same serial number. One prints
human-readable log lines, the other carries frames, and **which is which is not
stable across replugs**. Nothing here asks you to work that out, the tools
probe and keep the one that answers.

---

## 6. If you are in a virtual machine

The board has to reach the guest. The host will grab it first unless you tell
it not to.

**VirtualBox.** Devices → USB → tick the FlatSat. Add a USB filter so it
attaches automatically next time. You need the Extension Pack for USB 2.0/3.0
controllers.

**VMware.** VM → Removable Devices → the FlatSat → Connect.

**UTM / QEMU on Apple silicon.** USB device passthrough, then select the board.
Note that the device **disappears and reappears** when the board reboots,
which lab 2.7 does deliberately, and some configurations do not reattach it
automatically. If the sensor loses the board after a reset, that is the first
place to look.

**WSL2.** USB passthrough needs `usbipd-win` on the Windows side. This has not
been tested for this course.

Inside the guest, the check is the same:

```sh
lsusb | grep -i 239a
```

If the host sees the board and the guest does not, the problem is passthrough,
not Linux.

---

## 7. Installing without internet

**Read this before a workshop, not during one.** A room of twenty laptops all
running `pip install` over venue wifi is the most predictable way to lose the
first half hour, and in some buildings it does not work at all.

On one machine that **does** have internet, and that runs **the same Ubuntu
version and architecture** as the room:

```sh
cd JP-Bootcamp
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip download -r requirements.txt -d wheels/
```

That leaves a `wheels/` directory of about 60 MB. Copy the whole repository,
`wheels/` included, to a USB stick.

On each machine in the room:

```sh
cd JP-Bootcamp
python3 -m venv .venv
source .venv/bin/activate
pip install --no-index --find-links wheels/ -r requirements.txt
```

No network needed. The rest of `install.sh`, apt packages, `dialout`, the
udev rule, still needs either internet or a machine that already has
`python3-venv` installed, so **do the apt step before the day**.

Everything after installation is local: the three services bind to
`127.0.0.1`, the attacks go over USB, and nothing in the course reaches the
internet.

---

## 8. Updating, uninstalling, and working without a board

### Updating

```sh
cd JP-Bootcamp
git pull
source .venv/bin/activate
pip install -r requirements.txt     # in case dependencies moved
```

If the firmware image changed, reflash: [`02-firmware.md`](02-firmware.md).

### Uninstalling

Nothing is installed outside the repository except three system-level things,
and here is how to undo each:

```sh
# 1. the services, if you installed them
sudo systemctl disable --now pwnsat-ids pwnsat-c3
sudo rm -f /etc/systemd/system/pwnsat-ids.service /etc/systemd/system/pwnsat-c3.service
sudo systemctl daemon-reload

# 2. the udev rule
sudo rm -f /etc/udev/rules.d/99-flatsat.rules
sudo udevadm control --reload-rules

# 3. the dialout membership, if you want it gone
sudo gpasswd -d "$(id -un)" dialout

# then the repository itself
rm -rf JP-Bootcamp
```

The apt packages (`python3`, `git`, `usbutils`) are left alone deliberately:
removing them would break unrelated things on a machine you share.

### Working without a board

A student whose board fails is not stuck. The sensor runs its whole rule set
against recorded captures:

```sh
cd ids
./run.sh replay all          # fourteen captures, every rule covered
./run.sh replay nominal      # the one that must raise nothing
```

Every rule fires, the output is identical to the live bench, and the blue-team
half of each lab can be followed exactly as written. What is lost is the
attack itself, which means pairing up for the red-team half.

The Day 1 signal labs (1.5, 1.6) never needed a board at all: they run on
recorded captures by design, because nothing in this course transmits.

### A note on the firewall

You do not need to open anything. All three services bind to `127.0.0.1` and
are unreachable from the network on purpose: the ground console ships with
demo credentials and is not built to be exposed. If `ufw` is active, leave it
that way.

### Space and time

About 250 MB for the repository and the virtual environment together, plus
60 MB if you keep the offline `wheels/`. A clean install takes three minutes
with internet, under one without.

---

## What has actually been run on Ubuntu

**None of this.** Every step above is a translation of the macOS procedure that
was verified on 7 November 2026, using Ubuntu's documented behaviour for
`dialout`, udev and `lsusb`. The Python is platform-independent and the test
suites do not touch hardware, so those should be exact. The USB and permission
steps are the ones to watch.

If something here is wrong, it is wrong in this file. Please say what you hit.

---

Next: [**2. Flashing the firmware**](02-firmware.md)
