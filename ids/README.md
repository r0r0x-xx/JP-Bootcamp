# Space IDS, the sensor in the middle of the bench

```
FlatSat  --USB-->  [ Space IDS ]  -->  PWNSAT-C3
```

```sh
./run.sh boards            # which boards this machine can see
./run.sh run               # the sensor, in line
./run.sh replay all        # no hardware: the captures against the rules
python3 -m pytest tests/   # 15 tests, including the end-to-end one
```

Standard library plus `pyserial`. Nothing else.

## Why it is a process and not a device

A USB cable has **no physical midpoint** where you can insert a probe without
adding a second board. So the sensor is a process: it takes the serial port
for itself, classifies every frame, and passes it on untouched. Logically it
sits exactly in the middle, and that is what makes an alert arrive while the
attack is still running rather than afterwards.

**It watches both directions, and that is the point.** Every attack in this
course is something the operator *sends*. A sensor watching only telemetry
would see none of them.

**It forwards what it alerts on.** `--mode block` exists to demonstrate the
mitigation, but the default is `detect`: a bench where the attack never lands
teaches nothing, and blocking is a different device with a different failure
mode.

**If the sensor dies, C3 goes blind.** That is what an in-line IDS does, not a
fault.

## The fifteen rules

| Rule | ID | Severity | What sets it off |
|---|---|---|---|
| `unknown-apid-rate` | UACE-9 | medium | The **rate** of identifiers nobody implements |
| `duplicate-frame` | UACE-7 | high | The same bytes twice |
| `sequence-regression` | UACE-7 | high | A counter that went backwards |
| `length-mismatch` | UACE-8 | high | Declared length disagrees with what arrived |
| `length-underflow` | UACE-8 | high | A length below the header the application subtracts |
| `runt-frame` | UACE-8 | high | Under six octets: no primary header to read |
| `unauthenticated-tc` | UACE-2/3 | critical | A critical command executed with the secure link off |
| `position-jump` | UCEB-8 | high | A position that moved further than the orbit allows |
| `command-before-auth` | UACE-6 | high | A credentialed command **before** the station was established |
| `radio-origin-frame` | PWN-1\* | critical | The board says something arrived **over the air** on a build with no radio |
| `crc-accepted` | PWN-2\* | medium | A frame that failed CRC and was taken anyway |
| `refused-command-burst` | PWN-3\* | medium | A burst of refused commands |
| `secure-link-downgrade` | PWN-4\* | critical | The secure-link bit was set and stopped being set |
| `flash-read-sweep` | PWN-5\* | high | Memory reads walking across offsets |
| `gate-exemption-chain` | PWN-6\* | critical | An exempt command, and the gate falling right after |

**SPARTA's identifiers are SPARTA's.** Mapping an observation to one of them is
this project's analysis, not an official Aerospace Corporation classification.
Rules with no SPARTA equivalent carry an identifier of our own and **the
console marks them with `*`**.

**Every rule carries its defence**, and it lives in `pwnsat_ids/knowledge.py`:
what sets it off, why it matters, how the fault is fixed, and which line of the
firmware it is on. The console renders that next to the alert, and
`tests/test_knowledge.py` fails if a rule is added without it. An alert that
names the attack without naming the fix is half an observation.

### The rule that keeps the radio claim checkable

The course firmware holds both SX1262 transceivers in reset and does not
compile their driver, so **no frame can arrive over the air**. If the board
reports one, either it is not running the course build or the event channel is
not coming from the board.

`radio-origin-frame` is what makes that checkable continuously rather than
once, at flashing time. Against stock firmware, turn it off with
`--stock-firmware`.

> `crc-accepted` can only come from the radio, so on a course build it always
> arrives alongside `radio-origin-frame`. The two together are correct, not a
> duplicate.

## The console

`http://127.0.0.1:5011`. Standard library, one file. There is no build step,
because a console that needs compiling is a console that is down while the room
waits.

Two tabs:

**Alerts.** List on the left, detail on the right. Opening an alert shows what
the sensor saw, a table of what the board said about that frame, **a hexdump of
the octets that raised it** with the CCSDS primary header highlighted, why it
matters, and how it is fixed, with the firmware file and line where there is
one. Filters by severity, direction, rule and text, plus a timeline of the last
90 seconds.

**What this sensor watches for.** All fifteen rules, firing or not, and at the
end **the two attacks on the syllabus this set does not detect**, with what
covers them instead. An empty alert list means one of two things, nothing is
wrong or nothing is watching, and on a blank screen they look the same. So the
inventory is always there.

The page asks only for new alerts (`api/state?since=n`). With the 600 a full
pass produces, that is 256 octets per poll instead of 242,000, the difference
between 0.015 and 14.5 MB per minute.

| Endpoint | What it returns |
|---|---|
| `GET /` | The console |
| `GET /api/state?since=n` | Counters, and alerts numbered above `n` |
| `GET /api/rules` | The rule inventory and the blind spots |

## The board's event channel

Firmware v1.0.5 emits one event per frame received: APID `0x20`, 15 octets,
**always in clear** (the IDS must not need the spacecraft's key) and **over USB
only**. It carries origin, APID, length, sequence, RSSI/SNR, parse result,
mission mode and whether the command executed.

**The board reports, it does not judge.** There is no "attack detected" field
and there must not be one: detection belongs to the IDS, which updates without
reflashing a spacecraft.

The decoder refuses an event whose format version it does not know, rather than
guessing at the fields.

## How C3 attaches

The sensor listens on `127.0.0.1:5010` and **speaks exactly the framing the
board speaks**:

```
ground -> satellite   0xAA 0x55 <len:2> <SPP>
satellite -> ground   0xAA <SPP>
```

So the `ids` transport on the C3 side is the serial transport with a socket
instead of a tty, and nothing above it changes.

## Tests

Eleven captures, one per rule. A rule without a capture is a claim, not a
detection.

| Capture | Alerts |
|---|---|
| `nominal` | **0** |
| `recon` | `unknown-apid-rate`, `refused-command-burst` |
| `replay` | `duplicate-frame`, `unauthenticated-tc` |
| `malformed` | `length-mismatch`, `length-underflow` |
| `spoof` | `position-jump` |
| `handover` | `command-before-auth` |
| `radio-on` | `radio-origin-frame` |
| `crc` | `crc-accepted` |
| `downgrade` | `secure-link-downgrade` |
| `flash-dump` | `flash-read-sweep` |
| `gate-chain` | `gate-exemption-chain` |

**Clean traffic produces zero alerts.** It is the hardest property of a
detection set and the easiest to lose, so it is an assertion that runs on every
build.

The end-to-end tests stand up a pty instead of the board and check what the
slides promise: that the uplink is inspected **and forwarded byte for byte**,
that the downlink reaches the console, and that `block` really does drop.

## Two defects found building it

1. **`flush()` on the uplink path.** `serial.flush()` is `tcdrain`: it waits
   for the bytes to leave the UART, which means it waits on the other end. A
   board that stopped reading would have blocked that thread forever, and with
   it **every later command and all inspection**. A test that hung found it.
   The system buffer is enough; the real confirmation is the board answering.
2. **The sensor span forever on a dead port.** It now gives up after five
   consecutive failed reads and says so, instead of hiding the failure from
   whoever is watching the console.

## Known issue

**The 14-bit CCSDS sequence counter wraps at 16,384 frames**, and the replay
rule's `_seen` set never forgets, so after a wrap `duplicate-frame` fires on
every subsequent frame. At the rate an idle board emits, that is hundreds of
hours away. At one beacon per second it is 4.6 hours, which fits inside a
workshop day. The fix is to bound `_seen` to the anti-replay window.

## Open

- [ ] The `ids` transport on the C3 side (`zmq_link.py` today only receives;
      `send_tc` raises).
- [ ] Real bench captures in `captures/*.bin`, to replace the generated ones.
- [ ] Rules 08–17 (web) and 18–23 (ISL). Out of scope for this course.
- [ ] Hot discovery of several boards, for the ISL case.
