# 6. How it fits together

Enough of the design to debug it, and to argue with it.

---

## The chain

```
   FlatSat  ──USB──▶  Space IDS  ──TCP 5010──▶  PWNSAT-C3
   RP2040              a process                 FastAPI
   the target          on your laptop            the dashboard
                            │
                            └── HTTP 5011, its own console
```

**The sensor is a process, not a device.** A USB cable has no physical midpoint
where you can insert a probe without adding a second board. So the sensor takes
the serial port for itself, classifies every frame, and passes it on untouched.
Logically it is exactly in the middle, and that is what makes an alert arrive
while the attack is still running rather than afterwards.

**It watches both directions, and that is the point.** Every attack in this
course is something the *operator sends*. A sensor watching only telemetry
would see none of them.

**It forwards what it alerts on.** The default is `detect`, not `block`. A
bench where the attack never lands teaches nothing, and a detector that blocks
is a different device with a different failure mode.

---

## The framing on the wire

Asymmetric, and that is not a mistake:

```
ground -> satellite    0xAA 0x55 <len:2 big endian> <SPP packet>
satellite -> ground    0xAA <SPP packet>
```

The downlink carries **no length prefix**. The deframer has to trust the SPP
header's own length field to know where the packet ends.

That is also the first thing an attacker can lie about, which is why
`length-mismatch` exists as a rule and why lab `2.1` is a lab.

---

## CCSDS Space Packet, the six octets that matter

```
 ┌───────┬──┬──┬───────────┬────┬──────────────┬────────────────┐
 │  ver  │T │SH│   APID    │seq │   sequence   │  DATA LENGTH   │
 │ 3 bit │1 │1 │  11 bit   │flg │   14 bit     │    16 bit      │
 └───────┴──┴──┴───────────┴────┴──────────────┴────────────────┘
  └────────── octets 0–1 ──────────┘└─ 2–3 ─┘└───── 4–5 ──────┘
```

Three things catch everyone:

- **The fields are not octet-aligned.** APID is 11 bits straddling two octets.
  You cannot read it with a byte index.
- **DATA LENGTH is octets minus one.** A value of 0 means one octet of payload.
  Off-by-one here is the most common decoding bug in the course.
- **The sequence count is 14 bits**, so it wraps at 16,384. See the known issue
  in [troubleshooting](05-troubleshooting.md).

The sensor's console highlights those first six octets in every hexdump, which
is the cheapest way to make the boundary stick.

---

## The board's event channel

Firmware v1.0.5 emits one event per frame it receives: **APID `0x20`, 15
octets, always in clear, over USB only.**

It carries origin, APID, length, sequence, RSSI/SNR, the parse result, mission
mode, and whether the command executed. No payload bytes.

**The board reports; it does not judge.** There is no "attack detected" field
and there must not be one. Detection belongs in the IDS, which can be updated
without reflashing a spacecraft. That distinction is the whole argument for
why the sensor exists as a separate thing.

Six of the fifteen rules can only work because of this channel: the board is
the only thing that knows whether a command *executed*, whether the secure link
covered it, and whether the CRC passed.

---

## Two parsers, on purpose

`attacks/lib/flatsat.py` and `ids/pwnsat_ids/spp.py` both decode CCSDS packets,
and they **share no code**.

That is deliberate. A detector that parses with the attacker's parser cannot
catch a frame that parser gets wrong. Independent implementations disagree, and
the disagreement is the finding.

---

## The link "encryption"

**The FlatSat does not implement SDLS.** Its secure link is hand-rolled
AES-128-ECB: no IV, fixed key, two-octet length prefix, zero padding. The key
is `PWNsatLabKey1234` and it is the same on every board.

This matters for how you talk about it. CCSDS 355.0-B (SDLS) is the real
standard and it lives on **PWNCUBE** (cFS + CryptoLib), not here. Labs `1.9`
and `2.6` use the FlatSat's version as the teaching case and the SDLS downgrade
as an analogy.

ECB with a fixed key is a textbook failure for a reason: identical plaintext
blocks produce identical ciphertext blocks, so the structure of the traffic
survives the encryption. That is lab `1.9`.

---

## The rules, and the two it cannot catch

Fifteen rules, and fourteen captures that between them fire all fifteen. Clean
traffic produces **zero** alerts, which is the hardest property of a detection
set and the easiest to lose, so it is asserted on every build.

Every rule carries its defence, in `ids/pwnsat_ids/knowledge.py`: what sets it
off, why it matters, how the fault is fixed, and which firmware line it is on.
`tests/test_knowledge.py` fails if a rule is added without that.

Two attacks on the syllabus produce **no usable detection**, and both are on
the console rather than left out:

| Attack | Why nothing fires | What covers it instead |
|---|---|---|
| **Passive eavesdropping** (`1.9`) | Listening leaves no trace. Nothing sent, nothing malformed, no counter moves. There is no frame to look at | Per-session keys and rotation. Nothing detects the attack; the controls make it worthless |
| **Mission-ending command** (`2.5`) | `unauthenticated-tc` fires, correctly, *after* the command executed. For a reset there is no window between detecting and having lost the platform | A critical-command list enforced in firmware, and a second operator on the ground |

A detection set that lists only its wins teaches students to trust a quiet
screen. That is why both are visible.

---

## Why the radio is held in reset

Because a build that cannot transmit is checkable and a promise is not. The
control has three layers:

1. **Seven call sites compiled out**, every function that touches a radio.
2. **Both SX1262 held in reset** before anything else runs in `setup()`: RESET
   low, antenna switches low, chip selects high. They cannot modulate a carrier
   whatever the firmware above them does.
3. **It says so at boot**, on the text console, so it can be read rather than
   believed.

And then the sensor watches: `radio-origin-frame` fires if the board ever
reports a frame from the air. On a course build that rule can never fire, which
is exactly what makes it worth having. It keeps the claim checkable for both
full days instead of only at flashing time.

Verified on 7 November 2026 by SDR: 916 and 918 MHz at the noise floor with the
board powered.

---

## Where the numbers come from

| | |
|---|---|
| SPARTA technique identifiers | The Aerospace Corporation's. Mapping an observation to one is **this project's analysis**, not an official classification, and every alert says so |
| `PWN-*` identifiers | Ours. No SPARTA technique describes them, and the console marks them with `*` |
| Severity tiers | NIST/CVSS only: critical, high, medium |
| CCSDS references | 133.0-B (Space Packet), 355.0-B (SDLS) |

---

## Further reading in this repository

| | |
|---|---|
| [`ids/README.md`](../ids/README.md) | The rule set, the console, the event format, two defects found building it |
| [`firmware/README.md`](../firmware/README.md) | The seven call sites, the three layers, what `verify.sh` proves |
| [`attacks/README.md`](../attacks/README.md) | What each attack breaks, and the two firmware changes that made two of them possible |
| [`c3/DOCUMENTATION.md`](../c3/DOCUMENTATION.md) | The ground console in depth: transports, telemetry bus, the dashboard |
| [`challenges/README.md`](../challenges/README.md) | The RF captures for labs 1.5 and 1.6, where they came from, and the tools that read them |
