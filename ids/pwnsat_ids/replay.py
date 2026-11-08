"""Offline mode: run a recorded session past the rules, with no hardware.

This is how the rules get checked, and how somebody can see an alert without a
board on the desk. Captures are generated from a seed, so everyone gets
identical bytes and a result can be marked; a real bench recording dropped in
`captures/<name>.bin` replaces the generated one without touching a rule.
"""
from __future__ import annotations

import hashlib
import random
import struct
from pathlib import Path

from . import spp
from .events import build_event
from .rules import SpaceIDS

CAPTURES = Path(__file__).resolve().parent.parent / "captures"


def _nav(i: int) -> bytes:
    """A NAV snapshot in the firmware's own layout: little endian, coordinates
    scaled by 1e7. A ground track at roughly 7 km per report, which is what low
    orbit looks like from the ground segment."""
    return _nav_at(-51.0 + i * 0.062, 12.4 + i * 0.041)


def _nav_at(lat: float, lon: float) -> bytes:
    out = bytearray()
    out.append(0x01)                                    # spacecraft id
    out.append(0x03)                                    # gps status: fix
    out.append(9)                                       # satellites
    out += int(lat * 1e7).to_bytes(4, "little", signed=True)
    out += int(lon * 1e7).to_bytes(4, "little", signed=True)
    out += int(517_00).to_bytes(4, "little", signed=True)   # altitude, cm
    out += bytes([12, 30, 0, 21, 11]) + (2026).to_bytes(2, "little")
    out += b"\x00" * 8                                  # accelerometer
    return bytes(out)


def generate(name: str) -> list[tuple[str, bytes]]:
    """Returns [(direction, raw_spp)]. Direction is 'up' or 'down'."""
    rng = random.Random(hashlib.sha256(name.encode()).digest()[:8])
    out: list[tuple[str, bytes]] = []
    seq = {a: 0 for a in spp.APIDS}

    def tm(apid: int, payload: bytes) -> None:
        seq[apid] = (seq.get(apid, 0) + 1) & 0x3FFF
        out.append(("down", spp.build_spp(apid, tc=False, seq=seq[apid], payload=payload)))

    def event(**kw) -> None:
        kw.setdefault("flags", 0x03)                    # executed + secure
        out.append(("down", spp.build_spp(spp.APID_IDS_EVENT, tc=False,
                                          seq=0, payload=build_event(**kw))))

    if name == "nominal":
        for i in range(200):
            tm(spp.APIDS and 0x0C, struct.pack("<HHH", rng.randint(3300, 3400),
                                               rng.randint(180, 220), i & 0xFFFF))
            tm(0x0F, bytes([1, rng.randint(0, 3)]))
            tm(0x0E, _nav(i))
            if i % 20 == 0:                             # the operator polls
                event(apid=0x0C, length=12, sequence=i, result=0x00, flags=0x03)
    elif name == "recon":
        for i in range(300):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            if 80 < i < 220 and i % 2 == 0:
                unknown = 0x100 + (i % 180)
                out.append(("up", spp.build_spp(unknown, tc=True, seq=i, payload=b"\x00")))
                event(apid=unknown, length=7, result=0x04, flags=0x02)
    elif name == "replay":
        for i in range(60):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
        cmd = spp.build_spp(spp.APID_SET_THRUSTER, tc=True, seq=41, payload=b"\x01\x80")
        out.append(("up", cmd))
        for i in range(30):
            tm(0x0C, struct.pack("<HHH", 3350, 200, 100 + i))
        out.append(("up", cmd))                         # byte for byte identical
    elif name == "malformed":
        for i in range(40):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
        for n, declared in enumerate((40, 20, 8, 6, 4, 2)):
            out.append(("up", spp.build_spp(spp.APID_BROADCAST, tc=True, seq=n,
                                            payload=b"\x00" * 4,
                                            declared_length=declared - 1)))
            event(apid=spp.APID_BROADCAST, length=10, result=0x05, flags=0x02)
    elif name == "spoof":
        for i in range(60):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            tm(0x0E, _nav(i))
        for i in range(60, 90):                         # injected, not flown
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            tm(0x0E, _nav_at(-9.4 + (i - 60) * 0.06, 38.7 + (i - 60) * 0.04))
    elif name == "handover":
        for i in range(40):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
        out.append(("up", spp.build_spp(spp.APID_SET_THRUSTER, tc=True, seq=7,
                                        payload=b"\x01\x80")))
        for i in range(10):
            tm(0x0C, struct.pack("<HHH", 3350, 200, 100 + i))
        tm(spp.APID_GS_ACCESS, b"\x01" + b"GS-TOKYO-1")  # the exchange, too late
    elif name == "radio-on":
        for i in range(20):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
        event(origin=0x00, apid=spp.APID_SET_THRUSTER, length=22, sequence=0x1234,
              rssi_dbm=-38.0, snr_db=13.5, result=0x00, flags=0x03)
    elif name == "crc":
        for i in range(20):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
        event(origin=0x00, apid=0x0C, length=18, result=0x00, flags=0x0B)
    elif name == "downgrade":
        # attack 24: the link is encrypted, then one command and it is not.
        for i in range(10):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            event(apid=0x0C, length=12, sequence=i, flags=0x03)
        event(apid=spp.APID_AES_CONFIG, length=18, result=0x00, flags=0x03)
        for i in range(10, 20):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            event(apid=0x0C, length=12, sequence=i, flags=0x01)   # secure bit gone
    elif name == "flash-dump":
        # attack 25: one read is maintenance, a walk is a copy.
        for i in range(10):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            event(apid=0x0C, length=12, sequence=i, flags=0x03)
        for i in range(12):
            event(apid=spp.APID_FLASH_READ, length=22, sequence=i, flags=0x03)
    elif name == "gate-chain":
        # attack 26: an exempt command, then the gate going down.
        for i in range(10):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            event(apid=0x0C, length=12, sequence=i, flags=0x03)
        event(apid=spp.APID_DEBUG_CONFIG, length=18, result=0x00, flags=0x03)
        event(apid=spp.APID_GS_MODE, length=18, result=0x00, flags=0x03)
    elif name == "injection":
        # lab 2.2: a critical command executed with the secure link off.
        for i in range(12):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
            event(apid=0x0C, length=12, sequence=i, flags=0x03)
        for n, apid in enumerate((spp.APID_SET_THRUSTER, spp.APID_RESETC,
                                  spp.APID_SET_THRUSTER)):
            out.append(("up", spp.build_spp(apid, tc=True, seq=50 + n,
                                            payload=b"\x01\x80")))
            event(apid=apid, length=18, sequence=50 + n,
                  result=0x00, flags=0x01)             # executed, not secure
    elif name == "runt":
        # lab 2.1: frames too short to hold a primary header.
        for i in range(15):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
        for raw in (b"\x18", b"\x18\x0c", b"\x18\x0c\xc0", b"\x18\x0c\xc0\x00\x00"):
            out.append(("up", raw))
    elif name == "regression":
        # lab 1.10: the sequence counter walking backwards.
        for i in range(40):
            tm(0x0C, struct.pack("<HHH", 3350, 200, i))
        # Built by hand: an exact repeat raises duplicate-frame and stops
        # there, so each frame has to be one the sensor has not seen.
        for n in range(300, 310):
            out.append(("down", spp.build_spp(0x0F, tc=False, seq=n,
                                              payload=bytes([1, n & 0x03]))))
        for n in (295, 296, 297):                       # behind, within the window
            out.append(("down", spp.build_spp(0x0F, tc=False, seq=n,
                                              payload=bytes([1, n & 0x03]))))
    else:
        raise KeyError(f"unknown capture '{name}'. Available: {', '.join(NAMES)}")
    return out


NAMES = ("nominal", "recon", "replay", "malformed", "spoof", "handover",
         "radio-on", "crc", "downgrade", "flash-dump", "gate-chain",
         "injection", "runt", "regression")


def load(name: str) -> list[tuple[str, bytes]]:
    """A real bench recording if one shipped, otherwise the generated one."""
    path = CAPTURES / f"{name}.bin"
    if path.exists():
        data = path.read_bytes()
        frames, _ = spp.deframe_tm(data)
        return [("down", f) for f in frames]
    return generate(name)


def run(name: str, ids: SpaceIDS | None = None) -> SpaceIDS:
    """Feed a capture past the rules, exactly as the sensor would."""
    from .events import parse_event
    ids = ids or SpaceIDS()
    for direction, raw in load(name):
        try:
            packet = spp.parse_spp(raw)
        except ValueError:
            ids.observe_raw(raw, direction=direction)
            continue
        if packet.apid == spp.APID_IDS_EVENT:
            try:
                ids.observe_event(parse_event(packet.payload))
            except ValueError:
                pass
        else:
            ids.observe(packet, direction=direction)
    return ids
