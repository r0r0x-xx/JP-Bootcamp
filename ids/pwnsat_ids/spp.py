"""CCSDS Space Packet Protocol, and the USB framing the FlatSat actually uses.

The framing is asymmetric and that is not a mistake in this file:

    ground -> satellite   0xAA 0x55 <len:2> <SPP>
    satellite -> ground   0xAA <SPP>          (length recovered from the
                                               SPP header's own field)

The firmware's transmit path sends no length prefix, so the deframer has to
trust the header to know where the packet ends. That is also the first thing
an attacker can lie about, which is why `length-mismatch` exists as a rule.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

SPP_HEADER = 6
SYNC = 0xAA
TC_PREFIX = b"\xAA\x55"

# The applications this spacecraft implements, taken from the firmware's
# mission.h. Anything else is somebody looking around.
#
# These used to be the course book's teaching abstraction (0x001 housekeeping,
# 0x010 command, ...). Against a real board that mislabels every frame and
# makes unknown-apid-rate fire on ordinary traffic, so they are now the real
# ones.
APIDS = {
    0x01: "PING",            0x02: "RESETC",         0x03: "SEND_FW",
    0x04: "SET_THRUSTER",    0x05: "SET_BEACON_RATE", 0x06: "BROADCAST_MSG",
    0x07: "FLASH",           0x08: "SEND_TM",        0x09: "ERROR",
    0x0A: "AES_CONFIG",      0x0B: "FLASH_READ",     0x0C: "STATUS",
    0x0D: "MISSION_MODE",    0x0E: "NAV",            0x0F: "PAYLOAD_STATUS",
    0x10: "DEBUG_CONFIG",    0x11: "GS_MODE",        0x12: "GS_ACCESS",
    0x13: "GS_STATUS",       0x20: "IDS_EVENT",
}

# Named, because rules read better naming a command than a number.
APID_PING = 0x01
APID_RESETC = 0x02
APID_SET_THRUSTER = 0x04
APID_BROADCAST = 0x06
APID_FLASH = 0x07
APID_ERROR = 0x09
APID_AES_CONFIG = 0x0A
APID_FLASH_READ = 0x0B
APID_NAV = 0x0E
APID_DEBUG_CONFIG = 0x10
APID_GS_MODE = 0x11
APID_GS_ACCESS = 0x12

# Moves something physical. The strongest severity in the set.
ACTUATOR_APIDS = {APID_SET_THRUSTER}

# Commands whose effect cannot be walked back from the console, or which
# weaken a protection. These are the ones worth alerting on hardest.
CRITICAL_APIDS = {APID_RESETC, APID_SET_THRUSTER, APID_FLASH,
                  APID_AES_CONFIG, APID_GS_MODE}

# NAV payload, from telemetrySPPTransmitNavSnapshot(). Little endian, and the
# coordinates are scaled by 1e7, not 1e5.
NAV_LAT_OFFSET = 3
NAV_LON_OFFSET = 7
NAV_SCALE = 1e7
NAV_MIN_LEN = 11

APID_IDS_EVENT = 0x20

# Applications that subtract their own header from the declared length before
# reading. Only these can underflow.
SUBTRACTING_APPS = {APID_BROADCAST}
APP_HEADER = 6


@dataclass
class SpacePacket:
    version: int
    type_: int
    sec_hdr: int
    apid: int
    seq_flags: int
    seq_count: int
    data_length: int
    payload: bytes
    raw: bytes

    @property
    def is_telecommand(self) -> bool:
        return self.type_ == 1

    @property
    def declared_payload(self) -> int:
        """The header says "length - 1", so a zero means one octet."""
        return self.data_length + 1

    @property
    def name(self) -> str:
        return APIDS.get(self.apid, "unknown")

    def __str__(self) -> str:
        kind = "TC" if self.is_telecommand else "TM"
        return (f"{kind} apid=0x{self.apid:03X} ({self.name}) seq={self.seq_count} "
                f"len={len(self.raw)}")


def parse_spp(raw: bytes) -> SpacePacket:
    """Decode a primary header. Deliberately trusting: it reports what the
    frame claims, and the rules compare that against what arrived."""
    if len(raw) < SPP_HEADER:
        raise ValueError(f"need {SPP_HEADER} octets for a primary header, got {len(raw)}")
    ident, seq, length = struct.unpack(">HHH", raw[:SPP_HEADER])
    return SpacePacket(
        version=(ident >> 13) & 0b111,
        type_=(ident >> 12) & 0b1,
        sec_hdr=(ident >> 11) & 0b1,
        apid=ident & 0x7FF,
        seq_flags=(seq >> 14) & 0b11,
        seq_count=seq & 0x3FFF,
        data_length=length,
        payload=raw[SPP_HEADER:],
        raw=raw,
    )


def build_spp(apid: int, *, tc: bool = True, seq: int = 0, payload: bytes = b"",
              sec_hdr: bool = False, declared_length: int | None = None) -> bytes:
    """`declared_length` lets a test lie about the payload size, which is what
    the fuzzing rule has to catch."""
    ident = (0 << 13) | (int(tc) << 12) | (int(sec_hdr) << 11) | (apid & 0x7FF)
    seq_field = (0b11 << 14) | (seq & 0x3FFF)
    length = declared_length if declared_length is not None else max(len(payload) - 1, 0)
    return struct.pack(">HHH", ident, seq_field, length & 0xFFFF) + payload


def frame_tc(raw_spp: bytes) -> bytes:
    """Ground -> satellite. Matches pwnsat_tools/usb_tc_send.frame_usb."""
    return TC_PREFIX + len(raw_spp).to_bytes(2, "big") + raw_spp


def deframe_tm(stream: bytes) -> tuple[list[bytes], bytes]:
    """Satellite -> ground. Returns the packets found and whatever tail could
    not be decided yet, which the caller keeps for the next read."""
    packets: list[bytes] = []
    offset = 0
    while offset < len(stream):
        if stream[offset] != SYNC:
            offset += 1
            continue
        if len(stream) - offset < 1 + SPP_HEADER + 1:
            break
        length_field = int.from_bytes(stream[offset + 5: offset + 7], "big")
        total = 1 + SPP_HEADER + length_field + 1
        if len(stream) - offset < total:
            break
        packets.append(stream[offset + 1: offset + total])
        offset += total
    return packets, stream[offset:]


def deframe_tc(stream: bytes) -> tuple[list[bytes], bytes]:
    """The same, for the commands C3 sends down the wire to the board. The
    sensor has to decode these too: every attack in the course is something
    the operator sends, and a sensor watching only telemetry sees none of it."""
    packets: list[bytes] = []
    offset = 0
    while offset < len(stream):
        if stream[offset: offset + 2] != TC_PREFIX:
            offset += 1
            continue
        if len(stream) - offset < 4:
            break
        n = int.from_bytes(stream[offset + 2: offset + 4], "big")
        total = 4 + n
        if len(stream) - offset < total:
            break
        packets.append(stream[offset + 4: offset + total])
        offset += total
    return packets, stream[offset:]


def hexdump(data: bytes, width: int = 16) -> str:
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}  {hx:<{width * 3}} |{txt}|")
    return "\n".join(out)
