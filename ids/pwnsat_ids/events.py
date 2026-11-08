"""The firmware's own event channel: APID 0x20, format v1.

One event per frame the board received, over radio or over USB, in clear,
carrying facts about the frame and no payload bytes. The board reports; it
does not judge. Deciding whether any of it is an attack is this program's job,
which is why the format has no "attack detected" field and should never get
one: rules change without reflashing a spacecraft.

Format reference: FlatSat-Bulk2/firmware-v1.0.5/IDS-EVENT-FORMAT.md
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

FORMAT_VERSION = 1
EVENT_LEN = 15

ORIGIN = {0x00: "radio", 0x01: "usb", 0x02: "isl"}

RESULT = {
    0x00: "accepted",
    0x01: "not an SPP packet",
    0x02: "secure link could not decode",
    0x03: "ground-station gate refused",
    0x04: "no handler for that APID",
    0x05: "handler refused the payload",
    0x06: "not allowed from that source",
}

FLAG_EXECUTED = 0x01
FLAG_SECURE = 0x02
FLAG_SEC_HDR = 0x04
FLAG_CRC_BAD = 0x08
FLAG_ARMED = 0x10


class UnknownEventVersion(ValueError):
    """Refuse the event rather than guess at its layout."""


@dataclass
class BoardEvent:
    version: int
    origin: str
    apid: int
    length: int
    sequence: int
    rssi_dbm: float
    snr_db: float
    result: int
    mission_mode: int
    flags: int

    @property
    def executed(self) -> bool:
        return bool(self.flags & FLAG_EXECUTED)

    @property
    def secure(self) -> bool:
        return bool(self.flags & FLAG_SECURE)

    @property
    def sec_hdr(self) -> bool:
        return bool(self.flags & FLAG_SEC_HDR)

    @property
    def crc_bad(self) -> bool:
        return bool(self.flags & FLAG_CRC_BAD)

    @property
    def armed(self) -> bool:
        return bool(self.flags & FLAG_ARMED)

    @property
    def accepted(self) -> bool:
        return self.result == 0x00

    @property
    def result_text(self) -> str:
        return RESULT.get(self.result, f"unknown ({self.result:#04x})")

    def __str__(self) -> str:
        where = f"{self.rssi_dbm:+.1f} dBm" if self.origin == "radio" else "cable"
        bits = "".join(c for c, on in (
            ("X", self.executed), ("E", self.secure), ("H", self.sec_hdr),
            ("C", self.crc_bad), ("A", self.armed)) if on) or "-"
        return (f"[{self.origin:5}] apid=0x{self.apid:03X} len={self.length:<4} "
                f"seq={self.sequence:<6} {where:>11}  {self.result_text} [{bits}]")


def parse_event(payload: bytes) -> BoardEvent:
    """Decode one APID 0x20 payload.

    Reads the first 15 octets and ignores anything after them: the format
    grows at the end and bumps `version` whenever an existing field changes
    meaning, so a longer v1 payload is still a v1 payload."""
    if len(payload) < EVENT_LEN:
        raise ValueError(f"event needs {EVENT_LEN} octets, got {len(payload)}")
    version = payload[0]
    if version != FORMAT_VERSION:
        raise UnknownEventVersion(
            f"event format v{version}; this build understands v{FORMAT_VERSION}. "
            "Refusing it rather than reading the wrong fields.")
    (origin, apid, length, sequence, rssi, snr,
     result, mode, flags) = struct.unpack(">BHHHhhBBB", payload[1:EVENT_LEN])
    return BoardEvent(
        version=version,
        origin=ORIGIN.get(origin, f"unknown({origin})"),
        apid=apid,
        length=length,
        sequence=sequence,
        rssi_dbm=rssi / 10.0,
        snr_db=snr / 10.0,
        result=result,
        mission_mode=mode,
        flags=flags,
    )


def build_event(*, origin: int = 0x01, apid: int = 0x001, length: int = 0,
                sequence: int = 0, rssi_dbm: float = 0.0, snr_db: float = 0.0,
                result: int = 0x00, mission_mode: int = 1,
                flags: int = 0, version: int = FORMAT_VERSION) -> bytes:
    """Only the tests and the replay generator need this. The board builds the
    real ones."""
    return struct.pack(">BBHHHhhBBB", version, origin, apid, length, sequence,
                       int(round(rssi_dbm * 10)), int(round(snr_db * 10)),
                       result, mission_mode, flags)
