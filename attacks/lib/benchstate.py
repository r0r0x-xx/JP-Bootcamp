"""What state the board is in, asked rather than assumed.

Every lab on day 2 starts from a board state: where it says it is, whether
ground-station mode is on, and whether a session is open. Nothing in the kit
used to check any of that, so a lab that ran after one that moved the position
failed for a reason its own output could not explain.

Reads are retried, because one silent window is not an answer: the board
answers on a 1 Hz cycle and a reply that misses its window is not a refusal.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Optional

from flatsat import FlatSat

TC_GET_STATUS = 0x0C
TC_GET_NAV = 0x0E
TC_GS_MODE = 0x11
TC_GPS_OVERRIDE = 0x14
TM_ERROR = 0x09

# Where the course firmware says it is at boot, and where the authorising
# ground station sits. 830 km apart, so the gate starts closed.
TOKYO = (357122000, 1397038000, 3500, 11)
SAPPORO = (430618000, 1413545000, 2000, 11)


@dataclass
class BenchState:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    gs_mode: Optional[bool] = None
    session_open: Optional[bool] = None
    last_error: str = ""

    def __str__(self) -> str:
        where = ("unknown" if self.latitude is None
                 else f"{self.latitude:.4f},{self.longitude:.4f}")
        return (f"position={where} gs_mode={self.gs_mode} "
                f"session={self.session_open} last_error={self.last_error or '-'}")


def _errors(fs: FlatSat, replies) -> str:
    out = []
    for p in replies:
        if p.apid == TM_ERROR and p.payload:
            out.append(fs.plaintext(p).split(b"\x00")[0].decode("ascii", "replace"))
    return " | ".join(out)


def read_state(fs: FlatSat, tries: int = 3) -> BenchState:
    st = BenchState()

    for _ in range(tries):
        r = fs.send(TC_GET_NAV, b"\x00", seq=1, listen=2.5)
        for p in r:
            body = fs.plaintext(p)
            if p.apid == TC_GET_NAV and len(body) >= 15:
                lat, lon, _alt = struct.unpack_from("<iii", body, 3)
                st.latitude, st.longitude = lat / 1e7, lon / 1e7
        err = _errors(fs, r)
        if err:
            st.last_error = err
        if st.latitude is not None or err:
            break
        time.sleep(0.4)

    # A gated command answering means the gate is open: either the mode is off,
    # or it is on and a session is live. The error says which.
    for _ in range(tries):
        r = fs.send(TC_GET_STATUS, b"\x00", seq=2, listen=2.5)
        answered = any(p.apid == TC_GET_STATUS for p in r)
        err = _errors(fs, r)
        if answered:
            st.session_open = True
            st.gs_mode = None            # open: cannot tell mode from this alone
            return st
        if "AUTH REQUIRED" in err:
            st.gs_mode, st.session_open, st.last_error = True, False, err
            return st
        if "RANGE LOCK" in err or "GPS" in err:
            st.gs_mode, st.session_open, st.last_error = True, False, err
            return st
        if err:
            st.last_error = err
        time.sleep(0.4)

    return st


def set_position(fs: FlatSat, where=TOKYO, seq: int = 1) -> None:
    """Only works while the gate is open. GPS_OVERRIDE is a gated command, so
    with the mode on and no session it is refused like any other."""
    lat, lon, alt, sats = where
    fs.send(TC_GPS_OVERRIDE, struct.pack("<iii", lat, lon, alt) + bytes([sats]),
            seq=seq, listen=2.5)


def set_gs_mode(fs: FlatSat, on: bool, seq: int = 1) -> None:
    fs.send(TC_GS_MODE, bytes([1 if on else 0]), seq=seq, listen=2.5)
