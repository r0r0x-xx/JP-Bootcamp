#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# reset_bench.py -- put the FlatSat back to the state every lab assumes.
#
# Every attack assumes a clean bench and none of them leave one: lab 03 leaves
# the spoofed position, lab 04 leaves the gate closed with no session, lab 07
# leaves the secure link off.
#
# The clean state:
#
#   secure link   on     -- the attacks open with encrypt=True
#   gs mode       off    -- with the mode off the gate does not apply, so each
#                           lab can set up whatever gate state it needs
#   position      Tokyo  -- COURSE_GPS_* in sensors.cpp, the firmware default
#
# Two obstacles, both found running this against a used board:
#
#   1. The board may be listening in cleartext, because lab 07 left the secure
#      link off, so the encryption state is discovered rather than assumed.
#
#   2. The gate may be shut. With the mode on, no session and the position out
#      of range, every gated command is refused, GS_MODE included: a complete
#      lockout. The way out is the door the firmware leaves open on purpose,
#      SPP_APID_TC_GS_ACCESS being exempt from the gate (worker.cpp:424). So
#      the reset runs lab 04's handshake with the same key, and the session it
#      opens is what lets the rest of the commands land.

import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from flatsat import (FlatSat, TC_AES_CONFIG, TC_DEBUG_CONFIG, TC_GS_ACCESS,  # noqa: E402
                     TC_GS_STATUS)
import benchstate as B  # noqa: E402

CLEAN_POSITION = B.TOKYO

#: worker.cpp:148. The gate's whole challenge-response is an exclusive-or with
#: this constant, which is lab 04's finding and this script's back door.
GS_AUTH_KEY = 0xC0DEFACE


def _talking(fs: FlatSat) -> bool:
    st = B.read_state(fs, tries=2)
    return st.latitude is not None or st.gs_mode is not None


def _open_session(fs: FlatSat, *, verbose: bool = True) -> bool:
    """Complete the ground-station handshake, so gated commands land.

    Returns True when a session is open. The two frames are the ones lab 04
    sends; the challenge sits at octet 5 of the GS_ACCESS reply, little endian,
    behind the spacecraft id, the phase, the auth state and two status octets.
    """
    def say(*a):
        if verbose:
            print(*a)

    replies = fs.send(TC_GS_ACCESS, b"\x00", seq=20, listen=1.5)
    challenge = None
    for p in replies:
        body = fs.plaintext(p)
        if p.apid == TC_GS_ACCESS and len(body) >= 9:
            challenge = struct.unpack_from("<I", body, 5)[0]
    if challenge is None:
        say("  [!] the gate issued no challenge. Power-cycle the board.")
        return False

    resp = challenge ^ GS_AUTH_KEY
    say(f"  [*] gate was shut; opened a session "
        f"(challenge 0x{challenge:08X})")
    fs.send(TC_GS_ACCESS, b"\x01" + resp.to_bytes(4, "big"),
            seq=21, listen=1.5)
    time.sleep(0.2)
    return True


def _is_locked_out(st) -> bool:
    """True when the gate is up and nothing gated will land."""
    if st.gs_mode is not True:
        return False
    if st.session_open:
        return False
    return True


def reset(verbose: bool = True) -> bool:
    """Leave the board in the state the labs assume. True if it took."""
    def say(*a):
        if verbose:
            print(*a)

    for encrypt in (True, False):
        with FlatSat(verbose=False, encrypt=encrypt) as fs:
            if not _talking(fs):
                continue
            say(f"  [*] the board is listening in "
                f"{'ciphertext' if encrypt else 'cleartext'}")
            st = B.read_state(fs)
            say("  [*] before:", st)

            if _is_locked_out(st):
                if not _open_session(fs, verbose=verbose):
                    return False

            B.set_gs_mode(fs, False, seq=1)
            B.set_position(fs, CLEAN_POSITION, seq=2)
            fs.send(TC_AES_CONFIG, b"\x01", seq=3, encrypt=encrypt, listen=2.0)

            # USB debug off, and it matters more than it looks.
            # mission_ctx.usbDebugEnabled makes the board bypass the secure
            # link entirely (worker.cpp:707), so while it is on every
            # encrypted command is read as cleartext and lands as garbage.
            #
            # Lab 1.8 turns it on as a side effect: the identifier sweep
            # probes DEBUG_CONFIG like any other APID, and that flips it. A
            # student who runs recon and then an encrypted lab gets failures
            # that look like a broken lab.
            #
            # It goes LAST on purpose. The gate-exemption-chain rule fires on
            # DEBUG_CONFIG followed by GS_MODE inside a window, which is lab
            # 2.8's finding. Clearing the flag before the gate would trip
            # that rule on every reset and teach the room to ignore a critical
            # alert.
            fs.send(TC_DEBUG_CONFIG, b"\x00", seq=4, encrypt=encrypt, listen=1.5)
            time.sleep(0.3)

        # The link may have just changed under us, so the check reconnects
        # with encryption on, which is the state this is meant to leave.
        with FlatSat(verbose=False, encrypt=True) as fs:
            st = B.read_state(fs)
            say("  [*] after: ", st)
            ok = (st.latitude is not None
                  and abs(st.latitude - 35.7122) < 0.01)
            say("  [+] bench clean" if ok
                else "  [!] the position did not go back")
            return ok

    say("  [!] the board did not answer in either mode. Power-cycle it:")
    say("      unplug the USB cable, count to three, plug it back in.")
    return False


if __name__ == "__main__":
    raise SystemExit(0 if reset() else 1)
