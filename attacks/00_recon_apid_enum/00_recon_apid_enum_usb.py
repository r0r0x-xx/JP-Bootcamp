#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 00_recon_apid_enum_usb.py -- build a command map for a board nobody
# documented, over USB.
#
# You have the protocol and you do not have the command dictionary. That is
# the normal situation. The method is the lesson: vary one field at a time,
# record every response including silence, and keep the table.
#
# Reading the silence is the part that matters. A rejection WITH an error code
# means the packet parsed, so the shape was right and only the content was
# wrong. Silence means it was dropped earlier. The boundary between the two
# tells you where validation lives.
#
# SAFETY: the probe payload is four non-zero octets. A zero-length payload to
# BROADCAST_MSG (0x06) is attack 01's underflow, and a zero to
# SET_BEACON_RATE (0x05) is a beacon flood. Neither belongs in a sweep.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TM_NAMES  # noqa: E402

ERROR_TM = 0x09
PROBE = bytes([0x01, 0x01, 0x01, 0x01])

# Identifiers the sweep refuses to send, and why. A sweep that reboots the
# target maps nothing: RESETC answered the second probe by detaching the USB
# device, and every identifier after it then read as silent. That is how this
# sweep reported "0 of 12 answered" on hardware before 7 Nov 2026, while the
# board was in fact answering.
#
# Deciding what it is willing to send is part of what a recon tool is. The
# skipped ones are printed rather than quietly dropped, because a gap in the
# map the student is building has to be visible in the map.
SKIP = {
    0x02: "RESETC reboots the board and the rest of the sweep reads silence",
}


def classify(apid: int, replies) -> str:
    for p in replies:
        if p.apid == apid:
            return "answers"
        if p.apid == ERROR_TM:
            return "rejects"
    return "silent"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x01)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x18, help="inclusive")
    # The board services its USB output on a 1 Hz tick, so a reply lands up
    # to a second after the command. A 0.6 s window closed before the answer
    # arrived and every identifier read as silent.
    ap.add_argument("--listen", type=float, default=1.5)
    ap.add_argument("--cleartext", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    table = []
    with FlatSat(port=args.port, encrypt=not args.cleartext, verbose=False) as fsat:
        print("\n=== 1. who talks? two minutes of telemetry ===")
        for p in fsat.listen(5.0):
            if p.apid not in [t[0] for t in table]:
                print(f"    heard 0x{p.apid:03X}  {p.name}")

        print(f"\n=== 2. who listens? sweeping 0x{args.start:02X}..0x{args.end:02X} ===")
        for n, apid in enumerate(range(args.start, args.end + 1)):
            if apid in SKIP:
                table.append((apid, "not probed", 0))
                if not args.quiet:
                    print(f"  0x{apid:03X}  {TM_NAMES.get(apid, '?'):16} "
                          f"not probed  ({SKIP[apid]})")
                continue
            replies = fsat.send(apid, PROBE, seq=(n + 1) & 0x3FFF,
                                listen=args.listen)
            verdict = classify(apid, replies)
            table.append((apid, verdict, len(replies)))
            if not args.quiet:
                print(f"    0x{apid:03X}  {TM_NAMES.get(apid, '?'):16} {verdict}")
            time.sleep(0.05)

    print(f"\n{'APID':6} {'NAME':18} {'VERDICT':9} REPLIES")
    for apid, verdict, n in table:
        print(f"0x{apid:03X}  {TM_NAMES.get(apid, 'unknown'):18} {verdict:9} {n}")

    answers = [a for a, v, _ in table if v == "answers"]
    print(f"\n[+] {len(answers)} of {len(table)} identifiers answered.")
    print("Keep this table. Every attack after this one starts from it.")
    print("\nWhat the sensor should have shown: the rate of identifiers nobody "
          "implements.\nNo single probe looks wrong.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
