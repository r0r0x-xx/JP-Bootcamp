#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 06_resetc_usb.py -- the command with no undo, and the gap between being
# detectable and being too late.
#
# RESETC (0x02) reboots the flight computer. On a bench that is a nuisance; in
# orbit a reboot during a pass costs the rest of the pass, and the next
# contact may be hours away. A reboot loop costs every pass until somebody
# uplinks a fix, and uplinking needs a working receiver.
#
# **This is the reversible stand-in.** It is deliberately not the irreversible
# command, and no script here sends one. What is being measured is the gap
# between the first moment a defender could have known and the moment the
# effect could no longer be undone, and a reboot shows that faithfully.
#
# Expected: the CDC port drops and re-enumerates, and the uptime in STATUS
# goes back to zero.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_RESETC, TC_GET_STATUS  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--cleartext", action="store_true")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation")
    args = ap.parse_args()

    if not args.yes:
        print("This reboots the board. The port will drop and come back.")
        if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            return 1

    t0 = time.time()
    try:
        with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
            print("\n=== 1. uptime before ===")
            fsat.send(TC_GET_STATUS, b"", seq=args.seq, listen=1.2)

            print("\n=== 2. RESETC. No authentication, no acknowledgement, no undo ===")
            sent_at = time.time()
            fsat.send(TC_RESETC, b"", seq=args.seq + 1, listen=1.5)
    except Exception as exc:
        sent_at = time.time()
        print(f"[+] the link dropped ({type(exc).__name__}) -- that is the reboot.")

    print(f"\n[*] command sent at T+{sent_at - t0:.1f}s")
    print("[*] waiting for the board to come back...")
    for attempt in range(20):
        time.sleep(1.0)
        try:
            with FlatSat(port=None, encrypt=not args.cleartext, verbose=False) as fsat:
                replies = fsat.send(TC_GET_STATUS, b"", seq=1, listen=1.0)
                if replies:
                    back = time.time()
                    print(f"[+] back at T+{back - t0:.1f}s "
                          f"({back - sent_at:.1f}s of silence)")
                    break
        except Exception:
            print(f"    still gone ({attempt + 1}s)")
    else:
        print("[!] it did not come back. Replug it.")

    print("\nNow the only question that matters: how long before a human would "
          "have known,\nand was that before or after the effect could no longer "
          "be undone?")
    print("\nFor this class of command the alert is correct, fast, and too "
          "late. Prevention is the only meaningful control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
