#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 03_gps_spoofing_usb.py -- give the platform a position it cannot verify, and
# watch a permission change that should not depend on it.
#
# The real attack is over the air, against the u-blox receiver, and it has no
# USB equivalent because it attacks a separate piece of hardware. With the
# radio held in reset there is no way to run it, so the course firmware
# accepts a position on the cable instead, at the same trust boundary:
#
#     GPS_OVERRIDE (0x14), course build only
#     payload: latE7 (i32 LE), lonE7 (i32 LE), altCm (i32 LE), satellites (u8)
#
# The lesson is unchanged and it is not about radio. Navigation and
# authorisation get wired together because it is convenient, and a wrong fix
# then becomes a permission. Nothing downstream can tell this fix from a real
# one, which is the point.
#
# Requires the course build. On stock firmware this APID does not exist and
# the board answers with an error.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_GPS_OVERRIDE, TC_GET_NAV  # noqa: E402


def payload(lat: float, lon: float, alt_m: float, sats: int) -> bytes:
    return (int(round(lat * 1e7)).to_bytes(4, "little", signed=True)
            + int(round(lon * 1e7)).to_bytes(4, "little", signed=True)
            + int(round(alt_m * 100)).to_bytes(4, "little", signed=True)
            + bytes([sats & 0xFF]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--lat", type=float, default=35.6895, help="Tokyo by default")
    ap.add_argument("--lon", type=float, default=139.6917)
    ap.add_argument("--alt", type=float, default=40.0, help="metres")
    ap.add_argument("--sats", type=int, default=11)
    ap.add_argument("--ramp", type=int, default=0,
                    help="walk this many steps toward the target instead of jumping")
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--cleartext", action="store_true")
    args = ap.parse_args()

    with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
        print("\n=== 1. where does it think it is? ===")
        fsat.send(TC_GET_NAV, b"", seq=args.seq, listen=1.2)

        if args.ramp:
            print(f"\n=== 2. walking there in {args.ramp} steps ===")
            print("    (a ramp is how you find the rate at which a plausibility "
                  "check would stop you)")
            for i in range(1, args.ramp + 1):
                lat = args.lat * i / args.ramp
                lon = args.lon * i / args.ramp
                fsat.send(TC_GPS_OVERRIDE, payload(lat, lon, args.alt, args.sats),
                          seq=(args.seq + i) & 0x3FFF, listen=0.4)
                time.sleep(0.2)
        else:
            print(f"\n=== 2. one jump to {args.lat}, {args.lon} ===")
            fsat.send(TC_GPS_OVERRIDE, payload(args.lat, args.lon, args.alt, args.sats),
                      seq=args.seq + 1, listen=1.2)

        print("\n=== 3. where does it think it is now? ===")
        fsat.send(TC_GET_NAV, b"", seq=args.seq + 90, listen=1.2)

    print("\nRecord how fast the position had to move. That number is the "
          "detection,\nand it is the whole of the defensive half of this lab.")
    print("\nWhat the sensor should have shown: a fix that moved further than "
          "anything in orbit could have moved between two reports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
