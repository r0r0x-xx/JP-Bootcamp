#!/usr/bin/env python3
"""Lab 1.6: take a recorded capture back to frames.

Shifts the signal to baseband, runs it through the LoRa receiver, and parses
what comes out as CCSDS Space Packets. You supply the numbers you measured in
lab 1.5; nothing here guesses them for you.

    python3 challenges/rx.py challenges/01_downlink_916MHz.cf32 --offset 117000

Nothing transmits. This reads a file.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

APIDS = {0x01: "PING", 0x08: "SEND_TM", 0x0C: "STATUS",
         0x0E: "NAV", 0x20: "IDS_EVENT"}


def sigmf_sample_rate(capture: pathlib.Path):
    """The sidecar carries the sample rate so it travels with the file."""
    meta = capture.with_suffix(".sigmf-meta")
    if not meta.exists():
        return None
    try:
        return float(json.loads(meta.read_text())["global"]["core:sample_rate"])
    except (ValueError, KeyError):
        return None


def shift_to_baseband(capture, offset_hz, samp_rate, out):
    import numpy as np

    iq = np.fromfile(capture, dtype=np.complex64)
    if iq.size == 0:
        sys.exit(f"{capture}: no samples. Wrong file, or not complex float32.")
    if offset_hz:
        t = np.arange(iq.size) / samp_rate
        iq = iq * np.exp(-2j * np.pi * offset_hz * t)
    iq.astype(np.complex64).tofile(out)
    return iq.size


def demodulate(path, *, samp_rate, bw, sf, cr, sync_word, centre):
    from gnuradio import gr, blocks, lora_sdr

    class RX(gr.top_block):
        def __init__(self):
            gr.top_block.__init__(self)
            self.sink = blocks.vector_sink_b()
            self.connect(
                blocks.file_source(gr.sizeof_gr_complex, str(path), False),
                lora_sdr.lora_sdr_lora_rx(
                    bw=bw, cr=cr, has_crc=True, impl_head=False,
                    pay_len=255, samp_rate=samp_rate, sf=sf,
                    sync_word=[sync_word], center_freq=int(centre),
                    print_rx=[False, False]),
                self.sink)

    tb = RX()
    tb.run()
    return bytes(tb.sink.data())


def parse_ccsds(data):
    """Six octets of primary header, DATA LENGTH being octets minus one."""
    rest, seen, total_packets = data, {}, 0
    while len(rest) >= 6:
        ident = int.from_bytes(rest[0:2], "big")
        length = int.from_bytes(rest[4:6], "big")
        total = 6 + length + 1
        if total > len(rest):
            break
        apid = ident & 0x7FF
        seen[apid] = seen.get(apid, 0) + 1
        total_packets += 1
        rest = rest[total:]
    return seen, total_packets, len(rest)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", type=pathlib.Path)
    ap.add_argument("--offset", type=float, required=True,
                    help="frequency offset in Hz, as you measured it in lab 1.5")
    ap.add_argument("--bw", type=int, default=250000, help="bandwidth in Hz")
    ap.add_argument("--sf", type=int, default=7, help="spreading factor")
    ap.add_argument("--cr", type=int, default=1,
                    help="coding rate, 1 to 4. 1 is 4/5")
    ap.add_argument("--samp-rate", type=float, default=None,
                    help="samples per second. Read from the SigMF sidecar if omitted")
    ap.add_argument("--sync-word", type=lambda s: int(s, 0), default=0x12)
    ap.add_argument("--centre", type=float, default=916e6)
    ap.add_argument("--keep", action="store_true",
                    help="keep the shifted file instead of deleting it")
    args = ap.parse_args()

    if not args.capture.exists():
        sys.exit(f"{args.capture}: not found. Paths are relative to the "
                 f"repository root, not to the directory you are in.")

    samp = args.samp_rate or sigmf_sample_rate(args.capture)
    if samp is None:
        sys.exit("no --samp-rate given and no SigMF sidecar beside the capture.")

    shifted = args.capture.with_name("centred.cf32")
    n = shift_to_baseband(args.capture, args.offset, samp, shifted)
    print(f"{n} samples, shifted by {args.offset/1000:+.1f} kHz")

    data = demodulate(shifted, samp_rate=samp, bw=args.bw, sf=args.sf,
                      cr=args.cr, sync_word=args.sync_word, centre=args.centre)
    if not args.keep:
        shifted.unlink(missing_ok=True)

    print(f"{len(data)} octets recovered")
    if not data:
        sys.exit("\nNothing came out. The offset is the usual reason: the "
                 "receiver needs the signal at the centre of the band, and it "
                 "has no tolerance worth relying on. Re-read your measurement "
                 "from lab 1.5, and try being wrong by five kilohertz on "
                 "purpose to see how sharp the edge is.")

    seen, packets, leftover = parse_ccsds(data)
    for apid, count in sorted(seen.items()):
        print(f"  0x{apid:03X}  {APIDS.get(apid, '?'):10} x{count}")
    print(f"{packets} packets, {len(seen)} identifiers")
    if leftover:
        print(f"{leftover} octets left over, which is a truncated final packet")


if __name__ == "__main__":
    main()
