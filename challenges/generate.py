"""Build the capture files for labs 1.5 and 1.6.

The signal is synthesised, and the book says so. Nothing in this course
transmits, and the course firmware cannot, so there is no way to record the
FlatSat's link. What is synthesised are the samples; the parameters are the
board's real ones, read out of ruplink.h and rdownlink.h, and the frames
inside are real traffic captured off the bench over USB.

    downlink  916 MHz   BW 250 kHz   SF7   CR 4/5   sync 0x12
    uplink    918 MHz   BW 250 kHz   SF7   CR 4/5   sync 0x12

Two files, because the two labs want different things.

  01  for reading a spectrum: the signal sits off centre, the noise floor is
      real enough to have to look through, and the bursts are spaced. The
      student has to find it before measuring it.

  02  for demodulating: centred and cleaner, so the exercise is the decode
      chain rather than a fight with frequency offset.
"""
from gnuradio import gr, blocks, lora_sdr
import numpy as np, pickle, json, os, sys

SF, BW, CR, SYNC = 7, 250000, 1, [18]
SAMP = 500000                      # 2x bandwidth
OUT = sys.argv[1] if len(sys.argv) > 1 else "."

frames = pickle.load(open("real_frames.pkl", "rb"))
print(f"{len(frames)} tramas reales del banco")


def modulate(frame_list, path):
    open("tmp.hex", "w").write(",".join(f.hex() for f in frame_list) + ",")
    class TX(gr.top_block):
        def __init__(self):
            gr.top_block.__init__(self)
            self.connect(
                blocks.file_source(gr.sizeof_char, "tmp.hex", False),
                lora_sdr.whitening(True, False, ',', 'packet_len'),
                lora_sdr.header(False, True, CR),
                lora_sdr.add_crc(True),
                lora_sdr.hamming_enc(CR, SF),
                lora_sdr.interleaver(CR, SF, 2, BW),
                lora_sdr.gray_demap(SF),
                lora_sdr.modulate(SF, SAMP, BW, SYNC, 2**7, 8),
                blocks.file_sink(gr.sizeof_gr_complex, path, False))
    tb = TX(); tb.run()
    return np.fromfile(path, dtype=np.complex64)


def shape(iq, *, offset_hz, snr_db, gap_s, seed):
    """Put it where a recording would put it: off centre, in noise, bursty."""
    rng = np.random.default_rng(seed)
    n = len(iq)
    t = np.arange(n) / SAMP
    iq = iq * np.exp(2j * np.pi * offset_hz * t)        # frequency offset

    # Silence between bursts, so the waterfall shows structure in time.
    gap = np.zeros(int(gap_s * SAMP), dtype=np.complex64)
    out = np.concatenate([gap, iq, gap])

    sig_p = np.mean(np.abs(iq[np.abs(iq) > 0]) ** 2) if np.any(iq) else 1.0
    noise_p = sig_p / (10 ** (snr_db / 10))
    noise = (rng.normal(0, np.sqrt(noise_p / 2), len(out))
             + 1j * rng.normal(0, np.sqrt(noise_p / 2), len(out)))
    out = (out + noise).astype(np.complex64)
    return out / (np.max(np.abs(out)) * 1.05)           # headroom, no clipping


def sigmf(path, centre_hz, desc, extra):
    meta = {
        "global": {
            "core:datatype": "cf32_le",
            "core:sample_rate": float(SAMP),
            "core:version": "1.0.0",
            "core:description": desc,
            "core:author": "Starsec",
            "core:recorder": "gr-lora_sdr via GNU Radio 3.10",
        },
        "captures": [{"core:sample_start": 0, "core:frequency": float(centre_hz)}],
        "annotations": [{
            "core:sample_start": 0,
            "core:sample_count": os.path.getsize(path) // 8,
            "core:description": extra,
        }],
    }
    with open(path.replace(".cf32", ".sigmf-meta"), "w") as f:
        json.dump(meta, f, indent=2)


def neighbour(n, *, offset_hz, period_s, on_s, amp, seed):
    """A second emitter, because real ISM spectrum is not empty and finding
    the right signal is most of the exercise. Narrowband, bursty, and nothing
    to do with the spacecraft."""
    rng = np.random.default_rng(seed)
    t = np.arange(n) / SAMP
    dev = 8000.0
    sym = rng.integers(0, 2, size=int(n / (SAMP / 2400)) + 1) * 2 - 1
    idx = np.minimum((t * 2400).astype(int), len(sym) - 1)
    phase = np.cumsum(2 * np.pi * (offset_hz + dev * sym[idx]) / SAMP)
    carrier = amp * np.exp(1j * phase)
    duty = ((t % period_s) < on_s).astype(np.float32)
    return (carrier * duty).astype(np.complex64)


# ---- 01: for the waterfall -------------------------------------------------
raw = modulate(frames, "tmp01.cf32")
a = shape(raw, offset_hz=+117_000, snr_db=12, gap_s=0.05, seed=11)
a = (a + neighbour(len(a), offset_hz=-168_000, period_s=0.11,
                   on_s=0.022, amp=0.22, seed=5)).astype(np.complex64)
a = a / (np.max(np.abs(a)) * 1.05)
p = os.path.join(OUT, "01_downlink_916MHz.cf32")
a.tofile(p)
sigmf(p, 916_000_000,
      "FlatSat downlink, synthesised at the link's real parameters and "
      "carrying frames captured from the bench over USB.",
      "The signal is not at the centre of the band. Find it before you measure it.")
print(f"  01  {os.path.getsize(p)/1e6:.1f} MB  offset +117 kHz  SNR 12 dB")

# ---- 02: for the decode ----------------------------------------------------
b = shape(raw, offset_hz=0, snr_db=25, gap_s=0.02, seed=22)
p = os.path.join(OUT, "02_downlink_916MHz_decode.cf32")
b.tofile(p)
sigmf(p, 916_000_000,
      "The same downlink, centred and with a cleaner noise floor, for the "
      "demodulation exercise.",
      "Centred on the carrier. Feed it to the gr-lora_sdr receiver.")
print(f"  02  {os.path.getsize(p)/1e6:.1f} MB  centrado  SNR 25 dB")

for f in ("tmp.hex", "tmp01.cf32"):
    try: os.remove(f)
    except OSError: pass
