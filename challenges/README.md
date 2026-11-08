# Challenges: the captures labs 1.5 and 1.6 work on

Two files, one signal, two exercises. What lab 1.5 measures is what lab 1.6
needs, so they are meant to be done in order.

| File | Lab | What it is |
|---|---|---|
| `01_downlink_916MHz.cf32` | **1.5** and **1.6** | The capture. The spacecraft's downlink, off centre, in noise, with another emitter in the band |
| `02_downlink_916MHz_decode.cf32` | 1.6, if you are stuck | The same traffic, centred and cleaner. A known-good file so nobody is blocked |
| `03_frames_ccsds.bin` | **1.7** | What lab 1.6 recovers: 661 octets, 28 CCSDS packets end to end. Shipped so lab 1.7 runs even if your demodulation did not |

Each `.cf32` has a `.sigmf-meta` beside it. That is [SigMF](https://sigmf.org),
the standard sidecar: it carries the sample rate and the centre frequency so
they travel with the file instead of living in somebody's head. Every tool
below reads the `.cf32` directly; the metadata is for you.

```
format        complex float32, interleaved I/Q, little endian
sample rate   500 kHz
centre        916 MHz
```

---

## Where this came from, exactly

**The samples are synthesised. The parameters and the frames are real.**

Nothing in this course transmits, and the course firmware cannot: the radio
driver is not compiled into it. So there is no way to record the FlatSat's
link, and these files were built rather than captured. Saying that plainly
matters more than the files looking authentic.

What is real:

**The link parameters**, read out of the firmware source
(`firmware/Firmware/rdownlink.h` and `ruplink.h`):

| | |
|---|---|
| Downlink | **916 MHz**, BW **250 kHz**, SF **7**, CR **4/5**, sync word **0x12** |
| Uplink | 918 MHz, same modulation |

**The frames inside**: 28 CCSDS packets captured off a real board over USB,
through the Space IDS, on 8 November 2026. Beacon pings, a telemetry dump, a
status reply, a navigation report and three IDS events. Nothing invented.

**The modulation**: generated with
[`gr-lora_sdr`](https://github.com/tapparelj/gr-lora_sdr), the same LoRa
implementation you decode it with. Regenerate it yourself with `generate.py`
if you want to see how.

---

## Setting up, on Ubuntu

```sh
sudo apt update
sudo apt install -y inspectrum gnuradio git cmake build-essential
```

`inspectrum` is the spectrum and waterfall viewer for lab 1.5. It is in the
Ubuntu archive for 22.04, 24.04 and 26.04.

For lab 1.6 you need the LoRa receiver, which is not packaged:

```sh
git clone https://github.com/tapparelj/gr-lora_sdr.git
cd gr-lora_sdr && mkdir build && cd build
cmake .. && make -j$(nproc) && sudo make install && sudo ldconfig
```

---

## Lab 1.5, reading a spectrum and a waterfall

```sh
inspectrum challenges/01_downlink_916MHz.cf32
```

Set the sample rate to **500000** in the toolbar. Nothing else is configured
for you.

What you are looking for, in order:

1. **There is more than one signal.** Find both. One is the spacecraft and
   one is not, and deciding which is which is the exercise.
2. **Where is the spacecraft's signal?** Measure its offset from the centre of
   the band. You will need that number in lab 1.6, so write it down.
3. **How wide is it?** Drag a selection across it and read the bandwidth.
   Compare against the table above.
4. **What are those diagonal lines?** A chirp that sweeps up across the whole
   bandwidth and wraps. That shape is what makes LoRa recognisable on a
   waterfall at a glance.
5. **How long is one chirp?** From the symbol duration and the bandwidth you
   can derive the spreading factor: `T = 2^SF / BW`. Check your answer against
   the table.
6. **What is the burst structure?** Count the identical chirps at the start of
   a burst. That is the preamble, and its length is a parameter too.

You are done when you can state the offset, the bandwidth and the spreading
factor from the picture alone, without having read them here first.

---

## Lab 1.6, demodulating a capture back to frames

Use the offset you measured. The receiver expects the signal at baseband
centre, so shift it there first:

```python
import numpy as np
SAMP   = 500_000
OFFSET = ...            # the number you measured in lab 1.5

iq = np.fromfile("01_downlink_916MHz.cf32", dtype=np.complex64)
t  = np.arange(len(iq)) / SAMP
(iq * np.exp(-2j*np.pi*OFFSET*t)).astype(np.complex64).tofile("centred.cf32")
```

Then run the receiver:

```python
from gnuradio import gr, blocks, lora_sdr

class RX(gr.top_block):
    def __init__(self, path):
        gr.top_block.__init__(self)
        self.sink = blocks.vector_sink_b()
        self.connect(
            blocks.file_source(gr.sizeof_gr_complex, path, False),
            lora_sdr.lora_sdr_lora_rx(
                bw=250000, cr=1, has_crc=True, impl_head=False,
                pay_len=255, samp_rate=500000, sf=7, sync_word=[18],
                center_freq=916000000, print_rx=[False, False]),
            self.sink)

tb = RX("centred.cf32"); tb.run()
data = bytes(tb.sink.data())
print(len(data), "octets")
```

**Expected: 661 octets.** If you get zero, your offset is wrong by enough to
matter. Go back to inspectrum, measure again, and note how little error it
takes to lose the signal entirely.

Then take those octets apart as CCSDS, the way lab 1.8 taught: six octets of
primary header, DATA LENGTH being octets minus one, and the APID straddling
two octets. You should find 28 packets across five application identifiers.

If you want to check your answer, `02_downlink_916MHz_decode.cf32` is the same
traffic already centred. Decode that and compare.

---

## Regenerating these files

```sh
cd challenges && python3 generate.py .
```

It needs GNU Radio with `gr-lora_sdr`, and `real_frames.pkl`, which is the
captured bench traffic. The script documents its own choices: the frequency
offset, the signal-to-noise ratio, the burst spacing and the second emitter.

---

## `03_frames_ccsds.bin`, and what you can read in it

661 octets, 28 packets, five application identifiers. It is byte for byte what
lab 1.6 produces, so you can start lab 1.7 whether or not your receiver
worked.

**The headers are in clear and the payloads are not.** That split is the point
of lab 1.7 rather than an inconvenience: a spacecraft has to be routable by
whoever receives it, so version, type, APID, sequence count and length all
travel readable. What is inside is a different decision.

| APID | | Payload |
|---|---|---|
| `0x001` | PING | AES-128-ECB |
| `0x008` | SEND_TM | AES-128-ECB |
| `0x00C` | STATUS | AES-128-ECB |
| `0x00E` | NAV | AES-128-ECB |
| `0x020` | IDS_EVENT | **in clear** |

The one that opens is the board's own event channel, and it is in clear on
purpose. The detector sits between the spacecraft and the ground console; if
it needed the spacecraft's key to read what the board reports, then losing
that key would blind the detection as well as the link.

So the events carry facts about a frame and never its contents. The
identifier, the length, where it arrived from, whether it was accepted.
Enough to detect, not enough to decrypt.

The rest opens in **lab 1.9**, where the key comes off the firmware image
rather than off the wire.
