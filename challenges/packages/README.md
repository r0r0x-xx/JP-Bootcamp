# The LoRa receiver, prebuilt

Lab 1.6 demodulates a recorded capture back to frames. It does that with
[`gr-lora_sdr`](https://github.com/tapparelj/gr-lora_sdr), which is a GNU
Radio out-of-tree module and **is not in the Ubuntu archive**.

The alternative was to have everybody compile it on the morning of the
workshop. That is a few minutes per machine when it works, and an open-ended
problem when it does not, so the module ships here already built.

```sh
./install-lora.sh
```

The script reads your release and your architecture and installs the matching
package. Nothing is compiled on your machine. If there is no package for your
combination it says so and prints the commands to build from source, which
still works.

---

## Why there are 6 of them and not one

The module links against GNU Radio's runtime library, and **every Ubuntu
release ships a different one**:

| Ubuntu | Architecture | Package | Size | Links against |
|---|---|---|---|---|
| 22.04 | `amd64` | `gr-lora-sdr_0.0.1+git862746d-ubuntu22.04_amd64.deb` | 270 KB | `libgnuradio-runtime3.10.1` |
| 22.04 | `arm64` | `gr-lora-sdr_0.0.1+git862746d-ubuntu22.04_arm64.deb` | 266 KB | `libgnuradio-runtime3.10.1` |
| 24.04 | `amd64` | `gr-lora-sdr_0.0.1+git862746d-ubuntu24.04_amd64.deb` | 281 KB | `libgnuradio-runtime3.10.9t64` |
| 24.04 | `arm64` | `gr-lora-sdr_0.0.1+git862746d-ubuntu24.04_arm64.deb` | 239 KB | `libgnuradio-runtime3.10.9t64` |
| 26.04 | `amd64` | `gr-lora-sdr_0.0.1+git862746d-ubuntu26.04_amd64.deb` | 306 KB | `libgnuradio-runtime3.10.12` |
| 26.04 | `arm64` | `gr-lora-sdr_0.0.1+git862746d-ubuntu26.04_arm64.deb` | 251 KB | `libgnuradio-runtime3.10.12` |

A package built against one of those will not satisfy its dependency on
another, so a single `.deb` cannot cover the three releases. The Python
bindings are release-specific too: they are compiled against the interpreter
that release carries, which is 3.10, 3.12 and 3.14 respectively.


### SHA-256

```
0ad6ff5064ee67f54e79e34498d21e69a57d603d0acaf53f8c7a708a3848fa4a  gr-lora-sdr_0.0.1+git862746d-ubuntu22.04_amd64.deb
961ae5433869c1e20f8f16bf48eb4133a09e6c1adae1cdb76c4b3b27fcee998a  gr-lora-sdr_0.0.1+git862746d-ubuntu22.04_arm64.deb
79fbab399933f6e9e5f3507dd084434dfff2ccc90d4abb458ae05b6699106545  gr-lora-sdr_0.0.1+git862746d-ubuntu24.04_amd64.deb
58868c488180e926920a78954e638118d40629f0f51ab95471754e8275dd105f  gr-lora-sdr_0.0.1+git862746d-ubuntu24.04_arm64.deb
08cc3c28a724f0d7935112a0796f01d5c5f6a2b846293d4015fab6fd732dd864  gr-lora-sdr_0.0.1+git862746d-ubuntu26.04_amd64.deb
272fc24e642af322adf6b724077062ac7457d9296c0ea6361d0405026fdf4ba5  gr-lora-sdr_0.0.1+git862746d-ubuntu26.04_arm64.deb
```

---

## What is inside

Each package installs, under `/usr`:

- `libgnuradio-lora_sdr.so`, the blocks themselves
- the Python bindings, in `/usr/lib/python3/dist-packages/gnuradio/lora_sdr/`
- the GNU Radio Companion block definitions, so the blocks appear in the GUI
- the upstream example flowgraphs, under `/usr/share/gnuradio/examples/`

It declares `gnuradio` as a dependency, so `apt` pulls GNU Radio in on a
machine that has never had it.

**One thing worth knowing about the install path.** GNU Radio's build system
puts Python modules in `<prefix>/lib/pythonX.Y/site-packages` by default.
Debian and Ubuntu do not search that directory for system packages; they
search `dist-packages`. A package built with the default lands a module that
imports nowhere, installs without an error, and fails only when the lab
starts. These are built with `-DGR_PYTHON_DIR=/usr/lib/python3/dist-packages`
for that reason.

---

## How they were built

From upstream commit [`862746d`](https://github.com/tapparelj/gr-lora_sdr/commit/862746dd1cf635c9c8a4bfbaa2c3a0ec3a5306c9),
in a clean container of each release, with no patches:

```sh
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX=/usr \
         -DGR_PYTHON_DIR=/usr/lib/python3/dist-packages \
         -DENABLE_DOXYGEN=OFF
make -j$(nproc)
make DESTDIR=/stage install
dpkg-deb --root-owner-group --build /stage
```

The build scripts are in `Bootcamp/packaging/` in the course working tree,
not in this repository: `build-deb.sh` builds one, `build-all.sh` builds the
matrix, and `make-readme.py` writes this file from the packages it finds.

Each package was installed into a clean container of its own release and
checked two ways: that `from gnuradio import lora_sdr` works and exposes the
whole receive chain, and that it decodes `01_downlink_916MHz.cf32` to the
**28 CCSDS packets** that are known to be in it.

---

## Licence

`gr-lora_sdr` is GPLv3, by Joachim Tapparel at EPFL's Telecommunication
Circuits Laboratory. These packages are an unmodified build of the upstream
source and carry the same licence. Upstream is the place to report bugs in
the blocks; the packaging is ours.
