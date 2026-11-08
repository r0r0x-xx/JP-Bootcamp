"""Self-contained USB transport for the FlatSat, for the attack scripts here.

Everything the bench needs travels in `Bench/`: no imports out of this tree, so
the kit works on a laptop that has never seen the wider project.

**It deliberately does not share a codec with the IDS.** A detector that parses
frames with the attacker's own parser cannot catch a frame the parser gets
wrong. Two independent implementations is the point, not duplication to tidy up.

APIDs and the AES wrapper are taken from the firmware (`mission.h`) and from
`pwnsat_crypto.py`, byte for byte.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional

import serial
import serial.tools.list_ports

BAUD = 921600

# How a FlatSat announces itself on USB. Same pair the IDS matches on, so both
# halves of the bench agree on what a board is.
FLATSAT_VID_PID = (0x239A, 0xCAFE)

# Opening a CDC-ACM port asserts DTR, and the board needs a moment before it
# will answer. Without the wait the first frame written is dropped: measured on
# hardware 7 Nov 2026, where a single probe answered correctly about half the
# time and the first command after open() was lost on every run.
PORT_SETTLE_S = 0.35
PROBE_ATTEMPTS = 4

# The board serves its USB output on a 1 Hz tick, so a reply lands about a
# second after the command: 1.007, 1.014, 1.010, 1.008 s across consecutive
# commands, measured 7 Nov 2026. The first command after the port opens is
# different, and waits for the board to come up to speed: 2.67 s on that same
# run. A window below either number reads silence and reports a board that
# answers nothing, which is how the flash-read lab failed on its first step
# every single time.
BOARD_TICK_S = 1.0
WARMUP_TIMEOUT_S = 5.0

# The first command on a fresh connection costs more than the ones after it:
# 2.67 s against a steady 1.01 s, and waiting longer before sending does not
# move it, so the cost belongs to that first command and not to the port.
# It is paid once, in its window, instead of being charged to every send.
FIRST_COMMAND_S = 4.0

# A script that starts while the previous one's telemetry is still arriving
# reads that backlog as its own answers. reset_input_buffer clears the host
# side only; the board keeps sending for seconds afterwards. So wait for the
# line to go quiet before the first command, and give up waiting rather than
# refuse to run on a board that chatters by itself.
QUIET_FOR_S = 0.5
QUIESCE_TIMEOUT_S = 6.0

# With the sensor in line it owns the serial port, so the attacks reach the
# board through it rather than around it. That is the point of the bench: the
# alert arrives while the attack runs. The sensor speaks the board's framing
# on this socket, so nothing above this line changes.
DEFAULT_IDS_ENDPOINT = "127.0.0.1:5010"
SYNC = 0xAA
TC_PREFIX = b"\xAA\x55"
SPP_HEADER = 6

# --- telecommands, from mission.h -------------------------------------------
TC_PING = 0x01
TC_RESETC = 0x02
TC_SEND_FW = 0x03
TC_SET_THRUSTER = 0x04
TC_SET_BEACON_RATE = 0x05
TC_BROADCAST_MSG = 0x06
TC_FLASH = 0x07
TC_AES_CONFIG = 0x0A
TC_FLASH_READ = 0x0B
TC_GET_STATUS = 0x0C
TC_SET_MISSION_MODE = 0x0D
TC_GET_NAV = 0x0E
TC_GET_PAYLOAD_STATUS = 0x0F
TC_DEBUG_CONFIG = 0x10
TC_GS_MODE = 0x11
TC_GS_ACCESS = 0x12
TC_GS_STATUS = 0x13
TC_GPS_OVERRIDE = 0x14          # course build only, see mission.h

# The ground-station gate's shared secret, from PWNSAT-C3's settings.py.
GS_AUTH_KEY = 0xC0DEFACE

# --- telemetry --------------------------------------------------------------
def gs_response(challenge: int, auth_key: int = GS_AUTH_KEY) -> int:
    """The gate's whole challenge-response: exclusive-or with a constant."""
    return (challenge ^ auth_key) & 0xFFFFFFFF


TM_NAMES = {
    0x01: "PING", 0x02: "RESETC", 0x03: "SEND_FW", 0x04: "SET_THRUSTER",
    0x05: "SET_BEACON_RATE", 0x06: "BROADCAST_MSG", 0x07: "FLASH",
    0x08: "SEND_TM", 0x09: "ERROR", 0x0A: "AES_CONFIG", 0x0B: "FLASH_READ",
    0x0C: "STATUS", 0x0D: "MISSION_MODE", 0x0E: "NAV", 0x0F: "PAYLOAD_STATUS",
    0x10: "DEBUG_CONFIG", 0x11: "GS_MODE", 0x12: "GS_ACCESS",
    0x13: "GS_STATUS", 0x14: "GPS_OVERRIDE", 0x20: "IDS_EVENT",
}

# --- the intentionally weak link wrapper, from pwnsat_crypto.py -------------
AES_KEY = b"PWNsatLabKey1234"
AES_BLOCK = 16


def _aes_ecb(data: bytes, key: bytes, encrypt: bool) -> bytes:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            c = Cipher(algorithms.AES(key), modes.ECB())
            op = c.encryptor() if encrypt else c.decryptor()
            return op.update(data) + op.finalize()
    c = AES.new(key, AES.MODE_ECB)
    return c.encrypt(data) if encrypt else c.decrypt(data)


def encrypt_payload(payload: bytes, key: bytes = AES_KEY) -> bytes:
    """Two-octet big-endian length, then the payload, zero padded to a block."""
    plain = len(payload).to_bytes(2, "big") + payload
    padded = (len(plain) + AES_BLOCK - 1) & ~(AES_BLOCK - 1)
    return _aes_ecb(plain.ljust(padded, b"\x00"), key, True)


def decrypt_payload(payload: bytes, key: bytes = AES_KEY) -> bytes:
    if not payload or len(payload) % AES_BLOCK:
        raise ValueError("ciphertext must be a non-zero multiple of 16 octets")
    plain = _aes_ecb(payload, key, False)
    n = int.from_bytes(plain[:2], "big")
    if n > len(plain) - 2:
        raise ValueError("length prefix does not fit the plaintext")
    return plain[2:2 + n]


# --- SPP --------------------------------------------------------------------

@dataclass
class Packet:
    apid: int
    seq: int
    payload: bytes
    raw: bytes
    is_tc: bool
    sec_hdr: bool

    @property
    def name(self) -> str:
        return TM_NAMES.get(self.apid, f"0x{self.apid:03X}")

    def __str__(self) -> str:
        return f"{self.name:16} seq={self.seq:<5} {len(self.payload)} octets"


def build_tc(apid: int, payload: bytes = b"", *, seq: int = 1,
             encrypt: bool = True, sec_hdr: bool = False) -> bytes:
    if encrypt:
        data = encrypt_payload(payload)
    elif len(payload) == 1:
        # The firmware only copies payload octets when the SPP length field is
        # above zero, so a one-octet cleartext command needs a companion.
        data = payload + b"\x00"
    else:
        data = payload
    ident = (0 << 13) | (1 << 12) | (int(sec_hdr) << 11) | (apid & 0x7FF)
    seq_field = (0b11 << 14) | (seq & 0x3FFF)
    return struct.pack(">HHH", ident, seq_field, max(len(data) - 1, 0)) + data


def parse(raw: bytes) -> Packet:
    ident, seq, _length = struct.unpack(">HHH", raw[:SPP_HEADER])
    return Packet(apid=ident & 0x7FF, seq=seq & 0x3FFF, payload=raw[SPP_HEADER:],
                  raw=raw, is_tc=bool((ident >> 12) & 1),
                  sec_hdr=bool((ident >> 11) & 1))


def frame(raw_spp: bytes) -> bytes:
    return TC_PREFIX + len(raw_spp).to_bytes(2, "big") + raw_spp


def deframe(stream: bytes) -> tuple[list[bytes], bytes]:
    out, off = [], 0
    while off < len(stream):
        if stream[off] != SYNC:
            off += 1
            continue
        if len(stream) - off < SPP_HEADER + 2:
            break
        total = 1 + SPP_HEADER + int.from_bytes(stream[off + 5:off + 7], "big") + 1
        if len(stream) - off < total:
            break
        out.append(stream[off + 1:off + total])
        off += total
    return out, stream[off:]


def list_boards(serial_number: Optional[str] = None) -> list[dict]:
    """Every FlatSat this machine can see.

    Matched on the USB identity rather than on a device-name pattern, so the
    same call works against /dev/cu.usbmodem* on macOS and /dev/ttyACM* on
    Linux without either name appearing anywhere in this file.
    """
    out = []
    for p in serial.tools.list_ports.comports():
        if (p.vid, p.pid) != FLATSAT_VID_PID:
            continue
        if serial_number and (p.serial_number or "") != serial_number:
            continue
        out.append({"port": p.device, "serial": p.serial_number or "?",
                    "product": p.product or "?"})
    return sorted(out, key=lambda d: d["port"])


def candidate_ports(serial_number: Optional[str] = None) -> list[str]:
    """Ports worth probing, in a stable order.

    Filtered by USB identity so a scan does not open every Bluetooth node on a
    Mac or every /dev/ttyS* on a Linux box, both of which are slow and can
    block. Falls back to everything when nothing matches, which is what a
    reflashed board with different descriptors looks like.

    On macOS the /dev/tty.* twin of each port is dropped: opening it blocks
    waiting for carrier detect, and the /dev/cu.* node is the one that works.
    """
    mine = [b["port"] for b in list_boards(serial_number)]
    if mine:
        return mine
    if serial_number:
        return []
    every = [p.device for p in serial.tools.list_ports.comports()]
    if sys.platform == "darwin":
        every = [d for d in every if "/tty." not in d] or every
    return sorted(every)


class _SocketLink:
    """A socket dressed as the serial object the rest of this file expects.

    Same five methods, same meanings, so send() and listen() cannot tell the
    difference between a cable and the sensor sitting on it.
    """

    def __init__(self, endpoint: str, timeout: float = 0.2):
        host, _, port = endpoint.rpartition(":")
        self._sock = socket.create_connection((host or "127.0.0.1", int(port)),
                                              timeout=5.0)
        self._sock.settimeout(timeout)

    def write(self, data: bytes) -> int:
        self._sock.sendall(data)
        return len(data)

    def read(self, n: int = 1) -> bytes:
        try:
            return self._sock.recv(n)
        except socket.timeout:
            return b""
        except OSError:
            return b""

    def reset_input_buffer(self) -> None:
        self._sock.settimeout(0.01)
        try:
            while self._sock.recv(4096):
                pass
        except OSError:
            pass
        self._sock.settimeout(0.2)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


# --- the link ---------------------------------------------------------------

class FlatSat:
    """The board over USB.

    FlatSat exposes two CDC interfaces with the same serial number, and which
    one is the binary link is not stable across replugs. So the port is found
    the way the firmware answers: send an unencrypted PING and see who replies
    with an 0xAA-framed packet."""

    def __init__(self, port: Optional[str] = None, *, encrypt: bool = True,
                 verbose: bool = True, serial_number: Optional[str] = None):
        # FLATSAT_PORT and FLATSAT_SERIAL let every script in this tree target
        # a specific board without any of them growing a new flag. With two
        # boards on one laptop, export FLATSAT_SERIAL and the ten attacks
        # follow it.
        self.port = port or os.environ.get("FLATSAT_PORT") or None
        # FLATSAT_HOST points the attack at the sensor instead of the cable.
        # "1" means the default endpoint, so a lab can turn it on without
        # anybody memorising a port number.
        host = os.environ.get("FLATSAT_HOST")
        if host in ("1", "yes", "true"):
            host = DEFAULT_IDS_ENDPOINT
        self.endpoint = host or None
        self.serial_number = (serial_number
                              or os.environ.get("FLATSAT_SERIAL") or None)
        self.encrypt = encrypt
        self.verbose = verbose
        self._ser: Optional[serial.Serial] = None
        self._rx = b""
        self._first_send = True

    # -- plumbing ------------------------------------------------------------

    def _say(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    @staticmethod
    def _probe(port: str, attempts: int = PROBE_ATTEMPTS) -> bool:
        """Does a FlatSat answer here?

        Retried on purpose: one probe is not a reliable answer. The port has
        to settle after DTR before the board will take a frame, and a probe
        sent too early is simply lost. Raises PermissionError untouched so the
        caller can tell "no board" from "not allowed to open the board", which
        on Linux is the difference between a missing cable and a missing group
        membership.
        """
        probe = frame(build_tc(TC_PING, b"", seq=1, encrypt=False))
        for attempt in range(max(1, attempts)):
            try:
                with serial.Serial(port, BAUD, timeout=1.0) as s:
                    time.sleep(PORT_SETTLE_S)
                    s.reset_input_buffer()
                    s.write(probe)
                    s.flush()
                    if SYNC in s.read(64):
                        return True
            except PermissionError:
                raise
            except (OSError, serial.SerialException):
                pass
            time.sleep(0.2)
        return False

    def find_port(self) -> str:
        denied: list[str] = []
        ports = candidate_ports(self.serial_number)
        for p in ports:
            try:
                if self._probe(p):
                    return p
            except PermissionError:
                denied.append(p)

        lines = ["no FlatSat answered a PING on any serial port."]
        if denied:
            lines.append(f"  - permission denied on: {', '.join(denied)}")
            if sys.platform.startswith("linux"):
                lines.append("    on Ubuntu the account has to be in the "
                             "dialout group, then log out and back in:")
                lines.append("      sudo usermod -aG dialout \"$USER\"")
        if not ports:
            lines.append("  - no USB device with the FlatSat identity "
                         f"{FLATSAT_VID_PID[0]:04x}:{FLATSAT_VID_PID[1]:04x} "
                         "is plugged in")
        if self.serial_number:
            lines.append(f"  - looking only for serial {self.serial_number}; "
                         "unset FLATSAT_SERIAL to take any board")
        lines.append("  - a charge-only USB cable enumerates nothing; "
                     "try another cable")
        lines.append("  - if the IDS is running it owns the port exclusively; "
                     "stop it first")
        raise RuntimeError("\n".join(lines))

    def open(self) -> "FlatSat":
        if self.endpoint:
            self._ser = _SocketLink(self.endpoint)       # type: ignore[assignment]
            self.port = self.endpoint
            self._say(f"[*] FlatSat via Space IDS at {self.endpoint}"
                      f"  ({'encrypted' if self.encrypt else 'cleartext'} link)")
            self._first_send = True
            self._quiesce()
            return self
        self.port = self.port or self.find_port()
        self._ser = serial.Serial(self.port, BAUD, timeout=0.2)
        # Same settle as the probe. Without it the first command of every
        # script is written into a port that is not listening yet, which is
        # why a run used to answer four out of five PINGs instead of five.
        time.sleep(PORT_SETTLE_S)
        self._ser.reset_input_buffer()
        self._first_send = True
        self._quiesce()
        self._say(f"[*] FlatSat on {self.port} @ {BAUD}"
                  f"  ({'encrypted' if self.encrypt else 'cleartext'} link)")
        return self

    def _quiesce(self) -> None:
        """Wait until the board stops talking, so the first reply is ours.

        Whatever is still in flight belongs to whoever ran last. Reading it as
        an answer is how a flash dump assembled ping acknowledgements into an
        image, and how a sweep counted another script's telemetry as proof
        that an identifier was live.
        """
        deadline = time.time() + QUIESCE_TIMEOUT_S
        last = time.time()
        while time.time() < deadline:
            chunk = self._ser.read(512)              # type: ignore[union-attr]
            if chunk:
                last = time.time()
            elif time.time() - last >= QUIET_FOR_S:
                break
            else:
                time.sleep(0.02)
        self._rx = b""
        try:
            self._ser.reset_input_buffer()           # type: ignore[union-attr]
        except Exception:
            pass

    def close(self) -> None:
        if self._ser:
            self._ser.close()
            self._ser = None

    def __enter__(self) -> "FlatSat":
        return self.open()

    def __exit__(self, *a) -> None:
        self.close()

    # -- traffic -------------------------------------------------------------

    def send(self, apid: int, payload: bytes = b"", *, seq: int = 1,
             encrypt: Optional[bool] = None, sec_hdr: bool = False,
             listen: float = BOARD_TICK_S * 1.6) -> list[Packet]:
        enc = self.encrypt if encrypt is None else encrypt
        # The first command on this connection waits longer, because the
        # board takes longer to answer it. Scripts that pass their own window
        # still get at least this much for that one command: a lab that gives
        # up on its first step never reaches the second.
        if self._first_send:
            listen = max(listen, FIRST_COMMAND_S)
            self._first_send = False
        raw = build_tc(apid, payload, seq=seq, encrypt=enc, sec_hdr=sec_hdr)
        self._say(f"[>] {TM_NAMES.get(apid, hex(apid)):16} seq={seq} "
                  f"{len(payload)} octets{'' if enc else '  (cleartext)'}")
        self._ser.write(frame(raw))                      # type: ignore[union-attr]
        return self.listen(listen)

    def send_raw(self, raw_spp: bytes, *, listen: float = 1.0) -> list[Packet]:
        """For the labs that need to put a specific byte sequence on the wire."""
        self._ser.write(frame(raw_spp))                  # type: ignore[union-attr]
        return self.listen(listen)

    def listen(self, seconds: float = 1.0) -> list[Packet]:
        packets: list[Packet] = []
        deadline = time.time() + seconds
        while time.time() < deadline:
            chunk = self._ser.read(4096)                 # type: ignore[union-attr]
            if chunk:
                self._rx += chunk
                frames, self._rx = deframe(self._rx)
                for f in frames:
                    if len(f) >= SPP_HEADER:
                        packets.append(parse(f))
            else:
                time.sleep(0.01)
        for p in packets:
            self._say(f"[<] {p}")
        return packets

    def plaintext(self, p: Packet) -> bytes:
        """The payload, decrypted when the link is in its encrypted mode."""
        if not self.encrypt or not p.payload:
            return p.payload
        try:
            return decrypt_payload(p.payload)
        except ValueError:
            return p.payload


def hexdump(data: bytes, width: int = 16) -> str:
    out = []
    for i in range(0, len(data), width):
        c = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in c)
        tx = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        out.append(f"{i:06x}  {hx:<{width * 3}} |{tx}|")
    return "\n".join(out)
