"""The sensor, in the middle of the bench.

    FlatSat  --USB-->  [ this ]  -->  PWNSAT-C3

A USB cable has no physical midpoint you can tap without putting a second
board on it, so the sensor is a process: it owns the serial port, classifies
every frame that crosses it, and hands the frame on unchanged. Logically it is
exactly in the middle, and that is what makes an alert arrive while the attack
is still running rather than afterwards.

**Watching both directions is the point.** Every attack in this course is
something the operator sends: the enumeration sweep, the replayed frame, the
malformed length, the telecommand nobody authenticated. A sensor watching only
telemetry would see none of them.

**Detect-only by default.** It forwards what it alerts on. A bench where the
attack never lands teaches nothing, and blocking is a different device with a
different failure mode. `--mode block` is opt-in, for showing the mitigation.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import spp
from .events import UnknownEventVersion, parse_event
from .rules import Detection, SpaceIDS

log = logging.getLogger("pwnsat_ids.sensor")

DEFAULT_BAUD = 921600
USB_VID_PID = "239a:cafe"          # how a FlatSat announces itself


# --------------------------------------------------------------- the board

def find_boards() -> list[dict]:
    """Every FlatSat on this machine, with the serial number that tells two
    boards apart. v1.0.5 derives it from the RP2040's unique chip id, so the
    identity survives ports being renumbered on replug."""
    try:
        from serial.tools import list_ports
    except ImportError:                                   # pragma: no cover
        return []
    vid, pid = (int(x, 16) for x in USB_VID_PID.split(":"))
    found = []
    for p in list_ports.comports():
        if p.vid == vid and p.pid == pid:
            found.append({"port": p.device, "serial": p.serial_number or "?",
                          "product": p.product or "?"})
    return sorted(found, key=lambda d: d["port"])


def classify_port(device: str, baud: int = 921600,
                  listen: float = 1.2) -> str:
    """"console", "binary" or "unknown" — decided by listening only.

    A FlatSat exposes two CDC interfaces with the same serial number, and
    which one carries frames is not stable across replugs or rebuilds. The
    console one prints human-readable log lines; the binary one says nothing
    until it is spoken to.

    The sensor must not transmit to find out which is which. A detector that
    injects a probe is no longer only observing, and on a bench where "nothing
    radiates, nothing is touched" is the rule, that distinction is the whole
    point. So this listens and classifies what arrives, and answers "unknown"
    rather than guessing when nothing does.
    """
    try:
        import serial as _serial
        with _serial.Serial(device, baud, timeout=listen) as s:
            time.sleep(0.35)             # DTR settle, same as the attack side
            raw = s.read(512)
    except Exception:
        return "unknown"
    if not raw:
        return "unknown"
    if b"\xAA\x55" in raw:
        return "binary"
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    return "console" if printable / len(raw) > 0.9 else "binary"


def probe_port(device: str, baud: int = 921600, attempts: int = 3) -> bool:
    """Send one PING and see whether frames come back.

    The last resort of the port search, for a board that is sitting idle. The
    frame is built with this package's own SPP encoder, so no parser is shared
    with the attack scripts and the two implementations stay independent.
    """
    probe = spp.frame_tc(spp.build_spp(spp.APID_PING, tc=True, seq=1))
    for _ in range(max(1, attempts)):
        try:
            import serial as _serial
            with _serial.Serial(device, baud, timeout=1.0) as s:
                time.sleep(0.35)
                s.reset_input_buffer()
                s.write(probe)
                s.flush()
                if spp.SYNC in s.read(64):
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def select_board_port(boards: list[dict]) -> tuple[Optional[str], str]:
    """The one port to listen on, or None and the reason there isn't one.

    One board shows up as two entries here, so counting entries and calling it
    "more than one board" is wrong: it made the sensor refuse to auto-detect
    with a single FlatSat on the bench, every time.
    """
    if not boards:
        return None, "no FlatSat found"
    by_serial: dict[str, list[dict]] = {}
    for b in boards:
        by_serial.setdefault(b["serial"], []).append(b)
    if len(by_serial) > 1:
        names = ", ".join(sorted(by_serial))
        return None, f"more than one board ({names}); pick one with --port"
    ports = [b["port"] for b in next(iter(by_serial.values()))]
    if len(ports) == 1:
        return ports[0], ""
    kinds = {d: classify_port(d) for d in ports}
    # Positive evidence first: a port that actually carried a framed packet is
    # the binary one, whatever the others did. Only when nothing identified
    # itself does ruling out the console have to carry the decision, and an
    # idle board gives exactly that case.
    binary = [d for d, k in kinds.items() if k == "binary"]
    if len(binary) == 1:
        return binary[0], ""
    usable = [d for d, k in kinds.items() if k != "console"]
    if len(usable) == 1:
        return usable[0], ""
    # An idle board says nothing on either interface, so listening alone
    # cannot decide. One PING settles it. This is a USB cable to our own
    # board, not the air, so the bench rule is untouched -- and it is built
    # with this module's own codec, so the sensor still shares no parser with
    # the attack side. Only the port search sends; the sensor never does.
    answered = [d for d in ports if probe_port(d)]
    if len(answered) == 1:
        return answered[0], ""

    detail = ", ".join(f"{d.rsplit('/', 1)[-1]}={k}" for d, k in kinds.items())
    return None, f"cannot tell the interfaces apart ({detail}); use --port"


class BoardLink:
    """The serial side. Opened with O_NOCTTY so the tty never becomes this
    process's controlling terminal, which is the lesson carried over from the
    spacecop-arm-test experiment."""

    def __init__(self, port: str, baud: int = DEFAULT_BAUD):
        self.port, self.baud = port, baud
        self._ser = None
        self._lock = threading.Lock()

    def open(self) -> None:
        import serial
        # pyserial already opens POSIX ports with O_NOCTTY, so the tty never
        # becomes this process's controlling terminal. Checked rather than
        # assumed, because getting it wrong is how a stray Ctrl-C on the
        # console killed the capture in the spacecop-arm-test experiment.
        self._ser = serial.Serial(self.port, self.baud, timeout=0.2,
                                  exclusive=True)
        log.info("board open: %s @ %d (exclusive)", self.port, self.baud)

    def close(self) -> None:
        if self._ser is not None:
            try:
                self._ser.close()
            finally:
                self._ser = None

    @property
    def is_open(self) -> bool:
        return self._ser is not None and self._ser.is_open

    def read(self, n: int = 4096) -> bytes:
        if self._ser is None:
            return b""
        waiting = self._ser.in_waiting or 1
        return self._ser.read(min(n, waiting))

    def write(self, data: bytes) -> None:
        """No flush().

        pyserial's flush() is tcdrain(): it waits until the bytes have left the
        UART, which means waiting on the far end. A board that stops reading
        would block this call forever, and this call is on the uplink path --
        one wedged write would stop every later command *and* all inspection
        with it. The OS buffer is enough; the board's own reply is the real
        confirmation that anything arrived."""
        if self._ser is None:
            raise RuntimeError("board is not open")
        with self._lock:
            self._ser.write(data)


# ------------------------------------------------------------- the console side

class DownstreamServer:
    """What C3 connects to. It speaks exactly the framing the board speaks, so
    the transport on the C3 side is the serial one with a socket in place of a
    tty, and nothing above it has to change."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5010):
        self.host, self.port = host, port
        self._sock: Optional[socket.socket] = None
        self._clients: list[socket.socket] = []
        self._lock = threading.Lock()
        self.on_tc: Optional[Callable[[bytes], None]] = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(4)
        threading.Thread(target=self._accept_loop, name="ids-accept", daemon=True).start()
        log.info("downstream listening on %s:%d", self.host, self.port)

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for c in self._clients:
                try:
                    c.close()
                except OSError:
                    pass
            self._clients.clear()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def broadcast(self, data: bytes) -> None:
        with self._lock:
            dead = []
            for c in self._clients:
                try:
                    c.sendall(data)
                except OSError:
                    dead.append(c)
            for c in dead:
                self._clients.remove(c)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()        # type: ignore[union-attr]
            except OSError:
                return
            log.info("console connected from %s", addr)
            with self._lock:
                self._clients.append(conn)
            threading.Thread(target=self._client_loop, args=(conn,),
                             name="ids-client", daemon=True).start()

    def _client_loop(self, conn: socket.socket) -> None:
        buf = b""
        try:
            while not self._stop.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
                frames, buf = spp.deframe_tc(buf)
                for raw in frames:
                    if self.on_tc:
                        self.on_tc(raw)
        except OSError:
            return
        finally:
            with self._lock:
                if conn in self._clients:
                    self._clients.remove(conn)
            try:
                conn.close()
            except OSError:
                pass


# ------------------------------------------------------------------ the sensor

@dataclass
class Stats:
    tm_frames: int = 0
    tc_frames: int = 0
    events: int = 0
    dropped: int = 0
    started: float = field(default_factory=time.time)


class Sensor:
    def __init__(self, board: BoardLink, downstream: DownstreamServer,
                 ids: Optional[SpaceIDS] = None, *, mode: str = "detect",
                 live: bool = True, on_alert: Optional[Callable[[Detection], None]] = None):
        if mode not in ("detect", "block"):
            raise ValueError("mode is 'detect' or 'block'")
        self.board = board
        self.downstream = downstream
        self.ids = ids or SpaceIDS()
        self.mode = mode
        self.live = live
        self.on_alert = on_alert
        self.stats = Stats()
        self._stop = threading.Event()
        self._rx = b""
        self.board_lost = False
        self.downstream.on_tc = self._from_console

    # -- uplink: console -> board -----------------------------------------

    def _from_console(self, raw: bytes) -> None:
        """Everything the operator sends crosses here first. This is where the
        attacks are, so this is the half that must not be skipped."""
        self.stats.tc_frames += 1
        new = self.ids.observe_raw(raw, direction="up")
        self._alert(new)
        if self.mode == "block" and new:
            self.stats.dropped += 1
            log.warning("blocked a telecommand that raised %d rule(s)", len(new))
            return
        try:
            self.board.write(spp.frame_tc(raw))
        except Exception as exc:                            # pragma: no cover
            log.error("could not write to the board: %s", exc)

    # -- downlink: board -> console ---------------------------------------

    def _from_board(self, chunk: bytes) -> None:
        self._rx += chunk
        frames, self._rx = spp.deframe_tm(self._rx)
        for raw in frames:
            try:
                packet = spp.parse_spp(raw)
            except ValueError:
                self._alert(self.ids.observe_raw(raw, direction="down"))
                continue

            if packet.apid == spp.APID_IDS_EVENT:
                self.stats.events += 1
                try:
                    event = parse_event(packet.payload)
                except (UnknownEventVersion, ValueError) as exc:
                    log.warning("event refused: %s", exc)
                else:
                    self._alert(self.ids.observe_event(event))
                # The event channel is for the sensor. C3 gets it too, so the
                # console can show what the board saw.
            else:
                self.stats.tm_frames += 1
                self._alert(self.ids.observe(packet, direction="down"))

            self.downstream.broadcast(b"\xAA" + raw)

    def _alert(self, new: list[Detection]) -> None:
        for d in new:
            if self.live:
                print(f"  >> IDS  {d}", flush=True)
            if self.on_alert:
                self.on_alert(d)

    # ----------------------------------------------------------------------

    #: How long the sensor keeps trying to get its board back before it gives
    #: up and says so. A reset takes the board away for about eight seconds
    #: and the device node can come back under a different name, so this is a
    #: window rather than a count of reads, and each attempt reopens the port
    #: instead of reading a handle the kernel has already closed.
    #:
    #: The lab that sends RESETC is on the syllabus. A sensor that dies when
    #: the student runs it leaves every later lab unmonitored, and that looks
    #: exactly like the rules not firing.
    REOPEN_WINDOW_S = 30.0
    REOPEN_INTERVAL_S = 1.0

    def _reopen(self) -> bool:
        """Get the board back after it went away. True if it came back.

        The port is looked up again rather than reused: a board that reboots
        can enumerate under a different device node, and reopening the old
        name then fails forever on a board that is sitting right there.
        """
        deadline = time.time() + self.REOPEN_WINDOW_S
        attempt = 0
        while time.time() < deadline and not self._stop.is_set():
            attempt += 1
            time.sleep(self.REOPEN_INTERVAL_S)
            try:
                self.board.close()
            except Exception:
                pass
            try:
                boards = find_boards()
                if boards:
                    device, _ = select_board_port(boards)
                    if device:
                        self.board.port = device
                self.board.open()
            except Exception as exc:
                log.info("waiting for the board (%ds left): %s",
                         int(deadline - time.time()), exc)
                continue
            log.info("board back after %d attempt(s): %s", attempt, self.board.port)
            return True
        return False

    def run(self) -> None:
        log.info("sensor in line, mode=%s.  FlatSat --USB--> [ Space IDS ] --> PWNSAT-C3",
                 self.mode)
        while not self._stop.is_set():
            try:
                chunk = self.board.read()
            except Exception as exc:
                log.error("board read failed: %s -- trying to get it back", exc)
                if self._reopen():
                    continue
                log.error("giving up on %s after %.0fs. C3 will stop receiving, "
                          "which is what an in-line sensor losing its board "
                          "looks like.", self.board.port, self.REOPEN_WINDOW_S)
                self.board_lost = True
                self._stop.set()
                return
            if chunk:
                self._from_board(chunk)
            else:
                time.sleep(0.01)

    def stop(self) -> None:
        self._stop.set()
