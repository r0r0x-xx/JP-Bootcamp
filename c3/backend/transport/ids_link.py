"""Transport that reaches the FlatSat through the Space IDS.

```
FlatSat  --USB-->  [ Space IDS ]  -->  PWNSAT-C3
```

The sensor opens the serial port exclusively, because a USB cable has no
midpoint where a probe could sit. So when it is in line, nothing else can
have the cable: the console reaches the board through it or not at all.

The sensor speaks the board's own framing on this socket -- `0xAA 0x55 <len>
<SPP>` up, bare `0xAA` sync down -- so this class is SerialTransport with a
socket where the port was, and everything above the transport layer is
unchanged.

Set PWNSAT_C3_IDS_ENDPOINT to use it, e.g. 127.0.0.1:5010.
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Optional

from .. import settings  # noqa: F401  (ensures pwnsat_tools/ is on sys.path)
from usb_tc_send import frame_usb, iter_usb_sync_packets

from .base import Transport

log = logging.getLogger("pwnsat_c3.ids_link")

# Same cadence as the serial transport's reconnect. The sensor going away is
# an ordinary event here: it is restarted whenever somebody reloads a rule.
RECONNECT_INTERVAL_S = 2.0
READ_CHUNK = 4096


class IdsTransport(Transport):
    def __init__(self, endpoint: str) -> None:
        super().__init__()
        host, _, port = endpoint.rpartition(":")
        self._host = host or "127.0.0.1"
        self._port = int(port)
        self._sock: Optional[socket.socket] = None
        self._write_lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._rx_buffer = bytearray()

    @property
    def description(self) -> str:
        return f"FlatSat via Space IDS ({self._host}:{self._port})"

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> None:
        self._sock = self._open()
        if self._sock is None:
            raise RuntimeError(f"no Space IDS listening on {self._host}:{self._port}")
        self._stop_event.clear()
        self._reader_thread = threading.Thread(
            target=self._read_loop, name="ids-reader", daemon=True
        )
        self._reader_thread.start()
        log.info("connected: %s", self.description)

    def disconnect(self) -> None:
        self._stop_event.set()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2.0)
            self._reader_thread = None
        self._close()

    def send_tc(self, raw_spp: bytes) -> None:
        if not self.connected:
            raise RuntimeError("IDS transport is not connected")
        frame = frame_usb(raw_spp)
        with self._write_lock:
            assert self._sock is not None
            self._sock.sendall(frame)

    # -- plumbing ------------------------------------------------------------

    def _open(self) -> Optional[socket.socket]:
        try:
            s = socket.create_connection((self._host, self._port), timeout=3.0)
        except OSError:
            return None
        s.settimeout(0.2)
        return s

    def _close(self) -> None:
        if self._sock is not None:
            with self._write_lock:
                try:
                    self._sock.close()
                except OSError:
                    pass
            self._sock = None

    def _read_loop(self) -> None:
        was_connected = True
        while not self._stop_event.is_set():
            if self._sock is None:
                if was_connected:
                    log.warning(
                        "Space IDS at %s:%d went away -- retrying every %.0fs",
                        self._host, self._port, RECONNECT_INTERVAL_S,
                    )
                    was_connected = False
                new = self._open()
                if new is not None:
                    with self._write_lock:
                        self._sock = new
                    log.warning("Space IDS reconnected")
                    was_connected = True
                    # A partial frame from before the drop would be glued to
                    # the first one after it, and the decoder would reject a
                    # packet that was never actually malformed.
                    self._rx_buffer = bytearray()
                else:
                    self._stop_event.wait(RECONNECT_INTERVAL_S)
                continue

            try:
                chunk = self._sock.recv(READ_CHUNK)
            except socket.timeout:
                continue
            except OSError:
                self._close()
                continue
            if not chunk:                       # the sensor closed the socket
                self._close()
                continue
            self._rx_buffer.extend(chunk)
            packets, trailing = iter_usb_sync_packets(bytes(self._rx_buffer))
            self._rx_buffer = bytearray(trailing)
            for raw_spp in packets:
                self._emit(raw_spp)
