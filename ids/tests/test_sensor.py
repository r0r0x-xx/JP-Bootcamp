"""The sensor in line, end to end, with a pty standing in for the board.

Proves the thing the slides claim: both directions cross the sensor, and it
forwards what it alerts on.
"""
import os
import pty
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwnsat_ids import spp                                  # noqa: E402
from pwnsat_ids.rules import SpaceIDS                       # noqa: E402
from pwnsat_ids.sensor import BoardLink, DownstreamServer, Sensor   # noqa: E402


def _bench(port=0):      # 0 = whatever the OS has free
    master, slave = pty.openpty()
    # A pty cannot take the board's 921600: macOS needs IOSSIOSPEED for it and
    # a pty has no such ioctl. The rate is meaningless here anyway -- what is
    # under test is the path through the sensor, not the line speed.
    board = BoardLink(os.ttyname(slave), baud=9600)
    board.open()
    down = DownstreamServer("127.0.0.1", port)
    down.start()
    ids = SpaceIDS()
    sensor = Sensor(board, down, ids, live=False)
    threading.Thread(target=sensor.run, daemon=True).start()
    client = socket.create_connection(down._sock.getsockname(), timeout=2)
    time.sleep(0.2)
    return master, board, down, sensor, ids, client


def test_uplink_is_inspected_and_forwarded():
    """Every attack in the course is something the operator sends. A sensor
    that watched only telemetry would see none of them."""
    master, board, down, sensor, ids, client = _bench()
    try:
        # An enumeration sweep: identifiers the spacecraft does not implement.
        sent = b""
        for apid in (0x101, 0x102, 0x103, 0x104, 0x105):
            raw = spp.build_spp(apid, tc=True, seq=apid, payload=b"\x00")
            client.sendall(spp.frame_tc(raw))
            sent += spp.frame_tc(raw)
        time.sleep(0.4)

        rules = {d.rule for d in ids.detections}
        assert "unknown-apid-rate" in rules, f"uplink not inspected: {rules}"
        assert any(d.direction == "up" for d in ids.detections)
        assert sensor.stats.tc_frames == 5

        # ...and every one still reached the board, byte for byte. Detect-only
        # forwards what it alerts on.
        os.set_blocking(master, False)
        assert os.read(master, 65536) == sent, "the sweep did not reach the board intact"
        assert sensor.stats.dropped == 0
    finally:
        sensor.stop(); down.stop(); board.close(); client.close(); os.close(master)


def test_downlink_reaches_the_console():
    master, board, down, sensor, ids, client = _bench()
    try:
        frame = spp.build_spp(0x0C, tc=False, seq=3, payload=b"\x00" * 6)
        os.write(master, b"\xAA" + frame)
        time.sleep(0.3)
        client.settimeout(1.0)
        assert client.recv(4096) == b"\xAA" + frame
        assert sensor.stats.tm_frames == 1
        assert ids.detections == []
    finally:
        sensor.stop(); down.stop(); board.close(); client.close(); os.close(master)


def test_block_mode_drops_what_it_alerts_on():
    """Block mode drops the frame that trips a rule, and only that one. The
    four probes before it raise nothing, so they go through."""
    master, board, down, sensor, ids, client = _bench()
    sensor.mode = "block"
    try:
        passed = b""
        for n, apid in enumerate((0x101, 0x102, 0x103, 0x104, 0x105)):
            raw = spp.build_spp(apid, tc=True, seq=apid, payload=b"\x00")
            client.sendall(spp.frame_tc(raw))
            if n < 4:                       # the fifth is the one that trips it
                passed += spp.frame_tc(raw)
        time.sleep(0.4)

        assert sensor.stats.dropped == 1, "exactly the frame that alerted should fall"
        os.set_blocking(master, False)
        try:
            got = os.read(master, 65536)
        except BlockingIOError:
            got = b""
        assert got == passed, "block mode dropped the wrong frames"
    finally:
        sensor.stop(); down.stop(); board.close(); client.close(); os.close(master)
