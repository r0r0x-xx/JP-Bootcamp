"""The whole thing at once: board, sensor, console link and the web API.

This is the end-to-end check that the slides' claim is true -- both directions
cross the sensor, alerts reach the console, and nothing is dropped in detect
mode.
"""
import json
import os
import pty
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwnsat_ids import spp                                      # noqa: E402
from pwnsat_ids.console import ConsoleState, serve              # noqa: E402
from pwnsat_ids.events import build_event                       # noqa: E402
from pwnsat_ids.rules import SpaceIDS                           # noqa: E402
from pwnsat_ids.sensor import BoardLink, DownstreamServer, Sensor  # noqa: E402


def test_full_bench_reaches_the_console():
    master, slave = pty.openpty()
    board = BoardLink(os.ttyname(slave), baud=9600)
    board.open()
    down = DownstreamServer("127.0.0.1", 0)   # let the OS pick
    down.start()
    state = ConsoleState()
    ids = SpaceIDS()
    sensor = Sensor(board, down, ids, live=False, on_alert=state.add)
    state.sensor, state.board_name = sensor, "pty"
    httpd = serve(state, "127.0.0.1", 0)
    threading.Thread(target=sensor.run, daemon=True).start()
    c3 = socket.create_connection(down._sock.getsockname(), timeout=2)
    time.sleep(0.3)

    try:
        # Uplink: an enumeration sweep, then a command with no credential.
        for apid in (0x101, 0x102, 0x103, 0x104, 0x105):
            c3.sendall(spp.frame_tc(spp.build_spp(apid, payload=b"\x00")))
        c3.sendall(spp.frame_tc(spp.build_spp(0x106, seq=7, payload=b"\xff")))
        time.sleep(0.4)

        # Downlink: ordinary telemetry, then the event that cannot happen on a
        # course board -- the firmware reporting a frame from the air.
        os.write(master, b"\xAA" + spp.build_spp(0x0C, tc=False, seq=1,
                                                 payload=b"\x00" * 6))
        os.write(master, b"\xAA" + spp.build_spp(spp.APID_IDS_EVENT, tc=False, seq=2,
                 payload=build_event(origin=0x00, apid=0x04, rssi_dbm=-38.0, flags=0x01)))
        time.sleep(0.4)

        api = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{httpd.server_address[1]}/api/state", timeout=3))
        rules = {a["rule"] for a in api["alerts"]}

        assert sensor.stats.tc_frames == 6, "the uplink did not cross the sensor"
        assert sensor.stats.tm_frames == 1
        assert sensor.stats.events == 1
        assert api["clients"] == 1
        assert "unknown-apid-rate" in rules
        assert "radio-origin-frame" in rules
        assert sensor.stats.dropped == 0, "detect mode must forward everything"
        assert {a["direction"] for a in api["alerts"]} >= {"up", "down"}
        # The local identifier is labelled as ours, not SPARTA's.
        local = [a for a in api["alerts"] if a["rule"] == "radio-origin-frame"][0]
        assert local["taxonomy"] == "local"
    finally:
        sensor.stop()
        httpd.shutdown()
        down.stop()
        board.close()
        c3.close()
        os.close(master)
