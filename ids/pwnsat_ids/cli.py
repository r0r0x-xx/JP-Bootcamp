"""Entry point.

    pwnsat-ids run                 # sensor in line, auto-detects the board
    pwnsat-ids run --mode block    # drop what trips a rule, for the mitigation
    pwnsat-ids replay recon        # no hardware: run a capture past the rules
    pwnsat-ids boards              # which FlatSats are on this machine
"""
from __future__ import annotations

import argparse
import logging
import sys
import time

from . import replay as replay_mod
from .console import ConsoleState, serve
from .rules import SpaceIDS
from .sensor import (BoardLink, DownstreamServer, Sensor, classify_port,
                     find_boards, select_board_port)


def _log(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(message)s", datefmt="%H:%M:%S")


def cmd_boards(_: argparse.Namespace) -> int:
    boards = find_boards()
    if not boards:
        print("no FlatSat found. Check the cable: a charge-only cable enumerates nothing.")
        return 1
    # One board enumerates as two interfaces. Saying which is which here is
    # what saves twenty people from pasting the console path into --port and
    # watching the sensor sit on a stream of log lines.
    print(f"{'PORT':32} {'SERIAL':18} {'KIND':9} PRODUCT")
    for b in boards:
        kind = classify_port(b["port"])
        label = {"console": "console", "binary": "frames",
                 "unknown": "idle"}[kind]
        print(f"{b['port']:32} {b['serial']:18} {label:9} {b['product']}")
    chosen, why = select_board_port(boards)
    print()
    if chosen:
        print(f"the sensor would take {chosen}")
    else:
        print(f"{why}  (an idle board says nothing on either interface; "
              f"send it one command and run this again)")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    names = replay_mod.NAMES if args.capture == "all" else (args.capture,)
    worst = 0
    for name in names:
        ids = replay_mod.run(name)
        print(f"\n=== {name} ===")
        print(ids.report())
        for d in ids.detections[: args.limit]:
            print(f"  {d}")
        if name == "nominal" and ids.detections:
            print("  !! clean traffic raised an alert. That is a rule bug, not a finding.")
            worst = 1
    return worst


def cmd_run(args: argparse.Namespace) -> int:
    boards = find_boards()
    port = args.port
    if port is None:
        if not boards:
            print("no FlatSat found. Use --port, or --replay to work without hardware.",
                  file=sys.stderr)
            return 1
        port, why = select_board_port(boards)
        if port is None:
            print(f"{why}:", file=sys.stderr)
            for b in boards:
                print(f"  {b['port']}  {b['serial']}", file=sys.stderr)
            return 1

    state = ConsoleState()
    state.board_name = port.rsplit("/", 1)[-1]
    ids = SpaceIDS(radio_disabled_build=not args.stock_firmware)

    board = BoardLink(port, args.baud)
    board.open()
    down = DownstreamServer(args.host, args.downstream_port)
    down.start()
    sensor = Sensor(board, down, ids, mode=args.mode, live=not args.quiet,
                    on_alert=state.add)
    state.sensor = sensor
    serve(state, args.host, args.console_port)

    print(f"\n  FlatSat --USB--> [ Space IDS ] --> PWNSAT-C3")
    print(f"  board      {port} @ {args.baud}")
    print(f"  downstream {args.host}:{args.downstream_port}   <- point C3 here")
    print(f"  console    http://{args.host}:{args.console_port}")
    print(f"  mode       {args.mode}"
          f"{'  (forwards everything)' if args.mode == 'detect' else '  (drops what trips a rule)'}\n")
    try:
        sensor.run()
    except KeyboardInterrupt:
        print("\nstopping.")
    finally:
        sensor.stop()
        down.stop()
        board.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pwnsat-ids", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="sit between the board and the console")
    r.add_argument("--port", help="serial port; auto-detected when there is one board")
    r.add_argument("--baud", type=int, default=921600)
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--downstream-port", type=int, default=5010)
    r.add_argument("--console-port", type=int, default=5011)
    r.add_argument("--mode", choices=("detect", "block"), default="detect")
    r.add_argument("--quiet", action="store_true", help="no alerts on stdout")
    r.add_argument("--stock-firmware", action="store_true",
                   help="the board's radio is enabled; do not treat radio traffic as impossible")
    r.set_defaults(func=cmd_run)

    p = sub.add_parser("replay", help="run a recorded session past the rules")
    p.add_argument("capture", nargs="?", default="all",
                   choices=("all",) + replay_mod.NAMES)
    p.add_argument("--limit", type=int, default=6)
    p.set_defaults(func=cmd_replay)

    b = sub.add_parser("boards", help="list the FlatSats on this machine")
    b.set_defaults(func=cmd_boards)

    args = ap.parse_args(argv)
    _log(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
