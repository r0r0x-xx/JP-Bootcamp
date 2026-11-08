"""Every rule needs a capture that fires it, or a lab cannot be shown
without a board."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pwnsat_ids import replay
from pwnsat_ids.knowledge import inventory


def fired_by_capture():
    return {n: {d.rule for d in replay.run(n).detections} for n in replay.NAMES}


def test_nominal_raises_nothing():
    assert replay.run("nominal").detections == []


def test_every_rule_has_a_capture():
    fired = set().union(*fired_by_capture().values())
    uncovered = sorted(k["rule"] for k in inventory() if k["rule"] not in fired)
    assert not uncovered, f"no capture fires {uncovered}"


def test_every_capture_fires_something():
    quiet = sorted(n for n, r in fired_by_capture().items() if n != "nominal" and not r)
    assert not quiet, f"these captures raise nothing: {quiet}"
