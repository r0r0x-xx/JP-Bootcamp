"""The two properties that matter, asserted on every run."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwnsat_ids import replay                              # noqa: E402
from pwnsat_ids.rules import SpaceIDS                      # noqa: E402

# Each capture, and the rule it exists to prove. A rule with no capture is a
# claim, not a detection.
EXPECTED = {
    "nominal":    set(),
    "recon":      {"unknown-apid-rate"},
    "replay":     {"duplicate-frame"},
    "malformed":  {"length-mismatch", "length-underflow"},
    "spoof":      {"position-jump"},
    "handover":   {"command-before-auth"},
    "radio-on":   {"radio-origin-frame"},
    "crc":        {"crc-accepted"},
    "downgrade":  {"secure-link-downgrade"},
    "flash-dump": {"flash-read-sweep"},
    "gate-chain": {"gate-exemption-chain"},
}


def test_clean_traffic_is_silent():
    ids = replay.run("nominal")
    assert ids.detections == [], (
        "clean traffic raised an alert. That is a rule bug, not a finding:\n"
        + ids.report())


def test_every_capture_proves_its_rule():
    for name, wanted in EXPECTED.items():
        fired = {d.rule for d in replay.run(name).detections}
        missing = wanted - fired
        assert not missing, f"{name}: expected {missing}, got {fired or 'nothing'}"


def test_radio_rule_is_off_against_stock_firmware():
    """A stock board has a working radio, so a frame from the air is normal.
    The rule has to know which build it is watching."""
    ids = SpaceIDS(radio_disabled_build=False)
    replay.run("radio-on", ids)
    assert not [d for d in ids.detections if d.rule == "radio-origin-frame"]


def test_ordinary_commands_do_not_fire_unauthenticated_tc():
    """The rule used to key off the SPP secondary header, which no legitimate
    command on this firmware sets. Against a real board that fired on every
    command an operator sent."""
    from pwnsat_ids import spp
    ids = SpaceIDS()
    for i, apid in enumerate(sorted(spp.APIDS)):
        ids.observe(spp.parse_spp(spp.build_spp(apid, tc=True, seq=i,
                                                payload=b"\x00" * 4)), direction="up")
    assert not [d for d in ids.detections if d.rule == "unauthenticated-tc"]


def test_local_ids_are_labelled_as_ours():
    """SPARTA identifiers are SPARTA's. Ours say so."""
    for name in replay.NAMES:
        for d in replay.run(name).detections:
            assert d.taxonomy in ("SPARTA", "local")
            if d.iob.startswith("PWN-"):
                assert d.taxonomy == "local", f"{d.iob} must not claim to be SPARTA"
