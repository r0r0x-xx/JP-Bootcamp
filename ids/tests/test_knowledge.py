"""The console's explanations have to keep up with the rules.

A rule added without an entry here still fires, and the alert still appears,
but it appears with no account of why it matters and no fix beside it. That is
the failure this file exists to make loud: it is invisible on the screen and
obvious in a test run.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwnsat_ids.knowledge import BLIND_SPOTS, KNOWLEDGE, inventory   # noqa: E402
from pwnsat_ids.rules import CATALOG                                 # noqa: E402

SOURCE = (Path(__file__).resolve().parent.parent / "pwnsat_ids" / "rules.py").read_text()
FIRES = set(re.findall(r'_fire\(\s*"([a-z0-9-]+)"', SOURCE))


def test_every_rule_that_can_fire_is_explained():
    missing = FIRES - set(KNOWLEDGE)
    assert not missing, (
        f"these rules fire with nothing to say about them: {sorted(missing)}. "
        "Add them to pwnsat_ids/knowledge.py.")


def test_no_explanation_without_a_rule():
    stale = set(KNOWLEDGE) - FIRES
    assert not stale, f"knowledge for rules that no longer exist: {sorted(stale)}"


def test_every_entry_carries_its_defence():
    """The house rule, asserted. Attack without defence is out of brand."""
    for rule, k in KNOWLEDGE.items():
        for field in ("means", "why", "fix"):
            assert k.get(field), f"{rule} has no {field}"
            assert len(k[field]) > 40, f"{rule}'s {field} is too thin to be useful"


def test_identifiers_resolve_to_the_catalog():
    for rule, k in KNOWLEDGE.items():
        for key in ("iob", "iob_alt"):
            if key in k:
                assert k[key] in CATALOG, f"{rule} points at unknown {k[key]}"


def test_inventory_is_what_the_console_renders():
    inv = inventory()
    assert len(inv) == len(KNOWLEDGE)
    assert [d["severity"] for d in inv] == sorted(
        (d["severity"] for d in inv), key={"critical": 0, "high": 1, "medium": 2}.get), \
        "the inventory must come out worst-first"
    for d in inv:
        assert d["taxonomy"] in ("SPARTA", "local")
        assert d["ids"] and all(i in CATALOG for i in d["ids"])


def test_blind_spots_are_stated_rather_than_omitted():
    """The two attacks with no detection stay on the page. A set that lists
    only its wins teaches students to trust a quiet screen."""
    assert len(BLIND_SPOTS) == 2
    for b in BLIND_SPOTS:
        for field in ("attack", "lab", "why", "fix"):
            assert b.get(field), f"blind spot {b.get('attack')} has no {field}"
