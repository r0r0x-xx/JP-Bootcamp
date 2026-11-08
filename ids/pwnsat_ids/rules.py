"""The detection set.

One method per rule, so each one can be read on its own and argued with. Every
rule answers an attack that is run in the course, and every rule has a capture
that proves it fires.

Two properties matter more than coverage:

**Clean traffic raises nothing.** It is the hardest property of a detection set
and the easiest to lose. `tests/` asserts it on every run.

**Identifiers say where they come from.** SPARTA's technique identifiers are
SPARTA's. Mapping an observation to one of them is this project's analysis, not
an official Aerospace Corporation classification, and the alert says so. Rules
with no SPARTA equivalent carry a local identifier and are labelled `local`.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

from .events import BoardEvent
from .spp import (APIDS, APID_AES_CONFIG, APID_DEBUG_CONFIG, APID_FLASH_READ,
                  APID_GS_ACCESS, APID_GS_MODE, APID_NAV, APP_HEADER,
                  ACTUATOR_APIDS, CRITICAL_APIDS, NAV_LAT_OFFSET, NAV_LON_OFFSET,
                  NAV_MIN_LEN, NAV_SCALE, SPP_HEADER, SUBTRACTING_APPS, SpacePacket)

# (label, severity, taxonomy). Severity uses NIST/CVSS tiers only.
CATALOG = {
    "UACE-2": ("Unauthenticated command accepted", "critical", "SPARTA"),
    "UACE-3": ("Actuator state changed by command", "critical", "SPARTA"),
    "UACE-6": ("Ground-station authentication anomaly", "high", "SPARTA"),
    "UACE-7": ("Replayed frame accepted", "high", "SPARTA"),
    "UACE-8": ("Malformed command, parser fault", "high", "SPARTA"),
    "UACE-9": ("Command-space enumeration", "medium", "SPARTA"),
    "UCEB-8": ("Command outside expected envelope", "high", "SPARTA"),
    # No SPARTA technique describes these. They are ours, and labelled.
    "PWN-1": ("Radio traffic on a build whose radio is disabled", "critical", "local"),
    "PWN-2": ("Corrupt frame accepted by the parser", "medium", "local"),
    "PWN-3": ("Burst of refused commands", "medium", "local"),
    "PWN-4": ("Secure link disabled by command", "critical", "local"),
    "PWN-5": ("Memory read walking a range", "high", "local"),
    "PWN-6": ("Command gate disabled through an exemption", "critical", "local"),
}


@dataclass
class Detection:
    rule: str
    iob: str
    severity: str
    detail: str
    at: int
    direction: str = "capture"      # "up" from the console, "down" from the board
    taxonomy: str = "SPARTA"
    #: Wall clock, so the console can put an alert next to the lab that caused
    #: it. `at` is a frame counter and answers a different question.
    ts: float = field(default_factory=time.time)
    #: The octets that raised this, hex, truncated. An alert a student cannot
    #: look at is a claim, and the blue-team report asks for evidence.
    raw: str = ""
    #: What was known about the frame or the board event at the time. Small on
    #: purpose: the console polls this once a second.
    evidence: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return CATALOG.get(self.iob, ("?", "?", "?"))[0]

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "id": self.iob, "taxonomy": self.taxonomy,
            "severity": self.severity, "label": self.label,
            "detail": self.detail, "frame": self.at, "direction": self.direction,
            "ts": self.ts, "raw": self.raw, "evidence": self.evidence,
        }

    def __str__(self) -> str:
        arrow = {"up": "UP  ", "down": "DOWN", "capture": "    "}.get(self.direction, "    ")
        tag = self.iob if self.taxonomy == "SPARTA" else f"{self.iob}*"
        return (f"[{self.severity.upper():8}] {arrow} {self.rule:24} {tag:8} "
                f"{self.label} — {self.detail}")


def _ground_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    r = 6371.0
    la1, lo1, la2, lo2 = (math.radians(x) for x in (a[0], a[1], b[0], b[1]))
    h = (math.sin((la2 - la1) / 2) ** 2
         + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2)
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


class SpaceIDS:
    def __init__(self, *, unknown_rate_window: int = 50, unknown_rate_max: int = 5,
                 replay_window: int = 32, position_max_km: float = 60.0,
                 refused_window: int = 40, refused_max: int = 6,
                 flash_window: int = 30, flash_max: int = 4,
                 chain_window: int = 20,
                 radio_disabled_build: bool = True):
        self.known = set(APIDS)
        self.unknown_rate_window = unknown_rate_window
        self.unknown_rate_max = unknown_rate_max
        self.replay_window = replay_window
        self.position_max_km = position_max_km
        self.refused_window = refused_window
        self.refused_max = refused_max
        self.flash_window = flash_window
        self.flash_max = flash_max
        self.chain_window = chain_window
        # The course firmware holds both SX1262 in reset, so a frame that the
        # board says arrived by radio cannot have happened. Set False when
        # running against stock firmware.
        self.radio_disabled_build = radio_disabled_build
        self.reset()

    def reset(self) -> None:
        self._seq: dict[int, int] = {}
        self._seen: set[tuple[int, int]] = set()
        self._recent_unknown: list[int] = []
        self._recent_refused: list[int] = []
        self._recent_flash: list[int] = []
        self._was_secure: bool | None = None
        self._debug_enabled_at: int | None = None
        self._last_fix: tuple[float, float] | None = None
        self._authenticated = False
        self._n = 0
        self._direction = "capture"
        self._raw = b""
        self._evidence: dict = {}
        self.detections: list[Detection] = []

    # -- frame rules -------------------------------------------------------

    def _unknown_apid(self, p: SpacePacket, i: int) -> None:
        if p.apid in self.known:
            return
        self._recent_unknown.append(i)
        self._recent_unknown = [x for x in self._recent_unknown
                                if i - x <= self.unknown_rate_window]
        if len(self._recent_unknown) >= self.unknown_rate_max:
            self._fire("unknown-apid-rate", "UACE-9", i,
                       f"{len(self._recent_unknown)} unknown identifiers in "
                       f"{self.unknown_rate_window} frames")
            self._recent_unknown.clear()

    def _replay(self, p: SpacePacket, i: int) -> None:
        key = (p.apid, p.seq_count)
        if key in self._seen:
            self._fire("duplicate-frame", "UACE-7", i,
                       f"apid 0x{p.apid:03X} seq {p.seq_count} seen before")
            return
        self._seen.add(key)
        last = self._seq.get(p.apid)
        if last is not None and p.seq_count < last and last - p.seq_count < self.replay_window:
            self._fire("sequence-regression", "UACE-7", i,
                       f"apid 0x{p.apid:03X} went {last} -> {p.seq_count}")
        self._seq[p.apid] = max(p.seq_count, last or 0)

    def _length(self, p: SpacePacket, i: int) -> None:
        """Two distinct faults, and which one matters.

        A *mismatch* is any packet whose declared length disagrees with what
        arrived. An *underflow* is narrower: an application that subtracts its
        own header from the declared length, handed a value below that header.
        A one-octet payload is legal, so firing on every short packet is how a
        detection set becomes noise nobody reads."""
        real = len(p.raw) - SPP_HEADER
        if p.declared_payload != real:
            self._fire("length-mismatch", "UACE-8", i,
                       f"declared {p.declared_payload}, received {real}")
        elif p.apid in SUBTRACTING_APPS and p.declared_payload < APP_HEADER:
            self._fire("length-underflow", "UACE-8", i,
                       f"apid 0x{p.apid:03X} declared {p.declared_payload}, "
                       f"below its {APP_HEADER}-octet application header")

    def _unauthenticated_command(self, e: BoardEvent, i: int) -> None:
        """A critical command that ran with the secure link off.

        This used to key off the SPP secondary header, which was the course
        book's abstraction for "authenticated". The real firmware does not work
        that way: it protects the link by encrypting the payload and gating the
        command, and an ordinary legitimate command has no secondary header at
        all. Keeping the old rule would have fired on every command an operator
        sent, which is worse than having no rule.

        The board's own event says whether the secure link covered the frame
        and whether the command ran. That is the evidence, so that is the rule.
        """
        if not e.accepted or not e.executed:
            return
        if e.apid not in CRITICAL_APIDS:
            return
        if e.secure:
            return
        iob = "UACE-3" if e.apid in ACTUATOR_APIDS else "UACE-2"
        self._fire("unauthenticated-tc", iob, i,
                   f"{APIDS.get(e.apid, hex(e.apid))} executed with the secure link off")

    def _position_jump(self, p: SpacePacket, i: int) -> None:
        """A platform in low orbit sweeps its ground track at about 7 km per
        second. A fix that moves further than that between two consecutive
        reports did not come from the orbit. The ceiling is loose on purpose:
        it is not there to measure the orbit, it is there to be impossible to
        reach by flying."""
        if p.apid != APID_NAV or len(p.payload) < NAV_MIN_LEN:
            return
        lat = int.from_bytes(p.payload[NAV_LAT_OFFSET:NAV_LAT_OFFSET + 4],
                             "little", signed=True)
        lon = int.from_bytes(p.payload[NAV_LON_OFFSET:NAV_LON_OFFSET + 4],
                             "little", signed=True)
        fix = (lat / NAV_SCALE, lon / NAV_SCALE)
        last, self._last_fix = self._last_fix, fix
        if last is None:
            return
        km = _ground_km(last, fix)
        if km > self.position_max_km:
            self._fire("position-jump", "UCEB-8", i,
                       f"fix moved {km:.0f} km between consecutive reports, "
                       f"ceiling is {self.position_max_km:.0f} km")

    def _auth_order(self, p: SpacePacket, i: int) -> None:
        """The handover bug, and it is an ordering fault rather than a missing
        credential. The command carries a secondary header, so it looks
        authenticated, and the spacecraft acts on it before the exchange that
        establishes who sent it has completed. A command with no credential at
        all is a different finding, and unauthenticated-tc owns it."""
        if p.apid == APID_GS_ACCESS and not p.is_telecommand:
            self._authenticated = True
            return
        if p.is_telecommand and p.apid in CRITICAL_APIDS and not self._authenticated:
            self._fire("command-before-auth", "UACE-6", i,
                       f"{APIDS.get(p.apid, hex(p.apid))} accepted before the "
                       "ground-station exchange completed")

    # -- rules that need the board's own event channel ---------------------

    def _radio_origin(self, e: BoardEvent, i: int) -> None:
        """The course firmware holds both SX1262 in reset, so no frame can
        arrive by radio. If the board says one did, either it is not running
        the course build or the event stream is not coming from the board.

        This is the rule that keeps the "nothing radiates" claim honest for the
        length of the workshop instead of only at flashing time."""
        if self.radio_disabled_build and e.origin == "radio":
            self._fire("radio-origin-frame", "PWN-1", i,
                       f"board reports a frame from the air (apid 0x{e.apid:03X}, "
                       f"{e.rssi_dbm:+.1f} dBm) on a build whose radio is held in reset")

    def _crc_accepted(self, e: BoardEvent, i: int) -> None:
        if e.crc_bad and e.accepted:
            self._fire("crc-accepted", "PWN-2", i,
                       f"apid 0x{e.apid:03X} failed CRC and was accepted anyway")

    def _refused_burst(self, e: BoardEvent, i: int) -> None:
        """Attacks that fail are the early signal. One refusal is somebody
        getting a field wrong; a run of them is somebody working at it."""
        if e.accepted:
            return
        self._recent_refused.append(i)
        self._recent_refused = [x for x in self._recent_refused
                                if i - x <= self.refused_window]
        if len(self._recent_refused) >= self.refused_max:
            self._fire("refused-command-burst", "PWN-3", i,
                       f"{len(self._recent_refused)} commands refused in "
                       f"{self.refused_window} events")
            self._recent_refused.clear()

    def _secure_downgrade(self, e: BoardEvent, i: int) -> None:
        """The link stops being encrypted between one frame and the next.

        Alarm on the transition, not on the state: once it settles, a plaintext
        link looks exactly like a board that was never encrypted."""
        was, self._was_secure = self._was_secure, e.secure
        if was is True and not e.secure:
            self._fire("secure-link-downgrade", "PWN-4", i,
                       "the secure-link flag was set on the previous frame and is "
                       "clear on this one")

    def _flash_sweep(self, e: BoardEvent, i: int) -> None:
        """One read can be maintenance. A walk across offsets is a copy."""
        if e.apid != APID_FLASH_READ:
            return
        self._recent_flash.append(i)
        self._recent_flash = [x for x in self._recent_flash
                              if i - x <= self.flash_window]
        if len(self._recent_flash) >= self.flash_max:
            self._fire("flash-read-sweep", "PWN-5", i,
                       f"{len(self._recent_flash)} memory reads in "
                       f"{self.flash_window} events")
            self._recent_flash.clear()

    def _gate_chain(self, e: BoardEvent, i: int) -> None:
        """An exempt command, then the gate going down. Either alone is
        routine, which is exactly why only the pair is worth an alert."""
        if e.apid == APID_DEBUG_CONFIG and e.executed:
            self._debug_enabled_at = i
            return
        if (e.apid == APID_GS_MODE and e.executed
                and self._debug_enabled_at is not None
                and i - self._debug_enabled_at <= self.chain_window):
            self._fire("gate-exemption-chain", "PWN-6", i,
                       f"gate disabled {i - self._debug_enabled_at} events after an "
                       "exempt DEBUG_CONFIG")
            self._debug_enabled_at = None

    # ----------------------------------------------------------------------

    #: How many octets of the offending frame travel with the alert. Enough to
    #: show the primary header and the start of the payload, which is where
    #: every fault in this set lives, without turning the console poll into a
    #: packet capture.
    EVIDENCE_OCTETS = 48

    def _fire(self, rule: str, iob: str, at: int, detail: str) -> None:
        _, sev, tax = CATALOG.get(iob, ("", "medium", "local"))
        raw = self._raw[:self.EVIDENCE_OCTETS].hex()
        if len(self._raw) > self.EVIDENCE_OCTETS:
            raw += "..."
        self.detections.append(
            Detection(rule, iob, sev, detail, at, self._direction, tax,
                      time.time(), raw, dict(self._evidence)))

    def observe(self, p: SpacePacket, *, direction: str = "capture") -> list[Detection]:
        """Classify one frame as it goes past, and hand back only what it
        raised. This is what the sensor calls, once per frame, in both
        directions."""
        before = len(self.detections)
        i, self._n = self._n, self._n + 1
        self._direction = direction
        self._raw = p.raw
        self._evidence = {
            "kind": "TC" if p.is_telecommand else "TM",
            "apid": f"0x{p.apid:03X}",
            "app": p.name,
            "seq": p.seq_count,
            "declared": p.declared_payload,
            "received": len(p.raw) - SPP_HEADER,
            "sec_hdr": bool(p.sec_hdr),
        }
        for rule in (self._length, self._unknown_apid, self._replay,
                     self._position_jump, self._auth_order):
            rule(p, i)
        self._direction = "capture"
        self._raw, self._evidence = b"", {}
        return self.detections[before:]

    def observe_event(self, e: BoardEvent, *, direction: str = "down") -> list[Detection]:
        before = len(self.detections)
        i = self._n
        self._direction = direction
        self._raw = b""
        self._evidence = {
            "kind": "board event",
            "origin": e.origin,
            "apid": f"0x{e.apid:03X}",
            "app": APIDS.get(e.apid, "unknown"),
            "seq": e.sequence,
            "length": e.length,
            "result": e.result_text,
            "executed": e.executed,
            "secure": e.secure,
            "crc_bad": e.crc_bad,
            "armed": e.armed,
            "mission_mode": e.mission_mode,
        }
        if e.origin == "radio":
            self._evidence["rssi_dbm"] = e.rssi_dbm
            self._evidence["snr_db"] = e.snr_db
        for rule in (self._radio_origin, self._crc_accepted, self._refused_burst,
                     self._unauthenticated_command, self._secure_downgrade,
                     self._flash_sweep, self._gate_chain):
            rule(e, i)
        self._direction = "capture"
        self._raw, self._evidence = b"", {}
        return self.detections[before:]

    def observe_raw(self, raw: bytes, *, direction: str = "capture") -> list[Detection]:
        """Same, for bytes that may not survive a parse. A frame too short to
        hold a primary header is itself the finding."""
        from .spp import parse_spp
        try:
            p = parse_spp(raw)
        except ValueError:
            before = len(self.detections)
            i, self._n = self._n, self._n + 1
            self._direction = direction
            self._raw = raw
            self._evidence = {"kind": "unparsed", "received": len(raw)}
            self._fire("runt-frame", "UACE-8", i,
                       f"{len(raw)} octets, below the {SPP_HEADER}-octet primary header")
            self._direction = "capture"
            self._raw, self._evidence = b"", {}
            return self.detections[before:]
        return self.observe(p, direction=direction)

    def report(self) -> str:
        if not self.detections:
            return "no detections. Either the traffic was clean, or the rules are not watching."
        by: dict[str, list[Detection]] = {}
        for d in self.detections:
            by.setdefault(d.rule, []).append(d)
        lines = [f"{len(self.detections)} detection(s) across {len(by)} rule(s)", ""]
        for rule, ds in sorted(by.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"{rule}  ({len(ds)})")
            for d in ds[:3]:
                lines.append(f"    frame {d.at:5d}  {d.iob}  {d.detail}")
            if len(ds) > 3:
                lines.append(f"    ... and {len(ds) - 3} more")
        return "\n".join(lines)
