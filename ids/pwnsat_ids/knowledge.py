"""What each rule means, why it matters and how the fault is fixed.

The rules file says *how* a detection fires. This one says what to do with it,
and it exists because an alert that reads `declared 40, received 12` tells a
student what happened and nothing about whether it matters.

**Every entry carries its defence.** That is the house rule, not a stylistic
choice: SPARTA, NIST IR 8401 and CCSDS 355.0-B all describe threat and
countermeasure together, and an alert that names the attack without naming the
fix is half a finding. The console renders `fix` next to `why` for that reason.

`where` points at the line in this bench's own firmware, when there is one.
Paths are relative to `Bootcamp/Bench/firmware-norf/Firmware/`.
"""
from __future__ import annotations

# rule name -> what the console shows when you open the alert.
#   means  - what the sensor actually observed, in one sentence
#   why    - why it is worth an alert rather than a log line
#   fix    - the countermeasure, concrete enough to implement
#   where  - firmware location of the fault, when it has one
#   lab    - the lab that produces this alert
KNOWLEDGE: dict[str, dict] = {

    "unknown-apid-rate": {
        "iob": "UACE-9",
        "means": "Frames addressed to application identifiers this spacecraft "
                 "does not implement, arriving faster than a typo explains.",
        "why": "Nobody guesses an APID by accident. A sweep is the opening move "
               "of an operator who has the link but not the command list, and "
               "everything that comes after it depends on what the sweep "
               "returns. It is cheap, it is quiet, and it is the one stage "
               "where the attack is still only looking.",
        "fix": "Reject unknown identifiers at the deframer, count them, and "
               "downlink the count as housekeeping telemetry. A spacecraft "
               "that discards them silently hands over a free map of its "
               "command space.",
        "lab": "1.8 · Reconnaissance and command-space enumeration",
    },

    "duplicate-frame": {
        "iob": "UACE-7",
        "means": "An (APID, sequence count) pair that already crossed the "
                 "sensor crossed it a second time.",
        "why": "The frame is authentic. It was a legitimate command the first "
               "time, which is why authentication on its own does not stop "
               "this: every signature checks out. The spacecraft has no way "
               "to tell “do this” from “do this again”.",
        "fix": "An anti-replay window enforced on reception: keep the last N "
               "sequence counts per APID and refuse anything at or below the "
               "floor. CCSDS 355.0-B specifies it. This firmware has none.",
        "lab": "1.10 · Replay attacks",
    },

    "sequence-regression": {
        "iob": "UACE-7",
        "means": "The sequence count for one APID went backwards by less than "
                 "the width of the replay window.",
        "why": "Counters only go up. Going back means either a frame from an "
               "earlier session is being sent again, or the counter was "
               "written by hand. Both are worth stopping the pass for.",
        "fix": "Same window as above, plus refusing a counter that moves "
               "backwards at all outside of a declared session reset.",
        "lab": "1.10 · Replay attacks",
    },

    "length-mismatch": {
        "iob": "UACE-8",
        "means": "The packet's declared DATA LENGTH disagrees with the number "
                 "of octets that actually arrived.",
        "why": "The length field is the first thing an attacker can lie about. "
               "The firmware's transmit path sends no length prefix, so the "
               "deframer has to trust the header to know where the packet "
               "ends, and a parser that believes it reads past the buffer.",
        "fix": "Compare declared against received before dispatch and fail "
               "closed. The check costs two instructions and it is the one "
               "that was missing.",
        "lab": "2.1 · Protocol fuzzing and the integer-underflow crash",
    },

    "length-underflow": {
        "iob": "UACE-8",
        "means": "An application that subtracts its own header from the "
                 "declared length was handed a value below that header.",
        "why": "In unsigned arithmetic the result is not negative. "
               "`payload_total - 2` on a one-octet payload is "
               "18446744073709551615, and the copy sized by that number is "
               "the crash. The board stops answering and the pass is over.",
        "fix": "Test `declared >= APP_HEADER` before subtracting, or do the "
               "arithmetic in a signed type and check the sign. Validating "
               "length before using it is the general form.",
        "where": "worker.cpp:1612",
        "lab": "2.1 · Protocol fuzzing and the integer-underflow crash",
    },

    "runt-frame": {
        "iob": "UACE-8",
        "means": "Fewer than six octets arrived, which is not enough to hold a "
                 "CCSDS primary header.",
        "why": "There is nothing to parse. A deframer that tries anyway reads "
               "whatever the buffer held before this frame, and what it "
               "decides about those bytes drives everything downstream.",
        "fix": "A length check at the door, before any field is read.",
        "lab": "2.1 · Protocol fuzzing and the integer-underflow crash",
    },

    "unauthenticated-tc": {
        # UACE-3 when the command moved an actuator, UACE-2 otherwise. The
        # rule decides per event; the inventory shows both.
        "iob": "UACE-2",
        "iob_alt": "UACE-3",
        "means": "The board executed a command from its critical list while "
                 "the secure link was off.",
        "why": "This is the finding, not a precursor to one. The command ran. "
               "If it was SET_THRUSTER, something physical moved, and the "
               "console that should have authorised it was never consulted.",
        "fix": "Authenticate critical commands at the application layer, not "
               "only at the link, and keep the critical list in firmware so "
               "it cannot be edited from the ground. With the link clear, "
               "refuse.",
        "where": "worker.cpp:684",
        "lab": "2.2 · Command injection against an unauthenticated telecommand",
    },

    "position-jump": {
        "iob": "UCEB-8",
        "means": "The reported fix moved further between two consecutive NAV "
                 "reports than the orbit can carry it.",
        "why": "A platform in low orbit sweeps its ground track at about seven "
               "kilometres a second. A jump that cannot be flown did not come "
               "from the orbit; it came from whoever is writing the register. "
               "The ceiling is loose on purpose. It is not there to measure "
               "the orbit, it is there to be impossible to reach by flying.",
        "fix": "Do not condition any authorisation on a single sensor. "
               "Cross-check the fix against propagated ephemeris and the "
               "onboard clock, and treat a disagreement as loss of position "
               "rather than as a new position.",
        "lab": "2.3 · Position spoofing and the handover problem",
    },

    "command-before-auth": {
        "iob": "UACE-6",
        "means": "A critical command was accepted before the ground-station "
                 "exchange that establishes who sent it had completed.",
        "why": "An ordering fault rather than a missing credential. The "
               "command carries a secondary header, so it looks "
               "authenticated, and the spacecraft acts on it and verifies "
               "afterwards. A command with no credential at all is a "
               "different finding and `unauthenticated-tc` owns it.",
        "fix": "Make the gate a state machine. Nothing critical dispatches "
               "until the challenge-response has completed in this session, "
               "and the session ends when the contact does.",
        "where": "worker.cpp:415",
        "lab": "2.4 · Ground-station authentication spoofing",
    },

    "radio-origin-frame": {
        "iob": "PWN-1",
        "means": "The board reported a frame that arrived over the air, on a "
                 "build that holds both SX1262 transceivers in reset.",
        "why": "On the course firmware this cannot happen. Either the board is "
               "not running the course build, or the event stream is not "
               "coming from the board. This rule is what keeps “nothing "
               "radiates” a control for the length of the workshop instead of "
               "only at flashing time.",
        "fix": "Not a spacecraft fault but a bench integrity check. Reflash "
               "flatsat-course-noradio-v1.0.5.uf2 and read the boot banner: "
               "`[INFO] Radio: disabled (held in reset, course build)`.",
        "lab": "bench integrity · every lab",
    },

    "crc-accepted": {
        "iob": "PWN-2",
        "means": "The board's own event says the frame failed its CRC and was "
                 "accepted anyway.",
        "why": "The integrity check ran and its answer was thrown away. Every "
               "assumption downstream about those payload bytes is now "
               "unfounded, including the ones the operator is about to act on.",
        "fix": "Let the CRC result gate dispatch. A check whose outcome "
               "changes nothing is overhead, not a check.",
        "lab": "2.1 · Protocol fuzzing and the integer-underflow crash",
    },

    "refused-command-burst": {
        "iob": "PWN-3",
        "means": "A run of commands the board refused, inside a short window.",
        "why": "Attacks that fail are the early signal. One refusal is "
               "somebody getting a field wrong; a run of them is somebody "
               "working at it. This is the only rule in the set that fires "
               "while the attack is still losing.",
        "fix": "Nothing to repair in firmware, which is already refusing. "
               "Rate-limit the source and downlink the refusal count, so the "
               "ground sees the attempt instead of only its outcome.",
        "lab": "2.5 · Mission-ending command and availability",
    },

    "secure-link-downgrade": {
        "iob": "PWN-4",
        "means": "The secure-link flag was set on the previous frame and is "
                 "clear on this one.",
        "why": "Encryption that a command can switch off is a setting, not a "
               "protection. The alert is on the transition: once the link "
               "settles, a downgraded link looks exactly like a board that "
               "was never encrypted, and there is nothing left to see.",
        "fix": "No cleartext fallback. If the link cannot be established "
               "securely, the link is down, and the command that changes that "
               "policy is itself critical.",
        "where": "worker.cpp:684",
        "lab": "2.6 · Secure-link downgrade by telecommand",
    },

    "flash-read-sweep": {
        "iob": "PWN-5",
        "means": "Repeated memory reads inside a short window, walking across "
                 "offsets.",
        "why": "One read can be maintenance. A walk across offsets is a copy. "
               "What comes off this board's flash is the AES key, which is "
               "fixed, shared by every unit, and good until somebody "
               "reflashes all of them.",
        "fix": "Do not hold a long-lived key in readable flash and do not "
               "expose an arbitrary-offset read to the ground. Per-session "
               "keys, derived at contact, with the root held where the "
               "command path cannot reach it.",
        "lab": "2.7 · Reading flash from the ground",
    },

    "gate-exemption-chain": {
        "iob": "PWN-6",
        "means": "A command exempt from the ground-station gate ran, and the "
                 "gate went down shortly after.",
        "why": "Either half is routine, which is exactly why only the pair is "
               "worth an alert. The exemption list is the way in: "
               "DEBUG_CONFIG does not need the gate, and what it sets is the "
               "flag that makes the gate stop asking.",
        "fix": "An exemption list is an authorisation decision and belongs in "
               "a review. No exempt command may change the state of the gate "
               "itself.",
        "where": "worker.cpp:424",
        "lab": "2.8 · Walking through an exemption in the gate",
    },
}

# The two attacks in the syllabus this sensor does not catch, and why. They are
# on the console on purpose. A detection set that only lists its wins teaches
# students to trust a green screen.
BLIND_SPOTS = [
    {
        "attack": "Passive eavesdropping",
        "lab": "1.9 · Passive eavesdropping and static-key recovery",
        "why": "Listening leaves no trace on the link. Nothing is sent, "
               "nothing is malformed, no counter moves. There is no frame for "
               "a rule to look at.",
        "fix": "Per-session keys and rotation. The attack is not detected, it "
               "is made worthless: a recovered key that expires with the "
               "contact buys nothing.",
    },
    {
        "attack": "Mission-ending command",
        "lab": "2.5 · Mission-ending command and availability",
        "why": "`unauthenticated-tc` fires, and it fires correctly, after the "
               "command has executed. For a reset or a payload shutdown there "
               "is no window between detecting and having lost the platform.",
        "fix": "A critical-command list enforced in firmware and a second "
               "operator required on the ground. The control has to sit "
               "before execution, because detection cannot.",
    },
]


def for_rule(rule: str) -> dict:
    return KNOWLEDGE.get(rule, {})


def inventory() -> list[dict]:
    """Every rule in the set, fired or not, with its severity and provenance.

    The console shows this whether or not anything has happened. A sensor that
    only becomes visible when it alerts leaves the student with no way to tell
    "nothing is wrong" from "nothing is watching", and those look identical on
    an empty screen.
    """
    from .rules import CATALOG
    out = []
    for rule, k in KNOWLEDGE.items():
        label, severity, taxonomy = CATALOG.get(k["iob"], ("?", "medium", "local"))
        ids = [k["iob"]] + ([k["iob_alt"]] if "iob_alt" in k else [])
        out.append({
            "rule": rule, "ids": ids, "label": label,
            "severity": severity, "taxonomy": taxonomy,
            "means": k["means"], "why": k["why"], "fix": k["fix"],
            "where": k.get("where", ""), "lab": k.get("lab", ""),
        })
    order = {"critical": 0, "high": 1, "medium": 2}
    return sorted(out, key=lambda d: (order.get(d["severity"], 9), d["rule"]))
