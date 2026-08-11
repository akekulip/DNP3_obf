#!/usr/bin/env python3
"""Wire-gate scorer — decides whether an OBSERVED DNP3 response is device-independent.

The wire gate (silicon) captures outstation->master responses on Vision, the passive observer's
vantage. This scorer checks each captured response against the joint defense's public contract:
  * SIZE/STRUCTURE — canonical G30 V3, 54 B (matches canonical_response.CANON signature);
  * TIMING         — the ACK->response CLRT equals the public deadline (constant, native-independent);
  * INTEGRITY      — the frame is well-formed DNP3 (CRCs valid) so the master's SOE still decodes.
A native, un-normalized response FAILS (wrong size/variation/CLRT) -> the scorer has teeth, so a PASS
on real silicon is meaningful.

This is the SEL-751 READ wire-gate scorer. SBO (Group-12 control) is a separate contract, validated
offline + against the software outstation (the physical relay stays READ-only).

Run:  python3 wire_gate_score.py       # self-test: canonical capture PASSes, native capture FAILs
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from canonical_response import (structural_signature, parse_response, _strip_blocks,   # noqa: E402
                                DNP3ParseError, G30, VAR3, QUAL00, PUB_STOP)

# the single public canonical signature every observed response must present (device-independent)
CANON_SIG = (54, G30, VAR3, QUAL00, 1, PUB_STOP, 4)


def _crc_ok(frame):
    try:
        _strip_blocks(frame)
        return True
    except DNP3ParseError:
        return False


def score_response(frame, clrt_ms, deadline_ms, tol_ms=1.0):
    """Per-check PASS/FAIL for one observed (frame, CLRT). All True == indistinguishable + on-time."""
    try:
        p = parse_response(frame)
        sig = structural_signature(frame)
    except DNP3ParseError:
        p, sig = None, None
    return {
        "size: wire length == 54 B (public)": len(frame) == 54,
        "structure == canonical signature": sig == CANON_SIG,
        "variation == V3 (no per-point flag)": p is not None and p["var"] == VAR3,
        "integrity: DNP3 well-formed (CRCs valid, SOE-decodable)": _crc_ok(frame),
        "timing: CLRT == public deadline (+/- %.1f ms)" % tol_ms: abs(clrt_ms - deadline_ms) <= tol_ms,
    }


def score_capture(responses, deadline_ms, tol_ms=1.0):
    """responses = [(frame, clrt_ms), ...]. Returns (per_response_checks, device_independent, all_pass)."""
    per = [score_response(f, c, deadline_ms, tol_ms) for f, c in responses]
    sigs = set()
    for f, _ in responses:
        try:
            sigs.add(structural_signature(f))
        except DNP3ParseError:
            sigs.add(None)
    device_independent = (sigs == {CANON_SIG})           # ALL responses present the ONE canonical shape
    all_pass = all(all(cs.values()) for cs in per)
    return per, device_independent, all_pass


# --------------------------------------------------------------------------- self-test
def main():
    from canonical_response import _load_corpus, canonicalize
    corpus = _load_corpus()
    DEADLINE = 10.0                                       # public CLRT deadline (ms)
    NATIVE_CLRT = {"sel751": 1.4, "ion7550": 1.6, "ab1400": 1.5}   # measured native medians

    # (a) what the switch SHOULD emit: canonical frames, released at the deadline
    canon_cap = [(canonicalize(f), DEADLINE) for _, f in corpus.values()]
    _, di_c, pass_c = score_capture(canon_cap, DEADLINE)

    # (b) what a NATIVE (undefended) outstation emits: raw frames at native timing -> must FAIL
    native_cap = [(f, NATIVE_CLRT[dev]) for dev, (_, f) in corpus.items()]
    per_n, di_n, pass_n = score_capture(native_cap, DEADLINE)

    checks = []
    checks.append(("canonical capture: every check passes", pass_c))
    checks.append(("canonical capture: device-independent (one public signature)", di_c))
    checks.append(("native capture: FAILS (scorer has teeth)", not pass_n))
    checks.append(("native capture: NOT device-independent (models leak)", not di_n))
    # the ION7550 native response must be the one that trips size+variation+timing
    ion_native = score_response(corpus["ion7550"][1], NATIVE_CLRT["ion7550"], DEADLINE)
    checks.append(("native ION7550 fails size", not ion_native["size: wire length == 54 B (public)"]))
    checks.append(("native ION7550 fails variation",
                   not ion_native["variation == V3 (no per-point flag)"]))
    checks.append(("native (all) fails timing (native CLRT != deadline)",
                   not any(score_response(f, NATIVE_CLRT[d], DEADLINE)[
                       "timing: CLRT == public deadline (+/- 1.0 ms)"] for d, (_, f) in corpus.items())))

    print("%-60s RES" % "CHECK")
    print("-" * 66)
    npass = 0
    for name, ok in checks:
        print("%-60s %s" % (name, "PASS" if ok else "FAIL"))
        npass += ok
    print("-" * 66)
    print("WIRE-GATE SCORER self-test: %d/%d pass" % (npass, len(checks)))
    print("\nHeadline: a correctly-defended capture (canonical + deadline) scores device-independent;")
    print("a native capture FAILS on size/variation/timing -> the scorer distinguishes defended traffic.")
    sys.exit(0 if npass == len(checks) else 1)


if __name__ == "__main__":
    main()
