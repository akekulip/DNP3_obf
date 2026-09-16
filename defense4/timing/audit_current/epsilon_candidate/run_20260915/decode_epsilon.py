#!/usr/bin/env python3
"""Decode the epsilon registers from the preserved raw rows. Offline; reads only jsonl.

    python3 decode_epsilon.py epsilon_v2.jsonl

DECODE VERSION 2, which differs from the arithmetic used in `RESULT_V2.md`:

* **The deadline word is not a timestamp.** The program stores it as
  `(timestamp & TICK_MASK) | ARMED_MARK`, with `TICK_MASK = 0xFFFFFF00` and `ARMED_MARK = 1`, so
  the low byte carries the armed flag rather than nanoseconds. Version 1 subtracted the raw word,
  which made every interval one nanosecond short and produced at least one negative value.
* **A negative value was called a clock wrap.** Row 4's first ACK expiry, 562737152, against the
  deadline word 562737153, gives -1 ns undecoded. Decoded, the deadline is 562737152 and the
  interval is 0 ns. It was never a wrap, and treating it as one would have hidden a decode error
  behind a plausible-sounding explanation.
* **Wrap is handled explicitly and narrowly.** The register is 32 bits of nanoseconds, so it wraps
  about every 4.295 s. A modular difference is accepted only when it falls inside
  `MAX_PLAUSIBLE_NS`; anything larger is reported as rejected rather than silently folded.

What the numbers are, stated at their endpoints. Both timestamps come from
`ig_intr_md.ingress_mac_tstamp`, taken in **ingress**, on a blocker token that is recirculating.
The interval therefore runs from the stored release deadline to the ingress timestamp of the last
blocker token that terminated because that deadline had passed. That is an internal
blocker-termination interval. It is **not** the held packet's departure from the wire, and it is
not a traffic-manager queue-empty time: ingress sees a packet arrive, and this program has no
egress timestamp register, so whatever service and egress time follows the last blocking action is
outside these numbers. `epsilon` in the paper's sense is the post-deadline blocking interval, and
this measures it up to that last blocking action only.
"""
from __future__ import annotations

import json
import statistics
import sys

DECODE_VERSION = 2
TICK_MASK = 0xFFFFFF00
ARMED_MARK = 1
MOD = 1 << 32
#: A blocking interval is microseconds, not seconds. Anything beyond this is not a plausible
#: post-deadline interval on this mechanism and is reported rather than wrapped into range.
MAX_PLAUSIBLE_NS = 10_000_000          # 10 ms


def decode_deadline(word: int) -> tuple[int, bool]:
    """(deadline_ns, armed). A zero word means the slot was never written."""
    if word == 0:
        return 0, False
    return word & TICK_MASK, bool(word & ARMED_MARK)


def interval_ns(later: int, deadline_word: int) -> tuple[int | None, str]:
    """Modular difference from a decoded deadline to a raw ingress timestamp."""
    deadline, armed = decode_deadline(deadline_word)
    if not deadline_word:
        return None, "deadline slot never written"
    if not armed:
        return None, "deadline word %d has no armed marker" % deadline_word
    if not later:
        return None, "sample slot never written"
    d = (later - deadline) % MOD
    if d > MAX_PLAUSIBLE_NS:
        return None, "modular difference %d ns exceeds the plausible bound" % d
    return d, ""


def summarise(values: list[int]) -> dict:
    if not values:
        return {"n": 0}
    return {"n": len(values), "median": statistics.median(values),
            "min": min(values), "max": max(values),
            "sd": round(statistics.stdev(values), 2) if len(values) > 1 else 0.0}


def main(path: str) -> int:
    rows = [json.loads(ln) for ln in open(path) if ln.strip()]
    lanes = {
        "ack_detection": ("expiry_first_ack", "deadline_ack"),
        "ack_block_termination": ("block_last_ack", "deadline_ack"),
        "resp_detection": ("expiry_first_resp", "deadline_resp"),
        "resp_block_termination": ("block_last_resp", "deadline_resp"),
    }
    out = {"decode_version": DECODE_VERSION, "source": path, "rows": len(rows),
           "quantity": "internal blocker-termination interval, ingress to ingress",
           "not_measured": "the held packet's departure from the wire",
           "lanes": {}}
    for name, (sample_key, deadline_key) in lanes.items():
        good, rejected = [], []
        for i, r in enumerate(rows):
            v, why = interval_ns(r.get(sample_key, 0), r.get(deadline_key, 0))
            (good.append(v) if v is not None else rejected.append({"row": i, "why": why}))
        out["lanes"][name] = dict(summarise(good), rejected=rejected)
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "epsilon_v2.jsonl"))
