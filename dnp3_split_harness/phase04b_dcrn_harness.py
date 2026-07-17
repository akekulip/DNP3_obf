#!/usr/bin/env python3
"""phase04b_dcrn_harness.py -- unprivileged DCRN replay harness (corrective.md sec 11).

Builds a per-profile replay spec (real request/response bytes + each profile's NATIVE ACK structure --
SEL-751 separate, AB1400/ION7550 combined) and drives the tested stdlib replay server/client
(phase05_rig_replay.py) so the DCRN data plane -- loaded externally by the privileged prepare script --
re-times whatever native structure the replay produces. The harness itself changes NO ACK mode: the
separate/combined structure comes from the captured profiles; DCRN only re-times egress packets.

Roles:
  build : write spec.json (per-profile native-structure transactions) for the campaign.
  (the actual server/client replay reuses phase05_rig_replay.py, invoked by the campaign scripts.)

Capture and BPF load/unload are done by the privileged scripts; this stays unprivileged.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import characterize_ack_traces as C
import phase04b_dcrn_policy as D   # noqa: F401 (kept: campaign predicts expected release via the oracle)
import phase05_defended_wire_eval as DW

TRAFFIC = "/home/philip/Projects/DNP3/Traffic Trace"
PCAPS = ["SEL751.pcap", "SEL751L.pcap", "AB1400.pcap", "AB1400L.pcap", "ION7550.pcap", "ION7550L.pcap"]


def build_spec(max_per_pcap: int, out_path: str) -> dict:
    """Per-profile native-structure replay spec: real bytes + native ACK mode + native timing.

    Unlike the Phase-05 spec, DCRN uses ONE structural condition -- native -- because DCRN preserves
    packet structure and only re-times. The DCRN treatment (fixed/bounded) is applied externally by the
    loaded eBPF, not by the replay.
    """
    replay = {}
    counts = {}
    for name in PCAPS:
        device = C.device_from_pcap(name)
        txns = DW.device_transactions(os.path.join(TRAFFIC, name), name, device, max_per_pcap)
        # [req_hex, resp_hex, native_req_to_resp_ms, native_is_separate]
        replay[name] = [[r.hex(), s.hex(), ms, sep] for (r, s, ms, sep) in txns]
        counts[name] = len(txns)
    spec = {
        "port": 20000, "conditions": ["native"], "pcaps": PCAPS, "replay": replay,
        # keys consumed by the reused phase05_rig_replay server (native structure only); DCRN re-times
        # at egress independently of these server-side values.
        "delayed_ack_window_ms": 40.0, "edt_target_ms": 25.0,
        "_counts": counts,
        "_note": ("native structure only: DCRN preserves separate/combined and re-times at egress. "
                  "The DCRN fixed/bounded treatment is the externally-loaded eBPF, applied per campaign "
                  "condition; the replay is identical across NATIVE / OLD_APPLICATION_SCHEDULER / "
                  "DCRN_FIXED / DCRN_COMMON_BOUNDED so the comparison isolates the timing mechanism."),
    }
    with open(out_path, "w") as fh:
        json.dump(spec, fh)
    return spec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("role", choices=["build"])
    ap.add_argument("--out", default="/tmp/phase04b_run/spec.json")
    ap.add_argument("--max-per-pcap", type=int, default=120)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    spec = build_spec(args.max_per_pcap, args.out)
    print("spec written -> %s  per-pcap: %s" % (args.out, spec["_counts"]))
    print("replay is reused from phase05_rig_replay.py (server/client); DCRN treatment is external eBPF.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
