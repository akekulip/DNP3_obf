#!/usr/bin/env python3
"""Reproduce smoke-test counts and master-visible timing from retained evidence."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics
import sys

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[1]
sys.path.insert(0, str(STAGE.parent / "analysis"))
from dnp3_timing import extract_transactions, read_packets

identity = json.loads((HERE / "switch/loaded_identity.json").read_text())
manifest = json.loads((STAGE / "evidence/candidate_sde9132/manifest.json").read_text())
source_sha = hashlib.sha256((STAGE / "src/defense4_timing.p4").read_bytes()).hexdigest()
assert identity["source_sha256"] == manifest["source_sha256"] == source_sha
assert identity["artifact_sha256"] == manifest["artifact_sha256"]
assert (identity["ingress_stages"], identity["egress_stages"]) == (7, 0)
report = {"source_sha256": source_sha, "program": identity["program"],
          "ingress_stages": 7, "egress_stages": 0, "arms": {}}
for label, config, mode in [("timing_off", "off", 0), ("obfuscated", "d4", 4)]:
    root = HERE / "vision" / label
    state = json.loads((HERE / "switch" / ("config_" + config + ".json")).read_text())
    params = state["tables"]["pipe.Ingress.tbl_params"]["default"][0]
    bor = state["tables"]["pipe.Ingress.tbl_bor_params"]["default"][0]
    assert params["mode"] == mode and params["read_len"] == 0
    assert params["d_ticks"] == bor["a_ticks"] == 20000000
    assert params["da_dr"] == bor["r_ticks"] == 24000000
    assert params["budget"] == 18000 and bor["anchor_req"] == 1
    outcomes = [json.loads(line) for name in ("read.jsonl", "sbo.jsonl")
                for line in (root / name).read_text().splitlines()]
    counts = Counter(r["operation"] for r in outcomes)
    assert counts == {"READ": 20, "SELECT": 10, "OPERATE": 10}
    assert all(r["outcome"] == "OK" and not r["problems"] for r in outcomes)
    assert sum(r["stale_frames_discarded"] for r in outcomes) == 0
    for name in ("outputs_before.log", "outputs_after.log"):
        outputs = json.loads((root / name).read_text())
        assert outputs["points"] == 32 and outputs["all_open"] and outputs["all_online"]
    cap = root / "traffic.pcapng"
    # The extra G10 reads request points 0..31 for output status. Functional READ
    # requests use the frozen 0..22 range and are the timing sample reported here.
    safety = {p.t_ns for p in read_packets(cap)
              if p.from_master and p.dnp3_func == 1 and len(p.payload) > 17
              and p.payload[17] == 31}
    txns = [t for t in extract_transactions(cap) if t.t_req_ns not in safety]
    arm = {"application_counts": dict(counts), "failed": 0, "stale_frames": 0,
           "output_status": "32/32 online and open before and after",
           "captured_additional_output_polls": len(safety), "timing_ms": {}}
    for func, name in [(1, "READ"), (3, "SELECT"), (4, "OPERATE")]:
        rows = [t for t in txns if t.req_func == func]
        assert len(rows) == counts[name] and all(t.clrt_ms is not None for t in rows)
        arm["timing_ms"][name] = {"n": len(rows)}
        for metric in ("ack_ms", "resp_ms", "clrt_ms"):
            values = [getattr(t, metric) for t in rows]
            arm["timing_ms"][name][metric] = {
                "median": round(statistics.median(values), 6),
                "min": round(min(values), 6), "max": round(max(values), 6)}
        if mode == 4:
            assert 3.9 <= arm["timing_ms"][name]["clrt_ms"]["median"] <= 4.1
    report["arms"][label] = arm
(HERE / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
