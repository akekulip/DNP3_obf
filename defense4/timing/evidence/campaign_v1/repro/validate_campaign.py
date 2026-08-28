"""Validate every campaign_v1 capture and emit the canonical transaction table.

Raw pcaps are the only trusted input. The frozen transactions.csv and the per-capture
JSONL driver logs are treated as claims to be checked, never as sources.
"""
from __future__ import annotations
import csv, glob, json, hashlib, os, sys
from collections import Counter, defaultdict
import pcap_dnp3 as P

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_OK = 0


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    caps = sorted(glob.glob(os.path.join(ROOT, "s[0-9][0-9]", "raw_pcaps", "*.pcap")))
    problems, rows, per_cap, hashes = [], [], [], {}
    for pc in caps:
        base = os.path.basename(pc)[:-5]
        run, block, arm = base.split("_", 2)
        rep = P.extract(pc)
        hashes[base] = sha256(pc)
        cnt = Counter(P.FUNC_NAME.get(e.func, str(e.func)) for e in rep.exchanges)
        # ---- per-capture structural expectations
        exp = {"READ": 400, "SELECT": 40, "OPERATE": 40}
        for k, v in exp.items():
            if cnt.get(k, 0) != v:
                problems.append(f"{base}: {k} count {cnt.get(k,0)} != {v}")
        if rep.frames != 1448:
            problems.append(f"{base}: frames {rep.frames} != 1448")
        if rep.wire_bytes != 130708:
            problems.append(f"{base}: wire bytes {rep.wire_bytes} != 130708")
        for label, val in (("retransmissions", rep.retransmissions),
                           ("malformed", rep.malformed),
                           ("unpaired requests", rep.unpaired_requests),
                           ("out-of-order timestamps", rep.out_of_order_ts),
                           ("wrong-endpoint payloads", rep.wrong_endpoint)):
            if val:
                problems.append(f"{base}: {val} {label}")
        # ---- per-exchange checks
        for e in rep.exchanges:
            ack_ms = (e.t_ack - e.t_req) * 1e3
            clrt_ms = (e.t_resp - e.t_ack) * 1e3
            rt_ms = (e.t_resp - e.t_req) * 1e3
            if not (e.t_req <= e.t_ack <= e.t_resp):
                problems.append(f"{base}: non-monotonic exchange at {e.t_req:.6f}")
            if abs((ack_ms + clrt_ms) - rt_ms) > 1e-6:
                problems.append(f"{base}: latency identity violated")
            if e.resp_func != P.RESP_FUNC:
                problems.append(f"{base}: response func 0x{e.resp_func:02x} != 0x81")
            if e.func in (3, 4) and e.status != STATUS_OK:
                problems.append(f"{base}: {P.FUNC_NAME[e.func]} status {e.status} != SUCCESS")
            rows.append(dict(run=run, block=block, arm=arm,
                             txn_class=P.FUNC_NAME.get(e.func, str(e.func)),
                             func=e.func, t_req=repr(e.t_req),
                             ack_ms=round(ack_ms, 6), clrt_ms=round(clrt_ms, 6),
                             rt_ms=round(rt_ms, 6),
                             status=("SUCCESS" if e.status == 0 else e.status)))
        per_cap.append(dict(capture=base, run=run, block=block, arm=arm,
                            frames=rep.frames, wire_bytes=rep.wire_bytes,
                            cap_bytes=rep.cap_bytes, tcp_syn_frames=rep.syn,
                            tcp_connections=rep.syn // 2,
                            exchanges=len(rep.exchanges),
                            read=cnt.get("READ", 0), select=cnt.get("SELECT", 0),
                            operate=cnt.get("OPERATE", 0),
                            high_level_ops=cnt.get("READ", 0) + cnt.get("SELECT", 0),
                            sha256=hashes[base]))
    # ---- corpus-level expectations
    tot = Counter(r["txn_class"] for r in rows)
    per_arm = Counter((r["arm"], r["txn_class"]) for r in rows)
    expectations = {
        "captures": (len(caps), 132),
        "exchanges_total": (len(rows), 63360),
        "READ_total": (tot["READ"], 52800), "SELECT_total": (tot["SELECT"], 5280),
        "OPERATE_total": (tot["OPERATE"], 5280),
        "grouped_runs": (len({r["run"] for r in rows}), 22),
    }
    for arm in ("native", "obfuscated"):
        expectations[f"{arm}_exchanges"] = (sum(v for (a, _), v in per_arm.items() if a == arm), 31680)
        for c, v in (("READ", 26400), ("SELECT", 2640), ("OPERATE", 2640)):
            expectations[f"{arm}_{c}"] = (per_arm[(arm, c)], v)
    for k, (got, want) in expectations.items():
        if got != want:
            problems.append(f"corpus: {k} = {got}, expected {want}")
    # unique hashes (captures are equal in size, not identical in content)
    if len(set(hashes.values())) != len(hashes):
        problems.append("corpus: capture hashes are not unique")

    with open(os.path.join(out_dir, "transactions_canonical.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    with open(os.path.join(out_dir, "per_capture.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(per_cap[0].keys())); w.writeheader(); w.writerows(per_cap)
    report = dict(captures=len(caps), exchanges=len(rows),
                  expectations={k: {"got": g, "want": w_} for k, (g, w_) in expectations.items()},
                  unique_capture_hashes=len(set(hashes.values())),
                  distinct_frame_counts=sorted({c["frames"] for c in per_cap}),
                  distinct_wire_byte_counts=sorted({c["wire_bytes"] for c in per_cap}),
                  tcp_connections_per_capture=sorted({c["tcp_connections"] for c in per_cap}),
                  high_level_ops_per_capture=sorted({c["high_level_ops"] for c in per_cap}),
                  problems=problems)
    with open(os.path.join(out_dir, "validation_report.json"), "w") as f:
        json.dump(report, f, indent=1)
    print(f"captures={len(caps)}  exchanges={len(rows)}  problems={len(problems)}")
    for k, (g, w_) in expectations.items():
        print(f"  {'OK ' if g == w_ else 'BAD'} {k:22s} {g}")
    print(f"  unique capture hashes: {len(set(hashes.values()))}/{len(hashes)}")
    print(f"  frames per capture: {sorted({c['frames'] for c in per_cap})}")
    print(f"  wire bytes per capture: {sorted({c['wire_bytes'] for c in per_cap})}")
    print(f"  TCP connections per capture: {sorted({c['tcp_connections'] for c in per_cap})}")
    print(f"  high-level ops per capture: {sorted({c['high_level_ops'] for c in per_cap})}")
    for p in problems[:15]:
        print("  PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/campaign_v1_out"))
