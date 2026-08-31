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


def verify_dataset_manifests(problems):
    """Verify all 22 per-run DATASET.sha256 manifests before any analysis reads a capture."""
    mans = sorted(glob.glob(os.path.join(ROOT, "s[0-9][0-9]", "provenance", "DATASET.sha256")))
    if len(mans) != 22:
        problems.append(f"manifests: found {len(mans)} DATASET.sha256 files, expected 22")
    n_entries = 0
    for man in mans:
        run_dir = os.path.dirname(os.path.dirname(man))
        for line in open(man):
            line = line.strip()
            if not line:
                continue
            want, rel = line.split(None, 1)
            path = os.path.join(run_dir, rel)
            if not os.path.exists(path):
                problems.append(f"manifest {os.path.relpath(man, ROOT)}: {rel} missing")
                continue
            got = sha256(path)
            if got != want:
                problems.append(f"manifest {os.path.relpath(man, ROOT)}: {rel} "
                                f"hash {got[:12]} != recorded {want[:12]}")
            n_entries += 1
    return len(mans), n_entries


def compare_frozen_table(rows, problems):
    """Compare the regenerated table row by row against the frozen scapy-extracted table.

    The frozen table carries session, block, arm, txn_class and the three intervals, in
    per-capture order. Both tables store six decimals of a millisecond, so the comparison
    tolerance is one unit in that last stored place and is justified by nothing else.
    """
    frozen_path = os.path.join(ROOT, "derived", "transactions.csv")
    if not os.path.exists(frozen_path):
        problems.append("frozen table derived/transactions.csv is missing")
        return None
    TOL = 1e-6                      # one unit in the last stored decimal place
    frozen = []
    with open(frozen_path) as f:
        for r in csv.DictReader(f):
            frozen.append(r)
    if len(frozen) != len(rows):
        problems.append(f"frozen table: {len(frozen)} rows != regenerated {len(rows)}")
        return None
    # Per-capture ordinal position is the stable key; both producers walk each capture in
    # capture order, so row i of a capture must describe the same transaction in both.
    seen = 0
    for i, (a, b) in enumerate(zip(rows, frozen)):
        if a["run"] != b["session"] or a["block"] != b["block"] or a["arm"] != b["arm"]:
            problems.append(f"frozen table row {i}: identity "
                            f"({a['run']},{a['block']},{a['arm']}) != "
                            f"({b['session']},{b['block']},{b['arm']})")
            break                       # ordering has diverged; later rows are meaningless
        if a["txn_class"] != b["txn_class"]:
            problems.append(f"frozen table row {i}: class {a['txn_class']} != {b['txn_class']}")
            break
        for col in ("clrt_ms", "ack_ms", "rt_ms"):
            if abs(float(a[col]) - float(b[col])) > TOL:
                problems.append(f"frozen table row {i} ({a['capture']} #{a['idx']}): "
                                f"{col} {a[col]} != {b[col]}")
                break
        seen += 1
    return seen


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    caps = sorted(glob.glob(os.path.join(ROOT, "s[0-9][0-9]", "raw_pcaps", "*.pcap")))
    problems, rows, per_cap, hashes = [], [], [], {}
    n_manifests, n_manifest_entries = verify_dataset_manifests(problems)
    print(f"manifests verified: {n_manifests} DATASET.sha256, {n_manifest_entries} entries, "
          f"{len(problems)} problems")
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
        # `idx` is the transaction's ordinal position within its capture. Together with the
        # capture name it is the stable key that lets the regenerated table be compared row by
        # row against the frozen table, which preserves the same per-capture order.
        for idx, e in enumerate(rep.exchanges):
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
            rows.append(dict(run=run, block=block, arm=arm, capture=base, idx=idx,
                             txn_class=P.FUNC_NAME.get(e.func, str(e.func)),
                             func=e.func, req_seq=e.req_seq, resp_func=e.resp_func,
                             t_req=repr(e.t_req), t_ack=repr(e.t_ack), t_resp=repr(e.t_resp),
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

    # ---- row-by-row agreement with the frozen, independently extracted table
    n_compared = compare_frozen_table(rows, problems)

    with open(os.path.join(out_dir, "transactions_canonical.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    with open(os.path.join(out_dir, "per_capture.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(per_cap[0].keys())); w.writeheader(); w.writerows(per_cap)
    report = dict(captures=len(caps), exchanges=len(rows),
                  expectations={k: {"got": g, "want": w_} for k, (g, w_) in expectations.items()},
                  dataset_manifests_verified=n_manifests,
                  dataset_manifest_entries_verified=n_manifest_entries,
                  frozen_table_rows_compared=n_compared,
                  frozen_table_comparison=("row-by-row against derived/transactions.csv on "
                                           "identity, ordering, class and the three intervals, "
                                           "tolerance 1e-6 ms = one unit in the last stored "
                                           "decimal place"),
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
