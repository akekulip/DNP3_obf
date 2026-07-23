#!/usr/bin/env python3
"""
Analyze the 300-poll physical-SEL-751 CLRT experiment.

Inputs : evidence/<exp>.pcap  (authoritative wire timing) + evidence/clrt_app_metadata.jsonl
Outputs: per_poll.csv, per_poll.json, summary.csv, plots/*.png, CLRT_EXPERIMENT_REPORT.md

Per-poll wire fields come from the pcap; decoded_point_count/completion/error from the app JSONL,
merged by transaction order. Retransmissions are de-duplicated on TCP sequence number. TCP anomaly
counts (retransmission / duplicate-ack / reset / lost-segment) come from tshark's tcp.analysis.
"""
import os, sys, json, hashlib, subprocess
import numpy as np
from scapy.all import PcapReader, TCP, IP

EXP = "clrt_300poll_20260723T152242"
BASE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.join(BASE, "evidence")
PCAP = os.path.join(EV, EXP + ".pcap")
JSONL = os.path.join(EV, "clrt_app_metadata.jsonl")
PLOTS = os.path.join(BASE, "plots")
RELAY, VIS = "192.168.10.7", "192.168.10.1"
FUNC = {0: "CONFIRM", 1: "READ", 129: "RESPONSE", 130: "UNSOL_RESPONSE"}
RNG = np.random.default_rng(20260723)   # fixed seed => reproducible bootstrap


def dnp3(pl):
    if len(pl) < 13 or pl[:2] != b"\x05\x64":
        return None
    ac = pl[11]
    d = dict(link_len=pl[2], dst=pl[4] | (pl[5] << 8), src=pl[6] | (pl[7] << 8),
             fir=(ac >> 7) & 1, fin=(ac >> 6) & 1, con=(ac >> 5) & 1, seq=ac & 0x0f,
             func=pl[12], func_name=FUNC.get(pl[12], pl[12]))
    if pl[12] == 129 and len(pl) >= 15:
        d["iin_lsb"], d["iin_msb"] = pl[13], pl[14]
    else:
        d["iin_lsb"] = d["iin_msb"] = None
    return d


def load_pcap():
    pkts = []
    for p in PcapReader(PCAP):
        if TCP not in p or IP not in p:
            continue
        t = p[TCP]
        pkts.append(dict(time=float(p.time), src=("VIS" if p[IP].src == VIS else "RELAY"),
                         sport=int(t.sport), dport=int(t.dport), flags=int(t.flags),
                         seq=int(t.seq), ack=int(t.ack), pl=bytes(t.payload)))
    return pkts


def tshark_anomalies():
    out = {}
    for key, filt in [("retransmissions", "tcp.analysis.retransmission"),
                      ("duplicate_acks", "tcp.analysis.duplicate_ack"),
                      ("resets", "tcp.flags.reset==1"),
                      ("lost_segments", "tcp.analysis.lost_segment")]:
        try:
            r = subprocess.run(["tshark", "-r", PCAP, "-Y", filt, "-T", "fields", "-e", "frame.number"],
                               capture_output=True, text=True, timeout=120)
            out[key] = len([x for x in r.stdout.split("\n") if x.strip()])
        except Exception as e:
            out[key] = "tshark_error:%r" % e
    return out


def build_transactions(pkts):
    """Reconstruct one transaction per unique request (dedup retransmits by (dir, seq))."""
    session_sport = next((p["sport"] for p in pkts if p["src"] == "VIS" and (p["flags"] & 0x02)
                          and not (p["flags"] & 0x10)), None)
    # app-layer frames only (link_len>5 => has transport+app); skip link-status/reset frames
    def is_app(pl):
        return len(pl) >= 13 and pl[:2] == b"\x05\x64" and pl[2] > 5
    def is_req(pl):
        return is_app(pl) and pl[12] == 1      # app READ
    def is_resp(pl):
        return is_app(pl) and pl[12] == 129    # app RESPONSE
    seen = set()
    retrans_req = retrans_resp = 0
    reqs, resps, pure_acks = [], [], []
    for p in pkts:
        F = p["flags"]
        keyd = (p["src"], p["seq"], len(p["pl"]))
        if p["src"] == "VIS" and is_req(p["pl"]):
            if keyd in seen:
                retrans_req += 1
            else:
                seen.add(keyd); reqs.append(p)
        elif p["src"] == "RELAY" and is_resp(p["pl"]):
            if keyd in seen:
                retrans_resp += 1
            else:
                seen.add(keyd); resps.append(p)
        elif p["src"] == "RELAY" and len(p["pl"]) == 0 and (F & 0x10) and not (F & 0x02) \
                and not (F & 0x01) and not (F & 0x04):
            pure_acks.append(p)
    # temporal match: for request i, response = first relay-DNP3 after it and before request i+1
    txns = []
    for i, rq in enumerate(reqs):
        t_next = reqs[i + 1]["time"] if i + 1 < len(reqs) else float("inf")
        rs = next((r for r in resps if rq["time"] < r["time"] < t_next), None)
        pa = next((a for a in pure_acks if rq["time"] < a["time"] < (rs["time"] if rs else t_next)), None)
        txns.append(dict(req=rq, ack=pa, resp=rs))
    return dict(session_sport=session_sport, txns=txns,
                retrans_req=retrans_req, retrans_resp=retrans_resp,
                n_req=len(reqs), n_resp=len(resps))


def stats_block(x):
    x = np.asarray([v for v in x if v is not None], float)
    if len(x) == 0:
        return {"count": 0}
    def boot(fn, n=10000):
        idx = RNG.integers(0, len(x), size=(n, len(x)))
        vals = fn(x[idx], axis=1)
        return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]
    return dict(count=int(len(x)), mean=float(np.mean(x)), median=float(np.median(x)),
                std=float(np.std(x, ddof=1)), min=float(np.min(x)), max=float(np.max(x)),
                p25=float(np.percentile(x, 25)), p75=float(np.percentile(x, 75)),
                iqr=float(np.percentile(x, 75) - np.percentile(x, 25)),
                p90=float(np.percentile(x, 90)), p95=float(np.percentile(x, 95)),
                cov=float(np.std(x, ddof=1) / np.mean(x)) if np.mean(x) else None,
                bootstrap_ci95_mean=boot(np.mean), bootstrap_ci95_median=boot(np.median))


def main():
    os.makedirs(PLOTS, exist_ok=True)
    app = [json.loads(l) for l in open(JSONL)]
    pkts = load_pcap()
    tx = build_transactions(pkts)
    txns = tx["txns"]
    anomalies = tshark_anomalies()

    rows = []
    for i, t in enumerate(txns):
        rq, pa, rs = t["req"], t["ack"], t["resp"]
        a = app[i] if i < len(app) else {}
        dq = dnp3(rq["pl"]); ds = dnp3(rs["pl"]) if rs else None
        req_t = rq["time"]
        ack_t = pa["time"] if pa else None
        resp_t = rs["time"] if rs else None
        r2a = (ack_t - req_t) * 1e3 if ack_t else None
        clrt = (resp_t - ack_t) * 1e3 if (ack_t and resp_t) else None
        r2r = (resp_t - req_t) * 1e3 if resp_t else None
        rows.append(dict(
            poll_number=i + 1, tcp_session_sport=tx["session_sport"],
            dnp3_app_seq=(ds["seq"] if ds else None), request_seq_app=(dq["seq"] if dq else None),
            request_timestamp=req_t, pure_tcp_ack_timestamp=ack_t, response_timestamp=resp_t,
            request_to_ack_ms=r2a, ack_to_response_clrt_ms=clrt, request_to_response_ms=r2r,
            separate_pure_ack=(pa is not None),
            request_wire_bytes=len(rq["pl"]), response_wire_bytes=(len(rs["pl"]) if rs else None),
            dnp3_response_length=(ds["link_len"] if ds else None),
            fir=(ds["fir"] if ds else None), fin=(ds["fin"] if ds else None), con=(ds["con"] if ds else None),
            function_code=(ds["func"] if ds else None), function_name=(ds["func_name"] if ds else None),
            iin_lsb=(ds["iin_lsb"] if ds else None), iin_msb=(ds["iin_msb"] if ds else None),
            decoded_point_count=a.get("decoded_point_count"),
            completion=a.get("completion"),
            timeout=(a.get("error") == "task_wait_timeout"),
            error=a.get("error"), notes=""))

    # per-poll CSV + JSON
    cols = list(rows[0].keys())
    import csv
    with open(os.path.join(BASE, "per_poll.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)
    json.dump(rows, open(os.path.join(BASE, "per_poll.json"), "w"), indent=1)

    # latency variables
    clrt = [r["ack_to_response_clrt_ms"] for r in rows]
    r2a = [r["request_to_ack_ms"] for r in rows]
    r2r = [r["request_to_response_ms"] for r in rows]
    S = {"request_to_pure_ack_ms": stats_block(r2a),
         "ack_to_response_clrt_ms": stats_block(clrt),
         "request_to_response_ms": stats_block(r2r)}

    # comparisons
    clrt_arr = np.array([c for c in clrt if c is not None])
    first = clrt[0]
    rest = stats_block(clrt[1:])
    comparisons = dict(
        n_polls=len(rows), successful=sum(1 for r in rows if r["completion"] == "SUCCESS"),
        failed=sum(1 for r in rows if r["completion"] != "SUCCESS"),
        first_clrt_ms=first, first_vs_rest=dict(first=first, rest_mean=rest.get("mean"),
            rest_median=rest.get("median"), delta_first_minus_rest_mean=(first - rest["mean"]) if rest.get("mean") else None),
        response_wire_bytes_distinct=sorted(set(r["response_wire_bytes"] for r in rows if r["response_wire_bytes"])),
        dnp3_response_length_distinct=sorted(set(r["dnp3_response_length"] for r in rows if r["dnp3_response_length"])),
        decoded_point_count_distinct=sorted(set(r["decoded_point_count"] for r in rows if r["decoded_point_count"] is not None)),
        firfincon_distinct=sorted(set((r["fir"], r["fin"], r["con"]) for r in rows)),
        function_codes_distinct=sorted(set(r["function_code"] for r in rows if r["function_code"] is not None)),
        iin_distinct=sorted(set((r["iin_lsb"], r["iin_msb"]) for r in rows), key=lambda z: (z[0] or -1, z[1] or -1)),
        app_seq_first=rows[0]["dnp3_app_seq"], app_seq_last=rows[-1]["dnp3_app_seq"],
        app_seq_monotonic_mod16=all(((rows[i + 1]["dnp3_app_seq"] - rows[i]["dnp3_app_seq"]) % 16) == 1
                                    for i in range(len(rows) - 1)
                                    if rows[i]["dnp3_app_seq"] is not None and rows[i + 1]["dnp3_app_seq"] is not None),
        separate_pure_ack_count=sum(1 for r in rows if r["separate_pure_ack"]),
        missing_responses=sum(1 for r in rows if r["response_timestamp"] is None),
        tcp_session_count=1 if tx["session_sport"] else 0,
        unique_requests=tx["n_req"], unique_responses=tx["n_resp"],
        retransmitted_request_pkts=tx["retrans_req"], retransmitted_response_pkts=tx["retrans_resp"],
        tcp_anomalies_tshark=anomalies)

    summary = dict(experiment=EXP, latency_ms=S, comparisons=comparisons)
    json.dump(summary, open(os.path.join(BASE, "summary.json"), "w"), indent=1)
    # summary CSV (flat, one row per latency variable)
    with open(os.path.join(BASE, "summary.csv"), "w", newline="") as f:
        keys = ["count", "mean", "median", "std", "min", "max", "p25", "p75", "iqr", "p90", "p95", "cov"]
        w = csv.writer(f)
        w.writerow(["latency_variable"] + keys + ["ci95_mean_lo", "ci95_mean_hi", "ci95_median_lo", "ci95_median_hi"])
        for name, s in S.items():
            w.writerow([name] + [round(s.get(k), 4) if isinstance(s.get(k), float) else s.get(k) for k in keys]
                       + [round(s["bootstrap_ci95_mean"][0], 4), round(s["bootstrap_ci95_mean"][1], 4),
                          round(s["bootstrap_ci95_median"][0], 4), round(s["bootstrap_ci95_median"][1], 4)])

    # ---- plots (ms labels, no truncated axes) ----
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    # histogram
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.hist(clrt_arr, bins=30, color="#0e7c86", edgecolor="white")
    ax.set_xlabel("ACK-to-response CLRT (ms)"); ax.set_ylabel("count")
    ax.set_title("Physical SEL-751 CLRT histogram (n=%d)" % len(clrt_arr)); ax.set_xlim(left=0)
    fig.tight_layout(); fig.savefig(os.path.join(PLOTS, "clrt_histogram.png"), dpi=140); plt.close(fig)
    # ECDF
    fig, ax = plt.subplots(figsize=(7, 4.2))
    xs = np.sort(clrt_arr); ys = np.arange(1, len(xs) + 1) / len(xs)
    ax.plot(xs, ys, color="#0e7c86"); ax.set_xlabel("CLRT (ms)"); ax.set_ylabel("empirical CDF")
    ax.set_title("Physical SEL-751 CLRT empirical CDF"); ax.set_xlim(left=0); ax.set_ylim(0, 1)
    ax.grid(alpha=0.3); fig.tight_layout(); fig.savefig(os.path.join(PLOTS, "clrt_ecdf.png"), dpi=140); plt.close(fig)
    # boxplot + violin
    fig, ax = plt.subplots(figsize=(6, 4.2))
    ax.violinplot(clrt_arr, showmedians=True); ax.boxplot(clrt_arr, widths=0.25)
    ax.set_ylabel("CLRT (ms)"); ax.set_xticks([1]); ax.set_xticklabels(["CLRT"])
    ax.set_title("Physical SEL-751 CLRT distribution"); ax.set_ylim(bottom=0)
    fig.tight_layout(); fig.savefig(os.path.join(PLOTS, "clrt_box_violin.png"), dpi=140); plt.close(fig)
    # time-series
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.plot(range(1, len(clrt) + 1), clrt, color="#0e7c86", lw=0.9, marker=".", ms=3)
    ax.axhline(np.median(clrt_arr), color="#b0432c", ls="--", lw=1, label="median")
    ax.set_xlabel("poll number"); ax.set_ylabel("CLRT (ms)"); ax.set_ylim(bottom=0)
    ax.set_title("Physical SEL-751 CLRT by poll number"); ax.legend(); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(os.path.join(PLOTS, "clrt_timeseries.png"), dpi=140); plt.close(fig)

    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
