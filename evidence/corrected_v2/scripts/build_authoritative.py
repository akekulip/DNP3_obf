#!/usr/bin/env python3
"""build_authoritative.py — the single source of truth for every number in the corrected package.

Reads ONLY the four shipped pcaps. Recomputes every statistic with the exact-pairing analyzer, and
independently cross-checks each CLRT with a separate tshark extraction that shares no code with it.
Emits evidence/corrected_v2/authoritative_results.json.

Every figure, table and sentence in the corrected report, HTML, interactive page, README and
RESULT.md is generated from that JSON. Nothing is hand-transcribed.

Reported for each series, separately and never merged into one "corrected" number:
  all_state    every paired transaction in the capture
  steady_state the same, excluding the explicitly identified first connection-cold transaction

Entropy is reported only with its bin width, bin origin, edge convention and sample count.
"""
import csv
import hashlib
import json
import math
import os
import statistics as st
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
PCAPS = os.path.join(ROOT, "pcaps")
ANALYZER = os.path.join(HERE, "analyze_live_clrt.py")
RELAY = "192.168.10.7"

SERIES = [
    ("A", "native",    "campaignA_native_n10.pcap",    None),
    ("A", "protected", "campaignA_protected_n11.pcap", 25),
    ("B", "native",    "campaignB_native_n13.pcap",    None),
    ("B", "protected", "campaignB_protected_n13.pcap", 25),
]

# observer resolutions, in milliseconds
RESOLUTIONS = [0.010, 0.050, 0.100, 0.500, 1.000]
BIN_ORIGIN_MS = 0.0
EDGE_CONVENTION = "half-open [lo, hi): bin index = floor((x - origin) / width)"


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def pipeline_a(pcap, outdir):
    """Exact-pairing analyzer: expected-ack matching, DNP3 func 129, CRC-checked decode."""
    os.makedirs(outdir, exist_ok=True)
    subprocess.run([sys.executable, ANALYZER, "--pcap", pcap, "--label", "native",
                    "--outdir", outdir], capture_output=True, text=True, check=True)
    rows = list(csv.DictReader(open(os.path.join(outdir, "native_transactions.csv"))))
    out = []
    for r in rows:
        if r["clrt_ms"].strip():
            out.append(dict(clrt_ms=float(r["clrt_ms"]),
                            read_frame=int(r["read_frame"]), ack_frame=int(r["ack_frame"]),
                            resp_frame=int(r["resp_frame"]),
                            resp_tcp_len=int(r["resp_tcp_len"]), resp_ip_len=int(r["resp_ip_len"]),
                            resp_frame_len=int(r["resp_frame_len"]),
                            read_dnp3_src=r["read_dnp3_src"], read_dnp3_dst=r["read_dnp3_dst"],
                            resp_dnp3_src=r["resp_dnp3_src"], resp_dnp3_dst=r["resp_dnp3_dst"],
                            resp_dnp3_func=r["resp_dnp3_func"],
                            ambiguity=r["ambiguity"], validation_failure=r["validation_failure"]))
    return out, rows


def pipeline_b(pcap):
    """Independent cross-check: tshark only, no shared code with pipeline A.

    Pairs the outstation's last pure ACK preceding each response, which is a DIFFERENT rule from
    pipeline A's expected-ack match. Agreement between two different rules is the check."""
    out = subprocess.run(
        ["tshark", "-r", pcap, "-T", "fields", "-e", "frame.number", "-e", "frame.time_epoch",
         "-e", "ip.src", "-e", "tcp.len", "-e", "tcp.flags"],
        capture_output=True, text=True, check=True).stdout
    vals, ack_t, ack_f = [], None, None
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 5 or not p[1].strip():
            continue
        fn, t, src, ln = int(p[0]), float(p[1]), p[2].strip(), int(p[3] or 0)
        flags = int(p[4], 16) if p[4].strip() else 0
        if src != RELAY:
            continue
        if flags & 0x007:          # SYN, FIN or RST
            continue
        if ln == 0:
            ack_t, ack_f = t, fn
        elif ack_t is not None:
            vals.append(dict(clrt_ms=(t - ack_t) * 1000.0, ack_frame=ack_f, resp_frame=fn))
            ack_t = None
    return vals


def entropy_at(vals, width_ms):
    h = {}
    for v in vals:
        k = int(math.floor((v - BIN_ORIGIN_MS) / width_ms))
        h[k] = h.get(k, 0) + 1
    n = sum(h.values())
    e = 0.0
    for c in h.values():
        p = c / n
        e -= p * math.log2(p)
    return dict(bin_width_ms=width_ms, bin_origin_ms=BIN_ORIGIN_MS,
                edge_convention=EDGE_CONVENTION, n=n,
                occupied_bins=len(h), entropy_bits=round(e, 4),
                bins={str(k): v for k, v in sorted(h.items())})


def describe(vals):
    v = sorted(vals)
    n = len(v)
    def pct(q):
        return v[min(n - 1, int(q * n))]
    d = dict(n=n, min=round(v[0], 4), max=round(v[-1], 4),
             mean=round(st.mean(v), 4), median=round(st.median(v), 4),
             sd_population=round(st.pstdev(v), 4),
             sd_sample=round(st.stdev(v), 4) if n > 1 else None,
             p5=round(pct(.05), 4), p25=round(pct(.25), 4), p75=round(pct(.75), 4),
             p95=round(pct(.95), 4), p99=round(pct(.99), 4),
             range=round(v[-1] - v[0], 4),
             mad=round(st.median([abs(x - st.median(v)) for x in v]), 4))
    d["entropy"] = [entropy_at(v, w) for w in RESOLUTIONS]
    return d


def main():
    result = dict(
        generated_from="the four shipped pcaps only",
        analyzer=os.path.relpath(ANALYZER, ROOT),
        clrt_definition=("Cross-Layer Response Time: t(DNP3 RESPONSE, function 129) minus "
                         "t(the qualifying pure TCP ACK), observed at the master-side capture "
                         "point, host pcap timestamps"),
        clrt_primary_source=("Formby, Srinivasan, Leonard, Rogers, Beyah, 'Who's in Control of "
                             "Your Control System? Device Fingerprinting for Cyber-Physical "
                             "Systems', NDSS 2016"),
        dnp3_link_addresses=dict(master=1, outstation=0,
                                 note="verified on the wire; the older 'outstation=10' came from "
                                      "the 10.0.0.x capture corpus and is wrong for this relay"),
        steady_state_rule=("the first transaction of each capture is the connection-cold "
                           "transaction and is excluded from the steady-state series; it is "
                           "reported separately, never discarded"),
        series=[])

    for campaign, treatment, fn, g in SERIES:
        pcap = os.path.join(PCAPS, fn)
        outdir = os.path.join(ROOT, "authoritative", "%s_%s" % (campaign, treatment))
        pa, raw = pipeline_a(pcap, outdir)
        pb = pipeline_b(pcap)

        # cross-check: same count, and every CLRT agreeing to < 1 us
        agree, maxdiff = True, 0.0
        if len(pa) != len(pb):
            agree = False
        else:
            for x, y in zip(pa, pb):
                d = abs(x["clrt_ms"] - y["clrt_ms"])
                maxdiff = max(maxdiff, d)
                if d > 0.001:
                    agree = False

        vals = [x["clrt_ms"] for x in pa]
        cold = pa[0]
        steady = vals[1:]

        lens = sorted({(x["resp_frame_len"], x["resp_ip_len"], x["resp_tcp_len"]) for x in pa})
        s = dict(
            campaign=campaign, treatment=treatment, pcap=os.path.join("pcaps", fn),
            sha256=sha256(pcap), g_ms=g,
            pipeline_cross_check=dict(pipeline_a_n=len(pa), pipeline_b_n=len(pb),
                                      agree=agree, max_abs_diff_ms=round(maxdiff, 9),
                                      rule_a="expected-ack match + DNP3 func 129",
                                      rule_b="last pure ACK preceding each response (tshark only)"),
            ambiguous=sum(1 for r in raw if r["ambiguity"].strip()),
            validation_failures=sum(1 for r in raw if r["validation_failure"].strip()),
            connection_cold_transaction=dict(
                clrt_ms=round(cold["clrt_ms"], 4), read_frame=cold["read_frame"],
                ack_frame=cold["ack_frame"], resp_frame=cold["resp_frame"]),
            response_lengths=[dict(frame_len=a, ip_len=b, tcp_payload_len=c) for a, b, c in lens],
            dnp3_link_addresses_observed=dict(
                read_src=sorted({x["read_dnp3_src"] for x in pa}),
                read_dst=sorted({x["read_dnp3_dst"] for x in pa}),
                resp_src=sorted({x["resp_dnp3_src"] for x in pa}),
                resp_dst=sorted({x["resp_dnp3_dst"] for x in pa})),
            all_state=describe(vals),
            steady_state=describe(steady),
            clrt_values_all_state_ms=[round(v, 6) for v in vals])
        if treatment == "native":
            # for a NATIVE series this counts protection-miss candidates: transactions whose own
            # timing already exceeds the target, so a hold could not have shortened them.
            s["protection_miss_candidates_vs_25ms"] = dict(
                g_ms=25, all_state=sum(1 for v in vals if v > 25),
                steady_state=sum(1 for v in steady if v > 25))
        else:
            # for a PROTECTED series the excess over G is the release tail, NOT a miss.
            s["release_tail_ms"] = dict(
                g_ms=g,
                median_minus_g=round(st.median(vals) - g, 4),
                min_minus_g=round(min(vals) - g, 4),
                max_minus_g=round(max(vals) - g, 4),
                note=("realized CLRT sits slightly above the configured target; this is the "
                      "release implementation tail (deadline recognition, reservoir termination, "
                      "scheduling and loopback), not a protection miss"))
        result["series"].append(s)

    # paired comparisons, both variants, never merged
    result["comparisons"] = []
    for camp in ("A", "B"):
        nat = next(x for x in result["series"] if x["campaign"] == camp and x["treatment"] == "native")
        pro = next(x for x in result["series"] if x["campaign"] == camp and x["treatment"] == "protected")
        c = dict(campaign=camp)
        for var in ("all_state", "steady_state"):
            sn, sp = nat[var]["sd_population"], pro[var]["sd_population"]
            c[var] = dict(
                native_n=nat[var]["n"], protected_n=pro[var]["n"],
                native_sd_pop=sn, protected_sd_pop=sp,
                sd_ratio=round(sn / sp, 4) if sp else None,
                native_median=nat[var]["median"], protected_median=pro[var]["median"],
                native_range=nat[var]["range"], protected_range=pro[var]["range"])
        result["comparisons"].append(c)

    out = os.path.join(ROOT, "authoritative_results.json")
    json.dump(result, open(out, "w"), indent=2)
    print("wrote %s" % out)
    for s in result["series"]:
        cc = s["pipeline_cross_check"]
        print("  %s %-9s n=%-3d cross-check=%s (max diff %.2e ms)  amb=%d fail=%d"
              % (s["campaign"], s["treatment"], s["all_state"]["n"],
                 "AGREE" if cc["agree"] else "DISAGREE", cc["max_abs_diff_ms"],
                 s["ambiguous"], s["validation_failures"]))
    for c in result["comparisons"]:
        print("  campaign %s  all-state sd ratio %.1fx   steady-state sd ratio %.1fx"
              % (c["campaign"], c["all_state"]["sd_ratio"], c["steady_state"]["sd_ratio"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
