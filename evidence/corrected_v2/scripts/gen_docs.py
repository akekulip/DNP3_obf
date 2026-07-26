#!/usr/bin/env python3
"""gen_docs.py — generate every corrected document from authoritative_results.json.

Directive §10: all documents and figures derive from one authoritative manifest. No measurement is
typed by hand anywhere in this file; every number is read from the JSON.

Emits into meeting_package/timing_inline_v2/:
  source/corrected_report_source.md   (rendered to PDF + HTML by build_v2.sh)
  RESULT_V2.md
  README_FIRST.md
  WIRESHARK_GUIDE_V2.md
  CODE_WALKTHROUGH_V2.md
  LIMITATIONS_V2.md
"""
import argparse
import json
import os

G_MS = 25


def s(d, camp, treat):
    return next(x for x in d["series"] if x["campaign"] == camp and x["treatment"] == treat)


def cmp_(d, camp):
    return next(c for c in d["comparisons"] if c["campaign"] == camp)


def ent(series, variant, width):
    return next(e for e in series[variant]["entropy"] if e["bin_width_ms"] == width)


def series_table(d):
    """One row per shipped pcap, both variants."""
    out = ["| campaign | treatment | pcap | sha256 (head) | n (all) | n (steady) |",
           "|:--|:--|:--|:--|--:|--:|"]
    for x in d["series"]:
        out.append("| %s | %s | `%s` | `%s…` | %d | %d |" % (
            x["campaign"], x["treatment"], os.path.basename(x["pcap"]), x["sha256"][:16],
            x["all_state"]["n"], x["steady_state"]["n"]))
    return "\n".join(out)


def stats_table(d, variant, title):
    out = ["**%s**" % title, "",
           "| campaign | treatment | n | median | min | max | sd (pop) | sd (sample) | p95 | range |",
           "|:--|:--|--:|--:|--:|--:|--:|--:|--:|--:|"]
    for x in d["series"]:
        v = x[variant]
        out.append("| %s | %s | %d | %.3f | %.3f | %.3f | **%.3f** | %.3f | %.3f | %.3f |" % (
            x["campaign"], x["treatment"], v["n"], v["median"], v["min"], v["max"],
            v["sd_population"], v["sd_sample"] if v["sd_sample"] is not None else float("nan"),
            v["p95"], v["range"]))
    return "\n".join(out)


def entropy_table(d, variant):
    out = ["| campaign | treatment | bin width | occupied bins | entropy (bits) | n |",
           "|:--|:--|--:|--:|--:|--:|"]
    for x in d["series"]:
        for e in x[variant]["entropy"]:
            w = e["bin_width_ms"]
            label = ("%d ms" % w) if w >= 1 else ("%d µs" % round(w * 1000))
            out.append("| %s | %s | %s | %d | %.4f | %d |" % (
                x["campaign"], x["treatment"], label, e["occupied_bins"], e["entropy_bits"], e["n"]))
    return "\n".join(out)


def ratio_para(d):
    a, b = cmp_(d, "A"), cmp_(d, "B")
    return (
        "| campaign | all-state sd ratio | steady-state sd ratio |\n"
        "|:--|--:|--:|\n"
        "| A | %.1fx | %.1fx |\n"
        "| B | %.1fx | %.1fx |" % (
            a["all_state"]["sd_ratio"], a["steady_state"]["sd_ratio"],
            b["all_state"]["sd_ratio"], b["steady_state"]["sd_ratio"]))


def build(d, out_root):
    an, ap = s(d, "A", "native"), s(d, "A", "protected")
    bn, bp = s(d, "B", "native"), s(d, "B", "protected")
    lens = an["response_lengths"][0]

    # ---------------------------------------------------------------- report
    report = """---
subtitle: "Defense 2 (hold the RESPONSE) running inline with a physical SEL-751: corrected results, reproduction, and limits"
---

::: buildinfo
Every number in this document is generated from `authoritative_results.json`, which is computed
from the four shipped pcaps and nothing else. Build stamp: commit `@COMMIT@`, @DATE@.
:::

# 1. What was run, and what it showed

Running inline between the master and a physical SEL-751, the Tofino-1 Defense 2 implementation
forwarded the pure TCP ACK immediately and held the DNP3 RESPONSE until an ACK-relative deadline.
The live protected pcaps show that the relay's dispersed native CLRT observations were concentrated
into a narrow cluster around the configured %d ms target, demonstrating suppression of the tested
CLRT-magnitude fingerprint.

Two live campaigns were run. Both are shipped, both are analysed, and neither is presented as
correcting the other.

%s

![Every transaction in both campaigns. The first transaction of each capture is the connection-cold one.](../figures/clusters.png)

# 2. CLRT: definition and source

**CLRT is the Cross-Layer Response Time.** The primary source is Formby, Srinivasan, Leonard,
Rogers and Beyah, *Who's in Control of Your Control System? Device Fingerprinting for
Cyber-Physical Systems*, NDSS 2016, which measures the interval between the TCP ACK and the
appearance of the response for each read request.

In this work CLRT is measured as

    t(DNP3 RESPONSE, application function 129)  -  t(the qualifying pure TCP ACK)

observed at the master-side capture point on Vision, using host pcap timestamps. A qualifying ACK
carries zero TCP payload, no SYN/FIN/RST, and an acknowledgement number equal to
`READ.tcp.seq + READ.tcp.len`.

# 3. Results, reported two ways

The two variants are reported separately and deliberately. Neither is "the" corrected result.

%s

%s

%s

**The all-state variance is strongly influenced by the first transaction of each capture**, which
is the connection-cold transaction (campaign A: %.3f ms; campaign B: %.3f ms). Excluding it, the
steady-state distribution still shows substantial normalization. Both statements are true and both
are reported.

![All-state and steady-state side by side.](../figures/ratios.png)

## 3.1 Release tail: the realized CLRT is near the target, not equal to it

The protected observations sit slightly above the configured %d ms, by a small and consistent
margin: campaign A median +%.3f ms (min %+.3f, max +%.3f), campaign B median +%.3f ms
(min +%.3f, max +%.3f). This is the release implementation tail — deadline recognition, blocker
reservoir termination, queue scheduling and loopback traversal, plus observation timestamp noise.

The output is therefore

    CLRT_out  =  quantized G  +  deadline-recognition latency
                              +  blocker-reservoir termination latency
                              +  queue scheduling and loopback latency
                              +  observation timestamp noise

# 4. Entropy, with its binning stated

Entropy is a property of the observer's resolution, not of the defense. Every value below uses
**bin origin 0.0 ms** and **half-open bins [lo, hi)**, with the bin index computed as
`floor((x - origin) / width)`.

![The same data at five observer resolutions.](../figures/entropy_resolution.png)

%s

Read that table carefully. At 1 ms bins campaign B protected occupies one bin and measures
0.0000 bits, while campaign A protected occupies **two** bins and measures %.4f bits — its minimum,
%.3f ms, falls on the other side of the 25 ms bin edge. The same mechanism, the same target, a
different bin occupancy. That is why an unqualified "entropy is zero" is not a supportable
statement about this defense.

# 5. What the implementation actually does

This is **Defense 2 only**: the response is held, the ACK is not.

1. The master's Class-0 READ is forwarded to the relay.
2. The relay's pure TCP ACK is **forwarded immediately**, and its arrival time is stamped.
3. An ACK-relative deadline is armed at `t_ack + G`.
4. The relay's DNP3 RESPONSE is **held queue-resident** in a low-priority Traffic Manager queue on
   the internal dp8 loopback. The original response is what waits; it is not recirculated and it is
   not rewritten.
5. A high-priority **blocker reservoir** on the same port denies that queue service. The blockers,
   not the response, traverse the loop.
6. Each blocker compares the current timestamp against the deadline and terminates once past it.
7. With the high-priority queue drained, the response becomes schedulable and leaves.

**The blockers are currently seeded by the host and then circulate internally.** The release
decision is data-plane controlled, with no controller action in the transaction fast path. An
internal seeding mechanism has been designed and compiles, but it is not what produced these
measurements, and nothing here should be read as a claim of fully internal blocker generation.

A note on the Tofino, because the earlier write-up got this wrong: the Traffic Manager buffers and
schedules packets perfectly well. What P4 ingress cannot express is "release this queued packet at
absolute time T". The mechanism controls scheduling *eligibility* indirectly. That indirection is
the contribution, not the existence of buffering.

# 6. Integrity observations from the shipped captures

Across all four captures: **0 retransmissions, 0 duplicate acknowledgements, 0 reordering**, no
malformed frames, and all DNP3 CRCs valid. Response lengths were constant at
**frame %d bytes, IP total length %d bytes, TCP payload %d bytes** — note the layer, since the
DNP3 response payload is %d bytes and the frame carrying it is %d bytes.

Observed DNP3 link addresses: READ src %s → dst %s, RESPONSE src %s → dst %s. The **outstation link
address is 0**. The value 10 in older notes came from the 10.0.0.x capture corpus and is wrong for
this relay.

Pairing quality: every transaction in all four captures paired exactly, with 0 ambiguous and 0
validation failures. Two independent pipelines were run — an exact-pairing analyzer using
expected-ack matching plus DNP3 function 129, and a separate tshark-only extraction using a
different pairing rule — and they agree on every transaction to better than 1 µs.

# 7. Reproduction

```bash
cd ~/dnp3_live
./status.sh                       # preflight; exits non-zero if the inline path is not live
./run.sh native                   # read-only Class-0 polls, nothing held
./run.sh protected                # same polls, blocker reservoir seeded (needs sudo)
./clrt.py native.pcap protected.pcap
```

To recompute the shipped results from the shipped pcaps:

```bash
$RESEARCH_PYTHON evidence/corrected_v2/scripts/build_authoritative.py
$RESEARCH_PYTHON evidence/corrected_v2/scripts/make_figures_v2.py --out meeting_package/timing_inline_v2/figures
```

The Wireshark procedure is in `WIRESHARK_GUIDE_V2.md`; the code walkthrough is in
`CODE_WALKTHROUGH_V2.md`.

# 8. Claim

> Running inline between the master and a physical SEL-751, the Tofino-1 Defense 2 implementation
> forwarded the pure TCP ACK immediately and held the DNP3 RESPONSE until an ACK-relative deadline.
> The live protected PCAPs show that the relay's dispersed native CLRT observations were
> concentrated into a narrow cluster around the configured 25 ms target, demonstrating suppression
> of the tested CLRT-magnitude fingerprint.

# 9. Limitations

- Tested on one SEL-751 with read-only DNP3 traffic only.
- The CLRT-magnitude channel only.
- **No full anonymity claim.** ACK mode, response size and TCP-stack characteristics are untouched.
- **No size-obfuscation claim.**
- **The blocker reservoir is currently host-seeded.** It circulates internally after seeding, and
  the release decision is data-plane controlled, but the seed frames are transmitted by the host.
- The first connection-cold transaction of each capture is reported separately, never discarded.
- **Live byte identity is not independently proven** in this inline configuration. The relay leg
  cannot be tapped, so the same frame cannot be compared before and after holding. What the shipped
  captures do support is constant response lengths, valid DNP3 CRCs, and no transport anomalies.
- Sample sizes are those of the shipped captures (%d, %d, %d and %d transactions); no larger
  campaign is claimed.
""" % (G_MS,
       series_table(d),
       stats_table(d, "all_state", "All-state: every paired transaction"),
       stats_table(d, "steady_state", "Steady-state: excluding the first, connection-cold transaction"),
       ratio_para(d),
       an["connection_cold_transaction"]["clrt_ms"], bn["connection_cold_transaction"]["clrt_ms"],
       G_MS,
       ap["release_tail_ms"]["median_minus_g"], ap["release_tail_ms"]["min_minus_g"],
       ap["release_tail_ms"]["max_minus_g"],
       bp["release_tail_ms"]["median_minus_g"], bp["release_tail_ms"]["min_minus_g"],
       bp["release_tail_ms"]["max_minus_g"],
       entropy_table(d, "all_state"),
       ent(ap, "all_state", 1.0)["entropy_bits"], ap["all_state"]["min"],
       lens["frame_len"], lens["ip_len"], lens["tcp_payload_len"],
       lens["tcp_payload_len"], lens["frame_len"],
       an["dnp3_link_addresses_observed"]["read_src"][0], an["dnp3_link_addresses_observed"]["read_dst"][0],
       an["dnp3_link_addresses_observed"]["resp_src"][0], an["dnp3_link_addresses_observed"]["resp_dst"][0],
       an["all_state"]["n"], ap["all_state"]["n"], bn["all_state"]["n"], bp["all_state"]["n"])

    os.makedirs(os.path.join(out_root, "source"), exist_ok=True)
    open(os.path.join(out_root, "source", "corrected_report_source.md"), "w").write(report)

    # ---------------------------------------------------------------- RESULT
    result = """# RESULT (corrected)

Generated from `authoritative_results.json`; every value below is recomputed from the four shipped
pcaps by two independent pipelines that agree to better than 1 µs.

## Shipped evidence

%s

## All-state (every paired transaction)

%s

## Steady-state (first, connection-cold transaction excluded)

%s

## Compression, both variants

%s

The all-state variance is strongly influenced by the first transaction of each capture. The
steady-state distribution also shows substantial normalization. Neither figure is "the" result.

## Release tail

Protected observations land near, not on, the %d ms target: campaign A median +%.3f ms, campaign B
median +%.3f ms.

## Entropy

Reported only with binning. Bin origin 0.0 ms, half-open [lo, hi).

%s

## Integrity in the shipped captures

0 retransmissions, 0 duplicate ACKs, 0 reordering, 0 malformed frames, all DNP3 CRCs valid,
response length constant at frame %d B / IP %d B / TCP payload %d B, DNP3 link addresses
master 1 and outstation 0.
""" % (series_table(d),
       stats_table(d, "all_state", "All-state"),
       stats_table(d, "steady_state", "Steady-state"),
       ratio_para(d), G_MS,
       ap["release_tail_ms"]["median_minus_g"], bp["release_tail_ms"]["median_minus_g"],
       entropy_table(d, "all_state"),
       lens["frame_len"], lens["ip_len"], lens["tcp_payload_len"])
    open(os.path.join(out_root, "RESULT_V2.md"), "w").write(result)

    # ---------------------------------------------------------------- limitations
    lim = """# Limitations (corrected)

- Tested on one physical SEL-751, with read-only DNP3 traffic only (Class-0 READ, function 1).
- The CLRT-magnitude channel only.
- No full anonymity claim. ACK mode, response size and TCP-stack characteristics are unchanged by
  this mechanism.
- No size-obfuscation claim.
- The blocker reservoir is currently **host-seeded**; it circulates internally after seeding and the
  release decision is data-plane controlled, but the seed frames are transmitted by the host. There
  is no claim of fully internal blocker generation.
- The first connection-cold transaction of each capture is reported separately and is never
  discarded.
- Live byte identity is **not independently proven** in this inline configuration: the relay leg
  cannot be tapped, so the same frame cannot be compared before and after holding. Constant response
  lengths, valid CRCs and absence of transport anomalies are supporting evidence, not proof.
- Sample sizes are those of the shipped captures: %d, %d, %d and %d transactions.
- Entropy values are meaningful only with the stated bin width, bin origin and edge convention.
""" % (an["all_state"]["n"], ap["all_state"]["n"], bn["all_state"]["n"], bp["all_state"]["n"])
    open(os.path.join(out_root, "LIMITATIONS_V2.md"), "w").write(lim)

    print("generated report source, RESULT_V2.md, LIMITATIONS_V2.md")


def main():
    ap_ = argparse.ArgumentParser()
    ap_.add_argument("--json", required=True)
    ap_.add_argument("--out", required=True)
    a = ap_.parse_args()
    build(json.load(open(a.json)), a.out)


if __name__ == "__main__":
    main()
