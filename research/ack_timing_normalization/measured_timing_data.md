# Measured Timing Evidence (rig, this session)

_All numbers below are **measured fact** produced this session by running the existing
`dnp3_split_harness/analyze_ack.py` (scapy 2.7.0, `~/.venvs/research/bin/python`) over
real Vision↔Hulk rig captures already in the repo. No code was modified; the analyzer
was pointed at multi-CROB PCAPs via CLI flags and outputs were written to a scratch dir.
These are the empirical anchors for the study — cite them as "measured, this rig, this
session," distinct from paper-reported or inferred values._

## Rig / capture provenance
- Master = Vision `10.10.54.19`; Outstation = Hulk `10.10.54.158:20000`; OpenDNP3
  (community fork) software outstation; 1 G management LAN, directly switched.
- Tool: `analyze_ack.py` — per master request→outstation reply exchange it reports
  pure vs piggybacked ACK, request→ACK delay, request→response delay, and TCP/IP
  fingerprint fields (options, TTL, IP-ID, window, PSH).
- TCP option signature on steady-state data segments: `NOP-NOP-Timestamp` (Linux
  6.8 / i40e stack, timestamps enabled).

## A. Baseline large Class-0 READ (reproduced first-hand this session)
Capture `dnp3_split_harness/captures/baseline/large_read.pcap`, re-run this session
(matches the prior `reports/tcp_ack_fingerprinting.md` exactly):
- 9 request exchanges, **9/9 piggyback**, 1 stray pure ACK (ratio 0.111).
- mean request→ACK = **0.239 ms**; mean request→response = **1.014 ms**;
  TCP option signature `NOP-NOP-Timestamp`.

## B. Multi-CROB SBO (Test C, 2 CROBs) — `captures/multi_crob_sbo.pcap`
5 request exchanges, 5 piggyback, response delays (ms):
`0.334, 0.253, 0.215, 1.37, 1.34`. The three ~0.2–0.3 ms exchanges are the
connect/disable-unsol/integrity-poll setup; the two ~1.3–1.4 ms exchanges are the
SELECT-response and OPERATE-response (which carry the CROBs).

## C. CROB-count sweep — `captures/sweep/multicrob_n<N>.pcapng`
For each N (number of CROBs in the SELECT/OPERATE), the two largest response delays
are the SELECT-response and OPERATE-response; the other three are N-independent setup.

| N (CROBs) | mean RT (ms) | SELECT-resp (ms) | OPERATE-resp (ms) |
|---|---|---|---|
| 1  | 0.741 | 1.12 | 1.62 |
| 2  | 0.830 | 1.40 | 1.99 |
| 3  | 0.855 | 1.51 | 2.04 |
| 4  | 0.930 | 1.71 | 2.25 |
| 5  | 1.025 | 1.92 | 2.49 |
| 6  | 1.091 | 2.07 | 2.66 |
| 8  | 1.241 | 2.42 | 3.08 |
| 10 | 1.481 | 2.81 | 3.65 |
| 12 | 1.540 | 3.09 | 3.91 |
| 16 | 1.903 | 3.87 | 4.90 |

### Linear fit (response delay vs CROB count N)
- **SELECT-response:**  slope **0.179 ms/CROB**, intercept 0.992 ms, **R² = 0.9985**, Pearson r = 0.9992.
- **OPERATE-response:** slope **0.214 ms/CROB**, intercept 1.427 ms, **R² = 0.9954**, Pearson r = 0.9977.
- OPERATE-response range 1.62 → 4.90 ms across N=1→16 (**3.0×**).

## Interpretation (measured — with its limits stated)
On this outstation, response **processing time rises linearly with request complexity**
(CROB count) — the per-exchange timing signal a passive observer could regress to recover
the number of control points in the request. It is a **measured** relationship, not an
assumption.

**Read the R² honestly.** The fit is over 10 N-levels with **one SELECT-response and one
OPERATE-response sample per level** (each capture has 5 exchanges, of which exactly one
SELECT and one OPERATE carry the CROBs). So R² = 0.9985 / 0.9954 describes a clean
10-point line, **not** a replicated near-deterministic law: with n = 1 per N there is no
within-N variance, no confidence interval, and the conditional information I(time; N) is
not yet computable. **A replicated sweep (≥30 repetitions per N, bootstrap CI on the
slope) is the first planned experiment (evaluation_plan E1) and must precede any
"near-deterministic" / "R²>0.99 law" wording in a paper.**

**CROB count is not database size.** CROB count is control-*command* complexity (the
SELECT/OPERATE payload); outstation *database size* is the number of static points, whose
leak would appear in **Class-0 integrity-read** serialization time — a channel this sweep
never varied. They are different mechanisms; the database-size correlation is **unmeasured**
and is a separate planned experiment. Do not call CROB count a "database-size proxy."

**Scope:** single software outstation, single rig, one implementation — an
information-theoretic / regression result on one device, **not** a cross-device (device
identification) claim.

_Scratch CSVs: `<session scratchpad>/sw_n{1..16}.csv`, `sbo_details.csv`._
