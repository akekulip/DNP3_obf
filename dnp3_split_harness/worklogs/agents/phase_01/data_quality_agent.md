# Phase 01 — Data-Quality Agent Worklog

Run: `runs/20260716T024101Z_phase_01_real_trace_characterization/`
Date: 2026-07-15 · Scope: READ-ONLY audit of the Phase-01 reconstructed-transaction tables.
Method: every count recomputed directly from `tables/ack_trace_characterization.csv`
(22,988 data rows, 46 columns) with `python3`/`csv`; the report's prose was **not** trusted.

## Verdict: all recomputed counts MATCH the report. No data-quality defects found.

## Recomputed vs reported

| Item | Reported (`data_quality_report.md`) | Recomputed (from CSV) | Match |
|---|---|---|---|
| Total reconstructed transactions | 22988 | 22988 | ✅ |
| Device-specific (`is_reference==False`) | 11494 | 11494 | ✅ |
| Reference (`is_reference==True`) | 11494 | 11494 | ✅ |
| Transactions w/ retransmission | 93 | 93 | ✅ |
| Transactions w/ duplicate ACK | 93 | 93 | ✅ |
| Transactions w/ out-of-order | 0 | 0 | ✅ |
| Transactions w/ reset | 4 | 4 | ✅ |
| Transactions w/ missing response | 0 | 0 | ✅ |
| OTHER_OR_AMBIGUOUS | 0 | 0 | ✅ |
| Confidence high | 22891 | 22891 | ✅ |
| Confidence medium | 97 | 97 | ✅ |
| Confidence low | 0 | 0 | ✅ |
| Reference txns on 10.0.0.2 | 11494 | 11494 | ✅ |
| `transaction_anomalies.csv` rows | (enumerates ambiguous/anomalous) | 97 | ✅ (= medium count) |

### Per-capture / per-device n (device-specific; cross-checked vs `device_summary.csv`)

| device_label | capture | outstation_ip | n (CSV) | n (device_summary) | Match |
|---|---|---|---|---|---|
| AB1400 | AB1400.pcap (base) | 10.0.0.12 | 399 | 399 | ✅ |
| AB1400 | AB1400L.pcap (L) | 10.0.0.12 | 1999 | 1999 | ✅ |
| ION7550 | ION7550.pcap (base) | 10.0.0.11 | 799 | 799 | ✅ |
| ION7550 | ION7550L.pcap (L) | 10.0.0.11 | 3999 | 3999 | ✅ |
| SEL751 | SEL751.pcap (base) | 10.0.0.1 | 299 | 299 | ✅ |
| SEL751 | SEL751L.pcap (L) | 10.0.0.1 | 3999 | 3999 | ✅ |

Device-specific sum 399+1999+799+3999+299+3999 = **11494** ✅.
Each capture holds an equal reference slice (same n on `is_reference==True`), so per-capture
total rows = 2× the device-specific n (e.g. SEL751L 3999 dev + 3999 ref = 7998). Grand total
11494 dev + 11494 ref = **22988** ✅.

## Six audit questions — findings

**1. Transaction counts.** Confirmed 22988 / 11494 / 11494 and all per-device/per-capture n.
`is_reference` has exactly two values (`True` 11494 / `False` 11494). `device_summary.csv`
lists only the six device-specific (base/L) groups — it does not mint a group for the shared
reference, which is correct.

**2. Missing / malformed fields.** Zero empty `req_frame`, `classification`, `resp_frame`,
`req_time_epoch`, `resp_time_epoch`, `req_func`, `first_rev_frame`. Classification enum is
`{COMBINED_ACK_RESPONSE: 18683, SEPARATE_ACK_RESPONSE: 4305}` — no blanks, no OTHER.
`pure_ack_*` blanks are **legitimate and perfectly partitioned**: all 18683 COMBINED rows have
blank `pure_ack_frame`/`req_to_pure_ack_ms`/`pure_ack_to_resp_ms`; all 4305 SEPARATE rows have
them filled (`pure_ack_present` == True iff SEPARATE). No malformed rows.

**3. Timestamps & direction.** `resp_time_epoch >= req_time_epoch` for **every** classified row
(0 negative-delay violations); `req_to_resp_ms < 0` count = 0. Direction consistent: every row
`outstation_port == 20000`; single master `master_ip == 10.0.0.3`; 0 rows where
`master_ip == outstation_ip`. Outstation IPs partition cleanly by role (see Q5).

**4. Duplicate / overlapping observations.** Duplicate `(capture, tcp_stream, req_frame)` keys:
**0**. `resp_frame` claimed by >1 request within the same `(capture, tcp_stream)`: **0** — no
window overlap.

**5. Shared reference outstation (10.0.0.2).** Confirmed excluded from device-specific analysis.
All 11494 reference rows sit on `10.0.0.2`; **0** device-specific rows reference `10.0.0.2`
(device-specific IPs are exclusively 10.0.0.11 / 10.0.0.1 / 10.0.0.12). The reference is present
in every capture for provenance only, never folded into a device profile or `device_summary`
group. Treatment is correct.

**6. Confidence distribution.** high 22891 / medium 97 / low 0 (recomputed = reported).
`medium ≡ has-anomaly` holds exactly: all 97 medium rows carry at least one anomaly flag, 0
medium rows are anomaly-free, and all 97 anomaly rows are labelled medium. `low == OTHER` holds
vacuously (both 0 this run). Anomaly composition: retransmission (93) and duplicate_ack (93)
co-occur on the same rows; the remaining 4 are reset-only → 93 + 4 = 97 = medium.

## Ranked data-quality issues

Ranked by severity. **No blocking or material issues.** Two cosmetic notes only:

1. **(Cosmetic) Report prose uses shorthand class labels.** `data_quality_report.md` and the
   task brief say "COMBINED"/"SEPARATE"; the CSV enum is `COMBINED_ACK_RESPONSE` /
   `SEPARATE_ACK_RESPONSE`. Same semantics, no data error — flagged only so downstream filters
   match the full string.
   Query: `python3 -c "import csv,collections;print(collections.Counter(r['classification'] for r in csv.DictReader(open('tables/ack_trace_characterization.csv'))))"`

2. **(Cosmetic) `low`/`OTHER_OR_AMBIGUOUS` buckets are empty this run.** The rule
   `low == OTHER` is verified only vacuously (0 == 0). Not a defect — this trace set produced no
   ambiguous transactions — but the "OTHER retained not discarded" claim has no positive example
   to exercise here.
   Query: `awk -F, 'NR>1{print $(45)}' tables/ack_trace_characterization.csv | sort -u` (confidence col) → `high`,`medium` only.

## Commands of record

- Counts / dupes / overlap / confidence: `scratchpad/verify.py` (csv.DictReader over
  `ack_trace_characterization.csv`), reproduced above.
- pure_ack partition by class, direction, master_ip: inline `python3` heredoc.
- No files were modified outside this worklog.
