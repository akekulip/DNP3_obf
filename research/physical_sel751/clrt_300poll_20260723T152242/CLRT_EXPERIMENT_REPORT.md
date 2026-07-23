# Physical SEL-751 CLRT Distribution — 300-poll experiment

**Date:** 2026-07-23 · **Experiment:** `clrt_300poll_20260723T152242` · **Relay:** physical SEL-751A
`192.168.10.7:20000` · **Master:** Vision `192.168.10.1` (eno1) · master addr **1**, outstation **0**.
Read-only. Tofino not involved. No relay/network/Tofino/history changes.

## Design (as authorized)
300 sequential Class-0 READ transactions over **one persistent TCP session**, **one outstanding
request at a time**, **1 s idle after each completed response**. **No auto-retry, no auto-reconnect**
(opendnp3 `ChannelRetry` min=max=3600 s), no parallel requests. Every automatic stack behaviour pinned
off (no startup poll, no ENABLE/DISABLE unsolicited, `timeSyncMode=None`, `ignoreRestartIIN=True` ⇒ no
restart-IIN WRITE). Hard-stop (no reconnect/retry) on any task failure, response timeout, IIN
request-error, or channel close. Probe: `clrt_experiment.py`. Runtime ≈ 5 min (19:24:43–19:29:47).

## Outcome — completed cleanly
- **All 300 polls completed. No stop condition fired. `stop_reason = None`.**
- **One TCP session** (1 SYN, source port constant), **0 RST**, **0 retransmissions, 0 duplicate ACKs,
  0 lost segments** (agreed by TCP-seq de-dup *and* tshark `tcp.analysis`).
- **300 unique requests → 300 unique responses, 0 missing.** Session opened with the normal DNP3
  link-status handshake (relay `REQUEST_LINK_STATUS`, master `LINK_STATUS`) — excluded from the poll set.
- **Case A holds for every transaction:** a **separate pure TCP ACK preceded the DNP3 response in all
  300** polls.

## CLRT distribution (ACK → response), n = 300, milliseconds
| stat | value |
|---|---|
| mean | **2.983** (bootstrap 95% CI [2.734, 3.251]) |
| median | **1.899** (bootstrap 95% CI [1.825, 1.926]) |
| std dev | 2.273 |
| min / max | 0.905 / 15.649 |
| p25 / p75 / IQR | 1.734 / 3.055 / 1.321 |
| p90 / p95 | 5.990 / 7.426 |
| coefficient of variation | 0.762 |

Right-skewed: a tight central mode near ~1.9 ms with a tail to ~15.6 ms. (No strong p99 claim is made
from 300 observations.)

## The other two latency variables, n = 300, milliseconds
| variable | mean | median | std | min | max | p25 | p75 | p90 | p95 | CoV |
|---|---|---|---|---|---|---|---|---|---|---|
| request → pure-ACK | 0.905 | 0.563 | 0.926 | 0.415 | 5.150 | 0.506 | 0.845 | 1.515 | 3.060 | 1.023 |
| ACK → response (CLRT) | 2.983 | 1.899 | 2.273 | 0.905 | 15.649 | 1.734 | 3.055 | 5.990 | 7.426 | 0.762 |
| request → response | 3.888 | 2.626 | 2.480 | 2.168 | 16.294 | 2.328 | 4.620 | 7.430 | 7.958 | 0.638 |
Bootstrap 95% CIs (10 000 resamples, seed 20260723) are in `summary.csv` / `summary.json` for all three.

## Consistency & protocol checks (all 300)
- **Response wire bytes:** all **134 B**; **DNP3 link length:** all **115 B**; **decoded points:** all
  **69** — invariant across the run.
- **Application header:** FIR=1, FIN=1, CON=0 for every response (single fragment; **no application
  CONFIRM requested or sent**). **Function code 129 (RESPONSE)** only — no unexpected functions.
- **Objects:** Group 1 Variation 2 binary inputs (index 0 = True), consistent with the baseline.
- **IIN:** every response carried **`0x8000`** = **DEVICE_RESTART set, no request-error bits**. The
  restart bit persists because we deliberately never sent the restart-clearing WRITE (read-only,
  `ignoreRestartIIN=True`). `HasRequestError()` was False on all 300 — no protocol error.
- **Application sequence:** increments 0→15 and wraps correctly across all 300 (`monotonic_mod16=True`).

## Comparisons / effects
- **First transaction vs remaining 299:** first CLRT = **1.767 ms**, rest mean = 2.987 ms, rest median =
  1.901 ms — the first poll is *slightly faster* than the rest-mean (Δ = −1.22 ms). **No cold-session
  latency penalty** is observed.
- **No retransmissions / duplicate ACKs / resets / lost segments** anywhere in the session.

## Interpretation (observed vs inferred)
- **Observed:** the physical SEL-751 exhibits Case A (separate ACK then response) with a **central CLRT
  around 1.9 ms (median) / 3.0 ms (mean)** under 1 Hz Class-0 polling, right-skewed with occasional
  excursions to ~15 ms.
- **Relation to the single baseline:** the earlier one-shot baseline (`6.12 ms`) sits high in this
  distribution (near p90), i.e. it was an unremarkable but upper-side single draw — underscoring why one
  sample is not a distribution.
- **Relation to the meeting's ~13 ms figure:** that came from the *original device traces*; the live
  median here (~1.9 ms) is substantially lower, though the tail reaches ~15.6 ms. This is **reported, not
  explained** — the difference could be relay load/state, polling cadence, response content, or how the
  original figure was computed. It is a flag for follow-up, not a conclusion.

## Limitations
- One relay, one configuration, one persistent session, 1 Hz cadence, 300 samples — **not** a
  multi-condition or multi-device characterization. No strong tail (p99) inference from 300 points.
- CLRT is sensitive to relay internal load and concurrent activity, which were not controlled here.
- Read-only Class-0 only; no event classes, no controls — by design.

## Evidence (this directory)
Raw: `evidence/clrt_300poll_20260723T152242.pcap`, `evidence/clrt_app_metadata.jsonl`,
`evidence/clrt_experiment.out`, `evidence/clrt_experiment.err`, `evidence/clrt_tcpdump.log`.
Derived: `per_poll.csv`, `per_poll.json`, `summary.csv`, `summary.json`,
`plots/{clrt_histogram,clrt_ecdf,clrt_box_violin,clrt_timeseries}.png`. Code: `clrt_experiment.py`,
`analyze_clrt.py`. Integrity: `SHA256SUMS.txt`.
