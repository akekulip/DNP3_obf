# Phase 01 — Real-Device DNP3 ACK and Response Trace Characterization

All results below are **re-derived this phase from the six immutable raw PCAPs**; no
number is carried from any prior report. Produced by the isolated run
`20260716T024101Z_phase_01_real_trace_characterization` (regenerable — see §Reproduction).

- **Run directory:** `runs/20260716T024101Z_phase_01_real_trace_characterization/`
  (git-ignored, regenerable; manifest committed under this phase folder).
- **Audited baseline / driver commit:** `c69e07e` (branch `research/ack-timing-phased`).
- **Inputs:** the six PCAPs in `Traffic Trace/` — SHA-256 in `DATA_PROVENANCE.md`, matched
  by the run manifest and re-verified by the reproducibility agent.
- **Tooling:** Python 3.8.10, tshark 4.4.9 (canonical extractor), scapy 2.4.3 (cross-check).

## Objective & scope

Characterize the ACK and response behavior of the captured DNP3 outstations from the raw
traces only. No timing/ACK/split behavior was modified; no new mechanism was built; no
migration was performed; Phase 02 was not entered. The shared reference outstation
(`10.0.0.2`) is excluded from device-specific analysis and reported only for provenance.

## Transactions reconstructed

**22,988 request→response transactions** reconstructed (device-specific **11,494**;
shared reference outstation **11,494**). Per device-specific outstation: SEL-751 4,298
(base 299 + L 3,999), AB1400 2,398 (399 + 1,999), ION7550 4,798 (799 + 3,999).
`OTHER_OR_AMBIGUOUS` = 0 this run; classification confidence high 22,891 / medium 97 / low 0.

## Research questions

### RQ1 — which traces have a pure TCP ACK *before* the DNP3 response?
Only **SEL-751**: **100%** of its 4,298 classified device-specific transactions are
`SEPARATE_ACK_RESPONSE` (a zero-payload pure TCP ACK precedes the payload-bearing DNP3
response). ION7550's L capture contains a single such transaction (1 of 3,999, 0.02%);
AB1400 has none.

### RQ2 — which traces piggyback the TCP ACK on the DNP3 response?
**AB1400** (100% of 2,398) and **ION7550** (99.98%, 4,797 of 4,798) are
`COMBINED_ACK_RESPONSE`: the payload-bearing DNP3 RESPONSE also acknowledges the request
bytes at the TCP layer. (Terminology: the TCP ACK is *piggybacked on the payload-bearing
DNP3 RESPONSE*; this is not a DNP3 application CONFIRM.)

### RQ3 — per-device delay distributions (device-specific, base/L)
Medians in ms (bootstrap 95% CIs in the machine-readable `device_summary.csv`):

| device | capture | req→first-reverse | req→pure-ACK (sep) | pure-ACK→resp (sep) | req→response |
|---|---|---:|---:|---:|---:|
| SEL-751 | base | 3.695 | 3.695 | 12.898 | 16.985 |
| SEL-751 | L | 3.673 | 3.673 | 12.178 | 16.104 |
| AB1400 | base | 16.620 | n/a | n/a | 16.620 |
| AB1400 | L | 16.247 | n/a | n/a | 16.247 |
| ION7550 | base | 16.055 | n/a | n/a | 16.055 |
| ION7550 | L | 15.984 | n/a | n/a | 15.984 |

For the combined devices there is no separate ACK, so request→first-reverse equals
request→response. For SEL-751 the response arrives ~12–13 ms after its pure ACK.

### RQ4 — request and response sizes
Near-identical across devices at the median: **request payload 35 B** (p5 22, p95 35 —
two request types), **response payload 37 B** median for all three (p95 54 B for
AB1400/SEL-751, **61 B** for ION7550). Per-transaction packet count and IP bytes differ by
ACK mode: SEL-751 = **3 packets / 270 IP bytes** (request + pure ACK + response), AB1400 &
ION7550 = **2 packets / 180–191 IP bytes** (request + combined response).

### RQ5 — feature stability across base vs L captures
Base and L distributions are close within the captured data (full table in
`statistical_comparison.md` / `capture_comparison.csv`). Effect sizes are small: AB1400 and
ION7550 request→response KS ≈ 0.001–0.14 (Cliff's δ ≤ 0.34); SEL-751 shows the largest
base-vs-L drift (request→response KS 0.236, W1 1.28 ms, Cliff's δ 0.22, Cohen's d 0.19).
Packet-count and median sizes are identical base vs L. These describe only the captured
traces and do **not** imply temporal stability beyond them.

### RQ6 — TCP anomalies and ambiguity
Across all 22,988 transactions: **retransmission 93, duplicate-ACK 93, reset 4,
out-of-order 0, missing-response 0, OTHER_OR_AMBIGUOUS 0.** Every flagged transaction is
enumerated in `tables/transaction_anomalies.csv` with its reason; none are silently
dropped. (Independently recomputed by the data-quality agent — exact match.)

### RQ7 — do the tshark and Scapy analyzers agree?
Yes, on a validated fixture: **23/23** fixture transactions (10 combined + 10 separate + 3
anomalous) agree on frame selection, ACK mode, timestamps, and sizes
(`extractor_validation.md`). tshark remains the canonical extractor with an independent
Scapy cross-check; neither is retired.

## Key finding (stated with discipline)

In these captures the **median** request→response time (~16 ms) and the **median** payload
sizes (35 B request, 37 B response) are **not** device-distinguishing — all three devices
sit near the same point. The features that separate these captured devices are the **ACK
mode** (SEL-751 emits a separate pure ACK; AB1400 and ION7550 piggyback), the resulting
**per-transaction packet count / total bytes** (3 / 270 B vs 2 / 180 B), and the **tail
behavior** (SEL-751 req→response p95 ≈ 21 ms with higher CV vs ≈ 17 ms for the combined
devices). This refines the earlier "native ~16 ms is device-distinguishing" framing: the
median is shared; the signal is in ACK mode, shape, and the tail.

## Claim discipline (§10)

These statements describe the **captured traces of these specific devices**, not product
families. The pure-ACK→response gap is a wire-visible interval, **not** the device's exact
internal processing time. Host-side capture timestamps are **not** identical to wire
timestamps. No claim is made that "Linux causes" any behavior.

## Prior claims reproduced / refined

- **Reproduced:** the ~22,988-transaction count (independently reconstructed = 22,988);
  SEL-751 separate-ACK vs AB1400/ION7550 combined-ACK behavior (for the captured devices).
- **Refined:** median request→response time and payload size are shared across the three
  captured devices; the device-distinguishing signal is ACK mode + packet-count/bytes +
  tail, not the median timing/size.

## Independent agent verification

| Agent | Scope | Verdict |
|---|---|---|
| B — Data quality | counts, negatives, duplicates, overlaps, reference treatment | PASS — all counts match; 0 negative delays; 0 duplicate keys; 0 overlaps; reference `10.0.0.2` cleanly excluded (single master `10.0.0.3`) |
| D — Visualization | 15 figures + metadata sidecars | PASS — 45 images + 15 sidecars from real data; degenerate cases (ION7550 n=1 separate; undefined correlation cell) flagged, not fabricated |
| E — Reproducibility | manifest, hashes, determinism, refusal | PASS — manifest complete (tshark+scapy); six hashes match Phase 00; two runs byte-identical (same SHA-256, 22,988 rows); fixed reports untouched; populated-dir refusal works |
| A — PCAP transaction | reconstruction / seq-ack / classification spot-check | PASS — 10/10 spot-checks sound; SEL-751 separate & AB1400/ION7550 combined confirmed; `tcp.ack == req_seq + req_tcp_len` held; anomaly counts match tshark exactly; ION7550's lone separate (`ION7550L:8135`) is a genuine rare event |
| C — Statistical | recompute stats / CIs / KS / Wasserstein | PASS — all statistics match to 6 dp; bootstrap deterministic; SEL-751 base-vs-L KS/W1 matched scipy exactly; degenerate cells (ION7550 n=1, constant packet_count) handled honestly |
| F — Research reviewer | overclaiming / terminology / ambiguity | PASS — 0 hard §10 overclaims; no RESPONSE called an application ACK; ambiguous retained; the one flagged item (ION7550 n=1 "median") is now annotated `(n=1, single obs)` |

_Verification note:_ all six agents verified run `…4101Z`; the reproducibility agent proved the reconstruction is byte-identical across independent runs, so the data is fixed. After review, the run's summary/profile text was regenerated in place to annotate the ION7550 single-observation (n=1) separate-ACK cell (per reviewer item M1). Deferred (non-blocking, not required by §4): persisting the response packet's `tcp.ack` in the main table — the COMBINED ACK relationship was instead verified by the PCAP agent and by the manual-validation re-read.

## Reproduction

```bash
cd dnp3_split_harness
python3 phase01_characterize.py --isolated            # or --run-dir <fresh dir>
python3 phase01_extractor_agreement.py --run-dir <run>
python3 phase01_manual_validation.py   --run-dir <run>
python3 phase01_figures.py             --run-dir <run>
```
Each run mints a fresh `runs/<UTC>_phase_01_real_trace_characterization/`, refuses a
populated directory, and records a manifest (git commit, tshark/scapy versions, six input
SHA-256, command, timestamps, exit status).

## Phase 01 gate (§11)

| Requirement | Status |
|---|---|
| Six PCAP hashes match Phase 00 provenance | PASS (reproducibility agent) |
| All outputs from the isolated Phase 01 run | PASS |
| No existing fixed report overwritten | PASS (git clean for tracked reports/profiles) |
| Transaction reconstruction reproducible | PASS (two runs byte-identical) |
| Ambiguous transactions reported | PASS (0 this run; enumerated mechanism in place) |
| Manual validation completed | PASS (60/60, seed 20250716; automated re-extraction, labeled) |
| Extractor agreement measured | PASS (23/23) |
| Figures trace to machine-readable data | PASS (metadata sidecars) |
| Prior headline numbers reproduced or corrected | PASS (22,988 reproduced; median-distinguishability refined) |
| No product-family generalization | PASS (per §10 discipline) |
| No Phase 02 code / timing behavior introduced | PASS |

**Status: PASS.** All eleven gate requirements are met and all six independent verification
agents returned PASS. `next_phase_allowed = false` (awaiting explicit human authorization for
Phase 02).

```
STOP: Awaiting human review before Phase 02.
```
