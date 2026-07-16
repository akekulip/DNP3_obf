# Phase 01 PCAP Transaction Agent — Verification Worklog

**Run audited:** `runs/20260716T024101Z_phase_01_real_trace_characterization/`
**Table:** `tables/ack_trace_characterization.csv` (22,988 rows) + `tables/transaction_anomalies.csv` (97 rows)
**Reconstruction code:** `phase01_reconstruct.py` (classification logic mirrored from `characterize_ack_traces.py`)
**Tooling:** TShark 4.4.9, default relative TCP sequence numbers (matches the extractor, which uses tshark defaults).
**Mode:** READ-ONLY (this worklog is the only file written).

---

## Structural understanding (prerequisite for reading the table correctly)

- Master = `10.0.0.3` in every capture. Outstation port = 20000.
- Each capture contains **two** DNP3 flows: the device-specific outstation and a **shared reference outstation `10.0.0.2`** (`REFERENCE_IP` in the code).
  - SEL751 device = `10.0.0.1`, AB1400 device = `10.0.0.12`, ION7550 device = `10.0.0.11`, plus `10.0.0.2` reference in all six pcaps.
- `is_reference = (outstation_ip == 10.0.0.2)`. So each transaction is stored **once**, but the CSV mixes the device-specific flow (`is_reference=False`) with the reference flow (`is_reference=True`).
- **This explains the apparent SEL751 split** (CSV-wide: 4296 COMBINED / 4300 SEPARATE): the SEPARATE rows are the SEL-751 device (`10.0.0.1`), the COMBINED rows are the shared reference (`10.0.0.2`). The run `stdout.log` per-device summary reports the **device-specific** outstation only, hence "SEL751 100% separate." Not a defect, but a reader must filter on `outstation_ip`/`is_reference` before quoting per-device classification percentages.

Distribution (device-specific outstation only, `is_reference=False`):
- SEL751 `10.0.0.1`: 4298 SEPARATE / 0 COMBINED → 100% SEPARATE.
- AB1400 `10.0.0.12`: 2398 COMBINED / 0 SEPARATE → 100% COMBINED.
- ION7550 `10.0.0.11`: 4797 COMBINED / **1 SEPARATE** → 99.98% COMBINED (the 1 SEPARATE is real — verified below, txn9).

No `OTHER_OR_AMBIGUOUS` transactions, no `missing_response=True`, all `ambiguity_reason` empty — internally consistent, since the code only sets a reason when `classification == OTHER`.

---

## Spot-check table (10 transactions, 3 devices; frames verified against raw pcap)

Txn id = `capture:req_frame`. All seq/ack are tshark relative. **ACK eq** = does the ACKing packet's `tcp.ack == req_seq + req_tcp_len`?

| # | Txn id | stream / outstation | req (frame: seq,ack,len,func) | ACKing pkt (frame: len,flags,ack) | resp (frame: len,func) | recorded class | pkt-verified class | ACK eq | Verdict |
|---|--------|--------------------|------------------------------|-----------------------------------|------------------------|----------------|--------------------|--------|---------|
| 1 | SEL751L:4 | s0 / 10.0.0.1 dev | f4: 1,1,22,func1 | f5 pure-ACK: len0, 0x0010, ack23 | f6: len54, func129 | SEPARATE | SEPARATE (pure ACK f5 before resp f6) | 23=1+22 ✓ | PASS |
| 2 | SEL751:1 | s0 / 10.0.0.1 dev | f1: 1,1,22,func1 | f2 pure-ACK: len0, 0x0010, ack23 | f3: len54, func129 | SEPARATE | SEPARATE | 23=1+22 ✓ | PASS |
| 3 | SEL751L:16011 | s1 / 10.0.0.2 ref | f16011: 23,55,22,func1 | f16012 resp: len54, 0x0018, ack45 | f16012: len54, func129 | COMBINED | COMBINED (first rev carries payload) | 45=23+22 ✓ | PASS |
| 4 | AB1400L:4 | s0 / 10.0.0.12 dev | f4: 1,1,22,func1 | f5 resp: len54, 0x0018, ack23 | f5: len54, func129 | COMBINED | COMBINED | 23=1+22 ✓ | PASS |
| 5 | AB1400:1198 | s0 / 10.0.0.12 dev | f1198: 11344,18110,35,func5 | f1199 resp: len37, 0x0018, ack11379 | f1199: len37, func129 | COMBINED, reset=True | COMBINED; RST is f1203 (0x0014) later in window | 11379=11344+35 ✓ | PASS |
| 6 | AB1400:1207 | s1 / 10.0.0.2 ref | f1207: 1,1,22,func1 | f1208 pure-ACK: len0, 0x0010, ack23 | f1209: len54, func129 | SEPARATE | SEPARATE (reference occasionally separates) | 23=1+22 ✓ | PASS |
| 7 | ION7550L:4 | s0 / 10.0.0.11 dev | f4: 1,1,22,func1 | f5 resp: len61, 0x0018, ack23 | f5: len61, func129 | COMBINED | COMBINED | 23=1+22 ✓ | PASS |
| 8 | ION7550:100 | s0 / 10.0.0.11 dev | f100: 705,1953,22,func1 | f101 resp: len61, 0x0018, ack727 | f101: len61, func129 | COMBINED, retrans=1, dupack=1 | COMBINED; retrans=f103, dupACK=f104 in window | 727=705+22 ✓ | PASS |
| 9 | ION7550L:8135 | s0 / 10.0.0.11 dev | f8135: 68549,147914,35,func5 | f8136 pure-ACK: len0, 0x0010, ack68584 | f8137: len37, func129 | SEPARATE | **SEPARATE — genuine** (real pure ACK f8136 then resp f8137) | 68584=68549+35 ✓ | PASS |
| 10 | ION7550L:12097 | s1 / 10.0.0.2 ref | f12097: 1,1,22,func1 | f12098 pure-ACK: len0, 0x0010, ack23 | f12099: len61, func129 | SEPARATE | SEPARATE | 23=1+22 ✓ | PASS |

**Result: 10/10 transactions match the packets exactly.** In every case `resp_frame` is genuinely the outstation's first reverse-direction packet with `tcp.len>0` and DNP3 present; pure TCP ACKs (`tcp.len==0`, flags `0x0010`, no DNP3) are never mislabeled as the response, and no DNP3 response (`tcp.len>0`, DNP3 present) is ever mislabeled as a pure ACK.

### Notable adversarial cases (verified correct, not defects)
- **txn5 (AB1400:1198)** — `reset=True` on a COMBINED transaction. Verified the RST is frame 1203 (`tcp.flags=0x0014` = RST+ACK) appearing *later* in the transaction window (connection teardown), not the first reverse packet. Classification stays COMBINED correctly because `first_rev`=f1199 is the DNP3 response. Confidence downgraded to `medium` — correct.
- **txn8 (ION7550:100)** — `retrans=1, dupack=1`. Verified retransmission is frame 103 (dup of response f101, `tcp.analysis.retransmission` set) and duplicate ACK is frame 104 (`tcp.analysis.duplicate_ack`), both inside the window. First response is still f101 → COMBINED correct. Confidence `medium` — correct.
- **txn9 (ION7550L:8135)** — the single device-specific SEPARATE for ION7550 out of ~6000. Verified real in the raw pcap: pure ACK (f8136, len0) precedes the response (f8137) for a func=5 request. The reconstruction faithfully captured a genuine rare event; it is **not** a misclassification.

---

## Requirement-by-requirement findings

1. **Request→response matching** — PASS. 10/10 `resp_frame` values are the true first payload-bearing DNP3 reverse packet; COMBINED/SEPARATE match the packets.
2. **Seq/ACK numbers** — PASS. `tcp.ack == req_seq + req_tcp_len` holds for all 10 (pure-ACK for SEPARATE, piggyback response for COMBINED). Note: COMBINED ACK values were verified from tshark because the CSV does not persist a `resp_ack` column (see Concern C1).
3. **ACK classification** — PASS. SEL-751 device (10.0.0.1) = 100% SEPARATE (pure ACK precedes response). AB1400 (10.0.0.12) / ION7550 (10.0.0.11) = COMBINED (piggyback). No DNP3 response mislabeled as a TCP ACK (`_is_pure_tcp_ack` requires `tlen==0`, structurally excludes payload packets).
4. **TCP anomalies** — PASS, exact match against tshark `tcp.analysis`:
   - ION7550.pcap: tshark 49 retransmissions / 49 duplicate-ack packets / 1 RST → CSV sums 49 / 49 / 1 reset-txn.
   - AB1400.pcap: tshark 0 / 0 / 1 RST → CSV 0 / 0 / 1 reset-txn.
   - SEL751L.pcap: tshark 0 / 0 / 0 → CSV 0 / 0 / 0.
   Exact per-packet equality means every flagged packet fell inside exactly one transaction window (none orphaned).
5. **Ambiguity** — N/A but clean. Zero `OTHER_OR_AMBIGUOUS` transactions and zero missing responses in this run, so nothing is silently dropped. 1:1 request→transaction anchoring confirmed: SEL751.pcap 598 DNP3 requests = 598 rows; ION7550L.pcap 7998 = 7998; AB1400L.pcap 3998 = 3998. Every payload-bearing request produces exactly one row. The code path that would emit `OTHER` always attaches a non-empty `ambiguity_reason`, so any future ambiguous case would be labeled, not dropped.

---

## Concerns (none block soundness)

- **C1 (schema/completeness, not correctness):** The audit task lists a `resp_ack` column, but `phase01_reconstruct.py`'s `RichTransaction` does not record the response packet's ACK number — only `pure_ack_ack` (SEPARATE only) is persisted. For COMBINED transactions the ACK that satisfies `req_seq + req_tcp_len` lives in the response packet and is **not** in the CSV. Any downstream ACK-equation check on COMBINED rows must go back to the pcap (as I did). Recommend adding `resp_ack` to the dataclass if the downstream analysis needs it.
- **C2 (reader hazard, not a bug):** CSV-wide classification percentages per `device_label` are misleading because each capture folds in the shared `10.0.0.2` reference flow. Consumers must group by `outstation_ip` (or `is_reference`) — e.g. SEL751 looks ~50/50 COMBINED/SEPARATE across the whole table but is 100% SEPARATE on its own outstation. The run's own `stdout.log` and `device_summary` already scope to the device outstation; downstream consumers of the raw CSV should do the same.

---

## Verdict

**Reconstruction is SOUND.** 10/10 spot-checked transactions across all three devices match the raw packets on frame selection, seq/ack arithmetic, classification, and anomaly counts; per-capture anomaly totals equal tshark's `tcp.analysis` counts exactly; request→transaction anchoring is 1:1 with no drops. No misclassification found. Two non-blocking concerns logged (C1 missing `resp_ack` column; C2 reference-flow folding in CSV-wide percentages).
