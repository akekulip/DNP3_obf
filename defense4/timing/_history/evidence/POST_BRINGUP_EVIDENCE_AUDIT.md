# A3 — audit of the 2026-08-07 bring-up verdict

Every claim below was recomputed from primary artifacts (committed `transactions.jsonl`, the
runner/scorer/block.py source, live `tbl_params`, and the now-preserved raw PCAPs in
`bringup_live_20260807T014243Z/pcaps_original/`). Prior prose reports were not treated as proof.
An independent skeptical review ran in parallel; where it corroborates a primary finding it is
noted, but the classification below rests on the primary evidence.

## Verdict on the prior "HARDWARE BRING-UP PASS"

The run **did** establish a real, valuable feasibility result, but several of its headline claims
are **CONTRADICTED or only PARTIALLY SUPPORTED** by its own data. The corrected standing is:
**the mechanism loads, forwards real relay READ traffic, and the two-reservoir split is real, but
generation rollover was not tested, D2/D4 response shaping was not demonstrated, D3 was never run,
and fail-open was not induced.** The word "PASS" is withdrawn pending the corrected campaign.

## Claim-by-claim classification

| # | Claim in HARDWARE_BRINGUP_RESULT.md | Verdict | Primary evidence |
|---|---|---|---|
| 1 | Program `defense4_caseA` loads and forwards real SEL-751 READ traffic | **SUPPORTED** | all 34 txns `responded=1`; live A2 probe responds; binary sha256 `0ec4e452…` matches |
| 2 | 34 transactions received responses | **SUPPORTED** | `transactions.jsonl`: 34 rows, `responded=1` each |
| 3 | First protected READ generated + admitted 128 tokens | **SUPPORTED** | txn2 `pktgen_pkt_delta=128`, `cf_pktgen_admit_delta=128`; raw `blk_t2.pcap` corroborates the txn |
| 4 | Two-reservoir split seeds qid7 AND qid5 from one READ | **SUPPORTED** | txn2 wm_inc qid7=+43, qid5=+64; both reservoirs populated from one 128-token burst |
| 5 | qid4 held the RESPONSE, qid6 the ACK | **PARTIALLY SUPPORTED** | txn2 qid4 wm_inc=+3, qid6=+1 — true for that txn only; watermark is latched so no per-txn attribution after txn2 |
| 6 | ACK released before RESPONSE (ordering) | **PARTIALLY SUPPORTED** | txn2 raw pcap: ACK@032.014516 < RESP@032.014565 (49 µs). Structural guarantee is the strict-priority ladder; wire resolves it only sometimes (many D1 rows are equal-timestamp/inconclusive) |
| 7 | Zero TM drops/escape in the run | **PARTIALLY SUPPORTED** | no `drop_count_packets` increase on qid4-7; BUT capture filter was `host relay_ip`, so an escaped 0x88C1 token to the master could not be seen; global/port TM drops not read |
| 8 | "17 D1 transactions crossed the 16-generation rollover" | **CONTRADICTED** | runner calls `block.py t$TXN 1 0.2` (N=1) → block.py sends `FRAMES[0]`=C0 every time; `configure`→`clear_state` runs before each txn. All 17 D1 trials were C0 on a fresh TCP connection with reset state. No C0..CF advance, no rollover exercised |
| 9 | "CLRT normalized per mode: D2 4.784 ms (RESP deadline)" | **CONTRADICTED as shaping** | `tbl_params d_ticks=32768` = 32.768 µs; `da_dr=65536` = 65.536 µs (1 tick ≈ 1 ns from D3 2 ms→1,999,872). Native CLRT ≈ 1.8–6 ms, so T_RESP expired before the native RESPONSE. The 4.78 ms D2 figure is native late-arrival latency, not deadline-created shaping. qid4 watermark=0 on the live A2 probe confirms the RESPONSE is not held |
| 10 | D1 median 0.031 ms (collapsed) | **SUPPORTED (as event release)** | D1 holds the ACK until the RESPONSE event; `blk_t2.pcap` shows read→ack = 8.0 ms (held; native ~2 ms) and ACK/RESP within 49 µs. This is genuine event-driven collapse, though every trial was C0 |
| 11 | D4 exercised dual-deadline shaping | **CONTRADICTED as shaping** | same 32.768 µs / 65.536 µs sub-native deadlines; D4 rows are late-arrival delivery, not held-to-deadline shaping |
| 12 | FAIL_OPEN behavior demonstrated | **PARTIALLY SUPPORTED** | only the *configured* FAIL_OPEN bypass mode was run (1 txn, pktgen disabled). No missing-ACK, missing-RESPONSE, or budget-exhaustion failure was induced |
| 13 | D3 (ACK-deadline) mode validated in the integrated program | **NOT YET TESTED** | SCHED = OFF/D1/D2/D4/FAIL_OPEN — D3 mode was never run in `defense4_caseA` |
| 14 | Rollback restored a forwarding Defense 3 | **SUPPORTED** | rollback log + independent ping 0.6 ms after restore; validated end-to-end |
| 15 | "Switch left running Defense 4, protecting" | **PARTIALLY SUPPORTED** | D4 is loaded and forwarding, but with 32.768 µs deadlines it does not shape (A2: live clrt 2.82 ms native, qid4 wm=0). "Protecting" overstates the running policy |
| 16 | Raw PCAP evidence preserved | **CONTRADICTED (now fixed)** | 0 pcaps were in the committed dir; the 34 originals survived on Vision and are now copied to `pcaps_original/` with SHA256SUMS |

## Confirmed harness defects driving the flawed claims (fix in Part B)

1. `bringup_runner.sh` calls `configure --mode $M` before every poll; `configure` calls
   `clear_state` (setup.py:457, resetting reg_tag/deadlines/counters). State is destroyed each txn.
2. Traffic driver uses `block.py … 1 …` (N=1) opening a new TCP connection and sending only C0.
3. Parameters passed as raw ticks (`0x8000`) mislabeled as millisecond-scale; d_ticks=32768=32.768 µs.
4. Capture filter `host relay_ip` cannot see a token escaping to the master.
5. Scorer attributes queue occupancy from a latched watermark, valid only for the first protected txn.

## Preserved-valid result (do not discard)

The program loads and forwards real SEL-751 READ traffic; the first protected READ generated and
admitted exactly 128 tokens; qid7/qid6/qid5/qid4 were all exercised and qid5 was demonstrably
populated (the two-reservoir split is real on silicon); no four-queue TM drop was seen in that
short run; the tested rollback restored a forwarding Defense 3; and D1 produced a near-coincident
ACK and RESPONSE on the observed wire with a genuine ACK hold (read→ack 8 ms vs ~2 ms native).

## Corrected verdict wording

Replace "HARDWARE BRING-UP PASS" with: **"Mechanism bring-up feasibility demonstrated (load,
forward, two-reservoir split, D1 event collapse, safe rollback); generation rollover, D2/D3/D4
deadline shaping, and induced fail-open NOT yet demonstrated — pending the corrected campaign."**
The evidence-freeze verdict (Part F) supersedes this.
