# WORKING NOTES — Defense 4 Case-A OVERNIGHT AUTONOMOUS RUN

**Task:** `defense4/overninght.md`. Branch `defense4-caseA-hw-integration`. Start HEAD `a085f00`.
Execute in the MANDATED ORDER; paper writing is LAST and gated on the experiment freeze.
Circle back to `defense4/overninght.md` continuously. Do not stop until the experiment gate
closes (or a genuine safety blocker remains after bounded attempts). Do NOT call the project "ADTA".

## Hard rules (from overninght.md)
- Recompute from primary evidence (P4/PCAP/JSON/counters/compiler/live readbacks). Do NOT trust
  prior Claude reports, commit messages, or this file as proof.
- Preserve frozen D1/D2/D3/Part11/Part12/four-queue sources. Do not merge to main. No size obfuscation.
- Physical SEL-751 READ-only. NO physical SELECT/OPERATE ever. No controller in the release fast path.
- Do NOT weaken a check/reinterpret a failure/modify scorer merely to get PASS.
- Do NOT call a delay "optimal" — say calibrated/tested/selected. No em dashes in prose.
- Only the main agent touches the live switch; expert agents are advisory; verify every agent claim.

## KNOWN FLAWS in the prior bring-up (must confront — from A3)
1. runner runs `configure` (→ clear_state) before EVERY poll → state reset each txn.
2. block.py: N=1, NEW TCP conn each poll, always FRAMES[0]=C0 → 17 D1 did NOT advance C0..CF → **rollover NOT proven**.
3. `0x8000` = 32768 ns = **32.768 us**, NOT ms. Native CLRT ~1.8-6 ms >> 32.768us -> deadlines expired
   before native RESPONSE -> D2/D4 did NOT prove response-deadline shaping (only classification+delivery).
4. FAIL_OPEN trial = configured bypass, NOT induced failure. D3 mode NOT run in integrated program.
5. Watermark latched -> only attributes occupancy to FIRST protected txn. Raw PCAPs not committed.

## PHASE TRACKER (update after each phase; commit at checkpoints)
- [x] A1 git state — HEAD=a085f00, local==origin, branch ok. Untracked intermediate evidence dirs to preserve.
- [x] A2 hardware snapshot -> A2_CURRENT_STATE_SNAPSHOT.md. CONFIRMED: d_ticks=32768=32.768us (1 tick~=1ns via D3 2ms=1999872), D4/0x8000 does NOT shape (live clrt 2.82ms native, qid4 wm=0). Binary+source hashes match.
- [x] A3 POST_BRINGUP_EVIDENCE_AUDIT.md written. All 7 flaws CONFIRMED from primary data. Rollover CONTRADICTED (C0-only,N=1,clear each txn). D2/D4 shaping CONTRADICTED (32.768us<<native). D3 NOT run. FAIL_OPEN not induced. 34 original PCAPs preserved+hashed in pcaps_original/. Independent reparse of blk_t2 corroborates txn2.
- [ ] A4 SPEC_IMPLEMENTATION_EVIDENCE_MATRIX.md
- [ ] B1 separate initialize / set-policy / clear-evidence / verify-only / snapshot ops + offline tests
- [ ] B2 correct parameter handling (real ms units, quantization authority)
- [ ] B3 sustained-connection campaign driver (multi-READ one TCP, C0..CF preserved)
- [ ] B4 expand evidence collection + scorer detections + raw PCAP + SHA256 manifest
- [ ] C hardware safety harness for campaigns (watchdog survives session loss, idempotent rollback)
- [ ] D1 recover original raw PCAPs from Vision (or state loss)
- [ ] D2 real generation rollover (>=33 READs one conn, C0..CF twice)
- [ ] D3 runtime fail-open (emulator/synthetic: missing ACK, missing RESP, zero budget, recovery, ..)
- [ ] D4 validate OFF/D1/D2/D3/D4 in integrated program (real shaping, not late-arrival)
- [ ] D5 PARAMETER_CALIBRATION.md (OFF pilot dist + justified D_A/D_R grid)
- [ ] D6 statistical campaigns A (fixed blocks) + B (randomized, seeded) >=100 valid/condition
- [ ] D7 protocol/adversarial 22-trace matrix vs integrated binary
- [ ] D8 DNP3 op boundary (READ physical; SELECT/OPERATE only controlled outstation)
- [ ] D9 DEFENSE4_BOTTLENECKS.md (compiler + runtime)
- [ ] F evidence freeze: EXPERIMENT_MATRIX, EXPERIMENTAL_EVIDENCE_FREEZE, SHA256SUMS, raw dir — one verdict
- [ ] G (ONLY if gate PASS/PARTIAL-closed) /research-pipeline Introduction + claim-source matrix + /humanizer

## Current switch state (update on every change)
- Per prior report: `defense4_caseA` loaded, D4 D_A=D_R=0x8000 armed, forwarding. TO BE RE-VERIFIED in A2.
- Switch decps@10.10.54.81; master/Vision decps@10.10.54.19; relay 192.168.10.7:20000 READ-only.
- SDE 9.13.2. D4 build /home/decps/d4_build/build9132/. Rollback: bash /home/decps/d4_build/rollback_defense3.sh.

## NEXT ACTION
A4 spec-implementation matrix (read P4 + TIMING_SPEC; fold in P4+DNP3 agents). Then Part B harness correction.
