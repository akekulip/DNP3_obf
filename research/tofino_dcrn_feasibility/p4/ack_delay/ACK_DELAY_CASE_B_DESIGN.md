# Case B — RESPONSE_DELAY_INCREASE_CLRT — off-switch design (2026-07-20)

Separate compile-time variant `dcrn_ackB.p4`. **Case A is untouched** (`dcrn_ackA.p4` sha 6e1b659b,
commits `bf4acdf..e6c2280`, tag `ack-delay-caseA-c3-pass` preserved). Case A and Case B are **not**
merged into one binary. Scope of this doc: deliverables 1–4, 8, 9, 10. Deliverable 5 (reference model
+ tests) is `refmodel/case_b_state_machine.py` + `tests/test_case_b.py` (10/10 PASS). Deliverables
6–7 (local bf-p4c compile + resource report) are delegated and appended on completion.

## 1. State-machine specification
Per flow (flow_id = hash(client_ip, server_ip, client_port), identical to Case A):

```
IDLE ──request(Class-0 READ, fc_allowlisted, dp8/dir0)──▶ ARMED
     arm: reg_armed:=1; reg_expected_ack:= req.seq + req.payload_len; forward request UNCHANGED

ARMED ──pure ACK (EXACT match, dir1)──▶ ACKED
     record: reg_deadline := now_tick + G_i        (ACK-RELATIVE — the only deadline write)
     forward the ACK IMMEDIATELY (PORT_VISION, no recirc, no hold)

ACKED ──response (dir1, payload>0, armed)──▶ RESP_HELD  (if now_tick < reg_deadline)
                                        └──▶ release   (if now_tick >= reg_deadline: deadline already
                                                        matured; release unchanged, no hold)
RESP_HELD ──recirc pass, now_tick refreshed from egress-bridged global_tstamp──▶
     now_tick >= reg_deadline  → release unchanged (PORT_VISION); clear state → IDLE
     pass_count > MAX_PASS      → FAIL-OPEN release (PORT_VISION); clear state → IDLE   [safety only]

any state ──reverse RST/FIN | stale generation | ambiguity──▶ fail open + clear → IDLE
```

The ACK is **never** held (contrast Case A). The response is the only held frame, and only ever on a
pass where `now_tick < reg_deadline`.

## 2. Exact ACK-relative release equation
```
t_response_out = max( t_response_ready , t_ACK + G_i )
```
- `t_ACK` = arrival time of the matching pure ACK (the deadline base — recorded at the ACK).
- `G_i` = common device-independent target gap (control-plane-loadable; NOT compiled-in).
- Effect: **request→ACK unchanged; ACK→response increased to G_i (when G_i ≥ readiness); request→
  response increased.** CLRT observed by the attacker = `t_response_out − t_ACK = G_i` (constant).
- This is **ACK-relative**. It is NOT `t0(request) + Di` (the old request-relative dcrn.p4 policy —
  a hard STOP condition).

## 3. Parser and bypass rules
- Parser: identical to Case A (payload-length DNP3 gate: descend into DNP3 only when
  `total_len ≥ 30 + 4·data_offset`, else `accept` → forwarded; fixes the zero-payload-ACK drop).
- **Exact pure-ACK match (required, unweakened):** hold-eligible ACK ⇔ `armed && (flags & 0x17)==0x10`
  (ACK=1, SYN=0, RST=0, FIN=0) `&& reg_expected_ack == tcp.ack_no`, first-only. Any failure → the ACK
  is forwarded (it always is in Case B) and no deadline logic fires on a non-matching frame.
- **Combined ACK-bearing response bypass:** a payload-bearing reverse frame on a flow with **no
  recorded ACK deadline** (no separate pure ACK was seen) → BYPASS unchanged. Its request→response
  time is **NOT** called CLRT (combined-mode delay is a separately labelled extension, out of scope).

## 4. Transaction lifecycle and fail-open
- State cleared **after response release** (deadline or fail-open): reg_armed, reg_expected_ack,
  reg_deadline, occupancy → 0. Also cleared on reverse RST/FIN (abort), stale generation, ambiguity.
- Occupancy = binary per-flow (like Case A FIX4): set when a response enters the hold loop, cleared
  on release/bypass/MAX_PASS. Returns to 0 after every txn — **no cold reload** (a STOP condition).
- **MAX_PASS is fail-open ONLY.** Normal release is the deadline. If the recirc clock fails to refresh
  (`now_tick` stale), the deadline never matures → MAX_PASS forwards the response (never drops). The
  reference model asserts `release_reason=="deadline"` under a healthy clock and only
  `"max_pass_fail_open"` under the injected clock bug.

## 8. Comparison against the Case-A architecture
| Aspect | Case A (ACK-delay, committed) | Case B (response-delay, this design) |
|---|---|---|
| Held frame | the **pure ACK** | the **response** |
| Governing | **event** (response arrival flips reg_ack_gone) | **deadline** (now ≥ t_ACK + G_i) |
| Recirc clock | not needed (event-governed) | **required** (global_tstamp refresh on recirc) |
| ACK path | held on recirc, released near response | **forwarded immediately** |
| CLRT effect | collapse to ~guard δ (**reduce**) | fix to constant G_i (**increase**) |
| Zero-inversion invariant | load-bearing (ACK before response) | trivially holds (ACK already egressed) |
| Key SALU risk | monotone register visibility | **runtime-operand deadline compare** (resolved at M1) |
| Reuse | — | Case-A parser/arm/exact-ACK/lifecycle + dcrn.p4 deadline/clock |

Case B is structurally simpler on the ordering axis (no held-ACK inversion hazard) but adds the
deadline arithmetic + the recirc-clock dependency that Case A deliberately avoided.

## 9. Proposed fixed-target calibration (B1_FIXED)
Measured (deliverable 9): response-readiness tails — rig dev1 max 26.6 ms, dev2 max 40.3 ms; real
SEL-751 capture p99 35.8 ms, max 170.8 ms; AB1400 max 95.3 ms; ION7550 max 21.5 ms. TCP RTO_MIN
measured **207 ms** (retransmit backoff). Constraint: `max(readiness rel. ACK) < G_i < RTO_MIN − margin`.
- **B1_FIXED (rig): G_i = 60 ms** (~916 ticks @ 65.536 µs). Exceeds dev2's 40 ms tail + 20 ms margin;
  well below the 207 ms RTO so the outstation does not retransmit while the switch holds the response.
  Chosen from the **tail (40 ms), not the median (35 ms)**, per the PI directive.
- **B2_COMMON_BOUNDED:** one bounded target distribution for every eligible device, independent of
  device identity / IP / response size / source pcap / native CLRT / ACK mode. NOTE: the real SEL-751
  readiness tail (170 ms) sits near RTO (207 ms); B2 must trade tail-coverage against retransmit risk
  on real devices — **do not reuse the 60 ms rig value for real-device B2 without re-measuring.**

## 10. Exact gated hardware experiment plan (NOT authorized yet)
Pre-req to request a window: dcrn_ackB.p4 fits ≤12 ingress stages locally AND the reference model
proves the 6 invariants (done). Then, in a gated window (snapshot+rollback; gc-switchd masked;
restore Case-A/decoy after):
1. Rebuild dcrn_ackB 9.13.2 on-switch (non-destructive). Confirm ≤12 stages, byte-preserving.
2. Load dcrn_ackB; control plane sets G_i = 60 ms (B1_FIXED) via the loadable register/action-data;
   dp8 loopback; verify arming (fc_allowlist) + a single-txn hold. Re-verify the "leave switch"
   discipline / restore contract with the PI.
3. **B1_FIXED acceptance (single-flow, then continuous):** for rig dev1 (17 ms) and dev2 (35 ms),
   measure: request→ACK unchanged; ACK forwarded immediately (ACK on the wire before any hold);
   response held to t_ACK + 60 ms; **CLRT ≈ 60 ms constant for BOTH profiles** (device-independent);
   response byte-identical; 0 retransmits/resets; occupancy→0; release_reason=deadline (MAX_PASS=0);
   zero response reordering. Continuous 120-txn one-connection run, shuffled profiles, NO cold reload.
4. **B2_COMMON_BOUNDED:** repeat with the bounded target distribution; confirm the CLRT distribution is
   device-independent (same for dev1 and dev2) and within the bounded band; re-measure the real-device
   readiness-vs-RTO margin before applying to any real capture.
5. Restore Case-A/decoy; tear down the rig.
STOP conditions (halt before/within the window): >12 stages; request-relative deadline; Case-A
modified; exact-ACK weakened; combined mixed into CLRT; cleanup needs cold reload; MAX_PASS becomes
the normal release.
```

## 6–7. Local bf-p4c 9.13.1 compile + resource report (FIT PASS)
dcrn_ackB.p4 sha256 `6387accb…` (separate binary; Case-A `dcrn_ackA.p4` unchanged at `6e1b659b`).
Independently re-verified: **0 errors, 2 benign parser-unroll warnings.**

| Metric | Case B (dcrn_ackB) | Case A (dcrn_ackA) |
|---|---|---|
| Ingress stages | **10 / 12** (2 headroom) | 12 / 12 |
| Egress stages | 1 | 1 |
| Critical path (table dep graph) | 8 | 7 |
| Logical tables | 48 | 48 |
| SRAM | 63 | 62 |
| TCAM | **0** | 0 |
| Stateful (Meter) ALUs | 6 (6 registers) | — |
| Stats ALUs | 6 | — |
| byte-preserving | yes (no Checksum extern) | yes |

Case B fits with MORE headroom than Case A (10 vs 12 stages) — it holds only the response (no held-ACK
ordering hazard) but adds the ACK-anchored deadline + the recirc-clock dependency. One accepted
simplification: no one-shot latch on the ACK (a duplicate EXACT-qualified pure ACK re-writes reg_deadline
— bounded, fail-open; a reg_ack_seen test-and-set can add strict one-shot within the 2-stage headroom).
Evidence: evidence/ackB_9.13.1/ (compile.log, table_summary.log, mau.resources.log, bfrt.json, SHA256.txt).

## Gate status: MET. Reference model proves all 6 invariants (tests/test_case_b.py 10/10) AND the local
## binary fits <=12 stages (10). Ready to REQUEST a Case-B hardware window (PI-authorized this run).
