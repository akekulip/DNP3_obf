# Event semantics truth table

What every measured or configured timing event is, where it is observed, which line of the
implementation or extractor defines it, and which equation follows. Built from the exact
experiment source (`defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`,
sha256 `7ce30494…`), the control-plane chain at the same commit, the readbacks, the six raw
captures, and the extractor `defense4/timing/analysis/dnp3_timing.py`. Only equations supported
by this table appear in the manuscript.

## 1. Observation point and clocks

All timestamps are from one capture on the master host (Vision, `enp59s0f0np0`), on the link
between the master and switch port dp9. One clock. The switch-internal deadlines are computed on
the switch's own ingress timestamp (`now_word`, 256 ns ticks); the master-facing capture sees
each release after a path and capture offset of roughly 1 ms, which cancels in every difference
the paper reports (`audit/VERDICT.json` `bor_operate_timing.note`). Nothing on the relay-facing
port dp64 or the internal port dp68 was captured.

## 2. Notation (one symbol per quantity, used throughout the paper)

| symbol | meaning | where set |
|---|---|---|
| `T_req` | master-side timestamp of the master's DNP3 request (function 1, 3 or 4) | extractor, `t_req_ns` |
| `T_ack` | master-side timestamp of the first relay packet with the TCP ACK flag after that request | extractor, `t_ack_ns` |
| `T_resp` | master-side timestamp of the relay's DNP3 application response (function 0x81) | extractor, `t_resp_ns` |
| `t_A` | switch ingress time of the relay's TCP ACK (unobserved; the anchor of the read path) | P4 `now_word` on the ACK, line 2549 |
| `T0` | switch ingress time of the master's OPERATE (unobserved; the anchor of the control path) | P4 `now_word` on the OPERATE, lines 2966–2971 |
| `D_A`, `D_R` | read-path offsets: ACK release delay after `t_A`, response release delay after the ACK release | `tbl_params.d_ticks`, `da_dr = D_A + D_R`; setup defaults 20 ms, 4 ms |
| `A`, `R` | control-path offsets from `T0` to the ACK release and to the echo release | `tbl_bor_params`; `A_DEFAULT_TICKS` = 20 ms, `R_DEFAULT_TICKS` = 24 ms |
| `J` | control-path hold: OPERATE forwarded to the relay at `T0 + J` | `tbl_bor_codebook`, {2, 6, 12} ms fixed passes |
| CLRT | `T_resp − T_ack` (Formby's cross-layer response time) | extractor `clrt_ms` |

`G` (Dr. Lin's spoken name for the operate hold) is the same quantity as `J`; the paper uses `J`,
the name in the implementation, the readbacks and the manifests.

## 3. The table

| # | transaction class | packet | DNP3 func | direction | observation point | timestamp | source | extractor column | configured register | P4 action / queue | release rule | equation | measured interval | observed or inferred |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | READ | request | 1 | master → relay | master-facing | `T_req` | capture | `t_req` | — | forwarded unchanged; `tag_arm` marks the transaction active (lines 3099–3102) | none (not held) | — | — | observed |
| 2 | READ | relay TCP ACK (pure ACK, no DNP3 payload) | — | relay → master | master-facing (after release) | `T_ack` | capture | `t_ack` | `tbl_params.d_ticks` = D_A | `dec_ack_arm`: `dl_val = now_word + D_A` (lines 2549, 2586); held in Q_ACK_HOLD (qid6) on dp8 behind Q_ACK_BLOCK (qid7) | released at `t_A + D_A` (mode D4); forwarded immediately in mode OFF (line 2840, `MODE_OFF`) | `T_ack ≈ T_req + a + D_A` where `a` = relay ACK latency | request-to-ACK: Timing OFF median 0.627 ms; Obfuscated 20.661 ms (READ) | observed master-facing; `t_A` inferred |
| 3 | READ | relay DNP3 response | 0x81 | relay → master | master-facing (after release) | `T_resp` | capture | `t_resp` | `tbl_params.da_dr` = D_A + D_R | `dec_ack_arm`: `dl_val_resp = now_word + da_dr` (lines 2557, 2586, 1706); held in Q_RESP_HOLD (qid4) behind Q_RESP_BLOCK (qid5) | released at `t_A + D_A + D_R` | CLRT = `T_resp − T_ack` = D_R when the response has arrived by then | CLRT: Timing OFF median 1.272 ms (n=999); Obfuscated 4.001 ms (n=599) | observed |
| 4 | SELECT (SELECT phase of SBO) | request | 3 | master → relay | master-facing | `T_req` | capture | `t_req` | — | as row 1; additionally `BPC_PREPARE` allocates a BOR epoch (line 2954) | none | — | — | observed |
| 5 | SELECT | relay TCP ACK | — | relay → master | master-facing | `T_ack` | capture | `t_ack` | D_A | as row 2 (multi-function admission, header item 1) | `t_A + D_A` | as row 2 | request-to-ACK: Timing OFF 0.492 ms; Obfuscated 20.510 ms | observed |
| 6 | SELECT | relay DNP3 response (the SELECT echo) | 0x81 | relay → master | master-facing | `T_resp` | capture | `t_resp` | D_A + D_R | as row 3 | `t_A + D_A + D_R` | CLRT = D_R | CLRT: Timing OFF 2.107 ms (n=488); Obfuscated 4.001 ms (n=499) | observed |
| 7 | OPERATE | request | 4 | master → relay | master-facing on arrival; relay-facing release unobserved | `T_req` | capture | `t_req` | `tbl_bor_codebook` → J | `BPC_OPERATE`: held in Q_OP_HOLD (qid2) on dp10 behind Q_OP_BLOCK (qid3); `reg_bor_topj = T0 + J` (lines 383–395, 1784–1794) | forwarded to the relay at `T0 + J` (`OUT_OP_RELAY`, line 793) | relay-facing time `T0 + J` | not measured | `T0 + J` inferred from configuration only; never observed |
| 8 | OPERATE | master-visible ACK | — | relay → master | master-facing | `T_ack` | capture | `A_ms` in `sbo_j*.csv` | `tbl_bor_params.a_ticks` = A | `dl_val = dl_cand_op = T0 + A` (lines 2970, 3146); the later relay ACK's `deadline_arm_once` is a no-op (lines 3139–3145) | released at `T0 + A` | `T_ack − T_req ≈ A + offset` | medians 21.03 / 21.02 / 21.03 ms at J = 2 / 6 / 12 | observed |
| 9 | OPERATE | master-visible echo (OPERATE response) | 0x81 | relay → master | master-facing | `T_resp` | capture | `R_ms` | `tbl_bor_params.r_ticks` = R | `dl_val_resp = tresp_cand_op = T0 + R` (lines 2971, 3147) | released at `T0 + R` | `T_resp − T_req ≈ R + offset` | medians 25.03 / 25.03 / 25.03 ms | observed |
| 10 | OPERATE | echo minus ACK | — | — | master-facing | derived | — | `echo_ack_ms` | — | — | — | `T_resp − T_ack = R − A`, J absent | 4.001 / 4.002 / 4.003 ms, std ≈ 0.026 ms, n = 30 each | observed |
| 11 | any | relay-facing ACK, response, OPERATE arrival at the relay, physical actuation | — | switch → relay | dp64 (no tap) | — | — | — | — | — | — | — | — | not captured; no relay-facing event is evidence |

Row 8 note: the master-visible ACK of an OPERATE is the relay's own TCP ACK, released by the
switch at `T0 + A`. Because the OPERATE reaches the relay only at `T0 + J`, the relay's ACK exists
only after `T0 + J`; the setup asserts `A > J_max + native_ACK` (readback row 1) so the deadline
is always after the ACK has arrived. This is why the control path must be anchored at `T0`: a
deadline of `t_A + D` would carry `J` into the observable.

## 4. Consequences for the equations in the paper

Read path (READ and the SELECT phase of SBO), timing mode D4:

    t_ack,rel  = t_A + D_A
    t_resp,rel = t_A + D_A + D_R
    CLRT       = t_resp,rel − t_ack,rel = D_R                   (policy value 4 ms)

valid when the relay's response arrives before `t_A + D_A + D_R`; every response in every capture
did (no unpaired transaction). The master-visible request-to-ACK interval becomes `a + D_A`; it is
shifted by D_A but still carries the relay's own ACK latency `a` (about 0.5 ms with 0.5 ms spread),
which the paper states rather than hides. The first transaction of a TCP connection is excluded
from the statistics as a cold start (`read_txn_csv(drop_cold=True)`).

Control path (OPERATE), timing mode D4:

    t_ack,rel  = T0 + A
    t_echo,rel = T0 + R
    t_relay    = T0 + J        (relay-facing, unobserved)
    O          = t_echo,rel − t_ack,rel = R − A                   (policy value 4 ms)

`J` does not appear in `O`, so an observer subtracting the two timestamps it has learns nothing
about the configured hold. `A` and `R` are the same 20 ms and 24 ms in both formulations of the
anchor; what differs between the read and control paths is the anchor, not the offsets. The
absolute intervals measured master-facing (about 21 and 25 ms) exceed the configured 20 and 24 ms by
the path-and-capture offset, which cancels in `O`.

Timing mode OFF: `MODE_OFF` forwards the ACK and the response immediately (P4 lines 632, 2833,
2840); no deadline is armed (`tag_val = TAG_NO_WRITE`, line 3050); the pktgen reservoirs are
disabled (`PKTGEN_ENABLED_MODES` excludes OFF, `defense4_caseA_setup.py` line 67). The size carve
(`shape_enable = 1`) is applied in both modes.

## 5. What the earlier manuscript got wrong

`design_pipeline_v1.tex` (2026-08-19) stated `t_ack = T0 + A`, `t_resp = T0 + R` for the read
path and argued that anchoring reads to `T0` removes any dependence on the relay's ACK. The
implementation anchors reads to the relay ACK. The corrected Design section presents both rules
and the reason the control path alone is request-anchored. The manifest fields `D_A_ms`/`D_R_ms`
were filed under "no OPERATE transactions"; they are read-path parameters and are corrected in
`make_capture_manifest.py` (regenerated `CAPTURE_MANIFEST.csv/.json`).

## 6. Provenance status of each configured value in the E phase

| value | how known | status |
|---|---|---|
| mode OFF / D4 | frozen `E_FINAL/README.md` configure lines; corroborated by CLRT | VERIFIED |
| D_A = 20 ms, D_R = 4 ms | `defense4_rrc_bor_unified12_setup.py` defaults (lines 487–488, 1083–1084) not overridden by the frozen configure line; corroborated by request-to-ACK ≈ 20.5 ms and CLRT = 4.001 ms; no `tbl_params` readback archived for the E phase | PARTIAL |
| A = 20 ms, R = 24 ms | `A_DEFAULT_TICKS`/`R_DEFAULT_TICKS`; E0 record; readback rows (quantization, admissibility); corroborated by 21/25 ms master-visible | VERIFIED (rows matched to a passing configure-all run; see L7) |
| J ∈ {2, 6, 12} ms | E0 record; readback rows `J[2]…J[12]`; configured per batch, never observed | PARTIAL |
| shape_enable = 1 | direct observation: 28 + 21 byte payloads in every capture | VERIFIED |
