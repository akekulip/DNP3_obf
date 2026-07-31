# §5.5 (B) TCP-sequence-zero fix — validated on silicon (2026-07-31)

The value-sentinel on `reg_exp_relay_seq` (seq 0 == "no write", which mis-fires after a TCP
sequence wrap to 0) is replaced by a **writer/reader split** selected by packet class, so the
write is unconditional and seq 0 is stored.

## Compile (bf-p4c 9.13.2, deploy compiler) — resource-neutral
core 10/12 path10, telemetry/synth/injector 11/12 path10, 0 errors, 0 uninitialized_out_param.
Identical to the pre-B canonical build; B adds one logical table (the class-select gateway),
absorbed in existing stage 1. SALU input crossbar carries exactly 2 PHV inputs
(hdr.tcp.seq_no, meta.seq_w) — within the reg_tag-class budget.

## Assembly proof (artifacts/final/final_core_sde9132.bfa)
- `exp_seq_w_0`: `sub hi, phv_lo, lo ; alu_a lo, phv_hi ; output alu_hi` — an UNCONDITIONAL
  store of meta.seq_w; there is NO value predicate, so **seq 0 is written**.
- `exp_seq_r_0`: `sub hi, phv_lo, lo ; output alu_hi` — read-only (computes the diff, no write).
- the old value-sentinel `exp_seq_rmw_0` is ABSENT.
- `assert_salu_asm.py --require-r2` PASS — R2's note predicate is unchanged, so B did not
  disturb the R2 repair.

## Behaviour (Gate 2, synthetic build) — no regression
Gate 2 on the B build: 1 PASS / 0 FAIL, VERDICT PASS (the full arm->hold->ACK-first->RESPONSE
lifecycle). The normal seq!=0 path is unchanged; the only behavioural delta is that a seq-0
relay ACK after a wrap now qualifies instead of being forwarded unprotected.

Switch restored to Defense 2, one bf_switchd, verified.
