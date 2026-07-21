# Case-A pre-scale hardening (FIX 1+2+4) — COMPLETE off-switch (compiles + unit-verified)

Date 2026-07-20. Hardened `dcrn_ackA.p4` sha256 `6e1b659b…` (supersedes the C3-pass baseline
`c9f4c109` / tag `ack-delay-caseA-c3-pass`). Local bf-p4c 9.13.1: **0 errors, 2 warnings (both benign
parser-unroll, identical to baseline), 12/12 ingress stages, egress 1, critical path 7,
byte-preserving** (no `Checksum()` extern), evstat registers intact.

## Implemented (this round — the PI-selected accumulation-critical subset)
- **FIX 1 exact pure-ACK qualification** — hold a reverse frame only if `armed && flags_ok
  ((flags&0x17)==0x10: ACK=1,SYN=RST=FIN=0) && expack_match (reg_expected_ack==tcp.ack_no)`, and only
  the FIRST such ACK (fha test-and-set). FIN/RST/SYN/keepalives/dup-ACKs/window-updates forward, never
  held — the direct fix for the accumulation root cause.
- **FIX 2 transaction lifecycle** — `armed` cleared on the response (armed_getclr) AND on a pure
  RST/FIN abort (armed_get_absclr, a single SALU that reads armed and clears it when
  not_abort==0 — no extra register access). A payload-bearing abort clears via the response path.
- **FIX 4 true occupancy** — binary `flow_has_held_ack` (set at hold, getclr at response/exit),
  replacing the old cumulative `reg_held_count`. Occupancy returns to 0 after every txn.

## The line-484 correctness fix (why the first WIP compiled but was wrong)
The WIP computed `exp_ack = tcp.seq_no + (bit<32>)payload_len` in one ALU op; the widened-narrow add
threw `BIT_COLLISION` / "invalid container action the compiler cannot correctly interpret" (0 errors
but a wrong hardware result). Fixed by materialising a real 32-bit `exp_addend` via a SET in the
prologue (`exp_addend = (bit<32>)payload_len`), so the arm-time add is a clean 32+32. `payload_len`
stays 16-bit — its `total_len + neg_ov` overhead calc relies on 16-bit wraparound.

## Off-switch verification (PASS)
- `tests/test_hardening_fix124.py` — 12/12 PASS. Faithful Python mirror of the P4 reverse-path
  decision logic: FIN/RST/SYN/wrong-ack/dup not held; occupancy returns to 0 after completed AND
  aborted txns; the exact accumulation scenario (session-close FIN after a completed txn) NOT held;
  100 sequential txns leak no state.
- `tests/test_ack_state_machine.py` — 17/17 PASS (zero-inversion ordering invariant intact; FIX 1+2+4
  do not change ordering).

## NOT yet proven (needs a gated switch window)
Continuous-traffic hardware acceptance campaign (100+ consecutive Class-0 txns on one connection,
shuffled readiness, NO cold reload; zero retrans/reset/inversion/MAXPASS, occupancy→0, no backlog).
This is the on-hardware confirmation that the reload-dependency is gone. `phase_status.case_a_
continuous_operation` stays NOT_YET_PROVEN until that campaign passes on silicon.

## Deferred to a follow-up (per the PI scope decision)
FIX 3 (watermark fail-open ack_seen cosmetic) and FIX 5 (generation freshness, matters most at
multi-flow). 12/12 stages is at the limit — adding those will likely require the evstat→egress
write-only offload for headroom.
