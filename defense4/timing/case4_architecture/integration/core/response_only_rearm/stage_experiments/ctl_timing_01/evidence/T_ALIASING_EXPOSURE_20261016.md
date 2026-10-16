# Exposure of earlier measurements to T's 32-bit readiness aliasing (directive ba50eac69, C1; 2026-10-16)

Every T build before ctl_timing m7 compares 32-bit nanosecond values by the sign of now − D − t0
(`model_contention_m6_07_01/TRACE_sweep_SELECT_000ms.md`).
- **Not ready:** a held packet whose anchor is older than D + 2^31 ns reads as "not ready".
- **Fresh:** past 2^32 ns (4.29 s), the anchor aliases to a fresh exchange.
- **Anchor:** T's anchor `t0_reg` is a single register written by each admitted REQUEST, so an anchor's age is the
  time since the latest admitted request on any connection.

This note assesses which retained measurements could be affected. It changes none of them.

**Measured exchanges: not exposed.** The scan covered all 94 directories under
`seg61_02/evidence/hw_campaigns`; 72 of them carry exchange timing. Across those, the largest per-exchange
`rt_us`/`clrt_us` is 218,415 µs, so no measured exchange was resolved anywhere near readiness + 2^31 ns (silicon
readiness 12 ms, so about 2.16 s). The m5 and earlier qualification, characterization, recovery and piggyback results
were therefore not decided in the aliasing region. The index-127 tail (about 1 ms) is unrelated.

**Stale-token isolation runs: exposed by design. Effect not yet assessed.** The runs are `candidate61_stale_tokens_950_01`
and `_02`, `ctl_m4_stale_tokens_950_01` and `ctl_m5_stale_iso20_950_01`. They keep old blockers and tokens
circulating through c2's 10–20 s pre-READ pause, and T judges those against an anchor that by then is seconds old.
Whether aliasing changed when they were rejected is open. It is one hypothesis for the two unattributed STALE_BLOCKER
events in `ctl_m5_stale_iso20_950_01`, to be tested in C3 by trace, not assumed.

**Model runs.** The m6_07 contention failure is the documented instance. Other model runs used readiness 2 s with
exchanges far shorter, except where the driver or host stalled; retained model logs carry global timestamps if a run
needs checking.
