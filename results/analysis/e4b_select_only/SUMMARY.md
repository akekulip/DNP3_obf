# E4b: SELECT without OPERATE on the physical SEL-751 (c72, 2026-10-29)

Plan step 5; design registered before traffic in `DESIGN.json`. Evidence: the c72 build (source SHA-256
`97812585…`), campaign `rc01_hw_c72_e4b_20261029_01`, block `e4b_select_only_d20_combined`.

**Run.** Qualification block 10 without its loss preset, D = 20 ms, timing+size (T = 1, padding = 1). Six cold
connections, each with 20 READs (full schedule, integrity class), the first four followed by a guarded SELECT on
points 1 and 3 that is never operated (`traffic.sbo_select_only`). The campaign ran under its own freeze, after a
dry-run of the exact command. Block rc 0; restoration verified.

| Observable | Result |
|---|---|
| Trials whose master workload and recorded verdict pass | 6/6 |
| SELECTs answered CROB SUCCESS on points 1 and 3 (decoded from the captured bytes) | 24/24 |
| OPERATE requests in the master records or the captured master stream | 0 |
| READ sent right after an abandoned SELECT, answered OK | 24/24 |
| All READs answered OK | 120/120 |
| READ responses equal to the integrity class image (158 octets) | 120/120 (24/24 right after a SELECT) |
| TCP retransmissions, master to relay and relay to master | 0 and 0 |

CLRT of the 24 READs right after an abandoned SELECT: median 19.66 ms, range 18.27–21.73 ms, at D = 20 ms.

**Reading.** On the relay, an abandoned SELECT with timing enabled leaves the connection working:
- the next READ is forwarded, answered, padded to its class image and released by the timing hold like any other
  READ;
- the switch checks of the recorded verdict (counters and loop-port gaps) pass.

This matches the model scenario E4 (`results/models/c72_e4_abandon_t1/`, 14/14), in which the READ after the SELECT,
an RST and a new SYN are forwarded and N's work state is free after every step.

**Limits.** Six trials are a bounded diagnostic. The switch checks see counters, not T/N register state, and they
cannot read the relay's selection state. That a later SELECT succeeds shows the relay accepted it, not that the
earlier selection was cancelled.

Files: the campaign's per-trial records under
`results/hardware/blocks/rc01_hw_c72_e4b_20261029_01_e4b_select_only_d20_combined/`, and `runs/<campaign>/`
(prepare, freeze, dry-run and init logs).
