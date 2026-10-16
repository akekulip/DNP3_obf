# C3 diagnostic plan: attributing the two STALE_BLOCKER events (2026-10-16, directive ba50eac69 section 3)

The original block `ctl_m5_stale_iso20_950_01` stays **FAIL**, unchanged. These are diagnostics on m5_10, not
qualification of any build. m7 is qualified separately.

## Question

During c2 and c3 traffic, T outcome 6 (`OUT_TOKEN_STALE`, counted by `stop_blocking_stale`, which retires a blocker
whose lane generation no longer matches) rose by 2. That happened after all 7 old READ and 4 old OPERATE **raw timer**
rejections (outcomes 24 and 23) had been counted inside c2's pause. Outcome 6 (retirement of a stale blocker) and
outcomes 23/24 (rejection of a stale raw timer token) are kept apart throughout.

## Competing explanations

- **E1, delayed old-blocker cleanup.** A blocker seeded during c1 was still circulating after the permit and was
  retired when c2 or c3 advanced the lane generation. One candidate exists: of c1's 8 READ-lane tokens, 7 were rejected
  raw, so one seeded a blocker. Outcome 6 was 0 through the quiet end.
- **E2, fresh-connection cleanup.** c2's and c3's own SBO cycles stranded their SELECT's blockers when the OPERATE
  opened the next lane generation, the per-cycle cleanup that `protocol/hw_vepa/checks.py` budgets as 2k per SBO.
  The normal three-connection m5 blocks show 4 such events.
- **E3, accounting or instrumentation error.** The outcome cells, the baselines or the window definitions are wrong,
  or a counter is read inconsistently.

Neither simulator reproduces stale-blocker retirement: the compiled model run is `model_isolation_cleanup_m5_10_01`,
and the source pipeline gave 0 events even with real SBO pacing. Attribution therefore needs silicon observation.

## Blocks (m5_10, same endpoint, margins and restore verification; stop all hardware on an unverified restore)

- **D1, isolation diagnostic:** the original config `ctl_m5_stale_iso20_950`, with the delayed old-token cohort.
- **D2, normal-traffic control:** the same workload, pacing, shaping and endpoint settings, and the same c2 20 s
  pre-READ pause and permit procedure. The **only** difference is no READ-IPG delay: the old tokens run at the normal
  IPG and drain before c2's pause ends. Its permit requires drain and unchanged authority, not old arrivals after
  readiness.

## Observation (identical in D1 and D2)

A light switch-side poller runs from before c1 to after c3. Each sample, taken about every 100 ms, reads:
- all 25 T outcome cells;
- the READ and OPERATE generator app counters;
- `p0.n_Ingress.epoch` and `p0.n_Ingress.owner`;
- `p0.n_Ingress.work.work` (generation and phase);
- `p1.t_Ingress.cur_epoch_reg`, `gen_alloc_reg` and `op_gen_alloc_reg`.

Every sample records switch `time.monotonic_ns` at start and end, so its duration is known. Every window is defined
on the switch's single clock by register values, never by comparing clocks across hosts:
- **c1 completion:** the first sample after N's epoch changes for c2's handshake (the c1 → c2 boundary).
- **c2 readiness:** the existing `quiet_before` snapshot.
- **quiet-window completion:** the last quiet poll, plus one sample after the permit.
- **c2 and c3 completion:** the epoch change for c3, and the final sample after c3.
- **Within each connection:** the READ, SELECT and OPERATE lane generations (`gen_alloc_reg`, `op_gen_alloc_reg`) mark
  exchange boundaries. A 100 ms period cannot separate a SELECT from its OPERATE, which are about 13 ms apart. No
  application pause is added between them: the endpoint makes one SELECT-and-OPERATE library call. If events
  cannot be placed relative to that pair, the report says so.

The poller is a perturbation (register reads over gRPC on the switch host). It runs identically in both blocks, and
its sample durations are reported.

## Reading the result

- Outcome-6 increments in a window that contains only c2/c3 lane generations, with the same count as in D2 → supports
  E2.
- Increments that D2 lacks, or that coincide with no fresh lane-generation change → support E1.
- Cell totals that disagree with the existing before/after snapshots, or non-monotonic values → E3.

Aggregate deltas localize an event to a window. They cannot name its blocker's generation. If the windows stay
ambiguous, attribution is reported **unresolved** with the smallest further instrumentation (a diagnostic counter of
stale-retirement by ladder generation in T, as a separately named build).

No acceptance bound is changed and nothing is rerun to obtain a result. Every diagnostic attempt is retained.
