# RESUME — Case A DEFENSE 3, predetermined ACK-delay release

**Authority: `/home/philip/Projects/DNP3/meeting_direction.md`.** It governs. Nothing in this file
overrides it; where they differ, the direction wins.

State saved 2026-07-29. Branch `research/case-a-defense3-fixed-ack-delay` @ `7ab443a`.
**Switch restored to Defense 2 and verified on all five facts.**

---

## THE NEXT ACTION

Resolve **F01-a** (the K=64 reservoir never fires), then re-run Gate 2. Read
`evidence/defense3/failures/F01_gate2_no_blockers/CORRECTION.md` **before**
`DIAGNOSIS_PROGRESS.md` — the latter's hypothesis is superseded and wrong.

```bash
# load (destructive; displaces Defense 2)
ssh decps@10.10.54.81 'sudo /home/decps/d3/swap_to_d3_synth.sh'
cd research/case_a_defense3 && ./run/run_defense3.sh --gate2
# restore, always
research/case_a_read_anchored_dual_release/run/run_four_queue_oracle.sh --restore-only
```

---

## Progress against the direction's §17 completion list

| stage | state |
|---|---|
| 1 expert-panel review | **DONE** — 7 memos, `design/defense3_panel/` |
| 2 architecture synthesis | **DONE** — `CONSENSUS.md`, disagreements resolved |
| 3 stripped implementation | **DONE** — built from the stripped baseline, not the dual-release program |
| 4 compile probes | **DONE** — variants A/B/C priced; A selected |
| 5 resource optimization | **DONE** — 9/12 ingress, 0 egress, critical path 8 |
| 6 synthetic tests | **Gate 1 PASS · Gate 2 FAIL (F01) · Gates 3–4 not started** |
| 7 safety tests | not started |
| 8 physical SEL validation | not started |
| 9–13 statistics, classifier, reports, cleanup, rollback | not started |

**Completion vocabulary (§18):** designed ✅ · compiled ✅ · loaded ✅ · synthetically validated ❌ ·
physically validated ❌ · statistically evaluated ❌.

## Gate 1 — PASS (evidence stands)

Both SDEs compile identically (9 ingress / 0 egress / critical path 8, no drift); loads;
`Q_BLOCK max_priority=7 > Q_HOLD=0`; K=64 with `increment_source_port=False`; restore verified.

★ The **dp8 `$SPEED` guard fired** on the first attempt (`ABORTED_SPEED`, dp8 at 10G) — the same
silent fault that voided a prior run. Cause was a sequencing bug (a cold load has no `$PORT`
entries, so the pre-check could not tell "absent" from "present and wrong"); patched to distinguish
them. **Keep this guard.**

★ Fail-open verified on hardware as `H = B × K / rate_dp8` → B=18000, K=64, τ=1.711 µs,
H=30.802 ms — the CONSENSUS resolution of the Panel B/F conflict, replacing an inherited comment
that was ~5.8× wrong.

## Gate 2 — FAIL, three independent open faults

| id | fault | evidence |
|---|---|---|
| **F01-a** | reservoir never fires | `tag_diff = 0xC1 ≠ 0` so the clone *should* have been emitted, yet `trigger_counter = 0`. The mirror→dp68→pattern→fire path does not fire when the triggering packet is itself a dp68-originated generated packet. |
| **F01-b** | synthetic ACK rejected | `ACK_REJECT = 1` with a **live** generation, so a header conjunct fails. Prime suspect: `tcp.seq` vs `EXP_RELAY_SEQ` — the template's `seq` is fixed while `EXP_RELAY_SEQ` is seeded from the master ACK's `ack_no`. |
| **F01-c** | one-shot fired twice | `app_event.trigger_counter = 2`, 6 packets for 3 intended. **All counter tallies mix two fires.** |

Two constructions remain valid and untested (they were disqualified only by the wrong theory):
**C1** app 2's READ carries app 1's trigger pattern directly, no clone hop; **C2** timer-armed
reservoir in the synthetic build only — legitimate scoping, since request-triggered pktgen is
already proven on silicon by Defense 2 and §14 re-verifies it on the real relay. The live build
must stay request-triggered either way.

**Nothing about the mechanism is indicated by Gate 2.** Every scored quantity was downstream of a
reservoir that never existed, and the analyzer correctly refused to pass a zero hold.

## Instruments that worked — keep all three

- `D + K/rate` correction exposed the deterministic 1711.230 ns bias (raw vs corrected).
- Reservoir-standing check caught the anomaly directly (291,769,556 ns vs a <100 µs bound).
- `ACK_RELEASE_FAILOPEN = 0` ruled out the budget immediately.

## Hardware facts learned this session — do not rediscover

- **The chip has TWO pipes, not four**: `tf1.dev.device_configuration` → `num_pipes=2`,
  `sku=BFN-T10-032D`. Pipes 2/3 return `INVALID_ARGUMENT`. Every conf declares
  `pipe_scope [0,1,2,3]` (tolerated — it is a pipeline scope, not a probe) but **any control-plane
  loop over pipes 0–3 errors**. Read `num_pipes` from the device.
- `pgrep -f bf_switchd` **overcounts** (3 for one daemon) — use `pgrep -cx`.
- `usage_cells` reads 0 on dp8 queues even when packets are queued, and is writable — never build a
  verdict on it.
- `${LD_LIBRARY_PATH:-}` — an unset var under `set -u` once aborted a swap *after* stopping the old
  program.
- A swap script's `pkill` pattern must match **what is actually loaded**, not just Defense 2's conf.

## Corrections made to prior work

- **The C3 "steady-state" corpus contains a connection-cold poll** (index 0, `clrt = 21.695` = the
  sample max). D for 100% clamp is **13 ms, not 22**; latency **10.76 ms, not 19.57**. `feee51b`.
- **The "arm write did not land" diagnosis was wrong** — `CORRECTION.md`, `7ab443a`.

## Standing scope from the direction

Case A only · one active protected transaction · two queues · one deadline · K=64 · no
size/padding work · no Case B · no host or controller fast path · **D=1 ms is a null control, not a
treatment arm** · evaluation blocked within session (session drift exceeds the effect: C1/C2/C3
native-vs-native AUROC to 0.985) · count **attempted** not successful transactions · report
AUROC-vs-native beside every concealment number · never binned entropy as a headline.
