# RESUME — Case A DEFENSE 3, predetermined ACK-delay release

**Authority: `/home/philip/Projects/DNP3/meeting_direction.md`.** It governs. Nothing here
overrides it; where they differ, the direction wins.

State saved 2026-07-29. Branch `research/case-a-defense3-fixed-ack-delay`.
**Switch RESTORED to Defense 2 and verified on all five facts.**

---

## THE NEXT ACTION — the physical SEL-751 read-only smoke transaction at D = 2 ms

Everything synthetic is green and both pre-physical issues are closed. **Defense 3
(SYNTHETIC build) is currently LOADED**; do not restore Defense 2.

The smoke transaction needs the **LIVE** build, which has NEVER been on hardware:

```bash
# 1. build the LIVE artifact ON THE SWITCH (no -DD3_SYNTH_EVENTS, and NOT
#    -DD3_REPLAY_ON_HULK, because CONSENSUS 8.1's first conjunct is ingress_port ==
#    PORT_RELAY). Local 9.13.1 already confirms 9/12 ingress, 0 egress, path 8.
ssh decps@10.10.54.81 'cd /home/decps/d3 && bf-p4c ... -o build_9.13.2 \
    case_a_defense3_fixed_ack_delay.p4'
# 2. load it: /home/decps/d3/d3_abs.conf already points at build_9.13.2, and
#    swap_to_d3.sh is the loader (the synthetic loader is swap_to_d3_synth.sh)
ssh decps@10.10.54.81 'sudo /home/decps/d3/swap_to_d3.sh'
```

Then, on Vision (`10.10.54.19`, REACHABLE; the relay `192.168.10.7` is on its subnet):
one read-only DNP3 poll through the switch, D = 2 ms, no control commands.

★ Prerequisites that are NOT yet verified and must be before the poll: the relay inline
on dp64 (`PORT_RELAY`) with Vision on dp9, both links up; `reg_exp_relay_seq` /
`reg_session_port` learned from the real handshake rather than control-plane seeded (the
live build learns them in the data plane); and the keepalive guard, which the synthetic
build cannot exercise at all.

★ Live-build differences that only the physical run can exercise: the RESPONSE's
generation comes from the real DNP3 parse chain (a solicited response sets CON, so
`app_control` is `0xEn` not `0xCn` — CONSENSUS 7 R7), the ACK's `tcp.seq == EXP_RELAY_SEQ`
conjunct rejects keepalives, and byte preservation must hold on the wire.

## Progress against the direction's completion list

| stage | state |
|---|---|
| expert panel · architecture · stripped implementation · compile probes · resource optimization | **DONE** |
| **CHECK 1** inactive-marker safety | **DONE** — `evidence/defense3/CHECK1_INACTIVE_MARKER_SAFETY.md` |
| **CHECK 2** production blocker-start latency | **DONE** — `evidence/defense3/CHECK2_PRODUCTION_BLOCKER_START_LATENCY.md` |
| Gate 1 | **PASS** |
| **Gate 2** | **PASS 17/17** — `evidence/defense3/GATE2_PASS.md` |
| **Gate 3** (five transactions) | **PASS 5/5** — `evidence/defense3/GATE3_PASS_GATE4_CASE_C_FAIL.md` |
| **Gate 4 A / B** | **PASS 3/3 each** — same report |
| **Gate 4 C** (missing RESPONSE) | **FAIL 0/3** — the generation never retires; same report §4–6 |
| safety tests · §14 physical SEL validation · statistics · classifier · reports | not started |

**Completion vocabulary (§18):** designed ✅ · compiled ✅ · loaded ✅ ·
**synthetically validated ✅ (one transaction)** · physically validated ❌ ·
statistically evaluated ❌.

## The headline result

`hold = 2 001 505 ns` = `D (1 999 763, quantized) + drain (1 692) + tail (27) + detect (23)`.
The R5 `K/rate = 1 711 ns` bias is no longer a model justified by the residual it removes —
the **drain is measured directly** and agrees to 19 ns (1.1%). Corrected deadline error
**−78 ns** against a ±1 000 ns bound. Reservoir standing 678 ns; READ→ACK 500 010 ns.

## Hardware facts learned — do not rediscover

- **The generator withholds a triggered app's batch until the in-progress app's whole RUN
  ends**, and the wait equals the run SPAN. Measured at four points (1×3 @ipg 200k → 400 011;
  1×3 @ipg 500k → 1 000 012; 2×1 @ibg 500k → 500 010; 3×1 @ibg 200k → 400 012). It is the
  RUN, not the batch.
- **A recirculation-pattern app's packets cannot be told apart**: `packet_id` decodes as the
  same value for every packet, so per-packet roles collapse onto one entry. Proven for
  **timer** apps. Defense 2 never exposed this — it only `advance()`s over the header.
- **Two apps on one trigger are served events-first** (app 3 before app 1); the order is not
  controllable from the control plane.
- **Two separate `app_enable` writes skew ~1.15 ms.** One `entry_mod` with both keys collapses
  it to ~10 ns of realised offset error.
- **Production trigger chain:** READ→clone 688 ns, clone→first blocker 11 ns, READ→full
  64-token reservoir 1 215 ns, spread 4 ns over 100 trials, no warm-up cost.
- The chip has **TWO pipes** (`num_pipes=2`, `BFN-T10-032D`); any control-plane loop over
  pipes 0–3 errors. `pgrep -f bf_switchd` overcounts — use `pgrep -cx`. `usage_cells` reads 0
  on dp8 and is writable — never build a verdict on it.

## Corrections made to prior work

- **`TAG_NO_WRITE` collided with the new `TAG_INACTIVE = 0`**, so both transaction-retire
  paths were silent no-ops. Found by CHECK 1 before it ran. Now `0x01`.
- **The trigger clone was counted as `BAD_PORT`**, making G-10's isolation clause
  unsatisfiable whenever the defense armed. Now `CF_CLONE_SEEN` + `ROLE_CLONE`.
- **The analyzer's G-10 hard-coded `0xFF`** and could never pass after the F02 repair.
- **The F02 mechanism claim is narrowed:** bf-p4c emits `equ lo, lo, -K` for *every* K with
  no warning (`p4/probe_salu_immediate.p4`, 13 constants), so the `.bfa` cannot distinguish a
  safe constant from an unsafe one. The repair is confirmed behaviourally on silicon; "the
  immediate field is too narrow" is an inference. The durable rule is structural and is now
  enforced by a test: **never compare SALU state against a large constant.**
- **The C3 "steady-state" corpus contains a connection-cold poll.** D for a 100% clamp is
  **13 ms, not 22**; latency **10.76 ms, not 19.57**.

## Standing scope from the direction

Case A only · one active protected transaction · two queues · one deadline · K=64 · no
size/padding work · no Case B · no host or controller fast path · **D=1 ms is a null control,
not a treatment arm** · evaluation blocked within session (session drift exceeds the effect:
C1/C2/C3 native-vs-native AUROC to 0.985) · count **attempted** not successful transactions ·
report AUROC-vs-native beside every concealment number · never binned entropy as a headline.
