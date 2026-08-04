# Agent note — Tofino-1 primitive feasibility (wave 1)

**p4-dataplane-engineer, 2026-08-04. Analysis only; two READ-ONLY offline compiles run (no frozen
file modified, no switch touched). Full budget also in agent memory
`tofino1-defense4-feasibility-budget`. Verdict: GO WITH CONSTRAINTS, split by subsystem.**

## The decomposition that decides everything

- **Size plane is FREE.** Fixed-size padding lives in EGRESS (`egress_intrinsic_metadata_t.pkt_length`
  exists; ingress has no length field). Defense-3 egress is **0/12 empty**, and the B0-15/W0-15 PHV
  exhaustion is INGRESS-only — egress PHV is a separate free allocation. N size states cost ~2–4
  EGRESS stages, ZERO ingress. **Size is not the blocker.**
- **Ingress is the blocker.** All stateful logic (two deadline compares = D3-ACK + D2-response, D1
  event reg, two blocker arm/terminate chains, the SBO 2nd key, the slot bitmap) is ingress/pipe-0.
  D3 is 10/12 dependency-bound (CP=10), only 2 free dependency levels, W0-15 exhausted (a new 32-bit
  SALU pair must go to W32-47, 14 free). Bounded estimate 10(D3) + 1(D2 resp deadline) + 1–2(SBO) ≈
  **11–12 stages — a coin-flip at the ceiling.**

## Fresh compiles this session (bf-p4c 9.13.1, `/home/philip/bf-sde-9.13.1`)

- **D3 shipped**: 10 ingress / 0 egress / **CP 10** / 76 tables — dependency-bound (reconfirmed).
- **Frozen D2 pktgen core** (read-only compile): 10 ing / 0 egr / **CP 8** / 70 tables; per-stage
  [9,2,3,2,5,16,13,4,10,6] — st5 saturated(16)/st6=13 → the middle is CAPACITY-limited, tail
  st8=10/st9=6 = telemetry. **Stripped-D2 core ≈ 7–8 ingress** (CP floor 8; strip telemetry tail +
  size microbench + A/B toggles; keep deadline/hold/expiry/fail-open/match/cleanup/gen-isolation/
  light counters). This is the WP-E resource baseline.

## The ONE decisive compile (run before any Defense-4 build)

Unified release-engine SKELETON, non-frozen, OFFLINE: D3 ingress core + D2 response-deadline compare
(T_R = A_ref + G) + mode-select over existing `tbl_params` + SBO SELECT↔OPERATE 2nd bidirectional key
(flow+phase, NOT app_seq) + slot bitmap. EXCLUDE the size plane (separable, egress-proven) and ALL
telemetry. **Rule: ≤12 ingress → GO; >12 → drop a mode / egress-bridge the SBO key / accept 2-pass.**

## Queue + topology (proven-adjacent)

- **4-queue** `Q_ACK_BLK>Q_ACK_HOLD>Q_RESP_BLK>Q_RESP_HOLD` = 4-level extension of the silicon-proven
  3-level Part-11 strict priority; max_priority is 3-bit (8 levels), 8 q/port — TM side free. The 4th
  level gives the RESPONSE its OWN independently-terminable blocker so it releases on A_ref+G (D2)
  regardless of the ACK's D3 deadline. Cost is the dual-blocker CONTROL in ingress, not the queues.
- **Queues are PER-PORT** (`pg_queue = pg_port*8 + qid`): reverse 4 queues on the master port, forward
  ≤3 on the outstation port. The "8 shared queues on one port" fear is unfounded; the forward gate is
  a single-blocker D3-style gate, not the 4-queue.
- **Two-edge one-switch:** the observable link MUST be a PHYSICAL front-panel DAC (dp10 FP15/2 ⇄ dp65
  FP33/1, both pipe-0, both free), **not** internal recirculation (recirc is invisible to the observer
  → would invalidate the observer model). The physical cable is the free encode→decode pass
  transition; discriminate the pass by `ingress_port`; both passes are pipe-0 so they share the
  generation/slot register (required for the decoder to recognise filler). Cost: 2 extra FP ports + 1
  DAC; the observer taps the loop cable.
- **Encap = PREPEND only** (deparser emits headers then the residual; DNP3-over-TCP is
  self-delimiting) — GridCloak-proven. Decode `setInvalid` the outer → inner bit-identical by
  construction, no inner-checksum recompute.

## What must NOT be claimed

No Defense 4 exists yet (no real physical SELECT→OPERATE SBO corpus; no combined program). No
live-DNP3 size normalization (Level-1 was synthetic pad-only, 128 B). No combined ingress-stage total
until the decisive compile. No arbitrary cellization/reassembly (infeasible-under-named-limit for v1).
SBO linkage needs a 2nd key — app_seq alone insufficient.
