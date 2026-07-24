# Decision: accept the in-network negative, pivot to endpoint timing (2026-07-24)

## Decision (Philip)
The systematic negative result is **accepted**: on Tofino-1 there is no bounded, low-rate,
data-plane-actuated queue-resident hold of a sparse original packet (strict priority, backpressure,
and two-stage all refuted; P-SCHED proves the only true hold is control-plane only). We stop trying to
make the in-network hold work and **pivot the timing-obfuscation defense to the endpoint.**

The in-network line is preserved as scientific evidence + reusable sub-primitives (see
`IBSPG_MICROBENCH_FINAL_REPORT.md`, `TOFINO_INTERNAL_BACKPRESSURE_AUDIT.md`,
`PSCHED_MICROBENCH_RESULT.md`, and memory `tofino-dp-hold-actuation-negative`). No frozen P4 is deleted.

## Why endpoint timing is the right pivot (and the tension it resolves)
`meeting.md:158` records the project history: timing policies were first validated with **live TCP
replay and host-based packet scheduling**, then moved into the data plane *"to avoid requiring changes
to legacy industrial devices or their operating systems."* The data-plane path is now closed. The
endpoint pivot returns to the proven approach **without changing the legacy device**: a
**bump-in-the-wire endpoint** (near the outstation) that re-times the response, rather than modifying
the SEL-751 or the master. This keeps the legacy-device-untouched property that motivated the
in-network attempt, while using a mechanism that actually works.

## What already exists (proven endpoint assets — do NOT rebuild)
- **`dnp3_split_harness/split_server.py`** — an endpoint replay/split server that **already normalizes
  response timing**: records `request_received_ns` (:539), computes elapsed, `time.sleep(remaining_ms)`
  to hit a target CLRT (:573-576), then sends (:577). CRC-boundary splitting + request-aware replay,
  byte-preserving. This is endpoint timing, working.
- **`dnp3_split_harness/timing_policy.py`** — the timing policy (FIXED / target-delay mode).
- **`dnp3_split_harness/phase04_ebpf_prototype.py`** + `reports/phases/phase_04/edt_load_release_test.md`
  — the eBPF **EDT (Earliest Departure Time)** host-scheduling prototype, **proven on the wire**
  (Phase 04B DCRN edge = PASS_MEASURED). Host-OS-side; fits a host endpoint, not a hardware relay.
- Physical SEL-751 connectivity is established but blocked on relay DNP3 config (memory
  `physical-sel751-connectivity`): reachable 192.168.10.7, TCP:20000 open, but the relay FINs itself
  (~1.9ms) with 0 DNP3 exchanged until session/allowlist/single-session is configured.
- Target to match: the SEL-751 native ACK→response CLRT is a **stable cluster ~12–13 ms**
  (`meeting.md:126`); the defense normalizes response timing so a passive observer cannot fingerprint
  the device by CLRT.

## The pivot's central design question
Two endpoint forms, differing in where they sit and whether they touch a host OS:
- **(E1) Bump-in-the-wire proxy near the outstation** — a middlebox that terminates the master↔SEL
  TCP and forwards, re-timing the *live* response to a normalized CLRT. Touches neither the SEL-751
  nor the master. This is the legacy-safe endpoint and the natural target for the **physical SEL-751**.
  The `split_server` timing logic is reusable, but it is a *replay* server today — a **live forwarding
  proxy** is the new piece.
- **(E2) Host EDT scheduling** — eBPF EDT on an endpoint host (proven), for cases where an endpoint
  host exists and can run eBPF. Not applicable to the hardware relay itself.

## Proposed plan (for sign-off — gated per project convention)
1. **Consolidate the endpoint-timing baseline:** confirm `split_server.py` + `timing_policy.py`
   normalize CLRT to a configured target against the captured SEL-751 traces (offline, no rig), and
   record the residual fingerprint after normalization (reuse `attacker_eval.py` / `ack_fingerprint_eval.py`).
2. **Design the live bump-in-the-wire proxy (E1)** for the physical SEL-751: a small forwarding proxy
   that holds the response to the target CLRT, byte-preserving, one-outstanding-per-flow, fail-open.
   Compile-only / offline smoke first.
3. **Rig validation** against the physical SEL-751 once its DNP3 session config is unblocked
   (master=Vision, outstation=SEL-751), measuring normalized CLRT + residual leakage — **gated** on
   SEL involvement + explicit authorization.

## Recommendation / first concrete step
Start with **step 1 (offline consolidation of the existing endpoint timing on SEL-751 traces)** — it is
zero-risk, needs no rig/SEL, reuses proven code, and produces the baseline the live proxy must match.
Then bring the E1 proxy design for sign-off before any rig/SEL work (physical-SEL involvement is a
standing gate).

**Awaiting your steer:** confirm E1 (bump-in-the-wire proxy, legacy-safe) as the target form, and
whether to begin with step 1 offline consolidation now.
