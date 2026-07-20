# DCRN end-to-end on real hardware (switch + Hulk, Vision off) — 2026-07-20

First true request→response test of the on-switch DCRN through a real DNP3 master↔outstation,
using **only the Tofino switch + Hulk** (Vision powered off). Hulk hosts both roles in two network
namespaces; the unused **dp8 is put in MAC-near loopback** so the switch hairpins traffic and every
frame traverses DCRN's pipeline and returns to Hulk. Design validated by p4-dataplane-engineer.

## Topology (single-host loopback)
- Hulk `enp59s0f0np0` (dp9, 25G) carries both endpoints via two **VEPA macvlans** in two netns:
  master `10.0.1.10` (ns_master), outstation `10.0.2.10` (ns_out). VEPA forces same-host traffic out
  to the switch; the **dp8 MAC-near loopback** reflects it back → DCRN arms on the dp8/dir0 pass and
  holds the response on its dp9/dir1 pass, both returning to Hulk. `run_master.py --action scan-class0`
  (real pydnp3) ↔ `run_outstation.py` (real pydnp3). Capture on the physical wire (`enp59s0f0np0`).
- Two host-side fixes were required and are load-bearing:
  1. **i40e `disable-source-pruning on`** — without it the NIC drops the reflected frames (their src
     MAC is a locally-owned macvlan MAC). This was the initial "0 responses" failure.
  2. **Strip the stale `10.0.2.10` off the root NIC** (NetworkManager had auto-assigned it) — otherwise
     the root ns answered as `10.0.2.10` and masked the outstation namespace.
  (tcpdump on the macvlans captured nothing — a known macvlan quirk — so capture is on the physical NIC;
  each frame therefore appears twice, the VEPA TX + reflected-RX.)

## Results

### ✅ End-to-end works
Real DNP3 channel **OPEN**, master completed all Class-0 polls, multi-segment responses (292 B + 1263 B)
returned through the switch. Switch counters under P1_FIXED: **ARMED=12, HELD=12, RELEASED=12** — DCRN
armed each read, held each response on the dp68 recirc loop, and released it. 0 retransmissions.

### ✅ Byte-preservation PERFECT
Analyzer (`e2e_evidence/analyze.py` over the P0/P1 wire pcaps): **all 26 distinct response payloads are
byte-identical between P0_NATIVE and P1_FIXED**, including all 23 large (>100 B) DNP3 read responses.
DCRN changes only *when* the response leaves, never a byte.

### ⚠️ Timing hold works but is capped at ~2.9 ms, not the 33 ms target — root cause found
Per-response hold (time-spread of a response segment between its outstation-TX and its held return):
- **P0_NATIVE:** median **0.10 ms** (no hold — just the VEPA reflection).
- **P1_FIXED:** the first response segment is held **~2.88 ms** (consistent across polls) — a clear ~29×
  hold vs native — **but far short of the 33 ms FIXED deadline.**

**Root cause (confirmed):** `dcrn.p4` sets `ig_tm_md.ucast_egress_port = PORT_RECIRC` on the hold path
but **never sets `ig_tm_md.qid`**, so the recirc frame lands on dp68's *default* queue — not the qid-5
queue where `dcrn_setup.py` installed the `max_rate` shaper. The shaper never paces the loop, so the
frame recirculates at bare line rate (~0.70 µs/pass) and hits **`MAX_PASS=4096` in ~2.87 ms** (4096 ×
0.70 µs = 2.87 ms ≈ measured 2.88 ms) → fail-open release. This is exactly the design's flagged **Q3
(sparse-frame self-pacing)** unknown, now observed on silicon.

This confirms the feasibility verdict empirically: the ms-scale hold is the hard part on-chip. The
mechanism (arm / classify / recirc-hold / release / byte-preserve / fail-open) is proven end-to-end;
reaching the full 33 ms needs the recirc **paced**.

## Next step to reach the 33 ms hold (M2)
1. **Set `ig_tm_md.qid = QID_HOLD (5)` on both recirc-egress paths** in `dcrn.p4` so the loop uses the
   shaped queue (small P4 edit + recompile + reload).
2. Confirm the shaper actually paces a **single sparse** frame (Q3) — if a `max_rate` shaper releases a
   lone frame immediately on an empty queue, add a low-rate metronome recirc packet (design fallback).
3. Confirm **`global_tstamp` refreshes on each recirc pass** (Q1/#1) — with bare recirc capped at
   MAX_PASS we cannot yet distinguish "clock refreshes but 4096 passes < 33 ms" from "clock frozen".
   Raising `MAX_PASS` after the qid fix disambiguates.

## Follow-up: pushing for the full 33 ms hold (2026-07-20, same session)

Attempted to lift the hold from ~2.9 ms to the 33 ms target. Two P4 changes, each recompiled on 9.13.2
and reloaded on the switch, re-run through the same single-host loopback rig:

1. **qid fix — set `ig_tm_md.qid = QID_HOLD(5)` on both recirc paths.** Goal: land the loop on the shaped
   queue so the `max_rate` shaper paces it. **Result: no change — still ~2.97 ms** (MAX_PASS-limited). The
   shaper does not pace the loop even with the frame on qid5 — either its `(pg_id=17, pg_queue=5)` key does
   not map to dp68's qid5, or `max_rate` does not space a lone recirculating frame (the Q3 unknown). Kept
   the qid assignment (design-correct) but it is not what governs.

2. **Raise the fail-open cap so the deadline can govern.** `MAX_PASS 4096 → 65536 (2^16)` and widened the
   recirc counter `pass_count bit<16> → bit<32>` (needed because a large non-power-of-2 cap forces a full
   16-bit magnitude compare that blows the **Class-1 gateway** 44-bit input limit; a power-of-2 cap reduces
   to a cheap high-bits check). Compiles at **11/12 stages**. **Result: holds jumped to 42–82 ms**, with the
   aggregate **minimum at 32.95 ms ≈ the 33 ms FIXED deadline**, byte-identity still perfect (26/26).

**What this establishes on real silicon:**
- **The recirc-hold reaches the ms-scale target** — holds of 42–82 ms vs the earlier 2.9 ms cap. The
  on-switch hold mechanism genuinely operates at DCRN's timescale.
- **`global_tstamp` *does* advance on recirc** (the 32.95 ms floor = the deadline being reached), so Q1 is
  not a flat "no."
- **BUT the deadline does not govern *cleanly*.** Holds are variable (42–82 ms) and dominated by the ~82 ms
  MAX_PASS cap (65536 passes × ~1.25 µs/pass at 11 stages), not pinned at 33 ms. And only the **first
  response segment (292 B)** is held; the **second segment (1263 B) passes straight through** (0.10 ms).
  → `global_tstamp` refresh on recirc is **intermittent**, and the multi-segment response is not uniformly
  held. This is exactly the **Q1/Q2 recirc-clock unknown**, now characterized: the hold reaches 33 ms+ but
  is not a precise, per-segment 33 ms.

**Path to a clean, precise 33 ms (real M2, not a one-liner):**
- Use the **pass-count self-clock** (design fallback) instead of `global_tstamp` for the release decision —
  release after a calibrated N passes (N × per-pass ≈ 33 ms), which is immune to the intermittent timestamp
  refresh. Needs a gateway-friendly threshold (power-of-2 or an SALU compare) and a per-pass-latency
  calibration.
- And/or make the shaper actually pace the loop (verify dp68's real `pg_id`/queue; confirm `max_rate` spaces
  a lone frame or add a metronome packet) so a small paced pass-count maps to 33 ms.
- Hold **all** response segments uniformly (the multi-segment / per-flow-deadline interaction needs a look).

Net: the user's ask — "reach the full 33 ms hold" — is **reached in timescale** (holds now span the 33 ms
deadline, up from 2.9 ms) and **byte-preserving**, but **not yet a clean, deterministic 33 ms**; the precise
version is gated on the recirc-clock behaviour above. Current `dcrn.p4` carries the qid fix + `bit<32>`
pass_count + `MAX_PASS=2^16`.

## Real device replay through DCRN (2026-07-20)

Replayed the genuine device captures in `Traffic Trace/` (SEL751, AB1400, ION7550) through DCRN instead
of the synthetic pydnp3 outstation. Pipeline: `extract_payloads.py --pcap "Traffic Trace/<dev>.pcap"`
builds each device's request→response map → `split_server.py --delivery full --replay-dir payloads/<dev>`
serves the real captured responses to a live `run_master.py` (Class-0 polls), on the same single-host
dp8-loopback rig, DCRN in P1_FIXED.

**One harness change (repo + Hulk):** `run_master.py` now also clears `unsolClassMask` (`opendnp3.ClassField()`),
completing its existing "suppress automatic startup traffic" block — otherwise pydnp3 sends
ENABLE_UNSOLICITED (0x14) after startup, which a READ-only device replay can't answer and the master stalls.
(Note: the real captures also make the master send a WRITE (0x02) to clear the IIN bits baked into the
device response; split_server has no 0x02 response, so each poll cycle carries an unmatched WRITE + a ~1–2 s
timeout — harmless, just slower. Capture on the plain physical NIC, split into before/after by first-vs-last
wire occurrence of each frame.)

**Result — DCRN holds real device responses, byte-identical, before vs after the hold:**

| Device | response size | before hold (native, median) | after hold (DCRN, median) |
|---|---|---|---|
| SEL751 | 54 B | 1.46 ms | 94.1 ms (33–95) |
| AB1400 | 54 B | 1.45 ms | 94.2 ms (55–95) |
| ION7550 | 61 B | 1.44 ms | 76.5 ms (38–98) |

8 held responses per device; the response bytes are the genuine device bytes, unchanged — DCRN only delays
arrival. (The "after" spread reflects the same intermittent recirc-clock / MAX_PASS-cap behaviour as the
synthetic run.) Evidence: `p4/e2e_evidence/device_replay/{sel751,ab1400,ion7550}_{before,after}_hold.pcap`
(+ `_wire.pcap` plain captures, `ba_dev.py`, `split_ba.py`). Delivered to Philip.

## Evidence
`p4/e2e_evidence/`: `dcrn_P0_wire.pcap`, `dcrn_P1_wire.pcap` (2.9 ms cap), `dcrn_P1big_wire.pcap` (42–82 ms
holds), `analyze.py`. **Before/after-the-hold split** (`ba.py`, direction-split capture on the physical NIC
under P1_FIXED): `before_hold.pcap` = `-Q out`, the response as the outstation EMITS it → req→resp median
**0.97 ms** (native); `after_hold.pcap` = `-Q in`, the same response as it REACHES the master after the
recirc-hold → req→resp median **76.7 ms** (range 36–100 ms). Same byte-identical payloads; only the
departure time changes. Delivered to Philip.
(hold-spread + byte-identity), `hulk_setup.sh` / `hulk_run.sh`. Switch helper: `p4/dp8_loopback.py`.
Chip handled correctly: co-resident program displaced with authorization and **restored** afterward;
Hulk namespaces/macvlans torn down, NIC handed back to NetworkManager, source-pruning restored.
