# The RRC and BOR primitives — explanation

Two in-switch primitives run on one Tofino-1 pipe. Both are **byte-preserving** (no DNP3 field
edit, no CRC recompute) and are keyed to the SEL-751's **Case-A separate-ACK** behaviour.

## RRC — Response Recirculate + Carve (size + CLRT primitive for READ / SELECT)
**Goal:** make every eligible outstation response leave with a fixed *segmentation* and a fixed
*ACK→response latency (CLRT)*, so the device's native size/timing signature is replaced by a policy.

**Mechanism (per READ/SELECT response):**
1. The relay sends its native DNP3 response (a 49-byte application frame for the SEL, arriving
   whole or in native TCP segments) plus, in Case A, a **separate TCP ACK** first.
2. The switch **recirculates** the response through the **dp8 internal loopback scheduling
   domain** and **carves it only at existing DNP3 link-layer CRC block boundaries** into a fixed
   segment pattern — here **[28, 21]** (28+21 = 49). No byte is modified and no CRC is recomputed;
   the reassembled frame is bit-identical and passes DNP3 block-CRC + TCP checksum validation.
3. **CLRT normalisation:** the response is held on the dp8 ladder and released at a fixed deadline
   relative to the ACK, so the master-visible **CLRT = T_response − T_ACK** is a constant policy
   value (≈4 ms observed) instead of the relay's variable native CLRT (~1.2–2.1 ms, high variance).
4. **dp8 strict-priority ladder:** `qid7 ACK_BLOCK > qid6 ACK_HOLD > qid5 RESP_BLOCK > qid4
   RESP_HOLD` — reservoir/hold queues that pace the ACK and the response independently.

**Result (silicon):** native READ 1.27 ms / SELECT 2.11 ms CLRT (variable) → both **4.001 ms
(std 0.02)**; native single **[49]** segment → **[28,21]**, 1280/1280 CRC-valid, 0 source-copy escapes.

## BOR — Bounded OPERATE Release (timing primitive for the SBO OPERATE)
**Goal:** release a Select-Before-Operate **OPERATE exactly once at a secret internal delay T0+J**,
while the master-visible ACK and echo stay anchored to **T0+A and T0+R independent of J** — so a
passive observer cannot recover J or the relay's native operate latency (anti-subtraction).

**Mechanism (per SBO transaction):**
1. **SELECT prepares a BOR epoch:** the SELECT crosses into the **dp10 internal loopback domain**
   and pre-seeds the OPERATE blocker reservoir (`qid3 OP_BLOCK`), so the hold is armed before the
   OPERATE arrives (a fresh epoch, not the DNP3 generation).
2. **OPERATE arrives at T0** and is **held in `qid2 OP_HOLD`** (dp10 BOR ladder, `qid3 OP_BLOCK >
   qid2 OP_HOLD`) on a **second, independent scheduling domain** — separate from dp8 so the OPERATE
   hold cannot starve the RRC ACK/response queues.
3. At **T0+J** (J drawn from a secret bounded codebook, e.g. {2,4,6,8,10,12} ms via an in-switch
   PRNG the observer cannot predict from public fields) the switch **releases the original OPERATE
   exactly once** to the relay on **dp64**.
4. The relay's **ACK is released to the master at T0+A** and its **echo at T0+R** (echo carved to
   [28,21] by RRC), both **anchored to the original T0** — so **echo−ACK = R−A** is constant and
   **A, R are invariant to J**. Retransmissions and post-release duplicates are suppressed (spent-epoch marker).

**Result (silicon, guarded {1,3} empty-fanout decoys):** ACK@T0+A≈21 ms, echo@T0+R≈25 ms,
**echo−ACK = 4.00 ms invariant across J=2/6/12 (std 0.027)**; master-facing exactly-one OPERATE.
**Boundary:** relay-facing T0+J and release multiplicity were not captured (dp68 is internal); BOR
applies only to Case-A separate-ACK devices (not the Case-B ION7550).

## Why one pipe, two domains
The two ladders live on **two internal loopback ports (dp8, dp10)** — part of the switch
implementation, not inline devices — so RRC's ACK/RESP queues and BOR's OP queues arbitrate strict
priority on **separate egress schedulers**. Collapsing them onto one port cannot release the OPERATE
at T0+J (the OPERATE's own seeded ACK/RESP reservoirs would starve qid3/qid2). The whole thing fits
**one Tofino-1 pipe at 12 ingress MAU stages** via early packet-class dispatch → one meta.outcome →
one tbl_commit.
