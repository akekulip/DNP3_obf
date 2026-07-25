# Part 12 — HOLD_RESPONSE deadline branch: plan and gates

**Status: Gate 12.1 PASS (compiled, both toolchains). Gates 12.2+ not started — they require loading
this program on the switch.**

## What Part 12 tests, and why it is the point of the line

Parts 9 and 11 built the release primitive and its ordering:
- **Part 9** — a held packet is released by a *controlled data-plane drain packet*.
- **Part 11** — a held ACK is released *before* a held response, structurally, via three strict-priority levels.

Part 12 is the branch that produces the actual defensive property. The ACK is **forwarded
immediately** and its arrival stamps `t_ack`; only the **response** is held; and the release trigger
is a **data-plane deadline** `t_ack + G`. The emitted ACK→response interval therefore becomes `G` —
a fixed, policy-chosen constant, independent of the device's native interval. That is CLRT
normalization, the Formby-fingerprint-defeating goal; Part 11's ordering result is its substrate.

The distinguishing claim vs Part 9: **release here cannot be caused by any injected packet.** There
is no drain role and no drain register in this program. The only release causes are the deadline and
the fail-open budget, which is a strictly stronger isolation property than Part 9 demonstrated.

## Mechanism

The blocker becomes deadline-checking. On every loopback pass a token computes
`age = now − deadline` and self-terminates once `age ≥ 0`. When all tokens have terminated, Q_BLOCK
empties, strict priority stops starving Q_RESP, and the held response dequeues byte-identically.
Termination priority: **stale** (not armed / generation mismatch) > **deadline** > **budget**
(fail-open watchdog).

`G` is carried in the ACK's `hdr.ib.seq` field (TEST_ONLY), which makes a G sweep a pure host-side
parameter with no per-trial control-plane write. In a deployment `G` is policy and belongs in a
register or table; that substitution does not change the mechanism under test.

## Gates

Gate style mirrors Parts 9 and 11: compile → configure → negative controls → the positive result →
accuracy sweep → byte-identity on a host PCAP → isolation → repetition campaign.

| Gate | What it establishes | PASS condition |
|---|---|---|
| **12.1** | compile + resource fit | 0 errors on 9.13.1 **and** 9.13.2, ≤12 ingress stages, no drift — **PASS**, see `p4/ibspg_hold_response/ibspg_hold_response_compile_note.md` |
| 12.2 | control plane + TM config | program loads and binds; `strict_priority_verified: true` with Q_BLOCK(7) > Q_RESP(0) read back from hardware |
| 12.3 | pass-through control | with no blocker ring, an injected response egresses dp9 immediately and byte-identically (proves the harness and the forwarding path, isolating later results) |
| 12.4 | hold without a deadline | blockers running, no ACK: the response does **not** egress for the whole observation window; it is finally released only by budget exhaustion (`ctr_block_term_timeout > 0`, `ctr_block_term_deadline == 0`) |
| 12.5 | **the deadline release** | qualifying ACK arms `G`: the response is released, `ctr_block_term_deadline > 0`, and `G_observed ≈ G` |
| 12.6 | deadline accuracy sweep | G ∈ {1, 2, 5, 10, 17, 25, 40} ms; report median/min/max/p95 of `deadline_error` and of `release_tail`. 17 and 25 ms are the measured SEL-751 native CLRT p95/p99 and are the operationally interesting points |
| 12.7 | negative controls | a **stale-generation** ACK and an **unrelated-slot** ACK must NOT arm the deadline (`ctr_ack_arm == 0`, `ctr_ack_bypass ≥ 1`); the response then falls back to budget release. This is the causal control for "the deadline, and only a qualifying ACK, sets the release time" |
| 12.8 | byte-identity + isolation | host PCAP on Vision: released response byte-identical to what was injected; ACK egressed before the response; **zero** blocker tokens (ethertype 0x88C1) ever appear on dp9 or dp11 |
| 12.9 | repetition campaign | 100 reps at a fixed G: 0 premature releases, 0 byte mismatches, bounded jitter |

A gate that fails is recorded as a result, not worked around. `G_observed` is measured on-chip from
the register pair and cross-checked against the host PCAP; the two must agree.

## Constraints carried from the frozen parts

- Parts 1–11 files, `ibspg_controlled_drain.p4`, `ibspg_paired.p4` and the ring oracle are **frozen** —
  Part 12 lives entirely in `research/ibspg_hold_response/`.
- The Part 11 control-plane script (`research/ibspg_paired/control/ibspg_paired_setup.py`) is
  name-parameterized and is **reused as-is**, not forked.
- Lab facts that cost real time before and still apply: raw AF_PACKET injection needs `sudo`;
  inject from Hulk (dp11), capture released frames on **Vision** (dp9); use a neutral source MAC
  (`02:00:00:00:00:0a`) with Vision's real destination MAC to avoid i40e source-pruning; do not run
  tcpdump on the inject interface concurrently — reconstruct injected frames in the verifier instead.
- Reloading the switch with this program displaces the currently-loaded `ibspg_paired`. That is
  reversible: `sudo bash /home/decps/part11/launch_part11.sh`.

## Scope

TEST_ONLY synthetic markers, exactly as in Parts 9 and 11 — **not** real DNP3 traffic and **not** the
physical SEL-751. DNP3 integration is the next part and is gated on Part 12 passing.
