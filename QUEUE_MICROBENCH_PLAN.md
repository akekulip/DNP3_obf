# QUEUE_MICROBENCH_PLAN.md — Traffic-Manager queue microbenchmark (Phase 4)

_Master direction Phase 4 + meeting §18. Produced 2026-07-21 on `research/caseA-ditto-queue`.
This is a **plan** (off-switch). **Execution is gated** on an explicit hardware-authorization
window (master direction §10). Feeds the selection deferred in `CASE_A_QUEUE_DESIGN.md` §5._

> **Purpose (meeting §18, master direction Phase 4).** Build the **smallest possible** Traffic-
> Manager queue experiment — a **separate P4 program, no DNP3 parsing** beyond a packet-class mark —
> and measure whether a TM queue gives **lower timing variance, stable delay under load, acceptable
> loss, and predictable drain** compared to the existing **recirculation** hold. **Do not integrate
> any queue mechanism into the DNP3 program until this microbenchmark is complete** (master
> direction Phase 4; meeting §18). **Do not claim the queue is better before the head-to-head
> comparison is done** (master direction Phase 4).

---

## 1. Objective and decision it informs

Answer, with measured numbers on **our** Tofino-1 silicon (not Ditto's — `ASSUMPTIONS_AND_UNKNOWNS.md`
#8, #9):
1. Can a single **shaped TM queue** hold a **lone, sparse, small** frame to a **predictable release
   slot**? With what residence time, jitter, and first-packet behaviour?
2. Is the queue's timing **more stable under background load** than the recirculation hold (whose
   drain offset is load-dependent — `ASSUMPTIONS_AND_UNKNOWNS.md` #4/#5)?
3. What is the queue's **empty-slot behaviour** without chaff (skip / idle / stall — the M6 crux)?
4. Is per-slot precision usable for **small DNP3-sized** frames (Ditto's worst rate-control regime,
   S13)?

The results select (or reject) the D1-A/B/C Defense-1 mappings and the P-A…P-E Defense-2 policies in
`CASE_A_QUEUE_DESIGN.md`. **No Phase-3 selection is made until these numbers exist.**

---

## 2. Minimal P4 program (separate binary — NOT the DNP3 defense)

- **New program** `queue_microbench.p4` in a new dir (e.g. `p4/queue_microbench/`), **separate**
  from `dcrn_defense1/2.p4` (frozen). No DNP3/TCP state machine; **only** a class mark.
- **Packet classes (meeting §18, master direction Phase 4):** `immediate`, `delayed`, and an
  **optional** `test-chaff` (built only if empty-slot handling needs it — deferred, meeting §8).
  Class set by a simple match on a test field (e.g. UDP dst port or a DSCP/EtherType mark from the
  traffic generator) so **no DNP3 parsing** is needed.
- **Queues:** `Q0 = normal` (pass-through), `Q1 = shaped/delayed` (rate-limited / slotted). Later
  (only if justified by §1.3): `Q_real` high-priority + `Q_chaff` low-priority + round-robin.
- **Control plane** sets the Q1 shaper rate / slot config and reads TM queue counters (bfrt).
- **Timestamping:** capture ingress and egress timestamps (global_tstamp / egress-bridged) to
  compute residence time; corroborate with an **external capture** on the receiving host (the
  loopback-doubling caveat from prior work — observe on the physical receive NIC, not a macvlan).

Apply the `tofino-p4` skill constraints preemptively (wide flags, one hash instance per tuple, no
32-bit gateway magnitude compares) so the microbench compiles first/second try.

---

## 3. Metrics (master direction Phase 4 — measure all)

configured queue rate · **actual** queue rate · packet residence time · output inter-packet timing ·
**jitter** · queue depth · queue counters · **packet loss** · **packet ordering** · burst behaviour ·
queue **drain** behaviour · **first-packet** behaviour · **sparse-packet** behaviour ·
**background-load sensitivity** · **packet-size sensitivity** · port/loopback use · internal
bandwidth (recirculation vs loopback consumed).

Report per condition: **mean, median, std, p50/p90/p99, worst-case** residence/delay; loss %;
reordered %; drops.

---

## 4. Test matrix

### 4.1 Offered load / arrival pattern (master direction Phase 4 conditions 1–6; meeting §18)
| # | Pattern | Purpose |
|---|---|---|
| L1 | **one isolated packet** | first-packet / lone-sparse-frame release (the DNP3 case) |
| L2 | one packet / **20 ms** | sparse periodic (near DNP3 Class-0 poll cadence) |
| L3 | one packet / **10 ms** | denser periodic |
| L4 | one packet / **2 ms** | stress the slot cadence |
| L5 | **small bursts** (e.g. 10 packets) | drain + reordering under burst |
| L6 | **mixed packet sizes** | packet-size sensitivity of the shaper (S13: worse for small) |

### 4.2 Background load (master direction Phase 4 conditions 7–10)
`B0 none · B1 low · B2 moderate · B3 high` — constant background (UDP from the traffic generator on
other ports) to probe load sensitivity and the "correct-on-average / bursts drop" behaviour (S10).

Full sweep = {L1…L6} × {B0…B3} (24 cells), plus a **long continuous** run (drift/occupancy check).

---

## 5. Head-to-head comparison vs the recirculation hold (master direction Phase 4)

Run the **same L×B matrix** against the **existing recirculation** timing path (the frozen
`dcrn_defense*` mechanism, or a recirc-only microbench mirroring it), and compare on:

**mean delay · median delay · standard deviation · percentiles · worst-case delay · load
sensitivity · packet loss · reordering · internal resource cost · implementation complexity.**

Produce `tab:queue_vs_recirc` (feeds paper §VII). **Do not declare a winner until this table is
complete** (master direction Phase 4; `PAPER_OUTLINE.md` §VII placeholder).

---

## 6. Success / decision criteria (what a "queue is better" claim requires)

The queue arm is preferred **only if** it demonstrably provides, with evidence:
- a **predictable** lone-frame release (bounded residence + low first-packet jitter),
- **lower delay variance than recirculation under B1–B3** background load,
- **acceptable loss** (target 0 drops in the sparse DNP3 regime) and **no reordering** of a held
  frame,
- **usable slot precision for small frames**, and
- an internal-resource cost (loopback/recirc bandwidth, stages) documented against the recirc arm.

If the queue cannot hold a lone sparse frame predictably, **escalate** to the 2-level priority-pair
(chaff-or-idle) hierarchy **only with measured justification** (`CASE_A_QUEUE_DESIGN.md` §1) — do not
assume it is needed.

---

## 7. Pre-GO checklist (master direction §10 — required before requesting a window)

- exact `queue_microbench.p4` **source hash** + **commit hash**;
- **local bf-p4c** compile result + **stage/resource report** (must fit ≤12 ingress stages);
- exact switch commands; expected **port + loopback** use; expected **TM/queue** config changes;
- **current-program snapshot plan** (the chip is shared — `gc-switchd`/gridcloak may own it);
- **rollback commands**; Hulk/Vision cleanup plan; **stop conditions** (below).

## 8. STOP conditions (master direction §14)
queue cannot provide the assumed scheduling behaviour · a frame is reordered/dropped/lost · queue
occupancy grows without bound · loopback traffic escapes · background load changes timing
unexpectedly (report, do not hide) · a requested action would **displace another experiment** on the
shared chip · rollback not ready. On any STOP: **preserve evidence first**, do not patch multiple
mechanisms in the same failed run.

## 9. Evidence to store (master direction §11)
raw pcaps (ingress+egress, external NIC) · parsed CSV (per-packet residence/IPG) · JSON queue
counters/telemetry · compile logs · resource report · bfrt logs · switch/TM config · topology · host
commands · SDE/software versions · git commit · P4 hash · manifest · SHA-256 manifest. Separate
`raw/ processed/ figures/ logs/ manifests/`. **Never modify raw evidence.**

## 10. Output
`QUEUE_MICROBENCH_RESULT.md` (after execution) + `tab:queue_vs_recirc`. Then revisit
`CASE_A_QUEUE_DESIGN.md` selection and `QUEUE_VS_RECIRC_EVALUATION_PLAN.md` (Phase 8).

**Status: PLAN COMPLETE. Execution NOT_STARTED — gated on a hardware window (`hardware_authorized`
= false).**
