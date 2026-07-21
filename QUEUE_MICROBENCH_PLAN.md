# QUEUE_MICROBENCH_PLAN.md — joint size-and-time TM microbenchmark (Phase 4)

_Master direction Phase 4 + meeting §18, revised per Dr. Lin 2026-07-21 for the **locked joint
size-and-time architecture** (`CASE_A_QUEUE_DESIGN.md`). `research/caseA-ditto-queue`. This is a
**plan**; the microbench **source + compile report + TM config + rollback + commands are built for
REVIEW**. **Nothing touches the shared switch, and the full DNP3 program is NOT modified, until those
artifacts are reviewed and explicitly authorized** (master direction §10)._

> **Two axes, both required (do NOT build a timing-only queue).** The microbench must evaluate BOTH:
> **(a)** whether the scheduler produces the required **timing** pattern; and **(b)** whether it
> preserves the required **sequence of size-labelled states**. A size-labelled queue + scheduler is
> the mechanism under test — not a bare timing shaper.

---

## 1. Objective and the decision it informs
Measure, on **our** Tofino-1 (not Ditto's, not GridCloak's replay), whether a **size-labelled TM
queue + scheduler** can, for a **low-rate (~5 Hz) DNP3-cadence** flow:
- **(b) size axis** — emit packets in the required **size-state sequence** (e.g. `S1 S2 S1 S2`),
  padding small packets to a state and pacing a split response's components in order; and
- **(a) timing axis** — release those states on a **predefined schedule / to a common target**, with
  bounded jitter, correct ordering, and no loss — independent of native device timing.

The results select the Defense-1/Defense-2 realization and the schedule/target at Phase 4.5/5.5, and
determine **whether a metronome and/or chaff is required** (see §4c). No Phase-3/4.5 selection is made
before these numbers exist.

## 2. Minimal P4 program (separate binary — NOT the DNP3 defense)
`queue_microbench.p4` in a new dir, **separate** from `dcrn_defense1/2.p4` (frozen). No DNP3 state
machine — only a **class + size-state mark** on a test field (UDP dport / DSCP / ethertype) so no DNP3
parsing is needed. It must exercise:
- **≥2 size states** (e.g. S1, S2) with **size-labelled queues** (one queue per state).
- **Padding** a small test packet up to its state's target size (compile-time-constant filler + the
  deparser — the Tofino-feasible size knob).
- A **split-sequence** emulation: a marked "large" test packet represented as a pre-partitioned
  sequence of state components, paced in order by the scheduler (on-switch live splitting is
  infeasible — `CASE_A_QUEUE_DESIGN.md` §7 — so the microbench paces pre-split components).
- **Two release mechanisms compared** (the GridCloak lesson): a **pktgen periodic metronome** clock
  vs the **TM PPS shaper** — because GridCloak measured the TM shaper **starves below ~1200 pps** (0
  dequeue at 100/200 pps) and our flow is ~5 pps. The microbench must confirm which mechanism actually
  paces a lone low-rate frame.
Reuse the GridCloak bfrt inventory (ports, pktgen `port_cfg`/`app_cfg`, mirror, TM shaper cap, the
`pipe_id=0` rule) per `GRIDCLOAK_TM_QUEUE_AUDIT.md`. Apply `tofino-p4` constraints preemptively.

## 3. Metrics (per condition)
configured vs **actual** queue/slot rate · packet **residence time** · output inter-packet timing ·
**release jitter** · queue depth/occupancy · queue counters · **packet loss** · **packet ordering**
(incl. ACK-before-response and the size-state sequence order) · **size-state conformity** (did the
emitted size sequence match the target pattern — use a drop-robust metric, e.g. the state-count ratio
+ run-length histogram, NOT strict positional equality, per GridCloak B5) · **per-packet size**
(padded to target?) · burst/drain/first-packet/sparse behaviour · background-load sensitivity ·
port/loopback/recirc bandwidth. Report mean/median/std/p50/p90/p99/worst-case.

## 4. Test matrix (the required behaviours — master direction Phase 4 + Dr. Lin)
Each cell is run against **both** release mechanisms (pktgen metronome, TM shaper) and reports both
the timing axis and the size-state-sequence axis.

**a. Sparse first-packet behaviour** — a single lone marked packet: is it released on schedule / to
the target slot, padded to its state, with bounded first-packet jitter? (The DNP3 case.)

**b. Empty vs backlogged queues** — (i) queue empty except one real frame; (ii) queue backlogged.
Does the scheduler emit the size-state on an empty queue, or does round-robin **skip the empty state**
(the Ditto/GridCloak empty-slot problem)? This is the crux for a sparse flow.

**c. Chaff / metronome requirement** — does the size-state sequence hold **without** chaff on a sparse
flow (metronome-only), or is a chaff/idle-fill needed to keep the pattern from skipping? Explicitly
determine whether a metronome alone suffices or chaff is required (informs §4-claim scope).

**d. Background-load sensitivity** — idle / low / moderate / high background (UDP on other ports);
measure delay/jitter/loss/reordering and size-state conformity under each.

**e. Release jitter** — distribution of realized-vs-target release time per state.

**f. Packet ordering** — ACK-before-response preserved; size-state sequence order preserved; split
components emitted in order; zero reordering of a held frame.

**g. Loss** — 0 drops target in the sparse DNP3 regime; report any.

**h. Comparison with the frozen recirculation baseline** — same conditions against the recirc hold
(`dcrn_defense*` mechanism): mean/median/std/percentiles/worst-case delay, load sensitivity, loss,
reordering, internal resource cost, implementation complexity. Do not declare the queue better before
this comparison is complete.

Arrival patterns: one isolated packet · 1/20 ms · 1/10 ms · 1/2 ms · small bursts · mixed sizes/states.
Background: none · low · moderate · high.

## 5. Success / decision criteria
The joint queue is viable only if, with evidence, it: **(a)** produces the target **timing** pattern
(bounded jitter, correct target/slot, no reordering) **and (b)** preserves the target **size-state
sequence** (padded to state, sequence order held, split components paced) — for a **lone sparse
frame**, under background load, with acceptable loss, and at a documented resource cost vs recirc. If
a metronome/chaff is required to hold the sequence on a sparse flow, that requirement is reported (it
changes the claim scope). If the queue cannot do **both** axes for a sparse frame, escalate per
`CASE_A_QUEUE_DESIGN.md` §5 with measured justification — do not assume.

## 6. Artifacts produced for REVIEW (the authorization gate — master direction §10)
Before requesting any switch access, deliver for explicit review:
1. **Microbench source** — `queue_microbench.p4` + control plane (bfrt/TM config) + experiment harness.
2. **Local compile report** — bf-p4c result + stage/resource summary (must fit ≤12 ingress stages).
3. **TM configuration** — exact queues, size-state mapping, shaper/pktgen settings, ports, `pipe_id`.
4. **Rollback plan** — snapshot; restore co-resident program/ports/TM/queue/loopback; stop conditions.
5. **Experiment commands** — exact host + switch commands, expected port/loopback/recirc use.
**No `bf_switchd` restart, no switch load, no full-DNP3-program change until 1–5 are authorized.**

## 7. STOP conditions (master direction §14)
scheduler cannot produce the timing pattern OR cannot hold the size-state sequence · a frame is
reordered/dropped/lost · queue occupancy grows unbounded · loopback traffic escapes · background load
changes timing unexpectedly (report, don't hide) · a requested action would displace another
experiment on the shared chip · rollback not ready. On STOP: preserve evidence first; no multi-mechanism
patching in one failed run.

## 8. Evidence (master direction §11)
raw pcaps (ingress+egress + external NIC) · parsed CSV (per-packet residence/IPG/size-state) · JSON
queue counters · compile logs · resource report · bfrt logs · switch/TM config · topology · host
commands · SDE/software versions · git commit · P4 hash · manifest + SHA-256. Separate
`raw/ processed/ figures/ logs/ manifests/`. Never modify raw evidence.

**Status: PLAN COMPLETE. Microbench artifacts (source/compile/TM/rollback/commands) to be BUILT for
review. Execution NOT_STARTED — gated on explicit authorization (`hardware_authorized` = false).**
