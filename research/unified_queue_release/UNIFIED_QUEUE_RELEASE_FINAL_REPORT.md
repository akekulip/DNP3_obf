# Unified queue-release — final report

**Question:** How can a response-arrival or deadline event make the correct packet already stored in a
Tofino-1 TM queue eligible for dequeue, without a controller in the fast path, without external chaff, and
without continuously recirculating the original packet?

**Answer (evidence-grounded):** On Tofino-1 / BF-SDE 9.13.2 it **cannot**. There is no data-plane primitive
that reaches into the Traffic Manager and makes an already-enqueued packet eligible for dequeue on an event
or a deadline. The four required constraints — event/deadline release, packet queue-resident, no external
chaff, no controller in the fast path, no continuous recirculation of the original — are **jointly
unsatisfiable on this silicon**. This is a documented negative, not a weakened criterion. No microbench was
implemented, because Parts B–F identified no defensible on-switch mechanism (implementation was explicitly
gated on that).

Branch `research/unified-queue-release` off the accepted GATE-1 HEAD `8a71dc8`. Read-only research +
offline modeling only; the switch was not touched (it remains on `queue_microbench_abs.conf`).

## What Tofino-1 can and cannot do (with evidence)

**Cannot (the crux):**
- The data plane's ONLY handle into the TM is ingress `ig_intr_md_for_tm`, applied at **enqueue** (qid,
  egress port, color chosen once, before the queue). No field re-targets an already-enqueued packet.
  (`tofino1_base.p4:124`)
- Egress sees the queue **read-only, post-dequeue** (`enq_qdepth/deq_qdepth/deq_timedelta`); it runs after
  dequeue and cannot influence scheduling. (`tofino1_base.p4:220`)
- **No P4 extern** writes any TM scheduling control (exhaustive extern list). `Meter`→color only;
  `Mirror`/`Resubmit`/`Digest` inject new work, they do not release a backlog.
- Every scheduling/shaping/enable/priority/DWRR/pause control is a **CPU-only bfrt table** (`tf1.tm.*`); no
  data-plane write path exists. (capability audit, spine 1–4)
- No async dequeue notification / TM event, no move-between-queues, no wall-clock earliest-departure (EDT)
  primitive. The TF1 per-port queue flush is TF2-only (no-op on TF1).

**Can (but each breaks a constraint):**
- **Control-plane per-queue hold/release** (`bf_tm_sched_q_disable/enable`) — precise, but ms-scale CPU in
  the release path → breaks *no-controller-in-fastpath*.
- **Recirculation-hold** (frozen DCRN) — genuinely data-plane event/deadline-driven, no chaff, no
  controller, byte-preserving, zero-inversion; but the original is held by **continuously recirculating**
  (30000–40000 passes for 135–236 ms), not TM-resident → breaks *queue-resident* + *no-continuous-recirc*.
- **Shaper** — rate CAP only; cannot pace/up-pace a sparse flow (refuted on silicon: TM starves below
  ~1200 pps) and gives no per-packet deadline.
- **pktgen metronome** — can *decide* (a probe reads a Register) but cannot *actuate* a queue open; to
  release it must inject a copy (regeneration = a chaff form) or recirculate → breaks *no-chaff* /
  *no-recirc*. It is itself a chaff construct (adds only latency without chaff to fill).

## Direct answers to the required report questions

- **Can a response arrival release a buffered (TM-queue-resident) ACK?** **No** — not from the data plane;
  the release would require a control-plane write or injecting/recirculating a packet.
- **Can a deadline release a buffered (TM-queue-resident) response?** **No** — there is no EDT/earliest-
  departure primitive; the shaper only rate-caps and cannot deadline-pop, and cannot pace a sparse flow.
- **Does release require the control plane?** For a true queue-resident release, **yes** (ms-scale CPU) —
  which is a controller in the fast path.
- **Do original packets remain queue-resident in any working mechanism?** **No** on-switch — the only
  working on-switch mechanism (recirc-hold) keeps the original in the recirculation pipe, not a TM queue.
  Only a host/SmartNIC edge keeps the original queue-resident (via `fq`/EDT).
- **Is any loopback fixed-pass or repeated?** The only working on-switch hold is **repeated** recirculation
  (thousands of passes). A **fixed 1–2 pass** loopback (Ditto-style, permitted) cannot manufacture a
  variable event/deadline hold for a sparse packet.
- **Is no-chaff operation achievable?** For a **TM-queue** timing hold, **no** (round-robin skips empty
  queues → needs chaff; the metronome is a chaff construct). Recirc-hold **is** chaff-free — but it is not
  queue-resident.
- **Queue / concurrency limitations:** a FIFO TM queue cannot release a middle packet, so independent
  out-of-order transactions need one queue each; concurrency is bounded by the usable queue count (small on
  TF1). Under the tested one-outstanding-per-flow invariant a flow's hold queue holds ≤1 packet, so within
  a flow HOL is moot; hash collisions map two flows to one queue and reintroduce HOL, handled by generation
  + fail-open timeout. (HOL analysis, Part E)
- **Head-of-line limitations:** a single shared hold queue serializes all transactions to ACK-enqueue
  order; a stalled/never-completing transaction blocks all later ones — disqualifying beyond one-outstanding.
- **Compiler / resource results:** no new P4 was built for this research task (it is a capability/feasibility
  study; the microbench was correctly not implemented). The prior queue_microbench (the closest existing
  artifact) compiles 6/12 → 7/12 ingress and its silicon runs are the refutation evidence cited here.
- **Hardware results:** none run in this task (read-only audit). The load-bearing hardware evidence is prior:
  the queue_microbench silicon refutation of TM sparse-flow pacing and the GridCloak TM shaper starvation
  (<~1200 pps).
- **Unresolved architecture decisions:** (1) accept recirc-hold on-switch (relax "no continuous recirc") vs
  move the timing hold to the host/SmartNIC edge (relax "on Tofino-1"); (2) the joint size+time vs
  platform-split contradiction (C5); (3) Defense-2 deadline-scaling reconciliation (C10); (4) whether the
  SBO/CROB indistinguishability claim (which needs chaff, C7) stays in scope under a no-chaff mandate.

## Recommended next implementation step

The "unified transaction-aware normalizer with queue-resident release" is **not realizable on Tofino-1 as
specified**. Two coherent paths, for a human decision:

1. **On-switch, accept recirc-hold as the timing mechanism** (the frozen DCRN, event/deadline-driven,
   chaff-free, byte-preserving, zero-inversion — already the project's proven baseline). Treat "queue-
   resident, no-recirc" as an aspiration Tofino-1 cannot meet, and instead *characterize and bound* the
   recirc-hold's cost (recirc bandwidth, blast radius, the qid/drain calibration in C10). This keeps
   everything on the GATE-1-validated Tofino path. **Recommended if the deliverable must stay on the switch.**
2. **Platform split — put the timing (and size) hold on the trusted host/NFP edge.** The host datapath has
   exactly the missing primitive: `fq`/EDT holds a real packet queue-resident and releases it at a computed
   deadline, natively, no chaff, no controller-in-fastpath, no recirculation. The Tofino keeps its validated
   role (transaction-aware classification — the GATE-1 shadow), and the second edge does queue-resident
   timing+size. This is the platform split the END_TO_END plan already mandates for size, now extended to
   timing on the same evidence. **Recommended if a true queue-resident deadline release is required.**

Do NOT build a Tofino-1 microbench that claims queue-resident event release — the capability does not exist,
and any "PASS" would require a control-plane release, chaff, or continuous recirculation, all excluded.

## Deliverables (this branch)
`UNIFIED_QUEUE_ARCHITECTURE_RECONCILIATION.md` · `TOFINO_QUEUE_RELEASE_CAPABILITY_AUDIT.md` ·
`DITTO_QUEUE_RELEASE_RELEVANCE.md` · `UNIFIED_TRANSACTION_STATE_MACHINE.md` ·
`QUEUE_MAPPING_AND_HOL_ANALYSIS.md` · `QUEUE_RELEASE_FEASIBILITY_MATRIX.md` · this report. No hardware run;
switch on `queue_microbench_abs.conf`; frozen P4 untouched.
