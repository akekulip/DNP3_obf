# Queue-release feasibility matrix (Part F)

Scores the candidate architectures against the task's four hard constraints and the correctness/cost
dimensions, grounded in the capability audit (`TOFINO_QUEUE_RELEASE_CAPABILITY_AUDIT.md`), the silicon
refutation (`UNIFIED_QUEUE_ARCHITECTURE_RECONCILIATION.md`), and the Ditto verification
(`DITTO_QUEUE_RELEASE_RELEVANCE.md`). A candidate is selected ONLY if the required Tofino-1 primitive is
supported by evidence — not because it "sounds plausible."

The four hard constraints (all four required simultaneously):
- **[EV]** release on a data-plane event (matching response) and/or a deadline;
- **[QR]** the ORIGINAL packet remains resident in a TM queue (not spinning in the pipe);
- **[NC]** no external chaff;
- **[NF]** no controller in the packet fast path;
- **[NR]** no continuous recirculation of the original packet.

## Matrix

| # | Candidate | [EV] event/deadline release | [QR] queue-resident original | [NC] no chaff | [NF] no controller-in-fastpath | [NR] no continuous original-recirc | ACK-before-resp ordering | sparse behavior | HOL / multi-txn | cost | VERDICT |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **Data-plane-controlled queue gate** | ✗ (no DP TM write) | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | — | **INFEASIBLE** — the crux: no P4 extern / intrinsic writes TM eligibility (audit spine 1–4). The primitive does not exist. |
| 2 | **Control-plane queue gate** (`bf_tm_sched_q_enable`) | ✓ (CP flips on event) | ✓ | ✓ | **✗ (ms CPU in release path)** | ✓ | ✓ | ok | per-queue precise | high (CPU/txn) | **REJECTED** — violates no-controller-in-fastpath; ms latency, not per-packet. |
| 3 | **Static shaped queue** | ✗ (rate cap only; no deadline pop) | ✓ | ✓ | ✓ | ✓ | weak | **✗ lone packet gets burst→immediate; starves <~1200 pps** | — | low | **REFUTED on silicon** — shaper cannot pace a sparse flow (`QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md`). |
| 4 | **Priority + DWRR hierarchy** | ✗ (contention/share, not release) | ✓ | **✗ needs chaff to avoid empty-queue-skip** | ✓ | ✓ | — | ✗ | HOL per queue | med | **REFUTED** — Ditto's own reason chaff exists; empty queues are skipped. |
| 5 | **Ditto two-pass loopback, no chaff** | ✗ (schedule-driven, no event) | ✓ | attempted ✓ but **breaks** | ✓ | ✓ (fixed 2-pass) | — | ✗ empty-slot skip | — | med | **INFEASIBLE** — without chaff the round-robin skips empty states; Ditto has NO event release (`DITTO_QUEUE_RELEASE_RELEVANCE.md`). |
| 6 | **Internal pktgen release token** | partial — token can *decide*, **cannot actuate** a TM open | ✓ (if it could release) | ✓ (token consumed internally) | ✓ | ✓ | — | — | — | med | **INFEASIBLE for queue-resident** — pktgen generates NEW packets; it cannot flip `scheduling_enable` (CP-only). To release it must inject a copy (regeneration) or recirc — neither releases the queued original. |
| 7 | **Queue-resident + ONE bounded release-check pass** | ✗ (one pass can't hold variable G; can't open queue from DP) | ✓ | ✓ | ✓ | ✓ (1 pass) | — | ✗ | — | low | **INFEASIBLE** — a fixed 1-pass loopback delays by a fixed tiny amount, not a variable event/deadline; and the check cannot make the queued packet eligible (audit). |
| 8 | **Queue-resident + repeated release checks** (= DCRN recirc-hold) | **✓** event & deadline (Register / global_tstamp) | ✗ (packet is in the RECIRC pipe, not a TM queue) | ✓ | ✓ | **✗ 30000–40000 passes** | ✓ (zero-inversion, proven) | ✓ works for sparse | one-outstanding/flow | med | **WORKS but VIOLATES [QR]+[NR]** — this is the frozen `dcrn_defense1/2`; the original spins thousands of passes and is not TM-queue-resident. Explicitly excluded by the task. |
| 9 | **External proxy / SmartNIC / DPU** (comparison baseline) | ✓ (skb-EDT / `fq` earliest-departure) | ✓ (host qdisc) | ✓ | ✓ (host datapath, no switch CP) | ✓ | ✓ | ✓ | scales | new platform | **WORKS but OFF-Tofino** — the platform split the END_TO_END plan already mandates for size; satisfies the release semantics but not "on Tofino-1." |
| 10 | **Any other TF1-specific primitive** | — | — | — | — | — | — | — | — | — | **NONE FOUND** — the audit was exhaustive (all TM tables, all externs, mirror/resubmit/pktgen, TF2-only flush is a no-op on TF1). |

## Reading the matrix

- **No candidate satisfies all of [EV]+[QR]+[NC]+[NF]+[NR] on Tofino-1.** The only two that actually
  deliver correct event/deadline timing are #8 (recirc-hold) and #9 (host/DPU) — #8 breaks [QR]+[NR]
  (it recirculates the original, not TM-resident), and #9 is off-Tofino.
- The reason is singular and primitive-level: **the data plane cannot write TM scheduling** (audit spine
  1–4). Every "release a queued packet on an event" idea reduces to either a control-plane write (#2, breaks
  [NF]), injecting a new packet (#5/#6, chaff/regeneration, breaks [NC]), or recirculating the original
  (#7/#8, breaks [QR]/[NR]).
- #3/#4 additionally fail on their own: the shaper cannot pace a sparse flow (silicon-refuted) and
  round-robin skips empty queues (needs chaff).

## Selection

**No Tofino-1 candidate is selected.** The task's rule — "Select a candidate only if the required Tofino
primitive is supported by evidence" — is not met by any on-switch candidate. Per the task's explicit
instruction ("If no candidate can satisfy these criteria on Tofino-1, report that honestly. Do not weaken
the criteria merely to obtain a PASS"), the outcome is a documented negative, not a forced design.

**Consequently Part G (the microbench) does NOT proceed** — implementation is gated on Parts B–F
identifying a defensible mechanism, and none exists. The two feasible-but-constraint-relaxing options are
recorded for the human decision: (i) accept recirc-hold (#8, on-switch, break [QR]/[NR] knowingly), or
(ii) move the queue-resident deadline release to the host/SmartNIC edge (#9, the mandated platform split).
