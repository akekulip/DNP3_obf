# PI scoping — size + timing co-residency

**Author:** principal-investigator · **Date:** 2026-08-10 · **Silicon contact:** none (analysis only)

**Inputs read:** `research/size_timing_coresidency/CHARTER.md`, `CLAUDE.md`, `RESUME_STATE.md`,
`defense4/README.md`, `defense4/RISK_REGISTER.md`, `defense4/TIMING_SPEC.md` §12,
`research/stage_reclamation/SIZE_CORESIDENCY_VARIANT_MATRIX.md`,
`research/stage_reclamation/SIZE_PRIMITIVE_REUSE_AUDIT.md` (§0–§0.1, §8b–§8e, §10–§12),
`research/ibspg_dnp3_replay/PANEL_SYNTHESIS_WAY_FORWARD.md`,
`research/inline_dnp3_size_normalization/research_design.md`,
`docs/project-memory/split-pad-timing-policy-study.md`,
`deliverables/timing_tutorial/source/tutorial_source.md`, and the committee's own baseline compile
under `research/size_timing_coresidency/evidence/scratch/baseline_caseA/`.

---

## 0. Three corrections to the charter, before the question

These change the plan, so they come first. Each is a compile artifact or a repo line, not an opinion.

### 0.1 The charter's stage budget is measured on the wrong program

`CHARTER.md:29` records "Timing core alone: **8/12 ingress** after packed state (P1); 12/12 unpacked",
sourced to `SIZE_CORESIDENCY_VARIANT_MATRIX.md`. That number belongs to the **Part-12
stage-reclamation line** (`SIZE_CORESIDENCY_VARIANT_MATRIX.md:22`, variant P1), which is a different
P4 program from the one now on the switch.

The program this committee must actually extend is `defense4_caseA` — the calibrated D4 policy
currently armed and forwarding on silicon (`RESUME_STATE.md:64-69`). This committee's own compile of
it says:

```
Number of stages in table allocation: 12
  Number of stages for ingress table allocation: 12
  Number of stages for egress table allocation: 0
```
— `evidence/scratch/baseline_caseA/build/pipe/logs/table_summary.log:2-4` (0 errors, 2 parser-unroll
warnings: `.../baseline_caseA/compile.log:4`).

**The real baseline is 12 of 12 ingress stages and 0 of 12 egress stages. There are zero free ingress
stages.** Not four. The `defense4/RISK_REGISTER.md:113-126` Gate-2B entry independently says the same
thing from the other side: the integrated core *fails* the ≤12-stage fit on register co-location, and
the root cause is "per-register access-site-count × depth-spread + per-group PHV pressure", not
register count.

### 0.2 Tagalong PHV is not the binding resource on this program

`CHARTER.md:31` names tagalong PHV as **the** binding resource at 7 of 8 collections occupied. That is
P12's number (`SIZE_CORESIDENCY_VARIANT_MATRIX.md:88-92`). On `defense4_caseA`, tagalong collections
0–3 are in use and **collections 4, 5, 6, 7 are entirely empty**
(`.../baseline_caseA/build/pipe/logs/phv_allocation_summary_0.log:498-507`; overall PHV usage 22.8 %,
line 490).

So the constraint ordering inverts. The wall is **ingress MAU stages (0 free)**; tagalong has roughly
half its capacity unused. A committee optimising for tagalong headroom would be optimising the wrong
resource.

*Caveat, and the first thing `p4-dataplane-engineer` must close:* the scratch build must be confirmed
byte-identical (sha256) to the deployed source `defense4/timing/p4/defense4_caseA.p4` and to the
loaded `/home/decps/d4_build/defense4_caseA.conf`. If it is not, every number in §0.1 and §0.2 is
provisional.

### 0.3 CRC-boundary alignment is not required for reassembly

`CHARTER.md:19` justifies mechanism (b) as cutting "only on existing DNP3 CRC block boundaries **so
the master reassembles natively**". The repo's own measured correction says the premise is stronger
than it needs to be:

> "Master reassembles ANY byte-offset split (stream-oriented link parser); **CRC-block alignment is a
> defense/auditability choice, NOT a reassembly requirement.**"
> — `docs/project-memory/split-pad-timing-policy-study.md:47-48`

This *expands* the design space rather than shrinking it: the split grid can be chosen for its
information-theoretic properties instead of being pinned to 18-byte DNP3 link blocks. Keep CRC
alignment if you want the auditability argument, but do not defend it as correctness.

---

## 1. The research question

The structural question is closed. P12 compiled a timing core and a size normaliser in one program at
8 ingress / 2 egress, 0 errors, sha `c43409c82e93` (`SIZE_CORESIDENCY_VARIANT_MATRIX.md:32,88-92`),
and `p13_size_do8` reached full corpus coverage at the same 8/2 with ingress assembly bit-identical to
P12 (`SIZE_PRIMITIVE_REUSE_AUDIT.md:593-598`). Both are refuted as *defenses*: the pad sits below IP,
so `ip.len` entropy stayed at 1.000 bits with padding ON while `frame.len` went to 0.000
(`SIZE_PRIMITIVE_REUSE_AUDIT.md:448-452`). "Can they co-reside" is answered; answering it again is not
a contribution.

**The open question, stated precisely:**

> Given a Tofino-1 pipeline whose ingress is already fully occupied (12/12) by a *silicon-demonstrated
> but lifecycle-defective* timing engine, does there exist a response-shaping transform that
> simultaneously satisfies all four of:
>
> **(Q1) Observability** — it changes a length field a passive observer actually parses (`ip.len` /
> `tcp.len` / per-transaction payload-byte totals), not one it discards
> (`SIZE_PRIMITIVE_REUSE_AUDIT.md:489-495`);
>
> **(Q2) Placement** — it costs **zero additional ingress MAU stages**, i.e. it is decided in the
> ingress parser and executed in the currently-empty egress, per the P5 result that parser-produced
> classification is free on a stage-saturated pipeline (`SIZE_PRIMITIVE_REUSE_AUDIT.md:702-709`);
>
> **(Q3) Non-re-encoding** — the shaping does not push the size information it removes into the
> *timing* observable that the same pipeline exists to normalise; and
>
> **(Q4) Separability** — its correctness does not depend on the open `tag_retire_if_unmarked`
> retirement path (`CHARTER.md:54-59`), so it can be re-verified independently after that defect is
> fixed.

Q3 is the new one. It has never been posed in this repo, because size and timing have only ever been
measured separately. It is where I expect the effort to break, and §5 says why.

**Sub-question, specific to Philip's two directed mechanisms:** do CROB-volume padding and
CRC-boundary splitting satisfy Q1–Q4? My pre-analysis says *neither does on its own*, for reasons
already on the record, and that the defensible construction is the two of them **fused into a
quantised emission grid** — see H1 and §6.

---

## 2. Hypotheses, with kill tests ordered cheapest-first

Every kill test below is offline. None touches the switch. H0 and H5 are day-one work.

### H0 — There is no ingress room, and the size axis must be parser-decided / egress-executed

**Claim.** A size axis can be added to `defense4_caseA` with **zero** additional ingress MAU stages, by
producing its classification in the ingress parser and executing it in egress.

- **Confirmed by:** `defense4_caseA` + a parser-written class tag + a bridged metadata field compiles
  at ≤12 ingress, 0 errors, with ingress table placement unchanged.
- **Killed by:** the tag alone pushes ingress placement past 12, or displaces a table. Gate-2B
  (`defense4/RISK_REGISTER.md:113-126`) makes this live: PHV group W0-15 was already at 120 % of bits
  in the integrated build, so "free in stages" does not imply "free in PHV".
- **Cheapest kill test (day 1, ~1 compile):** take `defense4/timing/p4/defense4_caseA.p4` verbatim,
  add *only* a `bit<8>` parser-assigned `pad_class` (written in the payload-consuming states and
  nowhere else — the write-once rule at `SIZE_PRIMITIVE_REUSE_AUDIT.md:582-587`) plus its bridge,
  change nothing else, run `bf-p4c`. **If that does not place, the single-pipeline goal is dead on day
  one** and the honest outcomes are (a) a bounded ingress→egress two-pass, (b) recirculation, or
  (c) NO-GO for the single-binary goal per `defense4/RISK_REGISTER.md:5` (R1).
- **Owner:** `p4-dataplane-engineer` (dispatched — this must be its *first* deliverable, ahead of any
  optimisation survey).

### H1 — A quantised emission grid closes the size channel where padding-below-IP did not

**Claim.** Emitting every DNP3 response as a fixed shape — `K` segments of exactly `c` bytes, last
padded up — drives the mutual information between the observable byte/segment pattern and the
response's true content (point count `N`, response type) to within the permutation null band.

- **Confirmed by:** `I(observed_shape; N) ≈ 0` (Miller–Madow corrected, permutation null) **and** a
  size+count classifier at chance, at a byte overhead the Pareto frontier shows is tolerable.
- **Killed by:** no knee in the frontier — closure only at `K=1, c=max`, or a heavy-tail response keeps
  anonymity `k=1`. That is pre-registered Verdict B at
  `research/inline_dnp3_size_normalization/research_design.md:186-192,254-264`.
- **Cheapest kill test (day 1–3, no P4):** the **S0 offline byte-transform smoke test** already scoped
  at `research_design.md:225-230`. Apply the grid transform in Python to `Traffic Trace/SEL751.pcap`
  and `SEL751L.pcap`, run the size/count classifier and the MI estimator at
  `K ∈ {native, 8, 4, 1}`.
- **Note:** CRC-boundary splitting *is already a grid* — DNP3 link blocks are 16 data + 2 CRC = 18 wire
  bytes, so a `b`-block chunk is 18·b bytes with a short tail. The grid exists; what is missing is a
  fixed **count** and a padded **tail**. That is the fusion in §6.

### H2 — Segmentation alone relocates the leak rather than removing it

**Claim (the null this effort must beat).** CRC-boundary splitting, unpadded, leaves a passive
observer's recovery of response size unchanged, because the sum of TCP payload lengths across the
transaction is invariant and the chunk count is proportional to size.

- **Confirmed by:** classifier accuracy and `I(features; N)` statistically indistinguishable before and
  after splitting, when features include per-transaction byte totals and segment counts.
- **Killed by (good news):** splitting materially reduces leakage even without padding — contradicting
  `docs/project-memory/split-pad-timing-policy-study.md:26-28`: *"split **preserves total bytes**
  (sum-the-chunks recovers size) and at finest granularity the chunk count = CRC-block count ∝ size, so
  split **relocates** the leak to packet count / creates a **beacon**."*
- **Cheapest kill test (day 1–2, no new code):** `dnp3_split_harness/split_server.py` already performs
  exactly this transform with a byte-identity assertion (`CLAUDE.md:120-131`). Run it over the corpus
  offline, feed both feature sets to the classifier. Hours, not days.
- **Why run it despite the prior negative:** the prior verdict was reasoned plus measured on a
  different corpus slice, and it is load-bearing for the whole design. Re-measuring on `SEL751.pcap`
  costs an afternoon and either retires the mechanism or gives the effort its baseline.

### H3 — The two axes are not independent *(the hypothesis this committee exists for)*

**Claim.** Composing a segmentation-based size axis with the deadline-release timing engine does
**not** create a new size-dependent timing signal.

- **Confirmed by:** with the size axis ON, the timing feature vector — first-byte time, last-byte time,
  inter-segment gaps, transaction duration — carries no more information about response size than with
  it OFF (MI inside the permutation null band, paired bootstrap CI containing zero).
- **Killed by:** duration or inter-segment gap structure predicts response size above chance. Both
  horns are implied by the record:
  - **Paced release** — required for a split to survive the wire
    (`split-pad-timing-policy-study.md:50-51`) — makes duration a function of segment count, hence of
    size.
  - **Unpaced release** keeps `k` frames visible to an on-wire observer (H2's count leak stands) *and*
    multiplies the timing engine's per-transaction release events from 1 to `k`, which its state
    machine and its already-defective retirement path assume is 1.
- **Cheapest kill test (day 2–4, no hardware):** simulate. Apply the split transform to the corpus,
  apply the D1/D3 release policy on top in software, emit the composed timing feature vector, run the
  MI estimator. A superset of the H1/H2 harness — one extra feature block, not a new experiment.
- **Status:** untested anywhere in this repo. Every entropy and accuracy number on file is
  single-channel.

### H4 — Inert-CROB padding is operationally admissible on the physical relay

**Claim.** There exists a set of SEL-751 DNP3 control points, provably not mapped to any physical
output contact, that can absorb padding volume safely.

- **Confirmed by:** (a) the relay's own settings/point map naming the specific unmapped points, in
  writing; (b) a written, tested no-drop / no-duplicate / no-reorder argument for the control path
  *including fail-open* (`PANEL_SYNTHESIS_WAY_FORWARD.md:104-107` — a duplicated CROB pulse is not
  idempotent); (c) master and outstation both accept the fixed-N set with zero errors; (d) **Philip
  lifting the standing safety floor in writing.**
- **Killed by:** the points cannot be named from documentary evidence; or SBO/DIRECT_OPERATE sequencing
  makes the fixed-N set unsafe under retransmission; or the floor stands.
- **The floor is real and currently prohibits this mechanism.** `CLAUDE.md:40-41` and
  `defense4/RISK_REGISTER.md:128-130`: physical SEL-751 **READ-only**, **no SELECT/OPERATE to the
  physical relay**. Mechanism (a) requires exactly that.
- **Cheapest kill test (day 1, zero risk):** documents only — read the relay configuration and the DNP3
  point map, try to name eight provably unwired points. If you cannot name them with documentary
  evidence, the mechanism is dead on the physical relay regardless of everything downstream.
- **Owner:** `power-systems-expert` (dispatched — make this its first deliverable, not its last).

### H5 — Closing size and timing measurably reduces device identification

**Claim.** A combined defense reduces a realistic adversary's ability to identify the SEL-751.

- **Already falsified on the record.** On the 3-device corpus, ACK mode and the TCP-stack fingerprint
  (TTL / MSS / initial window / options) each identify the relay at **balanced accuracy 1.000**, and
  neither axis touches either (`PANEL_SYNTHESIS_WAY_FORWARD.md:33-43`;
  `deliverables/timing_tutorial/source/tutorial_source.md:177-179`). Size sits at 0.493 against a 0.333
  chance line. Timing closure is additionally an *anonymity-set-of-one* result, because only the
  SEL-751 has a CLRT in the corpus (`tutorial_source.md:180-183`).
- **Cheapest kill test — and the single highest-information experiment in the program (one afternoon,
  existing pcaps only):** the **perfect-defense oracle**. Take all six captures
  (`Traffic Trace/{SEL751,SEL751L,AB1400,AB1400L,ION7550,ION7550L}.pcap`), replace every size feature
  and every timing feature with a constant — simulating a *flawless* size+timing defense — and run the
  multi-feature device classifier. Whatever balanced accuracy survives is the **hard ceiling on this
  program's achievable benefit**, established before a line of P4 is written. If it is 1.000, the
  device-anonymity framing is finished and the claim must be restated per-channel (§3) or TCP-stack
  normalisation must join the scope (cheap in a data plane: TTL rewrite, MSS clamp, window and
  timestamp normalisation).
- **Contradiction this also resolves:** `research_design.md:54-55` reports a size-only classifier at
  ≈0.99 driven by ~14.6 B/CROB and ~5.7 B/analog-point, while `PANEL_SYNTHESIS_WAY_FORWARD.md:38`
  reports size at 0.493. Different label sets, different feature extractions, never reconciled — and
  the number that ends up in the paper depends on which is right.

---

## 3. The claim boundary

### What a combined timing+size defense can honestly claim

1. **A placement result with a named binding resource.** "One Tofino-1 pipeline carries a silicon-proven
   DNP3 timing engine and a size/segmentation transform simultaneously; the binding resource is ingress
   MAU stages, of which the timing engine leaves zero, so the size axis is confined to parser-side
   decision and egress-side execution." Measurable, reproducible, and *stronger* than the P12 version
   because it is measured against a program that has run on silicon.
2. **A per-channel, within-device normalisation result** for whichever mechanisms actually shape — CLRT
   entropy collapse on D1/D3, and `ip.len` / segment-shape entropy collapse if H1 survives — always
   labelled as within-channel, never as device anonymity.
3. **Protocol correctness under an active shaping transform:** master reassembles natively, zero DNP3
   parse/CRC errors, zero retransmits/resets, DNP3 payload bytes preserved. A real result for an
   in-network transform on a protection-relay link, and what distinguishes this from a simulation.
4. **Two general negatives more durable than any mechanism.** The existing one — *protocol-transparent
   padding is observer-transparent padding* (`SIZE_PRIMITIVE_REUSE_AUDIT.md:465-473`) — and, if H3
   breaks, the new one: *segmentation-based size normalisation re-encodes the removed size into the
   timing channel unless the emitted shape is quantised in both the byte and the time dimension.* A
   clean cross-axis impossibility result with a mechanism and a measurement is publishable at a
   security venue on its own.

### What it will NOT claim, and must not imply

1. **"A passive observer cannot fingerprint the SEL-751."** Refuted before the work starts: ACK mode and
   TCP stack are at balanced accuracy 1.000 and both axes leave them untouched
   (`PANEL_SYNTHESIS_WAY_FORWARD.md:33-43`). The charter's goal sentence (`CHARTER.md:8-9`) is not
   achievable as literally written unless TCP-stack normalisation joins the scope.
2. **Any device-anonymity claim.** One device per profile, and the only device with a CLRT
   (`tutorial_source.md:180-183`).
3. **Anything against a DPI-capable observer.** DNP3 is cleartext, so function codes and point counts
   are read directly off the payload; size fingerprinting is strictly weaker than parsing
   (`PANEL_SYNTHESIS_WAY_FORWARD.md:90-96`). **And the reconciliation is a trap:** the threat model is
   only coherent under DNP3-over-TLS (IEC 62351-3), yet *both* directed mechanisms require cleartext —
   the switch cannot find a CRC boundary or classify a CROB inside a TLS record. Mechanism and threat
   model are mutually exclusive as framed. Both halves are on record separately
   (`split-pad-timing-policy-study.md:55-57`; `PANEL_SYNTHESIS:90-96`) and have never been reconciled.
4. **Complete Defense 4.** The timing verdict on record is **PARTIAL with an open lifecycle defect** —
   D2 does not shape, D4 is a 160/80 mixture at n=240 (`RESUME_STATE.md:52-63`, `CHARTER.md:54-59`).
   Any composed claim inherits "partial" and must say so in the abstract, not a footnote.
5. **Deployment readiness.** An inline byte-modifying device inside the electronic security perimeter is
   itself a Cyber Asset with CIP obligations, and it changes what the utility's own monitoring sees a
   frame to be (`PANEL_SYNTHESIS_WAY_FORWARD.md:98-107`). Research prototype, not deployable defense.

### What a passive adversary retains even if both axes work perfectly

TCP-stack fingerprint (TTL, MSS, initial window, options — 1.000); ACK mode, separate-vs-combined,
categorical and untouched by either primitive (1.000); poll cadence and session structure; the DNP3
payload itself in cleartext; the direction and existence of control transactions; and — if deployed on
one link — the fact that this link is defended at all, a signature no other link carries.

---

## 4. Delegation map

Already dispatched in wave 1: `p4-dataplane-engineer`, `power-systems-expert`, `sdn-networks-expert`.
**A** marks a redirection of an already-dispatched agent; **NEW** marks a missing seat.

| # | Workstream | Agent / skill | Verification check | Mode |
|---|---|---|---|---|
| W1 | **Baseline truth + zero-ingress feasibility (H0)** — hash-verify the scratch build against `defense4/timing/p4/defense4_caseA.p4` and the deployed conf; confirm 12/12/0 and tagalong 4/8; then compile baseline **plus a parser-only `pad_class` and nothing else** | `p4-dataplane-engineer` **(A — first deliverable)** | A `bf-p4c 9.13.1` log in `evidence/` showing ≤12 ingress, 0 errors, ingress table placement diffed against baseline — or the placement failure text | **PARALLEL** |
| W2 | **Relay point map (H4)** — name SEL-751 control points provably unmapped to any output contact; SBO vs DIRECT_OPERATE idempotency under retransmission | `power-systems-expert` **(A — lead with the point map)** | A named point list with a documentary citation per point, or an explicit "cannot be established from available documentation" | **PARALLEL** |
| W3 | **Adversary feature set (H5 input)** — the exact feature vector a realistic passive observer computes, and which features either axis can move | `sdn-networks-expert` **(A)** | A feature list partitioned into moved / not-moved / not-moveable, each row citing where the feature is computed | **PARALLEL** |
| W4 | **NEW — Offline leakage harness:** perfect-defense oracle (H5), split null (H2), grid frontier (H1), cross-axis composition (H3) | `research-scientist` + `statistical-analysis`; `$RESEARCH_PYTHON` | Four numbers with CIs: (i) oracle ceiling, (ii) split-vs-native leakage delta, (iii) a `(c, K)` Pareto frontier with a named knee or documented absence, (iv) MI between timing features and response size under composition. Plus a written reconciliation of 0.99 vs 0.493 | **PARALLEL — highest-value missing seat** |
| W5 | **NEW — Root-cause `tag_retire_if_unmarked`** so the size design is not built around a bug (Q4) | `bug-analyzer` + `superpowers:systematic-debugging` | A named file:line for the premature retirement, a minimal proposed fix, and which release paths a size axis may and may not hang off | **PARALLEL** |
| W6 | **NEW — Positioning** — is quantised segmentation / length-grid normalisation for cleartext ICS or TLS record lengths already published? | `literature-reviewer` + `deep-research` | A gap statement with ≥15 verified references in Zotero (no fabricated citations) | **PARALLEL** |

### Wave 2 — gated on wave 1, in this order

| # | Workstream | Agent | Gate |
|---|---|---|---|
| W7 | **Synthesis + go/no-go** — reconcile W1–W6, pick one mechanism, or declare the honest negative | `principal-investigator` | all of W1–W6 returned |
| W8 | **Adversarial pre-review of the claim boundary** (§3), before any drafting | `ieee-journal-reviewer` | W7 verdict exists |
| W9 | **Architecture + gated build plan** for the surviving mechanism | `architect` then `dev-planner` | H0 confirmed **and** (H1 or H2) confirmed **and** H3 not fatally broken |
| W10 | **Paper framing** — the negatives are contributions, not caveats | `systems-paper-writing`; `ieee-paper-figures` | W8 clean |

**Do not spawn yet:** `rebuttal-writer`, `journal-adapt`, figure work beyond W4's exploratory plots.

**Parallelism note.** W1–W6 are fully independent and should run concurrently. W4 can change the entire
program's direction and is currently unstaffed; if only one seat is added, add that one.

---

## 5. The biggest risk nobody has named

**Segmentation-based size normalisation re-encodes the size it removes into the timing channel — and
the two axes have never once been measured together.**

Every efficacy number in this repository is single-channel. The timing side reports CLRT entropy
2.73 → 0.00 bits (`tutorial_source.md:175-176`) and CLRT sd 1.85 ms → 0.0068 ms
(`PANEL_SYNTHESIS_WAY_FORWARD.md:65-66`). The size side reports `frame.len` 1.000 → 0.000 bits with
`ip.len` unmoved (`SIZE_PRIMITIVE_REUSE_AUDIT.md:448-452`). Not one measurement in the tree evaluates a
feature vector containing both. The charter treats "co-residency" as a placement property — will they
fit in one chip — and it is not. It is an **observational** property: do they interfere in the
adversary's feature space.

They plausibly do, and both horns are closed:

- **Pace the segments** — what makes a split survive the wire
  (`split-pad-timing-policy-study.md:50-51`) — and the transaction's duration and inter-segment gaps
  become a function of the segment count, which is a function of response size. The timing engine
  flattens CLRT to a single value and the size mechanism writes size back into the time domain one
  layer up. The defense would normalise a channel and re-fill it in the same pass.
- **Do not pace them** and the segment count is nakedly visible to an on-wire observer (H2's leak
  stands), *and* the timing engine now has `k` release events per transaction where its state machine,
  its deadline, and its already-defective retirement path all assume exactly one. Most likely outcome:
  the 33 % `RESP_BYPASS` mixture (`RESUME_STATE.md:52-58`) gets worse, and the failure is discovered on
  silicon rather than in analysis.

Why nobody caught it: the two lines were developed in different directories by different reviewers
under an explicit priority ordering that deferred size until timing passed
(`defense4/README.md:17-25`). That ordering was correct for building. It is exactly wrong for
*evaluating*, because it guarantees the first joint measurement happens after both mechanisms are
built.

**It is also the cheapest thing on this list to test.** No switch, no P4, no relay. The corpus exists,
the splitter exists, the timing policy is a dozen lines of simulation.

**Runners-up, each named in fragments but never reconciled:**

1. **Switch-originated CROB implies a bidirectional TCP splice.** If the switch generates the padding
   volume rather than the master, it must inject requests the master never sent *and* absorb the
   outstation's replies before the master sees them — a sequence-space divergence in **both**
   directions, maintained for the connection's life. Strictly harder than the one-directional
   `seq += Δ / ack −= Δ` translator that `research_design.md:118-125` already rates as the top compile
   and rig risk. It is a transparent proxy without buffers. Both independent reviewers already said
   CROB padding belongs **at the master** (`PANEL_SYNTHESIS_WAY_FORWARD.md:72-82`) — which, if
   accepted, means mechanism (a) leaves the Tofino pipeline entirely and the charter's "both in the
   same pipeline" requirement (`CHARTER.md:21`) cannot be met for it.
2. **The standing safety floor forbids mechanism (a) on the physical relay today.** `CLAUDE.md:40-41`
   and `defense4/RISK_REGISTER.md:128-130`. Philip's direction and the repo's floor are in direct
   conflict; resolve it explicitly, in writing.
3. **Mechanism and threat model are mutually exclusive** (§3, item 3): the mechanisms need cleartext,
   the threat model needs encryption.

---

## 6. The stronger framing, if the committee wants one

If H2 kills unpadded splitting and H4 kills switch-side CROB (which I expect), the salvageable
contribution is not "two mechanisms co-resident" but a single fused one:

> **Quantised response emission.** Every DNP3 response leaves the switch as exactly `K` segments of
> exactly `c` bytes, on a fixed release schedule, with the tail padded up to the grid. Segmentation
> supplies the grid; padding supplies only the remainder, so the byte overhead is bounded by one grid
> unit instead of by the corpus maximum. Because the emitted shape is constant in **both** the byte
> dimension and the time dimension, the cross-axis re-encoding of §5 cannot occur by construction — it
> is designed out rather than measured away.

This reframes splitting from "an alternative to adding bytes" (which the record says does not work)
into "the thing that makes adding bytes affordable", and puts the design into the one surviving
family — genuinely extending the length-bearing unit (`SIZE_PRIMITIVE_REUSE_AUDIT.md:489-495`) — with
the seq-translation risk ledger that comes with it (`research_design.md:268-283`). The evaluation is
then the Pareto frontier over `(c, K)` already pre-registered at `research_design.md:176-192`, and the
contribution list is: one placement result, one quantisation mechanism, two general negatives. That is
a coherent submission. "We put two things in one pipeline" is not.

---

## 7. Open questions only Philip can decide

1. **Is the safety floor lifted?** Mechanism (a) requires SELECT/OPERATE to the physical SEL-751, which
   `CLAUDE.md:40-41` and `defense4/RISK_REGISTER.md:128-130` currently forbid. Yes, no, or "only
   against a simulated outstation" — each gives a different program.
2. **Where does the padding volume come from — the switch or the master?** Switch means the
   bidirectional splice of §5.1. Master means mechanism (a) leaves the pipeline.
3. **Which adversary is the paper's?** Metadata-only / no-DPI observer (defensible, must be argued), or
   DNP3-over-TLS (coherent, but retires CRC-boundary splitting and CROB classification, since neither
   survives encryption).
4. **Does TCP-stack normalisation join the scope?** Cheap in a data plane, and the only way the
   charter's stated goal becomes reachable rather than pre-refuted at balanced accuracy 1.000.
5. **Retirement defect first, or in parallel?** Recommendation: root-cause it now (W5, parallel, cheap)
   but do not block the size analysis on the fix.
6. **Risk appetite.** Is a well-characterised negative — the cross-axis impossibility, the measured
   ceiling, and why in-network size normalisation for cleartext ICS has not been done — an acceptable
   outcome? The evidence currently points there more strongly than at Verdict A.
