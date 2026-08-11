# Joint DNP3 Timing + Size Obfuscation — Design & Decision (v2)

**Supersedes** `JOINT_DEFENSE_SPEC.md` (v1), which is retained only as a feasibility-probe record.
v1 is not a correct joint defense: it embeds the wrong (incomplete) timing core, its size step
(G30 V1→V3) deletes analog quality flags, its claims overstate cross-device equality, and its
scripts do not reproduce from a clean clone. This document is the corrected design and the decision.

Grounded in a three-lens expert review (DNP3 semantics, Tofino feasibility, measurement/evaluation)
plus the repo's own leakage oracles. An adversarial venue-standard review is pending and will refine
§7 and §9.

---

## 0. Decision (the actionable verdict)

1. **Reframe the goal.** "Timing + size prevents device fingerprinting" is **false** and is dropped.
   The repo's own `m1_oracle` shows a *perfect* size+timing defense leaves device balanced-accuracy
   at **1.000** — device identity lives in the static TCP/IP **stack fingerprint** `(TTL,
   data_offset)`, which is the **handshake** axis. The system is a **three-axis composed defense**,
   each axis with an explicit observer and an explicit, separate claim.
2. **Adopt cover-frame *prepend* as the size primitive.** It is the only candidate that preserves
   operational semantics (real frame byte-for-byte untouched, never reaches the application layer).
   **Reject** V1→V3 canonicalization (deletes quality flags) and response-side decoy-CROB insertion
   (reaches the app layer; strippable *and* not obviously side-effect-free).
3. **Scope the size claim to a byte-counting observer.** A DNP3-parsing observer strips the cover
   frame to *exactly zero* size benefit by theorem. This is stated as a first-class limitation, not
   buried.
4. **Build the joint program on the corrected `defense4_caseA.p4`**, not the 566-line probe. Cover
   framing + the complete per-connection transport epoch go in **egress, executed at release**;
   Case-A is single-slot, so the transport state is ~5–6 single-entry registers, not a hash table.
5. **Select the policy `(S_req, S_resp, D_A, D_R)` from measured data**, not constants. `S` = the
   smallest legal reachable common size ≤ MSS covering the *measured* native-size support; `D` = an
   upper quantile of the *measured* native CLRT/ACK distribution.
6. **Do not claim device anonymity.** Anonymity set is k=1 behind one relay.
7. **Gate on three cheap pre-build tests** (§9) before any P4 authoring or hardware: the DNP3
   endpoint-discard test, the reproducibility fix, and a real response-size distribution measurement.

**One input is genuinely yours (§10): is the deployed adversary byte-counting or DNP3-parsing?**
The recommended posture is robust either way — report both observers, lead the size result with the
counting observer, and state the parsing-observer strip explicitly.

---

## 1. Why the change (the three-lens findings)

| Finding | Source | Consequence |
|---|---|---|
| A perfect size+timing defense leaves device BA = **1.000**; identity is `(TTL, data_offset)` | eval (`m1_oracle`) | Device fingerprinting is the **handshake** axis, not size/timing |
| A DNP3-parsing observer strips cover framing to **zero** size benefit (runs the endpoint's own address filter) | DNP3 + eval (theorem) | Size axis is scoped to a **byte-counting** observer |
| Wrong-address CRC-valid cover frame is silently discarded by stock master + outstation, no wire reply (IEEE 1815: no "wrong address" NACK) | DNP3 semantics | Cover framing is **DNP3-legal and safe** — testable in software |
| Cover-frame *prepend* is buildable on one Tofino-1, cheaper than decoy insertion; morph in egress **at release** satisfies "size before timing" observationally | Tofino | Axis 3 is **feasible**; ingress-morph is hazardous |
| Reachability is a theorem; target **71 drops the ION7550 tail** → real common target **183 B**, ≤2 frames | eval | Policy must cover the **measured support**, not a subset |
| V1→V3 deletes quality flags; oracle never checks the deleted status | code audit | **Rejected** as a defense |
| Six scripts hardcode `/home/philip`; the reachability oracle is not committed | eval | **Not reproducible** from a clone |

---

## 2. Threat model & observers

**Deployment.** `master —[observed WAN]— [Tofino-1 switch] — outstation`. The passive observer sits on
the WAN, **before** the switch. Stock endpoints unless cooperation is explicitly declared. Physical
relay stays READ-only.

**Two observers (claims are made per observer):**
- **O_count** — byte-counting / non-reassembling. Sees per-packet sizes, segment counts, timing.
  Does **not** parse DNP3 or reassemble the stream. *The only observer the size axis defeats.*
- **O_parse** — reassembling DNP3 parser. Reads each self-delimiting link frame's `LEN`, discards the
  wrong-address cover, recovers the real size in one subtraction. *Size benefit = 0 by theorem.*

**Two secrets (kept separate):**
- **Device / configuration identity `D`** — which unit / firmware / config.
- **Activity `A`** — control-vs-read, CROB count, event-backlog / SOE depth ("what the operator did").

---

## 3. The three-axis design

### Axis 1 — Handshake normalizer → **device identity**
The load-bearing axis for anti-fingerprinting. Rewrites the TCP handshake so `(TTL, data_offset,
options, MSS, window)` are device-independent. Already built and silicon-byte-identical. **This is the
only axis that attacks device `D`.** Residual it cannot close: application-layer object *structure*
(G30 V1 vs V3 variation, qualifier/index, quality-flag presence) — closeable only by endpoint
reconfiguration to a common flag-carrying variation (partial, operationally heavy), never by the
switch on stock endpoints.

### Axis 2 — Timing (corrected Case-A) → **CLRT / activity magnitude**
The strongest standalone result. The corrected `defense4_caseA.p4` holds ACK and RESPONSE and releases
on public deadlines `T_A = t_A + D_A`, `T_RESP = T_A + D_R`, giving a constant observed CLRT
independent of native timing. Silicon-validated on the physical SEL-751 (1,200 transactions; 0 bypass).
Deadlines from measured native CLRT quantiles (§5). Belongs to `defense4_caseA.p4`, **not** the probe.

### Axis 3 — Size (cover-frame prepend) → **response-size / activity vs O_count**
Normalize observable response byte-size **upward** by prepending one CRC-valid DNP3 **link** frame
addressed to a **reserved, unused individual** link address, in the same TCP stream, before the real
(unchanged) response. The endpoint silently discards it; the real frame is delivered byte-for-byte.

- **Address discipline:** unused *individual* address (never `0`/`1`, never reserved `0xFFF0–FFFB`,
  never self `0xFFFC`, never broadcast `0xFFFD/E/F`). Registered as a deployment parameter.
- **Function discipline:** UNCONFIRMED_USER_DATA (func 4), non-FCB → inert, reply-less even if
  misrouted. Never RESET_LINK (0) / REQUEST_LINK_STATUS (9).
- **Injection selection:** only onto segments already carrying a real DNP3 application PDU. Never onto
  pure-ACK / TCP-keepalive / zero-payload / link-keepalive / broadcast time-sync segments.
- **Semantics:** deletes nothing, never reaches the app layer, does not toggle FCB, adds no CONFIRM.
- **Cost vs decoy insertion:** constant CRCs (no CRC ALU), constant-per-class Δ (no runtime-carry
  ICE), tagalong-resident bytes (no normal-PHV blowup). Strictly cheaper.

---

## 4. Integrated Tofino-1 pipeline

**Ingress — frozen corrected `defense4_caseA.p4`:** role classification (SELECT/OPERATE/READ →
responses are func 0x81 = ROLE_RESP), four-queue hold/release ladder, K-token reservoir, per-flow
identity. Not modified. Case-A holds the *original* frame and releases the *same* frame on a
size-independent (deadline/event) schedule.

**Egress, executed AT RELEASE — the morph + transport epoch (new):**
1. **Morph pass:** prepend the cover link frame(s) to reach the target `S` (compute link + block CRCs
   on-chip — constant per class; set `LEN`; address to the reserved addr). *At release* means the
   observer sees the morphed frame at the scheduled instant → "size before timing" is satisfied
   **observationally** without physically morphing in ingress (which is hazardous: the held frame
   recirculates un-morphed and the parser re-derives its role each loopback pass).
2. **Complete per-connection transport epoch** (Case-A is single-slot → ~5–6 single-entry registers,
   **not** a collision-prone hash table — the 1024-entry index was a *probe* defect):
   - Separate cumulative offsets per direction `Δ_req`, `Δ_resp`.
   - **Owner tag + generation** validated on every packet (no bare-hash collisions).
   - **Insertion-boundary ledger** so a retransmit of a pre-insertion segment gets the correct delta.
   - **Valid bit** for the first response sequence.
   - Translate **every** later packet (CONFIRMs, later requests) — never fail-open pass-through
     mid-flow — through **clean teardown** (correct FIN/RST/SYN).
   - **Safe degradation:** on pressure, stop *new* padding but keep transport translation; never
     revert to untranslated pass-through.
3. **Checksum/length:** recompute IP/TCP length + checksum wholesale over the final bytes (Δ never
   enters the arithmetic) — or incremental if the tagalong wall bites.

**Co-residency (Tofino verdict):** feasible for the single-frame prepend. Two walls, each "one compile
away": egress serial depth against Case-A's LTID tail (fixed by bridging the flow identity Case-A
already computes) and tagalong under the wholesale checksum (fallback: incremental checksum / fewer
classes). **Does not fit on one chip:** splitting or *separate* cover packets — anything multi-frame.
Honest fallback there is a **second cooperating decap edge**, not recirculation (recirc shares
Case-A's binding capacity).

---

## 5. Reachability & measured-data policy

**Reachability theorem.** A cover link frame of `k` user bytes has wire length
`L(k) = 10 + k + 2·⌈k/16⌉`, `k ∈ [0,250]`. By prepending ≥0 frames, the achievable positive size
deltas are exactly `{10} ∪ {13,14,15,…}`; the **only unreachable** deltas are a native's
`+1..+9, +11, +12`. Every target ≥ native+13 is reachable in **≤2 frames**.

**Size targets.** `S = ` smallest legal reachable common target that covers the **measured native-size
support** of that direction, **capped at MSS** (to stay single-segment; above MSS a segment-count
observable reappears). For this corpus the full observed response support is `{37,54,61,74,122,183}` →
`S_resp = 183 B` (the preliminary "71" covers only `{37,54,61}` and silently drops the tail). `S_req`
covers the request support similarly. **Overhead** must be reported as realized (target 71 over
`{37,54,61}` = 50.3% mean; over-padding is expensive — measure on the real polling profile including
integrity polls and large READs, which the sparse capture lacks).

**Timing deadlines — the answer to "why 10 ms?"** `D_R = Q_p(native CLRT) + guard`. On the **physical
relay**, native CLRT median 2.92 ms, p5–p95 spread 5.69 ms; **10 ms ≈ p99 + guard**, giving near-total
tail coverage, ~7 ms added median latency, far under the master's 2 s response timeout and the ~1 s
poll interval. **Defensible — and re-derived per deployment** (the lab corpus median is 12.21 ms,
where 10 ms would not dominate).

**Optimization.**
```
minimize  L_resid(policy)                         # residual activity/size leakage vs O_count
over      (S_req, S_resp, D_A, D_R)
s.t.  S ∈ reachable common targets over measured support     (reachability theorem)
      S ≤ MSS(data_offset)                                    (single-segment; else count leak)
      P(native_CLRT ≤ D_R) ≥ 1−α,  P(native_ACK ≤ D_A) ≥ 1−α (tail coverage, α≈1e-3)
      D_A + D_R < 2 s   (master response timeout)  and  < ~1 s (poll interval)
      K_blockers ≥ hold-continuity floor at the deadline
      mean added bytes ≤ B_budget,  added latency ≤ Λ_budget
```
Device-ID BA cannot be the objective (it is an unmovable constant); `L_resid` is activity/size
leakage to O_count, with device-ID reported as a constant.

---

## 6. Honest claim boundary (per observer × secret)

| | **O_count** (byte-counting) | **O_parse** (reassembling parser) |
|---|---|---|
| **Device `D`** | Not reduced by size/timing (BA≈1.0); **Axis 1 (handshake)** is what reduces it; residual structure leak remains | Same; structure leak fully visible (DPI device BA = 1.0) |
| **Activity `A`** (response side) | **Reduced** by Axis 3 (size) + Axis 2 (timing) — the real, measurable win | Size benefit **= 0** (theorem); timing benefit remains |
| **Activity `A`** (request side) | **Not touched** by a response shaper (control-vs-read BA = 1.0 from request size) | Same |

- **Claim:** reduction of response-size/activity leakage to a non-parsing observer, with timing
  normalized to a measured-quantile deadline, **semantics fully preserved**, all residuals reported.
- **Do not claim:** device anonymity; size protection against a parsing observer; request-direction
  activity hiding.

---

## 7. Loophole ledger (open items → resolution)

1. Goal misdirection → three-axis reframe (§0.1). **Resolved in design.**
2. Cover framing strippable by O_parse → scope to O_count, state as theorem (§6). **Resolved by honest claim.**
3. Joint P4 on wrong core → embed corrected `defense4_caseA.p4` (§4). **Design fix.**
4. V1→V3 deletes quality → rejected; cover framing preserves semantics (§0.2). **Resolved.**
5. Reachability drops the tail → S=183 for full support, ≤2 frames (§5). **Corrected.**
6. Incomplete TCP translation → complete single-slot epoch (§4.2). **Design fix; needs compile.**
7. Pipeline order → egress-at-release satisfies size-before-timing observationally (§4). **Resolved.**
8. Multi-frame infeasible on one chip → single-frame prepend, or second edge (§4). **Scoped.**
9. Request-direction leak untouched → stated (§6). **Disclosed.**
10. Reproducibility → commit `reach_oracle.py`+test, repo-root resolver (§9). **Action item.**

Pending adversarial review (venue-standard) may add items to §9.

---

## 8. Status of current artifacts

| Artifact | Verdict |
|---|---|
| Timing D2/D4 silicon evidence (`defense4_caseA.p4`, 1,200 txns) | **Keep** — strongest result; the true timing core |
| READ range-expansion probe (`size_read_range.p4`) | **Keep** as a bounded primitive; correctly shows qual-0x06 all-points cannot be expanded request-side |
| `defense4_joint_canon.p4` (joint P4) | **Reclassify** as a feasibility probe; do not merge/load as a defense |
| V1→V3 canonicalization (`canonical_response.py`) | **Reject** as a defense (deletes quality); keep as a probe artifact |
| SBO OpenDNP3 tests | **Keep** as interoperability evidence only |
| Offline scores (18/18 etc.) | **Rework** — self-generated, not reproducible from the branch; fix before citing |
| Cover-frame reachability oracle | **Create + commit** (does not exist yet) |

---

## 9. Validation plan (pre-build gates — no hardware)

1. **DNP3 endpoint-discard test** (software first, then physical SEL-751 under authorization).
   Add a `cover-prepend` mode to `split_server.py`; run the C1–C8 address matrix (unused-individual,
   wrong-SRC, reserved, self-addr disabled/enabled, broadcast, chained, bad-CRC). Measure, baseline-
   differenced: any reply to the cover address (expect none for C1–C3/C7); real RESPONSE byte-identical;
   0 extra CONFIRM/RST/FIN/retransmit; no new IIN; no SER/DB delta; internal counters move only on the
   benign discard counter, by exactly the cover count. **C5 (self-addr enabled) and C6 (broadcast) are
   expected failures** proving the address discipline is load-bearing.
2. **Reproducibility fix.** Commit `reach_oracle.py` (`L(k)`, `Δ_reachable` DP, smallest-common-target)
   + a unit test asserting 71/183/269/271, ≤2 frames, and the forbidden band; add a repo-root resolver
   replacing the six hardcoded `/home/philip` paths; add `reproduce.sh`.
3. **Measure the real response-size distribution** including integrity polls and large READs — the
   entire `S ≤ MSS` single-segment advantage (and whether cover framing beats fixed-K) rides on it.
4. **Leakage factorial** `secret × observer` with the O_parse structure row, cluster-bootstrap CIs,
   matched permutation nulls, one seed — so the paper reports the O_count size-reduction next to the
   untouched O_parse / request-direction / device-ID leaks in one honest table.
5. **Only then**, if the threat model warrants (§10): build the joint program on `defense4_caseA.p4`
   (egress morph + transport epoch), compile-gate, then the READ wire gate under explicit hardware
   authorization.

---

## 10. Open decisions (yours)

1. **Adversary capability** — byte-counting or DNP3-parsing? Decides whether Axis 3 is worth building.
   Recommended posture: report both; lead the size result with O_count; state the O_parse strip.
2. **Target support set** — normalize to `{37,54,61}` (S=71) or the full observed support
   `{37,54,61,74,122,183}` (S=183) or the real measured profile (after §9.3). Sets the overhead.
3. **Endpoint cooperation** — is fleet reconfiguration to a common flag-carrying variation (e.g. all
   analogs G30V5) on the table? It is the only semantics-preserving lever against the *structure*
   fingerprint, but it touches every endpoint and NERC-CIP change control.
4. **Paper framing** — one three-axis systems paper, or lead with the strongest standalone result
   (the silicon timing defense) and treat size as a scoped, honest secondary contribution? (The
   adversarial review will inform this.)

---

---

## 11. Adversarial venue-standard review — verdict & required corrections (2026-08-11)

A hostile TDSC/NDSS/S&P-standard review of this design, read against the *committed* evidence
(`defense4/paper/METHODS_RESULTS.md`, `PAPER-STATE.md`, `PAPER_OUTLINE.md`). It corrects errors in
§0/§5 above and resets the paper framing. **Take §11 as authoritative where it conflicts with §5.**

**Verdict:** as a three-axis device-fingerprinting *system* → **REJECT** (one PARTIAL axis on silicon,
one unbuilt, one provably null vs the standard adversary; no device claim statistically attainable;
the deadline justification is self-contradicted). As the **narrowed honest core** — a validated
in-network CLRT-normalization *mechanism* plus two impossibility results (device identity is invariant
to timing+size; size obfuscation is null vs a parsing observer) — → **MAJOR REVISION with a clear path**.

**MUST-FIX:**
- **M1 — the "10 ms ≈ p99+guard" claim in §5 is FALSE against the real OFF table.** `METHODS_RESULTS.md`
  gives native **p99 = 13.67 ms, max = 15.65 ms** (Campaign A); `D_R = 10 ms` sits *below* p99, so the
  guard is negative. The defended distribution is therefore **bimodal** — a 10 ms plateau plus a
  native-correlated **late-safe-release tail to ~18.8 ms** (D4) — and entropy only drops **3.63 → 1.10
  bits (not closed)**. That tail *leaks the CLRT magnitude the deadline was meant to hide*, and the
  fixed plateau is itself a defense fingerprint. **Fix:** reconcile the baseline (M2), then set `D_R`
  **above** the reconciled native p99/max (re-measuring overhead), **or** characterize the tail as a
  named residual channel and quantify the surviving CLRT information. Do not headline "normalized to a
  fixed 10 ms."
- **M2 — the native CLRT baseline is not pinned.** Three committed docs disagree: outline median
  **12.90 ms**, `METHODS_RESULTS` p50 **≈2.9 ms**, memory **1.4–1.9 ms steady + cold ~25 ms**. (The eval
  and reviewer lenses literally pulled different numbers from different committed files — that *is* the
  bug.) The native CLRT is **multimodal** (cold vs steady, tail to ~166 ms); normalizing it to one
  deadline means cold-state transactions overshoot by design. **Fix:** one reconciled distribution,
  cold+steady characterized, deadline justified against it.
- **M3 — no device-level claim is statistically attainable here.** k=1 makes device BA=1.000 a
  *definition*; one unit per model is n=1; the permutation-p **floor 7/91 = 0.077 > 0.05**, so no
  leakage/reduction result can reach significance. **Fix:** drop all device-fingerprinting language, or
  build a k>1 anonymity set with ≥3 units/model and a corpus that clears p<0.01.
- **M4 — the headline is not what was built.** Only Axis 2 is on silicon (PARTIAL); Axis 1 (the only
  axis that touches device identity) is unbuilt; Axis 3 is null vs a parser. **Fix:** validate Axis 1
  (show device BA 1.0→~1/k after handshake normalization on ≥2 devices) *or* retitle to the single
  validated mechanism.

**SHOULD-FIX:** **S1** name the *specific* inference CLRT normalization defeats (e.g. event-buffer
occupancy from CLRT magnitude) and show a before/after attack-success drop — entropy is a capacity
statement, not a defeated adversary; control-vs-read stays BA=1.0 from the untouched request. **S2**
address choice is safety-critical and the experts *disagree* — DNP3-semantics says use an **unused
individual** address (defined "drop" filtering; reserved 0xFFF0–FB is undefined), the reviewer says the
**reserved** range; both agree self `0xFFFC` and broadcast `0xFFFD–FF` are *processed* (unsafe). The
C1–C8 endpoint test (§9.1) resolves this empirically per stack; cite the exact IEEE 1815-2012 clause and
show the discard *manner* (silent vs NAK vs RST) per stack, since the manner itself can leak the stack.
**S3** quantify OT overhead/availability — added latency, master-RTO margin, retransmit behavior under
the per-flow TCP translation, and reconcile the Case-C fail-open (one unprotected txn on a missing
RESPONSE) against the "0 bypass" headline; ground in NIST SP 800-82. **S4** state the delta vs Ditto
(NDSS'22), NetShaper, Pacer, and Hu et al. DNP3-in-P4 (SmartGridComm'23) — the novel kernels are
*narrow*: the strict-priority ACK-before-response ordering guarantee + in-switch blocker reservoir, the
semantics-preserving cover-frame + strip theorem, and the localization theorem. **Nits:** "1,200 txns"
= n=240/mode×2 campaigns (say so); GRO/GSO/TSO were on (caveat byte-boundary claims); close the citation
provenance flags.

**Strongest honest paper (the recommended framing):** *not* the three-axis system. It is *"In-network
CLRT normalization for legacy separate-ACK DNP3 devices on a commodity programmable switch — a validated
dataplane mechanism, with two impossibility results,"* i.e. **one mechanism + two theorems + honest
limits.** Venue: **TDSC / ACSAC / a CPS-ICS security venue**; NDSS/S&P/CCS with the current framing =
reject. **Shortest path:** (1) retitle/rescope to the timing mechanism + the two theorems, delete device
claims; (2) fix the deadline (M1) + report latency/RTO (S3); (3) reconcile the baseline (M2); (4) add a
second physical Case-A device; (5) ground the standards (IEEE 1815-2012 address clause; IEC 62351 /
DNP3-SA / TLS assumption; NIST SP 800-82; Formby NDSS'16 as the targeted attack; Juarez CCS'14 on why a
k=1 closed-world balanced accuracy cannot support a defense claim).

---

*Nothing in this document has been built or loaded on hardware. It is the design and decision to own
before implementation begins.*
