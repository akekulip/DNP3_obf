# In-Network DNP3 Response Size-Normalization — Research Design

*Synthesized 2026-07-18 from five parallel specialist workstreams (PI framing; Tofino mechanism;
DNP3/IEEE-1815 legality; SOTA + threat model; evaluation + statistics). Raw contributions in
`agent_contributions/`. Design/research only — nothing compiled, loaded, or run. Evidence tags:
[M] measured on the rig · [L] confirmed from working lab P4 code · [V] vendor/standard/spec ·
[P] paper · [I] inference on an unbuilt design · [H] hypothesis. A first `bf-p4c` compile on the
switch SDE 9.13.2 is the only proof of stage/SALU/PHV fit.*

---

## 1. Executive summary — the path to YES

**In-network DNP3 response size-normalization is buildable on the Tofino-1 switch.** The earlier
"padding is not doable on Tofino" conclusion was correct only for a *strict byte-preserving, append-a-
trailer* framing. Relaxing that to **append-only, integrity-correct, semantics-preserving** — and
correcting the mechanism — opens a credible, likely-novel path. Four findings carry it:

1. **The deparser-order crux dissolves: prepend, don't append.** TNA genuinely cannot emit bytes after
   an unparsed payload — but DNP3-over-TCP is a stream of *self-delimiting* link frames, so a constant
   filler frame placed *before* the real response is semantically equivalent to a trailer. This
   **pad-before-payload geometry is already proven on our chip** (it is exactly how the co-resident
   GridCloak program emits variable pad headers) [L].
2. **The CRC/checksum machinery is already running on this chip.** `p4_decoy` computes CRC-16/DNP *and*
   recomputes IP/TCP checksums for a DNP3-over-TCP response today, with the same externs [L]. For a
   *constant* filler frame the CRCs are precomputed host-side and baked in — the extern is not even
   invoked.
3. **A spec-legal, master-tolerated filler exists** — source-confirmed against the rig's *actual*
   master (`opendnp3-community`/pydnp3). Two candidate fillers (§4.2), both needing one rig test.
4. **One genuinely new hard element** — found independently by the mechanism *and* the SOTA
   workstreams: adding bytes to a live TCP flow requires a **per-flow sequence-space translator**
   (`seq += Δ` / `ack −= Δ`, Δ cumulative for the connection's life). Lighter than a proxy (no
   reassembly/buffering/termination), and NetWarden proved this bookkeeping runs at line rate on
   Tofino [P] — but its runtime-Δ checksum update is the top compile risk (Class-6 zone) and its
   retransmit/SACK behavior the top rig risk.

**Novelty (defensible):** *the first non-cooperative, integrity-correct, DNP3-semantics-preserving
response size-normalizer realized entirely in a commodity switch ASIC* — no cooperating de-obfuscator
on the far side, no end-host change, no full TCP proxy, and only the final grown packet ever on the
wire (recirculation passes never egress). This intersection is unoccupied in the verified literature
(ditto needs a cooperating far-end switch; NetWarden does header covert channels; store-and-rebuild
middleboxes terminate TCP).

**Scope pivot (state plainly):** this is a *new phase beyond the current byte-preserving rule*. The
real DNP3 response bytes stay **byte-identical** (they remain the deparser residual); what changes is
the outer TCP/IP envelope, the total length, and the added constant frame. The invariant becomes
**append-only, integrity-correct, semantics-preserving**, not "preserve every byte."

---

## 2. Problem and the conceptual pivot

DCRN closed the **timing** fingerprint on the rig (balanced accuracy 0.731 → 0.289 under BOUNDED [M]);
the on-switch ACK-delay is mapped. The dominant surviving fingerprint is **response size** — a
size-only classifier ≈ 0.99, driven by ~14.6 B/CROB (control) and ~5.7 B/analog-point (read) [M].

Prior work proved that **byte-preserving** DNP3 padding does not exist at any layer (`research/
split_pad_timing_policy/padding_analysis.md`): invalid filler is rejected and visible, valid filler is
ingested as real data, and the APDU has no length field to pad. The negative held **because
byte-preservation forbids adding bytes.** The pivot: normalize size = pad **up** (you cannot shrink a
response without destroying DNP3 semantics) = **add bytes**. That is inherently (a) byte-adding and
(b) TCP-connection-stateful — two facts the whole design flows from. The real response is never
modified; the primitive wraps a constant envelope around it.

---

## 3. The two hard kernels — resolved

**Kernel A — "trailer after an unparsed payload" (the crux I earlier called fatal).**
Confirmed unsolvable as stated (TNA emits parsed headers in program order, then the unparsed residual;
no API emits after the residual; parsing a multi-hundred-byte payload into the ~512 B PHV is
prohibitive). **Resolution: reframe append → prepend.** Parse only `Eth|IP|TCP` (~54 B, standard);
emit constant pad header(s) *between* TCP and the residual → on the wire `Eth|IP|TCP|[pad frame(s)]|
real DNP3 response`. DNP3's self-delimiting framing makes "before" ≡ "after" semantically, and the
real response stays the residual → byte-identical. This geometry is GridCloak-proven on the chip [L].

**Kernel B — "will a real master parse-and-tolerate the filler?"**
Answered against the rig's actual master source. Arbitrary bytes are a hard **NO** (parsed as an object
header → `UNKNOWN_OBJECT` → the two-pass fail-closed parser discards the *entire* response, the same
failure class as the CROB negative). Two constructions escape (§4.2), both source-grounded.

---

## 4. Mechanism on this chip

### 4.1 Recommended shape (Variant α): one-pass prepend ladder
Parse `Eth|IP|TCP`; classify the response and its DNP3-region size; pick the target bucket; in a single
pass conditionally `setValid()` the constant pad header(s) between TCP and the residual (GridCloak's
proven variable-emit ladder [L]); update IP `total_len`, apply the constant IP+TCP checksum delta, and
apply the per-flow seq/ack translation (§4.3); forward. **No recirculation** for the DNP3 size range.
The recirc **carousel (Variant α′)** — one constant block per pass on dp68, reusing the DCRN self-clock
— is the right tool only for *large* pad (PHV economy: O(1) PHV vs O(passes) recirc) or when folded
into the DCRN timing loop. So the seed "carousel" thesis is correct but repositioned: its value is PHV
thrift, not solving the deparser order.

### 4.2 The filler — two source-grounded candidates (reconcile on the rig)
Both are constant blocks whose CRCs are compile-time constants; the design is agnostic to which bytes
it carries, so **test both against the real master and pick the more robust**:

- **Candidate 1 — Group 110 (Octet String) application object**, appended *inside* the response
  fragment. Source-confirmed inert on `opendnp3-community`: group 110 is always recognized (any
  variation → `Group110Var0`, never `UNKNOWN_OBJECT`), is self-describing in length (`variation ×
  count`), is whitelist-clean, and is delivered as an opaque blob the master does not act on. Exact
  minimal unit: `6E 0B 00 F0 F0 <11 constant octets>` = 16 octets = one data-link block; use a reserved
  index band (0xF0–0xFF). **Master-dependent** (needs Group 110 support; guaranteed for the rig master,
  not universal). This is mechanism **Variant β** (grow the frame's data blocks) — needs the link
  header-CRC recompute on `LEN` change (bounded, 6-field, proven by `crc16_dnp_dl` [L]).
- **Candidate 2 — a header-only (10 B) black-hole DNP3 link frame**, prepended. Addressed to a link
  address that is not the master's, so the master's *data-link* layer silently discards it before the
  application parser runs [V] — potentially **more master-independent** (data-link addressing is core
  DNP3, not an optional object group). This is mechanism **Variant α** (prepend a constant frame).

**Reconciliation:** Candidate 2 (prepended black-hole frame) is the cleaner fit for the recommended
one-pass prepend ladder and is master-agnostic; Candidate 1 (octet-string object) is the fallback if a
prepended frame turns out to be re-sync-fragile on some master. The single rig experiment (§7, Probe A)
tests whichever is chosen first — recommend Candidate 2, with Candidate 1 as the documented fallback.

### 4.3 The genuinely new element — per-flow TCP sequence-space translator
Injecting *B* bytes into the outstation→master stream shifts every later sequence number by *B*. The
switch must maintain a per-flow cumulative offset Δ and, for the connection's life, rewrite
`seq += Δ` (outstation→master) and `ack −= Δ` (master→outstation), with a checksum fixup. Without it,
the outstation sees an ACK for data it never sent → challenge-ACK / RST → a loud tell and a broken
link. This is **not a proxy** (no reassembly, buffering, or TCP termination) and is proven Tofino-
feasible by NetWarden's per-flow seq/ack registers [P]. It is the element that makes size-normalization
genuinely harder than timing-normalization.

### 4.4 CRC and checksum
- **DNP3 CRC-16/DNP:** lab-proven (`p4_decoy` `CRCPolynomial(coeff=0x3D65, reversed, init=0,
  xor=0xFFFF)` + `Hash`, per-tuple instances = Class 7) [L]; for a constant frame the CRCs are baked in.
- **IP checksum:** header-only, all fields in PHV → wholesale or constant delta (lab-proven) [L].
- **TCP checksum:** must be **incremental, never wholesale** — the real payload is the unparsed
  residual, not in the PHV. Two contributions: the *constant* pad+pseudo-header-length delta (guarded
  two-case constant add — the Class-6-*safe* form), and the *runtime* seq/ack Δ delta (RFC-1624 folding
  with a runtime addend — the **Class-6 silent-ICE neighborhood**, the single highest arithmetic risk,
  native-ALU lowering to be confirmed at first compile). The residual payload is never read.

### 4.5 Resource + safety
One-pass ladder ≈ 5–6 of 12 ingress stages [I]; deadline compare/size bucket via a **range table**
(size sliced ≤20 b, avoids the gateway 44-bit limit); flags `bit<8>` (Class 3); Δ register
controller-seeded (Class 8, no in-SALU `v==0`); one Hash instance, one tuple shape (Class 7). **PHV is
the real ladder cost** (each emitted pad byte consumes PHV; comfortable to ~128–256 B, beyond which the
carousel wins). **MSS/MTU:** MTU (1500 B) is the hard ceiling; DNP3 responses are small (~292 B link
frame) leaving ~1150 B headroom; keep buckets sub-MTU so no re-segmentation. **Fail-open** is
mandatory: on any pad-incomplete/oversize condition, forward the *original unpadded* response — never
drop, fragment, or corrupt (a malformed/oversized frame trips the passive Zeek `dnp3` IDS).

---

## 5. Threat model and novelty

**Adversary:** passive on-path observer **downstream** of the switch (switch→master / WAN), reading
cleartext TCP payload lengths + DNP3 frame structure; classifies device from size / segment structure /
timing. **Protected region = the wire on the master side of the switch** (an upstream observer sees the
un-padded response — inherent to any in-network morphing; state it as an assumption). **The observer
sees only the final grown packet** — recirculation passes never egress a front-panel port and cannot be
externally mirrored, so unlike ditto's chaff the carousel adds *zero* new packets on the wire.

**Why the non-cooperative case is the one that matters:** a cooperative-endpoint tunnel trivially
normalizes size but is deployment-infeasible for OT (closed embedded RTUs/IEDs you cannot modify;
third-party SCADA masters you do not own). The novel/useful case is neither endpoint cooperating — a
single switch injects bytes a stock master accepts and a stock outstation never learns about.

**Contribution statement (as it would go to a PC):** *the first non-cooperative, integrity-correct,
application-semantics-preserving response size-normalizer for a real industrial protocol (DNP3),
realized entirely in a commodity RMT data plane via an append-only prepend/carousel, requiring no
cooperating de-obfuscator, no end-host modification, and no full TCP-terminating proxy.* Must beat:
ditto (cooperating switch pair, strips padding, chaff, not app-valid), NetWarden (header covert
channels, not app size), PayloadPark/P4-aggregation (move real bytes for efficiency), WF defenses
(host/proxy, cooperating endpoints), store-and-rebuild DPU (terminates TCP). The one sentence that
draws the boundary: *a store-and-rebuild proxy makes this easy and uninteresting; doing it as an
inline, non-terminating, transparent transform in the ASIC is what makes the seq-translation and
constant-CRC/constant-checksum machinery necessary and novel.*

---

## 6. Evaluation design (how we prove it works)

**Primary readout: a privacy-vs-overhead Pareto frontier**, one point per bucket count
`B ∈ {native,16,8,4,2,1}`, plotted with two y-axes — a **mechanism-independent** one
(`I(padded_size; device_label)`, Miller–Madow-corrected, permutation-null band) and an **adversary-
instantiated** one (size-only balanced accuracy, repeated grouped-CV 95% CI, chance 0.333). Two
pre-registered knees: `B*_MI` (Kneedle, most-privacy-per-byte — the headline) and `B*_op` (smallest B
meeting: size-only 95%-CI upper ≤ 0.40 **and** every bucket anonymity `k ≥ 2` — the deployment rec).

**The load-bearing information-theoretic ceiling (the honest boundary):** because padding is
**append-only / up-only**, every bucket pads members up to its ceiling, so padded size takes B shared
values — but **per-device bucket-occupancy frequencies stay device-specific**. Therefore
`I(padded_size; label) = 0` is reachable **only at B = 1** (one shared size). Every B > 1 leaves
residual leakage through occupancy, and **heavy-tail devices that already exceed a bucket keep `k = 1`
and are reported separately, never averaged away.** A convex frontier with an early knee → **Verdict A**
(few buckets suffice); closure only at B = 1 (huge overhead) or a persistent `k = 1` heavy tail →
**Verdict B** (honest negative privacy result).

**Correctness gate (binary prerequisite — no privacy number counts until it passes on the rig):**
append-only prefix invariant (`original == padded[:len(original)]`), constant-trailer, master parse
health (0 DNP3 parse/CRC errors at a real OpenDNP3 master), no operational-DB corruption, **no-desync
(CONFIRM count == native + single event-buffer flush)**, transport clean (0 retrans/reset/dup/reorder),
IDS-clean (Zeek `dnp3` 0 errors, filler object-group ⊆ native set), fail-open, and **segment-count
invariant** (no padded frame crosses MSS — else it re-introduces the packet-count fingerprint). The
no-desync and no-MSS-crossing checks are the two most likely to fail and the two that most threaten the
claim.

**Composition + the joint honesty split:** under **DCRN+PAD**, report *two* numbers — the `timing_size`
feature subset, pre-registered to **approach chance 0.333** (both axes closed), and the `all`-features
number, pre-registered to **floor at the ACK-mode residual ~0.667** (neither primitive closes the
categorical ACK mode — that is the separate socket-coalescing primitive). Stating both prevents an
overclaim. Also report **composed latency vs the RTO cap** (DCRN BOUNDED ~37.8 ms ⊕ pad latency vs
~150 ms; Vision RTO ≈ 211 ms [M]) — if the worst-case pad pushes composed p99 over the cap, that is a
Verdict-B/C signal.

**Sampling:** the 6-pcap offline set is a **pipeline smoke check only** (2 sessions/device is too few
for grouped CV); the CI-bearing result needs the rig at **R ≥ 5 runs/condition (target 10)**,
~130 transactions/device/condition, grouped CV by run, K = 100. Report effect sizes (paired Δ with
bootstrap CI, MI drop in bits), not bare p-values. **Environment fact:** the classifier eval runs on
**system `python3` 3.8 (sklearn 1.3.2)**; the numpy/scipy MI estimator runs on `$RESEARCH_PYTHON`.

---

## 7. Staged build-and-evaluate plan

Ordered so each step exposes one risk and produces evidence, and so a real privacy number arrives
*before* any P4 or hardware. Each hardware/P4 step is **gated** (explicit go/no-go; the shared switch +
`bf_switchd` restart per the DCRN map's Part 5).

- **S0 — Offline byte-transform smoke test (unprivileged, no switch, no P4) — DO THIS FIRST.** Apply
  per-response-type quantile-bucketed up-padding to the six replayed device captures; run the offline
  gate subset (prefix invariant, constant-trailer, segment-count) + the size-only classifier + MI at
  `B ∈ {native,4,1}`. Outcome: either the frontier shows an **early knee** (pursue the rig + compile) or
  a **heavy-tail k=1 residual** surfaces immediately (Verdict-B early warning). *This is the minimal
  step that produces a real privacy/overhead number and de-risks the whole program before touching P4.*
- **S1 — Rig filler-legality test (gated).** Prepend the chosen constant filler (Candidate 2 →
  fallback Candidate 1) to a captured READ response via a new byte-modifying replay mode; confirm on the
  real master: SOE for the real points byte-identical, 0 parse/CRC warnings, CONFIRM count native, 0
  retrans/reset, Zeek-clean. Answers Kernel B on hardware.
- **S2 — Probe A: P4 geometry + constant checksum (gated compile).** Parse `Eth|IP|TCP`; unconditionally
  emit one constant 10-B pad-frame header between TCP and the residual; `ip.total_len += 10`; constant
  guarded IP+TCP checksum delta; forward. Passes iff `bf-p4c` compiles clean (watch the Class-6 silent
  ICE first) and a captured frame is well-formed and master/Zeek-accepted. Upgrades the geometry +
  constant-checksum claims from [I] to fact.
- **S3 — Probe B: the per-flow Δ translator (gated compile + rig).** Add the flow-Δ register,
  `seq += Δ` / `ack −= Δ`, and the runtime-Δ incremental TCP checksum. Passes iff the runtime guarded
  carry lowers to native ALU (no Class-6 ICE — make-or-break) and a two-way DNP3 exchange shows no
  challenge-ACK/RST and idempotent re-padding under retransmit. This proves the one genuinely hard
  element.
- **S4 — Bucketing + fail-open.** Range-table bucket ladder (per response-type), the conditional-emit
  variable pad, and all fail-open guards.
- **S5 — Rig privacy/overhead campaign (§6).** Full grouped-CV + MI eval across NATIVE / DCRN-only /
  PAD-FIXED / PAD-BUCKETED / DCRN+PAD; the Pareto frontier + the joint two-number readout; verdict.
- **S6 — Fold into the DCRN timing loop (optional, Variant α′).** Merge size + timing into one dp68
  pass-count state machine (release when size satisfied AND deadline met).

---

## 8. Verdicts and decision criteria (pre-registered)

- **A — buildable-and-worth-building** (claim the headline): the gate passes on the rig; `B*_op` exists
  at tolerable overhead; composed DCRN+PAD latency stays under the RTO cap; no dominating `k=1` residual.
- **B — buildable-but-privacy-insufficient** (mechanism + honest negative privacy result; recommend
  tunnel padding for the size axis): the gate passes but size closure needs `B=1`, crosses the RTO cap,
  or a heavy-tail device keeps `k=1`.
- **C — needs a co-processor** (switch tags the bucket, a DPU pads — the size-axis analog of the DCRN
  "hold is edge-bound" finding): the ASIC cannot realize the mechanism (Class-6 runtime-Δ carry won't
  lower, or seq-translation is too fragile under retransmit/SACK). Variant γ is the graceful landing and
  still yields the privacy/overhead numbers — only the "in-network" claim narrows.

---

## 9. Risk ledger

| # | Risk | Severity | Disposition |
|---|---|---|---|
| R1 | Runtime-Δ TCP-checksum carry hits the Class-6 silent ICE | **High** | Probe B is designed to expose it first; fallback = Variant γ (host/DPU does the checksum) |
| R2 | TCP retransmit / SACK breaks seq-translation idempotency | **High** | Probe B rig test with forced retransmit; fallback γ (host TCP stack handles it natively) |
| R3 | Chosen filler not master-tolerated / not IDS-clean | **High** | S1 rig test of Candidate 2 → Candidate 1; the black-hole frame is filtered at the data-link layer (most robust) |
| R4 | No-desync (CONFIRM count) fails — filler leaks into a new fragment | High (safety) | Gate G5; keep filler inside one fragment / data-link-discarded |
| R5 | Heavy-tail device keeps `k=1` → residual size leak | Medium | Structural (append-only); reported separately → Verdict B, not hidden |
| R6 | Padded frame crosses MSS → re-segmentation re-adds the fingerprint | Medium | Gate G9; keep buckets sub-MTU; fail-open above the largest sub-MTU bucket |
| R7 | Composed DCRN+PAD latency exceeds the RTO cap | Medium | Measured composition vs re-measured Vision RTO; overlap the loops if serial is too slow |
| R8 | PHV budget too small for the ladder at large buckets | Medium | Switch to the carousel (α′, O(1) PHV) beyond ~128–256 B |
| R9 | Cross-master generalization (SEL/ION/AB may lack Group 110) | Medium | Candidate 2 (data-link filler) is master-agnostic; per-master check for Candidate 1 |
| R10 | Single device per profile → configuration, not family | Medium (external validity) | Stated ceiling; more physical devices is the only fix (Philip-gated) |
| R11 | Every Tofino stage/latency/load number is [I] until a compile | Medium | S2/S3 compiles convert to fact; privacy/byte-overhead numbers are real from S0 |

---

## 10. What is Philip's to decide

1. **Cooperation regime (drives the novelty claim).** Target a *stock, unmodified* master (higher-risk,
   hinges on the filler being transparently tolerated — the source evidence says yes for the rig master)
   vs. accept a *config-cooperating* master (a designated padding-sink point range — unblocks the design
   at a slightly narrower "endpoint-aware in-network" claim). The evidence currently favors the stock
   path via the data-link black-hole filler.
2. **Authorize S0 (offline smoke test)** — unprivileged, no switch, no P4; produces the first real
   privacy/overhead number. **Recommended immediate step.**
3. **Authorize the gated P4/rig steps (S1–S3)** — each touches the shared switch and a `bf_switchd`
   restart; explicit go/no-go per step.
4. **Which verdict is publishable-enough** (is Verdict B/C systematization acceptable, or only A) — sets
   the program's risk appetite.
5. **External-validity ceiling** — a device-*family* claim needs additional physical devices.

**Recommended immediate next action:** run **S0**, the offline byte-transform smoke test. It is safe,
needs no hardware, and either shows the privacy frontier has an early knee (green-light the rig + P4) or
surfaces the heavy-tail residual now — the cheapest possible test of whether this is Verdict A before
any P4 is written.

---

## 11. Provenance
Raw specialist contributions (full detail): `agent_contributions/{pi_framing, tofino_mechanism,
dnp3_legality, sota_threat_model, evaluation_design}.md`. Prior negative this overturns:
`research/split_pad_timing_policy/padding_analysis.md`. Reused machinery: `research/tofino_dcrn_
feasibility/` (recirc-hold, dp68 self-clock, gated restart). Lab P4 references: `Projects/GridCloak/
p4/gridcloak_c.p4` (pad-before-residual geometry), `Projects/p4_decoy/.../dnp3_decoy.p4` (CRC-16/DNP +
IP/TCP checksum on a DNP3 response). Master source: `Projects/opendnp3-community` (parser + g110). This
is a **new byte-modifying phase** beyond the current split-harness rule — every P4/rig step is gated.
