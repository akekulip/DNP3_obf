# PI Research Program — In-Network, Integrity-Correct DNP3 Response Size-Normalization

*PI framing + delegation map (agent, 2026-07-18). Evidence: [M] rig · [S] IEEE 1815/OpenDNP3 source · [P] paper · [I] inference · [H] hypothesis.*

## 0. Problem + claimed contribution
Timing axis closed by DCRN (0.731→0.289 BOUNDED [M]). Dominant residual = RESPONSE SIZE (size-only classifier ~0.99; ~14.6 B/CROB, ~5.7 B/analog-point [M]). Prior work proved BYTE-PRESERVING DNP3 padding does NOT exist at any layer ([M][S] `padding_analysis.md`, `agent_A_dnp3_split_padding.md`): invalid filler rejected+visible, valid filler ingested as real data, APDU has no length field to pad. **This program steps beyond byte-preservation.** Contribution: *first in-network, append-only, DNP3-semantically-valid response size-normalizer on a commodity programmable switch (Tofino-1) — a real master parses it, minimum checksums recomputed via compile-time-constant tables, no frame reconstruction, no TCP proxy, size fingerprint collapsed at a quantified privacy/overhead point.* Novelty = the CONJUNCTION (append-only + DNP3-integrity-correct + no-reconstruction + no-proxy on RMT), not "padding" or "in-network shaping" alone.

Reframe that makes YES plausible: old question "find inert filler that changes nothing" (proven impossible). New question: **"can we append a VALID, PARSEABLE DNP3 object whose ingestion is operationally benign, entirely on the data plane, WITHOUT a new application fragment (hence no new CONFIRM, hence no desync of the real outstation)?"** — a different, open question.

## 1. Research questions
- RQ1 mechanism: can the carousel grow a response by a variable number of CONSTANT trailer blocks (incrementing link LENGTH, transport SEQ/FIN, IP/TCP length; per-block checksum deltas) with compile-time-constant TABLES (no runtime CRC engine), original payload never in PHV, within Tofino-1 limits?
- RQ2 legality: is there a DNP3 object that (a) parses cleanly in OpenDNP3 master, (b) ingested without operationally-meaningful DB corruption, (c) rides INSIDE the existing fragment so no new CONFIRM, (d) `dnp3`-IDS-clean? Under which cooperation regime?
- RQ3 privacy: as a fn of bucket count B, size-only balanced-acc + I(padded_size; device_label)? Pareto knee? Append-only is UP-ONLY → targets must dominate the largest device; heavy-tail residual leakage reported separately.
- RQ4 safety: MSS/re-segmentation, RTO+recirc latency composed with DCRN hold, fail-open (forward ORIGINAL unpadded on any pad-incomplete), IDS-clean.
- RQ5 novelty boundary: which systems it dominates and where the honest boundary sits (if cooperation needed, "endpoint-aware in-network", priced vs tunnel padding).

## 2A. Hypothesis ledger (falsifiable)
- **H1 [CONFIRMED, S]** DNP3 link CRC is PER-16-byte-BLOCK → an identical appended data block has an IDENTICAL CRC = genuine compile-time constant. THE ENABLING FACT. (`LinkFrame.cpp` per-block ValidateBodyCRC.)
- **H2 [open]** link HEADER CRC (over LENGTH) + transport SEQ/FIN are NOT constant across passes but take a SMALL DISCRETE set → controller-installed TABLE OF CONSTANTS keyed by pass count, still no runtime CRC engine. (CRC-16 is affine → header-CRC delta is per-LENGTH-value, not one constant. Seed thesis's "constant delta" is TRUE for appended-block CRC + IP/TCP payload sum, FALSE for length-dependent header CRC.) Refute: table blows MAU budget.
- **H3 [open, SHARPEST]** filler must ride INSIDE the outstation's existing application FRAGMENT (de-FIN last link frame, append filler link-frames, FIN on last) → master reassembles ONE fragment → ONE unchanged CONFIRM → no CONFIRM to a fragment the real outstation never emitted (no proxy/desync). A NEW fragment would elicit a NEW CONFIRM → desync/event-buffer mis-flush ([S] `MasterContext.cpp:257-262`). Refute: extra CONFIRM on rig.
- **H4 [open, CRUX]** a valid filler object the master parses+ingests BENIGNLY. Prior Finding 3(c): valid filler ingested as real data → semantic change. Candidates: decoy point indices → discard sink; operator-designated padding class. Likely needs config-cooperation → **H4′**.
- **H4′ [H]** config-cooperating master (utility owns both ends, designates padding-sink range/class) tolerates filler — weaker but valuable, stays in-network+no-proxy. Weakens novelty "transparent"→"endpoint-aware". Refute: if it needs master CODE changes → collapses toward cooperating-endpoint/tunnel.
- **H5 [I]** original payload never enters PHV (only edited header/length/checksum + appended trailer). Caveat: the de-FIN edit means the outstation's LAST frame header DOES enter PHV.
- **H6 [I]** Tofino-1 can grow a packet by append via recirculation (accrete constant trailer/pass) OR emit constant trailer at egress deparser, within recirc/RTO limits, up to ~+590 B on controls. DCRN recirculates WITHOUT growing → grow-per-pass unproven.
- **H7 [H]** bucketed append-up drives size-only classifier toward chance at tolerable overhead. B=1 (pad-to-class-max) closes it at +590% on controls [M]; bet = few buckets get most closure.
- **HARD KERNEL = H2 ∧ H3 ∧ H4 ∧ H6.** H1 confirmed.

## 2B. Alternatives (don't single-thread)
- ALT-1 bucketed discrete pad-templates (one complete constant trailer per bucket, single-pass splice) — pragmatic default if H6 per-pass accretion fails but single-shot deparser append works.
- ALT-2 egress-deparser constant trailer (stacked trailer headers for variable size).
- ALT-3 switch-tags + DPU-pads hybrid — GRACEFUL DEGRADATION (mirrors DCRN "hold edge-bound, switch=instrument"); still no-full-proxy.
- ALT-4 mirror/reconstruction — edges toward store-and-rebuild middlebox the novelty must BEAT; deprioritize.
- ALT-5 pktgen decoy read-plane transactions — pads AGGREGATE not per-response; weaker target; read-plane only.

## 3. Verdicts / decision criteria
- **A "buildable-and-worth-building"** (claim headline): A1 `bf-p4c` compiles append+table-of-constants+trailer within limits; A2 real master parses padded response, 0 errors, NATIVE CONFIRM count, single event-buffer flush, no meaningful DB corruption; A3 bucketed padding drops size-only balanced-acc ~0.99→≤~0.40 at tolerable overhead; A4 fail-open + no MSS crossing + RTO-safe + IDS-clean.
- **B "buildable-but-privacy-insufficient"** (mechanism + honest negative privacy result; recommend tunnel): A1∧A2∧A4 pass but A3 fails (append-up can't normalize heavy-tail / bucket count too costly / crosses MSS).
- **C "needs a co-processor"** (land on ALT-3; size-axis analog of DCRN edge-bound finding): A1 fails (table blows up, H6 impossible, MSS forces stateful rebuild). Switch classifies+tags, pad on DPU.

## 4. Evaluation design skeleton
Reuse DCRN harness (grouped CV by run/session/source-txn; SEL-751/AB1400/ION7550; run_master↔replay through switch; Vision capture). (4.1) privacy: size-only+all-feature classifiers, grouped-CV balanced-acc+macro-F1+confusion+repeated-CV 95%CI, baseline 0.333, sweep B∈{1,2,4,8,16,native}; info-theoretic I(padded_size;label) + H(label|size) + anonymity-set k; PRIMARY readout = privacy-vs-overhead Pareto (knee = headline); append-only heavy-tail residual separately. (4.2) overhead: added bytes (mean/p95/worst +590B), recirc passes/load, added latency N×per-pass composed with DCRN hold vs RTO cap, MSS headroom. (4.3) correctness GATE: original SHA-256 preserved as PREFIX (padded==original++constant_trailer); 0 parse/CRC errors; SOE/DB diff only benign points; NATIVE CONFIRM count + single flush (H3 gate); 0 retrans/reset/dup/reorder; Zeek dnp3 0 errors + no new-object-group anomaly (R5); fail-open forwards original. Conditions: NATIVE / DCRN-only / PAD-FIXED(B=1) / PAD-BUCKETED(B=k) / DCRN+PAD composed (joint device balanced-acc → chance once both axes normalized).

## 5. Novelty matrix (to fill via literature-reviewer)
ditto (NDSS'22, Tofino): in-network YES, inner-protocol-valid NO (pad+chaff), rewrites → we keep DNP3 a valid PREFIX, append-only no chaff. NetWarden (USENIX'20): slowpath proxy/synthesizes ACKs → we are fast-path no-proxy no-synthesis. NetShaper (USENIX'24): buffered middlebox tunnel → we're on-switch no-tunnel. Pacer (USENIX'22): host secret-independent shaping → we're in-network, borrow the secret-independent-target OBJECTIVE. BuFLO/Tamaraw/DynaFlow: constant-shape padding → give the info-theoretic leakage bounds + B=1 ceiling. Store-and-rebuild DPU/FPGA: reconstructs → we claim append-only no-reconstruction (ALT-4 must not collapse into this).
Honest boundary: (i) if H4′ config-cooperation, claim = "endpoint-aware in-network", priced vs tunnel; (ii) append-only RAISES floor only → target dominates largest device; (iii) single-device-per-profile → device-CONFIG not device-FAMILY; (iv) every Tofino number is inference until a compile.
Venue: A→systems/security (NDSS/USENIX/CCS; ToN/TDSC extended). B/C→feasibility/systematization (size-axis analog of DCRN edge-bound). Write-up via systems-paper-writing/academic-paper + paper-voice.

## 6. Risk ledger
R1 H4 no stock-transparent filler → config-cooperation weakens novelty (HIGH). R2 header-CRC/length/SEQ delta not table-able → needs runtime CRC engine Tofino lacks (HIGH; fallback ALT-1/2 or Verdict C). R3 CONFIRM desync if filler leaks into new fragment (HIGH safety; rig gate on CONFIRM count/flush). R4 MSS crossing re-introduces packet-count fingerprint (MED; cap pad ≤ MSS). R5 appended object itself an anomaly (MED; choose filler from device's own emitted object set). R6 append-only can't normalize heavy-tail → Verdict B (MED). R7 recirc-grow + DCRN hold exceeds RTO (MED; re-measure Vision RTO). R8 gridcloak owns 4 pipes → gated bf_switchd restart (MED ops). R9 every Tofino number inference until compile (MED).

## 6B. Delegation map
- W1 carousel mechanism (p4-dataplane-engineer, RUNNING) — table-of-constants for header-CRC/len/SEQ/FIN (H2); trailer accretion per pass vs single-shot (H6/ALT-1/2); payload-out-of-PHV (H5).
- W2 DNP3 legality (power-systems-expert, RUNNING) — benign filler object (H4/H4′); fragment-internal append→no new CONFIRM (H3); cooperation regime; filler IDS-anomaly (R5). Source: OpenDNP3 APDUParser/MasterContext/MeasurementHandler.
- W3 SOTA+threat (sdn-networks-expert, RUNNING) — §5 matrix; info-theoretic padding-leakage bounds for RQ3.
- W4 eval+stats design (research-scientist + statistical-analysis) — PARALLEL, launched.
- W5 compile-only P4 append probe (p4, GATED — after W1 + explicit Philip go/no-go; gated bf_switchd restart per R8).
- W6 adversarial review (ieee-journal-reviewer) — after a claim exists.
- W7 find-skills scan — PARALLEL, minor.
Converge W1(H2/H6) + W2(H3/H4) FIRST (they decide the verdict), then W4 sizes privacy, then gate W5, then W6.

## 7. What only Philip decides
1. **Cooperation regime** (drives novelty): config-cooperating master acceptable (H4′ unblocks, claim "endpoint-aware in-network") vs stock unmodified master bar (higher-risk, hinges on W2 finding transparently-benign filler)?
2. Authorize the gated compile-only P4 append probe (W5)? Touches P4 + bf_switchd restart displacing gridcloak.
3. Which verdict is publishable-enough (B/C systematization acceptable, or only A)?
4. External validity: device-FAMILY claim needs more physical devices.

PI bottom line: path to YES is real, runs through H2 (table-of-constants deltas), H3 (fragment-internal append → no CONFIRM desync), H4/H4′ (benign filler, possibly config-cooperating), H6 (ASIC trailer accretion). H1 confirmed. None refuted; each has a concrete check. Carry ALT-1 (bucketed templates) as pragmatic default, ALT-3 (switch-tags+DPU) as graceful degradation.
