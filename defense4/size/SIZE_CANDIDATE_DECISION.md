# Size-candidate decision record

Decides between the two gated size primitives using the four verified software gates (Impl 1 timing,
Impl 2 cover-frame endpoint, Impl 3 configured-decoy endpoint, Impl 5 transport oracle) and the
observer-aware scoring (Impl 4). Software evidence only — **no hardware, no P4 integration**. Every
result below was re-run and verified by the main session (assertion counts in parentheses).

## Per-candidate scorecard

| Property | **Cover framing** | **Configured decoy — READ** | **Configured decoy — SBO (enc-A)** |
|---|---|---|---|
| Endpoint compatibility | **PASS** for individual≠endpoint, reserved 0xFFF0–FFFB, self 0xFFFC; **FAIL** for broadcast 0xFFFD/E/F (Impl 2, 263 assert) | **PASS** — master accepts, real values+flags byte-identical as decoys grow 0→16 (Impl 3, 160 assert) | **PASS** — master accepts (encoding A); B rejected (Impl 3) |
| Operational-semantic preservation | **Full** — real frame byte-identical, never reaches app layer | **Full** — every real value + quality flag unchanged; real CROB path untouched | **Full** — real CROB executes exactly once; decoys inert (0 physical actuation) |
| Packet-length observer (O_count) | size normalized (pads the observed total) | size normalized (native-looking padded total) | size normalized (padded total) |
| **DNP3-parsing observer (O_parse)** | **STRIPPED → zero benefit** — cover is self-identifying by non-endpoint address; the parser delivers both frames (`rx=n_cover+1`) and O_parse runs the same address filter | **NOT structurally strippable** — decoys are real higher-index points, indistinguishable from real; residual tell = decoy index-range / value-stability profiled over time | **DETECTABLE** — acceptance needs a *separate trailing* G12V1 header → two headers, which no native device emits |
| Endpoint-cooperation requirement | **None** (individual/reserved) | **Required** — decoys are configured endpoint points | **Required** |
| TCP-translation requirement | **Yes** — switch inserts bytes → per-flow seq/ack translation (Impl 5 model; bounded, with tested limits) | **None for the switch** — the outstation emits the padded response natively; switch stays timing-only | **Yes** — switch injects decoy CROBs → seq/ack translation |
| Likely Tofino cost | egress cover-frame prepend + full transport epoch on the frozen caseA core (per earlier feasibility) | **timing core only** (size done by endpoint config) | egress G12 decoy insertion + transport epoch |
| Remaining unsupported cases | broadcast address (hazard); a parsing/aggregating observer; the per-flow translation's bounded-model limits (Impl 5) | requires preconfiguration; residual index/value profiling; per-device decoy sets must be common to normalize | detectable by a parser; request direction untouched |

## Selection (per the stated rules)

- **Cover framing is NOT selected as a parsing-observer defense.** It is a valid in-switch size
  mitigation **only against a byte-counting observer**, needs no endpoint cooperation, and preserves
  semantics — but a parsing/aggregating observer strips it to zero (the bounded additive-cover
  impossibility, now empirically grounded on the real OpenDNP3 parser).
- **Configured decoys preserve real values, real quality flags, and real CROB behavior** (Impl 3
  verified), so they clear the semantics bar the rules require. Against a parsing observer they are the
  **only** candidate not trivially strippable — the decoys look like real points — at the cost of
  **endpoint preconfiguration** and a residual index/value profiling tell.
- **No in-switch byte-insertion mechanism defeats a parsing observer** (cover framing null; SBO enc-A
  detectable). This is a clean, valid negative and is recorded as such.

**Decision.** The size axis has two honest, non-overlapping outcomes, chosen by threat model and by
whether endpoint preconfiguration is available:

1. **Byte-counting observer, no endpoint cooperation → cover framing** (individual/reserved address),
   an in-switch mechanism gated on the transport epoch. Scope the claim to O_count explicitly.
2. **Parsing observer, endpoint preconfiguration available → configured READ decoys**, which move the
   size padding to the **outstation** (native, master-accepted, value/flag-preserving) and leave the
   **switch timing-only** — the strongest and structurally simplest size result, gated on
   preconfiguration and the residual profiling tell. SBO size stays detectable and is not selected as a
   covert mechanism.

Neither is declared "the" size solution; both are honestly-bounded, and the timing axis (Impl 1) stands
independently with its coupled `(D_A,D_R)` policy on the `H = D_A + D_R` surface.

## Smallest justified next P4 implementation step

**Only if the byte-counting-observer / cover-framing path is pursued:** a single **fixed-layout,
single-cover-frame prepend** at egress-at-release on the frozen `defense4_caseA.p4`, wired to the
**bounded transport epoch** whose *offline* model is Impl 5 (`transport_oracle.py`, 19/19). The minimal
compile kernel is: parse-classify the release packet → prepend one CRC-valid cover link frame to a
fixed public target → apply the single-slot seq/ack translation → recompute IP/TCP checksum. **This
kernel is NOT implemented** — Impl 5 is the offline reference only; the P4 compile is the next gate, not
a done result.

**If the configured-READ-decoy path is pursued, there is no new size P4** — the switch runs the existing
timing core and the size normalization is an endpoint-configuration deployment step; the next artifact
is a deployment spec for a common decoy set, not a P4 kernel.

## Evidence (all re-run by the main session)

- Impl 1 timing-policy: `defense4/timing/analysis/` — 20/20 tests; selector picks a domain-common
  `(D_A,D_R)`, tested `(4,10)` co-optimal at `H=14`.
- Impl 2 cover-frame gate: `defense4/size/evidence/cover_frame_gate/` — 263 assertions; individual/
  reserved/self PASS, broadcast FAIL; CRC 0 failures.
- Impl 3 decoy gate: `defense4/size/evidence/decoy_gate/` — 160 assertions; SBO A accepted / B rejected;
  READ values+flags preserved 0→16 decoys.
- Impl 4 observer scoring: `defense4/size/evidence/observer_scoring/observer_scoring.py` — 5/5.
- Impl 5 transport oracle: `defense4/size/offline/transport_oracle.py` — 19/19, with tested
  safe-degradation limits.
