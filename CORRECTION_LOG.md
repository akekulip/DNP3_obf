# Correction log — one-Tofino constraint revision

This revision supersedes the paired-gateway recommendation of the baseline commit
`f2bd3e4bda1c6ed17824053111a5b2aaac154be0` and re-scopes the project to the binding testbed
`Master <-> Tofino-1 <-> Outstation`. The baseline commit and all evidence it collected are preserved
in git history; this correction lands in a new commit. Each correction below is labeled: verified fact
| inference | hypothesis | falsification result | open question.

## The binding constraint (new)

The complete testbed is `Master <-> Tofino-1 <-> Outstation`, a single Intel Tofino-1 between an
unchanged plaintext DNP3/TCP master and an unchanged plaintext DNP3/TCP outstation. This is a hard
constraint, not one architecture among several. The following are excluded and may not be added or
required: software gateways, proxy endpoints or sidecars, a second switch, IP-TFS / IPsec / MACsec or
any other encrypted tunnel, split-TCP, SmartNICs, endpoint software modifications, or any other machine
in the forwarding path. Internal Tofino mechanisms (pktgen, TM queues, multicast, mirror,
recirculation, loopback ports) are permitted and are not additional endpoints. The control plane may
configure the P4 program and TM/pktgen/port state at startup, install policies, and read counters; it
may not pace individual packets, make per-transaction release decisions, or sit in the live data path.

## What is corrected

| # | Baseline claim (`f2bd3e4`) | Correction | Label |
|---|---|---|---|
| C1 | "A local encryption/encapsulation box near the outstation is unavoidable; the minimal viable design is paired software gateways with the Tofino as metronome." | The paired-gateway design is now an **excluded** stronger alternative, not the recommendation. The question is re-posed as: can a Tofino-ONLY mechanism, on unchanged endpoints, without encryption or a decoding peer, make the relevant plaintext DNP3 transcript independent of the protected device. The unavoidability argument still correctly shows that FULL transcript invariance is out of reach without encryption; it does not settle whether a bounded native defense exists, which this revision investigates. | inference (the unavoidability chain holds for the full-invariance target); open question (bounded native defense) |
| C2 | Objective: full fixed-transcript invariance over `O = [(d,S,t,h)]`. | Objective re-scoped to a bounded, request-synchronized public pattern `P_c = [(delta_i, S_i, d_i)]` for a declared public transaction class `c`, on unchanged endpoints. Direction and size and release-offset only; the outer-header vector `h` is handled as a partly-unreachable residual, not a claimed-normalized field. | hypothesis (a bounded native pattern is achievable); to be tested |
| C3 | Secret/public split placed most of the burden on hiding occurrence via continuous cover. | New split: Secret `X` = physical outstation identity plus response-dependent size, timing, count, and stack behavior; Public `C` = transaction occurrence and operation class (READ or SBO). Occurrence and operation type are PUBLIC in Phase 1, so READ and SBO may use different public patterns and no activity-hiding is claimed. | verified fact (this is the declared Phase-1 scope) |
| C4 | Candidate G (IP-TFS) was the strongest alternative and the novelty bar. | IP-TFS, NetShaper, Pacer, and Ditto's encryption-plus-peer model are now IMPORTED ONLY for what they establish and are explicitly unavailable in this testbed (no encryption, no peer de-padding). What remains useful from Ditto is its TM scheduling discipline. | verified fact (these systems require resources the testbed forbids) |
| C5 | The leading design used ciphertext chaff so real and cover are indistinguishable. | Chaff, if any, must be PROTOCOL-VALID native DNP3 that the unchanged endpoints safely accept, or there is no cover at all. Whether native cover can be made observer-indistinguishable without encryption is the central open question handed to the DNP3-safety and TCP specialists. | open question |
| C6 | Header normalization was to be done by the tunnel endpoints / split-TCP termination. | Without a proxy, only switch-rewritable header fields (for example TTL, DF, IP-ID with checksum delta) can be normalized; endpoint-stamped fields (TCP timestamps, sequence/acknowledgment progression, window trajectory, data-offset/option layout) cannot be rewritten on one switch and are the likely impossibility boundary for device-identity hiding. | inference; to be confirmed by the TCP specialist |

## What is preserved unchanged

- The frozen upstream Defense 4 timing result and its contract (`D4_UPSTREAM_CONTRACT.md`), the evidence
  ledger's 16/16 verification (`EVIDENCE_LEDGER.md`), and the provenance pin at `7c4a5a7`
  (`PROVENANCE.md`). Defense 4 is a frozen foundation and is not modified in this phase. **[verified fact]**
- The falsification of trailer padding below IP and of adaptive-K privacy; the empty-slot-skips finding;
  the cadence risk R13; the endpoint-stamped-header leak. These survive the re-scoping and now bound the
  native design. **[falsification result / verified fact]**
- The paired-gateway analysis in `TRANSPORT_AND_ENCRYPTION_OPTIONS.md`, retained as the documented
  excluded alternative. **[preserved as excluded]**

## Verdict vocabulary (new)

The decision memo closes with one of: `GO_NATIVE`, `GO_WITH_BOUNDED_CLAIM`, `NO_GO_FULL_TRANSCRIPT`
(universal plaintext invariance not reached under the hard architecture but a narrower defense or a
provisional analytical contribution remains), or `NO_GO`. The verdict is evidence-based and is not forced
positive to preserve the project direction.

## Second correction (documentation-only, the commit after `f2a0dec`)

`f2a0dec` overstated the result as a completed impossibility proof. This commit downgrades it to a
**conditional analytical verdict** and corrects specific claims. No code, no hardware, no change to the
frozen D4 repository; documentation only. Each correction is labeled.

| # | `f2a0dec` claim | Correction | Label |
|---|---|---|---|
| D1 | "three specialists + a skeptical PI converge, strengthening the verdict" — treated as evidence. | Their agreement is **correlated internal adversarial analysis that found no counterexample**, not independent evidence and not proof. The reviewer's failed search reduces but does not eliminate the chance a counterexample exists. | inference |
| D2 | "DNP3-blind Tofino." | Removed. Defense 4 is DNP3-aware; the real limitation is **bounded per-packet parsing and state, without arbitrary TCP-stream reassembly or application-level store-and-forward transformation.** | verified fact |
| D3 | The three "structural walls." | Reclassified: `ignore = strip` is a **design hypothesis / conditional lemma**; general size/count closure is the **strongest no-go candidate** with absence-from-frozen-implementation distinguished from architectural impossibility; endpoint-stamped TCP headers are **unresolved, not an impossibility**. | hypothesis / no-go candidate / open question |
| D4 | Endpoint-stamped headers "provably require a proxy." | Withdrawn. Concrete TCP-header counterexamples (handshake option suppression, canonical data offset, TSval/ISN translation, checksum correction, with retransmission/reuse/wraparound/PAWS/RTTM analysis) are recorded as **counterexamples to compile and test** before any header no-go. | open question / design hypothesis |
| D5 | "Fabricated CONFIRM permanently deletes SEL-751 SER/SOE records." | Corrected: a valid premature confirmation can **retire acknowledged events from the DNP3 event buffer and prevent later delivery to the master**; SEL-specific SER/SOE effects are unproven and the three stores are kept distinct. | verified fact (corrected) |
| D6 | Loose secret/public split. | Clarified: `X` = physical outstation identity via timing/size/count/TCP-IP-stack features; `C` = occurrence, operation class, and plaintext DNP3 semantics; claim conditional on the same public semantic transaction; payload confidentiality and activity hiding excluded; content in `X` would make the no-go trivial. | verified fact |
| D7 | Verdict scope and positive result. | `NO_GO_FULL_TRANSCRIPT` preserved **only** for universal plaintext size/count/timing/header invariance. A **positive bounded defense already exists** for the tested D4 timing scope; broader D4-plus-header normalization is **open**. | verified fact / open question |
| D8 | Experiment order led with cadence and a vague "functional size mechanism" co-residency probe. | Reordered: (1) read-only TCP-option attribution + PCAP canonical transforms; (2) compile-only standalone TCP-header normalizer, separately authorized; (3) endpoint-safety on ordinary TCP + isolated OpenDNP3, then read-only SEL-751. Cadence deferred. The co-residency probe is an **unresolved experiment-selection gate** until an exact endpoint-safe mechanism is named. | verified fact |

Files amended in this correction: `README.md`, `DECISION_MEMO.md`, `RESEARCH_CHARTER.md`, `THREAT_MODEL.md`,
`ARCHITECTURE_CANDIDATES.md`, `RISK_REGISTER.md`, `EVIDENCE_LEDGER.md`, `EXPERIMENT_PLAN.md`,
`OBSERVABLE_TRANSCRIPT_SPEC.md`, `PROOF_OBLIGATIONS.md`, and correction banners on the agent-authored
records (`SKEPTICAL_REVIEW.md`, `analysis/native_dnp3_mechanisms.md`,
`analysis/tcp_segmentation_and_headers.md`, `analysis/tofino_native_scheduling.md`).
