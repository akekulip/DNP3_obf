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
(full invariance unattainable under the hard architecture but a narrower defense or impossibility
contribution remains), or `NO_GO`. The verdict is evidence-based and is not forced positive to preserve
the project direction.
