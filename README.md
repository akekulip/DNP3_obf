# DNP3 fixed-transcript research

Working repository name only. This project is not ADTA, not GridCloak, and not Defense 4.

## What this is

A research and architecture study of whether a **single Tofino-1**, sitting between an **unchanged**
DNP3/TCP master and an **unchanged** DNP3/TCP outstation, can make the master-facing observable pattern
of DNP3 traffic look the same no matter which device is behind it, **without encryption and without a
decoding peer**.

The binding testbed is:

```
Master  <->  Tofino-1  <->  Outstation
```

No software gateways, proxies, second switch, encrypted tunnel (IP-TFS / IPsec / MACsec), split-TCP,
SmartNICs, endpoint modifications, or any other machine in the path. Internal Tofino mechanisms
(pktgen, TM, multicast, mirror, recirculation, loopback) are allowed. This constraint supersedes the
paired-gateway recommendation of the earlier baseline (`f2bd3e4`); see `CORRECTION_LOG.md`.

For a declared public transaction class `c`, the observer is meant to see a public pattern

```
P_c = [ (delta_i, S_i, d_i) ]   i = 1..K
```

(release offset, size, direction) that does not depend on the protected secret `X` given the public
context `C`. `X` = physical outstation identity plus response-dependent size, timing, count, and stack
behavior. `C` = transaction occurrence and operation class (READ or SBO). No activity-hiding,
operation-type-hiding, or content-confidentiality is claimed.

This phase produces a written decision, not a shipped system, and touches no switch or relay.

## Relationship to the upstream evidence

The upstream repository `/home/philip/Projects/DNP3` (branch `defense4-caseA-hw-integration`, commit
`7c4a5a7`) is strictly read-only. Its Defense 4 result closed the response-time fingerprint on one relay
under one narrow workload and is a frozen foundation here. Provenance and pinned hashes are in
`PROVENANCE.md`; the exact D4 contract in `D4_UPSTREAM_CONTRACT.md`. The native-mechanism investigation
draws on the upstream multi-CROB SBO harness, the split harness (including the 12,204-byte READ), and
the leakage study, all read-only.

## Deliverables

| File | Purpose |
|---|---|
| `PROVENANCE.md` | Upstream pin, blob hashes, read-only rules |
| `CORRECTION_LOG.md` | What this revision supersedes from `f2bd3e4`, each correction labeled |
| `RESEARCH_CHARTER.md` | Hard constraint, re-scoped objective, non-goals |
| `D4_UPSTREAM_CONTRACT.md` | Bounded scope of the frozen Defense 4 result and its eligibility interface |
| `EVIDENCE_LEDGER.md` | Established findings, each labeled and verified |
| `THREAT_MODEL.md` | Adversary, secret `X`, public `C`, observables, endpoint-safety boundary |
| `PRIOR_WORK_MATRIX.md` | Closest prior work; what is unavailable in this testbed |
| `OBSERVABLE_TRANSCRIPT_SPEC.md` | The pattern `P_c`, invariance definition, pattern states |
| `ARCHITECTURE_CANDIDATES.md` | Native one-Tofino candidates compared; the excluded alternatives |
| `TOFINO_TM_FEASIBILITY.md` | What one Tofino can and cannot do for the native pattern |
| `TRANSPORT_AND_ENCRYPTION_OPTIONS.md` | The excluded paired-gateway/encryption analysis (why it is out of scope) |
| `PROOF_OBLIGATIONS.md` | Functional correctness, transcript invariance, endpoint safety, privacy-failure accounting |
| `EXPERIMENT_PLAN.md` | Experiments that would discharge the obligations |
| `RESOURCE_BUDGET.md` | Budget in real compiler categories |
| `RISK_REGISTER.md` | Ranked risks, mitigations, retiring evidence |
| `SKEPTICAL_REVIEW.md` | Adversarial review that tries to falsify the recommendation |
| `DECISION_MEMO.md` | The recommendation and its justification |
| `OPEN_QUESTIONS_FOR_PHILIP.md` | Decisions only Philip can make |
| `references/README.md` | Annotated bibliography |
| `analysis/` | Specialist investigation notes (native DNP3, TCP/headers, Tofino scheduling) and probes |

## Verdict vocabulary

The decision closes with one of: `GO_NATIVE` (a complete endpoint-safe one-Tofino mechanism is ready for
a bounded prototype), `GO_WITH_BOUNDED_CLAIM` (selected features protectable under stated restrictions),
`NO_GO_FULL_TRANSCRIPT` (full plaintext fixed-transcript invariance is unattainable under the hard
architecture, but a narrower defense or impossibility contribution remains), or `NO_GO`.

## Rules honored

The source repo is never modified by this revision. No remote, nothing pushed. `f2bd3e4` is preserved in
history; corrections land in a new commit. Defense 4 is frozen. Barred: gateways/proxies/second-switch/
encryption/split-TCP/SmartNICs/endpoint changes; adaptive CRC splitting as privacy; trailer padding
below IP; adaptive `K`; assuming an empty queue emits a packet; assuming real and native cover are
indistinguishable without proof; treating a fabricated CONFIRM as safe; treating an offline zero-MI model
as a working switch.

## Status

Revision complete under the one-Tofino constraint. **Decision: `NO_GO_FULL_TRANSCRIPT`** (see
`DECISION_MEMO.md`). Full plaintext fixed-transcript invariance is unattainable on one DNP3-blind Tofino
with unchanged endpoints and no encryption: correct native size/count closure and indistinguishable
native cover both require a proxy the testbed forbids, and the endpoint-stamped TCP-stack fingerprint
keeps device identity visible. The only realizable native mechanism is timing normalization on the real
packets (the frozen Defense 4 mechanism) plus a stateless scrub of TTL and ip.id, which is a non-closing
mitigation, not a device-identity defense. The genuine contribution is the impossibility boundary
(the ignore-rule = strip-rule theorem, the refuted "split preserves bytes" in-repo belief, and the ICS
safety escalation of native cover). Decisions that gate the next phase are in
`OPEN_QUESTIONS_FOR_PHILIP.md`.
