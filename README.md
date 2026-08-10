# DNP3 fixed-transcript research

Working repository name only. This project is not ADTA, not GridCloak, and not Defense 4.

## What this is

A research and architecture study of whether a practical DNP3 system can make the observable wire
transcript look the same no matter which device or response is behind it, and whether that can be
proven on real hardware. The observer sees an ordered list of packets

```
O = [ (direction, size, release_time, outer_header)_1 , ... , _K ]
```

and the goal is that this list does not depend on the protected secret under the same public context:
`P(O | X=x, C=c) = P(O | X=x', C=c)`.

This phase produces a written decision (`GO`, `GO_WITH_BOUNDED_CLAIM`, or `NO_GO`), not a shipped
system. It does not implement a production pipeline and does not touch any switch or the physical
relay.

## Relationship to the upstream evidence

The upstream repository `/home/philip/Projects/DNP3` (branch `defense4-caseA-hw-integration`, commit
`7c4a5a7`) is treated as strictly read-only. Its Defense 4 result closed the response-time
fingerprint on one relay under one narrow workload. This project asks the next question: can the size,
count, and header leaks be closed too, together, and can size-and-timing protection co-reside. The
exact provenance and the pinned blob hashes are in `PROVENANCE.md`; the exact boundary of what
Defense 4 proved is in `D4_UPSTREAM_CONTRACT.md`.

## Deliverables (this phase)

| File | Purpose |
|---|---|
| `PROVENANCE.md` | Upstream pin, blob hashes, read-only rules |
| `RESEARCH_CHARTER.md` | Objective, scope, non-goals, phase discipline |
| `D4_UPSTREAM_CONTRACT.md` | Exact bounded scope of the Defense 4 proof and the interface it exposes |
| `EVIDENCE_LEDGER.md` | The established findings, each labeled fact / reproduction / inference / hypothesis / open |
| `THREAT_MODEL.md` | Adversary, secret `X`, public `C`, observables, trust boundaries |
| `PRIOR_WORK_MATRIX.md` | Closest prior work from primary sources; nearest-neighbor and novelty analysis |
| `OBSERVABLE_TRANSCRIPT_SPEC.md` | Exact transcript features, invariance definition, pattern states |
| `ARCHITECTURE_CANDIDATES.md` | Candidate transcript designs compared adversarially |
| `TOFINO_TM_FEASIBILITY.md` | What one Tofino-1 can and cannot do for the transcript |
| `TRANSPORT_AND_ENCRYPTION_OPTIONS.md` | Where encryption, padding, fragmentation, reassembly live |
| `PROOF_OBLIGATIONS.md` | Functional correctness, transcript invariance, privacy-failure accounting |
| `EXPERIMENT_PLAN.md` | Experiments that would discharge the obligations |
| `RESOURCE_BUDGET.md` | Budget in real compiler categories, not just ingress stages |
| `RISK_REGISTER.md` | Ranked risks, mitigations, retiring evidence |
| `SKEPTICAL_REVIEW.md` | Adversarial pre-decision review that falsifies the candidates and novelty claims |
| `DECISION_MEMO.md` | The recommendation and its justification |
| `OPEN_QUESTIONS_FOR_PHILIP.md` | Decisions only Philip can make |
| `references/README.md` | Annotated bibliography of primary sources |
| `analysis/` | Small read-only analysis or resource-only compile probes |

## Rules honored

The source repo is never modified. No GitHub remote is configured and nothing is pushed. Defense 4 is
a frozen upstream result, not code rewritten here. Barred by scope: adaptive CRC splitting as a
privacy solution, trailer padding below IP, adaptive `K`, assuming an empty queue emits a packet,
assuming real and chaff are indistinguishable without encryption, and treating an offline zero-mutual-
information model as a working switch.

## Status

Research/architecture phase complete. **Decision: `GO_WITH_BOUNDED_CLAIM`** (see `DECISION_MEMO.md`).
The full "provably fixed transcript on hardware" claim is not reachable as first framed (single-edge it
is infeasible, paired-gateway it is largely off-the-shelf IP-TFS, and the switch's unique value, a
low-jitter release grid, is unmeasured). The defensible result is an impossibility boundary plus the
measured single-edge floor plus a first-time TCP-timestamp closure, promotable to the full paired-
gateway claim only if a silicon cadence measurement (risk R13) comes back positive. The decisions that
gate the next phase are in `OPEN_QUESTIONS_FOR_PHILIP.md`; the most consequential is whether a local
encapsulation function near the outstation is deployable at all.
