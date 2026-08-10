# Research charter

Working repository name: `DNP3_fixed_transcript`. This is a working name only. The project is not
ADTA, not GridCloak, and not Defense 4.

This charter is revised from the baseline commit `f2bd3e4` to enforce the binding one-Tofino testbed.
The correction is recorded in `CORRECTION_LOG.md`; the baseline and its evidence are preserved in
history.

## The hard architecture constraint

The complete testbed is

```
Master  <->  Tofino-1  <->  Outstation
```

a single Intel Tofino-1 between an unchanged plaintext DNP3/TCP master and an unchanged plaintext
DNP3/TCP outstation. This is binding, not one option among several. The design may not add or require:
software gateways, proxy endpoints or sidecars, a second switch, IP-TFS / IPsec / MACsec or any other
encrypted tunnel, split-TCP, SmartNICs, endpoint software modifications, or any other machine in the
forwarding path. The master and the outstation stay standard, unchanged DNP3/TCP endpoints.

Internal Tofino mechanisms are permitted and are not additional endpoints: pktgen, TM queues,
multicast, mirror, recirculation, and loopback ports. The control plane may configure the P4 program
and the TM, pktgen, multicast, mirror, and port state at startup, install policies, and read counters
and evidence. It may not pace individual packets, make per-transaction release decisions, or take part
in the live data path.

## The question

A passive observer on the master-facing side of the switch learns which device is behind the link, and
what it is doing, from the sizes, counts, direction, and timing of plaintext DNP3 traffic, without
decrypting anything. The upstream Defense 4 work closed one leak, the response-time fingerprint, on one
relay under one narrow workload. It did not close size, count, or header leaks, and it did not show
those can be closed on one switch.

This project asks a single, re-scoped question. Can the existing one-Tofino testbed produce a bounded,
request-synchronized observable pattern for DNP3 traffic that does not depend on the protected device,
while the master and outstation stay unchanged, and without encryption or a decoding peer?

## The observable pattern

For a declared public transaction class `c` (for example READ, or SELECT/OPERATE), the defense claims a
public pattern the observer is meant to see:

```
P_c = [ (delta_1, S_1, d_1), ..., (delta_K, S_K, d_K) ]
```

where `K` is the public packet or slot count, `delta_i` is the scheduled release offset of slot `i`,
`S_i` is the observable packet size, and `d_i` is direction. `OBSERVABLE_TRANSCRIPT_SPEC.md` fixes the
exact features. No pattern parameter (`K`, any `delta_i`, any `S_i`, any `d_i`, the epoch length, the
continuation count, or the termination time) may depend on physical device identity, actual response
size, response values, response readiness, natural ACK timing, or natural response timing.

## The target property, scoped

Let `X` be the protected secret and `C` be public information. For the first bounded claim:

- **Secret `X`** = physical outstation identity, and response-dependent size, timing, count, and stack
  behavior.
- **Public `C`** = transaction occurrence and operation class (READ or SBO).

The target, within `PATTERN_NORMAL`, is that the master-facing pattern is independent of `X` given `C`:
`P(P_c | X=x, C=c) = P(P_c | X=x', C=c)` for all protected secrets `x, x'`. Because operation class and
occurrence are public in Phase 1, READ and SBO may use different public patterns, and we do not claim
activity hiding, operation-type hiding, encrypted-content indistinguishability, or universal
fixed-transcript confidentiality. The header vector is handled as a partly-unreachable residual (see
`THREAT_MODEL.md` and `OBSERVABLE_TRANSCRIPT_SPEC.md`), not a claimed-normalized field.

## The central research question

Without encryption or a decoding peer, can a Tofino-only mechanism safely make the relevant plaintext
DNP3 transcript independent of the protected device? We do not assume the answer is yes, and we do not
declare it impossible without fully investigating native DNP3, TCP, and Tofino mechanisms. The research
distinguishes six levels and states which each result reaches: (1) full observable-transcript
invariance; (2) closure of selected size, count, or timing features; (3) reduction without elimination;
(4) an idealized offline construction; (5) a mechanism realizable on Tofino; (6) a mechanism accepted
safely by the unchanged endpoints. If full invariance is not reachable under the hard architecture, we
state the boundary as precisely as the evidence supports (a conditional analytical no-go, with its
assumptions named, not a completed impossibility proof) and identify the strongest useful bounded defense
that remains.

## Native mechanisms under investigation

The revision investigates, and adversarially tests, native mechanisms that need neither encryption nor
a second endpoint (detailed in `ARCHITECTURE_CANDIDATES.md` and the `analysis/` notes): fixed DNP3
request/response templates; SBO and decoy CROBs on non-physical points; fixed-`K` DNP3/TCP segmentation
with fixed visible sizes; native protocol-valid chaff or duplication; same-switch scheduling techniques
(pktgen, TM, strict priority, round robin, multicast, mirror, recirculation, loopback, calendar/slot
tokens); and header normalization limited to switch-rewritable fields. Endpoint safety is a first-class
obligation: a decoy or template that the unchanged master or outstation would act on unsafely is
disqualified regardless of its privacy value.

## What this phase is, and is not

This is a research and architecture correction. It ends in a written decision, not a shipped pipeline.
No production P4, controller, pktgen, or test code is written in this phase. No hardware is loaded and
no switch or physical relay is contacted. Small read-only analysis or resource-only compile probes are
allowed to answer a concrete question; a design that merely compiles is not a result and does not start
implementation. Defense 4 is a frozen upstream timing result and is not modified.

## Scope discipline

We do not reintroduce the paired-gateway or any encrypted-tunnel design as the recommendation (it is
retained only as an explicitly excluded stronger alternative). We do not add a second endpoint, a
proxy, or a SmartNIC. We do not reintroduce adaptive CRC splitting as a privacy solution, trailer
padding below IP, or adaptive `K`. We do not assume a queue scheduler emits a packet from an empty
queue, that real and native cover are indistinguishable without proof, or that an offline zero-mutual-
information model is a working switch. We do not treat a fabricated DNP3 CONFIRM as safe unless proved
safe. We do not mix this project with ADTA, GridCloak, the earlier fixed-K emulator, or the old
multi-CROB harness (its results are read-only evidence, not active code). We do not make a novelty
claim from missing keywords.

## Provenance

Every reproduced number carries its source artifact and commit or blob hash. The upstream pin is in
`PROVENANCE.md` (source repo `/home/philip/Projects/DNP3` at commit `7c4a5a7`, strictly read-only).
Analysis dependencies are pinned and runs use deterministic seeds and encodings.
