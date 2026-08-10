# Research charter

Working repository name: `DNP3_fixed_transcript`. This is a working name only. The project is not
ADTA, not GridCloak, and not Defense 4.

## The question

A passive observer who watches a DNP3 control link learns things it should not, without decrypting
anything. The sizes of the frames, the number of them, the direction they travel, the time each one
appears, and the outer headers they carry are enough to tell one device from another and one
operation from another. The upstream Defense 4 work closed one of these leaks, the response-time
fingerprint, on one relay under one narrow workload. It did not close the size leak, the count leak,
or the outer-header leak, and it did not prove that the size axis and the timing axis can be closed
together.

This project asks a single question. Can we build a practical DNP3 system that makes the whole
observable wire transcript look the same no matter which device is behind it or what response it is
carrying, and can we prove that on real hardware rather than in an offline model?

## The observable transcript

We name what the observer sees. For one protected exchange the observer records an ordered list

```
O = [ (d_1, S_1, t_1, h_1), (d_2, S_2, t_2, h_2), ..., (d_K, S_K, t_K, h_K) ]
```

where each entry is one packet the observer captures: `d_i` is direction, `S_i` is the observable
frame or packet size, `t_i` is the release time, `h_i` is the observable outer-header behavior, and
`K` is the packet count. `OBSERVABLE_TRANSCRIPT_SPEC.md` fixes the exact features that go into each
field.

## The target property

Let `X` be the protected secret (the thing we must hide) and `C` be information that is deliberately
public. Under normal protected operation we want

```
P(O | X = x, C = c) = P(O | X = x', C = c)   for all protected secrets x, x'.
```

In plain terms: given the same public context, the transcript the observer sees must not depend on
the protected secret. If two different devices, or two different response values, or two different
response sizes produce transcripts the observer cannot tell apart, the property holds. `C` is where
we place things we choose to reveal, for example an allowed public transaction class. What exactly
belongs in `X` and what belongs in `C` is decided in `THREAT_MODEL.md`, and the parts that only
Philip can decide are collected in `OPEN_QUESTIONS_FOR_PHILIP.md`.

## What this phase is, and is not

This is a research and architecture phase. It ends in a written decision, not in a shipped pipeline.

In scope:
- Verify the upstream evidence and pin the exact boundary of the Defense 4 proof.
- Read the closest prior work from primary sources and state precisely what it already solves.
- Lay out the candidate transcript designs and compare them adversarially, with the Ditto-style
  repeating pattern as the leading hypothesis to beat, not the assumed winner.
- Establish what one Tofino-1 can and cannot do for this problem, budgeted with real compiler
  categories, not just ingress-stage count.
- Establish where encryption, padding, fragmentation, and reassembly must live, and whether a local
  encapsulation function near the outstation is unavoidable.
- Define the proof obligations (functional correctness, transcript invariance, privacy-failure
  accounting) and the experiment plan that would discharge them.
- Deliver one decision: `GO`, `GO_WITH_BOUNDED_CLAIM`, or `NO_GO`.

Out of scope this phase:
- No production P4 pipeline, controller, gateway, or packet generator.
- No hardware loading, no switch configuration, no contact with the physical relay.
- No rewrite of the Defense 4 source. Defense 4 is a frozen upstream result we build on, not code we
  edit here.

Small read-only analysis or simulation scripts are allowed when they answer a concrete research
question, and small resource-only compile probes are allowed to measure a footprint. A design that
merely compiles is not a result and does not start implementation.

## Scope discipline

We do not reintroduce adaptive CRC splitting as a privacy solution, we do not use trailer padding
below IP, we do not use an adaptive packet count `K`, we do not assume a queue scheduler emits a
packet from an empty queue, we do not assume real and chaff traffic are indistinguishable without
encryption, and we do not treat an offline zero-mutual-information model as a working switch. We do
not mix this project with ADTA, GridCloak, the earlier fixed-K emulator, or the old multi-CROB
harness. We do not make a novelty claim before the closest-work comparison is finished.

## Provenance

Every reproduced number carries the source artifact and its commit or blob hash. The upstream pin is
recorded in `PROVENANCE.md` (source repo `/home/philip/Projects/DNP3` at commit `7c4a5a7`, treated
as strictly read-only). Analysis dependencies are pinned and runs use deterministic seeds and
encodings.
