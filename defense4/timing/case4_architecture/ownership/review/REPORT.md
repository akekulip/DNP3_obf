# Independent native binding and controller review

This bounded review found two reproducible correctness bugs. Native forwarding
repair remained pending at the stop boundary. Controller restore now contains a
reviewed-registry guard; its repair was inspected but not independently rerun.
This report does not qualify a complete target or approve hardware use.

Scope was native binding/generator/reference/tests, controller preparation and
performance accounting. Only `ownership/review/` was written. No compile,
model, hardware, network traffic, commit or push was initiated by this review.
The user stopped further experiments for the weekly token limit.

## Exact reviewed source

[source_01/inventory.json](source_01/inventory.json) binds the retained source.
Native binding was `8b2164a48bf4a8b0026f901fe4387952a0596ef0210730ba5a61a0093bd8b7be`;
its ExpectedWorkRecord was `26b2019ec6e549e22e98cf8361ee208952bd1cc94021d2ea56b9f8bc88571ef2`.
Controller preparation was
`60673c0c5f76fca402750b95bc8e533f168d21f6ac9524a04a11d8d87de43b5f`.

The existing `binding/evidence/native_02` is a different retained source
`93312c121976c79f1542c3e714da4467f7e88d4c40c739540300cdffb4018569`.
Its exit code2/`compile_failed` log says18 ingress stages, exceeding12. It is
not compiled-current-source evidence for the reviewed native source.

## HIGH: valid native retries and established ACKs lose their original bytes

[Native first-event selection](source_01/integration/connection/binding/native_binding.p4:193)
recognizes initial handshake transitions only. Source claim happens before that
selection; [snapshot](source_01/integration/connection/binding/native_binding.p4:184)
starts with private event0x01ff. A valid retry outside its initial owner phase
retains this abort event. The real terminal branch then strips its prefix and
calls deny, dropping the original packet.

Four complete checksum-valid IPv4/TCP witnesses reproduce this behavior:

| Actual packet | Existing owner | Emitted private event | Actual terminal drop |
| --- | ---: | ---: | ---: |
| Native SYN retry after lost SYN forwarding | 0x00020001 | 0x01ff | 1 |
| Native SYNACK retry after lost SYNACK forwarding | 0x00040001 | 0x01ff | 1 |
| Native final-ACK retry | 0x00050001 | 0x01ff | 1 |
| Ordinary established client ACK | 0x00090001 | 0x01ff | 1 |

[counterexamples.py](counterexamples.py) and [counterexamples.json](counterexamples.json)
retain the complete bytes and evaluate the actual snapshot/first-event/terminal
source bodies. Independent byte parsing verifies the supported network shape
and checksums. This is restricted source-fragment execution, not a target parser
or queue/model run. Work generation/phase safety alone does not conserve these
originals.

Fix: recognize qualified native handshake retries and established ACKs as
nonmutating forwarding events, preserve actual original bytes through their
real terminal, and guard full current epoch/owner and actual full sequence
relations. Do not remint an application attempt or connection epoch.

The binding owner confirmed the witnesses and began an explicit private kind8
forwarding repair. At the final source inspection, native binding still had the
reviewed8b2164a4 hash and no forwarding repair. **Pending/unverified.**

## HIGH: caller relabeling can restore active runtime ownership

[configuration_rollback](source_01/integration/controller/preparation.py:161)
checked caller-supplied identity and inventory hashes, then trusted both the
inventory and snapshot's lifetime labels. It did not consult the reviewed
qualification registry. Relabeling the whole inventory's `timing_owner` as
configuration, recomputing its digest and supplying a matching expected identity
returned a write of0x80000001 to the owner while reporting
`runtime_state_restored: false`.

The pure mock-schema witness is retained in counterexamples.json. It performs
no hardware write. The pre-existing regression changed only snapshot labels;
it did not cover relabeling both supposed canonical inventory and snapshot.

Fix: bind rollback's complete identity and semantic inventory to trusted
qualification, rejecting caller enrollment or lifetime relabeling. Preserve
configuration-only restore and explicit mock separation.

Final controller source hash was
`d5b2121bea9482027e0f223155e6e0bbcbba4530eff120cdf492ed3f9d91c13f`.
Its rollback now calls `_qualification(identity, mock=mock)` before producing
actions. The empty production registry refuses the original caller-enrollment
case by source inspection. The implementation owner reports17 controller tests
passing, including refusal of the two old-source relabeling witnesses; mock
rollback requires explicit mock=True. **Source repair present and owner-tested;
this independent lane did not rerun post-fix tests before the requested stop.**

## Pin, receipt and accounting boundaries

The reviewed native source uses atomic full generation plus actual emitted
phase equality before advancing WorkRecord. Op3 is full-reference inspection
without a phase mutation; it does not fabricate a writer terminal. The final
actual return releases the producer. This addresses the frozen older helper's
duplicate/reordering and stale-close advancement assumptions.

The reviewed native source has no native OriginalCredit/debt installation or
retirement/reuse implementation. No zero-debt or no-old-writers input can be
certified from it. Future receipt installation must acquire the actual shared
connection producer grant, read real debt under that grant, retain every writer
pin across all receipt/tuple/cache writes, and release only on a later genuine
terminal. An asserted flag, transaction nonce, work-free read before claim or
missing receipt cannot authorize reuse. These are still composition gates,
not fixes silently supplied by this review.

Preparation remains offline, hardware_authorized staysfalse, the production
qualified registry is empty, and target9.13.2/schema/resource identity gates
remain required. Actual loaded identity, ports, physical drain and readbacks
are unavailable. Performance accounting preserves44 blocks/16168 attempts and
keeps missing circulation/repair/heartbeat service quantities unavailable.
Supplied pass/transfer/holding scenarios remain scenarios; they cannot prove
complete fit, worst-case service, actual bandwidth or the40ms cap.

## Handover

1. Finish and independently recheck the native retry/ACK forwarding repair.
2. Independently rerun whole-inventory rollback relabeling against the repaired
   reviewed-registry guard and preserve permitted configuration/mock cases.
3. Retain native02 as18-stage failure. Obtain current exact-source fit only when
   experiments resume; do not report primitive or historical evidence as full fit.
4. Keep actual receipt/no-reuse, native timing publication, complete coexistence,
   model/port/hardware and measured service gaps explicit.

No complete-target approval or hardware authorization is issued.
