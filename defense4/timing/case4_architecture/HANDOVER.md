# Case4 continuation checkpoint —2026-10-06

**Resume from the [core functionality and testing plan](PLAN.md).** It defines
the implementation order, required tests and acceptance criteria for each step.

Philip requested plans/handover instead of further experiments because weekly
tokens may run out. Development experiments are stopped. **The complete target
is absent and the assignment is unfinished.** Resume using the revised sequence
in [PLAN.md](PLAN.md); main packet forwarding comes before more architecture exploration.

Next: fix the four supported handshake retry/pure-ACK forwarding failures, using
the retained complete-byte counterexamples. Then complete one actual READ timing
path, followed by ordinary SELECT/OPERATE sizing and transport integration. Do
not restart standalone resource experiments. The planned `integration/core/`
candidate and full-packet harness are not implemented yet; existing tests execute
source fragments and do not prove that core path. Remaining loss/assembly/lifecycle
and qualification gates are specified in the linked plan, not dropped from scope.

Base is `a96a8e32758d498c58a3772ee774596658aad2d9`, branchmain. Work directly onmain,
preserve frozen sources/evidence/paper and unrelated local changes. Lead alone
commits, with `akekulip <akekulip@gmail.com>` as author AND committer and no
contributor trailers. This checkpoint does not authorize a push or hardware action.

## Reuse these actual results

| Current source / immutable compiler run | Local9.13.1 stage fit | Meaning |
|---|---:|---|
| `integration/egress_wire.p4` / egress_wire06 | 10ingress/7egress | Actual shared cache/READ/carving resource composition |
| `integration/egress_selected_wire.p4` / egress_selected_wire04 | 10/7 | Same banks plus configured object matching |
| `integration/read/validator.p4` / validator05 | 6/0 | Full READ packet/profile/link/CRC validation; original forwarding |
| `protocol/payload_mapping/forward.p4` / forward03 | 10/0 | Full32 two-boundary payload mapping/checksum adjustment |
| `protocol/payload_mapping/reverse.p4` / reverse12 | 11/0 | Inverse clamp plus both receive-window edges |
| `ownership/p4/held_timing_expected_probe.p4` / held_timing_expected02 | 12/0 | Actual originals, independent heartbeat, expected-phase qualification |
| `ownership/p4/original_credit_native_probe.p4` / original_credit_native04 | 4/0 | Epoch/cookie-qualified native receipt/debt primitive |
| `integration/handshake.p4` / handshake14 | 12/0 | Historical standalone protected handshake; old WorkRecord limitation |
| `integration/connection/selected.p4` / selected22 | 12/0 | Autonomous native object publisher/matching, not live epoch integration |

Full current source SHAs, binaries, schemas, compiler identity and resource hashes
are in `integration/evidence/verified_milestones_02.json` and each referenced
manifest. SDK9.13.1 is p4c e558d01; binary SHA
`e75d059fb5bba9cdf2bdda9a8430e31a997077e27dd3f156e5de34e38339ff41`.
Ignored licensed outputs stay local; rebuilding is required in a clean checkout.
Earlier successful snapshots cannot qualify later source changes.

## Exact blockers and defects

- **First fix: native retry/ACK forwarding.** Current native binding snapshot
  `8b2164a48bf4a8b0026f901fe4387952a0596ef0210730ba5a61a0093bd8b7be`
  drops valid SYN/SYNACK/final-ACK retries and established client ACKs through
  event01ff. Complete-byte counterexamples are retained in `ownership/review/`.
  This is unfixed; the current native source is uncompiled. ExpectedWorkRecord generation+emitted-phase/terminal checks
  were repaired; preserve them rather than reverting to gen-only qualification.
- Actual connection-binding composition still fails: native02 needs18stages;
  the actual two-pipeline alternatives need17–18 at the authority. Split03 source
  is `5e5074e9…`, with exact identity in its manifest. These are historical failed
  snapshots, not current native compile results. No third-pipeline build was
  started. Live receipt integration, transparent ACKs, READ/timing and safe reuse
  remain missing. No private physical topology has been verified.
- Shared scalar cache has an executable stale-descriptor/slot-overwrite example.
  Current owner pin and no-reuse are mandatory. Payload mapping has a16-byte
  producer envelope but no actual live WorkRecord gate. Configured context is
  not autonomous validation/publication. Carved physical order is unmeasured.
- Assembly's grouped, separate-worker, byte and staged layouts all fail PHV;
  even one four-bank worker fails48slices. Current producer04 fails460slices.
  `integration/assembly_passes/REPORT.md` states hypotheses, exact sources and
  additional unimplemented choices. Do not repeat annotations/packing.
- Holder still lacks native READ admission/join, full rekey/no-reuse lifecycle,
  service-loss qualification and measured40ms/physical-gap behavior. Internal
  commitment timestamps are not physical departure/drain measurements.
- Controller rollback relabeling was repaired: preparation and rollback both
  require a reviewed exact source/artifact/schema/profile/semantic-inventory
  identity. Registry is empty; no probe can be enabled or restored as qualified.
- Target model startup failed before packets because CAP_NET_RAW was unavailable.
  No target-model packet PASS,9.13.2 full build, activation, capture, physical
  OPERATE, measured campaign or saved-workload restoration occurred.

## Verified repairs and bounded checks

READ link/CRC/parser-error admission, descriptor-free response bypass, actual
shared-bank dispatch, source interpreter control/scalar-table handling, expected
work phase/terminal checks, and assembly parser/hop/deadline defects were repaired
with retained red witnesses. Assembly now refuses hops16 before writes; quantized
30ms expiry cannot accept a late write, with at most383ns early refusal.

Independent protocol review `protocol/review/evidence/verification_01` has18
passing checks, unchanged inputs,33/33 sealed hashes. It includes2560 deadline
residue/wrap cases and1260 legal fresh/duplicate cases per four-bank worker.
These execute source fragments, not the target. Fresh root verification is saved
under `integration/evidence/checkpoint_tests_01` (27 root +7 assembly passes);
controller17checks separately
verify the rollback repair. Historical endpoint/BMv2 results remain historical.

Reproduce only affected checks from this directory:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest discover -s integration/connection/binding/tests -p 'test_*.py' -v
python3 -m unittest discover -s integration/controller/tests -p 'test_*.py' -v
```

Compile changed candidates to a new evidence directory with `build.py`; never
overwrite retained evidence. `build.verify_evidence` refuses missing or changed
sources/includes/logs/compiler/schema/pipeline artifacts/resource summaries.
The campaign remains16,168 attempts≤18,360. No paper/figure edits are part of this
assignment. Preserve pre-existing `CLAUDE.md` changes and user prompt/untracked files.
