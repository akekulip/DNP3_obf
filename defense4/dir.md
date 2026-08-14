Act as the principal investigator and implementation lead for the next Defense 4 experiment. Work autonomously overnight. Use parallel specialist agents, but personally inspect their evidence, reconcile contradictions, run the decisive tests, and own the final conclusion.

Do not stop after writing a plan or literature review. Inspect the repository, restructure the size work where necessary, implement the strongest feasible design, run all software/emulator/compiler tests available, commit and push the work, and leave a precise evidence-backed report.

## Scientific objective

Determine whether READ and SBO traffic can be made indistinguishable under a clearly declared size-and-segmentation observer without switch-side byte insertion.

The primary design is:

1. The master and SEL-751 are configured with real and decoy output points.
2. Even-numbered objects are real.
3. Odd-numbered objects are decoys.
4. SBO requests contain the real CROB plus enough configured odd CROBs to produce a desired response size natively.
5. READ requests include suitable configured real/decoy measurement or status objects so the relay produces a matching response size natively.
6. The Tofino does not insert or delete stream bytes.
7. If needed, the Tofino deterministically splits native TCP payloads only at completed DNP3 link-layer CRC block boundaries.
8. Defense 4 timing normalization remains the timing mechanism.
9. The final claim must distinguish packet-count/size equality from equality against a parser-aware DNP3 observer.

This is endpoint-assisted native cover generation, not transparent switch-only padding. State that honestly.

## Current state you must verify

Begin from:

* Branch: `defense4-size-readsbo-normalizer`
* Expected head: `0b6fdba6bff43a81c4315331bb5630cf789c97c1`
* Parent setup commit: `d32187d`
* Prior baseline: `979426f`
* Project path: `DNP3_obf/defense4`

Do not trust summaries. Inspect the actual commits, source, tests, evidence, compiler logs, and documentation.

The present pad-normalization result must be treated as an unsafe negative probe, not as a deployable kernel:

* A native response at TCP sequence 1000 with length 40 is emitted as 64 bytes.
* The next native response starts at sequence 1040.
* Without forward sequence translation, the next response overlaps the inserted region `[1040,1064)`.
* Exact retransmission is also inconsistent: first emission can be 64 bytes and retransmission 40 bytes at the same sequence.
* Partial ACK inversion, teardown, resegmentation, and continuing response translation are not implemented.
* The existing conformance test appears to advance the next native sequence by the padded size instead of the native size.
* Arbitrary zero bytes after a valid application object are not automatically legal DNP3 padding.
* Current feature comparison uses hard-coded metadata in places where actual serialized packets must be parsed.
* The P4 does not implement native request parity or configured decoy CROBs.
* The setup script still targets the earlier split kernel and rejects the real 40/49-byte sizes.
* Do not repeat the categorical statement that continuous normalization is universally impossible on one Tofino-1. The current insertion design is unsafe and the single-register approach is inadequate; that is narrower and defensible.

No switch load, port configuration, relay configuration writes, physical SELECT, or physical OPERATE is authorized in this run. Software, OpenDNP3, packet emulation, tofino-model/PTF if already available, and `bf-p4c` compilation are authorized.

## Git and preservation rules

Run preflight and record:

```bash
git status --short
git branch --show-current
git rev-parse HEAD
git log --oneline --decorate -15
git remote -v
```

If the expected starting commit is present, create:

```text
defense4-size-native-parity-crc-split
```

Preserve all history. Do not amend, rebase, reset, clean, force-push, or merge to main. Do not delete prior negative experiments.

Use this identity for new commits:

```text
akekulip <akekulip@gmail.com>
```

Do not add Claude, AI, agent, or co-author attribution to commits or files.

Do not modify the frozen silicon-proven timing source:

```text
defense4/timing/p4/defense4_caseA.p4
```

Create sibling kernels and explicit composition artifacts.

## Organize parallel agents

Use specialist agents with concrete deliverables:

1. `protocol_length_synthesizer`

   * Derive exact legal DNP3 request and response encodings.
   * Build a length and CRC-boundary solver.
   * Work from serialized packets, not remembered constants.

2. `opendnp3_endpoint_engineer`

   * Implement the configured real/decoy point strategy in the existing master and outstation harnesses.
   * Exercise full SELECT-before-OPERATE behavior.
   * Capture raw requests, responses, command statuses, and logs.

3. `tofino_crc_split_engineer`

   * Design and implement a byte-preserving CRC-boundary splitter.
   * Preserve TCP stream semantics, options, flags, lengths, and checksums.
   * Compile it without loading hardware.

4. `transport_adversary`

   * Independently attack retransmission, overlap, partial segments, coalescing, clone loss, flags, options, and checksum behavior.
   * Attempt to falsify the proposed design before editing it.

5. `evidence_red_team`

   * Audit all final claims against raw captures, serialized bytes, test output, and compiler artifacts.
   * Reject metadata-derived “proof” where packet parsing is required.

Agents may work in parallel. As PI, review their source and rerun decisive tests yourself.

## Primary architecture: native size by construction

The switch must not invent padding bytes.

For SBO:

* Build the CROB collection at the master using OpenDNP3’s multi-command request support.
* Put the even real CROB and one or more configured odd decoy CROBs into the same `CommandSet`.
* Use SELECT on the complete set.
* OPERATE must repeat the exact same object headers, indices, values, ordering, timing fields, and control codes required by SBO semantics.
* Parse and verify every per-object status.
* Never silently ignore a failed decoy.
* Never use an index that is not configured at both endpoints.

For READ:

* Search for a legal configured collection of real and decoy data/status objects that makes the relay’s native response equal to the target SBO response size.
* Prefer ordinary relay database objects and standard group/variation encodings.
* Do not append opaque filler after an object.
* Verify that the candidate encoding is accepted by the actual OpenDNP3 stack and is plausible for the SEL-751 configuration.

The odd points are not merely “currently open.” Before any later physical experiment, they must be proven physically disconnected or unmapped from breaker control. This run must document that as a mandatory hardware prerequisite, but must not perform relay writes or physical operations.

## Exact length synthesis

Build a solver instead of choosing lengths manually.

For a DNP3 link frame with `u` bytes after the link header, check the candidate wire-size model:

```text
link_size(u) = 10 + u + 2 * ceil(u / 16)
```

Verify this formula against actual serialized frames and account for the exact convention used for `u`.

Begin with, but do not assume, these hypotheses:

### Multi-CROB SBO hypothesis

For one Group 12 Variation 1 header using a suitable indexed qualifier:

```text
u_SBO(K) ≈ 9 + 12K
```

This is suggested by:

* one CROB response/request family near 35 bytes,
* two CROBs near 49 bytes,
* predicted further sizes near 61, 75, and 89 bytes.

Derive the real formula from raw bytes. Determine whether OpenDNP3 emits one shared object header, repeated object headers, one-byte prefixes, two-byte prefixes, or another representation.

### Binary-output-status READ hypothesis

For Group 10 Variation 2 or another one-octet-per-point flags representation:

```text
u_READ(N) ≈ 10 + N
```

If legal and configured, a range around 23 points may produce a 49-byte link frame and match a two-CROB SBO. Verify exact headers, qualifiers, range fields, fragmentation, and native response bytes.

### Analog READ hypothesis

For a Group 30 Variation 1-style representation with flags plus a 32-bit value:

```text
u_READ(N) ≈ 10 + 5N
```

A range around seven points may produce a size near 61 bytes and could match a three-CROB SBO. Again, derive from actual serialization.

Enumerate at least:

* legal READ groups and variations supported by the current harness,
* one-byte versus two-byte ranges and prefixes,
* start/stop versus count versus indexed qualifiers,
* one shared G12 header versus multiple G12 headers,
* different counts of odd decoys,
* response fragmentation behavior,
* confirmed configured point ranges,
* complete DNP3 wire length,
* TCP payload length,
* every DNP3 CRC boundary,
* final residual-block length.

Search for intersections where READ and SBO have:

1. equal native TCP payload sizes;
2. preferably equal DNP3 link-block geometry;
3. manageable decoy counts;
4. no unsafe physical interpretation;
5. parser-valid objects;
6. support in both OpenDNP3 and the intended relay configuration.

Produce a Pareto table with:

* candidate ID;
* READ encoding;
* SBO encoding;
* real objects;
* decoy objects;
* native size;
* CRC-boundary offsets;
* point-configuration burden;
* parser-visible differences;
* physical risk;
* OpenDNP3 result;
* likely SEL-751 compatibility;
* selected/rejected reason.

An important experimental idea is residue-class engineering: if simple object counts do not intersect, vary legal fixed overhead by using different qualifier widths or more than one legal G12 object header. This may change the size residue enough to create an exact intersection. Test it; do not dismiss it from intuition.

## CRC-boundary segmentation

After finding a native common response size `S`, implement a deterministic splitter that preserves the byte stream exactly.

For one DNP3 link frame, candidate completed-block boundaries generally occur after:

```text
10, 28, 46, 64, ...
```

plus the end of the final residual block. Derive these from parsed frame structure, not packet length alone.

Examples to investigate:

* For `S = 49`, boundaries are approximately `10, 28, 46, 49`. Prefer a balanced split such as `[28, 21]` over `[46, 3]`.
* For `S = 61`, boundaries are approximately `10, 28, 46, 61`. Candidates include `[28, 33]` and `[46, 15]`.

If segmentation equality is part of the observer, apply the same deterministic split signature to both READ and SBO responses. “Split READ and pad SBO” should be reinterpreted as:

* SBO is enlarged natively by legal configured decoy CROBs.
* READ is enlarged natively by legal configured decoy/status objects if necessary.
* The switch emits the same byte-preserving segment-length vector for both classes.

For every generated TCP segment:

* The concatenated TCP payload must be byte-for-byte identical to the original payload.
* First segment sequence = original sequence.
* Subsequent segment sequence = original sequence plus its byte offset.
* ACK number and window are preserved.
* PSH and FIN belong only on the final segment.
* Clear them on earlier segments.
* Handle RST conservatively.
* Recompute IPv4 total length, IPv4 checksum, and TCP checksum.
* Preserve or explicitly constrain TCP options based on observed captures.
* Preserve packet direction, addresses, ports, and ownership predicates.
* Do not translate sequence or acknowledgment space.
* Do not alter application bytes.
* Respect MTU.
* Fail open for ineligible or ambiguous packets.

Investigate mirror-to-multicast-plus-drop-source, cloning, recirculation, or another TNA-supported replication method. Compile evidence is not runtime silicon proof. Label runtime replication behavior as unproven until a later authorized hardware gate.

Exact retransmission of an identical native packet must generate an identical pair of segments. A partial or differently segmented retransmission may safely pass natively if the splitter cannot prove eligibility; this can leak a feature, but it must never corrupt the stream.

Test the consequence of losing either generated segment. TCP retransmission should cause deterministic regeneration, and the receiver should deduplicate by sequence number. Demonstrate this in the emulator.

## Endpoint-native application fragmentation alternative

In parallel, investigate whether native DNP3 application fragmentation is a better mechanism than switch TCP segmentation.

OpenDNP3 exposes configurable maximum transmit and receive fragment sizes on master/outstation parameters. Determine:

* whether the current master and outstation harnesses can force stable application fragment boundaries;
* whether those boundaries coincide with complete DNP3 object and CRC boundaries;
* whether the SEL-751 exposes a compatible setting;
* whether fragmentation produces identical packet-count and size vectors for the selected READ and SBO candidates.

Do not assume the relay supports the setting. Inspect available manuals, device profiles, existing configuration artifacts, and current harness behavior. If relay support cannot be established, preserve this as a software-demonstrated alternative with an explicit hardware-compatibility unknown.

## Secondary innovation: fixed observation-window cover

If exact per-transaction equality cannot be achieved, implement and evaluate a secondary endpoint-assisted design:

* Define a fixed poll epoch or observation window.
* Schedule only legal endpoint-originated decoy READ/SBO traffic.
* Make total byte count and ordered segment-size vector constant within that window.
* Use existing Defense 4 timing control to reduce transaction correlation.
* Do not insert bytes at the switch.
* Report the added traffic, latency, endpoint changes, and parser-visible residuals.

Do not silently substitute this for per-transaction equality. It is a separate claim.

## Last-resort bounded transport investigation

Only if native equality fails, revisit switch insertion as a bounded engineering question rather than declaring universal impossibility.

Measure from real PCAPs:

* maximum simultaneous unacknowledged responses;
* response serialization behavior;
* delayed ACK behavior;
* retransmission frequency;
* whether the relay ever emits a new response before the prior response is acknowledged.

Evaluate:

1. A one-active-boundary design with cumulative retired delta `C`, active insertion boundary `b`, and delta `d`.
2. ACK-gated response serialization using existing traffic-manager queues.
3. Small bounded ledgers of depth 2 and 4 in stage-local registers.
4. Recirculation or staged state access with quantified bandwidth cost.

Compile each bounded counterdesign before rejecting it. Do not load it. If it fails, record the exact compiler/resource/semantic reason.

This is subordinate to the native no-insertion design.

## Safety invariants

These invariants are non-negotiable:

* Even point indices are real.
* Odd point indices are decoys.
* Every referenced point exists in both master and relay configurations.
* Odd outputs must eventually be proven physically disconnected or to have no breaker mapping.
* SELECT and OPERATE use the identical command set required by SBO semantics.
* The real callback occurs exactly once.
* Odd callbacks are inert in the test outstation.
* A failed decoy status fails the parity operation.
* Unconfigured, mismatched, duplicate, reordered, or mutated commands are rejected or reported.
* No direct OPERATE shortcut.
* No physical command transmission in this run.
* No endpoint proxy, paired gateway, arbitrary opaque filler, or fixed-K fallback disguised as the result.

## Observer definitions

Make the claim conditional on the observer.

At minimum implement:

### `O_count+segmentation`

The observer sees:

* direction;
* packet count;
* ordered TCP payload-length vector;
* timing bucket;
* retransmission pattern.

Acceptance target:

* READ and SBO use the exact same ordered response payload-length vector in the declared transaction or poll window.
* No switch byte insertion or deletion occurs.

### `O_parse_link`

Additionally parses:

* link source/destination;
* link control;
* DNP3 block layout;
* application fragment boundaries;
* function code and IIN where visible.

### `O_parse_app`

Additionally parses application objects, indices, values, qualifiers, and statuses.

### `O_profile/config_known`

Knows expected device polling and configured point map.

Run the observer against real serialized packets, not hard-coded labels. Link addresses, ordering, control fields, and object counts must be derived from bytes.

It is acceptable—and likely—that parser-aware observers still distinguish READ from SBO. Report that residual honestly. Do not claim full O2/DPI equality unless the actual parsed feature vectors are equal.

Do not claim device anonymity or generalize beyond the tested relay/model corpus.

## Repository restructuring and deliverables

Create a coherent size-native-parity area, for example:

```text
defense4/size/native_parity/
    NATIVE_PARITY_SPEC.md
    THREAT_MODEL.md
    length_synth.py
    test_length_synth.py
    candidates.json
    candidates.csv
    CANDIDATE_REPORT.md

    endpoint_harness/
        README.md
        master/
        outstation/
        tests/
        evidence/

    offline/
        crc_split_emulator.py
        test_crc_split_conformance.py
        observer.py
        test_observer.py
        fixtures/

    p4/
        defense4_crc_split_kernel.p4
        defense4_crc_split_setup.py
        README.md

    evidence/
        manifest.json
        commands.txt
        test_summary.txt
        compile/
        captures/
        packet_vectors/
        hashes/
```

Adapt this to the repository’s existing conventions. Do not duplicate stable shared utilities unnecessarily.

Update stale documentation to say:

* `0b6fdba` demonstrates application-block reconstruction but is unsafe as a persistent TCP transformer.
* The prior “universal impossibility” conclusion is narrowed.
* The new primary route is endpoint-native legal cover plus byte-preserving segmentation.
* Timing normalization remains the silicon-proven component.
* Size/segmentation work remains software- and compile-proven until a later hardware gate.

Fix contradictory physical-evidence language, including any claim that “no control was ever transmitted” if an earlier baseline did transmit a SELECT or OPERATE. Separate:

* configuration evidence;
* SELECT evidence;
* OPERATE evidence;
* mid-pulse observation;
* point-state result;
* PCAP/log evidence;
* statements that remain narrative-only.

Do not fabricate missing proof.

## Required tests

At minimum, add tests for:

### Native length synthesis

* Multiple READ group/variation/count combinations.
* CROB counts from 1 through the supported maximum.
* Shared and repeated object headers.
* One-byte and two-byte qualifier/prefix cases.
* DNP3 CRC validation.
* Exact link and TCP payload lengths.
* Candidate intersections.
* Mutation of every fixed overhead assumption.

### Endpoint semantics

* SELECT contains the exact even/odd set.
* OPERATE repeats it exactly.
* Real point callback exactly once.
* Odd point callbacks inert.
* Every object status parsed.
* Decoy failure.
* Real failure.
* Unconfigured point.
* Missing decoy.
* Added object.
* Reordered object.
* Value mismatch.
* Timing/control-code mismatch.
* Duplicate request.
* Exact retransmission.
* Direct OPERATE rejected where SBO is required.

### Splitter

* Reassembly byte-for-byte identical to original.
* Sequence offsets correct.
* ACK/window preserved.
* PSH/FIN only on last segment.
* RST behavior.
* TCP options.
* IPv4 length/checksum.
* TCP checksum.
* MTU.
* Wrong direction/port/owner.
* Short/incomplete DNP3 frames.
* Coalesced DNP3 frames.
* One frame split across input TCP packets.
* Invalid DNP3 CRC.
* Out-of-order input.
* Overlapping retransmission.
* Exact retransmission.
* Partial retransmission.
* Clone loss and TCP recovery.
* Mutation tests proving the test suite detects broken offsets, flags, lengths, checksums, and CRC boundaries.

### Observer

* Parses raw frames and segments.
* Produces feature vectors from bytes.
* Demonstrates equality or inequality separately under each observer.
* Does not use packet-class metadata as a substitute for parsing.

## Compilation

Compile any P4 kernel using the repository’s expected BF-SDE 9.13.1 environment.

Record:

* exact compiler command;
* compiler version;
* source hash;
* output hash where appropriate;
* warnings;
* errors;
* stage/resource reports;
* result of a clean rebuild.

Do not commit large compiler outputs, SDK binaries, caches, build directories, credentials, PCAPs containing unrelated traffic, or machine-specific absolute paths. Commit concise evidence manifests, hashes, relevant logs, and reproducible commands.

The setup script must:

* import without BFRT installed;
* lazily import BFRT;
* gate every hardware write behind `DEFENSE4_HW_AUTHORIZED`;
* default to a dry-run or inspection mode;
* refuse unsafe or unsupported size/split configurations;
* identify the exact P4 program and table/register names;
* provide a documented restore path;
* perform no hardware action during this run.

## Acceptance gates

### Gate N — native equality

Pass only if actual serialized READ and SBO response traffic has an exact common native size or declared common segment vector using legal configured objects.

### Gate E — endpoint semantics

Pass only if the full OpenDNP3 flow demonstrates correct SELECT-before-OPERATE, exact even/odd parity, per-object statuses, and inert decoys.

### Gate S — stream-safe segmentation

Pass only if reassembly is byte-identical and adversarial transport tests show no sequence-space translation or corruption.

### Gate O — observer result

Pass or fail independently for each observer. Do not collapse a packet-size success into a full-DPI success.

### Gate C — compiler

Pass only with a recorded reproducible clean `bf-p4c` result.

### Gate P — hardware

Explicitly blocked. Do not load or touch hardware.

## Research anchors

Use primary sources where available:

* OpenDNP3 master guide and multi-command `CommandSet`/`SelectAndOperate` behavior:
  https://github.com/dnp3/opendnp3-guide/blob/master/docs/api/masters.md

* OpenDNP3 outstation parameters, including `maxControlsPerRequest`, `maxTxFragSize`, and `maxRxFragSize`:
  https://dnp3.github.io/docs/cpp/3.0.0/d4/d39/structopendnp3_1_1_outstation_params.html

* OpenDNP3 master fragment-size parameters:
  https://dnp3.github.io/docs/cpp/3.0.0/da/d4b/structopendnp3_1_1_master_params.html

* DNP3 application-fragment guidance: a fragment contains a complete application header and parseable objects; arbitrary trailing bytes are not a valid padding assumption:
  https://www.dnp.org/LinkClick.aspx?fileticket=bTubmc6O7kg%3D&forcedownload=true&mid=447&portalid=0&tabid=66

* Lucid/Tofino state and recirculation model:
  https://www.cs.princeton.edu/~dpw/papers/lucid-SIGCOMM-2021.pdf

* Public Tofino Native Architecture material:
  https://github.com/barefootnetworks/Open-Tofino/blob/master/PUBLIC_Tofino-Native-Arch.pdf

Research is supporting work, not the deliverable. The deliverable is tested repository code and evidence.

## Final commit and report

Commit logical milestones and push the new branch. Before finishing, rerun the decisive tests from a clean state and record:

```bash
git status --short
git branch --show-current
git rev-parse HEAD
git log --oneline --decorate -15
```

Your final report must begin with a plain conclusion, then provide:

1. selected native READ/SBO construction;
2. exact point indices and why each is real or decoy;
3. actual serialized sizes and CRC boundaries;
4. exact emitted TCP payload-length vectors;
5. endpoint semantic results;
6. observer-by-observer equality matrix;
7. adversarial transport results;
8. P4 compile result and resource summary;
9. mutations killed;
10. residual distinguishers;
11. assumptions about SEL-751 point configuration;
12. all hardware steps still prohibited or awaiting authorization;
13. commits created;
14. pushed branch and exact final SHA;
15. clean/dirty tree status;
16. strongest next experiment.

If no legal native size intersection exists, do not force a positive result. Preserve the solver and evidence, explain the exact arithmetic/protocol obstruction, report the observation-window and bounded-ledger results separately, and identify the smallest configuration or observer change that would make the experiment feasible.

The desired outcome is not “prove the idea works.” It is to identify and implement the strongest stream-safe design that survives protocol parsing, endpoint semantics, transport adversaries, and compiler reality.
