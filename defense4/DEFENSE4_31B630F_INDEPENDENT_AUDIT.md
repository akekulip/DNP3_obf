# Independent audit of Defense 4 commit `31b630f`

Audit date: 2026-08-11/12 (America/New_York)  
Repository: `https://github.com/akekulip/DNP3_obf.git`  
Branch: `defense4-size-read-range-probe`  
Audited commit: `31b630fedd65f62a01bbc16aa323882f011fec89`  
Parent: `e6e15177f7f51a6233949a8ad4da623e088b568b`

## Executive verdict

The commit is real, published, internally consistent as a Git object, and contains substantial genuine corrections. The timing rerun, constructed cover convergence, OpenDNP3 application-context evidence, decoy round trip, compile-resource evidence, and most of the documentation reclassification are useful progress.

It is **not ready for a physical Tofino/SEL-751 experiment** and should not be described as having a passing transport or compile-level integration gate. Two blockers are decisive:

1. The 46/46 transport oracle mishandles a new connection that reuses a quarantined 5-tuple: its data is translated with the old epoch instead of being denied or isolated.
2. The compiled P4 emits a cover with placeholder, invalid DNP3 CRCs and wire-order-reversed addresses. Its scalar `delta/last_seq` state does not implement the offline oracle's boundary ledger and fails important TCP lifecycle, reordering, option, fragmentation, collision, and teardown cases.

Overall disposition: **major correction required; preserve `31b630f` as a checkpoint, branch from it, remain software/compile-only, and do not load `defense4_cover_kernel.p4`.**

## Repository and provenance verification

| Item | Independent result |
|---|---|
| Live remote branch | `git ls-remote origin refs/heads/defense4-size-read-range-probe` returned `31b630fedd65f62a01bbc16aa323882f011fec89` |
| Local vs remote | `0 0`; exact synchronization |
| Author and committer | `akekulip <akekulip@gmail.com>` |
| Attribution | No Claude/co-author attribution in the commit object |
| Parent chain | `31b630f` → `e6e1517` → `5541d78` → `246630e`; ancestors preserved |
| Main | Audited commit is not an ancestor of remote `main`; branch is not merged (`HEAD...main = 4/509`) |
| Change size | Exactly 53 paths, `+12,175/-1,882` |
| Worktree after audit | Clean; the audit did not alter the repository |
| `dir.md` | Its claimed local untracked/excluded status cannot be verified from GitHub because it is not in the commit |

All 53 changed paths were inventoried. Changed code and decision documents were reviewed; generated evidence was checked against manifests and regenerated where the current environment permitted. The committed OpenDNP3 C++ executables could not be rebuilt here because the required sibling OpenDNP3 checkout and CMake are absent. Their source, stored output, environment metadata, and available SHA manifests were inspected instead. This is a reproducibility limitation, not a silent rerun claim.

`git diff --check e6e1517..31b630f` is not clean. It reports CRLF/trailing whitespace in generated CSV/JSON metrics and a few blank EOF lines. This is mostly generated-file hygiene rather than a functional defect, but it should be cleaned or explicitly normalized.

## Independently reproduced or internally verified results

| Area | Result | Audit interpretation |
|---|---|---|
| Timing unit tests | 29/29 pass | Real deterministic tests, but they encode two disputed modeling choices described below |
| Timing regeneration | 30 datasets, 0 schema warnings, 30 `UNPINNED` firmware fields; regenerated `results.json` and `REPORT.md` are byte-identical | Reproducible analysis over committed evidence |
| Transport suite | 46/46 pass | The suite is green, but it omits a decisive tuple-reuse case and therefore cannot justify gate PASS |
| Observer scorer | 9/9 self-checks pass | Cover parsing is evidence-driven; READ temporal and SBO conclusions remain constructed/hard-coded |
| Cover convergence | 18 B and 45 B constructed frames each become a 63 B serialized DNP3 stream; regenerated outputs byte-identical; all four frames pass CRC verification | Valid offline construction for a counting observer, not a captured TCP transaction |
| Cover SHA manifests | Both manifests pass | Key source and generated convergence files match |
| Cover OpenDNP3 evidence | Stored output: 263 assertions + 130 assertions; OpenDNP3 commit `4648fcb...` | Supports a bounded in-process application/link-filter result, not a real full transport/TCP result |
| Decoy evidence | Stored output totals 729 assertions; source manifest passes; OpenDNP3 commit `4648fcb...` | Strong application-layer software evidence, bounded as described below |
| P4 compile evidence | Source SHA `570abb57...` matches; bf-p4c 9.13.1 stored result has exit 0, 0 errors/3 warnings, 76 tables, 41 SRAM, 4 TCAM, 20 MapRAM | Valid evidence of compiler fit for this source; not functional correctness |
| Shell syntax | New cover/decoy `run.sh` scripts pass `bash -n` | Syntax only |

The timing rerun reports the selected analysis-only `(D_A,D_R)=(2,12)` with `H=14 ms`, point coverage `0.9917`, Wilson 95% interval `[0.9701,0.9977]`, and validation-pool coverage `0.9875`. The reported `L_master` maximum is `19.244 ms` (validation-pool maximum `24.857 ms`), so it is correctly no longer claimed to be H-bounded.

## Blocking findings

### B1. Transport oracle translates new-epoch data through the old epoch

Files: `defense4/size/offline/transport_oracle.py`, `test_transport_oracle.py`, `README.md`.

The README says that when a 5-tuple is reused while its old flow is quarantined, new-connection data is denied coverage until retirement. The implementation does not do that. A reused SYN only writes `_isn_hint`; the exact-key lookup for the next data packet returns the old `Flow`, and the packet is translated using the old ledger.

Independent reproduction:

```text
old insertion:           seq=1000, pad=7, outcome=TRANSLATED_INSERTED
reused-tuple SYN:        seq=9000, outcome=NATIVE, next ISN hint=9000
new-connection data:     input seq=9001, output seq=9008, outcome=TRANSLATED
old Flow ISN remains:    1000
```

The existing tuple-reuse test sends a reused SYN, then tests an old lingering packet, retires the old flow, and only then sends new data. It never tests new-epoch data before retirement. The gate is therefore false-green.

Additional oracle gaps:

- An insertion at the same boundary and size but with a different `template_id` is treated as idempotent; it silently re-emits the old template. Template identity must be part of exact retransmit equivalence.
- SACK negotiation is supplied as a per-data-segment boolean instead of being learned and retained from the SYN/SYN-ACK handshake.
- The timeout is a logical same-flow packet clock and is evaluated only when that flow is processed. A missing final ACK can leave state forever if no later packet hits the flow.
- Delayed duplicates after full retirement/TIME_WAIT need an explicit safe policy.
- The README's “mutation-checked” statement is narrative. No committed mutation harness or machine-readable mutation results demonstrate it.

Required disposition: add failing regression tests first; implement a real connection/epoch discriminator or strictly deny all ambiguous tuple-reuse traffic until safe retirement; add explicit wall-clock/sweep semantics and handshake-derived eligibility.

### B2. The P4 cover is not CRC-valid and its addresses are wire-order reversed

File: `defense4/size/p4/defense4_cover_kernel.p4`.

The source simultaneously calls the fixed cover CRC-valid and defines:

```p4
COVER_DST    = 0x0032;
COVER_SRC    = 0x0001;
COVER_DL_CRC = 0xABCD; // placeholder
COVER_BCRC   = 0xEF01; // placeholder
```

P4 emits `bit<16>` fields in network byte order. The resulting 16 bytes are:

```text
05 64 09 44 00 32 00 01 AB CD C0 C1 02 00 EF 01
```

Independent CRC-16/DNP calculation gives:

```text
CRC(header 05 64 09 44 00 32 00 01) = wire FB 33, not AB CD
CRC(body   C0 C1 02 00)             = wire D8 2E, not EF 01
```

For intended little-endian DNP3 destination `0x0032` and source `0x0001`, the correct serialized fixed frame is:

```text
05 64 09 44 32 00 01 00 50 C7 C0 C1 02 00 D8 2E
```

This alone invalidates any functional or physical-load claim. A compile correctly proves only that the source fits.

### B3. The P4 transport is not the offline transport oracle

The P4 holds only cumulative `reg_delta`, one `reg_last_resp_seq`, and one `reg_dlast`. It does not implement the oracle's insertion-boundary step function or multiple-entry ledger. Consequences found by static trace:

- Retransmitting an older response after a newer one is classified as fresh, reinserts another cover, and grows the delta again.
- Forward sequence translation adds total delta to every packet, even an old/out-of-order packet preceding one or more insertion boundaries.
- Reverse ACK translation subtracts total delta regardless of ACK position. Duplicate ACKs before an insertion, ACKs within padding, and out-of-order ACKs are wrong.
- The first response with TCP sequence zero is falsely classified as a retransmission because `reg_last_resp_seq` initializes to zero and has no valid bit.
- `reg_last_resp_seq` and `reg_dlast` are not retired with the delta and can poison a later connection.
- Any SYN, FIN, or RST executes `delta_reset` before checking ownership. A foreign flow colliding on the 10-bit register index can reset a protected flow.
- FIN immediately resets state; FIN sequence/ACK translation, two-sided FIN acknowledgment, and final-ACK translation from the offline oracle are not implemented.
- A retransmission can bypass the MTU guard merely because `is_retx` is true.
- There is no explicit epoch/wrap discriminator.

The code and documentation must stop saying the P4 runs the offline oracle until conformance tests exercise one shared vector corpus against both models.

### B4. Unsupported TCP options and IP fragments are transformed and can be corrupted

The egress parser comment says `dofs>5` should pass unchanged. It accepts such packets without depositing the residual checksum, but egress has no eligibility bit. It still classifies, translates, may add a cover, and recomputes TCP checksum from a fixed 20-byte header plus zero residual—omitting TCP options and payload.

There is also no IPv4 fragmentation guard. A non-initial fragment can be parsed/transformed as if it had a TCP header. SACK-permitted negotiation is not parsed or retained in P4 despite being a stated eligibility condition.

Required disposition: add explicit parser-derived `eligible` metadata and fail-closed bypass before every state access or mutation; cover IP fragments, IP/TCP options, malformed lengths, SACK handshake, and checksums with packet-vector tests.

### B5. The P4 does not implement the demonstrated convergence policy

The offline convergence result uses a 45-byte cover for the 18-byte native profile and an 18-byte cover for the 45-byte profile, reaching 63 bytes in both cases. The P4 always prepends one fixed 16-byte cover. It therefore enlarges responses but does not drive different native sizes to a common public target. There is no target-size/template policy table.

Calling this a size-normalization integration gate is incorrect even if its CRC and transport bugs were fixed. It is presently a fixed-enlargement compile probe.

### B6. The proposed physical experiment is unsafe and not the next justified step

`SIZE_CANDIDATE_DECISION.md` recommends loading the kernel and capturing a physical SEL-751 transaction. Because the emitted cover is invalid and the TCP state machine has the defects above, that recommendation must be withdrawn. The next justified work is software packet-vector conformance plus a clean bf-p4c compile of the repaired or honestly downgraded kernel. No hardware action is justified by `31b630f`.

## Major analytical and evidence findings

### M1. Observer scoring is only partly evidence-driven

`observer_scoring.py` claims to parse `decoy_gate/out/partB_read.txt`, but never opens it. It constructs new READ responses in code using hard-coded counts, values, and zero-valued sentinel decoys. The actual OpenDNP3 test creates decoy values `50000 + index`, not zeros.

The `O_parse_profile` temporal-residual conclusion uses one constructed snapshot, not repeated reads or time-series evidence. It can label constant legitimate process points as decoys and provides no precision/recall, false-positive rate, attacker accuracy, or confidence interval.

The SBO result is also hard-coded as `request headers=1`, `echo headers=2`; no committed serialized request/echo is parsed. Thus 9/9 means the scorer's local logic is internally consistent, not that the observer experiment has been performed.

Required disposition: export machine-readable serialized READ and SBO vectors from the OpenDNP3 tests, collect repeated READ sequences with varying and constant legitimate values, parse those exact vectors, and report explicit leakage/classification metrics.

### M2. The cover “full transaction” omits the real transport layer and TCP

`test_full_transaction.cpp` uses real OpenDNP3 master and outstation application contexts and a real link parser/filter. That is meaningful. However, each emitted APDU is manually given a single `0xC0` transport octet, manually framed, passed through a newly constructed link-layer fixture, stripped back to APDU hex, and injected into the peer context.

It does not use persistent OpenDNP3 transport reassembly, an actual OpenDNP3 TCP channel, a socket, TCP sequencing/retransmission, or TCP teardown. Its split test splits `LinkLayerParser.OnRead()` calls, not real TCP segments. `masterCloses==0` cannot prove “no TCP/link close” because the master lower layer is never brought down.

Supported claim: a bounded in-process application-context round trip through a real link address filter. Unsupported wording: “full application+transport transaction,” “split TCP delivery,” and any conclusion about TCP close/reset.

The 18/45→63 result is also an exact constructed serialized byte stream, not a captured TCP payload. “DNP3 serialized bytes, numerically equal to a one-segment TCP payload by construction” is accurate; “TCP payload measured” is too strong.

### M3. Timing uses differential release error as an absolute latency error

The model correctly distinguishes:

```text
CLRT_out = max(C-D_A, D_R) + (epsilon_R - epsilon_A)
L_master = a + max(C,H) + epsilon_R
```

But the implementation estimates `eps_ms = median(CLRT_out)-D_R`, explicitly a differential `(epsilon_R-epsilon_A)`, and then adds that same number to `L_master` as if it were absolute `epsilon_R`. The absolute latency correction is therefore not evidenced.

Required disposition: derive `L_master` directly from paired `t_read→t_response` timestamps for measured policies, or estimate `epsilon_A` and `epsilon_R` separately. Until then, report the epsilon contribution to absolute latency as UNKNOWN while preserving the observed direct latency distribution.

### M4. Timing tolerance and policy-selection language remain too strong

`target_band_tolerance()` first keeps only defended values within ±1 ms of `D_R`, then computes the error quantile inside that preselected band. This can exclude the errors it is intended to summarize and does not pair those transactions with the native `C<=H` condition. It should be labeled a normalized-band conditional statistic or replaced with paired, untruncated coverage.

The selected policy meets 0.99 only by point estimate (`0.9917`). Its Wilson lower bound is `0.9701`, and the validation pool is `0.9875`. No H=14 policy establishes ≥0.99 coverage with 95% confidence. Even H=16 has a Wilson lower bound around `0.984`. The report should say “analysis candidate under a point-estimate rule,” not “selected and tested,” and should not imply a confirmed 99% policy.

The protection domain contains one SEL-751 and 30 unpinned firmware fields. That prevents a multi-device/common-domain or pinned-firmware generalization.

### M5. The 2-second response-timeout margin lacks campaign provenance

`make_registry.py` calls 2000 ms a “DNP3 application-layer response timeout default (protocol constant).” It is neither a protocol constant nor the OpenDNP3 3.1.2 implementation default. The repository's reusable Python harness explicitly configures 2 seconds, while the physical campaign driver uses a raw socket with a 4-second `recv` timeout. The timing evidence does not bind its physical campaign to a 2-second OpenDNP3 master configuration.

Required disposition: cite the exact master binary/configuration and invocation that produced the evidence, or set the DNP3 application-timeout margin to UNKNOWN. Keep the independently evidenced 400 ms poll gap separate.

### M6. Decoy claims are useful but bounded, and two prohibited statements remain

The full SBO application-context round trip supports: the legitimate CROB is actuated once, configured decoys are mapped inertly, the master accepts the transformed exchange, duplicate APDUs use cached behavior, and mismatch/failure cases fail safe. It does not test TCP retransmission; it repeats identical application data.

The READ gate supports software-generated application-layer convergence from 29/59 to 89 bytes and per-real-object serialized preservation. Segment counts are computed, not captured. Both mechanisms require endpoint configuration/cooperation. One failing decoy safely drops the legitimate SBO command, an important availability fragility.

`decoy_gate/README.md` still says twice that two G12V1 headers are something “no native device” emits, contradicting `SIZE_CANDIDATE_DECISION.md`'s bounded correction. Those universal statements must be removed. Detectability is only established relative to the tested one-header request/baseline.

## Additional provenance and hygiene observations

- The cover run script modifies evidence logs after execution to sanitize paths. Store raw and normalized evidence distinctly and hash both; do not call a post-edited file verbatim raw output.
- The decoy manifest hashes sources and the patch but not the suite output or environment file. The cover manifest also omits some console/environment outputs. Git binds the committed files, but the run-level evidence manifest should bind inputs, toolchain metadata, command, exit codes, and outputs together.
- Several older active-looking size scripts still contain hard-coded absolute paths (`canonical_response.py`, `p4_egress_emulator.py`, `size_transform.py`, `joint_transform_oracle.py`, `sbo_oracle.py`), and `size/p4/baseline.err` contains a user home path. If these remain part of the supported workflow, they contradict the broad reproducibility claim.
- The remote cannot prove that local `dir.md` is the standing worklist. A reproducible audit checklist should be committed without private/local path data.

## Claims that remain supportable

- Commit/branch/provenance facts listed above.
- Timing analysis is deterministic over committed evidence and correctly models late-safe release as not H-bounded, subject to the epsilon and timeout caveats.
- Offline, CRC-valid DNP3 cover frames can make the two constructed serialized profiles 18/45→63 bytes for a counting observer; a parser removes them and recovers the native sizes.
- The tested OpenDNP3 link filter discards the selected unused individual address in the bounded software setup; broadcast is a hazard.
- Configured READ profiles 29/59→89 bytes in the OpenDNP3 application-layer test with per-real-object serialized preservation.
- The bounded SBO application-context round trip completes with one legitimate actuation and inert configured decoys, with the documented fail-safe fragility.
- The exact P4 source compiles and fits with the reported compiler/resource numbers.

## Claims to withdraw or downgrade now

- Transport oracle “gate PASS” and “mutation-checked.”
- P4 compile-level “integration gate demonstrated.”
- P4 cover “CRC-valid.”
- P4 implements the offline transport oracle.
- P4 implements common-target normalization.
- Cover harness is a full application+transport/TCP transaction or proves no TCP/link close.
- Observer READ temporal residual is demonstrated from evidence.
- Observer SBO result is parsed from evidence.
- Two G12V1 headers are impossible for all native devices.
- `(2,12)` is a tested/confirmed ≥99% policy.
- 2000 ms is a protocol/default timeout tied to this physical campaign.
- Loading the current kernel is the smallest justified physical experiment.

## Recommended next step

Create a new repair branch from `31b630f`; keep `31b630f` immutable. Run the software/compile-only program in the companion overnight prompt. The minimum promotion gate before any hardware proposal is:

1. all newly identified transport/P4 regressions fail before and pass after the repair;
2. one shared packet-vector corpus agrees between a reference boundary-ledger model and P4 behavior/emulation;
3. the emitted cover bytes are exact and independently CRC-verified;
4. unsupported packets provably bypass without any state access or mutation;
5. target-size convergence is actually implemented, or the P4 is explicitly downgraded to fixed enlargement;
6. bf-p4c succeeds on the repaired source with reproducible, hashed evidence;
7. documentation and observer/timing reports reflect only those demonstrated properties.

