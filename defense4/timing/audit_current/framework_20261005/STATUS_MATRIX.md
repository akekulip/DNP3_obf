# Cumulative implementation / evidence matrix — 2026-10-06

These are distinct levels: implemented, offline-tested, compiled, loaded, configured and hardware-measured. Current complete target acceptance is **not achieved**. Historical successful snapshots do not qualify changed source.

New architecture checkpoint: [handover](../../case4_architecture/HANDOVER.md),
[focused plan](../../case4_architecture/PLAN.md). Experiments stopped at Philip's
request. The original rows below retain earlier baseline evidence.

| New capability | Achieved | Still required |
|---|---|---|
| Shared cache/carving/READ compositions | Local9.13.1 compiled10/7; verification02 | Lifetime pin/no-reuse, payload mapping and live owner join |
| Full READ validation | Local compiled6/0; packet/profile/link/CRC checks | Actual timing/connection admission and terminal integration |
| Payload mapping | Forward10/0, reverse11/0; exact-byte references | Actual WorkRecord gate and upstream validator |
| Expected-phase holder / native credits | Local compiled12/0 and4/0 | Native admission, lifecycle, service and physical measurements |
| Native binding | Implemented; historical authorities fail17–18stages | Unfixed retry/ACK drops; current source uncompiled; receipts/reuse/timing |
| Assembly alternatives | Executable grouped/worker/byte/staged candidates | Current producer460PHV slices, four-bank workers48; lifetime authority |
| Controller checkpoint | Rollback relabeling repaired;17 targeted tests | Complete qualified source/schema/inventory; registry empty |

No new model packets, loaded/configured state or hardware measurements are claimed.

| Capability | Current implementation / evidence | Level attained | Remaining acceptance |
|---|---|---|---|
| Timing contract/model | Request-anchored response-ready schedule; explicit quarantine/original termination and matching reset, including deferred-return model. | Implemented, offline-tested with ideal service assumptions. | Full parser/queue/bank interleaving and physical departure/drain; policy-off terminal debit/cleanup remains unproved. |
| Recovery source | `cac84a26aea5233ae01cb0f7ac220bded92a7a74c5005133dd8eeca2e53ca87a`; bounded source-control/SALU/table and real-byte fixtures; OP deadline/commit, duplicate-original coalescing, old-cookie refusal. | Implemented; source-fragment tests. Core22 exit 3, PHV 31 slices. | Actual target fit, producer, lifecycle, queued OPERATE-envelope proof and hardware queue service. |
| Instrumentation | 36-byte management learn records, no endpoint marker; decoder/import wrap, identity, mask and missing-endpoint checks. Instrument05 `8dcf04c3…`. | Implemented/offline-tested; separate compile exit 3, PHV 35 slices. | Instrument fit, actual collector/overhead, clock alignment and physical endpoints. |
| Private validation seam | Port 69/EtherType 0x88C9, full-profile proof flags, dynamic wire end and original observation time; invalid unvalidated Case 4 input bypasses state mutation. | Source/test subset only; producer absent. | Real full IPv4/TCP/DNP3 validation, images, assembly, port 69 availability, pretranslation wire ACK and end-to-end association. |
| Ingress translation component | Current `31bb3303…`, build33: source arithmetic/window guard, per-pass cookie and phase/pass checks, valid-bit seed checks. | Compiled SDE 9.13.1: six ingress / zero egress, 27 warnings; five arithmetic tests. | Tests interpret phases 1–14 only. CP geometry, atomic epoch change, producer authenticity/history, service and validated completion are unproved. Phase 15 drops. |
| Full inactive size prototype | Repaired native-end-minus-one clamps, both tails/right edge/wrap and 32-bit windows. Build27 `aea44d20…`. | Eleven static/oracle tests; compile exit 3 sliced-PHV clamp. | Complete cache, handshake/overlap/options, sentinel/epoch/teardown and actual runtime. Inactive. |
| Current composite probe | Build34 `413e8c5b…`, exact timing/mapping/wire inputs; source generator/test seams. | Exact compile exit 3 PHV; joint/deployment flags false. | Incomplete producer/cache/lifecycle and final processing forwarding; no full joint fit. |
| Software preprocessor | Explicit MSS-only handshake >= 57; SELECT 35->55; bounded OP 35-byte / 35-bit assembly with non-extending 30 ms expiry; cookie/CRC/shape/objectset checks; retained replay/translation/fault/close. | Nineteen offline cases pass. | Pure expected pipeline; cannot substitute for TNA implementation or physical lifecycle. |
| Production endpoint semantics | Pinned OpenDNP3 `4648fcb…`, context_evidence_03. | Four production-software cases/46 assertions pass. | Physical inert points/allowlist, endpoint build/timers and attendance. |
| Kernel transport repair | socket_evidence_03 plus independent raw PCAP analysis: both phases have native 1-byte repeat, cached 21-byte replay, SUCCESS 57-byte echoes, one callback/object/phase. | One real Linux TCP software pair passes. Retention 440.139 ms under configured 500 ms; two observed replay intervals 206.717 / 439.109 ms. | No target P4, future loss/timing bound, general TCP or exactly-once/physical claim. Earlier failed acquisitions preserved. |
| Immutable acquisition | Shared exclusive reserve/claim/seal API; endpoint/BMv2 wrappers snapshot inputs before side effects; process-group abort cleanup. | Nine reservation + five socket tests; nine sealed inventories hash-verified; isolated launcher smoke. | New acquisitions need new directories; no overwrite/resume or unbudgeted retry. |
| Joint-aware controller | Complete keyed/register/default inventory; exact policy/operation/profile/source/schema/build fingerprint; disable/backup/readback/enable/restore and interruption tests. | Seventeen mock binding tests plus schema/adapter tests. Production registry empty; live activation refused. | Actual full-source qualified schema/writes, binary/loaded identity, applicable admission/quiescence and saved-program restoration. |
| Admission/observation | SBO retention clock and normal/fallback cycle costs; imported identities/endpoint/clock checks; marker erasure rejects. | Active_control: 115 tests; observation: 15 tests; no invented physical values. | Applicable exact-build physical inputs remain unavailable; READ record provisional with 12 missing inputs, control adds SBO/profile requirements. |
| BMv2 Case 4 | Current unchanged P4 `0fba5225…`; software token gating/real-packet recirculation, Python codec endpoints. | Fresh 14/14 PASS, zero skips, 152.566 s; prior captures prove 35->55 and 57->[28,29]. | Software 1 ms heartbeat differs from requested target 100 us. Earlier combined 22/23 legacy timing failure retained. |
| Declarations/runbook | 44 blocks; 15,480 primary + 600 warmups + 88 state READs = 16,168; maximum 14,571,200 ms. | Prepared/offline-validated; hardware_authorized=false. | Full 9.13.2 fit, measurements, actual authorization/attendance and restoration. No new campaign or implicit retry. |
| Analysis/working paper/figure | Historical main OFF n=30 separate precheck; new Linux single-pair boundary; editable source/vector/PNG with proposed/executed panels. | Four-page draft builds; protected 2,210 hashes, five figure hashes and XML pass. Figure strict 13 warnings retained; intended full-width text >= 8 pt. | No new device classifier/physical population. Exact author text/acceptance and promotion instruction absent; frozen sources unchanged. |
| Historical/explanation-only | Cases 1–3, shift/reference policies, campaign_v2 and older build/cohort snapshots preserved. | Separate historical/model/software/physical evidence as recorded. | No new Case 1–3 campaigns and no transfer of old SDK 9.13.2/read-only OFF fit to current source. |

Current aggregate and post-review source identities/counts are in `CONTINUATION_VERIFICATION.json`; original `EXECUTION_VERIFICATION.json` and original failures remain immutable. See [claims ledger](CLAIMS_RECONCILIATION.md) for the limits of each evidence type.
