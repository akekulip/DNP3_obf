# read_complete_01 — completion record (updated 2026-10-22, two-READ-target directive)

## 0. Two-READ-target candidate m12p_c25 (Claude_Two_READ_Targets_Hardware_Directive.md)

m12p_c25 (P4 `61f9af0fa141…`, = m12p_c24's P4 with the corrected declared disposition) pads the mixed READ
(g1v2 0-15 + g30v1 0-7 in one request) 91 → 141 as link frames [50, 91] (26 G1V2 points 1024-1049, value 0, flags 0)
and the base-database full/integrity READ 247 → 271 as [24, 247] (4 points 1024-1027); SELECT/OPERATE 37 → 61
unchanged; timing and J unchanged. Range READ admitted and timed at native 49 (not padded). analog/class0 READ
requests are WITHHELD on an admitted connection (measured; a master issuing one stalls).

| workload | software (live endpoints) | compiler (9.13.1 + 9.13.2) | model (v3 gate, exact source) | physical switch |
|---|---|---|---|---|
| mixed READ 91→141 | live master via pad_read proxy, strict padding check (M1) | exit 0, N12/E12/T11 + pipe-1 egress 7 | gate passed (14 drivers; timed rounds, boundaries, retransmission, 3 corruption cases) | **size: 33/33 exact at 141** (size_only, combined; campaign 02); **timing precision FAILED** (p99 2.0-3.6 ms vs 100 us) |
| full READ 247→271 | same | same | same | **size: 32/32 exact at 271**; timing precision FAILED |
| SELECT/OPERATE 37→61 | unchanged | same | same | 64/64 exact at 61 per arm; timing precision FAILED |
| recovery (loss per class, persistence graceful/rst, reconnect, held OPERATE) | harness + configs ready, dry-runs rc 0 | — | robust driver green | **NOT EXECUTED** (campaign stopped on the timing failure; then hardware stopped, below) |

Hardware state: `unsafe_restoration=true` set by the supervisor on matched-control block rc01_hw_c25_20261022_03,
which failed its freeze check BEFORE any hardware contact (my unrewritten control freeze). The reviewed no-contact
reconcile refused (classifier does not recognise a freeze-check refusal). Flag not edited; hardware stopped pending
Philip. The timing failure is therefore NOT yet attributed: the matched m11_09 control has not run today (on
2026-10-21 it failed with p99 3,551 us on this host, see §4).

Limitations specific to this candidate: the READ-response TCP checksum on the shallow path is a WAIVER (0xffeb written,
not computed); responses are validated first block only; bare-RST behaviour is open (two model runs disagree); no
general READ-length support, no whole-response switch validation, no indistinguishability or conformance claim;
padding is visible to the master (declared, strictly checked).

Reproduce offline: `bash reproduce.sh` (CANDIDATE=c25 default); readout:
`bash reproduce.sh --readout evidence/hw_blocks/rc01_hw_c25_20261022_02_reference hw/config/rc01_m12p_c25_reference.json`.


**Delivery candidate: m12p_c20** (source sha `1e94c31d80e6…`), the faithful segmented READ 377→401 build.
**m12p_c12** (source sha `742089cbe762…`) is preserved unchanged as the reproducible checkpoint.

**Status by tier: software, encoding, both-SDK placement, and the compiled-model gate are COMPLETE and
reproducible for c20. The physical-switch tier for c20 is PENDING (not yet run) — it is NOT blocked: the
testbed is idle and restored (`unsafe_restoration=false`, no active unit).** Sizing and timing together on
silicon for the segmented class have NOT been shown. The earlier b08 block-1 silicon result is recorded as
history in §3.

## 1. Tiers reached (c20)

| tier | result |
|---|---|
| Source reasoning | Policy rule v3 (Ditto-inspired, aggregate-response layer): targets **141 / 247 / 401**, 10.93 % added vs 19.04 % for the 163/269/399 comparator (`policy/TARGET_POLICY.md`). Ditto's guarantee does not transfer; low overhead is not evidence of effective obfuscation. |
| Encoding tests | Handoff tests 51/51; policy coverage 25/25 over 10,243 profile cases; range constants byte-exact vs `pad_read` on 512 samples (`vectors/constants.json`, byte-stable at `6f819e7e…`); **segmented shape byte-exact vs `pad_read` on 512 samples** (`vectors/constants_segmented.json`; `prefix_link_crc_delta` 0x79bf invariant across samples); new interpreter tests `test_segmented_pad` (7) + `test_segmented_classifier` (2) + `test_segmented_mapper` (2). |
| Live software endpoints | Pinned OpenDNP3 4648fcb (binary `ea734720…`): range 49→141, analog/class0/integrity at target, large 377→401, 16+16 each, IIN 0x9000, no errors (`evidence/m3_live_policy_01`). Endpoint acceptance, not an IEEE 1815 conformance claim. |
| Compiler placement | m12p_c20 source `1e94c31d80e6…`: SDK **9.13.1 and 9.13.2 both exit 0**; **N 12 / E 12 / T 11** stages + the **pipe-1 egress padder, 7 stages** (same profile as c12; m11_09 is N 11 / E 12 / T 11). The segmented padder lives in pipe-1 egress, off the pipe-0 MAU budget, so the p0 wall feared in the c13/c15 probes did not materialize. The c16/c17 deparser nested-conditional wall was diagnosed and fixed with separate top-level validity-guarded checksums. |
| Compiled model (baseline shapes) | **v3 gate: `model_gate_passed`, blocked_reasons [], all 13 drivers, 0 failures** (smoke, packets, rearm 799/799, dup 102/102, repeat, select_lifecycle, control_timing, contention, abort, abandon, policy, policy_boundary, smoke_sizeoff). Committed `33e21fd07`; **recomputes `model_gate_passed` on a fresh detached worktree** after `restore_retained_logs.py`. This gate exercises the range/analog/class0/integrity shapes and the R→S→O→R timing and confirms c20 does not regress; `rearm`/`dup` exercise the two-child child-bank mechanism. None of the 13 drivers sends the 292+85 segmented wire shape. |
| Compiled model (segmented) | **PARTIAL — measured, seg0 only.** A dedicated driver (`seg61_02/model_segmented.py`, run `model_segmented_m12p_c20_01`, 10/10) injects a real 377-B two-segment integrity response through the compiled c20 model. **seg0 (native 292 B, ip.len 332) is admitted and padded to the exact 316-B first image at the wire-start TCP seq** (via E `out_translate` + the pipe-1 padder, `p1_outcome.p1_padded`) — the segmented padder fires correctly. **seg1 (85 B, ip.len 125, FIN continuation) is NOT forwarded:** it is admitted by N's parser (`read_response_fb`, kind 11) but dropped in N's pipe-0 ingress control before egress (0 egress frames, no E outcome code, no `p1_outcome`/`count_busy`/T-outcome bump). **The end-to-end 401 image is therefore NOT delivered by c20 — it emits only the padded first segment.** See §3a. |
| Physical switch (c20) | **PENDING — not yet run** and must not run for the segmented class until seg1 forwarding is fixed (a seg0-only build cannot deliver the 401 image on silicon). Testbed idle and restored. No c20 silicon result exists; none is claimed. |

## 2. Tier boundaries (honest)

- **Proven (source + encoding + placement):** the segmented construction's bytes (prefix frame, per-frame
  block-0 rewrite + recomputed CRCs, continuation renumbering) are byte-exact against the reference padder, and
  the integrated source places on both SDKs at the stage budget above.
- **Model-measured, seg0 only:** the segmented padder forwards and pads the **first** segment correctly on the
  compiled model (seg0 → 316 B at the wire start), but the **second-segment continuation is dropped in N ingress**
  (§3a), so the forward two-frame single-commit is **non-functional**, not merely unexercised, in c20. The deparser
  **IP/TCP checksum externs** on the seg0 path are compile-placed and seg0's 316-B bytes match the reference exactly,
  but the externs' wire-checksum correctness is not offline-checkable (same caveat as the range padder).
- **Content-blind gating:** seg1 admission keys on `dl.len==0x46 && FIN`, not on segment content.
- **Hardware:** segmented READ on silicon — size, first-frame vs complete-response timing, OPERATE hold J, ACK
  mapping, and recovery — is **pending**, not shown.

## 3a. Open finding: the segmented second segment is not forwarded by c20 (model-measured)

The driver `seg61_02/model_segmented.py` and the counter localization (`SEG_DIAG` run) establish, on the exact
c20 image:

- **seg0 works.** The FIR response segment (native 292 B, ip.len 332) is admitted, the pipe-1 egress padder
  prepends the 24-B frame and rewrites block 0, and the switch emits the exact 316-B first image at the wire-start
  TCP seq. Counters: E `TRANSLATE` +1, `p1_outcome.p1_padded` +1.
- **seg1 does not.** The FIN continuation (85 B, ip.len 125) is admitted by N's parser (`read_response_fb`,
  `packet_kind` 11 — the parser already carries the 332/125 entries from `segmented_classifier`) but is **dropped
  in N's pipe-0 ingress control before egress**: 0 egress frames, and across seg1 **no** counter moves — not E's
  `outcome` (no drop code either), not `p1_outcome`, not N's `count_busy`, not the T outcomes register. It is a
  silent read-lane drop, consistent with seg1 arriving after seg0 has consumed the outstanding read, with no
  continuation state to forward it.
- **Consequence.** c20 delivers only the padded first segment; the end-to-end two-segment 401 image is not
  delivered. The `--segmented-full` build applies `segmented_pad_pipe1` + `segmented_classifier` + `segmented_t`;
  the missing piece is **N read-lane continuation handling** — recognizing seg1 as the second segment of one
  in-progress response and forwarding it (the plan's "one commit at segment 1 with the continuation mapped by
  `out_translate`/`wend_fwd`"). `transform_segmented_n` only adds parser admission (already effectively present);
  it does not supply the N-control continuation, and its probe anchors no longer match the full+passthrough base.
- **Diagnosed, not fixed.** The fix is a non-trivial N-control change and is the next scoped step. The hardware
  campaign for the segmented class must wait for it — a seg0-only build cannot deliver the 401 image on silicon.
  The range/analog/class0/integrity classes are unaffected (single-frame; seg0-style path).

## 3. Physical-switch history (b08, 2026-10-21)

Recorded for provenance; superseded as the delivery tier by the pending c20 hardware run.

- Campaign `rc01_hw_b08_20261021_01` block 1 (four-arm reference) on m12p_b08: `off` and `timing_only` READ/SBO
  exactly native (65/65 READs); `size_only` SELECT/OPERATE 37→61 on all 128 responses, +16.75 % wire octets
  (SBO only), **READ 49 (padder not enabled)**. Root cause: the baseline installer `plan()` discarded the
  `p1.x_Egress.p1_conn` enable row; fixed as `plan_with_p1`, test red→green, review-confirmed (`232e26c57`).
- A later control config error set `unsafe_restoration` on a step that **never reached hardware**; the reviewed
  reconcile was later extended for that case and the flag cleared on fresh `restore_verify` evidence. The flag is
  now clear (§ status).

## 4. Open timing finding (not attributed to any build)

`timing_only` READ CLRT precision on today's Vision host fails the gate for **m11_09 as well as b08** (control
block `rc01_hw_b08_20261021_03`): m11_09 today p99 abs CLRT error 3,551 µs / median 1,344 (18 Oct: 63 / 5). The
`off` arm already differs (request transit median ≈ 1.1 ms vs ≈ 98 µs on 18 Oct). This **rules out a build-only
cause**; it does **not** identify a single cause and does **not** exclude an additional candidate-specific
component on top of the shared degradation. Vision was rebooted 2026-10-19, now runs docker bridges with adaptive
RX/TX coalescing; no latency tuning is recorded in the repo and Vision sudo needs a password, so nothing was
changed. Hardware timing **precision** is gated by this host state for every build equally until the pre-reboot
latency is restored (Philip's decision). Size / delivery / recovery hardware checks are not affected.

## 5. Coverage: software vs hardware

Software + compiled model cover the full declared profile for the **single-frame** classes: range 49→141, analog
141 and class0/integrity 247 at target (pass-through). The **377→401 segmented class** is implemented in P4 and
its construction is byte-exact at the interpreter tier, but on the compiled model it is **seg0-only**: the first
segment pads and forwards correctly, the second-segment continuation is dropped in N ingress (§3a), so the
end-to-end 401 is not delivered. Per-class recovery covers the single-frame classes (analog 141; one 247-B loss
selector `read_resp_247`, since class0 and integrity are byte-indistinguishable at 247 B — length-level claim
only); **segmented recovery is NOT_EXERCISED** (its forwarding is not yet functional). **Hardware coverage for c20
is pending** for all classes; the segmented class is additionally blocked at the model tier by §3a.

## 6. Residual limitations

C3: the SBO-61 image's pre-start region is withheld, not stale-dropped (a per-image key costs a 13th stage).
`ina_img_t` is not keyed on direction. E's CRC defence-in-depth is reduced (N validates all CRCs; pipe 1 checks
block 0; the segmented path's block-0 CRCs are recomputed on chip). T timing was calibrated on shorter frames;
segmented frames are longer, so first-frame vs complete-response timing must be measured separately on hardware.
The packet-boundary checker binds lengths as a set, not per kind. The model gate cannot see control-plane
installer behaviour (the b08 defect in §3).

Two findings from the adversarial review of commit `33e21fd07` (both honest-tier, neither a defect; the code is
faithful, byte-exact, both-SDK, model-gate-green):

- **Stateless seg1 renumber (cross-frame scope assumption).** `fix_s1` applies `tcp.seq += 24` and the transport
  renumber to any `(dl.len==0x46 && FIN)` frame on a `p1_conn` connection, with no per-flow state confirming this
  flow's seg0 (FIR) was actually prefixed. This is correct **only** because the obfuscated connection carries
  exactly the 292+85 integrity/class0 segmented shape; a different multi-frame response ending in a 70-byte FIN
  frame would be mis-renumbered and desynchronize the master's TCP stream. No guard is added (a per-flow register
  costs stages; the connection is single-shape by scope). Documented at the code site (`make_m12.py`, the seg0/seg1
  gate comment). **Hardware bring-up of the segmented class must exercise a mixed-response flow before this
  assumption is relied on.**
- **Segmented deparser checksum has no offline correctness coverage.** Its correctness rests on analogy to the
  range padder (every per-segment IP/TCP checksum varies across samples and is derived on chip). The seg0 `+24`
  pseudo-header growth and the seg1 `tcp.seq += 24` are the two places a wrong incremental checksum would first
  surface. **The hardware gate for the segmented class must verify master-side TCP/IP checksum acceptance;** it is
  not provable offline.

## 7. Corrections recorded

The 2026-10-19 reverify ran with counter-statistics stripping added after the original failure (`291e8cb30`);
I had told Philip it passed with unchanged rules. The hardware readout first paired captures in the wrong
direction (out.pcap is what Vision sent); fixed before any number here was taken.

## 8. Reproduce

`CANDIDATE=c20 bash reproduce.sh` (offline: software tests, policy, constants + segmented constants, P4
regeneration to `1e94c31d80e6…`, model gate, freeze) and `bash reproduce.sh --readout` for the hardware readout.
`bash reproduce.sh` with no override still regenerates and gates **c12** (the preserved checkpoint, source
`742089cbe762…`). The c20 model gate is recomputed on a fresh worktree via `restore_retained_logs.py` then
`model_summary.py evidence/m12p_c20 --v3 --enforce`.
