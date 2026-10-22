# read_complete_01 — status (newest first)

Plan: ~/.claude/plans/pasted-content-id-463c-execute-this-quiet-pascal.md (approved 2026-10-20).
Production implementation stays m12_fullsize/make_m12.py + its consumers; this directory holds evidence,
policy, reproduction and the completion record only.

## 2026-10-21T02:50:33Z M0 started
- Handoff: /home/philip/Projects/DNP3/Claude_READ_Complete_Handoff_20261020.zip
  sha256 7638cb2ad45369937e6c09619f64c369e6ae888632f924fbd3387edd4ca8dfba, extracted to handoff/.
  SHA256SUMS verified: top 98/98, read_coverage 38/38, target_selection 49/49.
- AUTONOMOUS_OVERNIGHT.md: NOT present in this verified archive, nor in any nested historical zip, nor
  elsewhere on gambit. Working from START_HERE.md + Philip's written corrections in the session.
- HEAD afbea5a52; uncommitted C1/C2/C3 in make_m12.py, model_fullread.py, run_model.py.
- Testbed ownership.json: unsafe_restoration=true (dev_m11_09_20261019_01); no dnp3-eval unit active.
- afbea5a52 review findings 1..6 -> current status: 1 fixed (C1, uncommitted); 2 fixed (C2 honest
  waiver + corruption 36/36, uncommitted); 3 partial (269 classify fixed; SBO-61 boundary + transitions
  open); 4 open (C4); 5 open (C5); 6 partial (C6 inputs.json).
- CORRECTION: Philip supplied the directive separately at /home/philip/Projects/DNP3/AUTONOMOUS_OVERNIGHT.md
  (sha256 bb12f57517dc0bf1cd667610a5e9f1db01d2bd9da7a300c0530afd5158959baf, 10,322 B). It was absent from the
  verified zip; it is the governing directive. Its precedence over START_HERE's stopping language is applied.
  Restore lock: Philip explicitly authorized a reviewed reconcile command in-session (lock + fresh unchanged
  restore_verify + immutable record + atomic ownership update); that is the "existing process" used.
- M1: handoff pytest 51/51 passed (Python 3.12.13, ~/.venvs/research) -> evidence/m1_pytest_01/pytest.log.
- M1 DONE (live software endpoints, pinned stack): full_read_gate built by full_read_01/endpoint/run_full_read.py
  build from git archive of OpenDNP3 4648fcb898456d1cb70b5baecc38cc256c859c2e (archive a4a9a8a8...),
  binary ea7347206072885e8ef4faa753748cd6a2afb1554fddfff800a68eb21f783405, libopendnp3.so c14c7628...,
  at ~/dnp3_endpoint_builds/read_complete_01_m1 (manifest + build.log copied to evidence/m1_software_pinned_01).
  reproduce_software.sh on that binary: pytest 51/51; live fallback full 247->269 16/16 + segmented 377->399
  16/16 (+ native comparison), target-163 range 16/16 + analog 16/16, IIN 0x9000, errors [] in all 8 runs.
  Tier: live software endpoints over loopback TCP, two independent connections via proxy; NOT switch/timing.
- M2 DONE: policy frozen {141,247,401} (rule v3, aggregate-response layer, Ditto-inspired seeds, profile
  coverage 10,243 cases + workload prefix constraint). 10.93% added vs comparator 19.04%. v1 (387, needs
  resegment for 377) and v2-greedy (249/401, 39.96%) preserved. select_policy.py 707077a697c94e7b, policy.json ade5643172ff0a00.
- M3 DONE (software tiers): test_policy_coverage 25/25; live pinned endpoint evidence/m3_live_policy_01 5 cases
  x16+16 PASS (range 49->141 prefix, analog/class0/integrity at target, large 377->401 prefix).
- NEXT: M4 P4 in make_m12.py: generalized READ shapes {49->141 pad, 141 pass, 247 pass, 377(292+85)->401 pad
  first seg + renumber continuation}, SBO 61 kept; single acct_try with size via m.ina (4-RegAction limit);
  C3 per-image boundary, C5, waiver gated on profile, zero-window restore.
- M4 phase A (range 49->141 + SBO 61) in make_m12.py --policy, constants from vectors/derive.py
  (constants.json, 512-sample byte-exact proof vs pad_read). Attempts: m12p_a01 (cb2e077e) failed:
  --Werror=overlimit (constants >64 bit) + PHV; m12p_a02 (f1c15af9) fails PHV allocation (egress p1).
  Bisect (scratch): no single ablation of {C3 m.y key, 64B const remainder plz, retained rbad1/rbadt verdicts,
  C5 rows + window-zero} fixes it; all four removed compiles; committed range 49->73 build compiles.
  Pairwise (plz + each) running. Old builds regenerate byte-identical (full f99773ce, range 0f12ee9b).
- M6: evaluation_campaign.py reconcile + tests/test_reconcile.py 13/13; existing campaign tests 28/28.
  Review running. NOT yet run on the live testbed.
- CORRECTION recorded: the 10-19 reverify passed under restore_verify.py with counter-statistics
  stripping (committed 291e8cb30 at 19:58) that the original 19:41 check did not have. My statement to
  Philip that it passed "with unchanged rules" was inaccurate. The fresh reconcile check uses the current
  committed rules, unchanged by this session.
- M6 DONE: reconcile committed 3e2f59aec (review OK + fixes). Run once 2026-10-21T03:41Z on the live testbed:
  fresh restore_verify (rules = committed 291e8cb30, unchanged) ok, 399 tables, program case4_response_path,
  Vision state, ping 3/3 -> reconciliation.json sha a16c6cf5...; ownership.json unsafe_restoration=false.
  Evidence: seg61_02/evidence/evaluation_campaigns/dev_m11_09_20261019_01/reconcile_*_20261021T034133Z.
- M4 phase A placement: a04 (constant-checksum folding of the 64B remainder) still PHV-fails with the same
  18 slices. Measured cause: p0 (N ingress + E egress) is ~95% PHV in the placing 73-byte build (16b and
  32b containers 100%); p1 is 24%. The 92-byte prefix does not fit p0 as built. Placement experiments Z
  (zero constants) and Y (first-block-only E parse) running.
- 05:3xZ M4/M5 progress (all compiled model, not yet committed):
  * READ prefix moved to PIPE-1 EGRESS (p0 PHV exhausted; P4_PLACEMENT_FINDINGS.md). m12p_b06 (37ae61e2):
    both SDKs exit 0 (9.13.1 81 s; 9.13.2 203 s). Model: policy interleaved R/S/O/R 386/386; boundary+C5
    105/105 (READ 141 exact; SBO 61 pre-start withheld = LIMITATION; C5 delayed pure ACK never reaches E);
    control_timing 211/211 (timed READ 141 + SBO 61 + OPERATE J); packets 622/622; smoke 30/30.
  * Review of b06 (code-reviewer): BLOCKING C1 = pipe-1 padder ungated by the per-arm size enable (size-off
    arms / reconnect c2 would be corrupted); H1 missing regressions; H2 C5 is a disposition record, not a C5
    pass; W1 leff_t key; W2 E CRC defence-in-depth reduced; W3 provenance; W4 T timing with larger frames.
  * b06 rearm 611/799: inverse_distance window cases -> my window-zero rule differed from m11_09's qualified
    rule. Restored with m11_09's own ladder (classify_rev key m.r + window range, 284 entries at image 141).
  * m12p_b07 = b06 + C1 gating (p1_conn per connection, cp.p1_pad_rows, installed by every model harness and
    the hardware bring-up when the build has the table) + p1_outcome counter + W1 + generator_sha256 +
    ladder window rule. Attempts: count-twice error; m.y window form -> 14 stages; ladder form compiling.
- Drivers adapted (read_policy_expect.py): build's READ encoder via encode61 install, growth per response,
  multi-frame independent decode, fullread response qualifiers; smoke growth = sum of per-response growth.
- 07:3xZ (after usage-limit pause) m12p_b07 (fd38841e881b): both SDKs exit 0 (9.13.1 86 s; 9.13.2 209 s),
  artifacts pinned; placement N11/E12/T11 (= m11_09) + pipe-1 egress padder 7 stages (new), no added traversal.
  First full gate: smoke 30/30, packets 622/622, rearm 799/799 (ladder restores m11_09 window rule), dup
  102/102, policy 386/386, policy_boundary 105/105; smoke_sizeoff 29/30 (READ/SBO exactly native = C1 fixed;
  cumulative_growth -123 = acct_grow removed by the m12 mapper, inherited, OPEN); control_timing 83/211,
  select_lifecycle 22/120, contention, abort, abandon failed: three ctl_timing drivers install their own rows
  and lacked cp.p1_pad_rows (fixed); repeat 522/523 hard-coded 12-octet READ growth (fixed). Rerun batch
  rc01-gate-b07b running (+ abandon on m11_09 baseline to test whether abandon's expectation predates m4+).
- Harness: read_image_len (vision_candidate, candidate_series, campaign, loss) + tests/test_read_image_len.py
  4/4; rearm_01/hw tests all pass. Hardware configs read_complete_01/hw/config/rc01_m12p_b07_*.json (6:
  four-arm reference + 5 recovery), validated + bound. Readout analysis/hw_read_readout.py validated on a
  retained m11_09 off-arm capture (65/65 READ exact native).
- NEXT: gate results -> model_summary --write -> review (resumed) -> gated commit -> freeze_gate write ->
  evaluation_campaign manifest (6 blocks, detached) -> readout per block.
- 07:5xZ b07 corrected reruns: repeat 523/523, select_lifecycle 120/120, control_timing 211/211, contention
  412/413 + abort 78/79 (released READ image end used 61: fixed len(image)/img_len); abandon 9/12 on b07 AND on
  unchanged m11_09 (model_abandon_m11_09_01): expectation predates control-timed builds, not a b07 defect.
  Review of b07: BLOCKING HIGH1 size-off accounting (acct_grow removed by m12 mapper), HIGH2 loss classes assume
  one padded length, HIGH3 configs dropped switch_compile.out_dir. Fixed: m12p_b08 (7b1281bc4aa7) keeps acct_grow
  + single acct_try fed by m.ina via ina_img_t (RegisterActions arm/try/grow/rev = 4); loss @LEN/READLEN +
  campaign suffix per class; configs field-by-field (make_b08_configs.py). Both SDKs exit 0, N11/E12/T11;
  harness tests 1122 + 5 pass; b08 configs validate. Full b08 gate running (rc01-gate-b08b); re-review running.
- 08:4xZ b08 final gate after the supported-profile change (make_m12.py emits the full profile; P4 source
  byte-identical 7b1281bc4aa7): all 13 drivers pass (smoke 30, packets 622, rearm 799, dup 102, repeat 523,
  select_lifecycle 120, control_timing 211, contention 413, abort 79, abandon 12, policy 386, policy_boundary 105,
  smoke_sizeoff 30); model_summary --v3 --enforce model_gate_passed. Commit 5b5397c5c.
  Configs regenerated; freeze_v3 rewritten (pre-profile freeze kept as freeze_v3_preprofile_SUPERSEDED.json);
  freeze check passes for all six configs; dry run rc01dry3_reference rc 0. Commit 1f47a99ae.
  Outstation in every block = Vision fixture 192.168.10.62 (no physical-relay OPERATE).
- 08:40Z hardware campaign rc01_hw_b08_20261021_01 started detached (evaluation_campaign start; 6 blocks:
  reference four-arm, persistence_graceful, persistence_rst, reconnect, held_operate_350, loss_core_950).
  Evidence: evidence/hw_campaigns/rc01_hw_b08_20261021_01/ and evidence/hw_blocks/<run_id>/.
- 08:46Z rc01_hw_b08_20261021_01 block 1 (reference, four arms) FAILED rc 1 at size_only; restore_verify ok;
  campaign stopped itself (stop_reason block_failed); blocks 2-6 unexecuted. Evidence kept.
  * off and timing_only trials ok (padding 0). size_only: master READ 49, expected 141.
  * ROOT CAUSE (read, then reproduced by tests/test_p1_plan.py RED 0 != 1): the baseline installer plan()
    (response_only/hw/bringup_composite.py:158-170) keeps only p0.r_/p0.n_ rows; the p1.x_Egress.p1_conn row
    that rows.build returned was discarded, so the padder was never enabled on silicon (bring-up manifest has
    no p1 table). The model drivers install rows themselves and never call plan(): model gate could not see it.
    FIX: response_only_rearm/hw/bringup_composite.py plan_with_p1 inserts the row before the first N row.
  * HARNESS: standards.expected_lengths, boundary requirement + capture_boundary, profile_check expected image
    and clrt_check pairing assumed READ = 61 on candidate61 builds; generalized for read_image_len (independent
    49->141 construction in profile_check and clrt_check, checked against 64 pad_read vectors
    vectors/read141_vectors.json). protocol/hw_vepa tests 602 pass; installer 96 pass.
  * TIMING FINDING (open): timing_only READ CLRT error median 1229 us / p99 2070 us vs m11_09 5 / 63 us (gap 950).
    Off arm (T off, no padding) on b08: master->outstation request transit median 0.66-1.16 ms, p99 ~4 ms, near
    1 ms multiples; m11_09 off arm ~95 us. Outstation->master pure ACKs unchanged (49 vs 28 us). Vision was
    rebooted (~1.4 d uptime vs ~13 d at m11_09) and runs docker bridges now; Vision TCP minrtt 0.875 vs 0.17 ms.
    Host vs build not yet separated: needs one m11_09 control block on today's host.
- 09:02Z campaign rc01_hw_b08_20261021_02 step 1 (m11_09 control) failed at config load (my edit made
  evaluation.purpose free text; I skipped its dry run). No hardware contact. Supervisor set unsafe_restoration
  (fail-closed). reconcile REFUSED (no restore record / snapshot / freeze check: block never reached hardware);
  flag LEFT SET. Fresh read-only restore_verify on a copy of block 1's inputs: ok (evidence/control/state_check_*).
  Control config corrected (load_config ok, dry run rc 0, re-frozen). HARDWARE BLOCKED pending Philip.
- Readout direction bug fixed (out.pcap = what Vision sent). Block 1 on silicon: off/timing_only exactly native;
  size_only SBO 37->61 on 128/128, +16.75 % wire octets, READ 49 (padder not enabled).
- COMPLETION_RECORD.md written (physical tier partial; decision needed).

## 2026-10-21 (afternoon) — review d531918e2 continuation
- Review package reproduced on a clean worktree at d531918e2 (all four counterexamples; gate blocked). Findings 3, 4, 5
  fixed and committed (5be733630, 3e47e9b06, 7dae3ed39): fail-closed readout (11 tests incl. a positive padded
  control), bound reset evidence verified against its launch pins and committed unchanged (logs as byte-exact xz +
  hash-checked restore), policy from tracked inputs; gate recomputes model_gate_passed on a fresh worktree.
- Restoration lock: reconcile extended for a never-reached-hardware block (65f1dd5ee, two reviews); run 15:24Z:
  fresh restore_verify ok, unsafe_restoration=false (record reconcile_20261021T152429Z).
- Endpoint READ-class schedule built (266adfda2): base 49/141/247/247, large DB class0 and integrity 292+85.
- Finding 2 (committed-image boundary): m12p_c04 compiles in 12 stages with per-image classify_rev (15 entries,
  was 284); contract tests 7 pass (source interpreter). c01-c03 failed attempts retained (2c5f81211).
- TIMING ATTRIBUTION (campaign rc01_hw_b08_20261021_03, control on the unchanged m11_09 build, 15:25-15:32Z,
  restore_verify ok): m11_09 TODAY fails the same precision gate (timing_only READ p99 abs CLRT error 3551 us,
  median 1344; 18 Oct: 63 / 5). Off-arm request transit median 1101 us (b08 1161; 18 Oct 98). This rules out a
  build-only cause: the degradation is NOT unique to b08 or to any candidate change. It does NOT identify a single
  cause and does NOT exclude an additional candidate-specific component on top of the shared degradation. Leading
  hypothesis (not demonstrated): the shared environment change. Even the restore ping through the PRODUCTION program
  to the relay is slower (avg 2.8-3.7 ms today vs 0.66-0.89 ms on 18 Oct); data-path min RTT unchanged (0.364 vs
  0.30-0.34 ms) but jitter large (avg 3.46, max 9.0 ms), while Vision's management path is fast (avg 0.21 ms). Vision
  rebooted
  2026-10-19 23:32; now adaptive RX/TX coalescing on (rx-usecs 50), intel_idle max_cstate 9, docker services up
  since boot. No Vision latency tuning is recorded in the repo; sudo on Vision needs a password, so nothing was
  changed. Hardware timing PRECISION is unlikely to pass on this host state for any build until the pre-reboot
  latency is restored (decision for Philip); this is a gate on all builds equally, not a candidate result.
  Size/delivery/recovery hardware checks are not affected.

- 2026-10-21 (later) m12p_c12 full 13-driver v3 gate: 13/13 rc 0 (policy 296/296, policy_boundary 99/99,
  control_timing 483/483 incl. the per-class READ cycles); evidence committed (f243d85f6), gate recomputes
  model_gate_passed on a fresh worktree. reproduce.sh now defaults to c12. Resource: N12/E12/T11 + pipe-1 egress
  padder 7 stages, both SDKs (vs m11_09 N11/E12/T11). Segmented READ 377->401 is OPEN/under investigation (not
  unsupported): the padded aggregate is link frames [24,292,85]; the first-block rewrite + continuation path is
  being probed. Recovery for the added single-frame classes (analog 141, base class0/integrity 247) is being added
  to the existing helpers; segmented recovery coordinates with the continuation probe.

## 2026-10-21 (evening) — review-96c729b7a continuation
- Workstream A DONE: c12 full gate evidence committed (f243d85f6), gate recomputes model_gate_passed on a fresh
  worktree; reproduce.sh defaults to c12; timing claim softened (control rules out a build-only cause, does not
  identify a cause); resource line = N12/E12/T11 + pipe-1 egress 7 stages. Commits 378306a89, 7a0afc772.
- Recovery (per-class) DONE: single-frame added classes covered; one 247-B loss selector read_resp_247 (class0 and
  integrity are byte-indistinguishable at 247 B, so no per-class drop claim); read_resp_analog 181; segmented
  NOT_EXERCISED; range unchanged; 668/583/65 pass; two reviews (BLOCKING collision fixed). Commit ae91e77f5.
- Segmented 377->401 OPEN (bounded probe done): software construct==pad_read byte-exact on 512 samples
  (constants_segmented.json; constants.json kept byte-stable 6f819e7e for c12's binding). Three P4 probes c13/c14/c15
  compile clean and each shows a wall PLACES (T 2nd child 0 extra stage; N len-admission 0 MAU; child-tag table in
  p0's 12 stages) but NONE is a faithful pad -- no segmented success claimed. Open risk: p0 MAU budget with the full
  padder+classifier+mapper together (next probe = faithful padder c16). Commit ed75a04d6.
- NEXT: faithful segmented padder c16 (decision: attempt now vs proceed to freeze c12 + hardware with segmented open);
  c12 freeze + per-class recovery hardware configs; hardware campaign (reference rotate4 + per-class recovery);
  timing PRECISION on hardware remains gated by the Vision environment (Philip decision to restore pre-reboot latency).

## 2026-10-22 — faithful segmented READ 377->401 landed (m12p_c20), software+model tier DONE
- Decision applied: option 1 (continue the faithful segmented implementation; c12 preserved as the reproducible
  checkpoint). The probe-only length tagging (c13/c14/c15) is replaced by the actual construction.
- make_m12.py --segmented-full: pipe-1 egress prefix padder (prepend 24-B synthetic FIR carrying the moved app
  header + padding-object header; rewrite block 0 of BOTH original frames -- frame 1 transport byte + its 4
  app-header bytes -> last 4 padding points, frame 2 transport byte -- recompute each block-0 CRC) + N classifier
  (admits ip.len 332/125) + T second child (child_seen1_reg) + E 401 reverse-ACK window. Link frames [24,292,85]=401;
  TCP packetization kept distinct, not assumed.
- derive.py / constants_segmented.json: segmented shape proved byte-equal to general_read_padding.pad_read over 512
  samples; prefix_link_crc_delta 0x79bf invariant across samples; written to a SEPARATE file so constants.json stays
  byte-stable at c12's binding 6f819e7e13660632. Per-frame block-0 CRCs and IP/TCP checksums are derived on chip
  (vary per response), not constants.
- c16/c17 wall DIAGNOSED: the TNA deparser rejects nested metadata conditionals on the checksum externs; FIXED by
  branching each checksum under a separate top-level header-validity guard. c18 (padder only) / c19 (+N classifier
  +T child) are the retained intermediate probes.
- m12p_c20 (source sha 1e94c31d80e6) compiles clean on bf-p4c 9.13.1 AND 9.13.2 at N12/E12/T11 PLUS the 7-stage
  pipe-1 egress padder (off the pipe-0 budget -- the feared p0 MAU wall from c13/c15 did not materialize because the
  padder lives in pipe-1 egress, same profile as c12). Resource line unchanged from c12.
- Profiles widened to t_child_count in (1,2,3): model_profile.py, hw/sealed_profile.py, test_supported_profile.py
  (bad-children mutation now 4). New interpreter tests: test_segmented_pad (7) + test_segmented_classifier (2) +
  test_segmented_mapper (2), byte-exactness vs pad_read.
- Full 13-driver v3 model gate on c20: qualification model_gate_passed, blocked_reasons [], all 13 drivers (rearm
  799/799 and dup 102/102 exercise the two-child hold/release). Committed 33e21fd07 with the per-run result/provenance
  files + the two bound contention logs as byte-exact xz (hash-checked restore). Gate RECOMPUTES model_gate_passed on
  a fresh detached worktree at 33e21fd07 after restore_retained_logs.py (both c20 logs restore to their pinned sha).
- TIER BOUNDARIES (honest): software construction + encoding byte-exactness and both-SDK placement are proven;
  the T two-child hold/release ORDER, the forward two-frame single-commit, and the deparser IP/TCP checksum externs
  are COMPILED-MODEL tier only (not interpreter-validatable, same caveat as the range padder). seg1 admission is
  content-blind (dl.len==0x46 && FIN gating). HARDWARE coverage of the segmented class is PENDING -- not claimed.
- NEXT: c20 freeze + hardware configs (reference rotate4 + per-class recovery, segmented block); endpoint deploy to
  Vision; dry-run; authorized detached campaign with restoration verification; report all occupied pipelines incl.
  the 7-stage padder; first-frame vs complete-response timing separately. Timing PRECISION stays gated by the Vision
  environment (Philip decision to restore pre-reboot latency); size/delivery/recovery are not blocked by it.

## 2026-10-22 (cont.) — segmented exercised through the compiled model: seg0 pads, seg1 continuation DROPPED (open)
- Built `seg61_02/model_segmented.py` (+ `read_complete_01/vectors/make_segmented_vectors.py` and the committed
  `segmented_vectors.json`, 16 samples cross-checked == pad_read). It injects a real 377-B two-segment integrity
  response through the compiled c20 model. The driver runs under the system Python 3.8 inside the model namespace,
  so the natives/expecteds are precomputed under the research Python (derive.py cannot import under 3.8).
- MEASURED (run model_segmented_m12p_c20_01, 10/10; SEG_DIAG counter run): **seg0 (ip.len 332) is admitted and
  padded to the exact 316-B first image at the wire-start seq** (E out_translate + p1_outcome.p1_padded) -- the
  segmented padder fires correctly on silicon-model. **seg1 (ip.len 125, FIN) is dropped in N pipe-0 ingress**:
  0 egress frames, no E outcome code, no p1_outcome/count_busy/T-outcome bump, though N's parser admits it
  (read_response_fb, kind 11). So c20 emits only the first segment; the end-to-end 401 is NOT delivered.
- ROOT CAUSE: --segmented-full applies segmented_pad_pipe1 + segmented_classifier + segmented_t but has NO N
  read-lane CONTINUATION handling (forward seg1 as the 2nd segment of one in-progress read). segmented_n only adds
  parser admission (already present via the classifier) and its probe anchors no longer match the full+passthrough
  base; a --seg-n-full attempt was reverted (wrong layer: the parser already admits 332/125; the drop is in the
  N control). The real fix is a new N-control change -- the next scoped step; the segmented hardware campaign must
  wait for it (a seg0-only build cannot deliver 401 on silicon). Recorded in COMPLETION_RECORD §3a.
- The driver ASSERTS seg0 (positive evidence) and RECORDS seg1 as a disclosed OPEN finding; it is runnable
  (registered in run_model) but NOT in the enforced 13-driver gate (segmented is not end-to-end functional). The
  c20 v3 gate still recomputes model_gate_passed with it registered. Single-frame classes are unaffected.

## 2026-10-22 — two-READ-target directive (Claude_Two_READ_Targets_Hardware_Directive.md), candidate m12p_c21
- Start: HEAD c432d195e (= origin/main = the directive's inspected source). Pre-existing tracked changes left alone:
  `D DNP3_Implementation_Directive_492013014.md`, `M WORKING_NOTES.md`. Scope: mixed READ 91->141 + base full
  (integrity) READ 247->271 with unchanged SBO 37->61 and timing/J; the native 377 segmented work is out of scope
  (history kept). Binding corrections from Philip: strict endpoint checks; the shallow tcp_sum=0xffeb is a WAIVER,
  not a computed checksum; loss.parse_drop's bound is payload-layer; placement choices are hypotheses.
- M1 DONE (live software tier; NOT switch, NOT timing). Endpoint SocketGateReadSchedule.cpp: class `mixed` = ONE READ
  Scan({Range8(1,2,0,15), Range8(30,1,0,7)}); schedules mixed_full / mixed / full; strict CASE4_PAD_EXPECT; fixture
  variants. Binary fdddba4f0b858091 (pinned lib 6b99199e...; pad58b binary unchanged 8d78cf2f; the pre-change build is
  kept untracked at repeat_sbo_endpoint/build_pre_two_read_20261022). Live captures (evidence/m1_two_read_01/
  native_capture_v0,v1): mixed request 25 B -> one 91-B frame in one TCP segment, headers G1V2 q00 x16 + G30V1 q00 x8;
  integrity 27 -> 247 (G1V2 16, G30V1 21, G20V1 8, G10V2 23); SBO 35 -> 37; variants carry different values/flags.
  live_two_read.py (live master through a pad_read proxy, targets [141,271]): 15/15 cases reach the intended outcome:
  4 positive (values/flags varied; exact [50,91]/141/26 and [24,247]/271/4 prefix), 11 negative each rejected by the
  master's fixture check on a delivered READ (undeclared, missing, wrong count, changed value, shifted index, non-zero
  flags, padding after originals, mixed reserved header, G1V1 padding, repeated analog, reordered originals).
- M1 review (code-reviewer, BLOCKING) found two live-confirmed loopholes in the first strict check: repeated AI/counter/
  BOS indices overwrote silently, and reordered/restructured original headers passed. FIXED: duplicates counted for every
  type; exact native header structure (gv, qualifier, count, order) required for mixed/integrity/class0. Both loopholes
  are now negative cases that fail. Also fixed: verdicts require the intended failure reason and the exact shapes;
  README/comment claims narrowed (the master does not see IIN/link octets -- the capture readout does); padding
  declared for an unscheduled class and a fixture variant without CASE4_DB are rejected. rotate4/variant 0 is
  byte-identical to the pre-change build on base and large (rotate4_unchanged_vs_head.json).
- M2-B1 DONE: vectors/derive_two_read.py -> constants_two_read.json (targets [141,271]; 512 fully varied samples per
  shape construct==pad_read; every constant invariant; live captures v0/v1 reproduced). mixed prefix LEN 0x27, link-CRC
  delta 29526, 22-B constant remainder; full prefix LEN 0x11, delta 49249. constants.json / constants_segmented.json
  unchanged (6f819e7e / 72beff03); derive.py not edited.
- M2 (2026-10-22/23) -- integrated P4 candidate, attempts recorded in order (make_m12.py --policy --c3 cimg --shapes
  passthrough --two-read; new transforms two_read_pad_pipe1 / two_read_e / two_read_admit_n; the range-READ padder
  is REPLACED, not stacked):
  * m12p_c21 compile_failed (9.13.1): action data as the second operand of a subtraction (out_reset_front_rd).
  * m12p_c22 compile_failed: 13 pipe-0 stages in BOTH gresses (critical path 11 -> resource contention, not depth).
    Isolation probes: m12p_c22_probe_e (every E/pipe-1 change, no mixed N admission) placed N12/E12;
    m12p_c22_probe_n (c12 + the stacked mixed N admission only) 13/13 -> the N transform cost the stage.
  * m12p_c23 placed N12/E12/T11 + pipe-1 egress 7 on 9.13.1 AND 9.13.2 by REPLACING the analog/class0 READ admission
    with the mixed one (net fewer N tables than c12). Model (c23): control_timing 415/415 incl. 6 timed rounds of
    mixed->S->O->full->S->O (READ images left as 141 x6 and 271 x6, held/released ACK-then-response, byte-exact incl.
    IP/TCP checksums); policy 281/281 (11 mixed @141 + 10 full @271, independent decode); policy_boundary 206/206
    (per-image C3 for 141/271/61 + every transition order incl. mixed<->full, C5 per READ image); smoke 30, packets
    622, smoke_sizeoff 30, repeat 523, select_lifecycle 120, abandon 12. rearm/dup stopped on the unpinned-artifact
    gate (not behavioural); abort/contention not completed (gate stopped for c24).
  * Review of c23 (code-reviewer): construction/arithmetic sound (independent incremental-vs-full checksum
    simulation 0/600 mismatches); findings acted on in m12p_c24: range READ RST row (49) restored; pipe-1 profile keys
    the exact (ip.len, LEN) pair (c23 padded a crossed IP-287/LEN-0x4c frame -- shown; c24 refuses it); generator
    cross-checks of the integrity request/object headers; the bad-block-0-CRC interpreter test now corrupts a point
    octet and a CRC octet (it had hit the profile) + a mutation test proving the CRC condition load-bearing; scope
    wording: analog/class0 are FORWARDED NATIVELY outside timing/size (not dropped); the control-timing profile gate
    accepts the two-READ native list strictly (candidate_campaign._native_inputs_supported + tests).
  * m12p_c24 (source 61f9af0fa141) placed N12/E12/T11 + pipe-1 egress 7 on 9.13.1 and 9.13.2; artifacts pinned for
    both SDKs. Full 13-driver gate running. The shallow READ-response TCP checksum is a WAIVER (finish_shallow writes
    0xffeb, the network table's accept residual): asserted as a limitation in the interpreter tests; a request's TCP
    checksum is verified (bad checksum -> network_valid 0, refused).
  * Shared driver module read_policy_expect.py now carries a per-native SHAPES map (single-shape builds unchanged);
    consequence: c12/c20 model gates recompute only at their last current commit (c432d195e), as b08 at its pin.

- 2026-10-22 (two-READ M3 + harness, c24 gate -> c25). Model gate on m12p_c24 (1st full run):
  control_timing 415, policy 281, policy_boundary 206, smoke 30, packets 622, smoke_sizeoff 30, dup 102, repeat 523,
  select_lifecycle 120, abandon 12, abort 79 all passed. Two non-passes, both diagnosed:
  * rearm 99/339 (240 inverse_distance cases): a DRIVER expectation, not the P4. The driver probed ACKs inside "the
    image" of its default READ, the range READ, which c24 leaves native (49): the switch returned every such ACK
    unchanged, which is the correct mapping for an unpadded response; the driver's padded-image formula expected
    ack 901 and a shrunk window. Fixed in the driver: on a two-READ build it drives the padded mixed READ (91 -> 141,
    captured bytes) and every hard-coded range offset is derived (READ_REQ, READ_NATIVE, READ_IMAGE_LEN; c12 values
    asserted unchanged). Re-run (attempt 02): 799/799, inverse distances 1..141.
  * contention rc=3 twice: bf_switchd gRPC not up within the launcher's 15 s WAIT (startup 9-10 s normally; both
    attempts overlapped heavy host load I had caused, load average 24). Re-run with WAIT=60 (startup allowance only):
    413/413.
  * two_read_robust (new driver): R retransmission (mixed, full, range control; each retransmitted response copy
    replayed exact, 1 copy each) and C corruption -- bad block-0 point CRC, bad TCP checksum, bad tail CRC with a valid
    TCP checksum, each on mixed and full -- all pass (108 checks). X FAILED as written: it expected analog/class0
    requests "forwarded natively" (the c23-review wording above); the model WITHHOLDS them. That wording was a source
    reading, never exercised; it was wrong. X rewritten to the measured disposition (request and its retransmission
    withheld, nothing either way; a supported READ at the same client sequence still pads byte-exact) -> passes.
    Z failed at the new connection's SYN-ACK after a BARE RST (no ACK flag): the reset reached the outstation but did
    not retire the connection. Z now uses the reset a Linux master sends (RST|ACK acknowledging the padded image, as
    ss -K in the persistence_rst block; the rearm driver's qualified_RST path); the bare RST is kept as a recorded,
    unasserted characterization run last (limitation, not compared with m11_09).
  * Correction carried forward: m12p_c25 = m12p_c24's P4 byte for byte (61f9af0fa141) with the profile scope text
    corrected to the measured disposition; c24 stays as the record. c25 is recompiled on both SDKs and the WHOLE gate
    re-runs once on it with the final drivers (the c24 runs above bind c24's inputs.json and mixed driver revisions).
  * Hardware harness for the two READs (protocol/hw_vepa): per-arm strict padding declaration
    (campaign.pad_expect_arg: padded arm 'mixed=26,integrity=4' restricted to the scheduled classes; off arm none) +
    an independent check of the master's pad_expect and per-READ padding_expected/padding_points
    (checks.read_padding_record_checks); report.py per-class targets/natives; single-class loss workloads (schedule
    mixed or full) with request_mixed/request_full selectors, class-image @LEN suffixes and per-class growth;
    reconnect carries the schedule on every connection and the declaration on c1/c3 only (c2 has no rows: native).
    Series path (vision_candidate/candidate_series) delegated with a spec; pending its review.
  * Recovery configs (make_two_read_configs.py, default build m12p_c25): loss_mixed_950 / loss_full_950 (one READ
    class each, core preset with the class's own request selector), persistence graceful/rst, reconnect and
    held_operate on mixed_full (no length selector involved). Expected per-class counts are written into each config
    (traffic.expected_reads_per_class).
- 2026-10-22 (c25 gate + review). m12p_c25 (P4 61f9af0fa141 = c24; corrected profile) compiled 9.13.1 + 9.13.2
  exit 0, N12/E12/T11 + pipe-1 egress 7 (assembly identical to c24 apart from the compiler run_id); artifacts pinned;
  resource_review.json written. Full gate, attempt 01, one run each, WAIT=60: control_timing 415, policy 281,
  policy_boundary 206, smoke 30, packets 622, smoke_sizeoff 30, rearm 799, dup 102, repeat 523, select_lifecycle
  120, abandon 12, abort 79, contention 413, two_read_robust 163 -- all passed. rearm re-run as attempt 02 after
  the review added an explicit padded-image check to the driver (see below).
  * two_read_robust c25_01 bare-RST characterization (recorded, not asserted): RST forwarded, next connection's SYN
    and SYN-ACK both passed. On c24_02 (Z, same shape, as an asserted step) the SYN-ACK was dropped. The two runs
    disagree; bare-RST behaviour is OPEN, not characterized.
  * Series path (builder, verified here): vision_candidate/candidate_series carry the schedule, db, endpoint
    binary, declaration and per-class expectation to every series connection; series suite 624 pass; the three
    series blocks plan with mixed_full and mixed=26,integrity=4. Nit kept: --endpoint-binary/--pad-expect appear twice
    in the series command (both copies from the same functions; argparse takes the last).
  * Independent review of the harness/driver/readout changes: no BLOCKING. Acted on: loss presets refused on
    multi-class two-READ schedules; read_padding required on padded two-READ arms; the independent padding check
    added to verdict_loss; robust R now requires >= 1 forwarded retransmission copy (it could pass on zero); robust
    module docstring corrected (X withheld); rearm two-READ path raises unless its probe image is the declared padded
    target; empty read_commands fail the padding check; pad_expect_arg never emits an empty flag; reproduce.sh
    prunes worktrees and no longer hides the git error. DISCLOSED behaviour change: report.py now takes per-class
    targets whenever standards.json carries read_classes, so rotate4 (c12) report metrics change -- they were
    comparing every READ class to one length and are corrected, not just the two-READ ones.
  * reproduce.sh pins: c20 recomputes at c432d195e (passes); c12 at 83498d4c1, the last commit before c20 changed
    model_profile.py (378306a89 lacked c12's abort run; c432d195e fails on model_profile.py).
