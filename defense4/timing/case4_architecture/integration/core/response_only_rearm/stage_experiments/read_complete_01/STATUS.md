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
