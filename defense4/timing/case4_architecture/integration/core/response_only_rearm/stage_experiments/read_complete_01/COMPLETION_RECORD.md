# read_complete_01 — completion record (2026-10-21, overnight run)

**Status: NOT complete at the physical-switch tier. Hardware is blocked by an unsafe-restoration flag that my own
config error set; the reviewed reconcile refused to clear it (by design), and clearing it needs Philip's decision.**
Every tier below the switch is complete and reproducible. Sizing and timing together on silicon have NOT been shown.

## 1. What blocks completion

| when (UTC) | event | evidence |
|---|---|---|
| 08:40–08:46 | Campaign `rc01_hw_b08_20261021_01`, block 1 (four-arm reference) on m12p_b08. `off` and `timing_only` ok; `size_only` failed: master READ 49, expected 141. restore_verify ok; campaign stopped itself. | `evidence/hw_blocks/rc01_hw_b08_20261021_01_reference/` |
| — | Root cause: the baseline installer's `plan()` (`response_only/hw/bringup_composite.py:158-170`) keeps only `p0.r_`/`p0.n_` rows, so the `p1.x_Egress.p1_conn` enable row was discarded; the padder never ran on silicon. Model drivers install their own rows and never call `plan()`, so the model gate could not see this. Fixed (`plan_with_p1`), test red→green; independent review confirmed the cause. | commit `232e26c57` |
| — | Hardware checkers assumed READ = 61 on candidate61 builds; generalized for `read_image_len` (standards, capture_boundary, profile_check, clrt_check), with independent 49→141 constructions checked against 64 reference-encoder vectors. | commit `232e26c57` |
| 09:02 | Campaign `rc01_hw_b08_20261021_02`, step 1 (m11_09 control) failed at config load: I had rewritten `evaluation.purpose` as free text, which `campaign.load_config` rejects. **No hardware contact** (traceback before any switch command, `steps/*control*/command.log`). With no restore record, the supervisor set `unsafe_restoration=true` (fail-closed). I had skipped the dry run for this config. | `evidence/hw_campaigns/rc01_hw_b08_20261021_02/` |
| 09:0x | `evaluation_campaign.py reconcile` **REFUSED** (no restore record, no pre-run snapshot, no freeze check retained: the block never reached hardware). Flag left set, as the rule requires. | ownership: `~/.local/state/dnp3-evaluation/tofino1-testbed/ownership.json` |
| 09:1x | Fresh read-only `restore_verify` on a copy of block 1's restore inputs: **ok** — production program, all compared tables equal the pre-run snapshot, Vision state, ping. This documents the switch state; it does not clear the flag. | `evidence/control/state_check_*/` |

**Decision needed (Philip):** the flag is on a step that provably never reached hardware, and the switch is
verified in its restored state. Options: (a) authorize clearing this specific flag on that evidence (one
atomic ownership update with a record binding the command.log and the fresh check), or (b) extend reconcile
to accept a "never reached hardware" case with its own test. Until then no hardware runs.

**Ready to run once cleared:** campaign manifest `rc01_hw_b08_20261021_02` (control first, then the b08 reference
and the five recovery blocks) needs re-init under a new id because step 1's config changed; corrected control
config passes `load_config` and its dry run (rc 0); b08 freeze checks pass for all six configs.

## 2. Tiers reached

| tier | result |
|---|---|
| Source reasoning | Policy rule v3 (Ditto-inspired adaptation, aggregate-response layer): targets **141 / 247 / 401**, 10.93 % added vs 19.04 % for the 163/269/399 comparator (`policy/TARGET_POLICY.md`). Ditto's guarantee does not transfer; low overhead is not evidence of effective obfuscation. |
| Encoding tests | Handoff tests 51/51; policy coverage 25/25 over 10,243 profile cases; constants byte-exact vs `pad_read` on 512 samples (`vectors/derive.py`). |
| Live software endpoints | Pinned OpenDNP3 4648fcb (binary `ea734720…`): range 49→141, analog/class0/integrity at target, large 377→401, 16+16 each, IIN 0x9000, no errors (`evidence/m3_live_policy_01`). Endpoint acceptance, not an IEEE 1815 conformance claim. |
| Compiler placement | m12p_b08 source `7b1281bc4aa7…`: SDK 9.13.1 and 9.13.2 both exit 0; N 11 / E 12 / T 11 stages (as m11_09) + pipe-1 egress padder 7 stages, no added traversal. 9.13.2 artifacts: p0 tofino.bin `438cb69b…`, p1 tofino.bin `f7200d90…`, bfrt.json `5c5939c4…`. |
| Compiled model | v3 gate passed (13 drivers, 0 failures: smoke 30, packets 622, rearm 799, dup 102, repeat 523, select_lifecycle 120, control_timing 211, contention 413, abort 79, abandon 12, policy 386, policy_boundary 105, smoke_sizeoff 30). Includes timed R→S→O→R and C3/C5 boundaries. |
| Physical switch | **Partial.** Block 1 on b08 silicon, independent readout (`analysis/hw_read_readout.py`): `off` and `timing_only` READ/SBO exactly native, 65/65 READs; `size_only` SELECT/OPERATE 37→61 on all 128 responses, wire overhead +16.75 % (SBO only), READ 49 (padder not enabled — the installer defect). READ padding on silicon: **not shown.** |

## 3. Open timing finding (not attributed)

On block 1, `timing_only` READ CLRT error vs the 950 µs gap: median 1,229 µs, p99 2,070 µs; m11_09's same block:
5 / 63 µs. The `off` arm already differs: master→outstation request transit median 0.66–1.16 ms (p99 ≈ 4 ms, near
1 ms multiples) vs ≈ 95 µs on m11_09, while outstation→master pure ACKs are unchanged (49 vs 28 µs). Vision was
rebooted since m11_09 (uptime ≈ 1.4 d vs ≈ 13 d), now runs docker bridges, and its TCP minrtt is 0.875 vs 0.17 ms.
The m11_09 control block on today's host separates host from build; it is the first step of the ready campaign.

## 4. Coverage: software vs hardware

Software covers the full declared profile (range, analog, class0, integrity at target, large 377→401, and the
resegment fallback). **Hardware implements the range shape only (49→141)**; analog/class0/integrity pass through
at target size untouched, and the 377→401 segmented class and the fallback are **not implemented in P4**.

## 5. Residual limitations

C3: the SBO-61 image's pre-start region is withheld, not stale-dropped (a per-image key costs a 13th stage).
`ina_img_t` is not keyed on direction. E's CRC defence-in-depth is reduced (N validates all CRCs; pipe 1 checks
block 0). T timing was calibrated with frames 92 octets shorter. The packet-boundary checker binds lengths as a
set, not per kind (review LOW). The model gate cannot see control-plane installer behaviour (the defect above).

## 6. Corrections recorded

The 2026-10-19 reverify ran with counter-statistics stripping added after the original failure (`291e8cb30`);
I had told Philip it passed with unchanged rules. The hardware readout first paired captures in the wrong
direction (out.pcap is what Vision sent); fixed before any number here was taken.

## 7. Reproduce

`bash reproduce.sh` (offline: software tests, policy, constants, P4 regeneration to `7b1281bc4aa7…`, model gate,
freeze; 4 min, all pass on 2026-10-21) and `bash reproduce.sh --readout` for the hardware readout.
