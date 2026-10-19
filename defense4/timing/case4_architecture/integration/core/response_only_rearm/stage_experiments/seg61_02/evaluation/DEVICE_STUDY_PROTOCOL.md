# Device-classification study on m11_09 (pre-registered 2026-10-19)

Authority: Philip, 2026-10-19 ("Device classification"; "go on. you are the PI"). This document is
written before any block of the study runs. Every choice below is fixed before data exist; any
later change is recorded as a dated amendment with its reason, and results are reported against
the version that was frozen when the data were collected.

## Question

Formby et al. (NDSS 2016) fingerprint *devices* from histograms of CLRT. The manuscript's
operation-classification result has two weaknesses (LIN_DRAFT_REVIEW item 7): the operation is
already visible in the function code, and the classifier trained before deployment fails under any
constant delay. This study asks Formby's own question on the evaluated binary:

> Once NOMAD is deployed, can a Formby classifier that is retrained on obfuscated traffic still tell
> apart devices that differ in their native CLRT, and does NOMAD do better than a constant delay?

## Build and scope

- Binary: m11_09 exactly as evaluated (`ctl_timing_01/evidence/m11_09`, source sha256 `f1de2b30…`),
  the common envelope frozen by `eval_m11_09_20261018_02` (`release/audit/common_envelope.json`),
  and that campaign's shaping, ports and K. Nothing in the data plane or the control plane changes.
- Setting: D = 10 ms, J = 2.4 ms (the primary setting). READ polls only (`sbo = 0`): Formby compute
  CLRT on READ, and no OPERATE is issued.
- Endpoints: the supported OpenDNP3 master and outstation on Vision (VEPA, device port 9). No
  physical relay is connected or operated.

## Devices (emulated, fixed before data)

Every device acknowledges separately and then responds, as the SEL-751 does. The response delay is
applied by netem on the outstation's READ responses (`vision_run.py casea on`).

| device | netem delay | jitter | distribution | rationale |
|---|---|---|---|---|
| `dev_const5` | 5 ms | 0 | none | the outstation of `eval_m11_09_20261018_02` |
| `dev_sel` | 2 ms | 2 ms | paretonormal | heavy right tail, after the SEL-751 READ captures of 2026-08-03 (median CLRT 2.79 ms, p95 7.45 ms, maximum 23.2 ms, n = 100) |
| `dev_slow` | 9 ms | 1 ms | normal | a slower device whose CLRT does not overlap the others' bulk |

The parameters are not tuned against any accuracy. The pilot reports each device's measured CLRT
distribution descriptively; a device is changed only if its pilot shows a harness fault, and that
change is a dated amendment.

## Arms

`off` (No obfuscation) and `combined` (Timing+Size). Size does not change CLRT; `combined` is the
configuration the paper headlines. The constant-delay control is computed offline from `off`
(below), not run.

## Collection order (frozen before the first block)

1. Pilot: one block per device, arms `off` then `combined`, 64 READ per arm. Pilot data are used only
   for qualification and descriptive device profiles, never for training or testing.
2. Qualification (stop rule): every pilot block must restore-verify, reconcile its exchanges, and
   show, for `combined`, a committed (non-fallback) release for at least 95% of READ exchanges of
   `dev_const5` and `dev_slow`. `dev_sel`'s fallback rate is reported, not gated, because its tail is
   the point of the device. A failure stops the study; nothing is replaced or rerun silently.
3. Main: 16 rounds × 3 devices = 48 blocks, 512 READ per arm per block. Round r runs the devices in
   the order rotated left by (r − 1) mod 3, and the arms in the order `off, combined` for odd r and
   `combined, off` for even r. Rounds 1–8 are training, 9–16 testing. The analysis is fitted and
   locked after round 8 and before round 9.

Same supervision as the campaign: `evaluation_campaign.py` on Gambit, `run_block_frozen.sh`, an
independent restore verification after every block, no retries, no replacement, no reorder.

## Attacker and analysis (locked)

- Observable: the master-visible ("in" capture) CLRT of READ exchanges, from the campaign's
  publication extractor. Label: the device.
- Classifier: Formby's multinomial naive Bayes (alpha 1) on 200-bin histograms, 199 regular bins on
  [0, H) and an overflow bin, H = max(1 µs, 1.05 × the largest training CLRT of that attacker's own
  training set). Windows of K = 8, 32 and 64 consecutive valid exchanges within one connection,
  session and split; same window code as the campaign (`publication_analysis.make_windows`).
- Attackers:
  1. **Retrained (primary).** Trained on rounds 1–8 of one arm, tested on rounds 9–16 of the same arm.
  2. **Pre-deployment (secondary).** Trained on `off` rounds 1–8, tested on `combined` rounds 9–16.
  3. **Constant-delay control.** The retrained attacker on `off` with every CLRT increased by one
     constant c, the same for all devices, c = median(`combined` CLRT) − median(`off` CLRT) over
     all devices' training rounds. This is the defense that only adds delay.
- Primary statistic: at K = 32, balanced accuracy of the retrained attacker under the
  constant-delay control minus under `combined`, with a 95% interval from 10,000 paired bootstrap
  resamples of the 8 test rounds (seed 20261019). Chance among three devices is 1/3.
- Secondary, all reported with pointwise intervals: every attacker at K = 8, 32, 64; `off` vs
  `combined` for the retrained attacker; per-device recall; fallback counts per device and arm.
- Offline baseline (no new data): Formby's classifier on native READ CLRT of the physical SEL-751
  (captures of 2026-08-03, n = 100) against `dev_const5` `off`, at K = 8, reported descriptively
  only, because 100 exchanges give 12 windows.

## What the result can and cannot claim

- Devices are emulated by response delay on one software outstation; the study shows what reaches
  the master when devices differ in response timing, not identification of real products.
- If the retrained attacker under `combined` stays above chance, the paper reports it, with the
  residual's source if the data show it.

## Amendment 1 (2026-10-19, before any block ran)

netem draws a jittered delay from a 16-bit table scaled by 8192, so a sample never exceeds
delay + 4 × jitter: 10 ms for `dev_sel` and 13 ms for `dev_slow`, both well inside the 31 ms
acknowledgment deadline. No device is therefore expected to fall back, and the campaign postcheck,
which already requires zero fallbacks for every block, applies to every device including `dev_sel`.
This replaces "reported, not gated" for `dev_sel` in the qualification rule; it is stricter, not
looser. The emulated `dev_sel` tail is consequently bounded at 10 ms, while the physical SEL-751
reached 23.2 ms once in 100 READs.

The offline baseline ran on 2026-10-19 (`device_analysis.py baseline`): physical SEL-751 against the
campaign outstation without obfuscation, K = 8, balanced accuracy 1.0 on 64 + 6 test windows.
