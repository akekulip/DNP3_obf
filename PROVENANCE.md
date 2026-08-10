# Provenance and upstream contract

This is a research-only repository. The source evidence repository
`/home/philip/Projects/DNP3` is treated as STRICTLY READ-ONLY: no modify, clean, checkout, reset,
rebase, or commit is performed against it. All reproductions here read committed blobs at a pinned
commit.

## Pinned upstream

- Source repo: `/home/philip/Projects/DNP3`
- Branch: `origin/defense4-caseA-hw-integration`
- Pinned commit: `7c4a5a78183b42cea4334b54faabcd5af14537a8` (`7c4a5a7`)
  - author akekulip <akekulip@gmail.com>, 2026-08-10, "Add size/timing co-residency leakage
    measurement study (research line)"
  - verified as the tip of `origin/defense4-caseA-hw-integration` and local HEAD; source tree clean.

## Key evidence blob hashes at 7c4a5a7 (git object ids)

| blob sha1 | path |
|---|---|
| `59ef164b830e974fda597d900e7a64368c4bf7a7` | research/size_timing_coresidency/CHARTER.md |
| `f44c3baf72c4c60c289ae5c025ffd357ae2656aa` | research/size_timing_coresidency/reports/leakage-measurements.md |
| `ace17e3d06874d8abc02244680fe1c9032a1340f` | research/size_timing_coresidency/reports/p4-resource-audit.md |
| `b1b3df231740d9cb771a468afd8f0530fdd680e4` | research/size_timing_coresidency/reports/retirement-defect.md |
| `af411c5e582ed1a9631aa92573dd441fc7305ef0` | defense4/timing/p4/defense4_caseA.p4 |
| `0e1de0d9662e5da37486fcfe6480c89482814a0d` | defense4/timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md |
| `a2a3aadaf3bcfbb5fb2fb66191f5801d70c6c30b` | defense4/timing/evidence/final_run/NORMALIZATION_ANALYSIS.md |

## Key upstream commits

- Retirement/lifecycle fix: `e47bcaa` (2026-08-07) "Defense 4 lifecycle fix: mode-conditioned
  ACK-release retire + qid5 terminate-when-pending".

## Large-READ evidence

- `dnp3_split_harness/captures/baseline/large_read.pcap` (the 12,204-byte READ that invalidates a
  general K=3 bound); attacker-eval artifact `dnp3_split_harness/reports/attacker_eval_results.json`.

## Rules honored

No GitHub remote is configured and nothing is pushed. This project is not ADTA, GridCloak, or
Defense 4; `DNP3_fixed_transcript` is only a working repository name. Defense 4 is a frozen upstream
timing result and is not rewritten here.
