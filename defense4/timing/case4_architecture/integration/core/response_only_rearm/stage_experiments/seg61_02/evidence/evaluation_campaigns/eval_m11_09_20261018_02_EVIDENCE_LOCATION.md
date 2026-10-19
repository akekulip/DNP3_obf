# eval_m11_09_20261018_02: where the raw evidence is

Philip's decision (2026-10-19): the raw block evidence is kept on disk and not committed. That is the whole campaign
directory, about 11 GB in 50,158 files: per-block captures, counters, snapshots, ledgers and logs, plus
`release/`, `release_training/` and the large result tables.

- **Location:** Gambit (the evaluation host), at `seg61_02/evidence/evaluation_campaigns/eval_m11_09_20261018_02/`
  in this checkout.
- **Integrity:** every file's sha256 is in `eval_m11_09_20261018_02_EVIDENCE.sha256` (committed). To verify:
  ```bash
  cd seg61_02/evidence/evaluation_campaigns && sha256sum -c eval_m11_09_20261018_02_EVIDENCE.sha256
  ```
- **Large files** (over 50 MB): also listed, with sizes, in `seg61_02/evidence/UNTRACKED_LARGE_LOGS.sha256`.
- **Committed** (`ec4bda169`): the campaign report and state, configs, freezes, envelope, qualification, training
  attestation, results tables under 50 MB and figures, and the release manifest and scripts.

Regenerating the analysis needs the on-disk release:
```bash
reproduce_evaluation.py release --output OUT
```
On 2026-10-19 that produced 39/39 output files byte-identical to the campaign's export.

Losing the disk copy loses the raw evidence: the committed manifest can only prove a copy authentic. It cannot
recreate one.
