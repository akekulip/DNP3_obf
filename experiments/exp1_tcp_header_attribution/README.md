# Experiment 1 — offline TCP/IP-header attribution and deterministic PCAP transformation

This is the first experiment authorized under the one-Tofino research baseline (`../../DECISION_MEMO.md`,
commit `7c89611`). It is **offline only**: read-only over the frozen Defense 4 corpus, no hardware, no
Tofino, no live traffic. It cannot prove endpoint safety, Tofino feasibility, or complete header closure;
it attributes the outstation header fingerprint and tests whether an offline transformation removes it.

## Question

1. Which TCP options and header fields produce the observed outstation fingerprint?
2. Why does each observed `data_offset` value occur?
3. Can selected header fingerprints be removed in an offline PCAP transformation?
4. Which identity leaks remain after transformation?
5. What per-flow state and packet operations would a future Tofino implementation require?

## Layout

```
scripts/   exp1_lib.py, run_attribution.py, run_transform.py, run_validate.py
out/       corpus_manifest.json, packet_features.csv, session_signatures.json,
           attribution.json, baseline_classification.json, transform_manifest.json,
           validation.json, post_transform_signatures.json, collapse_summary.json
pcaps/     transformed copies of the short captures (T0/T1/T2/T3); large "L"
           transforms are gitignored, hashes in out/transform_manifest.json
CORPUS_MANIFEST.md  METHODOLOGY.md  RESULTS.md  TOFINO_REQUIREMENTS.md  VERDICT.md
```

## Reproduce

```bash
cd scripts
RP=~/.venvs/research/bin/python
$RP run_attribution.py     # phases 1-3: manifest, attribution, baseline observer test
$RP run_transform.py       # phase 4: T0/T1/T2/T3 transformed pcaps (originals untouched)
$RP run_validate.py        # phases 5-6: validation + post-transform observer test
```

All three are deterministic. Originals in `/home/philip/Projects/DNP3` are never written.

## Headline

The outstation `data_offset` fingerprint is attributed to exact TCP option bytes, chiefly the SYN-ACK
option layout and whether established segments carry the Timestamp option. A canonical-option-layout
transformation (T2) collapses the three physically-distinct device fingerprints to one public header
profile, offline, with the DNP3 payload byte-identical and all checksums valid; length-only IP
normalization (T0) does not. What this means for a real, live, on-switch defense is the subject of
Experiments 2 and 3 and is not claimed here. See `VERDICT.md`.
