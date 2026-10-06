# Formby classifier evaluation

This directory contains a reproducible offline evaluation of the completed 100-round delay-grid run. It does not modify the P4 source or deployed switch program.

Run from the repository root:

```sh
python3 defense4/timing/latency_search/formby_evaluation.py
python3 defense4/timing/latency_search/formby_report.py
```

`results.json` stores the full metrics, confusion matrices, held-out round scores, selected model parameters, data hashes, and protocol notes. `metrics.csv` is the result-level table; `round_metrics.csv` contains held-out round accuracy and per-class precision and recall; `per_class_metrics.csv` contains pooled precision, recall, F1, support, and per-class round mean/min precision and recall. Round minima are observed worst cases, not confidence bounds. The primary task labels both SBO response phases as one SBO physical-function class; the PDF also retains the three-phase task as a secondary diagnostic. `tutorial_timing_statistics.csv` contains held-out timing summaries. The PDF is a detailed plain-English tutorial with a glossary and worked examples. Plot PDFs/PNGs are derived from held-out or explicitly labeled descriptive data.

## Explanation corrections

- The grid used request anchoring (anchor_req=1 in all 800 fixed readbacks). Older adaptive-explainer prose describing ACK anchoring does not describe this run.
- At pool 20, native test rounds contain 20 READ/40 SBO signatures; each protected setting contains 5 READ/10 SBO. Their minimum scores have different sample supports.
- Zero precision can mean a class was never predicted; below-chance binary scores can retain information under label inversion. The tutorial explains both cases.
- Late-subset balanced accuracy pools all retained late samples; complete-class rounds control round summaries and the reporting gate.
