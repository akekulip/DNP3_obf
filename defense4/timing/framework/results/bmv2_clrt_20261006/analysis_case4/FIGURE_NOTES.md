# BMv2 timing comparison

Question: how does the captured ACK-to-first-response gap change under the declared response-ready policy? Timing OFF and Obfuscated are the same retained 120-attempt software READ populations, not a new joint campaign.

Caption: Master-facing CLRT histograms with common 0.25 ms bins and a linear percentage of all attempted transactions per arm. The focused 0–3 ms view uses the same denominator as the full-range companion. Counts below/above each view and all outcomes are in stats.json.

Method: type-7 quantiles; sample variance divides by n−1 and is ms². Display bins differ from the separately retained Formby Eq. (1) signature (B=200, H=15 ms). Negative, nonfinite, and exact-H inputs are explicitly uncounted; positive overflow remains the last signature element. These populations have no device labels and establish no identification accuracy. BMv2 timings include software scheduling and do not establish Tofino wire bounds.

Sources: ../timing_off.json and ../response_ready.json in the historical bmv2_clrt_20261006 result directory; SHA-256 hashes are in provenance.json. Canonical transaction/bin CSVs are generated beside this note. Regenerate with analysis/clrt_figure.py RESULTS_DIR OUTPUT_DIR.
