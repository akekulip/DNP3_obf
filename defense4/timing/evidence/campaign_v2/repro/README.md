# campaign_v2 reproduction pipeline

This is `campaign_v1/repro/` with exactly two differences, kept as a copy rather than a
parameterisation because `campaign_v1` is a frozen record and its pipeline is part of that record.

1. **`policy_config.json`** carries `D_R` = 8 ms and a release budget of 28 ms, where `campaign_v1`
   carries 4 and 24, and records why: request anchoring measures the response deadline from the
   request, so the budget must cover the relay's whole request-to-response latency.
2. **The hardware policy sweep is absent.** `campaign_v1`'s sweep characterises the
   acknowledgment-anchored build, whose release tail is a function of arrival phase — measured, it
   moves 0.78 ms when nothing changes but how often the master polls. None of that transfers to the
   corrected build, whose tail is flat to within 8 microseconds across the same four intervals. A
   budget sweep on the corrected build is a separate run; until it exists the step is absent rather
   than wrong, and `validate_sweep.py` is not carried over.

Everything else — the extractor, the validator, the statistics, the two attacker models, the
permutation null, the figures, the tests and the publication gate — is byte-identical to
`campaign_v1/repro/`, so a difference between the two datasets is a difference in the data.

```
./reproduce.sh [OUT_DIR]        # default /tmp/cv2_out
```

On the first run the publication gate has nothing to compare against and needs `--update` to
publish; after that it is a real comparison.
