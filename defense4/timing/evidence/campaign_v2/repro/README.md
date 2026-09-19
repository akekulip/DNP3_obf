# campaign_v2 reproduction pipeline

A copy of `campaign_v1/repro/`, kept as a copy rather than a parameterisation because
`campaign_v1` is a frozen record and its pipeline is part of that record.

**What differs: `policy_config.json`, and the default output directory.** It carries `D_R` = 8 ms
and a release budget of 28 ms where `campaign_v1` carries 4 and 24, and records why — request
anchoring measures the response deadline from the request, so the budget must cover the relay's
whole request-to-response latency rather than only the part after its acknowledgment.

Everything else — the extractor, the validator, the sweep validator, the statistics, the two
attacker models, the permutation null, the figures, the tests and the publication gate — is
byte-identical to `campaign_v1/repro/`, so a difference between the two datasets is a difference in
the data and not in how it was read.

```
./reproduce.sh [OUT_DIR]        # default /tmp/cv2_out
```

## The sweep is a separate run, and it is required

Step 2 validates a hardware policy sweep in `../sweep/`, and `fig_policy_coverage_cost` is built
from it. `campaign_v1`'s sweep cannot be reused: it characterises the acknowledgment-anchored
build, whose release tail is a function of arrival phase — measured, it moves 0.78 ms when nothing
changes but how often the master polls, while the corrected build's is flat to within 8
microseconds across the same four intervals. A published figure has to describe the build that
shipped, so the sweep is re-run on the corrected build rather than dropped, and `reproduce.sh` will
fail at step 2 until `../sweep/` exists.
