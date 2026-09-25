# campaign_v2 reproduction pipeline

A copy of `campaign_v1/repro/`, kept as a copy rather than a parameterisation because
`campaign_v1` is a frozen record and its pipeline is part of that record.

**Campaign policy:** `policy_config.json` carries `D_R` = 8 ms
and a release budget of 28 ms where `campaign_v1` carries 4 and 24, and records why — request
anchoring measures the response deadline from the request, so the budget must cover the relay's
whole request-to-response latency rather than only the part after its acknowledgment.

The extractor and statistical/attacker estimators retain the same definitions as campaign v1.
The active figure generators were corrected on 2026-09-25: policy-centred detail windows,
exact empirical curve exports, complete scatter data, and legends outside the data panels.
The sweep validator also checks the archived per-point control-plane readbacks, including
the separately quantised timing addends, request anchoring in D4, and disabled size shaping.
Statistics metadata now describes the request-anchored build. These reporting corrections
do not change the canonical campaign measurements or campaign result values. Sweep intervals
now also use integer timestamp subtraction, removing sub-microsecond floating-point noise;
the corresponding sweep summaries may differ in their last stored decimal places. The tail
generator likewise uses integer capture timestamps. Campaign v1 remains the historical record
and its generators are unchanged.

See the [2026-09-25 figure/data audit](audit_20260925/README.md) for checks, corrections,
retained evidence, and the distinction from the later seven-stage hardware smoke test.

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
