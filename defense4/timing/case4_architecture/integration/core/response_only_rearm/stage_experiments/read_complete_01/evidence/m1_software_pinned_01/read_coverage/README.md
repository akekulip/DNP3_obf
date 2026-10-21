# READ encoding coverage extension (software only)

The previous prefix-only serializer had holes in exact-length reachability.
This version retains that path where it works and adds full application-fragment
serialization as a fallback. It prepends synthetic G1V2 points, preserves the
original application header and every original object byte, emits transport
segments of at most 249 application bytes, and regenerates link CRCs. Native
frame cuts may change. This is a software reference, not a P4 implementation.

## Precise coverage statement

For a solicited READ response in the supported object/request profile, one
complete application fragment, encoded native length at most 377 bytes, capacity
at least 333 application bytes, and a noncolliding reserved binary-input range
large enough for the added points (tested 1024..4095), the serializer can reach
one of 163, 269 or 399 bytes. Equality requires no modification. Larger inputs
and other profiles must be checked explicitly; no unbounded universal claim.

Why this holds independently of the measured size distribution:

* Canonical encoded targets 163/269/399 hold 134/228/333 application bytes.
* For A application bytes in k link frames, encoded size is at least
  A+11k+2*ceil((A+k)/16). If k=1 then A<=249. If k>=2 and encoded size<=377,
  this lower bound implies A<=315. Thus all permitted native fragments fit
  below the 333-byte application capacity of the 399 target.
* Adding a 16-bit-range G1V2 block requires 7 header bytes plus n>=1 points.
  At A<=315, n=333-A-7 is at least 11; for A>=4 it is at most 322. A reserved
  range of 322 points, endpoint capacity 333, and valid 16-bit indices suffice.
* No byte of the original objects is altered. The input validator retains its
  measurement-encoding limitations; this length argument does not add support
  for unimplemented DNP3 object variations or multiple application fragments.

## Verification

51 pytest tests passed. The coverage tests include every representable application
length in the exercised static-point family from 10 through 315 bytes, an empty
4-byte application response, varied native frame cuts, a split application header,
sequence wraparound, and the formerly unreachable 370->399 gap. The 48 earlier
regressions remain passing. This is not an exhaustive enumeration of all bytes
or object combinations; the length argument covers the size dimension.

Live upstream OpenDNP3 3.1.2 tests forced the fallback using wide padding indices:
16 full READs 247->269 and 16 segmented READs 377->399, each with native comparison
polls. Original points/flags and IIN indications matched; tasks succeeded.
The library commit was c1dc7165a79cc08edbf4b6f6a21dbca8dabd83195c. The pinned
deployment fork, Tofino model, hardware and timing integration were not tested.

Synthetic points have zero flags/value. Acceptance by this master does not prove
universal master acceptance or full standards conformance. Targets are complete
encoded response lengths, not guaranteed TCP packet sizes.

## Reproduce

```sh
python3 -m pytest -q test_general.py test_coverage.py
LD_LIBRARY_PATH=/path/to/opendnp3/build/cpp/lib python3 live_fallback.py --binary /path/to/full_read_gate --output ./new-live-results
```

Build the included endpoint fixture against the stated upstream commit as in the
previous package. Retained live evidence is under live_fallback_01; do not reuse
an existing run directory. No deployment source was committed or pushed.

## Target-policy correction after reading Ditto

Ditto Section V chooses pattern states using equal-probability percentiles.
Reference: https://www.ndss-symposium.org/wp-content/uploads/2022-56B-paper.pdf

Our earlier 163/269/399 selection minimized added aggregate-response bytes.
It was not an implementation of that rule. On our retained sample, inverse-CDF
thirds are 141/247/377 for complete responses, but 85/247/292 for the 1,200
payload-bearing TCP packet observations. These are different units. The latter
values are statistical seeds, not validated DNP3 padding targets. Keep target
policy provisional while applying the paper's method at the intended observation
layer. The encoder's proven size coverage remains useful independently.
