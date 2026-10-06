# Focused hardware results

Validated primary exchanges: 60,000.
Capture drops: 0; TCP retransmission flags: 0.

| Operation | Median total (ms) | p99 total (ms) | Added pooled median (ms) | >1 ms late |
|---|---:|---:|---:|---:|
| READ | 6.113 | 15.682 | 3.344 | 8.88% |
| SELECT | 6.116 | 14.835 | 3.580 | 8.98% |
| OPERATE | 6.115 | 13.974 | 2.726 | 11.98% |

Full tested attacker criterion met: False.
This is a measured result for the tested classifiers and transaction classes on one SEL-751, not a guarantee against all attackers.
