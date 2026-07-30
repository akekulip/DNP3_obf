# All three repairs on the live build against the physical SEL-751

**2026-07-30. `case_a_defense3_repair_candidate` with R1 + R2 + R3 and full telemetry,
11/12 ingress stages, critical path 10.** 960 attempted, **960 responded, 0 unanswered**.
Switch restored to `d3_abs.conf` and verified.

Same campaign design as both earlier runs — six arms, interleaved round by round, 200 ms
poll gap, same D values, 40 polls per block — so the three are directly comparable.

## R2 does no harm on the live path

| arm | READ→ACK median: original (unrepaired) | R1+R3 | **R1+R2+R3** |
|---|---|---|---|
| native | 0.453 ms | 0.457 | **0.461** |
| D = 1 | 1.514 | 1.519 | **1.513** |
| D = 2 | 2.515 | 2.517 | **2.514** |
| D = 4 | 4.508 | 4.514 | **4.514** |
| D = 8 | 8.519 | 8.587 | **8.519** |
| D = 16 | 16.509 | 16.510 | **16.512** |

**Every value is within 1–6 µs of the unrepaired original**, against holds of 1–16 ms.

**And it settles the one loose end from the R1+R3 run.** That session showed D = 8 at
8.587 ms — 68 µs high — which I attributed to session noise rather than to R1. With a
cleaner session it returns to **8.519 ms, matching the original exactly**. The attribution
was right, and it is now evidence rather than an assertion.

## The CLRT result, third independent reproduction

| arm | D | CLRT med | CLRT sd | CLRT max | collapsed | sep vs native |
|---|---|---|---|---|---|---|
| native | — | 2.831 | 3.041 | 14.758 | 0/160 | — (floor **0.511**) |
| d1 | 1 | 1.787 | 3.313 | 15.455 | 0/160 | 0.696 |
| d2 | 2 | 0.771 | 3.046 | 14.345 | 36/160 | 0.744 |
| d4 | 4 | 0.033 | 2.607 | 19.438 | 120/160 | 0.881 |
| d8 | 8 | 0.032 | 0.591 | 4.144 | 155/160 | 0.983 |
| d16 | 16 | **0.032** | **0.013** | 0.044 | **160/160** | 1.000 |

At D = 16: median 32 µs, sd 13 µs, max 44 µs, all 160 collapsed — against 0.032/0.012/0.047
originally and 0.031/0.011/0.049 on R1+R3. Still 21 distinct values, so still a distribution.

**This was the cleanest of the three sessions**: the native-versus-native drift floor is
**0.511**, against 0.530 originally and 0.582 on the R1+R3 run. Which is worth stating
plainly — it means the *lower* CLRT separabilities here (0.881 at D = 4 versus 0.966
originally) are again a session property, not a repair effect. Comparisons remain
within-session by construction.

## Mechanism, over 800 defended transactions

| measurement | value |
|---|---|
| ordering invariant | **960 / 960**, every arm 160/160 |
| tokens admitted | **+51 200 = 800 × 64**, exactly |
| tokens terminating on the deadline | equal to admitted, at every read |
| stale terminations / budget expiries / duplicate suppressions / queue drops | **0 / 0 / 0 / 0** |

**Fail-open margin, now agreed by three independent sessions**: 1.49×, 1.59× and **1.58×**
at D = 16. §6.3's original 8.8× is wrong on all three.

## What this does not show

**R2's path was not exercised here, by construction.** Fail-open requires the budget to
expire before the deadline, and in a healthy campaign the deadline always wins — `TMO = 0`
and `FAILOPEN = 0` in all six arms, exactly as in every previous campaign. This run
establishes that R2 **does no harm** on live traffic; its *positive* behaviour is
established synthetically (`evidence/failopen/RESULTS.md`, 28/28 trials at two budgets).

**R1's rejecting arm was likewise not exercised** — the relay sent no mis-sequenced
response, as before.

So all three repairs are now: correct in the model, correct in the compiled assembly,
demonstrated on silicon in the synthetic build, and shown harmless on the live path against
the real relay. The remaining gaps are adversarial cases the relay will not produce on its
own: a mis-sequenced response (R1), a foreign token at budget zero (R2), and an injected
`0x88C1` frame (R3).
