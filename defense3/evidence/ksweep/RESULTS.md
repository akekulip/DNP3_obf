# Fail-open K-sweep — reconciling the single-token and aggregate results

**2026-07-30. Pure-defect synthetic build (`-DD3_SYNTH_EVENTS -DD3_LIVE_FULL_TELEMETRY`,
no repairs), READ-only fail-open, budget 500, 12 fail-open trials per K.** Switch restored
to `d3_abs.conf` and verified.

## Why this was run

A previous note left a contradiction unresolved: a *single injected* token reaching budget
zero did not clobber `reg_tag`, yet the 64-token reservoir's first token appeared to. I
should not have attributed that to "reservoir dynamics" without finding the packet that
writes `reg_tag`. This sweep varies the reservoir size `K` on the **native** admitted
tokens — the real path, not the injector — and reads the termination counters and `reg_tag`
after each fail-open.

## The result

| K | TMO (budget-expiry) | STALE | `reg_tag` after |
|---|---|---|---|
| 1 | **1** | **0** | **0x00 (cleared)** |
| 2 | 1 | 1 | 0x00 |
| 4 | 1 | 3 | 0x00 |
| 8 | 1 | 7 | 0x00 |
| 16 | 1 | 15 | 0x00 |
| 32 | 1 | 31 | 0x00 |
| 64 | 1 | 63 | 0x00 |

**TMO = 1 and STALE = K − 1 at every K, and `reg_tag` is cleared even at K = 1.** (12 of
14 recorded trials per K reached fail-open; the other 2 did not arm and are excluded.)

## What it establishes, plainly

**The defect is present at K = 1.** A *single* native reservoir token, reaching budget zero,
writes `TAG_INACTIVE` into `reg_tag` — exactly the write the audit's static reading
predicted, firing at level 2 before the stale check at level 3. It is not an emergent
property of a large reservoir.

**The 1 / K−1 cascade is the direct consequence.** The first budget-zero token clears the
tag (counted TMO, because its own return value still reflects the pre-clear generation and
reads as live). Every subsequent token then dequeues against a cleared `reg_tag`, computes a
non-zero difference, reads as foreign, and terminates STALE. So `1 TMO + (K−1) STALE` is
mechanical, and it appears at every K ≥ 2.

**This corrects the earlier "single token does not clobber" claim.** That observation came
from the *injected* token (§7.8), and it is now clear it was an **injection-harness
artifact**: a token forged through the legacy `is_pktgen = 0` path with `seq = 0` from the
start does not traverse the same write as a native token that was admitted (stamped) and
looped its budget down to zero. The native path is the ground truth, and it clobbers. The
report's §7.8 wording is corrected accordingly.

**Which packet writes `reg_tag`, answered:** the first budget-zero token of the fail-open
reservoir. There is no ambiguity left — the K = 1 case isolates it to exactly one token.

## What it does *not* change

This is a **within-transaction** effect: at every K the tokens all carry the transaction's
own generation, so clearing `reg_tag` is the fail-open of *that* transaction, and the damage
is the corrupted termination accounting (1 TMO / K−1 STALE instead of K TMO / 0 STALE) and
the loss of orderly reservoir ownership. R2 fixes it to **K TMO, 0 STALE, `reg_tag`
preserved** — validated separately in `evidence/failopen/`.

The **cross-transaction** clobber — a token from a *retired* transaction clearing a
*different* live one — is a distinct claim. It still requires the generation-wrap
coincidence (a token outliving its transaction until the 4-bit DNP3 sequence reuses its
value), which this sweep does not produce because every token here belongs to the live
generation. That case remains model-checked (`analysis/test_tag_domain.py`, 321 assertions
over all ordered foreign pairs) rather than reproduced on hardware — but the *write
mechanism* it depends on is now confirmed real and single-token on silicon.

![The reconciliation](../../figures/out/fig9_ksweep.png)

## Files

| file | what |
|---|---|
| `20260730T230912Z/check2_k*.json` | per-K fail-open trials (the first run; K<64 aborted on the K==64 pin) |
| `<latest>/check2_k*.json` | the sweep after the K pin was scoped to allow a deliberate sweep |
| `figures/src/fig9_ksweep.py` | the figure |

The K-pin (`chk.expect("K", a.k, 64)`) was scoped to accept a deliberately swept K on a
READ-only trial, the same class of fix as the fail-open horizon guard — a check that
refused the one experiment it was needed for.
