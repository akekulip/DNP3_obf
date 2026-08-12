# READ vs SELECT-echo normalization on the physical SEL-751 — pcap-examined result

Goal: to a passive observer master-side of the outstation-edge Tofino, make a **READ** response and
a **SELECT** (SBO-arm) response on the SEL-751 present the same **size/segmentation** and the same
**Case-A timing** (ACK→response). Driven from Vision, captured on `enp59s0f0np0` (192.168.10.1),
analyzed at the packet level with TCP-ACK-based pairing (`analyze_rrc_pcaps.py`, rebuilt after the
ce3392d audit). Evidence: `evidence/hw_rrc_readsbo_20260812T212234Z/` (size-only, hold OFF) and
`evidence/hw_rrc_joint_20260812T223342Z/` (joint D4 + size). Switch left in the **joint** state
(`shape_enable=1, mode=4` D4, da_dr≈22 ms, PRE MGID 0x2849 → nodes 0x2851/0x2852 RID1/RID2 → dp9);
restore with `configure-timing --mode OFF` (size-only) or `+ rollback-rrc` (transparent).

## Scope (what this proves, and what it does NOT)

- It proves **per-response READ-vs-SELECT-echo parity**: the SEL's response to a 20 B READ and to a
  45 B non-actuating 2-CROB SELECT are made identical in segmentation and Case-A timing.
- It is **not** full READ-vs-SBO transaction equality. A complete SBO is **SELECT + OPERATE**, two
  independent transactions; **physical OPERATE was not run**. At whole-transaction granularity a READ
  (one exchange) and an SBO (two exchanges) differ in packet count regardless of shaping.
- The primitive is **multi-function, not fully type-agnostic**: the final size predicate and RID carve
  do not inspect G10 vs G12, but **admission branches on the DNP3 function** (READ vs SELECT vs OPERATE)
  to pick the expected request length (READ seq+20, SELECT/OPERATE seq+45). "Type-agnostic" applies
  only to the carve decision.

## Test design

| | Trial A (READ) | Trial B (SELECT) |
|---|---|---|
| Request | 23-point G10V2 READ (`0A 02 00 00 16`), 20 B | 2-CROB SELECT, real pt0 + decoy pt1, 45 B (**non-actuating**, no OPERATE) |
| Count | 30 over one persistent conn, src 192.168.10.1:40000 | 30 over one persistent conn, same tuple |
| Native response | 49 B TCP payload (G10) | 49 B TCP payload (G12 SELECT echo) |
| Also present | — | 2× all-points state READ (18 B req → 58 B resp), **not** an admitted profile |
| Safety | READ-only | SELECT-only; pt0/pt1 OPEN before **and** after — nothing actuated |

## SIZE / segmentation — identical (PASS)

From TCP-ACK-paired transactions (`analyze_rrc_pcaps.py`); response reassembled by TCP sequence, DNP3
block CRCs removed before parsing:

| Observable | READ | SELECT |
|---|---|---|
| Admitted transactions | 30/30 | 30/30 |
| Reassembled response | exactly 49 B (all 30) | exactly 49 B (all 30) |
| Segment vector, **TCP-sequence order** | `[28, 21]` | `[28, 21]` |
| Segment vector, **capture-arrival order** | `[21, 28]` | `[21, 28]` |
| Response DNP3 function | `0x81` | `0x81` |
| Object group | G10 | G12 |

Both segmentation orders are identical for READ and SELECT. The **suffix is consistently emitted
before the prefix**, so `[28,21]` is the sequence-order vector and `[21,28]` is the arrival-order
vector — equality holds in both, but the ordering must be named. Note **which is stated**: the switch
carves bytes `[0:28]` (RID 1, seq = orig) and `[28:49]` (RID 2, seq = orig+28); TCP reassembly is
byte-exact regardless of arrival order.

The 2 all-points state READs (18 B request) are **not** an admitted profile: they return a native 58 B
response and are **not carved** — proof the RRC eligibility is size/profile-specific, not "split
everything." Correct wording: **every admitted 20 B READ and 45 B SELECT profile in this campaign was
normalized** (not "every SEL response").

## TIMING — deadline-clamped, Case-A metric (PASS on ACK→response)

The Case-A signal is the **CLRT = pure-ACK → response** gap (what the D4 deadline clamps). Two states:

**(1) Size-only** (hold OFF): native CLRT is small and **transaction-dependent** — READ median
**2.11 ms**, SELECT median **1.06 ms** — i.e. separable (this is the fingerprint).

**(2) Joint D4 + size** (hold ON, D_A≈2 ms, D_R=20 ms, deadline da_dr≈22 ms, under the ~30.8 ms
fail-open horizon):

| metric (admitted, n=30 each) | READ | SELECT |
|---|---|---|
| CLRT: pure-ACK → response, median | **20.003 ms** | **20.001 ms** |
| CLRT std | 0.007 ms | 0.015 ms |
| request → response, median | 22.655 ms | 22.606 ms |
| request → response, std | 0.368 ms | **0.334 ms** |
| request → pure-ACK, median | 2.652 ms | 2.607 ms |

The **CLRT medians are 0.002 ms apart** with sub-20 µs spread — strong evidence of deadline
enforcement, well inside the declared 0.5 ms equivalence margin. The correct claim is
**deadline-clamped central timing parity (ACK→response) + identical segmentation** — **not** universal
statistical indistinguishability: on only 30 samples the full request→response distributions remain
distinguishable (a 0.049 ms median difference; different tests disagree). There is **no** 29.9 ms
outlier — that was an analyzer pairing artifact (an 18 B state-read paired with a later SELECT
response); with TCP-ACK pairing the SELECT count is 30, not 31, and the std is 0.334 ms, not 1.299 ms.

**How the D4 hold was armed (control-plane only — see `switch/CONFIG_PROVENANCE.txt`):** the frozen
caseA `config_params_d4` checks `tbl_params.read_len == 18`; the RRC kernel **retired** read_len (dead
PHV → reads 0), so that check fails and cascades to leaving pktgen disabled. A cold restart cannot
revive a compiler-eliminated field. Fix: call caseA with **`--read-len 0`** (matches the dead-field
readback) → pktgen arms. The `0x8000` DA/DR default is 0.033 ms (ns-scale) — a meaningless hold; the
normalizing deadline is set in milliseconds via `--d-a-ms/--d-r-ms`.

## Residuals / honest boundaries (unchanged)

- **Request direction differs:** READ request 20 B vs SELECT request 45 B — the transaction type still
  leaks on the *forward* channel (this defense shapes the outstation's *response*).
- **DPI observer** still separates G10 (READ) from G12 CROB (SELECT). Claim is size+segmentation +
  Case-A-timing parity, **not** DPI equality, and **no device-anonymity claim**.
- **Combined-ACK (Case B) is not covered by the current implementation.** The carve is hardcoded to a
  49 B single-fragment DNP3 response (IPv4 IHL 5, TCP data-offset 5–8, the fixed 28/21 layout); a 61 B
  combined response passes **uncarved**. More fundamentally, the timing engine **arms on a separate
  pure ACK**; a Case-B combined response has none, so it would reach bounded fail-open near the 30.8 ms
  horizon rather than the 22 ms path. A Case-B deadline needs a separately-configured, request-armed
  response deadline — not implemented. (The TCP-reassembly idea is generic; this *implementation* is not
  a generic arbitrary-size splitter.)
