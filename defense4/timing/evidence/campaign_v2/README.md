# campaign_v2 — the corrected, request-anchored build

`campaign_v1` evaluated a framework whose read lane armed its release deadlines at the relay's own
transport acknowledgment. That put the relay's acknowledgment latency inside the interval the master
sees, and an adaptive adversary read it: 0.568 bits and 0.794 balanced accuracy from that interval
alone, against 0.094 bits undefended. `defense4/timing/anchor_fix/FINDINGS.md` diagnoses it,
implements the fix and measures the before-and-after on the same hardware in one session.

This dataset is the corrected build collected in `campaign_v1`'s own shape, so the two are directly
comparable: **22 sessions of 6 blocks, 400 READ and 40 SBO per block, 132 captures, 63,360
exchanges**, arm order rotated across four patterns.

## What changed from campaign_v1

| | campaign_v1 | campaign_v2 |
|---|---|---|
| read-lane anchor | the relay's acknowledgment, `t_A` | **the request, `T_0`** |
| `D_A` / `D_R` | 20 / 4 ms | 20 / **8** ms |
| `A` / `R` | 20 / 24 ms | 20 / **28** ms |
| master-visible `O` | 4 ms | 8 ms |
| size carve | off, **assumed** | off, **read back and asserted per block** |
| anchor state | not a parameter | **read back and asserted per block** |
| configuration provenance | PARTIAL | complete |

`D_R` rises because request anchoring measures the response deadline from the request, so the budget
must cover the relay's whole request-to-response latency rather than only the part after its
acknowledgment. 20 + 8 = 28 ms is the smallest total on the 4 ms tick grid — `A` and `R` must be
exact multiples of the 256 ns tick — that covers this relay's worst observed response, 24.691 ms
over 6,288 Timing OFF exchanges measured on 2026-09-18. A 24 ms budget would have missed five of
them.

## Running it

```
_bin/campaign2_run.sh [sessions] [n_read] [n_sbo]      # default 22 400 40
_bin/campaign2_block.sh <session> <block> <OFF|D4> <n_read> <n_sbo> <seed>
```

Every block configures the switch, **proves the size carve off and the anchor state set from a
hardware readback**, captures the master-facing link, drives interleaved READ and guarded SBO, and
aborts on a missing, short, or still-open capture. A block that fails is retried once; a session
that still loses a block is kept on disk and named in `_bin/campaign2.log` rather than averaged
over. Per-session hashes, timing summaries and integrity counts are written by
`_bin/finalize_session.py` into each session's `provenance/`.

Shared facts — the loaded binary's hashes, the compiler, the policy, the driver guard — are in
`PROVENANCE_CONSTANTS.json`.

## Scope

The SELECT and OPERATE indices are hard-restricted to {1, 3} (RB02/RB04), which drive no relay
output; breaker-close is refused at frame construction. The size carve is off in both arms, so the
measurement is timing only. `campaign_v1` is kept intact as the archived record of the build that
was evaluated and found wanting.
