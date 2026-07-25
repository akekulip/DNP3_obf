# Root cause: why egress size normalization never fired

**Determined on silicon 2026-07-25, without a recompile.** `[OBS]`

## Finding

**`eg_intr_md.pkt_length` = `ipv4.total_len` + 18** — the full Ethernet frame length **plus the
4-byte FCS**. Every `size_norm` table key was computed as `total_len + 14`, so every entry was short
by exactly 4 and every frame fell through to the fail-open default.

## How it was determined

Nine probe frames were crafted whose IPv4 `total_len` spans the egress parser's length classes, then
injected one at a time with `ctr_size_normalized` read after each. **Exactly one normalized:
`total_len = 48` (wire 62).**

That single observation discriminates, because neither candidate convention predicts it — "pkt_length
equals the wire length" predicts all nine normalize, and "pkt_length equals the IP length" predicts
five. The FCS hypothesis predicts exactly one, and checking it against all thirteen parser classes
reproduces the observation uniquely:

| total_len | wire | pkt_length (= +18) | in `size_norm`? |
|---:|---:|---:|---|
| 46 | 60 | 64 | no |
| **48** | **62** | **66** | **YES — the one that fired** |
| 52 | 66 | 70 | no |
| 60 | 74 | 78 | no |
| 62 | 76 | 80 | no |
| 74 | 88 | 92 | no |
| 75 | 89 | 93 | no |
| 77 | 91 | 95 | no |
| 87 | 101 | 105 | no |
| 89 | 103 | 107 | no |
| 94 | 108 | 112 | no |
| 101 | 115 | 119 | no |
| 106 | 120 | 124 | no |

Predicted set `[48]`, observed set `[48]`. All thirteen classes and all nine probes are explained.

## Why it was not caught earlier

The size path had **never run on silicon**. It was compiled, resource-measured and reasoned about,
and the keying convention was assumed from the header definition rather than measured. The
compile-time evidence was strong and entirely consistent with a construction that cannot work.

## Fix

Every entry becomes `total_len + 18`: {60, 62, 66, 74, 76, 88, 89, 91, 101, 103, 108, 115, 120} →
{64, 66, 70, 78, 80, 92, 93, 95, 105, 107, 112, 119, 124}. Pad amounts must be re-derived against the
same convention — for a 128 B **wire** target the pad is `128 − (pkt_length − 4)`.

## Still open after this fix `[OPEN]`

- `data_offset = 8` coverage — the real corpus case (2,102 of 2,104 packets).
- Pure TCP ACKs (`total_len = 40`) are absent from the egress select and cannot normalize at all, so
  ACKs would leave at 60 B while data leaves at 128 B — trivially separable. Either cover them or
  narrow the claim to data frames explicitly.

## Artifacts

`pktlen_probes.json` — the nine probe frames, with the predicted match under each convention.
