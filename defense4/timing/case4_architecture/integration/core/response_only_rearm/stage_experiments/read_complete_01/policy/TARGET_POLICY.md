# READ size-target policy (frozen 2026-10-20)

**Selected targets: 141, 247 and 401 encoded DNP3 octets per complete solicited READ response.** Each response goes to the smallest target it can reach. A response already equal to a target is forwarded unchanged and recorded as `already_at_target`.

Reproduce with `python3 select_policy.py` (Python ≥3.10). It writes `policy.json` (sha256 in STATUS.md). Add `--history` to recompute the superseded rules v1 and v2-greedy.

## What the attacker is assumed to measure

The selection layer is the **aggregate response**: all link frames of one solicited application fragment, with headers and CRCs. An on-path observer of the master-facing link sees individual TCP packet lengths and timing, and can sum the packets of one request–response exchange. The padder works on the aggregate response because one response is one application fragment.

Packet-level sizes are reported as residuals and are not equated with the aggregate. Distributions in the retained sample (1,000 exchanges, five native loopback captures):

| layer | values (count) |
|---|---|
| aggregate response | 49 (200), 141 (200), 247 (400), 377 (200) |
| TCP payload (1,200 packets) | 49, 85, 141, 247 ×2, 292 (200 each unit) |
| link frame | same as TCP payload |

The 377-octet response is two link frames in two TCP segments, 292 and 85, with an inter-segment delay of about 41 ms on this database. That delay is kept as observed evidence. The sample consists of controlled fixture frequencies, not a field population. The 157-octet example used earlier was constructed and is not included.

## Rule: a Ditto-inspired adaptation, not Ditto

Ditto (NDSS'22, §V, Eq. 2) sets pattern state P_i = percentile_{(i+1)·100/L}(D) of the packet-size distribution, sends each packet as the next-larger state, and relies on a fixed-rate schedule, chaff and encryption for its guarantee. The author code (`nsg-ethz/ditto`, `generate_code.py`) hardcodes its pattern and contains no percentile code. We use only the percentile seeding. There is no schedule, chaff or encryption, so **Ditto's guarantee does not transfer.**

1. **Seeds.** Nearest-rank percentiles of the aggregate distribution, using exact integer ranks:
   - L=2: 247 and 377.
   - L=3: 141, 247 and 377.
   - For reference only, TCP payload: 141/292 and 85/247/292.
2. **Constraints:**
   - (a) **Coverage of the declared profile.** Each of the 10,243 profile cases must reach some target through the real encoder (`software/source/full_read_01/general_read_padding.py`, prefix or resegment).
   - (b) **Hardware construction.** Each retained workload shape must reach its target through the **prefix** construction (or already be at it). That is the construction the switch implements: padding goes only into the first segment and the native tail is forwarded verbatim.
3. **Search.** Exhaustive search over upward-adjusted target sets (T_i ≥ seed_i), choosing the minimum added octets on the retained sample. Ties go to fewer states, then smaller targets.

**History, kept and not hidden** (`policy_rule_v1.json` and `policy_rule_v2_greedy_REJECTED.json`):
- **v1** (greedy +1 moves, coverage only) gave 141/247/**387**, adding 9.61%. Its 377→387 step (+10) is reachable only by full resegmentation. That shifts every original byte and every CRC block across two TCP segments 41 ms apart, which the per-packet switch path cannot do. So v1 adds constraint (b).
- **v2-greedy** (+1 moves with (b)) gave 141/**249**/401, adding 39.96%. The greedy step pushed the 247 READs to 401, which shows the greedy rule is myopic. v3 replaces it with the search above.

## Result on the retained sample

| policy | targets | added DNP3 octets | residual aggregate classes |
|---|---|---:|---|
| **selected (L=3)** | 141 / 247 / 401 | **10.93%** | 141 ×400 (range + analog), 247 ×400, 401 ×200 |
| L=2 | 247 / 401 | 30.91% | 247 ×800, 401 ×200 |
| comparator 163/269/399 | 163 / 269 / 399 | 19.04% | same three-class partition |

- Per shape:
  - range 49 → 141 (+92: one 92-octet prefix frame, 64 synthetic points);
  - analog 141 and class0/integrity 247 are already at target;
  - large integrity 377 → 401 (+24: one 24-octet prefix frame, 4 synthetic points).
- On the assumed 66-octet Ethernet/IPv4/TCP header per payload packet, the added wire bytes are 7.96%. That is an assumption-based estimate; the physical readout measures it.
- **Residual distinctions:**
  - three aggregate classes remain, the same partition as the comparator;
  - the TCP payload sequences are [141], [247] and [316, 85], so the 85-octet trailing segment and the segment count still identify the large READ at the packet layer;
  - the link-frame structure stays visible ([92, 49] against [141], for example).
- Low overhead does not establish effective obfuscation. No indistinguishability or classifier-resistance claim is made.

## Frozen implementation decisions

- **Reserved padding indices:** G1V2 1024..4095, with 16-bit qualifier 0x01. Both fixture databases hold binary inputs 0..15 only. The choice does not depend on an 8-bit spare range, and it makes the minimum prefix frame 24 octets.
- **Synthetic padding:** G1V2 points with flags and value 0. They are not real measurements.
- **Recomputed needs of this construction over the profile:**
  - maximum padded application fragment 335 octets;
  - at most 127 added points, indices 1024..1150.
  These replace the 333/322 figures of the 163/269/399 construction.
- **Endpoint capacity:** the pinned OpenDNP3 4648fcb master accepted the 401-octet, two-frame padded integrity READ live, together with the 141 range READs (`evidence/m3_live_policy_01`).
- **Declared profile:**
  - one solicited application fragment;
  - native aggregate ≤377 octets (application ≤315);
  - static objects G1V2, G10V2, G20V1/2 and G30V1–5 with range qualifiers 0x00/0x01;
  - natural, max-first and every first-frame cut framing;
  - the retained captured shapes.
- **Out of profile:** multiple fragments, unknown objects, control responses and overlapping reserved indices raise; anything beyond capacity or without a reachable target returns `unreachable` with the input unchanged. Nothing is forced to the maximum and nothing is silently bypassed (`software/test_policy_coverage.py`).

## Evidence levels

- Encoding tests: `software/test_policy_coverage.py`, 25 passed, covering all 10,243 cases with preservation, padding range and boundaries.
- Live software endpoints on the pinned stack: `evidence/m3_live_policy_01`, five cases × 16 native + 16 padded polls. Originals, flags, IIN and tasks were preserved.
- Endpoint acceptance by this master is not a claim of IEEE 1815 conformance.
- No switch, model or timing evidence at this level.
