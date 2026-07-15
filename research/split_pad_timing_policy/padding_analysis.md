# Padding Analysis — The Honest Negative Result and the Future Path

_Synthesis of Agent D (padding/anonymity literature) and Agent A (DNP3 protocol), 2026-07-13.
Research/design only. Evidence tags as elsewhere. Detailed records:
`agent_reports/agent_D_padding.md`, `agent_reports/agent_A_dnp3_split_padding.md`._

## 0. Verdict up front
**For the current byte-preserving phase there is NO safe DNP3 padding.** This is a measured and
source-grounded **negative result**, not a gap to be filled by cleverness. It is the study's core
size-axis finding and should be published as such.

## 1. Why every in-band padding road is blocked [M][S][I]
The nine padding categories collapse into three fates:
1. **Modify DNP3 bytes / object counts / CRCs** → forbidden by the phase rule; needs CRC recompute,
   and on controls would operate real equipment.
2. **Rejected by outstation semantics** → the measured negative: invalid-index CROBs draw
   **OUT_OF_RANGE(12)** per index, **TOO_MANY_OPS(8)** past `maxControlsPerRequest`, and a partial
   SELECT blocks OPERATE — so the padding is not insertable and each rejected index leaks on the wire.
3. **Not actually padding** → delayed release adds no bytes; it is *timing normalization* and does not
   touch size.

Agent A generalized the measured dead end to the **parser level**: the APDU parser loops
`while(length>0)` and requires the buffer to be **fully consumed by known objects** — each object's
group/variation must resolve to a known type, the qualifier must be exactly one of **7** whitelisted
codes, and **the APDU has no length field** (`APDUParser.cpp:60-112`, `QualifierCode.cpp:42-63`,
`APDUHeaderParser.cpp`). There is **no NUL/comment/padding object group in IEEE 1815**. So: trailing
filler → parse error; invalid filler → rejected (the [M] dead end); *valid* filler → ingested as real
data or a real control (semantic change). All three roads are blocked. **No byte-preserving,
semantically-inert DNP3 padding exists in this stack at any layer.**

## 2. The nine categories (feasibility · phase · does it close the size leak?)
| # | Category | Byte-preserving? | Phase | Closes the measured SIZE leak? |
|---|---|---|---|---|
| 1 | Semantic DNP3 padding (add real objects) | No (adds bytes, CRC recompute) | FUTURE; control-plane unsafe | Yes only if padded to a fixed class-max on the **read plane** with genuinely inert points |
| 2 | Valid dummy/inert DNP3 object | No | FUTURE (endpoint exposes inert points) | Partially — only if decoy points are indistinguishable from real ([H]; static values may give them away) |
| 3 | Invalid-object padding | No | **DEAD END [M]** | No — rejected, visible |
| 4 | Padding outside the DNP3 message (in-band) | Injects non-DNP3 bytes | FUTURE; framing-unsafe (FrameReader desync) | No |
| 5 | **Tunnel / encrypted-envelope padding** | **Yes for DNP3** (inner bytes untouched) | FUTURE (cooperating endpoints) | **Yes — the only clean way to close the total-size leak** |
| 6 | Cover traffic / decoy transactions | No (whole fake transactions) | FUTURE; decoy *controls* forbidden | Statistically only (hides which/when, not per-response size) |
| 7 | Packet-count padding | Split does it up-only, byte-preservingly | Split NOW; independent padding FUTURE+proxy | No (raises packet count, not total bytes) |
| 8 | Silence hiding | No (injects filler) | FUTURE (cover traffic) | No (targets the silence/activity axis) |
| 9 | Timing-only delayed-release "padding" | **Yes (0 bytes)** | **CURRENT** | No — this is *timing normalization*, not padding |

## 3. The literature's one invariant
Every website-fingerprinting, mix-network, and cover-traffic mechanism shares one property:
**padding = adding bytes or packets.** So their **objectives** transfer to DNP3 (anonymity set /
k-anonymity; target-distribution matching; secret-independent shape; differential-privacy budget;
constant-shape upper bound) but their **mechanisms do not** in-band — they break DNP3 CRC/length/
framing or trip a spec IDS. They return only **inside a tunnel** (category 5). The single
byte-preserving obfuscator in the corpus, Random Segmentation (Alyami et al. 2023), is *split* — and
split cannot hide total size. Constant-shape padding (BuFLO/Tamaraw) is the provable size-closing
ceiling and is byte-adding by construction; NetShaper's differential-privacy tunnel shaping and
Pacer's secret-independent shaping are the reusable *objective functions*, both living in a tunnel.

## 4. Quantified cost of closing the leak [M]
To hide CROB count by constant-shape padding, every control response inflates to the class maximum.
For N=1→16 that is **+219 B on the SELECT response and +219 B on the OPERATE response (~+590% each)** —
a concrete bandwidth floor for any padding scheme that closes this leak.

## 5. Ranked FUTURE padding architectures (safety first)
1. **Encrypted tunnel with shaped padding** (TLS/IPsec/WireGuard carrying DNP3). Safest and most
   complete: DNP3 bytes untouched (no CRC recompute, transparent to a `dnp3` spec IDS); closes size +
   timing + total-volume + silence in one place; overhead is a dial (constant-rate strongest;
   DP/secret-independent shaping tunable). **Recommended future direction.** Requires both ends (or a
   gateway pair) and an out-of-tunnel observer.
2. **Gateway/RTAC exposing valid inert read-plane points**, padded to fixed size classes. No tunnel,
   but inert points may stay distinguishable [H]. **Read-plane only — never controls.**
3. **Read-plane decoy transactions (cover traffic).** Hides pattern/silence; highest bandwidth per
   unit privacy; does not close a per-response size leak alone. Read-plane only.
4. **Active in-path proxy** doing out-of-message/packet-count padding. Least safe (MITM, FrameReader
   desync risk, IDS may flag non-DNP3 bytes).

**Never, in any phase:** add real or invalid CROBs to a live SBO — it either operates equipment or
trips OUT_OF_RANGE and blocks the real OPERATE [M].

## 6. Recording the residual (do not paper over)
Because split preserves total bytes and no in-scope padding exists, these measured size channels stay
**open**: SELECT/OPERATE response size ∝ CROB count (14.6 B/CROB, R²=0.9999) and READ response size ∝
point count (~5.7 B/analog point). The software policy engine records undersized-response residual
size leakage as a **first-class exported metric** (Agent E). Caveats: one device/one build; the
inert-point distinguishability question is [H] and must be measured in a future phase; CROB-count size
leak ≠ database-size leak.

_Plain language: DNP3 has nowhere legal to put filler — fake filler is rejected, real filler becomes
real data or real commands, and there's no length field to pad. The only real fix is to wrap DNP3 in
an encrypted tunnel and pad the tunnel, which is future work needing both ends to cooperate. For now,
message size stays exposed, and we say so._
