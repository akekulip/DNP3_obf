# HISTORICAL_13MS_RECONCILIATION.md — what the ~13 ms actually measured (Task 4)

Reconciles the historical "~13 ms SEL-751 CLRT" against the live 300-poll result. Independent recompute
from the ORIGINAL trace (read-only). Script: `historical_reconcile.py`. Outputs:
`historical_reconcile.json`, `historical_vs_live_clrt.csv`.

## Where the ~13 ms comes from (located)
- **`research/tofino_dcrn_feasibility/p4/ack_delay/ACK_DELAY_POLICY.md` §5.A** and
  `ACK_DELAY_TECHNICAL_REPORT.md`: SEL751 (10.0.0.1), separate 299/299, **CLRT median 12.9 ms**
  (p10–p90 11.6–15.9), req→ACK 3.7 ms, req→resp 17.0 ms.
- `meeting.md`: "approximately 13 ms … stable cluster around 12 to 13 ms."
- Prior method/result: `…/ack_delay/evidence/clrt_baseline.py` + `native_clrt_baseline.txt`.
- Original trace: **`Traffic Trace/SEL751.pcap`** (captured 2026-06-10).

## Is the ~13 ms really ACK→response CLRT? — YES (reproduced)
Independent transaction walk on `SEL751.pcap`, filtered to **10.0.0.1** (the shared 10.0.0.2 device
excluded), reproduces the prior baseline **exactly**:
- **request→ACK:** median **3.70 ms** · **ACK→response CLRT:** median **12.90 ms** (mean 14.56) ·
  **request→response:** median 16.98 ms. n = **299**, 1 TCP connection, 0 payload retransmissions,
  separate ACK 299/299.
So "~13 ms" is genuinely the **ACK-to-response CLRT**, not a mislabelled request→response (17 ms) or
request→ACK (3.7 ms).

## Recompute split by request function — the decisive check
| dataset | request type | n | resp bytes | CLRT median (ms) | req→ACK median (ms) |
|---|---|---|---|---|---|
| historical SEL751 | DIRECT_OPERATE | 200 | 37 | **12.84** | 3.67 |
| historical SEL751 | READ | 99 | 54 | **13.18** | 3.83 |
| historical SEL751 | ALL | 299 | 37/54 | 12.90 | 3.70 |
| **live 300-poll** | READ (Class-0) | 300 | **134** | **1.899** | **0.563** |

**Request type does NOT explain the gap.** The historical **READ-only** CLRT (13.18 ms) is essentially
the same as its DIRECT_OPERATE CLRT (12.84 ms). The earlier intuition that controls inflated the
historical figure is **refuted** — historical READs alone are also ~13 ms.

## What the evidence actually shows
1. **The gap is systematic and appears in *both* intervals, not just CLRT.** Historical is ~7× the live
   in req→ACK (**3.70 vs 0.56 ms**) *and* in CLRT (**12.9 vs 1.9 ms**). A per-request-type effect would
   not scale both intervals together.
2. **Response content differs.** Historical responses are small (READ = 54 B, DIRECT_OPERATE = 37 B);
   the live Class-0 READ returns **134 B / 69 points**. Notably the historical relay took *longer* to
   produce a *smaller* response, so response size is not the driver (it would predict the opposite).
3. **TTL does not distinguish the endpoints.** Both the historical 10.0.0.1 and the live physical relay
   send TCP with **IP TTL 64** (checked against the committed live pcap). *(An earlier idea that the
   historical was a simulator, based on TTL, is retracted — the live relay's TCP is also TTL 64; its
   ICMP echo uses 255, but TCP is 64.)* TTL therefore neither supports nor refutes a different device.
4. **Different lab environment / epoch.** Historical = the 10.0.0.0/24 setup captured 2026-06-10; live =
   the 192.168.10.0/24 direct-attached setup captured 2026-07-23.

## Evidence-supported conclusions vs hypotheses
**Supported by evidence:**
- The ~13 ms is the ACK→response CLRT (reproduced: 12.90 ms, n=299).
- It is **not** a request-type artifact (READ 13.18 ≈ DIRECT_OPERATE 12.84 ms).
- The historical setup was **uniformly ~7× slower** across req→ACK *and* CLRT — a systematic offset.
- The two datasets differ in response content and in lab environment/epoch.

**Hypotheses (not proven from available evidence):**
- A different **capture environment / topology** (e.g. switched or routed path, or a non-direct capture
  point) added latency to req→ACK, and a different **relay firmware / configuration / scan load / device
  state** slowed response generation — together producing the ~7× offset. This is the most parsimonious
  fit but is **not confirmed**.
- The two measurements may simply be **not directly comparable** (different conditions), rather than the
  device's CLRT having "changed."

## What is missing to resolve it
- **Provenance of `SEL751.pcap`:** was 10.0.0.1 the physical relay or a simulator/replay? Exact capture
  point (at the master, a mirror/SPAN, or inline)? Network topology (direct vs switched/routed)? None of
  this is documented in the accessible evidence — only the packets.
- **Relay firmware / DNP3 map / scan configuration / load** at each capture — not recorded.
- A **controlled A/B**: measure the *same physical relay* under the historical topology and the current
  direct topology, same request, to isolate environment vs device.

## Bottom line
The historical ~13 ms is a real ACK→response CLRT and reproduces exactly, but it is **not comparable
head-to-head** with the live 1.9 ms: the historical environment was uniformly ~7× slower in both req→ACK
and CLRT, across *both* request types, with different response content and an unknown capture provenance.
The **live 1.899 ms median is the physical SEL-751's Class-0 CLRT in the current direct-attached setup**;
the ~13 ms should be cited as "original-trace baseline (different conditions)", not as the physical
relay's present CLRT. The cause of the ~7× offset is **undetermined** from the available evidence.
