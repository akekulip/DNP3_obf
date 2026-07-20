# ACK-Delay Policy — Dr. Lin's ACK-Centric CLRT Control (DNP3 / Tofino-1)

Authority: `/home/philip/Projects/DNP3/test_cases.md`. This document is the policy specification
(Section-27 items 1–2 + Section-25 `ACK_DELAY_POLICY.md`). Planning only — **no switch touched**.
Synthesised by the PI (main session) from five expert reviews (principal-investigator,
p4-dataplane-engineer, power-systems-expert, research-scientist, sdn-networks-expert) and the §5.A
native-CLRT measurement done this session.

## 1. Objective (Dr. Lin)

Defend the **cross-layer response time (CLRT)** device fingerprint of Formby et al. (NDSS 2016,
"Who's in Control of Your Control System? Device Fingerprinting for CPS") by controlling it inline on
a Tofino-1 switch, **byte-preservingly, non-cooperatively (legacy RTU unmodified), and entirely on the
ASIC datapath — no ACK synthesis, no controller in the fast path.**

```
CLRT = t(DNP3 application response) − t(pure TCP ACK)     [separate-ACK transactions only]
```

Native structure of a separate-ACK transaction:
```
master request  (t_req)
   → outstation pure TCP ACK  (t_ack)
   → outstation DNP3 response (t_resp)
G_native = t_resp − t_ack
```

## 2. The two policies

### CASE A — `ACK_DELAY_REDUCE_CLRT` (primary / headline)
Hold **only the pure ACK** until the response is ready; release the ACK first, then the response after
the smallest hardware-safe ordering guard `δ`.
```
t_ack_out  ≈ t_resp_ready
t_resp_out = t_ack_out + δ
G_reduce   = t_resp_out − t_ack_out ≈ δ          (small, common)
```
Effect: `request→ACK` **increases** (to ≈ native response-readiness), `ACK→response` **decreases** to δ,
`request→response` stays ≈ native + δ. **Lowest added operational latency.**

### CASE B — `RESPONSE_DELAY_INCREASE_CLRT`
Forward the pure ACK immediately; hold the **response** to an ACK-relative deadline.
```
deadline    = t_ack + G_i                        (G_i from a common bounded distribution)
t_resp_out  = max(t_resp_ready, deadline)
```
Effect: `request→ACK` stays native, `ACK→response` **increases** to ≈ G_i, `request→response`
increases. Normalises the device-bound response-readiness quantity, not just CLRT.

## 3. Combined ACK-bearing response — hard limitation (§3)
Some devices emit one **combined** ACK-bearing response (ACK piggybacked; no standalone pure ACK).
For these, **CLRT is undefined.** Policy: classify `COMBINED`, record "no pure ACK", **bypass the two
CLRT policies, preserve the packet unchanged.** Never synthesise a pure ACK, never suppress/split/
rewrite the ACK-bearing response, never call `request→response` "CLRT". A request-relative delay of a
combined response is a **separate, separately-reported extension (E5)** — never folded into the CLRT
result.

## 4. §5.A measured ground truth (this session, from `Traffic Trace/`, not memory)
Master 10.0.0.3, 2 s poll, one outstanding request; Zeek confirms Class-0 READ → RESPONSE.

| Device | Mode | pure ACKs | Native CLRT (ACK→resp) | req→ACK | req→resp | resp sizes |
|---|---|---|---|---|---|---|
| **SEL751** (10.0.0.1) | **SEPARATE** (299/299) | 299 | **median 12.9 ms** (p10–p90 11.6–15.9, max 166) | 3.7 ms | 17.0 ms | 37/54 B |
| AB1400 (10.0.0.12) | COMBINED (399/399) | 0 | — undefined | — | 16.6 ms | 37/54 B |
| ION7550 (10.0.0.11) | COMBINED (799/799) | 0 | — undefined | — | 16.1 ms | 37/61 B |

Evidence + SHA-256 provenance: `p4/ack_delay/evidence/native_clrt_baseline.txt`,
`clrt_baseline.py`. Captures hashed in that file.

## 5. Load-bearing findings the policy must own (expert consensus)
1. **On this corpus CLRT is NOT a cross-device discriminator — ACK MODE is.** Only SEL751 is
   separate; AB1400/ION7550 are ~100 % combined. A CLRT-only device classifier is degenerate (one
   class). The dominant device signal is separate-vs-combined ACK mode (segment count per txn), which
   **neither Case A nor Case B touches.** Every efficacy claim is scoped to *"collapsing the
   within-separate CLRT sub-channel"*, never *"hiding device identity."*
2. **The physical discriminator is the kernel ACK policy, not app speed.** All three devices respond
   in ~16–18 ms; SEL751's large CLRT comes from its kernel emitting a *prompt* pure ACK (~4 ms) while
   the others piggyback. The CLRT policies cannot reach the mode itself.
3. **Case A relocates the signal, it does not remove it.** With `t_ack_out ≈ t_resp_ready`,
   `request→ACK` now equals the device's processing time — the exact quantity CLRT measured. Against
   Formby's literal CLRT feature Case A works; against an adaptive adversary reading `request→ACK` or
   `request→response` it is near-theatre. **This is stated up front, not discovered by a reviewer.**
   → the attacker evaluation MUST include a `request→ACK` and a joint `(req→ACK, ACK→resp, size)`
   classifier, not CLRT alone.
4. **Case B is the more defensible signal-collapser** (masks response-readiness) but costs latency.
   The publishable story is the **latency–concealment tradeoff: Case A cheap-but-relocates vs Case B
   costly-but-normalises.**
5. **Separate/combined is a per-transaction property of the stack under this regime, not a device
   invariant.** Classify on the wire every transaction; never hardcode "SEL751 = separate."

## 6. Eligible traffic and bypass (§7) — conservative OT posture (power-systems-confirmed safe)
**Eligible:** IPv4 · TCP · DNP3 port 20000 · established session · routine solicited Class-0 READ ·
one outstanding request per flow · cleanly matched request/response · cleanly classified pure-ACK or
ACK-bearing response.

**Bypass + fail-open (forward unchanged, never drop, increment a bypass counter, log reason):** SYN/
SYN-ACK/FIN/RST · handshake · retransmissions · dup-ACKs · SACK recovery · zero-window/window updates
· keepalives · out-of-order · fragmented IPv4 · ambiguous DNP3 · **unsolicited DNP3 responses** ·
**DNP3 controls / SELECT-OPERATE / DirectOperate** · application CONFIRM · multiple outstanding
requests · unknown sequence state · register collision · state timeout · pass-count exhaustion · queue/
parser uncertainty.

**Grid-safety hard rules:** controls and unsolicited event reports are NEVER held (a delayed
breaker-open/trip target delays operator awareness). DNP3 Class-0 polling is *monitoring*; protection
executes locally in the relay (<1 power cycle) and never traverses this path — so holding only
idempotent monitoring polls by tens of ms is operationally invisible. Fail-open (never fail-closed) is
mandatory for an inline OT asset; the Tofino becomes a NERC-CIP Cyber Asset inside the ESP.

## 7. Prohibited (§22) — the guardrails this phase must not cross
No generic request→response normalisation as the primary experiment; no delaying **both** ACK and
response to one request-relative target; no calling `request→response` "CLRT"; no ACK synthesis /
suppression / coalescing; no TCP seq/ack rewrite; no DNP3 byte edit; no padding/splitting this phase;
no `sleep()` in the replay app as the "defense"; no device-specific / IP / size / native-timing target
selection; no treating the current uncontrolled 38–100 ms output as a common-bounded policy; no
treating MAX_PASS fail-open as a successful deadline release; no ungrouped train/test splits; no
zero-filling missing CLRT; no pooling all profiles into one number; no Claude attribution / codenames.

## 8. Relationship to the existing DCRN program (the gap)
The current `research/tofino_dcrn_feasibility/p4/dcrn.p4` is a **request-relative both-hold** normaliser
(arms on the READ, `reg_deadline = now_tick + Di` anchored to `t_req`, holds ACK **and** response to
that one deadline with a small guard) — precisely the §22-forbidden construction. Its only resemblance
to Dr. Lin's idea is the small *final* CLRT, reached with Case B's latency cost. Both target cases
require **re-anchoring off the ACK** and changing *what* is held: Case A holds only the ACK and
releases it on an **event** (response arrival); Case B forwards the ACK and re-anchors the deadline to
`t_ack`. See `ACK_DELAY_STATE_MACHINE.md`.
