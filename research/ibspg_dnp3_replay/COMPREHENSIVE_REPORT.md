# In-network DNP3 obfuscation on Tofino-1 — comprehensive status for decision

**Date:** 2026-07-25. **Scope:** timing axis and size axis of the DNP3 traffic-analysis defense,
from synthetic microbench through real replayed corpus to the physical SEL-751. **Purpose:** a
decision-grade summary of what is proven, what failed and why, what it costs, and the options.

Evidence tags used throughout: `[OBS]` single silicon measurement · `[REP]` repeated/statistical ·
`[DOC]` sourced elsewhere · `[OPEN]` unresolved.

---

## 1. Verdict at a glance

| axis | status | strongest evidence | one-line reason |
|---|---|---|---|
| **Timing (CLRT)** | **PROVEN on the physical relay** | native sd 2.199 ms → 0.0066 ms, 334× | queue-resident deadline release; measured on the real device's own frames |
| **Size** | **DISPROVEN as built; characterized negative** | `frame.len` 1.000→0.000 bits while `ip.len` stays 1.000 | trailer padding normalizes a field no observer reads |
| **Physical DNP3 session** | **SOLVED** (was blocked 2 days) | live 54-byte responses | source-IP allowlist + outstation link address 0 |

**The headline for judgement:** one axis is a complete, silicon-proven result on real hardware; the
other is a rigorously established *negative* — the transparent-padding approach cannot work, and the
reason is general, not a bug. Closing size for real is a separate, larger construction.

---

## 2. What each mechanism is

**Timing — IBSPG HOLD_RESPONSE.** The ACK is forwarded immediately and its arrival stamps `t_ack`;
the response is held **queue-resident** in a low-priority TM queue, starved by a high-priority
reservoir of internal "blocker" tokens that recirculate on an internal loopback port. Each token
checks a data-plane deadline (`t_ack + G`) every pass and self-terminates once it passes; when the
reservoir drains, strict priority serves the held response. No controller in the fast path, no
external chaff, no continuous recirculation of the original packet. The emitted ACK→response interval
(the Formby CLRT fingerprint) becomes a policy constant `G`.

**Size — egress trailer padding.** The egress parser consumes the whole payload into shared
power-of-2 chunk headers so the deparser residual is empty, then appends pad headers *after* the
complete IP datagram, growing the frame to a fixed wire size while leaving the inner IP/TCP/DNP3
bytes untouched.

---

## 3. Timing axis — the proven result

### 3.1 Progression of evidence

| stage | traffic | key result |
|---|---|---|
| Part 12 | synthetic markers, 200 reps | deadline error mean **1734 ns, sd 7.3 ns**, spread 27 ns across G = 1–40 ms; released by deadline 200/200, 0 fail-open `[REP]` |
| Part 13 | real DNP3 corpus (`data_offset=5`) | CLRT sd 1.85 → **0.0068 ms**; observer entropy 4.707 → 0.211 bits @50 µs, **0.000 bits @1 ms** `[REP]` |
| **Physical relay** | **real SEL-751 frames (`data_offset=8`)** | native sd 2.199 → **0.0066 ms, 334× collapse**; 1,920 tokens all deadline-terminated `[OBS]` |

### 3.2 The release tail, decomposed (Part 12, n=100, from raw registers)

Total deadline error 1734 ns = **c1** (deadline → first blocker termination) 14.4 ns mean, sd 7.16 +
**c2** (termination → egress) 1720 ns mean, **sd 1.14, range 6 ns**. c1 carries all the variance; c2
is a stable implementation offset a deployment can subtract. **Note the wording:** this is *not* "one
loopback RTT" — the measured single-token dp8 loop RTT is 408 ns, so c2 is ≈4.2× a traversal; its
internal composition is uninstrumented `[OPEN]`.

### 3.3 Classification on real framing `[OBS]`

On the relay's real `data_offset=8` frames: `arm=30, ack_arm=30, ack_bypass=0, resp_release=30`.
Every real READ (fc 1), pure ACK, and RESPONSE (fc 129) classified correctly — the classifier's
length-gate covers TCP header depths 5–8, so the relay's TCP timestamps do not defeat it. The historic
parser bug that dropped pure ACKs (and caused retransmission storms) is fixed and proven fixed on live
traffic.

### 3.4 The one operational constraint `[OBS]`

**G must exceed the native interval it masks.** G = 10 ms does *not* normalize (native ~12.9 ms
corpus / ~2 ms relay): the deadline has already passed when the response arrives, and a switch can
delay a packet but not make it arrive earlier. A deployment that sets G too low silently gets **no
protection while every counter reads healthy** — there is no telemetry today that flags a response
released without waiting. Operationally, set G at or above the native p95/p99 (SEL-751 corpus p95
17.2 / p99 25.1 ms). **This is a required guard, not yet built.** `[OPEN]`

### 3.5 What timing does NOT close (measured across the corpus) `[OBS]`

| channel | balanced accuracy, 3 devices (chance 0.333) |
|---|---:|
| TCP stack fingerprint (TTL/MSS/window/options) | **1.000** |
| ACK mode (separate vs combined) | **1.000** |
| CLRT magnitude | closed by this work |
| size | 0.493 |

Only the SEL-751 emits a separate ACK at all, so the *existence* of the ACK identifies it regardless
of the interval value. The supportable claim is **"closes the CLRT-magnitude channel on a separate-ACK
device,"** not device anonymity.

---

## 4. Size axis — why it is a negative

### 4.1 Three root causes, in order of depth

1. **Fundamental (fatal): the mechanism normalizes a field no observer reads.** `[OBS]` The pad is a
   trailer below IP, so `ipv4.total_len` is untouched by design. Measured on our own captures:
   `frame.len` 1.000 → 0.000 bits, while `ip.len` and `tcp.len` stay at 1.000 bits. tcpdump,
   Wireshark, Zeek and this project's own classifiers all read IP/TCP lengths. **General rule:** any
   padding a receiver can strip without cooperation is strippable by the observer applying the same
   rule — this also kills options padding (it changes `data_offset`, so `payload_len` is recoverable)
   and outer encapsulation (the inner IP header is in cleartext).
2. **It cannot fire on the real device.** `[OBS]` The live SEL-751 uses `data_offset=8` (RFC 7323
   timestamps) on every frame; the normalizer is built for `data_offset=5`. Confirmed on the live
   device, not just the corpus.
3. **Implementation bug (fixed, but moot): FCS keying.** `[FIX]` `eg_intr_md.pkt_length` reports
   `wire + 4` (FCS included); every table key was `wire`, short by 4, so nothing normalized. Found by
   a 9-probe injection sweep; fixing it makes the mechanism fire (uniform 128 B, valid checksums) but
   changes nothing about root cause 1.

### 4.2 A safety hazard discovered, not deployed `[OPEN]`

The `size_norm` table keys only on `pkt_length` while the egress parser requires `data_offset=5`, and
nothing couples them. On a `data_offset=8` frame — **2,104 of 2,104 real-corpus frames** — the pad
lands *between* the TCP header and its options, corrupting the frame and both checksums. **Fixing the
FCS offset does not fix this; it arms it.** The safe re-keying (recorded) is to key on a
parser-produced `pad_class`, so "table matched" implies "parser consumed the payload" by construction.

### 4.3 The Level-1 "size PASS" was on synthetic frames `[OBS]`

The earlier validated Level-1 result was cited as proof. Its own silicon capture is 150/150 frames of
128 B with **every byte after the Ethernet header zero** — no IP header, no TCP, no DNP3, no CRC. Only
the length was ever real, and its deparser emitted `ethernet → pads → body`, which on a live frame
displaces the IP header. That result does not survive contact with live traffic.

### 4.4 What would actually close size `[DOC]`

Byte modification the receiver cannot undo: **prepend** DNP3-legal filler inside the payload, grow
`ipv4.total_len`, correct IP/TCP checksums, and translate the per-flow TCP sequence space
(`seq += Δ` / `ack -= Δ`). Prepending is native to the TNA deparser (`[headers][residual]`), which
removes the chunk-set and parser-state cost of the trailer. The hard, unbuilt part is the per-flow
sequence translator under retransmission and SACK. Scoped in
`research/inline_dnp3_size_normalization/research_design.md`; not started.

### 4.5 Where the size effort should actually aim (both panels, independently)

Size leaks **weakly on READ** (0.493) but **decisively on CONTROL/CROB** — N-recovery 1.000, MI 4.0
bits, a size↔count bijection at ~14.6 B/point (structural in IEEE 1815 g12v1 encoding). The high-value
target is the control path, and the cheapest place to close it is **at the master**: compose a fixed-N
CROB set with valid-but-unwired decoy points, using SBO so a mis-composed set fails at SELECT. No
middlebox, no sequence translation, no receiver-tolerance question.

---

## 5. Physical relay connectivity — solved

Blocked since 2026-07-23; two root causes, both found read-only by measurement. `[FIX]`

1. **Source-IP allowlist.** Connect from `192.168.10.1` (not `.100`): the relay stops self-FINning and
   ACKs the READ. Pure TCP-layer.
2. **Wrong link address.** Outstation link address is **0, not the corpus's 10** (found via a
   Request-Link-Status scan — only dst=0 answered). Re-addressed READ → live 54-byte fc-129 responses.

Live characterization (30 read-only polls): separate-ACK device, native CLRT p50 2.075 / sd 2.199 ms /
28 distinct values, `data_offset=8`, response 54 B. **Method was read-only throughout** — Class-0 READ,
Request-Link-Status, telnet status only; no SET/control/SBO/WRITE/reset; `ACC` password not guessed.

---

## 6. Resource and cost accounting

### 6.1 Tofino-1 pipeline (bf-p4c 9.13.1 local + 9.13.2 on-switch, identical) `[OBS]`

| program | ingress stages | egress stages | TCAM | note |
|---|---:|---:|---:|---|
| Part 12 timing (synthetic) | 12/12 | 0 | 0 | dependency-bound at head of chain |
| `ibspg_dnp3` timing + real classifier | **11/12** | 0 | 0 | parser offload shortened the chain |
| `p12_combined` timing + packed state + size | **8/12** | 2/12 | 0 | packed state −4 stages |

Stage-reclamation findings, all measured: packed transaction state **−4 stages**; parser
classification offload **−1**; the two do **not** add (they remove the same head-of-chain edge);
egress telemetry offload and every deletion probe reclaimed **zero** (the tail is packing-bound, the
head is the generation-safety dependency chain). Binding resource in the combined program is
**tagalong PHV at ~7/8 collections**, dominated by the size chunk headers.

### 6.2 Runtime cost of the timing hold `[OBS]`

Per transaction at K=64: 64 blocker tokens, ~2.6 M internal loopback passes during a 25 ms hold
(≈150 M over a 30-transaction campaign), entirely on the internal loopback port — **zero blocker
frames ever reach a host port** (`ctr_bypass[1]=0`; capture filter admits the token ethertype and sees
none). Fail-open is a pass budget (~2 M passes ≈ 3.4 s at K=64), not a wall clock.

### 6.3 Bandwidth / overhead

Timing adds **no bytes** (byte-preserving). Size (if it worked) would add up to 68 B/frame of padding
per direction — overhead the control-path-at-master alternative avoids entirely.

---

## 7. Challenges encountered and how each was resolved

| challenge | root cause | resolution | status |
|---|---|---|---|
| Pure ACKs dropped, retransmission storms | parser extracted DNP3 unconditionally on zero-payload frames | two-gate length hardening (total_len then DNP3 LEN) | fixed, proven on live relay |
| DNP3 classifier "won't fit" (+2/3 stages predicted) | assumed classification adds MAU tables | moved classification into the parser | fit at 11/12 — one *fewer* than baseline |
| Packed 32-bit state rejected 3 ways | TF1 SALU: ≤2 PHV inputs; small immediates; runtime sub-field slicing breaks PHV | keep gen in its own byte; tag-difference SALU; armed-bit in deadline word | −4 stages, sentinel ambiguity eliminated |
| Size normalizer never fired | `pkt_length` = wire + 4 (FCS) | 9-probe injection sweep isolated it | root-caused; fix moot (see §4) |
| Relay refused DNP3 for 2 days | source-IP allowlist + link address 0 | source `.1`; Request-Link-Status scan → dst 0 | solved, live |
| Two-sided injection (real DNP3 needs correct ingress port) | classifier derives direction from port | READ from Vision/dp9, ACK+RESP from Hulk/dp11 | working |
| Campaign exit code not captured (Part 12 A) | runner discarded it | second campaign with full capture | closed |
| Timing wording "one loopback RTT" | unproven model | measured decomposition (c1+c2); 408 ns RTT cited | corrected in place |

---

## 8. Open items and risks (for the judgement)

1. **Relay never physically inline.** `[OPEN]` Its real bytes/framing were replayed through the Tofino;
   the relay's own TCP stack tolerating a live multi-ms hold (retransmit behaviour under the delay) is
   **untested** and needs inline re-cabling — a gated hardware step.
2. **G-selection guard missing.** `[OPEN]` A too-low G silently disables protection. Needs either a
   measured native distribution at commissioning or on-chip telemetry flagging un-held releases.
3. **ACK mode + TCP stack fingerprint remain at accuracy 1.000.** `[OBS]` Timing closes CLRT magnitude
   only; full device anonymity is out of scope and would need chaff/ACK-synthesis (rejected earlier for
   the live path) or normalizing the TCP stack.
4. **Size not closed.** `[OPEN]` Transparent padding disproven; the byte-modifying construction is
   scoped but unbuilt, and its sequence translator is the real risk.
5. **Operational/compliance** (for any relay-facing deployment) `[DOC]`: an inline byte-modifying device
   in the ESP is itself a CIP Cyber Asset and changes what the utility's IDS sees a frame to be; the
   control path carries DIRECT_OPERATE, so a no-drop/no-duplicate/no-reorder argument including
   fail-open must be written and tested with control traffic, not just READ. PRP/HSR segments are a
   hard exclusion for trailer padding (IEC 62439-3 RCT occupies the same space; the SEL-751 is
   PRP-capable).

---

## 9. Options for what to do next

**A — Publish the timing result now; report size as a characterized negative.**
Lowest risk, highest certainty. Timing is complete and silicon-proven on the real device. The size
negative is a genuine contribution (explains why in-network size normalization for cleartext ICS
traffic hasn't been done). Cost: writing. Gap: the relay-inline stack-tolerance test (item 1) would
strengthen it but is not required for the timing claim as a replay result.

**B — Close the relay-inline gap for the timing result.**
Re-cable the relay behind the Tofino and run a live master↔relay session through the hold. Converts
"replay of real frames" into "live device held in real time," and tests the relay's retransmit
tolerance. Cost: a gated hardware change + a live-session test. Risk: low-to-moderate (the hold is
25 ms, well under TCP RTO), but it is the one unproven assumption in the timing story.

**C — Pursue size where it actually leaks: the control path, at the master.**
Fixed-N CROB composition with valid-but-unwired decoy points. Closes the strong (4.0-bit) leak in both
directions with no middlebox and no receiver-tolerance question. Cost: master-side implementation +
utility sign-off for decoy points. Highest security value per effort of the size options.

**D — Build the in-network byte-modifying size normalizer.**
Prepend DNP3-legal filler + per-flow TCP sequence translation. The only in-network path that closes
size. Cost: substantial; the sequence translator under retransmission/SACK is real research risk. Do
only if an in-network size contribution is specifically required.

**E — Add the G-selection guard.**
Small, and it removes a silent-failure mode from any timing deployment. Worth doing regardless of A–D.

---

## 10. Recommendation

Ship **A** as the primary result, add **E** as a cheap robustness fix, and schedule **B** to remove the
one unproven assumption in the timing claim. Treat **C** as the next real security contribution if the
project wants a size result, and **D** as a separate research line rather than a bolt-on. Do not present
size as obfuscation "proven" — the mechanism runs but closes nothing, and both independent panels plus
direct measurement agree on that.

---

## 11. Evidence index

- Timing (synthetic): `IBSPG_HOLD_RESPONSE_RESULT.md` (Part 12, 26 sections, evidence-tagged).
- Timing (real DNP3): `END_TO_END_RESULT.md`, `evidence/e2e/`, `evidence/gsweep/`, `SUMMARY_FIGURE.png`.
- Timing (physical relay): `RELAY_TEST_RESULT.md`, `evidence/relay_live/` (+ figures).
- Size falsification: `evidence/size_falsification/SIZE_MECHANISM_FALSIFIED.md`,
  `evidence/pktlen_rootcause/PKTLEN_ROOT_CAUSE.md`.
- Panel reviews synthesized: `PANEL_SYNTHESIS_WAY_FORWARD.md`.
- Stage/resource campaign: `../../DNP3-stagereclaim/research/stage_reclamation/` (forensic report,
  variant matrix, packed-state and egress-offload designs).
- Relay connectivity: `evidence/relay_live/RELAY_CONNECTIVITY_SOLVED.md`.
