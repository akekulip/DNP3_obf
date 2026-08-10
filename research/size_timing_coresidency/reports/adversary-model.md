# Adversary Model and Defense Target — Size + Timing Co-Residency

**Workstream:** adversary model and defense target
**Author:** sdn-networks-expert (committee member)
**Date:** 2026-08-10
**Hardware contact:** none. No switch, no relay, no compile. Reading, pcap analysis and literature only.

---

## Evidence tags used throughout

| tag | meaning |
|---|---|
| `[M]` | **measured by me this session** from a repo pcap, with the command shown in §0.1 |
| `[R]` | **repo claim**, cited `file:line` |
| `[L✓]` | literature claim **verified this session** (I opened the source or a search result that states it) |
| `[L?]` | literature claim from background knowledge, **not verified this session** — treat as a hypothesis |
| `[I]` | my inference from `[M]`/`[R]` — reasoning, not measurement |

I have marked every claim. Where I could measure instead of assert, I measured, because the
falsification this committee exists to avoid was caused by asserting an observable instead of
measuring it.

### 0.1 What I ran

All commands are read-only `tshark` over pcaps already in the repo. Reproduce with:

```bash
cd /home/philip/Projects/DNP3
# stack fingerprints across the device corpus
tshark -r "Traffic Trace/SEL751L.pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==1" \
  -T fields -e ip.src -e ip.ttl -e ip.flags -e tcp.options.mss_val \
  -e tcp.options.wscale.shift -e tcp.window_size_value -e tcp.options
# (same for AB1400L.pcap, ION7550L.pcap)

# physical relay: IP ID, window, TCP timestamps
D=defense3/evidence/physical_repaired/20260730T194855Z/pcaps
tshark -r $D/blk_r1_native.pcap -Y "ip.src==192.168.10.7" -T fields -e ip.id
tshark -r $D/blk_r1_native.pcap -Y "ip.src==192.168.10.7" -T fields -e tcp.window_size_value
tshark -r $D/blk_r1_${ARM}.pcap -Y "tcp.srcport==20000" \
  -T fields -e frame.time_relative -e tcp.len -e tcp.options.timestamp.tsval
```

Corpora touched: `Traffic Trace/{SEL751,SEL751L,AB1400L,ION7550L}.pcap`,
`evidence/corrected_v2/pcaps/*.pcap`,
`defense3/evidence/physical_repaired/20260730T194855Z/pcaps/blk_r{1..4}_{native,d1,d2,d4,d8,d16}.pcap`,
`dnp3_split_harness/captures/{baseline/large_reply,replay/sweep_bpc1}.pcap`,
`dnp3_multicrob_harness/captures/*.pcap`.

---

## VERDICT FIRST

Four findings, in descending order of consequence.

**F1 — The topology forbids half of what is on the table.** With one switch **at the outstation
edge** and the observer on the WAN **between the master and that switch**, the master→relay
direction passes the observer *before* it reaches the switch. **Nothing the switch does to a
request is visible to this adversary.** CROB-decoy padding is a *request-size* mechanism. It is
therefore topologically incapable of defending anything at this vantage — not "expensive", not
"risky", **structurally null**. It works only if the padding is composed at the master, which the
charter forbids (no endpoint modification). This kills mechanism (1) of the charter before any
DNP3, safety or resource argument is needed. `[R]` — the topology is stated verbatim at
`defense4/README.md:10`: `DNP3 master → observed WAN → one Tofino-1 (outstation edge) → relay /
outstation`. The observer is on the "observed WAN", i.e. **between the master and the switch**.

**F2 — The same category error that killed the size axis is live in the timing axis, and I
measured it.** The SEL-751 negotiates RFC 7323 TCP timestamps. **TSval is stamped by the relay
when the relay builds the segment, not when the switch releases it.** The difference
`TSval(RESPONSE) − TSval(ACK)` therefore carries the relay's *internal* ACK→response interval and
is untouched by any in-network hold. On the D-sweep corpus (n = 160 transactions per arm, 4
connections per arm):

| arm | wall-clock CLRT (mean) | non-zero `ΔTSval` | rate | binomial test vs "internal gap == observed gap" |
|---|---:|---:|---:|---|
| native | 4.40 ms | 22 / 160 | 0.138 | p = 0.66 — **estimator is calibrated** |
| d1 | 3.10 ms | 30 / 160 | 0.188 | — |
| d2 | 2.13 ms | 27 / 160 | 0.169 | — |
| d4 | 1.00 ms | 35 / 160 | 0.219 | — |
| d8 | 0.18 ms | 69 / 160 | 0.431 | **p = 5.9 × 10⁻¹⁰⁸** |
| d16 | 0.03 ms | 27 / 160 | 0.169 | **p = 2.6 × 10⁻⁵¹** |

`[M]` The relay's timestamp clock has 1 ms units and a **30 ms tick** (all 83 TSvals in
`blk_r1_native.pcap` are exact multiples of 30; the smallest positive inter-packet delta is 30).
So `P(ΔTSval > 0) = c / 30 ms` for internal gap `c` under uniform phase. On **native** traffic the
estimator returns 30 × 0.138 = **4.12 ms** against a measured wall CLRT of **4.40 ms** — it works.
On **d16**, where `REPORT.md:1576-1577` records CLRT sd collapsing 2.854 → 0.012 ms and the
observed gap is 0.03 ms, the observer still sees 27 non-zero `ΔTSval` where 0.16 are expected.
That is not a marginal result; it is a 51-order-of-magnitude rejection.

Two honest qualifications. (a) The *point estimate* under defense is biased, because the poll
period (300 ms) is an exact multiple of the timestamp tick (30 ms), so the straddle indicator is
phase-locked rather than an i.i.d. Bernoulli sample — which is why d8 reads 0.431. (b) What is
robust and does not depend on the estimator is the **detection** result: a non-zero `ΔTSval` rate
is flatly inconsistent with the claimed 0.03 ms internal gap. So at minimum the adversary learns
*a middlebox is holding this device's packets*, and gets an order-of-magnitude estimate of the
concealed interval for free. `[M]`

**F3 — In cleartext DNP3 the size axis cannot be closed by any single non-cooperating switch.**
This is stronger than what is on record. `SIZE_PRIMITIVE_REUSE_AUDIT.md:465-473` states the rule
at the IP layer: protocol-transparent padding is observer-strippable. **The rule applies one layer
deeper, and that layer is fatal.** I decoded the physical relay's frames byte by byte `[M]`: the
DNP3 data-link header carries its own `LEN` field (`05 64 2b 44 …`, LEN = 0x2b), so **every DNP3
frame is self-delimiting inside the TCP payload**. A prepended black-hole filler frame
(`research_design.md:4.2` Candidate 2) announces its own length and is skipped by the observer in
one subtraction; a Group 110 octet-string filler (Candidate 1) announces its own group code and is
dropped by object type. Both are *exactly* as strippable as the Ethernet trailer that was already
falsified, for exactly the same reason, one layer up. The only non-strippable filler is filler
that is byte-indistinguishable from real measurement data, which means the relay must genuinely
produce it — an endpoint-side change.

**F4 — The size channel this device leaks is between-device, not within-device, and the switch
cannot touch between-device leakage with an anonymity set of one.** `[M]` The physical relay emits
**one** response size (134 B payload, 40/40 packets in `blk_r1_native.pcap`) against **one**
request size (18 B). Within-device size entropy is zero. Meanwhile the three-device corpus
separates perfectly on static TCP header fields that no size or timing mechanism touches (§1.3).
Normalizing the one relay behind the switch to a common target makes it the only emitter of that
target: `k = 1`, negative privacy gain. This corroborates `DITTO_VS_DEFENSE3.md:74-78` `[R]` with
an independent measurement.

**Bottom line for the committee.** The replacement size mechanism should not be built as a size
mechanism. The measurable, defensible, resource-cheap win available on this switch is
**normalizing the TCP header fields that carry endpoint-side state** — TSval first — because that
is where the device information the defense claims to have removed is still sitting in plaintext,
at a known offset, in a field the switch can already reach.

---

## 1. THE ADVERSARY MODEL, STATED PRECISELY

### 1.1 Vantage, capability, goal

**Position.** Passive on-path observer on the WAN segment **between the DNP3 master and the
outstation edge switch** — the "observed WAN" of `defense4/README.md:10`
(`DNP3 master → observed WAN → one Tofino-1 (outstation edge) → relay / outstation`) `[R]`.
Formally: for relay→master traffic the observer is **downstream** of the
defense (sees the shaped stream); for master→relay traffic the observer is **upstream** of the
defense (sees the unshaped stream). This asymmetry is the single most consequential fact in this
document and it is not stated in any existing repo file I read.

**Capability.** Full packet capture with hardware or kernel timestamps; no injection, no
modification, no drop, no delay (consistent with `defense3/REPORT.md:198-205` `[R]`). Can observe
for arbitrarily long; can observe many TCP connections; knows the protocol, the deployment, the
defense design and its parameters (Kerckhoffs). Can compute anything from the capture, including
full TCP stream reassembly — Zeek and Wireshark both do this by default `[L?]`, and the project's
own analysis pipeline is Zeek-based (`PANEL_SYNTHESIS_WAY_FORWARD.md:18-19` `[R]`).

**Goal — two distinct tasks, routinely conflated.**
- **Task A — defense detection.** Native SEL-751 vs defended SEL-751. This is what
  `REPORT.md:1442-1534` measures `[R]`, and it scores 1.000 at D ≥ 4 ms.
- **Task B — device discrimination.** Defended SEL-751 vs a *different* defended outstation. This
  is the task the threat model actually names, and `REPORT.md:1597-1609` correctly records that
  **no data in the project touches it** `[R]`.
- **Task C — operational inference.** Identify which packet carries a control command, or how many
  breakers an operation touches (the ICS-Sniper adversary, §3.1). Distinct from A and B; the size
  channel's real payoff is here, not in device ID.

**Encryption assumption.** Two regimes, and the answer differs completely between them. Regime
**PT** (plaintext DNP3-over-TCP, what the rig actually runs) and regime **CT** (DNP3 inside
TLS/IEC 62351-3, MACsec, or IPsec). `PANEL_SYNTHESIS_WAY_FORWARD.md:90-96` already flags that the
size threat model is only coherent under CT `[R]`; §3.4 sharpens why.

### 1.2 The complete observable inventory

Everything below is a field or statistic the adversary can compute at this vantage. **Bold** rows
are ones I verified are present and informative in this project's own traffic this session.

#### Layer 2 (present only if the observer taps the L2 segment; on a WAN tap, usually replaced)

| # | observable | status here |
|---|---|---|
| L2-1 | source/destination MAC, OUI → vendor | `[M]` relay MAC `00:30:a7:02:4c:a2` — OUI 00:30:A7 is an SEL allocation `[L?]`. Present in every repo capture. Vendor identification for free, before any statistics. |
| L2-2 | VLAN tag, priority bits | not present in the repo captures `[M]` |
| L2-3 | **`frame.len`** | **the field the falsified mechanism normalized.** Read by essentially no analyzer above L2 (`SIZE_PRIMITIVE_REUSE_AUDIT.md:461-463` `[R]`) |
| L2-4 | Ethernet trailer / minimum-frame padding | the falsified pad lived here `[R]` |
| L2-5 | PRP/HSR redundancy trailer | the SEL-751 is PRP/HSR-capable; IEC 62439-3 puts an RCT in the same space (`PANEL_SYNTHESIS_WAY_FORWARD.md:59-61` `[R]`, clause recalled by that reviewer, flagged unverified there and still unverified here) |

#### Layer 3 (IPv4) — all present, all readable, none touched by any mechanism so far

| # | observable | measured value / behaviour |
|---|---|---|
| **IP-1** | **`ip.ttl`** | `[M]` SEL-751 = 64, ION7550 = 64, **AB1400 = 128**. One field, one of three devices identified outright. |
| **IP-2** | **`ip.flags` (DF)** | `[M]` SEL-751 relay sets **DF = 0**; the Linux master/simulator sets **DF = 1**. Constant, per-device, free. |
| **IP-3** | **`ip.id`** | `[M]` SEL-751 uses a **strictly incrementing global counter**: 82 of 82 consecutive deltas equal exactly 1 in `blk_r1_native.pcap`, and **the same 82/82 under d16**. Consequences: (a) the ID *policy* (global sequential vs per-flow vs random) is a stack fingerprint `[L?]`; (b) gaps count packets the relay emitted on other flows — an off-path activity oracle; (c) the ID sequence preserves the relay's true **transmit order and count** through any switch hold, so reordering, duplication or injection by the switch is directly visible. |
| **IP-4** | **`ip.len` / `ipv4.total_len`** | `[M]` the field the observer actually reads for size. Two values on the relay side of `SEL751.pcap` (89, 106); exactly one (`186` = 20 IP + 32 TCP + 134 payload, 40/40 frames) on the physical relay's poll. `SIZE_PRIMITIVE_REUSE_AUDIT.md:448-454` `[R]` measured it unmoved at 1.000 bits with padding ON. |
| IP-5 | protocol, DSCP/ECN, fragmentation | constant here; DSCP/ECN would be an OT-network policy fingerprint `[I]` |
| IP-6 | source/destination address, address stability | trivially identifies the endpoints |

#### Layer 4 (TCP) — static fields: the channel that already scores 1.000

| # | observable | measured across the corpus `[M]` |
|---|---|---|
| **T-1** | **SYN/SYN-ACK option string and its ORDER** | SEL-751: `020405b4 010303 00 0101 0402 0101 080a…` = MSS, WScale, NOP, NOP, SACK-perm, NOP, NOP, TS. AB1400: `020405c6 01010100` = MSS + NOPs + EOL, **no TS, no SACK, no WScale**. ION7550: `020405b4` = **MSS only**. Linux master: `020405b4 0402 080a… 010303 07`. Four endpoints, four distinct option layouts. This is a textbook p0f-class fingerprint `[L?]`. |
| **T-2** | **MSS** | SEL-751 = 1460, ION7550 = 1460, **AB1400 = 1478** |
| **T-3** | **window scale** | SEL-751 shift **0**; AB1400 and ION7550 **absent**; master shift 7 |
| **T-4** | **initial window** | SEL-751 **8688**, AB1400 **2048**, ION7550 **4380** — three devices, three values, no overlap |
| **T-5** | **`tcp.hdr_len` / `data_offset` in steady state** | SEL-751 = **32 B (data_offset 8)** on 2 102 of 2 104 frames (`CHARTER.md:32` `[R]`, and I reproduced 32 on all steady-state frames `[M]`); AB1400 and ION7550 = **20 B (data_offset 5)**. This one field also explains why the falsified normalizer never fired (`CHARTER.md:41` `[R]`). |
| T-6 | source-port selection policy | `[M]` master ephemeral, monotone within a session |

#### Layer 4 (TCP) — dynamic fields: state that no size or timing mechanism has touched

| # | observable | measured behaviour `[M]` |
|---|---|---|
| **T-7** | **advertised window trajectory** | The SEL-751's window **decrements monotonically by exactly the received payload length and never reopens** within a connection: 8688, 8670, 8652, 8634, … (−18 per 18-byte READ) in `blk_r1_native.pcap`; 8688, 8666, 8644, … (−22 per 22-byte READ) in `campaignA_native_n10.pcap`. Over `SEL751L.pcap` it walks from 8688 down to 7218 before a new connection resets it. **Three separate leaks:** the transaction index `n` is readable in closed form (`W(n) = W0 − s·n`); the *request* payload size `s` is readable from the response direction; and "receive buffer never returns" is a device-firmware fingerprint. **Unaffected by any response-side padding, splitting, chaff or hold.** |
| **T-8** | **sequence-number advance** | The definitive size oracle. See §2.1. |
| **T-9** | **acknowledgement-number advance** | Independent confirmation of delivered byte counts, from the opposite direction. |
| **T-10** | **PSH boundaries** | `[M]` In `large_reply.pcap` the relay emits 292, 1448 (no PSH), 596 (PSH), 72 (PSH) — **PSH marks application-message boundaries**, so the observer segments the byte stream into DNP3 fragments without reading any payload. Survives encryption of the payload; does *not* survive a re-segmenting middlebox. |
| **T-11** | **TCP timestamps — TSval** | **The finding of this report.** §2.2. |
| **T-12** | **TCP timestamps — TSecr** | Echoes the peer's TSval, so it pairs each response to a specific request even under reordering, and yields the relay's view of RTT. |
| T-13 | retransmission timing, RTO and its back-off ladder | Zero `tcp.analysis.flags` in `SEL751.pcap` `[M]` — never exercised in this corpus, therefore **never characterized and never defended**. The relay's initial RTO and back-off schedule are strong stack fingerprints `[L?]`. |
| T-14 | SACK block emission during loss | Negotiated by the SEL-751 `[M]` (SACK-perm in the SYN-ACK). Under loss, `data_offset` grows past 8 and the option layout changes — which breaks any fixed-offset option rewriting. |
| T-15 | zero-window / window-probe behaviour | Reachable given T-7's monotone decrement; never exercised here |
| T-16 | FIN vs RST close style, TIME_WAIT behaviour, keepalive cadence | `[M]` `SEL751.pcap` contains a relay `FIN,PSH,ACK` (flags 0x0019) — an unusual combination and itself a stack tell |

#### Flow and burst structure

| # | observable | measured `[M]` |
|---|---|---|
| **B-1** | **poll cadence** | `SEL751.pcap` READ→READ inter-arrival: n = 98, min 2.0000 s, median 2.0001 s, max 2.0003 s. Effectively deterministic — transaction segmentation is unambiguous, so the adversary never has to guess which packets form a transaction. |
| **B-2** | **packets per transaction and their direction pattern** | `[M]` SEL-751 = READ, ACK, RESPONSE, ACK — a **separate-ACK** device. AB1400 and ION7550 coalesce. `PANEL_SYNTHESIS_WAY_FORWARD.md:36-38` scores ACK-mode at balanced accuracy **1.000** `[R]`. |
| **B-3** | READ→ACK interval | the feature Defense 3 *creates*; separability 1.000 at D ≥ 4 ms (`REPORT.md:1450-1456` `[R]`) |
| **B-4** | CLRT (ACK→RESPONSE) | the target feature (`REPORT.md:186-196` `[R]`) |
| **B-5** | READ→RESPONSE total | least separable while D < native CLRT (`REPORT.md:1528-1534` `[R]`) |
| B-6 | connection lifetime, reconnect rate, cold-first-poll cost | `[M]` the first poll after connect runs 22–37 ms against a 1–4 ms steady state — a per-connection tell already flagged in `DITTO_VS_DEFENSE3.md:146-149` `[R]` |
| B-7 | long-horizon volume and duty cycle | trivially computed; a fixed-cadence poll makes it constant |

#### Application layer — plaintext regime only

| # | observable |
|---|---|
| A-1 | DNP3 link header: `05 64`, **LEN**, CTRL, DEST/SRC link addresses, block CRCs `[M]` |
| A-2 | transport header FIR/FIN/SEQ `[M]` |
| A-3 | application control, **function code**, IIN bits `[M]` |
| A-4 | **object group/variation, qualifier, index range** — `[M]` the response's `1e 03 00 01 07` (g30v3, indices 1..7) determines the length exactly |
| A-5 | fragmentation and CONFIRM behaviour |

**In regime PT, A-1 through A-5 dominate everything else.** The adversary reads the function code
directly; size fingerprinting is strictly weaker than parsing
(`PANEL_SYNTHESIS_WAY_FORWARD.md:91-93` `[R]`).

### 1.3 The elephant, quantified with my own measurement

`PANEL_SYNTHESIS_WAY_FORWARD.md:32-43` reports TCP stack fingerprint = 1.000, ACK mode = 1.000,
size = 0.493 (chance 0.333) `[R]`. I reproduced the input to the first number independently:

| device | TTL | DF | MSS | WScale | initial window | steady `data_offset` | SYN-ACK option layout |
|---|---:|---:|---:|---:|---:|---:|---|
| SEL-751 | 64 | 0 | 1460 | 0 | 8688 | 8 | MSS, WS, NOP·2, SACKOK, NOP·2, TS |
| AB1400 | **128** | 0 | **1478** | absent | **2048** | 5 | MSS, NOP·3 |
| ION7550 | 64 | 0 | 1460 | absent | **4380** | 5 | MSS only |

`[M]` A depth-2 decision tree on `(ttl, initial_window)` separates all three at 1.000 from a single
packet. **No mechanism in this project — not the timing engine, not any size candidate on the
table — moves a single one of these fields.** Any device-anonymity claim over unshaped T-1..T-5 is
void on arrival.

---

## 2. WHAT MUST ACTUALLY BE NORMALIZED, AND IN WHAT ORDER

### 2.1 TCP sequence advance — addressed head-on, as instructed

The instruction says sequence-number advance may be the killer for padding. It is a killer, but
not in the way the framing suggests, and the distinction changes the design. Four cases:

**(a) Padding with correct per-flow sequence translation.** The switch adds `B` bytes to a
relay→master segment, rewrites `seq += Δ` on relay→master and `ack −= Δ` on master→relay, with `Δ`
cumulative for the connection's life (`research_design.md:118-127` `[R]`). At the observer's
vantage the whole stream lives in the padded sequence space, so
`seq(n+1) − seq(n) == tcp.len == total_len − 20 − 4·data_offset`. **Consistent. Sequence numbers
leak nothing extra.** Padding is not defeated by seq advance in this case — it is defeated by the
DNP3-layer strippability of §3.3.

**(b) Padding WITHOUT sequence translation.** Then
`seq(n+1) − seq(n) = true_len ≠ total_len − 20 − 4·data_offset`. The observer subtracts and reads
the exact pad length. Worse, the master ACKs bytes the relay never sent, the relay receives an ACK
beyond its `SND.NXT`, and RFC 9293 §3.10.7.4 specifies a challenge ACK and drop
(`DITTO_VS_DEFENSE3.md:181` corrects an earlier "RST" claim `[R]`), whose practical outcome is a
retransmission stall and loss of SCADA visibility on a protection relay. **This is the killer.**
Any padding design must be rejected at the whiteboard unless the sequence translator is part of it.

**(c) Splitting / re-segmentation — the charter's mechanism (2).** Splitting does not change any
sequence number: the first segment starts at the same `seq` and the last ends at the same
`seq + len`. `sum(tcp.len)` over the burst equals the original payload length exactly. A
reassembling observer — which is the default behaviour of both Zeek and Wireshark `[L?]` —
recovers the size with zero effort. `DITTO_VS_DEFENSE3.md:24` already states this `[R]`; I
measured what it looks like: in `sweep_bpc1.pcap` the split emitter produces a run of **18-byte
segments at ~10.4 ms spacing with contiguous sequence numbers** (seq 52, 62, 80, 98, 116, …) `[M]`.
So splitting is **doubly bad**: it hides nothing *and* it manufactures a segmentation-plus-cadence
signature that no real outstation produces, which is a perfect Task-A detector. Note also that
splitting destroys T-10 (PSH boundaries) in a way that is itself a tell.

**(d) Overlapping-segment emission** (emit each byte range twice at overlapping offsets to inflate
wire volume without changing sequence space). Someone will propose this. `max(seq+len) − min(seq)`
recovers the true length, and the pattern is indistinguishable from pathological retransmission.
Reject.

**Consequence.** Of the two mechanisms named in the charter, **splitting is a null result against
this adversary** and should be reported as characterized-negative rather than built. The
*preserved* value of CRC-boundary splitting is not privacy — it is that it is byte-preserving and
protocol-safe, which makes it a useful **timing** primitive (a way to release a response in
controlled quanta) if and only if the emitted chunk sizes and cadence are made device-independent,
which is a much harder requirement than it sounds.

### 2.2 TCP timestamps — the observable this project has never normalized

**Mechanism.** RFC 7323 defines TSval as the sender's timestamp clock value at the moment the
*sender* builds the segment `[L✓ — RFC 7323, confirmed via search this session; the field semantics
are unambiguous]`. An in-network hold changes when the packet appears on the wire; it cannot change
the value already written into the option. The relay's TSval is therefore an **endpoint-side clock
readout embedded in every packet**, transported intact through the defense.

**Measurement.** SEL-751 timestamp clock: 1 ms units, **30 ms tick** — all 83 TSvals in
`blk_r1_native.pcap` are multiples of 30 and the minimum positive delta is exactly 30 `[M]`. So
`P(ΔTSval > 0) = c / 30 ms` for internal ACK→response gap `c`. Results are in the F2 table above.
Calibrated on native (implied 4.12 ms vs measured 4.40 ms), and rejects the d16 claim at
p = 2.6 × 10⁻⁵¹.

**Why this matters more than it first appears.** The defense's own report already concedes that
Defense 3 *relocates* the leak into READ→ACK rather than erasing it
(`REPORT.md:1528-1534` `[R]`). The TSval channel is worse than relocation: it is **preservation**.
The device's internal interval is still on the wire, in a header field, at a fixed offset, in a
form the observer reads without any statistics beyond counting.

**Secondary TSval leaks, all `[M]` or `[L?]`.**
- The **tick granularity** (30 ms) and the **clock rate** (≈1000 units/s) are themselves device
  fingerprints; p0f and the clock-skew fingerprinting line use exactly these `[L? — Kohno,
  Broido, Claffy, IEEE TDSC 2(2), 2005, listed at `defense3/REPORT.md:1817`; I did not re-open it
  this session].
- **Clock skew** over long captures identifies the individual unit, not just the model `[L?]`.
- **TSecr** pairs each response to its request, defeating any attempt to hide correspondence by
  reordering.
- The relay's TSval also **advances during the switch's hold**, so a large `D` produces a growing
  gap between the on-wire arrival time and the embedded stamp — a direct measurement of `D` itself.

**Is normalizing TSval feasible here?** Yes, and cheaply — see §4.4. This is the one place where
the size-axis lesson ("normalize what the observer parses") converts directly into a buildable,
resource-light mechanism.

### 2.3 Priority ordering — what to normalize, in order

Ranked by (information carried) × (cost to normalize)⁻¹, for **Task B, device discrimination**,
which is the task the threat model actually names.

| rank | observable | carries | can this switch normalize it? | cost |
|---|---|---|---|---|
| **1** | T-1..T-5 static TCP stack fields (options layout, MSS, WScale, initial window) + IP-1 TTL + IP-2 DF | **balanced accuracy 1.000 on 3 devices** `[M]`/`[R]` | **Yes** — all are fixed-offset header fields, rewritable with a checksum delta. SYN/SYN-ACK option rewriting is the only fiddly part (variable-length option list, one packet per connection). | low–moderate: a handful of match-action stages, no state beyond per-flow |
| **2** | T-11 TSval (and T-12 TSecr) | **the device's internal ACK→response interval, D-invariantly** `[M]` | **Yes** — fixed offset when `data_offset == 8` and the layout is `NOP NOP TS`; needs a per-flow forward/reverse translation | low: 8 B into PHV, 2 registers, checksum delta, plus a fail-open for the SACK case |
| **3** | IP-3 `ip.id` | ID policy fingerprint + transmit-order/count oracle | **Yes** — rewrite to a switch-derived counter or randomize | very low: 16-bit field, checksum delta only (IP checksum is header-only) |
| **4** | T-7 window trajectory | transaction index, request size, buffer policy | **Yes but risky** — rewriting the advertised window changes real flow control on a protection relay's session. Needs a clamp that can only *reduce* effective window safely. | low resource, **high operational risk** |
| **5** | B-2 ACK mode (separate vs combined) | **1.000** `[R]` | **Partly** — the switch could hold the ACK until the response and emit them coalesced, or emit a synthetic ACK for a combined-ACK device. This is a packet-count change, not a timing change. | moderate; changes packet counts, interacts with the retirement defect |
| **6** | B-4 CLRT | the Formby feature `[R]` | Yes — demonstrated `[R]` | 8/12 ingress stages `[R]` |
| **7** | B-3 READ→ACK | created by the defense; 1.000 `[R]` | Yes if release is gridded (`DITTO_VS_DEFENSE3.md:127-139` `[R]`) | replaces the deadline machinery |
| **8** | IP-4 `ip.len` / T-8 payload size | **0.493 on 3 devices; 0 bits within this device** `[M]`/`[R]` | **No** in regime PT (§3.3) | very high, and negative under `k = 1` |
| 9 | A-1..A-5 DNP3 fields | dominates everything in regime PT | No (would require rewriting the protocol) | — |

**The size axis is eighth.** Rows 1, 2 and 3 are cheaper than row 8 by an order of magnitude and
carry more information. If the committee's objective is "a passive observer cannot fingerprint the
SEL-751 by either channel" (`CHARTER.md:7-9`), then rows 1–3 are the work, and the size axis is a
characterized negative.

---

## 3. THE FINGERPRINTING THREAT, AND POSITIONING AGAINST DITTO

### 3.1 What the literature establishes for ICS/SCADA specifically

- **Cross-layer response time identifies substation devices.** Formby, Srinivasan, Leonard, Rogers,
  Beyah, *"Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical
  Systems,"* NDSS 2016 — 92–99 % classification accuracy on substation devices from the
  ACK→response interval. `[L? — listed and used as the project's threat model at
  `defense3/REPORT.md:1821` and `:246-252`; I did not re-open the paper this session]`
- **Inter-arrival-time distributions identify device *and* device type.** Radhakrishnan, Uluagac,
  Beyah, *"GTID,"* IEEE TDSC 2014. `[L?]`
- **SCADA role fingerprinting without DPI on real critical-infrastructure captures.** Jeon, Yun,
  Choi, Kim, arXiv:1608.07679, 2016. `[L?]`
- **Hybrid communication-pattern + header fingerprinting for ICS/SCADA device recognition** uses
  exactly the field set I measured above — frame length, vendor MAC/OUI, TCP segment length, IP
  identification, IP total length, TTL, TCP window size (IFIP IM 2019 DISSECT workshop). `[L✓ for
  the feature list, from the search result text; the PDF host refused connection so I could not
  open the paper — treat the exact citation as unverified, the feature list as corroborated]`
- **Encrypted ICS traffic leaks enough for a *targeted physical* attack.** Mitra, Dash, Yao, Mehta,
  Pattabiraman, *"ICS-Sniper: A Targeted Blackhole Attack on Encrypted ICS Traffic,"*
  arXiv:2312.06140, Dec 2023; a related workshop version appeared at RICSS 2024. The adversary is
  an Internet-path observer of **encrypted** ICS traffic who uses **packet sizes and timing** to
  identify critical control packets and selectively drops them, damaging the process without ever
  entering it. `[L✓ — abstract and adversary model fetched this session]`

**ICS-Sniper is the citation that repairs this project's threat model.** It is the missing
justification for caring about size and timing *under encryption*, where DNP3 parsing is
unavailable — precisely the regime `PANEL_SYNTHESIS_WAY_FORWARD.md:90-96` says the size claim needs
`[R]`. It also reframes the target: the valuable secret is not only *which device* but *which
packet is the control command*, which is a size-and-timing question in the request direction — the
direction this switch placement cannot protect (F1).

### 3.2 What the literature establishes about padding and morphing defenses, including failures

- **Traffic morphing** reshapes one size distribution into another at minimal cost — Wright, Coull,
  Monrose, NDSS 2009. `[L? — `REPORT.md:1828`]`
- **Efficient countermeasures fail.** Dyer, Coull, Ristenpart, Shrimpton, *"Peek-a-Boo, I Still See
  You,"* IEEE S&P 2012: nine padding-based countermeasures fall to classifiers using coarse
  features (total bytes, total time, burst structure); only rigid constant-size constant-rate
  transmission (BuFLO) resists, at large overhead. `[L? — `REPORT.md:1829`]` **This is the single
  most transferable negative result for this committee**: padding that leaves the *aggregate*
  intact does not survive, and the aggregate here is trivially available because the poll cadence
  is deterministic to ±0.3 ms `[M]`.
- **Padding-only defenses fall to deep learning.** Sirinam, Imani, Juarez, Wright, *"Deep
  Fingerprinting,"* ACM CCS 2018. `[L? — `REPORT.md:1833`]`
- **Timing alone suffices.** Feghhi and Leith, IEEE TIFS 11(8), 2016 — traffic analysis using only
  timing, no size. `[L? — `REPORT.md:1835`]` This is why a timing-only contribution is
  non-redundant, and equally why a size-only contribution would not be.
- **Principled shaping needs a shaping point that owns the secret.** Pacer (Mehta, Alzayat, De
  Viti, Brandenburg, Druschel, Garg, USENIX Security 2022) shapes guest traffic *outside* the guest
  in the hypervisor and respects flow/congestion control; it requires hypervisor and guest-kernel
  modification. `[L✓ — verified this session]` NetShaper (Sabzi, Vora, Goswami, Seltzer, Lécuyer,
  Mehta, USENIX Security 2024) gives **differential-privacy** guarantees over packet size and
  timing via a **tunnel-endpoint** design with a middlebox implementation. `[L✓ — verified this
  session]`

**The pattern across all of them:** every defense that actually closes a size channel owns an
*envelope* — a tunnel, a hypervisor, a TLS endpoint — inside which it can add bytes the observer
cannot attribute. None of them is a single non-cooperating middlebox on a plaintext,
self-describing protocol. That is not a gap in the literature waiting to be filled; §3.3 argues it
is a theorem.

### 3.3 The strippability theorem, extended to the DNP3 layer

The recorded rule (`SIZE_PRIMITIVE_REUSE_AUDIT.md:467-468` `[R]`):

> Any padding that is protocol-transparent — strippable by a receiver without cooperation — is by
> construction strippable by the observer, who applies the same rule.

The corollary on record (`:493-495` `[R]`) says a size defense must change the length field the
observer reads, or make it unreadable, and that only two families qualify: genuinely extend the IP
datagram, or encrypt the length-bearing header.

**The extension this report adds.** The rule is not a statement about IP. It is a statement about
*any* layer the observer parses. In regime PT the observer parses DNP3, and DNP3 is
**self-delimiting and self-describing**. From the physical relay's actual bytes `[M]`:

```
05 64 2b 44 01 00 00 00 7a 15   link hdr: START, LEN=0x2b, CTRL, DEST=0001, SRC=0000, CRC
eb                              transport: FIR|FIN, seq
c0 81 80 00                     app: AC, func 129 RESPONSE, IIN 0x8000
1e 03 00 01 07                  object hdr: g30v3, qual 8-bit start/stop, indices 1..7
… 28 bytes of analog data … 70 a4
```

Therefore:
- A **prepended black-hole link frame** carries its own `LEN`. The observer reads `LEN`, skips
  `10 + LEN' + 2·⌈…⌉` bytes, and lands on the real frame. **Strippable in one subtraction.**
- A **Group 110 octet-string filler object** carries its own group code and self-describing length.
  The observer drops objects with group 110 and recomputes. **Strippable by type.**
- The `LEN` field means the true DNP3 frame length is on the wire **even after `ip.len` is
  normalized**. So in regime PT, normalizing `ip.len` is exactly as ineffective as normalizing
  `frame.len` was — one layer up, same category error, same measurement outcome predicted.

**Statement for the paper.** *In a plaintext, self-describing application protocol, no
non-cooperating in-network element can close the size channel, because the receiver's ignore-rule
and the observer's strip-rule are the same rule, and it is written in the packet.* The only filler
that survives is filler that is byte-indistinguishable from real data, which requires the endpoint
to genuinely produce it. This is a clean, defensible, general negative — stronger than the current
recorded version, and it is a contribution rather than a gap
(`PANEL_SYNTHESIS_WAY_FORWARD.md:66-70` already frames it this way `[R]`).

### 3.4 Regime CT: what changes under encryption

Under TLS / IEC 62351-3, MACsec or IPsec, A-1..A-5 vanish. What remains: IP-1..IP-6, T-1..T-16,
B-1..B-7, plus TLS record boundaries and lengths. The size channel becomes **the record length,
which tracks `ip.len` exactly**, so trailer padding still does nothing and the strippability
theorem still applies to any in-band filler that the *TLS layer* would have to ignore — except
that the observer can no longer parse inside the record. So in regime CT:

- padding *inside* the encrypted record is genuinely unstrippable, and that is what NetShaper and
  TLS record padding do `[L✓ for NetShaper]` — but it requires being the TLS endpoint;
- padding *outside* the record (extra TCP bytes) is visible as a length mismatch against the record
  header `[I]`;
- **the switch is not the TLS endpoint and cannot become one** — Tofino-1 structurally cannot
  encrypt the payload because the DNP3 bytes are the unparsed deparser residual and never enter the
  PHV (`DITTO_VS_DEFENSE3.md:80-82` `[R]`).

So regime CT makes the *threat* coherent and the *defense* no more achievable with one switch. It
does, however, make rows 1–3 of §2.3 more valuable, not less: under encryption, the static TCP
stack fields and TSval become a *larger* fraction of the adversary's total information.

### 3.5 Ditto (NDSS 2022), positioned precisely

**What Ditto does.** A fixed repeating pattern `P = [P_0 … P_{L-1}]` of packet **sizes**, L = 3–6,
emitted at a fixed rate, computed offline from the expected size distribution; three data-plane
operations — pad, delay, insert chaff. Per pattern state a **pair** of priority queues (high =
real, low = chaff-flooded) so the pair is never empty; round-robin across the L pairs emits the
pattern. TF1 has no hierarchical scheduler, so every packet traverses the switch **twice via
loopback ports**. Padding is ≤254 B per pass, added as custom headers of 32/16/8/4/2/1 B marked in
the EtherType, and recirculated when more is needed.
`[R — `DITTO_QUEUE_RECONSTRUCTION.md:44-135`, page-sourced against the repo PDF]`

**What Ditto assumes — the three assumptions that do not hold here.**
1. **A cooperating peer switch.** The far end strips the padding and restores the EtherType
   (`DITTO_QUEUE_RECONSTRUCTION.md:2.12` `[R]`). Ditto is a *pair*.
2. **An encrypted tunnel.** The switch is an endpoint of MACsec/IPsec, so padding is inserted where
   the observer's parse stops (`DITTO_VS_DEFENSE3.md:84-86` `[R]`). This is precisely what makes
   Ditto immune to the strippability theorem — and precisely what we do not have.
3. **A high-rate, always-busy aggregate.** Chaff is essential because round-robin skips empty
   queues (`DITTO_QUEUE_RECONSTRUCTION.md:2.4` `[R]`). At 5 pps and 200 B, the queue is empty
   almost always.

**Why it works.** Because (1) and (2) together give it an *envelope*: bytes it adds are
unattributable and are removed before anyone who could attribute them sees them. Everything else in
Ditto — the pattern, the priority pairs, the loopback — is engineering in service of that.

**What Ditto costs here.**
- **Peer switch:** not available (`CHARTER.md:26`, "one switch at the outstation edge") `[R]`.
- **Loopback ports:** ⌈L·bw/100⌉ per obfuscated port; L = 3 or 6 needs 2
  (`DITTO_QUEUE_RECONSTRUCTION.md:246-259` `[R]`).
- **Chaff:** operationally disqualified before effectiveness. Source-verified against
  `opendnp3-community`, injected DNP3 causes the master to write to the relay — `ProcessIIN` runs
  unconditionally even for rejected frames, so `NEED_TIME` triggers a g50 time-sync WRITE and
  `DEVICE_RESTART` a clear-restart WRITE; a fabricated CONFIRM makes the relay permanently delete
  SOE records (`DITTO_VS_DEFENSE3.md:90-105` `[R]`). Ditto's chaff is opaque ciphertext in a
  tunnel; ours would be live DNP3 aimed at a protection relay.
- **Padding cost on our chip:** the true-trailer construction already measured
  **tagalong 560 → 1840 bits = 89.8 % of the T-PHV budget** with egress parser states 6 → 36
  (`SIZE_PRIMITIVE_REUSE_AUDIT.md:432-436, :662` `[R]`), against a program where tagalong is already
  the binding resource at **7 of 8 collections occupied** (`CHARTER.md:31` `[R]`).
- **Timing fidelity:** Ditto's own caveat is that switch shaper rates are correct only *on average*
  and that the residual error is **worst for small packets** — our regime
  (`DITTO_QUEUE_RECONSTRUCTION.md:10-20, S13` `[R]`).

**The one framing worth keeping.** The polarity inversion already on record: Ditto manufactures
packets to *fill* a queue so round-robin will not skip it; this project manufactures tokens to
*starve* a queue so the scheduler will not serve it — same primitive, opposite sign, and ours never
egresses (`DITTO_VS_DEFENSE3.md:155-161` `[R]`). And the cost-model inversion: at 5 pps and 200 B
the provably optimal defense (emission on a content-independent schedule) costs ~10 kbit/s, so we
can afford the ideal rather than a heuristic (`:163-168` `[R]`). Both are good paper material and
both are about *timing*, not size.

**One-sentence positioning.** *Ditto closes the size channel because it owns an encrypted envelope
and a cooperating peer; with neither, and with a self-describing plaintext application protocol,
the size channel is not closable in the network — which is why the contribution here has to be the
timing and endpoint-state channels, plus a precise statement of the size impossibility.*

---

## 4. DEFENSE DESIGN GUIDANCE UNDER THE ACTUAL CONSTRAINTS

Constraints taken as given: Tofino-1, 12 ingress / 12 egress stages; tagalong PHV at 7/8
collections, 16-bit 83.3 %, 32-bit 84.4 % (`CHARTER.md:31` `[R]`); timing core alone consumes 8/12
ingress after packing (`:29` `[R]`); best measured combination P12 = 8 ingress / 2 egress
(`:30` `[R]`); one switch at the outstation edge; no endpoint modification; no peer; no decoder; the
relay is READ-only and is a protection relay; the retirement defect is open (`:54-59` `[R]`).

### 4.1 Ranked assessment of the size-defense classes

| # | class | defeats | leaves exposed | resource shape | verdict |
|---|---|---|---|---|---|
| **S1** | **Fixed-size padding to a single bucket** (in-band, prepend + seq translation) | `ip.len`, `tcp.len` per-packet size for a **regime-CT** observer | **Everything in regime PT** (DNP3 `LEN` strips it, §3.3). Even in CT: T-7 window, T-11 TSval, T-1..T-5, ACK mode, cadence. Anonymity set `k = 1`. | tagalong is the binding wall — the measured trailer variant hit 89.8 % T-PHV alone `[R]`; add per-flow seq/ack registers, runtime-Δ checksum (Class-6 compile zone `[R]`), SACK-option handling | **Do not build.** Only coherent in CT, and in CT the switch is not the crypto endpoint. |
| **S2** | **Padding to a small bucket set** | slightly less than S1 | strictly more than S1: per-device bucket-occupancy frequencies remain device-specific, so `I(padded_size; device) = 0` is reachable **only at B = 1** (`research_design.md:§6` `[R]`) | same as S1 plus a bucket table | **Do not build.** Strictly dominated by S1 and S1 is already void. |
| **S3** | **Chaff / dummy traffic** | volume and cadence, in principle | nothing in practice here | one recirculation loop | **Forbidden on safety grounds**, source-verified: can cause the master to WRITE to a live protection relay (`DITTO_VS_DEFENSE3.md:90-105` `[R]`). Not a privacy trade-off; a disqualification. |
| **S4** | **Response splitting / re-segmentation on CRC boundaries** | per-packet size histogram against a **non-reassembling** classifier only | total size (seq advance sums), all of §1.2 | cheap: no byte modification, no CRC recompute, no seq translation | **Report as characterized negative.** Additionally *creates* a Task-A signature — measured: contiguous 18-byte segments at 10.4 ms `[M]`. |
| **S5** | **CROB decoy padding** | request-direction size↔count leak (14.6 B/CROB, R² = 0.9999, `DECOY_CROB_PADDING.md:19` `[R]`) | — | — | **Topologically impossible at this vantage** (F1): the observer sees the request before the switch. Viable **only** as a master-side application-layer defense, exactly as `PANEL_SYNTHESIS_WAY_FORWARD.md:78-82` recommends `[R]`. Out of scope under "no endpoint modification". |
| **S6** | **Request canonicalization** — switch rewrites the READ's object range so the relay always answers a fixed maximal point set | makes the response size **genuinely constant** using only real measurements — the one filler that is not strippable | request direction (observer is upstream); creates a request/response range **mismatch** tell; response is still *this device's* maximal set, so `k = 1` persists | attractive: **no length change** if the rewrite is length-preserving → **no seq translation, no `ip.len` change**; needs DNP3 block-CRC recompute over one 16-byte block (`p4_decoy` demonstrated CRC-16/DNP on this chip per `research_design.md:§4.4` `[R]`) + TCP checksum delta | **The only size mechanism worth a paragraph in the paper** — and only as the constructive counterexample that shows what "unstrippable filler" has to look like. It does not fix `k = 1`, so it does not deliver device anonymity. |
| **S7** | **Combination S4 + timing** — split into fixed-size quanta released on a content-independent grid | converts a bursty response into a constant-size constant-rate emission for the duration of the response | the **number of quanta** still equals ⌈len/C⌉; you cannot fix the count without adding bytes | moderate; interacts with the retirement defect | **Weak.** Quantizes size to `C` granularity. For a device with one response size it quantizes zero bits. |

**Ranking, one line:** S6 > S4 > S7 > S1 > S2 > S5 > S3, and **every one of them is below the
non-size mechanisms in §4.2**.

### 4.2 What is actually achievable, ranked above the size axis

| # | mechanism | defeats | resource shape | risk |
|---|---|---|---|---|
| **N1** | **Static TCP/IP header normalization** — rewrite TTL, DF, IP-ID policy, MSS, window-scale, initial window, and the SYN/SYN-ACK option list to a canonical profile | the **1.000** channel `[M]`/`[R]`. This is the largest single leak in the whole system and nothing has ever touched it. | fixed-offset header fields + IP checksum delta (header-only, cheap) + TCP checksum delta. The SYN/SYN-ACK option-list rewrite is one packet per connection and is the only variable-length work; it can be handled with a small set of exact option-layout classes and a fail-open default. | **Moderate.** MSS and window-scale rewriting changes real flow control. A safe subset — TTL, DF, IP-ID only — is near-zero risk and already removes AB1400's TTL 128 and the DF bit. Rewriting the *client-visible* MSS downward is safe; upward is not. |
| **N2** | **TSval / TSecr normalization** — replace the relay's TSval with a switch-derived monotone clock on relay→master, and restore the original value in TSecr on master→relay | the D-invariant internal-timing channel measured in F2, plus the clock-rate/tick/skew fingerprints | 8 B of TCP options into PHV (already required to reach `data_offset = 8` cleanly); 2 registers per flow (last original TSval, offset); TCP checksum delta. One outstanding transaction means the mapping is 1-deep. | **Moderate and specific.** (a) PAWS and RTTM at the relay consume the echoed TSecr, so the restoration must be exact or the relay's RTO estimate is corrupted — dangerous on a protection relay. (b) During loss, SACK blocks push `data_offset` past 8 and change the option layout; the design **must** fail open to unmodified forwarding on any unexpected layout, and the leak during loss must be reported. |
| **N3** | **`ip.id` rewriting** | ID-policy fingerprint, off-path packet-count oracle, and the transmit-order/count side channel | one 16-bit field, IP checksum delta only | **Low.** IPv4 ID is only load-bearing for fragmentation, and DF is set / fragments absent here `[M]`. Must preserve uniqueness within the MSL if fragmentation is ever possible. |
| **N4** | **Gridded release** (Defense 4) — release on switch-clock edges `t_k = t_0 + kT` rather than a per-transaction deadline | makes every wall-clock observable a function of the lattice and the master's schedule, both adversary-known; structurally prevents the §12.4 relocation | predicted 7–8 ingress stages vs today's 10, by deleting the per-transaction deadline arithmetic and most of the response-authorization table (`DITTO_VS_DEFENSE3.md:141-143` `[R]`, prediction only — only `bf-p4c` settles it) | Residual **slip-rate** leak at granularity `T`; the cold first poll (21–37 ms `[M]`/`[R]`) exceeds any feasible `N·T`. **N4 is void without N2** — gridding the wire while TSval carries the true interval normalizes the field the adversary need not read. |
| **N5** | **ACK-mode normalization** | the other **1.000** channel `[R]` | coalescing the relay's ACK with its response changes packet counts; interacts directly with the open `tag_retire_if_unmarked` defect (`CHARTER.md:54-59` `[R]`) | High coupling to the open defect. Design it *after* the retirement fix, per `CHARTER.md:61-62`. |

**Recommended program, in order:** N3 (trivial, immediate) → N2 (the finding, cheap, high value) →
N1 safe subset (TTL/DF) → N4 (gridding, replaces the deadline machinery) → N1 full (option-list
rewrite) → N5 (after the retirement fix). The size axis is written up as §3.3's negative and not
built.

### 4.3 Why this respects the binding constraint

Tagalong PHV is binding at 7/8 collections `[R]`, and it is binding **because of the `pay*`/`pad*`
byte definitions** — 127 B of `pay*` plus 127 B of `pad*`
(`SIZE_CORESIDENCY_VARIANT_MATRIX.md:90-92` `[R]`). Every mechanism in §4.2 operates on **header
fields that are already in normal PHV or are small fixed-offset additions**, and none of them
requires carrying payload bytes through the pipeline. **Deleting the size axis frees the binding
resource.** That is a design argument, not a consolation: N1+N2+N3 are affordable *because* S1/S2
are abandoned.

Two constraint checks that must be run by `p4-dataplane-engineer` before any of this is promised:

1. **Option-region parsing at `data_offset = 8`.** Reaching the TS option requires 12 B of TCP
   options in PHV (`01 01 08 0a` + TSval + TSecr). Confirm these land in normal PHV, not tagalong,
   since they are MAU-written. Confirm the layout is invariant across the corpus — I measured
   `data_offset = 8` on all steady-state SEL-751 frames `[M]` and `CHARTER.md:32` records 2 102 of
   2 104 `[R]`, but the *option ordering* within those 12 B must be verified frame by frame, not
   assumed. **This is exactly the assumption class that produced the falsification.**
2. **Runtime-Δ TCP checksum update.** Flagged as the top compile risk and a Class-6 zone
   (`research_design.md:§1.4` `[R]`). N2 and N3 both need it (N3 only needs the *IP* checksum, which
   is header-only and cheap; N2 needs the TCP one). If runtime-Δ TCP checksum will not compile, N2
   is dead and must be reported as such rather than softened.

### 4.4 Spec sketch for N2, for handoff

Not P4 code — a spec for `p4-dataplane-engineer` to cost.

- **Parser.** Extend the existing TCP parse to consume the 12-byte option region when
  `data_offset == 8`; select on the first 4 option bytes. Layout `01 01 08 0a` → `parse_ts`;
  **anything else → `accept` with a parser-written class tag of 0.** Use the parser-produced
  `class tag` pattern from `SIZE_PRIMITIVE_REUSE_AUDIT.md:545-591` `[R]` so that "the table matched"
  implies "the parser consumed the option region" by construction. This is the corrected re-keying
  the audit prescribes, applied to a new mechanism so the bug class cannot recur.
- **Registers.** Per flow (one flow): `r_ts_last_orig` (32 b), `r_ts_offset` (32 b), plus a
  one-deep `r_ts_map_orig`/`r_ts_map_fake` pair to restore TSecr. One SALU each; note the
  four-operations-per-register hard limit (`REPORT.md:§8.3` `[R]`) and that a **32-bit packed state
  word cannot hold runtime fields on TF1** (`CHARTER.md:47-48` `[R]`) — keep these as separate
  registers, do not pack.
- **Tables.** `tbl_ts_norm` keyed on `(class_tag, direction)`, exact, ~4 entries. Actions:
  `ts_rewrite_fwd` (relay→master: write switch clock, record mapping), `ts_restore_rev`
  (master→relay: rewrite TSecr from the mapping), `ts_bypass` (fail open).
- **Checksum.** TCP checksum delta over the 8 changed bytes.
- **Fail-open.** Any unexpected option layout, any SACK-bearing segment, any second outstanding
  transaction → `ts_bypass`, and **increment a counter** so the leak during those windows is
  measured rather than assumed.
- **Safety invariant to state in writing before any hardware:** TSecr delivered to the relay must
  be bit-identical to what the master would have echoed in the absence of the defense, on every
  path including fail-open. Anything less corrupts the relay's RTO.

---

## 5. THE HONEST CEILING

### 5.1 What one switch, no endpoint changes, and a live relay can achieve

**Can be closed** (all wall-clock timing observables shaped, all rewritable header fields
canonicalized): B-3 READ→ACK, B-4 CLRT, B-5 total, IP-1 TTL, IP-2 DF, IP-3 ID, T-11/T-12
timestamps, and — at moderate operational risk — T-1..T-5 and T-7.

**Cannot be closed with this deployment, in any regime:**

1. **The master→relay direction.** The observer is upstream of the switch. Request sizes, request
   timing, request burst structure and the identity of control commands are unprotected. This is
   the ICS-Sniper channel (§3.1) and it is where the operationally sensitive secret lives. `[I]`
2. **Size, in regime PT.** §3.3. Not "hard" — *not possible* without endpoint cooperation.
3. **Size, in regime CT**, because the switch cannot be the crypto endpoint on TF1
   (`DITTO_VS_DEFENSE3.md:80-82` `[R]`).
4. **Anonymity with `k = 1`.** With one relay behind the switch, normalizing to any target makes
   that target this relay's signature. Device *anonymity* requires a confusion set behind the same
   normalizer. This is a deployment property, not a mechanism property, and no amount of P4 fixes
   it. `[I]`, corroborating `DITTO_VS_DEFENSE3.md:74-78` `[R]`.
5. **Behaviour under loss.** T-13 RTO, T-14 SACK, T-15 window probes are unexercised in every
   corpus in this repo `[M]` and would be unshaped by every mechanism proposed. An adversary who
   can induce a single loss — or simply waits for one — gets an unnormalized stack readout.
6. **Cold-connection behaviour.** The first poll after connect runs 22–37 ms against a 1–4 ms
   steady state `[M]`. A per-connection tell that no proposed grid absorbs
   (`DITTO_VS_DEFENSE3.md:146-149` `[R]`).

### 5.2 What Philip can and cannot say at the end

**Can say, if N2 lands and the retirement defect is fixed:**

> On a commodity switch ASIC, at the outstation edge, without modifying either endpoint, we
> normalize the wall-clock cross-layer response time **and** the endpoint-clock evidence of it, so
> that no observable we shape carries the device's internal processing interval. We show that the
> in-network *size* channel is not closable for a plaintext self-describing protocol, and we prove
> the negative rather than assert it.

**Can say about the negative, and it is the strongest part:**

> Two independent silicon measurements show that a size mechanism which is protocol-transparent is
> observer-transparent, and that the rule holds at every layer the observer parses — including the
> application layer, when the application protocol carries its own length. This is why in-network
> size normalization for cleartext ICS traffic has not been done, and it is a theorem about the
> deployment, not a limitation of the implementation.

**Cannot say, and must not:**

1. **"A passive observer cannot fingerprint the SEL-751."** The static TCP stack channel scores
   **1.000** `[M]`/`[R]` and no proposed mechanism touches it unless N1 is built. Until then this
   sentence is false by measurement.
2. **"The CLRT is hidden."** Not while TSval is forwarded unmodified. The d16 arm — the strongest
   arm in the sweep — is rejected at p = 2.6 × 10⁻⁵¹ by a header-field statistic `[M]`. **This
   invalidates the strongest form of the existing timing claim as currently implemented.** The
   claim survives only as: *hidden from an observer who does not read TCP options*. That is a
   defensible scoped claim, and it must be stated with the scope attached, in the abstract, not in
   a limitations paragraph.
3. **"Device anonymity."** `REPORT.md:1597-1609` already refuses this for lack of a confusion set
   `[R]`. Nothing in the size axis changes it; adding a size axis to a `k = 1` deployment makes it
   worse, not better.
4. **A combined size+timing claim of the form "both channels closed."** The size channel is not
   closed and, per §3.3, cannot be. The honest combined claim is *asymmetric*: **timing and
   endpoint-state normalized; size characterized as unclosable and proven so.**
5. **Anything about the request direction.** Topologically out of reach (F1).

### 5.3 The uncomfortable thing, said now

The team is preparing to design a replacement size mechanism. **The category error that killed the
first one is not specific to size, and it is currently live in the timing result.** The falsified
mechanism normalized `frame.len` while `ip.len` sat at full entropy. The current timing engine
normalizes the wall-clock CLRT while `TSval` sits at full entropy, carrying the same quantity,
D-invariantly, in a header field, at a fixed offset — and I measured it on the project's own
D-sweep captures. If a reviewer runs the four-line `tshark` pipeline in §0.1 against the artifact,
the strongest arm of the headline result fails a binomial test by fifty orders of magnitude.

That is fixable — N2 is cheap — but it must be fixed **before** the paper claims CLRT concealment,
not explained afterwards. And it should change the committee's priority order: the next mechanism
to build is not a size mechanism at all.

---

## 6. THE EVALUATION THAT WOULD SUBSTANTIATE A COMBINED CLAIM

### 6.1 Feature families (the adversary must be run per family and jointly)

| family | fields |
|---|---|
| `F_L2` | OUI, frame length |
| `F_IP` | TTL, DF, IP-ID policy + delta distribution, `ip.len` |
| `F_TCPstat` | SYN/SYN-ACK option layout and order, MSS, WScale, initial window, steady `data_offset` |
| `F_TCPdyn` | window trajectory (slope, reopen behaviour), seq/ack advance, PSH pattern, retransmit/SACK behaviour |
| `F_TS` | TSval tick granularity, clock rate, skew, **ΔTSval(ACK→RESP)**, TSval-minus-arrival-time drift |
| `F_size` | per-packet payload sizes, per-transaction total, size histogram |
| `F_time` | READ→ACK, CLRT, READ→RESPONSE, poll jitter, burst IPGs |
| `F_app` | DNP3 function code, object group/variation, index range, IIN (regime PT only) |
| `F_all` | union |

Per-family ablation is mandatory. The failure mode this committee exists to prevent is a headline
number computed over a feature set that excludes the channel that actually leaks.

### 6.2 Adversary classifiers

1. **Rule-based p0f-style oracle** on `F_TCPstat ∪ F_IP` — a depth-2 decision tree. Cheap, and it
   is the *bar*: if the defense does not beat this, nothing else matters. Current value: **1.000**
   `[M]`.
2. **The `F_TS` estimator** — the straddle test of §2.2, reported both as a detection test
   (binomial vs the null "internal gap equals observed gap") and as an estimator of `E[c]`. **With
   randomized poll phase**, to break the 300 ms / 30 ms commensurability that biased my point
   estimates.
3. **Gradient-boosted trees on engineered features** per family — the standard, interpretable
   baseline, and the one that supports ablation.
4. **A sequence model** (1D CNN over the (direction, size, IPG, header-delta) tuple sequence) as
   the Deep-Fingerprinting analogue `[L? — Sirinam et al., CCS 2018]`, to catch structure the
   engineered features miss.
5. **An adaptive adversary** retrained on defended traffic — required. A classifier trained only on
   native traffic is not the threat model.

### 6.3 Corpus

- **Task A (defense detection):** native vs defended, same device, ≥ 5 independent runs per
  condition, ≥ 20 TCP connections per run. Already feasible with the existing rig.
- **Task B (device discrimination) — the blocker.** Needs ≥ 2 **separate-ACK** outstations behind
  the same normalizer. `REPORT.md:1605-1609` records that no such second device exists `[R]`. Three
  options, in order of strength: (i) acquire a second separate-ACK relay — the only path to the
  headline claim; (ii) a host-based DNP3 outstation with a *deliberately varied* TCP stack profile
  (TTL, MSS, window, option layout set per run via `nftables`/`eBPF`), which makes `F_TCPstat` a
  controlled variable rather than a giveaway; (iii) the in-switch synthetic device population of
  `DITTO_VS_DEFENSE3.md:200-208` `[R]` — **a sufficient falsifier, not a sufficient confirmation**,
  and it must be labelled that way in the paper.
- **Loss regime:** a deliberate, controlled loss arm (netem, on the master-side link only, never on
  the relay link without authorization). Without it, `F_TCPdyn` rows T-13/T-14/T-15 are untested and
  the claim has an unmeasured hole.
- **Regime CT arm:** replay the same corpus with the payload encrypted (stunnel or an equivalent
  TLS wrapper between two hosts, not on the relay) to produce the regime-CT feature set. This is
  the arm that makes the threat model coherent per `PANEL_SYNTHESIS_WAY_FORWARD.md:90-96` `[R]`.

### 6.4 Metrics, statistics, and the null

- **Balanced accuracy**, chance = 1/(number of classes), with **grouped cross-validation by TCP
  connection** and **block bootstrap resampling whole connections** — the procedure
  `REPORT.md:1480-1503` already establishes as this project's standard `[R]`. Polls within a
  connection are not independent.
- **Mutual information** `I(feature; label)`, Miller–Madow corrected, with a **permutation null
  band**, as a mechanism-independent readout alongside the classifier.
- **A drift floor** measured native-vs-native across sessions (already 0.503–0.530 in
  `REPORT.md:1447-1448` `[R]`). No claim of "closed" without the CI touching this floor.
- **Report `F_all` alongside every per-family number.** Pre-register the expected `F_all` floor
  (currently ≈1.000, set by `F_TCPstat`) so the paper cannot appear to claim more than it shows.

### 6.5 Baselines

| # | arm | purpose |
|---|---|---|
| B0 | native | reference |
| B1 | Defense 3 timing only, at matched added latency | isolates the timing contribution |
| B2 | timing + N2 (TSval normalization) | tests the F2 finding directly |
| B3 | timing + N2 + N1 + N3 (full header canonicalization) | the real proposal |
| B4 | S4 splitting only | substantiates the size negative as a measurement, not an argument |
| B5 | **store-and-forward TCP-terminating proxy with a canonical stack** | the **upper bound**: what a defense that *can* do everything achieves. The gap between B3 and B5 is exactly what the in-network constraint costs, and quantifying it is a better contribution than pretending the gap is zero. |

### 6.6 Pre-registered failure criteria

The claim **fails** if any of the following holds after the defense:

1. Any feature family's held-out balanced-accuracy **95 % CI lower bound exceeds the drift floor**
   for Task B.
2. The `F_TS` binomial detection test rejects at α = 0.01 on any defended arm. *(Today it rejects at
   p = 2.6 × 10⁻⁵¹ on the strongest arm `[M]`.)*
3. `F_all` balanced accuracy does not decrease relative to B0 by an amount whose CI excludes zero.
4. Any correctness gate fails: DNP3 parse/CRC errors at a real OpenDNP3 master, non-zero
   retransmits/resets/reordering, CONFIRM-count deviation, or any relay error counter moving
   (`research_design.md:§6` correctness gate `[R]`).
5. The composed worst-case added latency exceeds the master's RTO cap (`research_design.md:§6`
   `[R]`).
6. The fail-open counters of §4.4 fire on more than a pre-registered fraction of frames — because a
   defense that bypasses is a defense that leaks, and the leak must be counted, not discovered by a
   reviewer.

A result that fails (1) or (2) but passes (4) is still publishable — as the characterized negative
of §3.3 plus the F2 finding. That is a genuine contribution and it is available *today*, without
building anything.

---

## 7. WHAT I DID NOT VERIFY

Stated so nothing here is taken for more than it is.

- I did **not** compile anything. Every resource number is quoted `[R]` from a compile someone else
  ran, with the file:line.
- I did **not** open Formby et al. 2016, GTID, Jeon et al., Dyer et al. 2012, Wright et al. 2009,
  Sirinam et al. 2018, Feghhi & Leith 2016, or Kohno et al. 2005 this session. They are cited from
  `defense3/REPORT.md:1815-1843`, which the task brief describes as 27 verified references. Marked
  `[L?]`.
- I verified **this session**: NetShaper (USENIX Security 2024, authors and design), Pacer (USENIX
  Security 2022, authors and design), ICS-Sniper (arXiv 2312.06140, adversary model and abstract).
  Marked `[L✓]`.
- The IFIP IM 2019 DISSECT paper's feature list is corroborated by search-result text but the PDF
  host refused connection; **do not cite it without opening it**.
- **PRP/HSR / IEC 62439-3 clause numbers remain unverified**, carried forward from
  `PANEL_SYNTHESIS_WAY_FORWARD.md:107` `[R]`.
- The SEL OUI attribution for `00:30:a7` is `[L?]` — check the IEEE registry before printing it.
- My TSval straddle estimator's **point estimates under defense are biased** by poll/tick
  commensurability, as stated. The **detection** result is robust; the **magnitude** estimate needs
  a randomized-phase experiment.
- I did **not** confirm that the SEL-751's TCP option *ordering* is invariant across all 2 104
  frames — only that `data_offset == 8`. §4.3 item 1 makes this a required check before N2 is
  promised. Assuming it is exactly the class of assumption that caused the falsification.

---

## 8. RECOMMENDATIONS TO THE COMMITTEE, IN ORDER

1. **Stop designing a size mechanism.** Write §3.3 up as the result. It is stronger than the
   version on record, it is measured twice on silicon, and it explains a genuine absence in the
   literature.
2. **Retire charter mechanism (1), CROB decoy padding, on topological grounds** (F1) before
   spending any further effort on its DNP3 legality or safety. It is a master-side defense.
3. **Retire charter mechanism (2), CRC-boundary splitting, as a privacy mechanism** (§2.1c). Keep it
   in the toolbox as a byte-preserving *timing* primitive only, and only if its emitted chunk
   pattern is made device-independent.
4. **Run the TSval analysis of §0.1 over the full D-sweep yourself, today, before anything else.**
   It is four lines of `tshark` and it changes what the timing claim may say.
5. **Build N2 (TSval normalization) next**, with the parser-tag re-keying of
   `SIZE_PRIMITIVE_REUSE_AUDIT.md:545-591` applied from the start so the coupling bug class cannot
   recur, and with the option-layout invariance check of §4.3 run *before* the design is costed.
6. **Add N3 (`ip.id`) in the same program** — it is nearly free and it removes a transmit-order
   oracle that would otherwise expose every future scheduling mechanism.
7. **Scope every timing sentence in the manuscript to "an observer who does not read TCP options"**
   until N2 is measured, or delete the sentence.
8. **Hand N1/N2/N3 to `p4-dataplane-engineer` as a spec** (§4.4 is the seed), and require the
   runtime-Δ TCP checksum feasibility answer *first*, since N2 dies without it and that is a
   one-compile question.
