# Agent B — TCP & Transport-Protocol Constraints on Bounded ACK-Bearing Response Delay

_Evidence report for the ACK-bearing DNP3 response timing-normalization study. Scope:
the transport-layer (TCP) constraints on how long the defense may hold / delay / pace an
already-existing, payload-bearing response segment **without** rewriting TCP seq/ack
numbers or forging ACKs. Every quantitative claim below is tagged by evidence class:
**[STD]** standard-defined behavior (RFC), **[SRC]** Linux kernel source / documented
default, **[PAPER]** peer-reviewed result, **[MEAS]** measured on this rig (from
`measured_timing_data.md`), **[INFER]** our engineering inference, **[HYP]** untested
hypothesis. All citations verified this session via WebFetch of rfc-editor.org, kernel.org
raw source, man7.org, and the Crossref API; see PAPER_MATRIX_ROWS / BIBTEX._

---

## 0. Bottom line (the three deliverables, up front)

1. **The binding transport constraint is the master's effective TCP RTO on its
   outstanding *request* segment — not any DNP3 timer.** Holding the outstation's
   piggybacked (ACK+response) segment leaves the master's request unacknowledged; if the
   hold exceeds the master's effective RTO, the master retransmits the request. On this
   directly-switched sub-millisecond 1 G LAN the effective RTO collapses to the Linux
   floor **`TCP_RTO_MIN` = HZ/5 = 200 ms** **[SRC]**, which is **25×–300× tighter** than
   every DNP3 app/link timer (5–60 s) **[MEAS/prior]**. So "stay under RTO" is both the
   correctness bound and the stealth bound. **Do not assume 200 ms — measure it** (§2),
   because `rto_min` is tunable per route and a low-latency-tuned master could floor an
   order of magnitude lower.

2. **RTO measurement procedure for Vision (§2):** read the static floor
   (`ip route get <Hulk>` for a per-route `rto_min`; the compile-time default is 200 ms),
   confirm `net.ipv4.tcp_retries2`, then **measure the effective value empirically** —
   induce a hold that overshoots, and read the delta from the master's original request
   segment to its first TCP retransmission of the same sequence number in the capture.
   That observed inter-retransmit interval *is* the effective RTO (first backoff step).

3. **RQ5 failure modes (§3):** our delay can cause all three, in decreasing order of
   real risk on this rig — **(a) TCP retransmissions** (overshoot RTO → the loudest tell;
   avoid with a hold budget a safe fraction of the measured RTO); **(b) packet
   reordering / spurious fast-retransmit** (only if a *multi-segment* response is released
   out of order; avoid by preserving strict per-flow FIFO — never emit segment N+1 before
   N); **(c) queue buildup** (negligible here — <1 held frame expected per outstation —
   but bound the held-frame table and pace in order). The software replay server has only
   failure mode (a); an in-network bump-in-the-wire hold adds a **second** retransmit
   source (the outstation's own RTO on a payload it has *already emitted*), which is the
   crux of the pure-ACK-vs-payload-ACK distinction (§1.4).

---

## 1. Transport background, grounded in the standards

### 1.1 The subject is a piggybacked (payload-bearing) ACK, not a bare ACK

TCP requires that "once in the ESTABLISHED state, all segments must carry current
acknowledgment information" (RFC 9293 §3.8) **[STD]** — every data segment is also an ACK.
The measured outstation piggybacks its DNP3 response onto the segment that ACKs the
master's request for **9/9** exchanges **[MEAS]**. Consequently, when the defense "holds
the response," it necessarily holds the ACK of the master's request as one indivisible
wire event. You cannot separate them without forging a bare ACK and rewriting seq/ack —
which the phase rule forbids. This is why the master's request-side RTO lands squarely on
the critical path.

Piggybacking happens (rather than a bare ACK followed by a later data segment) because the
response is produced in ~1 ms **[MEAS]**, far inside the outstation's delayed-ACK window
(below). A slower/embedded outstation whose processing exceeds that window would emit a
bare ACK first, then the response — a lower piggyback ratio, itself a device fingerprint
(consistent with the prior brief §2).

### 1.2 The delayed-ACK timer sets the piggyback window

A receiver may defer an ACK: RFC 1122 §4.2.3.2 requires a delayed-ACK mechanism "with a
maximum delay of 0.5 seconds," and "an ACK SHOULD be generated for at least every second
full-sized segment" **[STD]**. RFC 5681 restates this: an ACK "MUST be generated within
500 ms of the arrival of the first unacknowledged packet" and "a TCP receiver SHOULD send
an immediate duplicate ACK when an out-of-order segment arrives" **[STD]**.

Linux implements a tighter window than the RFC ceiling **[SRC]** (`include/net/tcp.h`):

| Constant | Definition | ms @ HZ=1000 | Meaning |
|---|---|---|---|
| `TCP_DELACK_MAX` | `(HZ/5)` | **200** | max delay before an ACK is forced |
| `TCP_DELACK_MIN` | `(HZ/25)` | 40 | min delayed-ACK hold |
| `TCP_ATO_MIN` | `(HZ/25)` | 40 | min adaptive ACK timeout |

**Relevance:** the piggyback we manipulate exists only because processing (~1 ms) ≪ the
outstation's ~200 ms delayed-ACK ceiling. Our hold *extends* the effective time the
master's request stays unacked, which is exactly what arms the master's retransmit timer.

### 1.3 RTT measurement → RTO, and the min-RTO floor (the core budget number)

RTO is derived from RTT samples via the Jacobson/Karels estimator, standardized in
**RFC 6298** (obsoletes RFC 2988) **[STD]**, and RFC 9293 §3.8.1 mandates "The RTO MUST be
computed according to the algorithm in [RFC 6298], including Karn's algorithm" **[STD]**.
The rules that bound our budget:

- First sample R: `SRTT = R`, `RTTVAR = R/2`, `RTO = SRTT + max(G, K·RTTVAR)`, K=4 (RFC 6298 rule 2.2) **[STD]**.
- Subsequent: `RTTVAR = (1−β)·RTTVAR + β·|SRTT−R'|`; `SRTT = (1−α)·SRTT + α·R'`; `RTO = SRTT + max(G, K·RTTVAR)`; α=1/8, β=1/4 (rule 2.3) **[STD]**.
- **Minimum RTO (rule 2.4): "if it is less than 1 second, then the RTO SHOULD be rounded up to 1 second."** **[STD]** Linux does **not** follow the 1 s recommendation; it floors at `TCP_RTO_MIN = (HZ/5) = 200 ms` **[SRC]** — the operative number for us.
- Initial RTO before any sample: 1 s (RFC 6298 rule 2.1; Linux `TCP_TIMEOUT_INIT = 1*HZ`, comment cites "RFC6298 2.1") **[STD/SRC]**.
- Backoff on expiry (rule 5.5): **"the host MUST set RTO ← RTO · 2"** **[STD]** — every missed retransmit doubles the timer. Linux caps at `TCP_RTO_MAX = 120 s` **[SRC]**.
- Karn's algorithm: RTT is **not** sampled from a retransmitted segment (RFC 6298 §3) — so a hold that triggers one retransmit also *poisons* the next clean RTT sample's provenance.

**Why 200 ms on this rig [INFER, grounded]:** a directly-switched 1 G LAN gives sub-ms
RTT, so `SRTT + 4·RTTVAR` computes to a few ms at most; RFC 6298 rule 2.4 / Linux
`TCP_RTO_MIN` then clamp the result up to the 200 ms floor. The floor, not the formula,
governs. TCP timestamps are on (option sig `NOP-NOP-Timestamp`, RFC 7323) **[MEAS/STD]**,
so the master takes an RTT sample on nearly every ack and the estimator is well-converged —
which only makes the clamp-to-floor behavior more certain, not less.

**Why every DNP3 timer is irrelevant to the budget [MEAS/prior]:** master app-response
5 s, outstation solicited-confirm 5 s, select 10 s, link keepalive 60 s. The TCP RTO
(~200 ms) fires **two-plus orders of magnitude sooner**, so the master retransmits at L4
long before any DNP3 session timer notices. The transport layer, not the application, is
the wall.

### 1.4 The decisive distinction: pure-ACK delay vs payload-bearing-ACK delay

This is the transport crux and it changes the budget by platform:

- **Pure ACK (no payload).** Its sender has no data outstanding *for that ACK*; it arms
  **no** retransmit timer of its own. Because ACKs are cumulative (RFC 9293), a later ACK
  subsumes a delayed/lost earlier one. Delaying a pure ACK risks only the *other* side's
  RTO on the data being acknowledged, and only if no subsequent ACK arrives first.
  Pure-ACK delay is "soft."
- **Payload-bearing ACK (our case).** The segment carries bytes the *receiver's peer*
  (the master) must ACK. Two clocks now run:
  1. **Master's RTO on its outstanding request** (the request is unacked while we hold the
     piggybacked ACK+response). Fires at ~200 ms on this rig.
  2. **Outstation's RTO on the response payload** — but **only in the in-network case**.
     A real outstation that has *already emitted* the response segment arms its own RTO for
     those payload bytes and expects the master's ACK within it. An in-network hold of H ms
     means the outstation sees its payload acked ~H+RTT after emission; if H+RTT exceeds the
     outstation's RTO, **the outstation retransmits the response before our held copy is
     even delivered** — a duplicate-data spurious retransmit sourced upstream of our element.

  **Platform consequence [INFER]:**
  - **Software replay server (immediate deliverable):** the server *generates* the response
    bytes, so there is no upstream sender and no clock #2. Only the master's request RTO
    bounds the hold. This is the cleanest case and the reason the software scheduler is the
    honest first result (prior brief §3.3/§8).
  - **In-network bump-in-the-wire (Tofino/DPU, future):** the hold budget is
    **min(master request RTO, outstation payload RTO)**, and clock #2 started at the
    outstation's *emission*, not at your hold — so you must subtract the transit/queue time
    already elapsed. Practically both floor near 200 ms on this LAN, but the correct model
    is the tighter of the two, minus elapsed time.

---

## 2. RTO measurement procedure for the Vision master (deliverable 2)

**Do not assume 200 ms.** `rto_min` is tunable per destination route, and low-latency
tuning (common in DC fabrics) can set it to single-digit ms — which would shrink the safe
budget by an order of magnitude. Establish the *effective* value on Vision empirically.

**Step A — static floor (what the kernel is configured to enforce).**
On Vision (the master, `10.10.54.19`):
```bash
# Per-route rto_min override toward the outstation, if any (ip-route(8): rto_min =
# "the minimum TCP Retransmission TimeOut to use when communicating with this destination"):
ip route get 10.10.54.158            # look for a trailing "rto_min <ms>"; absent ⇒ compile default
# The compile-time default when no route override exists is TCP_RTO_MIN = HZ/5 = 200 ms.
# Kill-the-connection retry ceiling (not the budget, but the escalation horizon):
sysctl net.ipv4.tcp_retries2         # default 15 ⇒ ~924.6 s before the socket is torn down
sysctl net.ipv4.tcp_retries1         # default 3  ⇒ when the stack first warns the IP layer
```
There is **no** global `sysctl` for the RTO floor; it is the compile-time `TCP_RTO_MIN`
unless a per-route `rto_min` overrides it (kernel `ip-sysctl` documents `tcp_retries2`/`1`
but not an `rto_min` sysctl — it lives on the route) **[SRC]**.

**Step B — effective RTO from a capture (the number that actually binds).**
1. Start a tcpdump on Vision for the DNP3 flow to Hulk (`tcp port 20000`).
2. Induce a single hold that deliberately overshoots (e.g., delay one response by ~400 ms,
   well past the expected 200 ms floor) on the split/replay path.
3. In the capture, locate the master's **request** segment, then its **first
   retransmission** (same TCP sequence number, `tcp.analysis.retransmission` in Wireshark).
4. **Effective RTO = t(first retransmit) − t(original request).** On a converged sub-ms
   LAN this should read ~200 ms (the floor); a materially smaller value means Vision has a
   tuned `rto_min` and the budget must shrink accordingly.
5. Confirm the **backoff doubling** (RFC 6298 rule 5.5): successive retransmits should sit
   at ~2×, 4×, … the first interval, capped at `TCP_RTO_MAX` = 120 s **[SRC]**. Seeing the
   geometric backoff confirms you are reading RTO, not a delayed-ACK artifact.
6. Because timestamps are enabled (RFC 7323), you can cross-check with `TSval/TSecr`: the
   retransmit reuses/echoes timestamps that disambiguate it from an original.

**Step C — sanity bound.** The measured effective RTO is the *hard* ceiling; the safe
operating budget is a fraction of it (recommend ≤ 25–50%, see §3.1). The current 10 ms/chunk
default sits ~20× under a 200 ms floor **[MEAS/prior]** — comfortable, but re-derive the
margin against the *measured* Vision RTO rather than the assumed 200 ms.

---

## 3. RQ5 failure modes: which our delay can cause, and how to avoid them (deliverable 3)

### 3.1 Failure mode (a): TCP retransmissions — the primary, loudest risk

**Mechanism.** Holding the piggybacked ACK+response leaves the master's request unacked;
overshoot the master's effective RTO and the master retransmits the request (RFC 6298
§5) **[STD]**. In the in-network case, the outstation's RTO on the already-emitted payload
is a second independent trigger (§1.4). A retransmit is precisely the event a passive
observer and a Zeek/Bro `dnp3` correctness monitor both flag (prior brief §4.4), so it is
simultaneously a correctness failure and a stealth failure.

**Secondary damage when it fires:** RTO backoff doubles the timer (RFC 6298 rule 5.5); the
sender's congestion window collapses to 1 MSS on an RTO (RFC 5681 recovery) **[STD]**;
Karn's algorithm voids the ambiguous RTT sample (RFC 6298 §3). None of this breaks DNP3
(app timers are seconds away) but all of it is visible on the wire.

**Avoidance.**
- Cap **per-hop hold** *and* **cumulative added latency of the whole transaction** below
  the **measured** effective RTO (§2), with margin — recommend a hold budget ≤ 25–50% of
  RTO so transient RTT/RTTVAR growth cannot cross the floor.
- **Multi-fragment reads compound** [MEAS/prior]: the DNP3 CONFIRM handshake serializes
  fragments, so per-fragment holds add; enforce `Σ holds < effective RTO` across the
  transaction, i.e., `D_max/fragment ≈ (RTO_margin) / n_fragments`, and each individual hop
  still under RTO.
- Prefer the **software replay server** for the first deliverable — it eliminates the
  outstation-RTO trigger entirely (§1.4), leaving only the master-request RTO to respect.

### 3.2 Failure mode (b): packet reordering / spurious fast retransmit

**Mechanism.** RFC 5681 **[STD]**: a receiver sends an immediate duplicate ACK on an
out-of-order segment, and **three** duplicate ACKs (dupthresh = 3) trigger the sender's
fast retransmit. So reordering ≥ 3 segments within one flow induces a spurious retransmit
*without* any RTO overshoot.

**Applicability to us.** A single held-then-released frame does **not** reorder anything —
FIFO order is preserved. Reordering is a risk **only** when a response spans multiple
segments (large READ, or a split into chunks) and the scheduler releases them out of order
or interleaves paced chunks. The prior brief already flags intra-burst reordering as "a
trap" (§3.1/§3.2) — this is the transport reason why: it is low-value and directly arms
fast-retransmit.

**Avoidance (by construction).** Maintain **strict per-flow FIFO**: never emit segment N+1
before segment N of the same connection. Hold/pace whole responses as ordered units; if
splitting, release chunks in sequence. Under this invariant, reordering-induced
fast-retransmit is structurally impossible. Linux `tcp_early_retrans`/TLP (default 3) and
`tcp_frto` (default on) further reduce spurious retransmits **[SRC]**, but we should not
rely on them — ordering discipline is the real control.

### 3.3 Failure mode (c): queue buildup / congestion-control side effects

**Mechanism.** Held frames occupy buffer; delayed/thinned ACKs perturb the sender.
RFC 3449 (BCP 69) **[STD]** documents that reducing ACK frequency causes (i) **burst
transmission** — "the sender transmits data in large bursts … limited only by the available
cwnd" because each infrequent ACK advances the window by several segments; (ii) **slower
cwnd growth** — "current TCP sender implementations increase their cwnd by counting the
number of ACKs … not by how much data is actually acknowledged"; and (iii) **weakened fast
recovery**. The dual phenomenon, **ACK compression**, is characterized by Zhang, Shenker &
Clark (SIGCOMM '91) **[PAPER]**: ACKs queued behind a data burst "become compressed in
time," producing "an intense burst of data packets in the other direction." Holding then
bulk-releasing ACKs is a deliberate ACK-compression event.

**Applicability to us [MEAS/INFER].** DNP3 is request/response, one transaction at a time,
with transfers far smaller than the initial window — so cwnd dynamics are largely inert
(there is no sustained bulk flow whose cwnd we can starve). Offered load is single-digit
kbps and, with hold (ms) ≪ poll interval (≥ 1 s), the **expected simultaneously-held frames
< 1 per outstation** (prior brief §4.3). Queue buildup is therefore negligible on this rig.
The residual, real concern is the **micro-burst on release**: a held ACK+response emitted
late can briefly compress with the next exchange.

**Avoidance.** Bound the held-frame table (64–256 entries is 1–2 orders of margin, prior
brief §4.3); **pace releases in order** rather than dumping; keep hold ≪ poll interval so
occupancy stays < 1. For principled pacing when we do shape multiple frames, the pacing
literature applies: Aggarwal, Savage & Anderson (INFOCOM 2000) **[PAPER]** show TCP pacing
smooths bursts (relevant to *not* recreating compression), and Carousel (SIGCOMM '17)
**[PAPER]** gives the modern single-timing-wheel "release by timestamp" design — the exact
software pattern for the replay server's per-response schedule, and evidence that
timestamp-based paced release is the scalable, correct way to hold-then-emit.

### 3.4 Failure-mode summary

| RQ5 mode | Trigger in our design | Risk on this rig | Governing standard | Avoidance |
|---|---|---|---|---|
| TCP retransmission | hold > effective RTO (master req; +outstation payload in-network) | **High if unbounded** — the loud tell | RFC 6298 §5; RFC 5681 | budget ≤ 25–50% of **measured** RTO; sum over fragments; prefer SW replay |
| Reordering / fast-retx | out-of-order release of a multi-segment/split response | Low–med (only multi-segment) | RFC 5681 (dupthresh=3) | strict per-flow FIFO; whole-response units |
| Queue buildup / cwnd | held-frame buffering; bulk ACK release (ACK compression) | Negligible (<1 held frame) | RFC 3449; Zhang'91 | bounded held table; in-order paced release; hold ≪ poll interval |

---

## 4. Caveats and scope limits

- The **200 ms figure is a rig-specific consequence of the Linux floor on a sub-ms LAN, not
  a universal constant.** It must be measured on Vision (§2); a tuned `rto_min` invalidates
  it downward. This is the single most important caveat.
- All RTT/RTO reasoning assumes the observed steady-state (timestamps on, converged
  estimator). Cold-start (first exchange, RTO = 1 s) is *more* forgiving, not less.
- RFCs are IETF standards (marked `peer_reviewed=no` in the matrix in the academic sense,
  but they are authoritative normative specifications, not preprints).
- The outstation-RTO (clock #2) hazard is an **[INFER]** from TCP semantics applied to the
  in-network topology; it is not yet measured here. Worth an explicit capture test before any
  in-network hold is built.
- Pacing papers (Aggarwal'00, Carousel'17) target high-throughput bulk flows; their
  *mechanisms* (paced release, timing wheels) transfer, but their *motivations* (buffer
  overrun at line rate) do not directly apply to low-rate DNP3 — cite them for the
  technique, not for a throughput claim.

---

## PAPER_MATRIX_ROWS
RFC 6298 Computing TCP's Retransmission Timer | V. Paxson, M. Allman, H.K.J. Chu, M. Sargent | 2011 | IETF RFC (Standards Track, obsoletes RFC 2988) | 10.17487/RFC6298 | https://www.rfc-editor.org/rfc/rfc6298 | no | 4 | TCP | NA | NA | RTO estimator (Jacobson/Karels) | NA | NA | NA | NA | NA | Defines SRTT/RTTVAR/RTO with alpha=1/8 beta=1/4 K=4; min-RTO SHOULD round up to 1s; backoff RTO*2 on expiry; Karn's algo | Recommends 1s min RTO which Linux overrides to 200ms; standard not empirical | The normative source for the master's retransmit-timer budget that bounds our hold | high
RFC 1122 Requirements for Internet Hosts -- Communication Layers | R. Braden (Ed.) | 1989 | IETF RFC (Standards Track, STD 3) | 10.17487/RFC1122 | https://www.rfc-editor.org/rfc/rfc1122 | no | 4 | TCP | NA | NA | delayed ACK | NA | NA | NA | NA | NA | Delayed-ACK max 0.5s; ACK at least every 2nd full-sized segment; immediate ACK on out-of-order | Ceiling only; OS timers are tighter | Bounds the piggyback window that makes response-time the same observable as ACK-time | high
RFC 5681 TCP Congestion Control | M. Allman, V. Paxson, E. Blanton | 2009 | IETF RFC (Standards Track, obsoletes RFC 2581) | 10.17487/RFC5681 | https://www.rfc-editor.org/rfc/rfc5681 | no | 4 | TCP | NA | NA | fast retransmit/recovery; delayed ACK | NA | NA | NA | NA | NA | 3 duplicate ACKs (dupthresh) trigger fast retransmit; immediate dup-ACK on out-of-order; ACK within 500ms | Standard, not measurement | Defines the reordering->fast-retransmit failure mode we must avoid via FIFO | high
RFC 9293 Transmission Control Protocol (TCP) | W. Eddy (Ed.) | 2022 | IETF RFC (Internet Standard STD 7, obsoletes RFC 793 et al.) | 10.17487/RFC9293 | https://www.rfc-editor.org/rfc/rfc9293 | no | 4 | TCP | NA | NA | RTO (per RFC 6298); cumulative ACK/piggyback | NA | NA | NA | NA | NA | All established-state segments carry ACK info (piggyback); RTO MUST follow RFC 6298 incl. Karn | Consolidated spec; defers timer detail to RFC 6298 | Establishes that ACK and response are one wire event (piggyback) | high
RFC 7323 TCP Extensions for High Performance | D. Borman, B. Braden, V. Jacobson, R. Scheffenegger (Ed.) | 2014 | IETF RFC (Standards Track, obsoletes RFC 1323) | 10.17487/RFC7323 | https://www.rfc-editor.org/rfc/rfc7323 | no | 4 | TCP | NA | NA | Timestamps option / RTTM | NA | NA | NA | NA | NA | Timestamps measure RTT on virtually every segment via TSval/TSecr; must be sent every non-RST segment once negotiated | More RTT samples have limited effect on RTO (cites Allman99) | Explains the observed NOP-NOP-Timestamp sig and why the RTO estimator is well-converged (clamps to floor) | high
RFC 3449 TCP Performance Implications of Network Path Asymmetry | H. Balakrishnan, V.N. Padmanabhan, G. Fairhurst, M. Sooriyabandara | 2002 | IETF RFC (BCP 69) | 10.17487/RFC3449 | https://www.rfc-editor.org/rfc/rfc3449 | no | 4 | TCP (asymmetric paths) | NA | ACK congestion control / ACK filtering / decimation | ACK thinning | NA | NA | NA | NA | NA | Reducing ACK frequency causes sender bursting, slower cwnd growth (ACK-counted), weakened fast recovery; defines ACK compression | Targets bandwidth-asymmetric WAN, not LAN OT | Grounds the queue-buildup/cwnd side effects of delaying ACK-bearing segments | high
Congestion avoidance and control | V. Jacobson | 1988 | ACM SIGCOMM '88 | 10.1145/52324.52356 | https://doi.org/10.1145/52324.52356 | yes | 2 | TCP | NA | NA | RTT-variance-based RTO estimation | NA | software | NA | NA | NA | NA | Introduced the mean+variance RTT estimator and exponential backoff that RFC 6298 standardizes | 1988 Internet conditions; superseded in detail by RFC 6298 | Seminal origin of the RTO math that sets our delay ceiling | high
Understanding the performance of TCP pacing | A. Aggarwal, S. Savage, T. Anderson | 2000 | IEEE INFOCOM 2000 | 10.1109/INFCOM.2000.832483 | https://doi.org/10.1109/INFCOM.2000.832483 | yes | 2 | TCP | NA | traffic pacing | pacing (spread segments over RTT) | software | NA | simulation | NA | throughput/latency | Pacing smooths bursts and can help or hurt throughput vs bursty TCP depending on regime | Simulation-based; bulk-flow focus not OT-rate | Technique reference for principled paced release; caution that pacing has regime-dependent effects | med
Observations on the dynamics of a congestion control algorithm: the effects of two-way traffic | L. Zhang, S. Shenker, D.D. Clark | 1991 | ACM SIGCOMM '91 | 10.1145/115992.116006 | https://doi.org/10.1145/115992.116006 | yes | 3 | TCP | NA | NA | NA (characterization) | NA | simulation | NA | simulation | NA | NA | Characterizes ACK compression: ACKs queued behind data bursts compress in time, causing data micro-bursts | Simulation; early-90s TCP | Explains the micro-burst-on-release risk when we hold then emit ACK-bearing frames | med
Carousel: Scalable Traffic Shaping at End Hosts | A. Saeed, N. Dukkipati, V. Valancius, V.T. Lam, C. Contavalli, A. Vahdat | 2017 | ACM SIGCOMM '17 | 10.1145/3098822.3098852 | https://doi.org/10.1145/3098822.3098852 | yes | 2 | TCP/general | NA | traffic shaping / pacing | timestamp-based single-queue release (timing wheel) | software | end-host kernel/NIC | testbed (production cloud) | NA | CPU/memory overhead, rate accuracy | Single-queue time-indexed shaper releases packets by timestamp; scales to 10k+ flows, 2 orders less memory | Datacenter video traffic scale; not OT | Directly the software pattern for the replay server's per-response 'release by deadline' scheduler | high
Linux kernel include/net/tcp.h (RTO/DELACK constants) | Linux kernel contributors | 2026 | Linux kernel source (mainline) | NA | https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/tcp.h | no | 4 | TCP | NA | NA | RTO/delayed-ACK timer floors | NA | software | Linux stack | NA | NA | NA | TCP_RTO_MIN=HZ/5=200ms; TCP_RTO_MAX=120s; TCP_TIMEOUT_INIT=1s; TCP_DELACK_MAX=HZ/5=200ms; TCP_DELACK_MIN=40ms | HZ-dependent; per-route rto_min can override | The operative 200ms floor that binds our hold budget on this rig | high
Linux kernel ip-sysctl documentation (tcp_retries2, thin streams) | Linux kernel contributors | 2026 | Linux kernel Documentation/networking/ip-sysctl | NA | https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt | no | 4 | TCP | NA | NA | retransmit retry limits; thin-stream timeouts | NA | software | Linux stack | NA | NA | NA | tcp_retries2 default 15 => ~924.6s to kill a live connection; tcp_thin_linear_timeouts for <4 pkts in flight | Documentation; version-dependent | Bounds the escalation horizon after RTO and notes thin-stream (DNP3-like) handling | high
Linux ip-route(8) manual (rto_min route option) | iproute2 / man-pages contributors | 2024 | Linux man-pages (man7.org) | NA | https://man7.org/linux/man-pages/man8/ip-route.8.html | no | 4 | TCP | NA | NA | per-route RTO floor tuning | NA | software | Linux stack | NA | NA | NA | rto_min sets the minimum TCP RTO per destination route (settable in ms via ip route) | Man-page; behavior version-dependent | The exact knob to check on Vision to confirm the effective RTO floor is not tuned below 200ms | high

## BIBTEX
@misc{paxson2011computing,
  author       = {Vern Paxson and Mark Allman and H. K. Jerry Chu and Matt Sargent},
  title        = {{Computing TCP's Retransmission Timer}},
  howpublished = {RFC 6298, IETF, Standards Track},
  year         = {2011},
  month        = jun,
  doi          = {10.17487/RFC6298},
  note         = {Obsoletes RFC 2988},
  url          = {https://www.rfc-editor.org/rfc/rfc6298}
}

@misc{braden1122requirements,
  author       = {Robert Braden},
  title        = {{Requirements for Internet Hosts -- Communication Layers}},
  howpublished = {RFC 1122, IETF, STD 3},
  year         = {1989},
  month        = oct,
  doi          = {10.17487/RFC1122},
  url          = {https://www.rfc-editor.org/rfc/rfc1122}
}

@misc{allman5681tcp,
  author       = {Mark Allman and Vern Paxson and Ethan Blanton},
  title        = {{TCP Congestion Control}},
  howpublished = {RFC 5681, IETF, Standards Track},
  year         = {2009},
  month        = sep,
  doi          = {10.17487/RFC5681},
  note         = {Obsoletes RFC 2581},
  url          = {https://www.rfc-editor.org/rfc/rfc5681}
}

@misc{eddy9293transmission,
  author       = {Wesley M. Eddy},
  title        = {{Transmission Control Protocol (TCP)}},
  howpublished = {RFC 9293, IETF, Internet Standard STD 7},
  year         = {2022},
  month        = aug,
  doi          = {10.17487/RFC9293},
  note         = {Obsoletes RFC 793, 879, 2873, 6093, 6429, 6528, 6691},
  url          = {https://www.rfc-editor.org/rfc/rfc9293}
}

@misc{borman7323tcp,
  author       = {David Borman and Bob Braden and Van Jacobson and Richard Scheffenegger},
  title        = {{TCP Extensions for High Performance}},
  howpublished = {RFC 7323, IETF, Standards Track},
  year         = {2014},
  month        = sep,
  doi          = {10.17487/RFC7323},
  note         = {Obsoletes RFC 1323},
  url          = {https://www.rfc-editor.org/rfc/rfc7323}
}

@misc{balakrishnan3449tcp,
  author       = {Hari Balakrishnan and Venkata N. Padmanabhan and Godred Fairhurst and Mahesh Sooriyabandara},
  title        = {{TCP Performance Implications of Network Path Asymmetry}},
  howpublished = {RFC 3449, IETF, BCP 69},
  year         = {2002},
  month        = dec,
  doi          = {10.17487/RFC3449},
  url          = {https://www.rfc-editor.org/rfc/rfc3449}
}

@inproceedings{jacobson1988congestion,
  author    = {Van Jacobson},
  title      = {Congestion avoidance and control},
  booktitle = {Symposium Proceedings on Communications Architectures and Protocols (SIGCOMM '88)},
  year      = {1988},
  pages     = {314--329},
  publisher = {ACM},
  doi       = {10.1145/52324.52356},
  url       = {https://doi.org/10.1145/52324.52356}
}

@inproceedings{aggarwal2000understanding,
  author    = {Amit Aggarwal and Stefan Savage and Thomas Anderson},
  title     = {Understanding the performance of {TCP} pacing},
  booktitle = {Proceedings IEEE INFOCOM 2000},
  year      = {2000},
  pages     = {1157--1165},
  publisher = {IEEE},
  doi       = {10.1109/INFCOM.2000.832483},
  url       = {https://doi.org/10.1109/INFCOM.2000.832483}
}

@inproceedings{zhang1991observations,
  author    = {Lixia Zhang and Scott Shenker and David D. Clark},
  title     = {Observations on the dynamics of a congestion control algorithm: the effects of two-way traffic},
  booktitle = {Proceedings of the Conference on Communications Architecture \& Protocols (SIGCOMM '91)},
  year      = {1991},
  pages     = {133--147},
  publisher = {ACM},
  doi       = {10.1145/115992.116006},
  url       = {https://doi.org/10.1145/115992.116006}
}

@inproceedings{saeed2017carousel,
  author    = {Ahmed Saeed and Nandita Dukkipati and Vytautas Valancius and Vinh The Lam and Carlo Contavalli and Amin Vahdat},
  title     = {Carousel: Scalable Traffic Shaping at End Hosts},
  booktitle = {Proceedings of the Conference of the ACM Special Interest Group on Data Communication (SIGCOMM '17)},
  year      = {2017},
  pages     = {404--417},
  publisher = {ACM},
  doi       = {10.1145/3098822.3098852},
  url       = {https://doi.org/10.1145/3098822.3098852}
}

@misc{linuxtcph,
  author       = {{Linux kernel contributors}},
  title        = {{include/net/tcp.h --- TCP\_RTO\_MIN, TCP\_RTO\_MAX, TCP\_TIMEOUT\_INIT, TCP\_DELACK\_MAX/MIN}},
  howpublished = {Linux kernel source, mainline},
  year         = {2026},
  note         = {TCP\_RTO\_MIN = HZ/5 = 200 ms; TCP\_RTO\_MAX = 120 s; TCP\_TIMEOUT\_INIT = 1 s; TCP\_DELACK\_MAX = 200 ms; TCP\_DELACK\_MIN = 40 ms},
  url          = {https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/tcp.h}
}

@misc{linuxipsysctl,
  author       = {{Linux kernel contributors}},
  title        = {{Documentation/networking/ip-sysctl --- tcp\_retries2, tcp\_thin\_linear\_timeouts}},
  howpublished = {Linux kernel Documentation},
  year         = {2026},
  note         = {tcp\_retries2 default 15 (~924.6 s to close a live connection)},
  url          = {https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt}
}

@misc{iprouteman,
  author       = {{iproute2 and Linux man-pages contributors}},
  title        = {{ip-route(8) --- rto\_min route attribute}},
  howpublished = {Linux man-pages, man7.org},
  year         = {2024},
  note         = {rto\_min sets the minimum TCP RTO per destination route},
  url          = {https://man7.org/linux/man-pages/man8/ip-route.8.html}
}
