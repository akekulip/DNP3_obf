# Agent B — TCP Transport & Packetization: Does the Split Survive the Wire, Is It a New Fingerprint, and What Are the RTO/Pacing Budgets?

_Scope: the transport-layer (L4/NIC) fate of application-layer CRC-boundary splitting for the
split/pad/timing policy study. Builds on the prior TCP report
(`research/ack_timing_normalization/agent_reports/agent_B_tcp_transport.md`) — that report settled
the RTO estimator, delayed-ACK window, and the three RQ5 failure modes for a **monolithic hold**;
this report extends it to **split + pacing** (many small segments), adds the **NIC-offload /
capture-vantage** analysis, **segmentation-as-fingerprint** (RQ2), and **RTO measurement on Hulk**
(not only Vision). Evidence labels per GROUNDING §17: **[M]** measured on this rig/host · **[S]**
standard (RFC) · **[V]** vendor/OS doc (Linux kernel docs, man7, ethtool) · **[P]** peer-reviewed
paper · **[I]** engineering inference · **[H]** hypothesis. RFCs 6298/1122/5681/9293/7323/3449 and
the Linux `tcp.h`/ip-sysctl/ip-route facts are already verified in the prior report — cited here by
result, not re-derived. New sources (RFC 896, `tcp(7)`, kernel segmentation-offloads doc) were
fetched and verified this session (see NEW_PAPER_MATRIX_ROWS / NEW_BIBTEX)._

---

## 0. Bottom line (three deliverables, up front)

1. **Splitting survives to the observer that matters, because of pacing — not TCP_NODELAY alone.**
   TCP is a byte stream and preserves **no** write boundaries [S]. What actually keeps the 141
   chunks as 141 separate wire segments is the **10 ms inter-chunk delay**: it drains the send
   buffer between writes, defeating both the TX-side coalescer (`tcp_autocorking=1` [M,gambit],
   Nagle is already off via `TCP_NODELAY` [M/CLAUDE.md]) and the RX-side coalescer (GRO, which only
   merges segments arriving in the same NAPI poll). The measured `141 chunks → 145 O→M data
   segments, 0 retransmits` [M/prior] is the fingerprint of a **paced** split; drop the pacing to
   ~0 ms and `tcp_autocorking` + GRO would start merging chunks back toward MSS-sized segments [I].
2. **Splitting does not remove a fingerprint — it swaps one for a louder one.** It converts the
   native shape (a large READ = 49 link frames / 20 TCP segments [M/prior]) into ~141 tiny (≤18 B)
   segments — a signature no unmodified DNP3 device produces, and it **amplifies the return path**
   too (≈70 delayed-ACKs instead of ≈10). A **fixed** split pattern (always bpc=1, always 10 ms) is
   itself a stable, learnable pattern (RQ2). Split reshapes Axis-1 segmentation but **cannot hide
   total bytes** [M/prior] — consistent with GROUNDING.
3. **Measure the effective RTO on BOTH endpoints; the split path stresses a different clock than a
   hold does.** A monolithic hold stresses **Vision's** request-RTO (prior report). A **split**
   ACKs the request on chunk 1, then stresses **Hulk's** RTO on the *tail* segment (final chunk
   waiting for the master's delayed-ACK). The binding quantity for split+pace is **not** the sum of
   delays but the **maximum inter-ACK gap**, plus a **tail-ACK-wait < Hulk-RTO** guard. Procedures
   for both hosts and a corrected four-constraint budget are in §3.

Plain language: the tiny split packets do reach a mid-network sniffer intact, but only because we
space them out; that same spacing is what keeps TCP from silently gluing them back together and
what keeps both machines from panicking and resending. The catch is that 141 tiny packets are just
a different, more obvious tell than a few big ones.

---

## 1. Does application-layer splitting survive the wire? (offloads × vantage point)

### 1.1 TCP preserves no message boundaries — the whole question is "who coalesces?"
`split_server.py` issues one `send()` per chunk, but TCP is a pure byte stream: the receiver's
`recv()` boundaries, and the on-wire **segment** boundaries, need not match the sender's `send()`
boundaries at all [S, RFC 9293 §3.7 segmentation is at the stack's discretion]. So "does the split
survive" reduces to: **between the app write and the passive capture, does any layer merge adjacent
chunks, or split/aggregate them?** Four coalescers and two expanders are in play:

| Layer | Direction | Action | Governing fact |
|---|---|---|---|
| Nagle's algorithm | TX | holds a new small segment while a prior small segment is unacked | RFC 896: "inhibit the sending of new TCP segments … if any previously transmitted data … remains unacknowledged" [S]. **Disabled** here — split server sets `TCP_NODELAY` [M] ("segments are always sent as soon as possible, even if there is only a small amount of data", `tcp(7)` [V]). |
| `tcp_autocorking` | TX | coalesces consecutive small `write()`/`sendmsg()` even with NODELAY, if data is still queued | `tcp(7)`/ip-sysctl: "the kernel tries to coalesce small writes … as much as possible, in order to decrease the total number of sent packets" [V]. **`=1` (on) by default** [M,gambit]. |
| GSO/TSO | TX | **expands** one >MSS buffer into MSS-sized wire segments (never merges) | kernel: GSO "breaks a packet across multiple buffers resized to match the MSS"; TSO does it in the NIC [V]. Inert for our ≤18 B chunks (nothing to expand). |
| GRO/LRO | RX | **merges** back-to-back same-flow segments into one super-segment before the stack/capture sees them | kernel: GRO is "the complement to GSO … any frame assembled by GRO should be segmented to create an identical sequence of frames using GSO" [V]. GRO **on**, LRO **off [fixed]** [M,gambit]. |
| Delayed ACK | RX→TX | thins the ACK stream (≈1 ACK / 2 segments) | RFC 1122 §4.2.3.2, RFC 5681 [S] (prior report). Amplification analysis in §2.2. |

**Why the paced split survives all of them [I, grounded]:** each chunk is (a) ≤ MSS, so GSO/TSO
never fires; (b) written with `TCP_NODELAY`, so Nagle never holds it; (c) followed by a 10 ms gap
≫ RTT (sub-ms LAN), so by the next write the send buffer is empty and `tcp_autocorking` has nothing
to coalesce with — each write becomes exactly one segment; (d) `TCP_NODELAY` sets **PSH** on each
small segment, and paced 10 ms apart the chunks arrive in **separate** NAPI polls, so GRO cannot
merge them (GRO merges only within a poll/flush window, and PSH forces a flush). Net: `141 chunks →
145 segments` on a clean connection [M/prior], ≈1:1. The 4 extra segments are the connect/
disable-unsol/integrity setup and the CONFIRM-triggered continuation, not chunk fragmentation.

**The fragility this exposes [I]:** the survival is a property of the **pacing**, not of splitting
per se. At `--chunk-delay-ms 0`, writes arrive back-to-back; `tcp_autocorking` and (on RX) GRO can
merge them toward MSS-sized segments, so the wire count would fall well below 141 and vary run to
run. **Any future "aggressive, zero-delay" split is not guaranteed to survive as distinct wire
segments** — it must be re-measured, and if the goal is a specific segment count, pacing ≥ ~1 RTT
between the boundaries you want preserved is the mechanism that guarantees it.

### 1.2 Capture vantage point decides what a passive observer actually counts
The offloads make **segment count vantage-dependent**. Three vantages, three different answers:

| Vantage | Tap point vs offloads | What it sees for our paced split | What it sees for the *native* large READ |
|---|---|---|---|
| **Sender host** (tcpdump on Hulk / split server) | AF_PACKET TX hook sits **above** hardware TSO segmentation | ~accurate (≤18 B chunks, no GSO to expand) → ~141 [I] | can **under-count**: a 2407 B / 12 kB response handed to the NIC as GSO super-frames shows as a few >MSS "segments" that never existed on the wire [I,V] |
| **Mid-path SPAN/tap** (switch mirror or inline tap) | on the physical link — **after** TX segmentation, **before** RX GRO | **ground truth**: the real ~141 small frames [I] | ground truth: 20 MSS-sized (1448 B) segments [M/prior] |
| **Receiver host** (tcpdump on Vision / master) | AF_PACKET RX hook sits **after** GRO merges | with pacing: ~accurate (PSH + separate polls defeat GRO) → ~141; **without** pacing GRO **over-merges** → far fewer [I,V] | GRO can merge the 20 wire segments into a handful of super-segments before capture [I,V] |

**The fingerprinting-relevant observer is the mid-path tap** — a passive on-path adversary (SPAN
port, optical tap, upstream router mirror). That vantage sees the **true** fine split with no offload
distortion in either direction. So for the threat model in GROUNDING, **splitting is fully visible
to the attacker**: the mid-path tap sees 141 tiny frames, and any claim that "splitting is hidden by
NIC offload" would be false for this observer [I]. Offload distortion only muddies **endpoint**
captures — which matters for *our own measurement hygiene* (see §3 caveat), not for the attacker.

Corollary — checksum offload is a capture artifact, not a wire fact: TX-checksum offload is on
[M,gambit], so a **sender-host** capture shows "checksum incorrect" placeholders on outgoing
segments (checksum filled by the NIC afterward) [I,V]. This never reaches the wire and never affects
the attacker; it only means **do not compute wire facts from a sender-side capture** — use the tap.

### 1.3 MSS non-alignment (why splitting was even structurally possible)
Native DNP3 link frames (292 B max) do not align with the 1448 B TCP MSS [M/prior]: the 12,204 B
READ = 49 link frames but only 20 MSS segments, so multiple DNP3 frames already share a segment.
Splitting works **against** this: it forces ≤18 B application chunks that are far below MSS, so each
becomes its own sub-MSS segment. This is why the split is so conspicuous — it drives segment size
from ~1448 B (MSS-packed) down to ≤18 B, the opposite end of the size axis.

Plain language: whether a snooper counts 141 packets or a handful depends on *where* they plug in.
On the actual cable in the middle they see all 141 — the NIC tricks that hide or merge packets only
happen inside the two end machines. So splitting is not hidden from a real network tap.

---

## 2. Packet-count / segmentation as a fingerprint (RQ2)

### 2.1 Split trades a size fingerprint for a segmentation fingerprint
Splitting is byte-preserving [M/prior], so it cannot touch total-bytes leakage — the size channel
(14.6 B/CROB, R²=0.9999; 5.7 B/analog-point) survives summation of the chunks [M]. What it *changes*
is Axis-1 **structure**: `#packets`, `TCP segment count`, `segment-size distribution`. But the new
structure is not neutral — it is **itself distinctive**:

- **Absolute anomaly.** No unmodified DNP3 outstation emits ~141 consecutive ≤18 B segments for one
  response; native responses are a handful of ≤292 B frames packed into ≤20 MSS segments [M/prior].
  A classifier keyed on "count of sub-64 B TCP segments per transaction" separates split from
  baseline trivially [I]. Split lowers the *size* discriminability of the payload while **raising**
  the *segmentation* discriminability of the device — a fingerprint transfer, not a removal [I].
- **The split parameters leak back.** Chunk count ≈ ⌈link-frames × 292/chunk-size⌉ and total bytes
  are both recoverable from the capture, so an observer can often **invert** the split to estimate
  the original response size, i.e., splitting adds observables without deleting the one it was meant
  to obscure [I]. This is the RQ2 core caution.

### 2.2 The return path amplifies too (ACK-count / ACK-timing as a second channel)
Each data segment the master receives feeds delayed-ACK: RFC 1122/5681 → ≈1 ACK per 2 full segments,
forced within the delayed-ACK window [S]. So 141 O→M data segments elicit on the order of **70
master→outstation ACKs**, versus ≈10 for the native 20-segment response [I]. Consequences:

- **ACK count and ACK cadence become a mirror fingerprint** of the split — an observer who ignores
  the O→M direction can read the split off the M→O ACK burst [I].
- **ACK compression on release [S/P].** A tight cluster of data segments produces a tight cluster of
  ACKs; RFC 3449 (BCP 69) documents that thinned/bursty ACKs perturb the sender, and Zhang-Shenker-
  Clark [P] characterize ACK compression. On this low-rate rig cwnd effects are inert (prior report
  §3.3), but the **ACK micro-burst pattern is still an observable** the attacker can match on.
- **Piggyback vs pure ACK.** The master's ACKs during the burst are **pure ACKs** (master has no
  data to send mid-response), so they carry no payload and are pure-timing/count signal; only the
  next request piggybacks (prior report §1.4). The pure-ACK burst is therefore a clean,
  payload-free timing channel that split creates on the return path [I].

### 2.3 Fixed split patterns are self-defeating; randomization is RTO-bounded
A constant policy (bpc=1, 10 ms, same order every transaction) yields an **identical** segment-count
and inter-segment-gap vector every time — a stable template that a passive learner locks onto after
a few transactions [I,H]. Mitigations and their transport limits:

- Randomize `blocks_per_chunk` and inter-chunk gap per transaction → breaks the constant template,
  but every gap still consumes the pacing budget (§3) and the **count** still reveals ≥ the native
  frame count. Randomization reduces pattern stability, **not** the absolute segmentation anomaly [I].
- To defeat the "sub-64 B segment count" discriminator you would need to *also* pad segments toward
  MSS or inject cover segments — but padding is a proven dead end for these DNP3 payloads (GROUNDING
  §5, negative result), so on the current byte-preserving phase the segmentation anomaly is a
  **residual** [I], parallel to the residual size leak.

### 2.4 TCP facts that constrain any split/reorder scheme
- **Reassembly is transparent** — the master's stack reassembles the byte stream regardless of
  segmentation; DNP3 sees identical bytes (`b"".join(chunks)==original`, 800 measurements, CONFIRM,
  0 resets [M/prior]). Splitting is L4-safe by construction as long as **order** is preserved.
- **Reordering → spurious fast retransmit.** dupthresh = 3: three duplicate ACKs from out-of-order
  arrival trigger the sender's fast retransmit (RFC 5681 [S]). A split that releases chunks out of
  order (or interleaves flows) can trip this with **no** RTO overshoot — the loud tell for free.
  **Invariant: strict per-flow FIFO** — never emit chunk N+1 before N (prior report §3.2). The split
  server is single-response/in-order, so this holds today; any parallelized/rate-shaped future
  version must preserve it.
- **Fragmentation (IP) is not segmentation.** All segments are ≤ MSS < PMTU, so no IP fragmentation
  occurs — the split lives entirely at the TCP-segment layer, which is what the attacker counts [I].

Plain language: cutting one big answer into 141 slivers doesn't erase the clue about how big the
answer was — you can add the slivers back up — and it prints a brand-new, very unusual "lots of tiny
packets" signature in **both** directions (the replies get chopped up too, and so do the
acknowledgements coming back). Always using the exact same slicing makes it even easier to spot.

---

## 3. RTO & budgets (RQ7): measure both hosts, and the corrected split-pacing budget

### 3.1 A split stresses a different clock than a hold — so measure BOTH endpoints
The prior report established the **monolithic-hold** budget: holding the whole response leaves the
master's **request** unacked, so `hold < Vision's request-RTO` [S/prior]. A **split** behaves
differently because **chunk 1 carries the piggybacked ACK of the request** — the master's request is
acknowledged in ~1 ms, so Vision's request-RTO is disarmed almost immediately and is **not** the
binding clock during the burst [I]. What binds instead:

- **Hulk's RTO on each sent chunk.** The split server (on Hulk, in the outstation's place) has 141
  segments outstanding-then-acked in sequence. Each is unacked until the master ACKs. As long as
  chunks keep arriving, the master's delayed-ACK keeps emitting ACKs (≈ every 2nd segment), which
  **reset Hulk's RTO continuously** — so a long burst does **not** accumulate toward RTO (see §3.4).
- **The tail segment.** After the *last* chunk there is no follow-on segment to trigger the master's
  "every-2nd-segment" ACK, so the final chunk can sit under the master's **delayed-ACK timer** (up to
  `TCP_DELACK_MAX` = 200 ms [V]) before being ACKed. If that wait exceeds **Hulk's** effective RTO,
  Hulk **retransmits the tail** — a spurious duplicate, the loud tell. This is the classic
  thin-stream tail pathology, and it is why **Hulk's RTO must be measured**, not just Vision's.

### 3.2 Vision (master) — request-RTO (still needed for the hold/timing arm)
As in the prior report §2 (unchanged; summarized):
```bash
# On Vision (10.10.54.19):
ip route get 10.10.54.158        # trailing "rto_min <ms>"? absent ⇒ compile default 200 ms
sysctl net.ipv4.tcp_retries2     # escalation horizon (default 15 ⇒ ~924.6 s to socket teardown)
```
Effective value from capture: induce a **hold** overshooting the floor, measure `t(first request
retransmit) − t(request)`; confirm ×2 backoff (RFC 6298 rule 5.5 [S]). This binds the **timing-
normalization / monolithic-hold** arm of the combined policy.

### 3.3 Hulk (outstation / split server) — response tail-RTO (NEW, split-specific)
The split server runs on Hulk, so Hulk is the **sender** whose RTO the split path stresses:
```bash
# On Hulk (10.10.54.158):
ip route get 10.10.54.19         # per-route rto_min toward the master, if any
sysctl net.ipv4.tcp_retries2 net.ipv4.tcp_retries1
sysctl net.ipv4.tcp_thin_linear_timeouts   # thin-stream tail handling; =0 (off) on gambit [M] — check Hulk
cat /sys/class/net/<dev>/queues/rx-*/... ; ethtool -k <dev> | grep -Ei 'receive-offload'  # GRO state
```
**Effective tail-RTO from capture (the number that actually binds split):**
1. tcpdump on Hulk (or the mid-path tap) for `tcp port 20000`.
2. Run a real split response so the **final** chunk is emitted with no follow-on segment.
3. Find the last data chunk, then any **retransmission of that same sequence number** before the
   master's ACK arrives. If present, `tail-RTO = t(retransmit) − t(last chunk)`. If **absent** across
   many runs, the master is ACKing the tail (PSH-forced quick-ACK) inside Hulk's RTO — the safe case;
   record the observed `t(master tail ACK) − t(last chunk)` as the **tail-ACK-wait** headroom.
4. Cross-check the delayed-ACK behavior directly: on the master, the tail ACK should arrive within
   `TCP_DELACK_MIN`≈40 ms (quick-ACK, PSH-triggered) rather than the 200 ms max — confirm which,
   because the 200 ms-delayed-ACK vs 200 ms-RTO race is the only realistic tail-retransmit trigger
   on this LAN [I].

**Why both floor near 200 ms but must still be measured [I/V]:** `TCP_RTO_MIN` and `TCP_DELACK_MAX`
are both `HZ/5` and evaluate to **200 ms independent of HZ** (gambit is `CONFIG_HZ=250` [M], not
1000, yet the ms values are unchanged) — so the HZ difference does not move the floor, but a per-route
`rto_min` or a tuned `tcp_delack`/quickack **would**. gambit shows **no** per-route `rto_min` toward
either rig IP [M]; confirm the same on Vision **and** Hulk before trusting 200 ms.

### 3.4 Corrected budget model for split + pacing (the key refinement over the prior report)
For a **hold**, the constraint is on the *sum* (hold < RTO). For **split + pace it is NOT the sum** —
`141 × 10 ms = 1410 ms` far exceeds 200 ms yet produced **0 retransmits** [M/prior], because RTO fires
only on an inter-ACK **gap**, and ACKs flow throughout the burst. The binding quantities are:

| # | Constraint | Bound | Margin at current defaults |
|---|---|---|---|
| C1 | **First-chunk latency** (request must be ACKed before Vision's request-RTO) | `< Vision RTO` (~200 ms) | chunk 1 in ~1 ms → ~200× [I] |
| C2 | **Max inter-ACK gap** = (inter-chunk delay × delayed-ACK stretch) + jitter — keep Hulk's RTO reset | `< Hulk RTO` ⇒ inter-chunk delay `< Hulk_RTO / 2` | 10 ms vs ~100 ms bound → ~10× [I] |
| C3 | **Tail-ACK-wait** (final chunk's delayed-ACK wait on the master) | `< Hulk RTO` | PSH-forced quick-ACK (~40 ms) vs ~200 ms RTO → OK **if** master quick-ACKs; **measure** (§3.3) [I] |
| C4 | **Total transaction duration** = Σ inter-chunk delays + processing | **not RTO-bounded**; bounded by timing-normalization target **and** `< poll interval` (≥1 s) and `≪` DNP3 confirm timer (5 s) | 1410 ms **already violates** a ≥1 s poll spacing and is a ~1000× timing anomaly vs ~1 ms native [I] |

**Recommended operating budgets (as fractions of the *measured* min-RTO), for the combined policy:**
- Per-chunk hold (inter-chunk gap): **≤ 10–25 % of min(Vision,Hulk) RTO** (C2). At a measured 200 ms
  floor that is **≤ 20–50 ms**; the current 10 ms sits comfortably inside.
- Tail guard (C3): ensure the master quick-ACKs the final chunk — rely on the PSH bit the split
  already sets (`TCP_NODELAY`), and keep `tail-ACK-wait ≤ 50 % of Hulk RTO`. If Hulk sets
  `tcp_thin_linear_timeouts=1`, tail retransmits become linear (not ×2 backoff) and *more* frequent
  for <4-packet-in-flight streams — check it (off on gambit [M]).
- Per-transaction total added latency (C4): governed by the **timing-normalization** arm, not RTO —
  cap the whole transaction well under the poll interval so transactions never overlap, and inside
  the chosen normalization target class. **This is the real ceiling on how many chunks × how much
  pacing you can afford** — not the RTO. The 141-chunk × 10 ms configuration is transport-safe but
  timing-loud; a combined policy must trade chunk count against total duration.
- Reordering/queue limits (unchanged from prior report §3.2–3.3): strict per-flow FIFO; bounded
  held-frame table (64–256 entries, 1–2 orders of margin); in-order paced release. Occupancy stays
  <1 held response per outstation while hold ≪ poll interval [I/prior].

Plain language: you can dribble out many small packets over more than a second without either
machine resending anything, because acknowledgements keep flowing and reset the "did it get lost?"
timers — so the limit is **not** "total delay < 200 ms." The two real limits are (a) don't let any
single gap between acknowledgements approach ~200 ms, especially for the very last packet, and (b)
don't stretch the whole exchange so long that it collides with the next poll or screams "abnormally
slow" — that second limit, not TCP, is what caps how aggressive the split can be.

---

## 4. Caveats and scope limits
- **The 200 ms floor is a rig consequence, not a constant.** It must be confirmed on **both** Vision
  and Hulk (§3.2–3.3); a per-route `rto_min` or delayed-ACK tuning invalidates it. gambit reads are
  the **dev box**, illustrative only — the master is Vision, the split server runs on **Hulk**.
- **Split-survival depends on pacing.** The 141→145 result is a **paced** property; a zero-delay
  "aggressive" split is not guaranteed to keep 141 distinct wire segments (`tcp_autocorking`+GRO)
  [I]. Any future aggressive-split claim needs a fresh mid-path capture.
- **Vantage matters for our own measurements too.** Segment/ACK counts taken on an **endpoint** can
  be distorted by GSO (TX under-count) or GRO (RX over-merge); take the authoritative counts from a
  **mid-path SPAN/tap**, and treat sender-side TX checksums as offload placeholders [I,V].
- **The tail-RTO hazard (C3) is [I], not yet measured.** It hinges on whether the master quick-ACKs
  the PSH-marked final chunk inside Hulk's RTO — worth one explicit capture (§3.3) before trusting
  any low-pacing configuration.
- RFCs are normative specs (`peer_reviewed=no` in the matrix sense) but authoritative. New rows below
  are Nagle (RFC 896), `tcp(7)`, and the kernel segmentation-offloads doc — the three sources this
  report adds beyond the prior TCP report's matrix.

---

## NEW_PAPER_MATRIX_ROWS
RFC 896 Congestion Control in IP/TCP Internetworks (Nagle's algorithm) | J. Nagle | 1984 | IETF RFC (Historic/foundational) | 10.17487/RFC0896 | https://www.rfc-editor.org/rfc/rfc896 | no | 4 | TCP | many-small-segments coalescing | NA | NA | NA | passive on-path | Nagle small-segment avoidance (basis for TCP_NODELAY) | software | Linux/BSD stacks | NA | NA | NA | Inhibits new small segment while prior small data unacked; TCP_NODELAY disables it | Historic RFC; per-implementation details vary | Explains why TCP_NODELAY is required for split boundaries to leave the sender as distinct segments | high
Linux tcp(7) manual (TCP_NODELAY, TCP_CORK, TCP_MAXSEG, tcp_autocorking) | Linux man-pages contributors | 2024 | Linux man-pages (man7.org) | NA | https://man7.org/linux/man-pages/man7/tcp.7.html | no | 4 | TCP | small-write coalescing / segmentation control | NA | NA | NA | passive on-path | TCP_NODELAY / TCP_CORK / autocorking socket & sysctl controls | software | Linux stack | NA | NA | NA | TCP_NODELAY sends small segments immediately; autocorking coalesces consecutive small writes even with NODELAY; TCP_CORK holds partial frames | Man-page; version-dependent | The OS knobs that decide whether split chunks survive as separate segments (NODELAY on, autocorking defeated only by pacing) | high
Linux kernel networking segmentation-offloads documentation (TSO/GSO/GRO/LRO) | Linux kernel contributors | 2024 | Linux kernel Documentation/networking/segmentation-offloads | NA | https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html | no | 4 | TCP/NIC | segment aggregation vs split; capture-vantage distortion | NA | NA | NA | passive on-path (endpoint vs tap) | GSO/TSO expand >MSS buffers; GRO/LRO merge received segments | hardware+software | Linux stack + NIC | NA | NA | NA | GSO breaks a packet into MSS-sized buffers; GRO is the inverse, reassembling frames before the stack sees them; LRO the hardware analogue | Doc; NIC/driver-dependent; LRO not detailed | Grounds why sender-side (GSO) and receiver-side (GRO) captures distort segment counts and why a mid-path tap is ground truth | high

## NEW_BIBTEX
@misc{nagle896congestion,
  author       = {John Nagle},
  title        = {{Congestion Control in IP/TCP Internetworks}},
  howpublished = {RFC 896, IETF},
  year         = {1984},
  month        = jan,
  doi          = {10.17487/RFC0896},
  note         = {Nagle's small-packet avoidance algorithm; basis for TCP\_NODELAY},
  url          = {https://www.rfc-editor.org/rfc/rfc896}
}

@misc{linuxtcp7,
  author       = {{Linux man-pages contributors}},
  title        = {{tcp(7) --- TCP\_NODELAY, TCP\_CORK, TCP\_MAXSEG, tcp\_autocorking}},
  howpublished = {Linux man-pages, man7.org},
  year         = {2024},
  note         = {TCP\_NODELAY disables Nagle; tcp\_autocorking coalesces consecutive small writes even with NODELAY},
  url          = {https://man7.org/linux/man-pages/man7/tcp.7.html}
}

@misc{linuxsegoffloads,
  author       = {{Linux kernel contributors}},
  title        = {{Segmentation Offloads --- TSO, GSO, GRO, LRO}},
  howpublished = {Linux kernel Documentation/networking/segmentation-offloads},
  year         = {2024},
  note         = {GSO breaks packets into MSS-sized buffers; GRO is the inverse, merging received segments before the stack/capture},
  url          = {https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html}
}
