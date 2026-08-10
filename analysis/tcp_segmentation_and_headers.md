# TCP segmentation and header normalization on one Tofino, unchanged endpoints

> **Reading note (documentation correction, `CORRECTION_LOG.md` §"Second correction").** Preserved as the
> analysis record; read with these corrections: (a) the size/count "needs a proxy" finding is the
> **strongest no-go candidate**, established as absence in the frozen implementation and in the
> constructions tried, **not** a proof that no non-proxy construction exists; (b) the endpoint-stamped
> TCP-header conclusion is **withdrawn as an impossibility** — the fields are an **unresolved** axis, and
> the concrete counterexamples (handshake option suppression during SYN/SYN-ACK, canonical NOP/EOL layout
> and public data offset, per-flow TSval and ISN translation with checksum correction, analyzed for
> retransmission/reuse/wraparound/PAWS/RTTM) must be compiled and endpoint-safety-tested before any
> header no-go is asserted (`EXPERIMENT_PLAN.md` Experiments 1-3). Corrected conclusions are in
> `DECISION_MEMO.md`, `ARCHITECTURE_CANDIDATES.md`, and `THREAT_MODEL.md`.

**Author:** sdn-networks-expert (TCP + traffic-analysis workstream) · **Date:** 2026-08-10
**Scope:** offline analysis only. No silicon, no relay, no git. Source read-only from
`/home/philip/Projects/DNP3` (frozen). This file is the sole deliverable.
**Testbed under analysis:** `Master <-> Tofino-1 <-> Outstation`, one switch, no proxy/gateway/second
box in the path; standard unchanged plaintext DNP3/TCP endpoints; internal Tofino mechanisms
(pktgen, TM, multicast, mirror, recirculation, loopback) permitted; control plane configures at
startup and reads counters only.

**Question.** Can this one-switch testbed produce a bounded, request-synchronized, fixed visible
pattern `P_c = [(delta_i, S_i, d_i)]` for a public class `c`, on unchanged endpoints, without
encryption and without a decoding peer, with no pattern parameter depending on device identity,
true response size, response value/readiness, or natural ACK/response timing.

---

## 0. Verdicts (read these first)

**V1 — On-switch fixed-K segmentation is NOT correct-and-safe on an unchanged master.** *(inference,
from TNA architecture + TCP semantics + the measured pcap; the single blocker is stated once and
holds for every variant.)*

> **The blocker:** a Tofino-1 can rewrite *parsed* header fields and can *truncate a packet to a
> fixed prefix*, but it cannot (a) excise a variable interior byte range from opaque multi-KB TCP
> payload, nor (b) buffer and re-slice an application object that spans several arriving TCP
> segments. Correct TCP reassembly by an unchanged master requires that each emitted segment carry a
> **non-overlapping, contiguous slice** of the byte stream at the **exact sequence offset** for that
> slice. The only on-switch primitives that produce multiple frames from one — mirror/multicast +
> per-copy truncation — produce **nested prefixes** (all starting at the same payload byte), which is
> either a set of overlapping retransmissions (master keeps the first, drops the rest) or, if the
> seq is bumped per copy, a corrupted stream. Producing correct slices needs store-and-forward TCP
> reassembly, i.e. a proxy — which the hard constraint forbids.

**V2 — The fixed *visible* pattern additionally requires padding small responses up, and padding on
an unchanged master is unsafe for a second, independent reason.** *(inference + falsification
result.)* To make a 47-byte response and a 12,204-byte response present the *same* fixed multiset of
sizes, the small one must be inflated to the large fixed shape. Inflation means injecting synthetic
bytes into the single authoritative TCP byte stream. Those bytes (i) arrive at the unchanged
master's OpenDNP3 parser as application data and corrupt DNP3 framing unless they are themselves
valid CRC-carrying DNP3, and (ii) force a growing per-flow seq/ack translation the switch must
maintain in both directions. Sub-IP trailer padding — the one form that avoids the TCP stream — was
already **falsified upstream**: it leaves `ip.len` unchanged, so the observer reads the true length
anyway (`docs/project-memory/size-timing-coresidency-egress.md`; restated
`OBSERVABLE_TRANSCRIPT_SPEC.md:25-36`).

**V3 — The exact impossibility boundary (fields one switch cannot normalize without a proxy):**
`tcp.seq`, `tcp.ack` (and therefore the byte-count / response-size channel they carry);
`ip.len`/`tcp.len` as size observables (bound to the real on-wire byte count); the TCP timestamp
option `TSval`/`TSecr` (PAWS-bound clock); `tcp.data_offset` / TCP-option layout / window-scale
(SYN-negotiated); and the entire DNP3 application content (function code, transport/app sequence,
object headers/indices, per-block CRC-16/DNP). These are endpoint-stamped and/or correctness-load-
bearing; a stateless switch can only rewrite them into an *inconsistent* connection (→ RST) or must
become a TCP-terminating, content-fabricating proxy to normalize them.

**V4 — Labelability: native cover can never be made indistinguishable from real traffic on this
testbed without encryption.** *(inference, corroborated by `THREAT_MODEL.md:120-123` and
`OBSERVABLE_TRANSCRIPT_SPEC.md:120-123`.)* Real DNP3 rides a single authoritative TCP connection
whose `seq`/`ack` the switch cannot rewrite to public constants; injected cover therefore either
corrupts that connection or lives in a distinguishable separate sequence space, and in every case
the plaintext DNP3 content plus the endpoint-stamped TCP stack fields label each packet as real or
cover.

**Bottom line for the parent:** on this one-switch, unchanged-endpoint, no-encryption testbed, a
*byte-level* fixed-K/fixed-size transcript is not achievable correctly-and-safely. What is achievable
is a strict subset of **outer-header** normalization (TTL, ip.id, DSCP/ToS, IP flags, Ethernet, and —
with care at this data rate — the TCP window value), which closes one of the two device-fingerprint
fields (TTL) but not its partner (`data_offset`) and not the size, clock, or content channels.

---

## 1. What the reference implementation actually is, and why it does not port

**Verified fact.** The frozen byte-preserving splitter `dnp3_split_harness/split_server.py` is a
**TCP-terminating application proxy**, not a stateless rewriter. It calls
`socket()/bind()/listen()/accept()/recv()` (`split_server.py:44,515-521`), reassembles whole DNP3
frames out of the TCP stream via `class FrameReader` (`:194-252`, "TCP gives no message boundaries: a
single recv() may hold half a frame, one frame, or several"), splits on CRC-block boundaries with the
invariant `b"".join(chunks) == data` asserted before send (`DNP3CRCSplitter`, `:254-331`, assert at
`:317` and `:556`), then `sendall()`s the chunks and holds the connection open for the master's DNP3
CONFIRM (`:460-593`). It is the outstation's TCP peer.

**Inference.** Everything that makes the reference splitter byte-correct — cross-segment reassembly,
choosing its own emit boundaries, owning the seq space, waiting on CONFIRM — is exactly what a switch
in the forwarding path does **not** do and, on Tofino-1, **cannot** do. The existing "CRC-boundary
splitting preserves bytes without CRC recompute" result is therefore a **proxy** result. It is not
evidence that splitting is achievable on the switch; it is evidence that splitting *requires* a TCP
endpoint. This is the crux the parent needs: the correctness of CRC-boundary splitting and its
on-switch feasibility are two different claims, and only the first is established.

---

## 2. FAMILY 3 — Fixed-K segmentation: feasibility, correctness, safety

### 2.1 The DNP3/TCP structure the switch would have to respect

**Verified fact** (from `dnp3_split_harness/reports/baseline_segmentation.md` and my re-read of
`captures/baseline/large_read.pcap` this session):

- The 12,204-byte READ response is one Class-0 integrity poll on a 300-point DB. It leaves the
  outstation as **9 DNP3 application (transport) fragments**, carried in **49 DNP3 link frames**
  (46 × 292 B — the DNP3 link ceiling of 8 B header + 2 B header-CRC + 250 B user data + 16 B of
  per-16-byte-block CRCs — plus short tails), packed by the kernel into **20 TCP data segments** of
  sizes `[17,17,17,292,1448,596,72,292,1448,668,292,1448,668,292,1448,669,292,1448,669,111]`.
- The DNP3 link-frame boundary (292 B, per-16-byte-block CRC-16/DNP) and the TCP segment boundary
  (MSS 1448) **do not align**: a 292 B link frame routinely straddles a TCP segment, and one TCP
  segment carries several partial link frames (`baseline_segmentation.md:40-42`).
- The response occupies a **contiguous, monotonic** TCP sequence range: first-relative seq offsets
  `0,1,1,18,35,52,344,1792,2388,2460,2752,4200,4868,5160,6608,7276,7568,9016,9685,9977,11425,12094`,
  last segment 111 B → the response is one contiguous ~12,204-byte window in seq space (measured this
  session from the pcap). `ttl=64`; `data_offset ∈ {8,10}`; `window` sweeps 509…65160; flags
  `A/SA/PA`.
- The small READ is one application fragment, ≈292 B, 1–2 TCP segments
  (`baseline_segmentation.md:14-16`); the corpus response sizes are `{37,54,61,74,122,183}` bytes
  (`research/size_timing_coresidency/reports/leakage-measurements.md:293`), i.e. the common response
  is **~47 B**.

**Inference.** Two consequences for any on-switch fixed-K scheme:

1. Because the response is spread across **20 arrival segments** and the DNP3 and TCP boundaries do
   not align, reshaping it into a fixed count of fixed-size cells needs the switch to **reassemble
   the byte stream across packets and re-cut it** — a store-and-forward operation. Tofino-1 processes
   each packet independently at line rate and has no cross-packet payload buffer; only per-flow
   register state (bytes, not payloads) is retained. So the general case is a proxy operation.
2. A single `K` covering both endpoints of the distribution is set by `L_max`. With the 12,204 B READ
   in profile, `K ≥ ceil(12204 / cell)`; at the 292 B DNP3-frame cell that is ~42 cells, at the
   1448 B MSS cell ~9 cells. Forcing the ~47 B response to present that same `K` and the same size
   multiset means inflating 47 B to ~12 KB — a ~260× blow-up per poll. The leakage study measured the
   small-corpus zero-leak fixed-K cost at 287 % overhead and states explicitly that with a large READ
   in profile it "rises by roughly two orders of magnitude"
   (`leakage-measurements.md:537-542, 603-605`). **No single fixed K covers both the ~47 B response
   and the 12,204 B READ at tolerable overhead**, and the overhead is the *lesser* problem — the
   correctness problems below are fatal first.

### 2.2 Why mirror/multicast + per-copy truncation does not produce a correct stream

**Verified fact (TNA architecture).** Tofino-1 replication (multicast engine, or ingress/egress
mirror) copies a packet; a mirror session may **truncate to a configured length**, which keeps the
**first N bytes** of the packet (a prefix). The deparser emits parsed headers (which the MAU may
rewrite) followed by the unparsed residual verbatim. There is no primitive that keeps an interior
byte window `[a, b)` of opaque payload. (Standard TNA capability; corroborated by the resource
audit's own description of the replication path, `p4-resource-audit.md:417-423`.)

**Inference (the correctness argument, spelled out).** Suppose a response arrives as one TCP segment,
payload `P[0..L)`, sequence `s`. To split into cells of sizes `c_1..c_K` (Σ = L) the master must
receive, for cell `j`: header with `seq = s + Σ_{k<j} c_k`, carrying `P[Σ_{k<j} c_k .. Σ_{k≤j} c_k)`.

- Mirror/multicast + truncate gives copy `j` = `P[0 .. Σ_{k≤j} c_k)` — a **prefix**, always starting
  at `P[0]`. The K copies are **nested prefixes**, not a partition.
- If each copy keeps `seq = s`, the master's TCP sees K overlapping segments all beginning at `s`,
  treats them as retransmissions, **keeps the first (`P[0..c_1)`) and discards the rest** → the
  master never receives `P[c_1 .. L)`. Broken (data loss).
- If copy `j` is stamped `seq = s + Σ_{k<j} c_k` but still carries the prefix `P[0 .. Σ_{k≤j} c_k)`,
  then the bytes placed at stream offset `Σ_{k<j} c_k` are `P[0..]`, not `P[Σ_{k<j} c_k ..]` → the
  master reassembles a **corrupted stream**. Broken (corruption).

Either way the unchanged master does not reconstruct `P`. **Mirror/multicast + per-copy truncation
cannot produce a correct fixed-K split.**

### 2.3 The one sub-case that is on-switch feasible — and why it does not scale to the requirement

**Inference.** A *single* input segment can be cut into a **fixed prefix + remainder** on-switch:
copy 1 = mirror-truncate to `header + c_1` (prefix `P[0..c_1)`, seq `s`, `ip.len`/`tcp.len` rewritten
to `c_1`, checksums fixed by delta); copy 2 = the original with the parser advanced past a **fixed,
compile-time** `c_1` payload bytes into a scratch header the deparser omits, so the residual begins at
`P[c_1)`, with `seq += c_1`, `ip.len -= c_1`, checksums fixed. This is correct for **K = 2** on a
**single** segment.

It does not reach the requirement, for three reasons, in increasing severity:

- **Parser-depth wall.** Producing cell `j` needs a fixed discard of `Σ_{k<j} c_k` payload bytes via
  parser advance. Tofino-1's parser advances are strictly bounded (tens of bytes of extraction, hard
  header-budget and PHV limits — the eight bf-p4c constraint classes; see the `tofino-p4` skill and
  `p4-resource-audit.md:90-105`). Discarding ~12 KB to reach the tail cells of a large READ is far
  beyond parser reach. Feasible for K∈{2,3} on small responses; infeasible for large K.
- **Cross-segment wall.** The 12,204 B READ is **not one segment** — it is 20, and the DNP3 unit
  straddles them (§2.1). Re-cutting across arrival-segment boundaries is store-and-forward = proxy.
- **Resource wall.** The resource audit states the replication/split path is **ingress** work landing
  in stages 8–11, which are at **16 of 16 logical table IDs**, and that the "zero ingress cost"
  co-residency result for the egress size axis **does not transfer** to splitting; it "should be
  priced with its own compile before any design commits to it"
  (`p4-resource-audit.md:405-423`). *(verified fact — compiler-measured.)*

### 2.4 Why padding-up (the direction a *fixed visible* pattern actually needs) breaks an unchanged master

**Inference.** Information cannot be removed by making packets look uniform; a *fixed* visible size
means the small response must be **padded up** to the fixed cell shape. Three independent failures on
an unchanged master:

1. **DNP3 corruption.** Bytes injected into the single TCP byte stream are delivered to the master's
   OpenDNP3 parser as application data. Unless every injected byte is valid, CRC-correct DNP3 that
   OpenDNP3 will accept and ignore, the master mis-parses (the governing spec already bars CRC
   recompute and field modification, `DNP3/CLAUDE.md` "Governing spec"). Fabricating valid CRC-16/DNP
   inside the switch and weaving it into the stream is proxy-grade content synthesis.
2. **Seq/ack desynchronization.** Injected bytes advance the byte stream. The master ACKs them; the
   outstation never sent them and sees an ACK for data beyond its `snd.nxt` → per RFC 9293 this is an
   unacceptable ACK (RST or discard). Avoiding this requires the switch to maintain a **growing
   per-flow seq/ack delta** and rewrite `seq` in one direction and `ack` in the other for the life of
   the connection — a TCP-NAT/split-TCP behavior, i.e. proxy state.
3. **The one padding form that avoids the stream is already falsified.** Ethernet-trailer padding
   below IP leaves `ip.len` unchanged, so the observer reads the true length (falsification result,
   `size-timing-coresidency-egress.md`; `OBSERVABLE_TRANSCRIPT_SPEC.md:25-36`,
   `THREAT_MODEL.md:90-92`). Do not claim size protection from trailer padding.

### 2.5 Even if the bytes were correct, the count/timing re-encoding is measured to reopen the leak

**Falsification result** (`leakage-measurements.md:228-281, 356-437`): unpadded CRC-boundary
splitting preserves the size leak exactly for an aggregating observer (`ΔMI = +0.0000 bits`,
CI95 `[-0.0000,+0.0000]`; the transform is invertible — summing chunks returns the length) and at the
finest granularity **relocates** it into segment count (`I(count;size)` 0.0687 → 1.0678 bits). Only
**fixed** K removes the cross-axis re-encoding (P5: `I(timing;size)=0.0000`); adaptive K still leaks
(P4: 4.0 % of H, p=0.001). So the *only* configuration that would be worth the correctness cost is
fixed-K — which §2.2–2.4 show cannot be produced correctly on one switch for this traffic.

### 2.6 Family 3 verdict

| question | answer | basis |
|---|---|---|
| Can a fixed-K split be produced on the switch without a proxy? | **No, in general.** K∈{2,3} on a single small segment only; not across the 20-segment large READ. | inference (§2.2–2.3) + resource audit (verified) |
| Will an unchanged master reassemble correctly? | **No** for mirror/truncate (overlap/corruption) and **No** for padding-up (DNP3 corruption + seq/ack desync). | inference (§2.2, §2.4) |
| One K covering ~47 B and 12,204 B, and at what overhead? | **None tolerable.** K≥~42 (292 B cell) / ~9 (MSS cell); overhead ~two orders of magnitude with the large READ in profile; measured floor 287 % on the small corpus. | verified (leakage §8.3/§9.2) |
| Is byte-preservation retained? | Only inside a **proxy** (the reference `split_server.py`), which is barred. | verified (§1) |

---

## 3. FAMILY 6 — Header normalization: per-field reachability

**Model of "the switch can rewrite it".** A stateless rewrite = set the parsed field to a fixed public
constant and repair the affected checksum by incremental delta, with **no per-flow state** and **no
break in TCP correctness at this ~1 Hz, ≤1.5 KB/poll data rate**. "Endpoint-stamped / unreachable"
means either the field is correctness-load-bearing (clobbering it desynchronizes or RSTs the
connection) or normalizing it requires per-flow bidirectional state that reconstructs proxy behavior.

Labels: **[P]** protectable by stateless on-switch rewrite; **[P*]** rewritable but with a caveat
(scale/negotiation or flow-control coupling); **[E]** endpoint-stamped / unreachable without a proxy.

| layer | field | verdict | why | evidence |
|---|---|---|---|---|
| Eth | dst/src MAC, EtherType | **[P]** | L2, switch owns it; FCS auto-recomputed by MAC | inference |
| Eth | frame length / min-64 padding | **[P]** but **useless for size** | rewritable, but `ip.len` still exposes true length | falsification (`OBSERVABLE_TRANSCRIPT_SPEC.md:25-36`) |
| IPv4 | version, IHL | **[P]** | constants (IHL=5 for no-option) | inference |
| IPv4 | DSCP/ToS | **[P]** | constant + csum delta | inference |
| IPv4 | **total length `ip.len`** | **[E]** as a size observable | must equal real on-wire byte count or the master's IP layer truncates/over-reads; only changeable by changing bytes (§2) = proxy | falsification + inference; `THREAT_MODEL.md:90-92` |
| IPv4 | identification `ip.id` | **[P]** | not used unless fragmenting; overwrite to constant + csum delta; closes the OS ip.id-counter fingerprint | inference |
| IPv4 | flags (DF), frag offset | **[P]** | force DF=1, frag=0 + csum delta | inference |
| IPv4 | **TTL** | **[P]** | rewrite to a constant + csum delta; correctness only needs TTL≥1 at the master. **This closes one of the two device-fingerprint fields.** | verified leak (`leakage-measurements.md:178-190`) + inference that rewrite is safe |
| IPv4 | header checksum | **[P]** | switch maintains it (function of the above) | inference |
| TCP | dst port (20000) | **[P]** (already public/constant) | DNP3 well-known port | inference |
| TCP | src port (master ephemeral) | **[P*]** | rewritable only as a consistent NAT; low info, not identity-bearing; leave | inference |
| TCP | **sequence number** | **[E]** | correctness-critical; a constant desynchronizes → RST; only a consistent per-flow bijection is possible, which does **not** normalize (progression still = bytes = size leak, ISN still a per-connection nonce) | inference; pcap seq structure §2.1 |
| TCP | **acknowledgment number** | **[E]** | same as seq; carries bytes-received; clobber → RST | inference |
| TCP | data offset + **option layout** | **[E]** | `data_offset ∈ {5,8}` fingerprints device; normalizing = rewriting the SYN-negotiated option set and translating every dependent field for the connection lifetime = proxy | verified leak (`leakage-measurements.md:178-190, 131-138`) |
| TCP | **window** | **[P*]** | value clampable to a constant + csum delta (safe at this data rate), but the *scale factor* is SYN-negotiated; window **trajectory** only closes if truly constant AND scale normalized | verified leak (window ranges separated devices, `leakage-measurements.md:187-188`) |
| TCP | flags (SYN/FIN/RST/PSH/ACK) | **[E]** (PSH only **[P]**) | semantically load-bearing; only PSH can be forced constant safely; lifecycle (SYN/FIN/RST) is observable and endpoint-driven | inference |
| TCP | urgent pointer | **[P]** | constant 0 | inference |
| TCP | checksum | **[P]** | switch maintains by delta over its own rewrites | inference |
| TCP | **timestamps TSval/TSecr** | **[E]** | PAWS-bound clock; TSecr must echo the peer's latest TSval; normalizing to a synthetic clock needs per-flow **bidirectional** state and correct echo = proxy; naive clobber → PAWS drops | verified leak ("TSval survives shaping", `leakage-measurements.md:214`, threat model `:95`) |
| DNP3 | link length, function code, transport/app seq, object headers/indices | **[E]** | this **is** the response content/operation type (the secret); rewriting to a constant cannot also deliver the true reading; the master parses it | verified (content leak, `leakage-measurements.md:171`, DPI BA=1.000) |
| DNP3 | per-16-byte-block CRC-16/DNP | **[E]** | any payload edit needs CRC recompute (spec-barred) and is a residual detection channel | governing spec (`DNP3/CLAUDE.md`) |

### 3.1 What header normalization on one switch does and does not buy

**Inference, quantified against the leakage study.** The device-identity fingerprint in the corpus is
carried by an **injective** `(TTL, data_offset)` map (`leakage-measurements.md:178-190`; two-field
lookup gives device balanced accuracy 1.0000 with zero training). One switch can close **TTL** [P]
but not **data_offset** [E]. Since the map is injective on the pair, closing only TTL degrades the
lookup but does not close it — `data_offset ∈ {5,8}` alone still splits SEL-751 (8) from AB1400/ION7550
(5), and the TSval clock and window-scale remain. So:

- **Achievable on one switch (stateless):** normalize Ethernet, `ip.id`, DSCP, DF/frag, **TTL**, TCP
  urgent, PSH, and clamp the **window value**. This removes the TTL and ip.id fingerprints.
- **Not achievable on one switch:** `data_offset`/option-layout, TSval clock, window-scale,
  seq/ack progression — the fields the study ranks as the ones that actually hold identity after
  size+timing are closed (`leakage-measurements.md:609-614`: stack normalization "is the only lever
  that moves the 1.000", and it needs "TTL rewrite, MSS clamp, window normalisation **and option-set
  normalisation**" — the last is the proxy-grade part).

**Conclusion for Family 6:** one switch can normalize the *cheap* stack fields but cannot close the
device-identity channel, because its most informative components (`data_offset`/options, the TSval
clock, window-scale) are SYN-negotiated and PAWS-bound and thus reachable only by a TCP-terminating
proxy. This is the header half of the impossibility boundary.

---

## 4. Leaked-vs-protectable observables (summary ledger)

| observable | on this one-switch, no-proxy, no-encryption testbed |
|---|---|
| `frame.len`, `ip.id`, `ip.ttl`, DSCP, DF | **Protectable** (stateless rewrite) |
| TCP window **value**, PSH, urgent ptr | **Protectable with care** (data-rate-safe; scale caveat on window) |
| **`ip.len` / `tcp.len` (true size)** | **Leaked** — bound to real byte count; trailer padding falsified |
| **TCP seq/ack progression (→ exact response bytes)** | **Leaked** — correctness-bound, not normalizable to a constant |
| **Segment count K / duration** (if adaptive splitting used) | **Leaked** — re-encodes 60.6 % of size entropy into timing (measured) |
| **`data_offset` / TCP option layout / window-scale** | **Leaked** — SYN-negotiated, proxy-only |
| **TSval/TSecr clock** | **Leaked** — PAWS-bound, survives shaping, proxy-only |
| **DNP3 content** (fc, seq, object indices, CRC) | **Leaked** — the secret itself; spec + correctness bar rewriting |
| **Request direction** (READ vs DIRECT_OPERATE by request size) | **Leaked** — 22 B vs 35 B, BA 1.0000; a response shaper never touches it (`leakage-measurements.md:123-129`) |

---

## 5. Labelability — can the observer separate real from cover and recover part of X

**Inference (decisive), corroborated by the frozen framing docs.** Yes. Three residual channels label
every packet and none is closeable on one switch without encryption:

1. **Seq/ack arithmetic.** The real exchange rides one authoritative TCP connection. The switch cannot
   rewrite `seq`/`ack` to public constants (§3, [E]), so the observer reads exact bytes delivered from
   seq deltas and the master's ack — recovering **response size** even if visible segment sizes `S_i`
   are uniform. Any injected cover either (a) advances that same connection's seq (corrupting it, and
   still summing to a visible byte count) or (b) uses a **separate** connection/seq space the observer
   trivially distinguishes. Either way, cover is labelable and size is recoverable. *(This is the
   core reason `S_i` normalization is cosmetic without encryption.)*
2. **Plaintext content + CRC.** The observer parses DNP3 directly (content DPI BA = 1.0000,
   `leakage-measurements.md:171`). Cover that is not valid DNP3 is separable by parsing; cover that is
   valid DNP3 requires switch-fabricated CRC-correct frames the **unchanged master will process as
   real data**, corrupting application state. There is no middle ground on an unchanged endpoint.
3. **Endpoint stack fingerprint.** `data_offset`, TSval clock, window-scale (§3) survive shaping and
   tie packets to a device/stack, so even perfectly uniform sizes and timing leave a per-packet label.

This is exactly the conclusion the frozen spec already reached and states as a non-negotiable
constraint: "Real and chaff packets must be indistinguishable to the observer. Without an encrypted
outer layer they are not, so a mixed real/chaff pattern implies encryption"
(`OBSERVABLE_TRANSCRIPT_SPEC.md:120-123`; `THREAT_MODEL.md:106-109, 120-123`). My analysis adds the
*mechanism* of the impossibility: it is the authoritative single-connection seq/ack space plus
plaintext content, not merely the header fingerprint.

**Therefore:** native cover can never be indistinguishable from real without encryption on this
testbed. Any design that needs real/chaff indistinguishability (i.e. any design that hides transaction
occurrence, or that pads by injecting cover cells) implies an encrypted outer layer and a decoding
peer — which the hard constraint excludes. Request-triggered epochs that shape **only** the visible
schedule of the *real* connection do not need cover and do not hit (1)–(3) as an indistinguishability
problem, but they also cannot normalize size (seq/ack), content, or the stack clock, so they protect
none of `X` as defined; they only reshape the *timing* axis, which is the Defense 4 result already on
record.

---

## 6. The precise impossibility boundary

On `Master <-> Tofino-1 <-> Outstation`, unchanged plaintext endpoints, no encryption, no decoding
peer, one switch cannot normalize the following observables (each requires either store-and-forward
TCP reassembly, per-flow bidirectional TCP-state rewriting, or content fabrication — i.e. a proxy):

1. **`tcp.seq` and `tcp.ack`** and their progression ⇒ the **response-size / byte-count** channel.
2. **`ip.len` / `tcp.len`** as size observables (bound to the true on-wire byte count).
3. **Segment count K and epoch duration** for any size-adaptive segmentation (measured 60.6 %
   size→timing re-encoding; only *fixed* K removes it, and fixed K is not producible on-switch here).
4. **TCP timestamp option `TSval`/`TSecr`** (PAWS-bound device clock).
5. **`tcp.data_offset` / TCP option layout / window-scale** (SYN-negotiated device fingerprint).
6. **DNP3 application content** — function code, transport/app sequence, object headers/indices, and
   per-16-byte-block CRC-16/DNP (the secret itself; CRC recompute spec-barred).

Fields **inside** the boundary (one switch **can** normalize statelessly): Ethernet MAC/EtherType,
IP version/IHL/DSCP/DF/frag, **`ip.id`**, **`ip.ttl`**, IP + TCP checksums, TCP urgent pointer, TCP
PSH, and (with a data-rate/scale caveat) the TCP **window value**. Closing these removes the TTL and
ip.id fingerprints but leaves the size, count/timing, clock, option-layout, and content channels open,
so device identity and response size/value remain recoverable.

---

## 7. Open questions (for Philip / the parent)

- **[open question]** Is the deployment target the *pre-encryptor* master-facing segment (this
  analysis) or *after* a WAN encryptor? If a tunnel already exists, size/seq/clock normalization moves
  into the tunnel's cell design and several boundary fields above become moot — but that reintroduces
  the encryptor+peer the current hard constraint forbids (`THREAT_MODEL.md:26-32`,
  `TRANSPORT_AND_ENCRYPTION_OPTIONS.md`).
- **[open question]** Is `X` device identity, or response value/size/operation-type? If the claim is
  narrowed to **timing only** (the Defense 4 CLRT result), none of §6 is a blocker for *that* claim,
  because Defense 4 never claimed size/content/stack normalization. If `X` includes size or identity,
  §6 is binding and one switch is insufficient.
- **[open question]** Is a **fixed K∈{2,3} on the common small response only** (not covering the large
  READ) of any interest? It is the one on-switch-feasible sub-case (§2.3), but it protects nothing
  under an aggregating observer (`ΔMI=0`) and re-encodes into count/timing, so I do not recommend it.

---

## 8. Provenance

Frozen artifacts read this session (all under `/home/philip/Projects/DNP3`, read-only):
`dnp3_split_harness/split_server.py`; `dnp3_split_harness/reports/baseline_segmentation.md`;
`dnp3_split_harness/reports/tcp_ack_fingerprinting.md`;
`dnp3_split_harness/captures/baseline/large_read.pcap` (22 response-direction packets re-parsed with
scapy this session — segment sizes and contiguous seq structure confirmed);
`research/size_timing_coresidency/reports/leakage-measurements.md`;
`research/size_timing_coresidency/reports/p4-resource-audit.md`. Framing:
`/home/philip/Projects/DNP3_fixed_transcript/THREAT_MODEL.md`,
`/home/philip/Projects/DNP3_fixed_transcript/OBSERVABLE_TRANSCRIPT_SPEC.md`. No silicon, no relay, no
git, no writes outside this file.
