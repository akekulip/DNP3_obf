# Transport and encryption placement for a DNP3 fixed-transcript defense

> **EXCLUDED ALTERNATIVE (revised scope, see `CORRECTION_LOG.md`).** The design this document
> recommends — paired software gateways with an encrypted fixed-cell tunnel and the Tofino as
> metronome — is **out of scope** under the binding testbed `Master <-> Tofino-1 <-> Outstation`, which
> forbids gateways, proxies, a second endpoint, and any encrypted tunnel (IP-TFS / IPsec / MACsec) or
> split-TCP. This analysis is retained **only** as the documented strongest excluded alternative and as
> the correct account of what full transcript invariance would require. Its central result stands and is
> now used as an impossibility argument rather than a recommendation: a full fixed transcript needs
> encryption and a decoding peer, neither of which the testbed permits, so full invariance is
> unreachable on one Tofino and the project pursues a bounded native defense instead. Do not treat any
> paragraph below as the current recommendation.

**Role:** transport & security architect · **Phase:** architecture only, no implementation ·
**Date:** 2026-08-10 · **Switch contact:** none · **Relay contact:** none

**Scope note.** This is a working repository named `DNP3_fixed_transcript`. It is not ADTA, not
GridCloak, and not "Defense 4." The demonstrated gridded-release timing engine referenced below is
a **frozen upstream result** at `/home/philip/Projects/DNP3` (pinned commit `7c4a5a7`, see
`PROVENANCE.md`); it is cited as prior art, never rewritten here.

---

## 0. Bottom line (verdict first)

**Is a local encryption/encapsulation function near the outstation unavoidable? YES.**
One line: a true fixed transcript must make the observable **cell sizes and the real-vs-chaff
distinction independent of the response**, but plaintext DNP3 is self-describing (the link/transport
`LEN` and the application object headers state the true length), so any padding is strippable and any
chaff is either malformed-and-detectable or valid-and-dangerous — only an **encrypted outer layer
whose ciphertext cells are all one length** removes both leaks, and Tofino-1 cannot produce that
layer because the DNP3 payload bytes are the unparsed deparser residual and never enter the PHV
(`research/size_timing_coresidency/reports/adversary-model.md:478-480`).

**Where the observation point forces the crypto to be local.** The protected segment is the WAN
between the master and the outstation-edge switch (`master → observed WAN → switch → relay`). The
outstation-side tunnel ingress — the point that turns plaintext DNP3 into fixed-size ciphertext cells
— must sit on the **relay side of that observation point**, i.e. physically between the relay and the
WAN. It cannot be the master (across the observed WAN) and it cannot be the Tofino (no data-plane
cipher). Therefore it is a local box near the outstation. This is a topology result, not a
preference.

**Minimal viable endpoint architecture:** **Architecture 4 — a pair of software tunnel gateways
(one local to the outstation, one at the master) that own the encrypted fixed-cell envelope, with the
Tofino-1 enforcing the content-independent release grid and rewriting the outer header to a canonical
profile.** Architecture 3 is the same design with the Tofino demoted to pure scheduling; it collapses
into Architecture 4 because a decrypting peer at the master is not optional. Architectures 1 and 5
**cannot** produce a fixed transcript and are retained as the two instructive failure/floor cases.

**The clean division of labor** (and the reason it is affordable): everything that needs to *read or
transform payload bytes* — encrypt, decrypt, pad to a fixed cell, inject/remove chaff, fragment the
12,204 B READ, reassemble, translate the TCP stream — is done by the **software gateways**; the
Tofino does only what silicon does better than software and what needs no payload access — **precise
low-jitter release on a grid** (the demonstrated D-series engine) and **fixed-offset outer-header
rewrite** (TTL / DF / IP-ID / TSval, already costed feasible as N1/N2/N3 in
`adversary-model.md:571-575`). The Tofino is deliberately kept **outside the confidentiality TCB**:
it sees only ciphertext cells.

---

## 1. What a fixed transcript actually requires

Define the observable transcript on the WAN as

```
O = [ (direction_i, size_i, release_time_i, outer_header_i) ]  for i = 1..N
```

"Fixed" means the joint distribution of `O` is **independent of the protected device and of the
response contents**: `O ⟂ (device, response)`. Decompose that into four independence requirements,
each of which is a separate mechanism with a separate home:

| requirement | closes which leak | mechanism | measured basis |
|---|---|---|---|
| **R-size** `size_i ⟂ response` | `ip.len` / `tcp.len` / byte-total | every emitted cell is the **same** ciphertext length | H2/H1: unpadded splitting relocates but removes nothing (`leakage-measurements.md:15,228-281`); closure only at fixed-K constant-C (`:597-605`) |
| **R-count** `N ⟂ response` | segment/packet count "beacon" | **constant cell count per epoch**, or continuous cover so there is no epoch | H2: count MI 0.0687→1.0678 bits under fine splitting (`:242,269-270`); H3: fixing K removes cross-axis re-encoding, adaptive-K does not (`:420-436`) |
| **R-time** `release_time_i ⟂ response` | CLRT, first-byte latency, inter-segment gaps | release on a content-independent grid `t_k = t0 + kT` | H3: perfect first-byte normaliser still leaks 60.6% of H(size) unless K is fixed (`:390-396`); gridded release = upstream N4 |
| **R-header** `outer_header_i ⟂ device` | TTL, DF, IP-ID, `data_offset`, **TSval/TSecr** | canonicalize every outer-header field on every cell | M1 oracle: stack signature carries 100% of device entropy, BA 1.000 with zero-width CI **after** perfect size+timing defense (`:157-224`); TSval preserves the internal interval `D`-invariantly (`adversary-model.md:305-336`) |

The leakage study's central result is that **R-size, R-count, R-time do not deliver device anonymity
on their own** — the perfect-defense oracle leaves balanced accuracy at 1.0000 because the stack
channel (R-header) is untouched (`leakage-measurements.md:218-224`). So R-header is not a finishing
touch; it is co-equal, and it is the one requirement the Tofino is actually good at.

**The two requirements that force encryption are R-size and R-count**, and they force it for the same
reason, developed next.

---

## 2. Why real and chaff are not indistinguishable without encryption

This is the crux of the unavoidability argument. A fixed transcript that survives idle periods needs
**cover cells** flowing when there is no real response, and it needs **padding** so real cells are the
same length as cover cells. Both fail in plaintext for a self-describing protocol.

**2.1 Padding is strippable in plaintext (regime PT).** DNP3 is length-explicit at three layers: the
link header carries `LEN`, the transport header carries FIR/FIN segmentation, and the application
layer carries function code + object range headers. A passive observer that parses DNP3 reads the
true payload length directly and subtracts any appended filler — the falsified prior size mechanism
proved this on silicon, driving `frame.len` to one value while `ip.len` and `tcp.len` stayed at full
entropy (`CHARTER.md:38-41`; `adversary-model.md:556` S1 "Everything in regime PT: DNP3 `LEN` strips
it"). In-band padding therefore cannot satisfy R-size against an observer who parses the plaintext it
is padding.

**2.2 Chaff is distinguishable or dangerous in plaintext.** A cover cell in plaintext is one of two
things:

- **Structurally valid DNP3** — in which case it is indistinguishable to the observer but the master's
  DNP3 stack *acts on it*. This is a hard safety disqualification, not a privacy trade-off:
  `ProcessIIN` runs unconditionally even on rejected frames, so an injected `NEED_TIME` triggers a
  g50 time-sync WRITE and a fabricated CONFIRM makes the relay permanently delete SOE records
  (`adversary-model.md:515-520,558`). Chaff aimed at a protection relay is forbidden.
- **Not valid DNP3** (random or malformed bytes) — in which case the observer that parses DNP3 tells
  it apart from real traffic trivially (bad CRC, illegal function code, wrong link addressing), so it
  does not satisfy R-count: the observer counts real cells and ignores chaff.

There is no third option in plaintext. A cover cell can be both **indistinguishable from real** and
**inert to the endpoints** only if its bytes are **opaque** — i.e. ciphertext — so the observer
cannot parse it and the receiving *tunnel* endpoint (not the DNP3 stack) discards it by an
authenticated marker inside the encrypted layer.

**2.3 Therefore the fixed cell sizes must be ciphertext lengths.** Combine 2.1 and 2.2: real cells and
cover cells must be byte-indistinguishable and constant-length to the observer, which forces them to
be equal-length ciphertext under a key the observer does not hold. The fixed cell size *is* the
ciphertext length of the tunnel framing. This is exactly the property Ditto (NDSS 2022) relies on and
the reason it works: "the switch is an endpoint of MACsec/IPsec, so padding is inserted where the
observer's parse stops … precisely what makes Ditto immune to the strippability theorem — and
precisely what we do not have" (`adversary-model.md:500-502`). Ditto also assumes a **cooperating
peer switch** that strips the padding before anyone who could attribute it sees it
(`:498-499`). A one-switch, plaintext deployment has neither.

**2.4 Where the cipher must live.** The encrypted envelope must span the observed WAN. Its outstation
end must be on the relay side of the observation point (§0). Three candidates, one conclusion:

- **The relay itself** (DNP3/TLS or IEEE 1815 Secure Authentication). Rejected twice over: it is
  endpoint modification of a READ-only protection relay (out of scope, `CHARTER.md:34`), and it is
  insufficient anyway — DNP3 SAv5 is HMAC authentication, not confidentiality, and DNP3/TLS record
  lengths track plaintext lengths, so neither produces fixed cells.
- **The Tofino.** Rejected structurally: no data-plane block cipher; the payload never enters the PHV
  (§3).
- **A local box between the relay and the WAN** (software gateway, or an existing IPsec/MACsec
  appliance). The only remaining place. Hence **local encapsulation is unavoidable.**

---

## 3. What Tofino-1 can and cannot do here

| capability | Tofino-1? | consequence for this design |
|---|---|---|
| Encrypt/decrypt arbitrary payload in the P4 pipeline | **No.** No block cipher; DNP3/payload bytes are the unparsed deparser residual and never enter the PHV (`adversary-model.md:478-480`). Cannot even *read* the payload. | The cipher must be off-chip. This is the whole ballgame. |
| MACsec-class (802.1AE) port line encryption | **SKU-dependent, and does not help.** Where present it is a fixed port engine, not a P4-programmable cipher; it needs a MACsec *peer*; it operates on whole Ethernet frames and is length-preserving (SecTAG + ICV are fixed overhead), so it hides content but **not size or count**; and it still never exposes payload to the P4 program. | MACsec ≠ fixed transcript. Do not rely on it for R-size/R-count. At most it is an alternative *envelope* that a peer must terminate — i.e. Architecture 2 with a MACsec appliance. |
| Buffer/reassemble a byte stream, hold per-flow TCP state | **No** at the required scale. The TM queues *packets*, not byte streams; there is no large per-flow reassembly buffer; the ingress state groups are saturated (W0-15 at 16/16 containers, 512/512 bits; stages 8-11 at 16/16 logical tables — `p4-resource-audit.md:99,127-129`). | Fragmentation, reassembly, and stream/seq translation cannot live on-chip. Software gateways own them. |
| Replicate one frame into many (mirror/multicast) for splitting | **Yes, but it lands wrong.** CRC-boundary splitting on-chip needs multicast/mirror + per-copy truncation, which is **ingress** work in stages 8-11 that are already at 16/16 (`p4-resource-audit.md:419-423`). | On-chip splitting is the one place "zero ingress cost" does **not** transfer. Push splitting into the tunnel framer. |
| Rewrite fixed-offset header fields with a checksum delta (TTL, DF, IP-ID, TCP options incl. TSval/TSecr) | **Yes.** Header-only IP-checksum delta is cheap; the runtime-Δ TCP checksum is the one compile risk to confirm (`adversary-model.md:571-575,600-603`). | This is R-header, and it is the Tofino's job. Grounded feasible as N1/N2/N3. |
| Release/hold a packet on a content-independent grid `t_k = t0 + kT` | **Yes — demonstrated.** The upstream D-series gridded-release engine holds and releases on switch-clock edges via TM queues + loopback recirculation. | This is R-time, and it is the Tofino's job. |
| Add a **fixed outer** header (Ditto-style 32/16/8/4/2/1 B pad headers keyed by EtherType) | **Yes**, but it is *outer* padding that a **peer must strip**, and on this program tagalong PHV is the binding wall — the measured trailer variant hit 89.8% of the tagalong budget alone (`adversary-model.md:521-524`). | Confirms padding belongs in the software tunnel framer (opaque, peer-stripped), not in the P4 deparser. |

**Reading:** the Tofino contributes **R-time and R-header** at line rate and zero payload exposure.
It cannot contribute **R-size or R-count**, because both require reading, transforming, and buffering
payload bytes and producing ciphertext — three things it structurally cannot do. That boundary, not a
resource budget, is what makes the local software function unavoidable.

---

## 4. The transport interface each viable architecture needs

The inner world is unmodified DNP3-over-TCP between the master and the relay. The outer world is a
fixed-cell encrypted tunnel across the observed WAN. The interface between them is the whole design.

**4.1 Terminate, don't translate — use a split-TCP tunnel.** The cleanest interface terminates the
inner TCP connection at each software gateway and carries the inner DNP3 **byte stream** inside a
separate, shaped, encrypted **outer** connection between the two gateways; the far gateway re-originates
a fresh inner TCP connection to its endpoint. Three independent TCP connections
(`relay ↔ local-gw`, `local-gw ↔ master-gw` [the tunnel], `master-gw ↔ master`) mean the sequence
spaces are **naturally independent** — there is no in-band sequence arithmetic to do, because you
never splice one seq space into another. This subsumes "TCP-seq-translate" into TCP termination and
sidesteps the resource wall that killed in-band seq translation on-chip (`p4-resource-audit.md:415-417`).
It also **hides the inner stack's loss behavior** — the SEL-751's SACK-under-loss `data_offset` growth
(T-14) and its monotone window trajectory (T-7, three separate leaks, `adversary-model.md:204`) never
reach the WAN, because the WAN only ever carries the outer connection's canonical header.

The alternative, an **in-band encapsulation tunnel** (wrap each original packet, pad in an outer
region, keep end-to-end TCP), is viable only if **all padding is in the outer/opaque region and the
peer strips it**, so the inner seq space is untouched — the Ditto model. The moment you pad the inner
stream you owe a per-flow forward/reverse seq/ack translation, which is exactly the per-flow ingress
state the resource audit rules out on-chip. Recommendation: **split-TCP**, and if end-to-end TCP
semantics are required, in-band encapsulation with **outer-only** padding — never in-band inner
padding.

**4.2 Fragmentation and reassembly of the 12,204 B READ.** The large integrity poll is 12,204 B — 9
DNP3 application fragments, 49 link frames, 20 TCP segments, MSS-sized bursts up to 1448 B
(`dnp3_split_harness/reports/baseline_segmentation.md`). Into fixed cells of payload `C`, this is
`⌈12204/C⌉` cells (≈9 at C≈1408, ≈24 at C≈512). The **fragmenter** lives at the sending gateway; the
**reassembler** at the receiving gateway buffers cells, restores the byte stream, and hands it to the
re-originated inner TCP. Two design facts follow directly from the leakage study:

- **Cell count leaks the response unless it is fixed** (R-count). A per-epoch cell count of `⌈len/C⌉`
  is the same "beacon" measured at `I(count;size) = 1.0678 bits` (`leakage-measurements.md:269-270`).
  Closing it requires **fixed-K** (constant cells per epoch) or **continuous cover** (no epochs). The
  fixed-K overhead is set by the *maximum* response the link ever carries, and 12,204 B makes that
  overhead roughly two orders of magnitude on the common 47-byte response
  (`leakage-measurements.md:540-542,602-605`). **This is the dominant open cost of the whole defense**,
  and it is a transport/framing decision, not a P4 decision.
- **Reassembly is stateful buffering** — a software-gateway job by §3.

**4.3 Loss and retransmission across the tunnel.** With split-TCP, WAN loss is recovered by the
**outer** connection's own reliable transport, invisibly to both inner connections. A retransmitted
cell is itself a fixed-size cell, so a retransmit is **indistinguishable from a fresh cell or a cover
cell** — loss produces no size/count tell *provided the cell stream stays constant-rate and
constant-size*. The one hazard is **timing**: if the grid stalls waiting for in-order tunnel delivery,
the stall is observable. The gateway must therefore keep emitting **cover cells during recovery** so
the release grid (Tofino, R-time) never idles on loss. Under an in-band encapsulation tunnel instead,
inner retransmissions traverse the WAN and their timing/size must be shaped like any other cell — more
coupling, another reason to prefer termination.

**4.4 Continuous vs event-triggered cover — the decisive transport choice.**

- **Event-triggered** (cells flow only during a request epoch): the epoch boundaries and the burst
  length leak `⌈len/C⌉` and the poll cadence. This satisfies R-time within an epoch but **fails
  R-count** across epochs, and it re-exposes exactly the segment-count / duration channel the leakage
  study measured (H3, `:390-396`). Cheaper, but it does not deliver a fixed transcript.
- **Continuous bidirectional cover** (a constant cell rate in both directions at all times, real data
  opportunistically replacing cover cells): the observer sees one unbroken constant-size constant-rate
  stream regardless of whether a poll is in flight. This is the only mode that satisfies R-size,
  R-count, and R-time simultaneously, and it is Ditto's "always-busy aggregate" (`:503-505`). Its cost
  is a fixed bandwidth floor — but at 5 pps / ~200 B the provably-optimal content-independent schedule
  is ~10 kbit/s, cheap enough to afford the ideal (`adversary-model.md:532-534`). **Recommended:
  continuous cover**, sized by the real polling profile including large READs (the measurement the
  program still owes, `leakage-measurements.md:602-605`).

**4.5 The request direction — a benefit only the tunnel provides.** Control-vs-read is recoverable
from the *request* size alone at BA 1.000 (`leakage-measurements.md:124-129`), and a single
outstation-edge switch structurally cannot touch it because the observer sees the request *before* the
switch (`adversary-model.md:560` F1). A **paired tunnel encrypts and shapes the request direction too**,
so it is the only architecture here that closes the request-side leak. This is a real discriminator in
favor of Architectures 3/4 over 1/5.

---

## 5. The five endpoint architectures

Each table uses the nine transport/security functions. "Trust" is what that point must be trusted with
(plaintext access = inside the confidentiality TCB; key custody; safety authority over the relay).

Topology legend: `M` master · `WAN` observed segment · `T` Tofino-1 at the outstation edge ·
`R` relay (READ-only SEL-751) · `G_o` outstation-local software gateway · `G_m` master-side software
gateway · `IPSEC` existing IPsec/MACsec appliance.

### Architecture 1 — one Tofino + a master-side software gateway
`M ── G_m ── WAN ── T ── R`

| function | where | trust |
|---|---|---|
| encrypt (M→R dir) | `G_m` | plaintext + key |
| decrypt (M→R dir) | **nowhere on the outstation side** — R speaks plain DNP3, T cannot decrypt | — |
| encrypt (R→M dir) | **nowhere** — R emits plaintext, T cannot encrypt | — |
| pad-insert / de-chaff | not possible in R→M (plaintext on relay→T→WAN) | — |
| fragment / reassemble | `G_m` for M→R only | — |
| stream/seq | inner TCP terminates at `G_m` and at R (plain) — asymmetric | — |
| release schedule | `T` (R-time) | none (ciphertext or plaintext) |
| outer-header neutralize | `T` (R-header) | none |

**Verdict: cannot produce a fixed transcript.** There is no decrypting peer near the outstation and no
cipher on the outstation side, so the **R→M direction is plaintext on the WAN** and degenerates to
Architecture 5. The Tofino would have to be the tunnel endpoint and it cannot. Retained as the proof
that **a single gateway is insufficient — the tunnel is inherently a pair.**

### Architecture 2 — Tofino between a relay LAN and an existing IPsec/MACsec gateway
`M ── WAN ── IPSEC ── T ── R`  (T on the plaintext relay-LAN side) **or**
`M ── WAN ── T ── IPSEC ── R`  (T on the ciphertext side)

| function | where | trust |
|---|---|---|
| encrypt / decrypt | `IPSEC` (both directions) | plaintext + key; **local to outstation** |
| pad-insert (fixed cell) | **only if `IPSEC` supports fixed-length framing** — standard IPsec TFC padding (RFC 4303) is limited and not fixed-cell; MACsec is length-preserving. Usually **not** satisfied. | `IPSEC` |
| de-chaff | `IPSEC` (if it can source cover) — usually not | `IPSEC` |
| fragment / reassemble large READ into cells | `IPSEC` (tunnel MTU) — but into *tunnel* packets, not fixed cells | `IPSEC` |
| stream/seq | IPsec is packet-encapsulation, so inner seq preserved; no translation | — |
| release schedule | `T` — best if placed on the **ciphertext** side (schedules opaque tunnel packets) | none |
| outer-header neutralize | `T` rewrites the **tunnel** outer header (TTL/DF/IP-ID; TSval only if a TCP tunnel) | none |

**Verdict: viable envelope, usually wrong shape.** The encryption is local (consistent with
unavoidability) and free to us, but R-size/R-count are satisfied only if the appliance can be
configured for **constant-length, constant-rate** output — most IPsec/MACsec deployments cannot, and
MACsec is length-preserving by construction. Place `T` on the **ciphertext side** so it is outside the
crypto TCB and shapes opaque packets. Use this architecture **only** when a fixed-cell-capable
appliance already exists; otherwise it provides confidentiality and timing but not a fixed transcript.

### Architecture 3 — software encapsulation/encryption near the outstation + Tofino scheduling
`M ── G_m ── WAN ── T ── G_o ── R`  (with `G_m` implied — see verdict)

| function | where | trust |
|---|---|---|
| encrypt / decrypt | `G_o` (outstation end), peer at `G_m` | plaintext + key; **local to outstation** |
| pad-insert (fixed cell) | `G_o` | key |
| de-chaff | `G_m` on receive (and `G_o` on the reverse) | key |
| fragment large READ into cells | `G_o` | plaintext |
| reassemble | `G_m` | plaintext |
| stream/seq | split-TCP: terminate at `G_o` and `G_m`; no translation | plaintext |
| release schedule | `T` (R-time), on the ciphertext cells between `G_o` and WAN | none |
| outer-header neutralize | `T` (R-header) on the cell stream | none |

**Verdict: viable, and it *is* Architecture 4.** "Software encap near the outstation + Tofino
scheduling" cannot stand alone — the cells must be decrypted and reassembled somewhere, and that
somewhere is a peer at the master (`G_m`). Once you name the peer, Architecture 3 is Architecture 4
with the Tofino's role narrowed to scheduling. Kept as the emphasis that **the heavy lifting is in
`G_o`, and the Tofino is only the metronome.**

### Architecture 4 — paired software gateways, Tofino enforces the critical schedule (RECOMMENDED)
`M ── G_m ── WAN ── T ── G_o ── R`
data path R→M: `R —plain→ G_o —[fragment, encrypt, pad, inject cover]→ cells → T —[grid release, outer-header rewrite]→ WAN → G_m —[de-chaff, decrypt, reassemble, re-originate TCP]→ M`

| function | where | trust |
|---|---|---|
| encrypt / decrypt | `G_o` ↔ `G_m` (both directions) | plaintext + key; `G_o` local to outstation |
| pad-insert (fixed cell) | sending gateway (`G_o` for R→M, `G_m` for M→R) | key |
| de-chaff | receiving gateway | key |
| fragment (12,204 B READ) | sending gateway | plaintext |
| reassemble | receiving gateway | plaintext |
| stream/seq-translate | subsumed by split-TCP termination at `G_o` and `G_m` | plaintext |
| release schedule (grid) | **`T`** — the demonstrated D-series engine, on opaque cells | **none — outside crypto TCB** |
| outer-header neutralize (TTL/DF/IP-ID/TSval) | **`T`** — N1/N2/N3 fixed-offset rewrites | **none** |

**Verdict: the minimal viable fixed-transcript architecture.** It is Ditto's shape (encrypted
envelope + cooperating peer + always-busy aggregate) with the peer switch replaced by a **peer
software gateway** and the shaping split so the one thing that needs silicon-grade timing — the
release grid — runs on the Tofino, at line rate, on ciphertext, outside the confidentiality TCB. It is
the only architecture that satisfies R-size, R-count, R-time, R-header **and** closes the
request-direction leak (§4.5). Trust cost: `G_o` must be physically secured on the relay LAN side of
the observation point and holds the key; `T` need not be trusted with plaintext.

### Architecture 5 — native DNP3, no cooperating endpoint (constrained comparison / floor)
`M ── WAN ── T ── R`  (no gateway, no cipher)

| function | where | trust |
|---|---|---|
| encrypt / decrypt / pad / de-chaff / fragment / reassemble / seq | **nowhere** — impossible without a cipher and a peer | — |
| release schedule | `T` (R-time) | none |
| outer-header neutralize | `T` (R-header: TTL/DF/IP-ID/TSval; request canonicalization S6) | none |

**Verdict: no fixed transcript is possible; a real but bounded defense is.** With no encryption and no
peer, R-size and R-count are unreachable (self-describing plaintext, strippable padding, distinguishable
or dangerous chaff — §2). What *is* reachable at the single outstation-edge switch is exactly the
upstream program's honest scope: **gridded timing release (R-time) + outer-header normalization
(R-header)** — TTL/DF/IP-ID (N1 safe subset), TSval/TSecr rewrite (N2, "the one place this project has
never normalized," `adversary-model.md:305-336`), and optionally **request canonicalization (S6)**,
the one filler that is not strippable because it makes the relay genuinely answer a fixed maximal point
set (`adversary-model.md:561`). This closes the timing and endpoint-state channels and supports a
**content-confidentiality** claim, but it does **not** deliver device anonymity (the stack channel and
`k = 1` survive, M1 oracle) and it does **not** touch the request direction. This is the correct paper
baseline: the best a non-cooperating, no-crypto, one-switch design can do — and the measured proof that
it is short of a fixed transcript.

---

## 6. Consolidated placement matrix

Where each function lives, by architecture. `G_o` = outstation-local gateway, `G_m` = master gateway,
`T` = Tofino, `IPSEC` = existing appliance, `—` = not achievable in that architecture.

| function | A1 (T + master gw) | A2 (existing IPsec) | A3 = A4 | **A4 (recommended)** | A5 (native, floor) |
|---|---|---|---|---|---|
| encrypt / decrypt | `G_m` one-sided → broken | `IPSEC` (local) | `G_o`↔`G_m` | **`G_o`↔`G_m`** | — |
| pad to fixed cell (R-size) | — (R→M plaintext) | `IPSEC` *if* fixed-cell capable | sending gw | **sending gw** | — |
| de-chaff (R-count) | — | `IPSEC` if capable | receiving gw | **receiving gw** | — |
| fragment 12,204 B READ | `G_m` (M→R only) | `IPSEC` | sending gw | **sending gw** | — |
| reassemble | `G_m` | `IPSEC` | receiving gw | **receiving gw** | — |
| TCP-seq / stream | asymmetric | preserved (encap) | split-TCP (none) | **split-TCP (none)** | native |
| release schedule (R-time) | `T` | `T` (ciphertext side) | `T` | **`T`** | `T` |
| outer-header neutralize (R-header) | `T` | `T` (tunnel header) | `T` | **`T`** | `T` |
| closes request-direction leak? | no | yes (both dirs tunneled) | yes | **yes** | no |
| fixed transcript achievable? | **no** | only if appliance is fixed-cell | yes | **yes** | **no** |
| Tofino inside crypto TCB? | no | no (ciphertext side) | no | **no** | n/a |

---

## 7. Outer-header neutralization requirements (the Tofino's job in every viable case)

Even a perfect fixed-cell encrypted tunnel fails R-header if the **cell's own outer header** varies by
device or direction — the M1 oracle shows the stack signature alone holds 100% of device entropy and
keeps balanced accuracy at 1.000 after a perfect size+timing defense
(`leakage-measurements.md:178-224`). The tunnel endpoints should emit a canonical outer header, and the
Tofino at the edge is the enforcement backstop because it is the last hop before the WAN. Required
rewrites, all grounded as feasible in `adversary-model.md:571-575`:

| field | requirement | Tofino mechanism | risk / caveat |
|---|---|---|---|
| `ip.ttl` | one constant value on every cell, both directions | fixed-offset rewrite + IP-checksum delta | none (header-only). Removes the AB1400 TTL-128 tell (`:182`). |
| `ip.flags.DF`, `ip.id` | constant DF; IP-ID from a canonical policy (or zero if DF set and no fragmentation) | one 16-bit field + IP-checksum delta (N3) | preserve IP-ID uniqueness within MSL only if fragmentation is possible; DF is set here (`:573`). |
| `tcp.data_offset` / option layout | constant option layout on the **outer** connection; the inner stack's `data_offset=8` is hidden by termination (§4.1) | outer connection is emitted by the gateway with a fixed profile; Tofino verifies/fails-open | this is the field that carried device identity at 1.000 and that broke the falsified normalizer (`CHARTER.md:41`; `:197`). Termination is what removes it. |
| `tcp.timestamp` **TSval / TSecr** | replace the endpoint clock with a switch-derived monotone clock on egress; restore the original in TSecr on ingress | 8 B options into PHV, 2 registers/flow, TCP-checksum delta (N2) | **the finding of the adversary report** (`:305-336`): TSval preserves the internal ACK→response interval `D`-invariantly, so a gridded wire while TSval is unmodified normalizes a field the adversary need not read. On a split-TCP tunnel the inner TSval never reaches the WAN; on an in-band tunnel N2 is mandatory. PAWS/RTTM at the relay make the restoration safety-sensitive — must be exact or fail open. |
| runtime-Δ TCP checksum | required by any TCP-field rewrite | flagged top compile risk / Class-6 zone (`adversary-model.md:600-603`) | **must be confirmed by `p4-dataplane-engineer` before promising N2**; if it will not compile, in-band N2 is dead and split-TCP termination becomes mandatory rather than preferred. |

**Handoff:** the Tofino tables/registers/actions for R-time (grid release) and R-header (N1/N2/N3
rewrites) are for `p4-dataplane-engineer` to spec against `bf-p4c` — this document does not write P4.
The two constraint checks that gate the header work are (1) TCP option-region parse at `data_offset=8`
lands in normal PHV, and (2) the runtime-Δ TCP checksum compiles (`adversary-model.md:592-603`).

---

## 8. What survives review

- **Local encryption/encapsulation near the outstation is unavoidable** for any defense that claims a
  fixed transcript, and the reason is a *protocol* property (self-describing plaintext ⇒ strippable
  padding + distinguishable/dangerous chaff) crossed with a *topology* property (the observation point
  is on the WAN, so the outstation-side cipher must sit between the relay and the WAN) crossed with a
  *hardware* property (Tofino cannot reach the payload). All three are measured or structural, none is
  an assumption.
- **The minimal viable architecture is a pair of software tunnel gateways with the Tofino as the
  metronome and header-scrubber (Architecture 4).** It is the only option that meets R-size, R-count,
  R-time, R-header and closes the request-direction leak, and it keeps the Tofino outside the
  confidentiality TCB.
- **If a fixed-cell-capable IPsec/MACsec appliance already exists, Architecture 2 borrows its
  envelope**; if the appliance is length-preserving (the common case, and all MACsec), it does not
  deliver R-size/R-count and reduces to timing + header confidentiality.
- **Architecture 5 is the honest baseline** and the correct thing to build and measure first if no
  second endpoint is available: it delivers R-time + R-header (real, demonstrated-class mechanisms) and
  is provably short of a fixed transcript — which is itself the paper's impossibility result.

### Open items that must be closed before any build (all lab- or handoff-gated)

1. **The fixed-K / continuous-cover overhead against the *real* polling profile**, including integrity
   polls and the 12,204 B READ. The 287% figure is a floor on a 47-byte-max corpus; the deployment cost
   is unknown until the real response-size distribution is measured (`leakage-measurements.md:602-605`).
   This is the single largest open cost and it is a transport decision, not a P4 one.
2. **Split-TCP loss/latency semantics on the WAN.** Terminating TCP moves congestion control to the
   outer connection; validate that cover-cell emission during recovery keeps the grid from stalling
   (§4.3) and that inner-connection RTOs at the relay stay within tolerance.
3. **Runtime-Δ TCP checksum compile check** (§7) — gates whether outer-header TSval work is in-band or
   forces termination. Hand to `p4-dataplane-engineer`.
4. **Key management and physical trust for `G_o`** — it holds plaintext and the tunnel key on the relay
   LAN; its physical security *is* the confidentiality boundary.
5. **No hardware contact** until Philip authorizes it; the switch is live in a calibrated policy
   (`CHARTER.md:66-67`). Everything above is offline architecture.

---

## Sources

All paths under `/home/philip/Projects/DNP3` at pinned commit `7c4a5a7` (`PROVENANCE.md`):

- `research/size_timing_coresidency/reports/leakage-measurements.md` — R-size/R-count/R-time
  measurements (H1/H2/H3/H5), the perfect-defense oracle, the fixed-K result, the request-direction
  leak.
- `research/size_timing_coresidency/reports/adversary-model.md` — the Tofino-cannot-encrypt fact
  (`:478-480`), Ditto positioning (`:486-540`), the size-class assessment (`:552-565`), the N1/N2/N3
  header-normalization mechanisms (`:571-575`), TSval (`:305-336`), request topology F1 (`:560`).
- `research/size_timing_coresidency/reports/p4-resource-audit.md` — on-chip state/stage saturation,
  why seq-translation and splitting land wrong (`:415-423`), tagalong budget.
- `research/size_timing_coresidency/CHARTER.md` — constraints, falsified prior size mechanism, relay
  READ-only, open retirement defect.
- `dnp3_split_harness/reports/baseline_segmentation.md` — the 12,204 B / 9-fragment / 49-frame /
  20-segment large READ.
