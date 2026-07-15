# Agent D — Padding & Cover-Traffic Analysis (RQ3)

_Author: Agent D (padding / anonymity-systems). Analysis only; no code changed. Reuses the
102-paper matrix and `bibliography.bib` from `research/ack_timing_normalization/`; adds no new
works (the corpus is complete for padding — see §7). Labels per GROUNDING §17: **[M]** measured ·
**[S]** standard · **[V]** vendor · **[P]** paper-reported (all at **abstract/landing-page level**;
no full texts read) · **[I]** inference · **[H]** hypothesis. A plain-language line follows each
technical block._

---

## 0. Verdict up front

**For the current byte-preserving phase there is NO safe DNP3 padding.** All nine padding
categories collapse into three outcomes:

1. **Modify DNP3 bytes / object counts / CRCs** → forbidden by the phase rule, and would require a
   CRC recompute and (for controls) actually operating equipment. [S][I]
2. **Rejected by outstation semantics** → our measured negative: invalid-index CROBs draw
   `OUT_OF_RANGE(12)`/`TOO_MANY_OPS(8)` and a partial SELECT blocks OPERATE, so the padding is not
   insertable and each rejected index leaks on the wire. [M]
3. **Not actually padding** → delayed-release (category 9) adds no bytes; it is timing
   normalization, and it does **not** touch the size leak.

Only **one** category — **tunnel/encrypted-envelope padding (category 5)** — can defeat the
measured size leak (CROB count, 14.6 B/CROB, R²=0.9999), and it is **FUTURE** work: it needs
cooperating tunnel endpoints and it pays a bandwidth cost. Every website-fingerprinting (WF),
mix-network, and cover-traffic mechanism in the literature shares one invariant — **padding means
adding bytes or packets** — which is exactly what the phase rule and DNP3's CRC/length/framing
integrity forbid in-band. Their **objectives** transfer to DNP3; their **mechanisms** do not,
except inside a tunnel.

**Do not claim padding is solved. It is not.** The size leak on small control responses is a
residual with no current-phase defense.

_Plain-language: hiding message size needs extra bytes, and we are not allowed to add any. We
tried the one in-protocol trick (fake points) and the outstation rejected it. The only clean way
to pad is to wrap DNP3 in an encrypted tunnel and pad the tunnel — that is future work and both
ends must cooperate._

---

## 1. What the anonymity / WF / cover-traffic literature actually teaches

The corpus splits padding defenses into a small number of regimes. All are **[P]**, abstract-level.

**(a) Constant-shape (the provable ceiling).** BuFLO/Peek-a-Boo [`dyer2012peekaboo`], Tamaraw
[`cai2014systematic`], CS-BuFLO [`cai2014csbuflo`] transmit fixed-size units at a fixed rate,
padding real traffic up to a constant envelope. This is the **only regime that provably closes the
total-size channel** (the observer sees a secret-independent shape), and it is the most expensive —
you pad to the peak continuously. This is the theoretical target for hiding CROB count, and it is
byte-adding by construction.

**(b) Target-distribution matching (cheaper, leaky).** Traffic Morphing [`wright2009traffic`]
convex-optimizes one class's packet-size distribution to look like another; Surakav
[`gong2022surakav`] regulates real traffic to follow a GAN-generated decoy trace; Walkie-Talkie
[`wang2017walkietalkie`] molds bursts into supersequences so pages **collide** into one anonymity
set. The **objective** (declare a target distribution / anonymity set and match it) is precisely
what we would want for CROB-count classes; the **mechanism** pads sizes and adds dummy packets.

**(c) Adaptive / zero-delay padding.** WTF-PAD [`juarez2016wtfpad`] and the Shmatikov–Wang adaptive
padding it descends from [`shmatikov2006timing`] fill inter-packet gaps with dummies statistically,
adding **no latency**; FRONT/GLUE [`gong2020front`] add zero-delay dummy packets. Attractive
(no delay) but still **byte/packet-adding**, and broken by deep classifiers (Deep Fingerprinting
[`sirinam2018deepfingerprinting`], and Tik-Tok [`rahman2020tiktok`] shows timing alone suffices).

**(d) Cover traffic / link padding.** Loopix [`piotrowska2017loopix`] (Poisson cover loops),
dependent link padding [`wang2008dependent`] (O(log m) covering rate for full indistinguishability
of m flows), Stop-and-Go mixes [`kesdogan1998stopandgo`], Fuzzy Time [`hu1991fuzzytime`] — the
formal home of the "cover traffic / decoy transaction / silence hiding" categories. Cover traffic is
the **most bandwidth-expensive per unit privacy** and hides *which/when*, not the size of a given
message.

**(e) Formal privacy-vs-overhead framings (reusable as goals).** Pacer [`mehta2022pacer`] —
"shape independent of the secret," done outside the guest; NetShaper [`sabzi2024netshaper`] —
**differential-privacy** traffic shaping in a middlebox **tunnel** with a tunable
privacy/bandwidth/latency budget. These are the right objective functions for our Pareto analysis
and they both live in a **tunnel**, which is the key architectural tell.

**(f) In-network / line-rate precedent.** ditto [`meier2022ditto`] pads packets + injects chaff on
an Intel Tofino at 100 Gbps — the closest platform precedent, and explicitly **not
byte-preserving**. It is a mechanism template only **inside a tunnel**; run in-band on cleartext
DNP3 it corrupts frames.

**(g) The one byte-preserving obfuscator in the corpus is NOT padding.** Random Segmentation
[`alyami2023random`] splits TCP segments into random-sized chunks with **no dummy bytes** — the
direct analog of our CRC-boundary split. It reshapes the *size distribution* but **does not change
total bytes**, so it does not defeat a total-size leak. This is the sharpest lesson: **the only
byte-preserving size tool in the literature is split, and split cannot hide total size.**

_Plain-language: every padding trick in the privacy literature works by adding bytes or dummy
packets. The one exception (random segmentation) is really splitting, and splitting still can't hide
how big the whole thing is. So the useful part we can borrow is the goals, not the machinery._

---

## 2. The nine padding categories — feasibility, cost, and the size leak

**Reference leak (all quantitative overheads below are anchored to this [M]):** the SELECT/OPERATE
response grows **14.6 B/CROB, intercept 22.5 B, R²=0.9999**, i.e. 37 B (N=1) → 256 B (N=16). To
hide N by constant-shape padding, every control response must be inflated to the class maximum. For
N=1→N=16 that is **+219 B on the SELECT response and +219 B on the OPERATE response (~+590% each)** —
a concrete bandwidth floor for any padding scheme that closes this leak.

| # | Category | Byte-preserving? | Phase | Requires | Overhead (bw / pkt / latency) | Defeats the measured SIZE leak? |
|---|----------|------------------|-------|----------|-------------------------------|---------------------------------|
| 1 | Semantic DNP3 padding (add real objects/CROBs) | **No** — adds app bytes, changes object count, needs CRC recompute | **FUTURE**; **control-plane = unsafe** | Endpoint/proxy rebuilds frames; on controls, extra CROBs = extra real operations | +bw up to class-max (≈+590% to reach N=16); +CRC-block pkts if also split | **Yes** if padded to a fixed class-max (constant-shape) — but only safely on the **read plane** with genuinely inert points; on controls it operates equipment |
| 2 | Valid dummy / inert DNP3 objects | **No** — adds bytes + CRC recompute | **FUTURE** | Outstation/gateway must *expose* inert read-only points (endpoint cooperation) | Same bw class as (1); no extra latency if response already generated | **Partially** — hides count only if decoy points are indistinguishable from real ones; **[H]** inert points may stay distinguishable (static/never-eventing values), shrinking the anonymity set. No inert *CROB* exists that operates nothing |
| 3 | Invalid-object padding (nonexistent/malformed) | No | **DEAD END [M]** | — | — | **No.** Measured: `OUT_OF_RANGE(12)` per index, `TOO_MANY_OPS(8)` past `maxControlsPerRequest`, partial SELECT blocks OPERATE → not insertable; each rejected index leaks on the wire; a Zeek `dnp3`/spec IDS flags malformed frames [`lin2013adapting`] |
| 4 | Padding outside the DNP3 message (extra bytes in the TCP stream) | DNP3 bytes yes, but injects non-DNP3 bytes | **FUTURE**; framing-unsafe | Active in-path proxy | +bw arbitrary; **risk: master's `FrameReader` parses the junk as the next frame → desync / parse error** | No, unless the injected bytes are themselves valid DNP3 (→ becomes cat 1/2) or the whole thing is a tunnel (→ cat 5) |
| 5 | **Tunnel / encrypted-envelope padding** | **Yes for DNP3** — inner bytes untouched; padding lives in the envelope | **FUTURE** | Cooperating tunnel endpoints (master↔outstation, or gateway pair): TLS/IPsec/WireGuard | Depends on shaping regime: constant-rate (BuFLO-like) = high, continuous pad-to-peak; **DP shaping [`sabzi2024netshaper`] = tunable**; adaptive = low-bw but leaky. Latency ≤ shaping budget | **Yes — the only category that can cleanly close the TOTAL-size leak** (incl. CROB count), because it pads total volume to a secret-independent shape and is invisible to a DNP3 parser/IDS |
| 6 | Cover traffic / decoy transactions | No — injects whole fake transactions | **FUTURE**; **control decoys = unsafe** | Cooperating master/gateway to emit decoy **reads** (decoy *controls* forbidden — they operate equipment) | Highest bw per unit privacy (Loopix loops [`piotrowska2017loopix`]; dependent-link O(log m) [`wang2008dependent`]) | **Only statistically** — hides *which/when* a transaction occurs, not the size of a given one; a per-response size leak persists unless combined with per-response padding |
| 7 | Packet-count padding | Adding DNP3-bearing pkts = cat 1/2; non-DNP3 pkts = cat 4; TCP artifacts = active manip | **Partial NOW via split (up-only); independent padding FUTURE + proxy** | Split (now) increases pkt/segment count byte-preservingly; independent packet padding needs a proxy | Split: measured 2407 B → 301 pkts at bpc=1, **0 added bytes** [M]. Spurious injected segments look like retransmits = loud tell | **No** — split raises packet count without changing total bytes; independent packet padding does not address per-response *size* |
| 8 | Silence hiding (fill idle gaps) | No — injects filler traffic | **FUTURE** | Cover traffic during silence (keepalives = transport-level & detectable; real DNP3 filler = decoy reads → cat 6) | Continuous low-rate fill; cheap in bytes if keepalive-only but then non-DNP3-detectable | **No** — targets the silence/activity observable (Axis 2), not per-response size |
| 9 | Timing-only delayed-release "padding" | **Yes** — adds no bytes | **CURRENT** (bounded sub-RTO hold) | Release scheduler `max(ready, deadline)` [`askarov2010predictive`] | 0 bytes; latency ≤ hold budget (< effective TCP RTO) | **No** — this is **timing normalization, not padding**; it hides *when*, never *how big*. Keep it distinctly labeled so nobody claims "we padded" when they only delayed |

_Plain-language, per row: (1) can't fake breaker operations — they'd operate breakers; (2) inert
decoy points can be padded in only if the device actually has them, and a patient attacker may spot
that they never change; (3) tried it, rejected, dead end; (4) shoving extra bytes into the stream
confuses the master's parser; (5) wrap DNP3 in an encrypted tunnel and pad the tunnel — the clean
future answer; (6) fake reads are OK if a real master sends them, fake controls are not; (7)
splitting gives you more packets for free but not more total bytes; (8) keep the line busy hides the
rhythm, not the size; (9) waiting is not padding._

---

## 3. Does anything close the measured SIZE leak? (summary)

| Closes CROB-count / total-size leak? | Categories |
|---|---|
| **Yes, cleanly** | **(5) tunnel/envelope padding only** — and it is FUTURE + needs endpoints |
| **Partially / conditionally** | (1)(2) read-plane constant-shape padding (needs inert points, distinguishability caveat, never on controls); (6) statistically only |
| **No** | (4)(7)(8) address other axes; (9) is timing not size |
| **Dead end [M]** | (3) invalid-index |

**None is both byte-preserving AND current-phase-safe against the size leak.** This is the study's
core asymmetry, and it is honest to state plainly: **timing is closeable now (category 9 / timing
normalization); size is not.** [M][I]

_Plain-language: only the tunnel actually hides size, and it's future work. Right now, size stays
exposed._

---

## 4. Ranked FUTURE padding architectures (safety first, then overhead)

1. **Encrypted tunnel with shaped padding** (TLS / IPsec / WireGuard carrying DNP3, padded in the
   envelope). **Safest and most complete.** DNP3 bytes untouched → no CRC recompute, transparent to
   a `dnp3` spec IDS; can close **size + timing + total-volume + silence** in one place. Overhead is
   a **dial**: constant-rate (BuFLO/Tamaraw envelope [`dyer2012peekaboo`,`cai2014systematic`]) =
   strongest, pad-to-peak bandwidth; **DP shaping (NetShaper [`sabzi2024netshaper`]) or
   secret-independent shaping (Pacer [`mehta2022pacer`]) = tunable** privacy/overhead; ditto
   [`meier2022ditto`] is the in-network/line-rate mechanism template *inside* the tunnel. **Cost:**
   both ends (or a gateway pair) must run the tunnel; the observer must not sit inside it. **This is
   the recommended future direction.**
2. **Gateway / RTAC exposing valid inert *read-plane* points**, padded to fixed size classes
   (constant-shape on the read plane). No tunnel needed, but **[H]** inert points may remain
   distinguishable (static values, no events), yielding a smaller anonymity set than a tunnel.
   **Read-plane only — never for controls.**
3. **Read-plane decoy transactions (cover traffic)** from a cooperating master/gateway (extra
   integrity polls / decoy reads). Hides transaction pattern and silence; **highest bandwidth per
   unit privacy** [`piotrowska2017loopix`,`wang2008dependent`]; does **not** close a per-response
   size leak by itself. Read-plane only (no decoy controls).
4. **Active in-path proxy doing out-of-message / packet-count / transport padding.** Lowest: needs a
   MITM proxy (forbidden now), risks `FrameReader` desync and retransmit-like tells, and a spec IDS
   may flag non-DNP3 bytes. Least safe, least clean.

**Explicitly not recommended in any future phase:** adding real or invalid CROBs to a **live SBO**
(semantic/invalid padding on the control plane) — it either operates equipment or trips
`OUT_OF_RANGE` and blocks the real OPERATE (measured [M]).

_Plain-language: tunnel first (it's the real fix), then a gateway with genuinely inert read points,
then fake reads, and only as a last resort a proxy that pads outside DNP3. Never pad control
commands._

---

## 5. Transfer verdict — which anonymity ideas survive to DNP3

**Transfer (as OBJECTIVES, realizable only in a tunnel — category 5):**
- **Anonymity set / k-anonymity** — Walkie-Talkie collisions [`wang2017walkietalkie`], DecIED
  k-anonymous decoys [`yang2020decied`].
- **Target-distribution matching** — Traffic Morphing [`wright2009traffic`], Surakav decoy trace
  [`gong2022surakav`].
- **Secret-independent shape** — Pacer [`mehta2022pacer`].
- **Differential-privacy budget** — NetShaper [`sabzi2024netshaper`].
- **Constant-shape upper bound** — BuFLO/Tamaraw [`dyer2012peekaboo`,`cai2014systematic`].

**Do NOT transfer (as in-band MECHANISMS on cleartext DNP3):** every one adds bytes/packets and so
breaks DNP3 CRC/length/framing or trips a spec IDS [`lin2013adapting`] — WTF-PAD/FRONT/GLUE dummy
packets [`juarez2016wtfpad`,`gong2020front`], adaptive padding [`shmatikov2006timing`], cover-traffic
loops [`piotrowska2017loopix`], chaff injection [`meier2022ditto`]. They become usable only once the
bytes they add live in a tunnel envelope rather than in a DNP3 frame.

_Plain-language: borrow the goals (make devices look alike, match a target shape, bound the leak
with a privacy budget); throw away the machinery (adding packets), because on bare DNP3 it corrupts
the protocol. The machinery comes back only inside a tunnel._

---

## 6. Caveats / integrity

- **One device, one OpenDNP3 build.** The invalid-index negative (§2 cat 3) is this
  build/host/config only [M]; other stacks may reject differently but the conclusion (per-index
  rejection is visible, partial SELECT blocks OPERATE) is protocol-grounded [S][I].
- **CROB-count size leak ≠ database-size leak.** The 14.6 B/CROB result is the control-plane
  CROB-count sweep; the ~5.7 B/analog-point relationship is the separate read-plane size leak. Do
  not conflate.
- **Distinguishability of inert decoy points (§2 cat 2, §4 rank 2) is [H], not measured.** A future
  phase must measure whether a profiling attacker can separate inert from live points.
- **Padding is not solved.** The current phase has no safe padding; even the best future option
  (tunnel) trades bandwidth for privacy and requires endpoint cooperation and an out-of-tunnel
  observer.

---

## 7. New works

**None.** The 102-paper matrix and `bibliography.bib` already contain the full padding /
cover-traffic / mix-network / DP-shaping / in-network-obfuscation corpus this analysis needs
(BuFLO, Tamaraw, CS-BuFLO, WTF-PAD, FRONT/GLUE, Walkie-Talkie, RegulaTor, Surakav, Traffic Morphing,
adaptive padding, dependent link padding, Loopix, Stop-and-Go, Fuzzy Time, Pacer, NetShaper, ditto,
NetWarden, Random Segmentation, DefRec, DecIED, HoneyPLC). A targeted search for a **DNP3/ICS-specific
byte-preserving padding or cover-traffic defense** returned none — consistent with the study's gap
statement. Adding rows would bloat the matrix without value, so `## NEW_PAPER_MATRIX_ROWS` and
`## NEW_BIBTEX` are intentionally empty.

## NEW_PAPER_MATRIX_ROWS
(none)

## NEW_BIBTEX
(none)
