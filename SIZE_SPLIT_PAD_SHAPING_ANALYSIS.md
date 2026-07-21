# Splitting vs. Padding vs. Ditto-style shaping — security properties & Tofino feasibility

_Research note, 2026-07-21, `research/caseA-ditto-queue`. Consolidates: a security-property /
related-work review, an SDN/P4 feasibility review, and a wire-overhead quantification on the
project's real numbers. Grounded in the Ditto PDF (read directly), the Formby PDF, and the
literature cited at the end. Feeds the paper's Design + Related-Work + the size-vs-timing split._

## Thesis (project lead) — what this note verifies
Splitting, padding, and Ditto-style shaping give **different** security properties. Splitting
preserves the DNP3 payload but changes segmentation and does **not** hide total volume (and adds
header overhead); padding changes per-packet size but hides neither packet count nor total volume;
Ditto combines size states + fixed-rate scheduling + chaff so the observed pattern is independent of
real traffic. General in-network TCP payload splitting is not practical on Tofino. **Therefore:**
software splitting stays a segmentation-obfuscation *feasibility study*; the Tofino uses **padding**
for size and **queue scheduling** for timing; a complete Ditto-inspired design later adds
size-labelled slots + padding + scheduling + (where required) chaff.

## Bottom line
**All three security claims are correct** (verified against first principles + literature). Two
refinements the research adds:
1. **Feasibility correction — checksum is NOT the blocker.** In the "why splitting is impractical"
   list, checksum recompute is feasible on Tofino (there is a `Checksum` extern; `p4_decoy` and
   GridCloak already recompute IP+TCP checksums on a DNP3 response on-chip). The **true** blockers
   are (i) **payload opacity**, (ii) **non-constant-time splitting**, (iii) **proxy-grade TCP state**
   (below). Splitting fails because it needs a **TCP-terminating proxy**, not because of checksums.
2. **Security refinement — splitting is volume-*adverse*, not volume-neutral.** It doesn't merely
   fail to hide volume; it **transduces** the response-size secret into two *other* observable
   channels — segment **count** (monotone in response size) and, if paced, intra-response
   **timing** — while inflating wire bytes 2–4×. As a standalone size defense it is, by the field's
   own coarse-feature yardstick (Dyer et al., S&P 2012), **close to useless**.

---

## 1. Feature-leakage matrix (the core result)

Passive on-path observer of **encrypted** DNP3/TCP (sees sizes, counts, timing, direction, ACK
behaviour — not payload). Key: **HIDES** = observable made independent of the secret · **PARTIAL** =
obscured only conditionally / secret re-encoded elsewhere · **LEAKS** = passes through unchanged ·
**INCREASES** = mechanism *adds* to this observable (worse than a passive leak).

| Mechanism | TCP vol | wire bytes | pkt count | per-pkt size | segmentation | timing / CLRT | ACK mode | dir |
|---|---|---|---|---|---|---|---|---|
| **SPLITTING** (byte-preserving) | LEAKS (Σ segments = original) | **INCREASES** (~54 B/extra seg) | **INCREASES** (count ∝ size) | PARTIAL (many equal small blocks) | PARTIAL (new seg + a split signature) | PARTIAL (only if paced) | LEAKS | LEAKS |
| **PADDING** (per-pkt → target) | INCREASES (adds bytes) | INCREASES | LEAKS (count unchanged) | **HIDES** (common target size) | LEAKS | LEAKS | LEAKS | LEAKS |
| **DITTO** (states + rate + chaff) | **HIDES** (§VII-A) | HIDES (constant pattern; *at chaff cost*) | HIDES (chaff fills slots) | HIDES (pattern states) | HIDES | HIDES (IPG ⟂ input, Fig 8) | PARTIAL→HIDES | HIDES |
| **TIMING queue** (byte-preserving hold/release) | LEAKS | LEAKS (adds none) | LEAKS | LEAKS | LEAKS | **HIDES** (PARTIAL if fixed-offset) | LEAKS | LEAKS |

**Reading:** only **Ditto** turns the whole row to HIDES — and only because it spends **chaff + a
fixed schedule**, both of which violate byte-preservation. The two byte-preserving mechanisms
(**splitting**, **timing queue**) each neutralize **at most one** channel and leak the rest.
**Splitting is the only mechanism that scores INCREASES on three columns.**

## 2. Wire-overhead quantification (project's real numbers)
Byte-preserving CRC-split into `N` segments adds `(N−1)×54 B` of Eth+IP+TCP headers **plus** `N−1`
packets. Total payload is exactly recoverable (Σ segment payloads = original, by construction).

| Response | → N chunks | wire footprint | extra packets |
|---|---|---|---|
| SEL-751 54 B | 3 | **2.0×** (108→216 B) | +2 |
| mid 292 B | 16 | **3.3×** (346→1156 B) | +15 |
| large 2407 B | 141 | **4.1×** (2461→10021 B) | +140 |

So against a volume/count observer, splitting makes the device **more** distinguishable — it grows
both total wire bytes and packet count, and both are fingerprint features. Its only genuine effect
is scrambling the fine-grained **segmentation** sequence.

## 3. Why in-network splitting is infeasible on Tofino-1 (feasibility)
Requirement-by-requirement (Ditto §III p3; TNA/bf-p4c):

| Requirement | Tofino-1? | Why |
|---|---|---|
| Generate N packets from 1 | Partial | clone/mirror/recirc make **identical copies**; not different payload slices |
| **Partition arbitrary payload at runtime offset** | **NO — blocker** | Ditto §III: payload "cannot be modified"; pipeline can't address byte *k* of the payload |
| **Variable segment count / data-dependent cut** | **NO — blocker** | Ditto §III: "loops, splitting or merging packets" are "not possible"; fn2: "fragmentation is often not available on switches" |
| Rewrite TCP seq/len per segment | Arithmetic OK, unusable | seq rewrite runs at line rate, but the correct value depends on the (impossible) cut offset |
| Recompute TCP/IP checksum | **YES — not a blocker** | `Checksum` extern + Class-6 guarded-add; `p4_decoy`/GridCloak already do it on a DNP3 response |
| Preserve end-to-end TCP state | **NO — compounding** | switch is not a TCP endpoint; re-splitting under retransmit/SACK needs proxy-grade buffering |

**The padding↔splitting asymmetry (key structural result).** *Padding* adds a **compile-time-constant**
filler — just another header the deparser already knows to emit, real payload untouched (byte-identical
residual); the only runtime unknown is a cumulative seq-space Δ (`seq+=Δ`/`ack−=Δ`). Because DNP3 is a
stream of self-delimiting link frames, a constant filler **prepended** is equivalent to a trailer,
dissolving the "can't emit after payload" crux. *Splitting* must **read, cut, and redistribute the
variable, opaque, runtime payload** at runtime-chosen offsets into a runtime-variable number of
packets. **Padding needs the deparser; splitting needs a TCP-terminating proxy.** That is exactly why
the Tofino normalizes size by **padding** and controls timing by **queue scheduling**.

**Novelty:** no in-network (P4/switch) packet-*splitting* work exists in the literature. The
segmentation-obfuscation papers (Random Segmentation, arXiv 2309.05941; Adaptive Segmentation, IEEE
2024) split at the **endpoint's TCP socket** (which owns TCP state); Ditto/PINOT/SPINE only pad or
rewrite headers. So in-network re-segmentation is **both unoccupied and infeasible** on this target —
segmentation obfuscation belongs to the endpoint. (In-network MSS clamping can coarsely cap *future*
segment sizes but cannot re-segment a *specific* response.)

## 4. The boundary result — volume/count independence requires cover traffic
Making the observable pattern **independent of the real traffic** is achievable **only by adding
dummy/cover traffic**. Ditto states it verbatim: the transmitted volume is *"static and independent
from the real traffic"* (§VII-A, p6), and the **chaff** is what makes it work — round-robin "skips an
empty queue," which would break the pattern, so every pattern state gets a real (high-prio) queue
**and** a chaff-flooded (low-prio) queue so it is "never empty" (§VI, p6). Fixed-rate scheduling alone
decouples **timing** from availability; **chaff** additionally decouples **volume and count**. Every
defense that reaches this independence — **BuFLO, CS-BuFLO, TARANET, Walkie-Talkie, Ditto** — adds
bytes/dummies. **No byte-preserving mechanism can reach it** (Dyer et al., *Peek-a-Boo*, S&P 2012:
coarse total-volume/count features defeat all padding-only defenses). This is a **boundary, not an
engineering gap.**

**Consequence for us (byte-preservation constraint):** we can close the **timing** channel with the
byte-preserving **timing queue**, but we **cannot** close the **size** channel without byte-modifying
**padding**, and we cannot reach full **volume/count** independence without **chaff**.

## 5. Related-work positioning (for the paper)
- **Add cover traffic → can equalize volume/count:** BuFLO (Dyer, S&P 2012), CS-BuFLO (Cai, WPES
  2014), TARANET (Chen, EuroS&P 2018 — its packet splitting is *paired with* constant-rate chaff,
  never standalone), Walkie-Talkie (Wang & Goldberg, USENIX Sec 2017), Ditto (Meier, NDSS 2022).
- **Pad per packet only → defeated by coarse features:** pad-to-MTU; Traffic Morphing (Wright, NDSS
  2009 — *flagged unverified*). Refutation: Dyer et al., S&P 2012.
- **"Segmentation obfuscation" (splitting without padding) is recognized nowhere as a size defense.**
- **In-network line — cite carefully:** of the "in-network" trio, **only Ditto** shapes size/timing.
  **iTAP** (Meier, SOSR 2017) is flow-unlinkability header rewriting; **NetHide** (Meier, USENIX Sec
  2018) is topology obfuscation. Cite iTAP/NetHide for *positioning* ("in-network obfuscation on
  programmable switches"), **not** as size/timing baselines.

## 6. Implications for our design (confirms the thesis)
- **Part 2 (timing, now):** byte-preserving **timing queue**, releasing to a **bounded /
  device-independent** target (a *fixed* offset just shifts the CLRT mean and the distribution shape
  still classifies — Formby classifies the CLRT *distribution over a window*, not one gap). This
  closes the CLRT channel and nothing else.
- **Part 1 (size, later):** **padding** (byte-modifying, prepend + seq-Δ) for per-packet size / total
  size normalization — the Tofino-feasible size knob. Splitting stays a **software** (endpoint-owned)
  feasibility study; it is not the deployed size mechanism.
- **Complete Ditto-inspired design (future):** size-labelled transmission slots + padding + queue
  scheduling + **chaff** — chaff being the explicit price of **volume/count** independence, which no
  byte-preserving mechanism can buy. Do not add full chaff before the minimal timing design works
  (master direction §13).

## Citations
Verified this session unless flagged. Formby et al., *Who's in Control of Your Control System?*,
NDSS 2016 [repo PDF]. Meier, Lenders, Vanbever, *ditto*, NDSS 2022 [repo PDF, §VI/§VII-A p6]. Dyer,
Coull, Ristenpart, Shrimpton, *Peek-a-Boo, I Still See You*, IEEE S&P 2012. Cai, Nithyanand, Johnson,
*CS-BuFLO*, ACM WPES 2014 [3rd author from memory]. Chen, Asoni, Perrig, Barrera, Danezis, Troncoso,
*TARANET*, IEEE EuroS&P 2018. Chen, Asoni, Barrera, Danezis, Perrig, *HORNET*, ACM CCS 2015 [not
re-verified]. Wang, Goldberg, *Walkie-Talkie*, USENIX Sec 2017. Meier, Gugelmann, Vanbever, *iTAP*,
ACM SOSR 2017. Meier, Tsankov, Lenders, Vanbever, Vechev, *NetHide*, USENIX Sec 2018. Wright, Coull,
Monrose, *Traffic Morphing*, NDSS 2009 [NOT re-verified — confirm before citing]. In-network
splitting prior art: PINOT (arXiv 2006.00097), Random Segmentation (arXiv 2309.05941), Adaptive
Segmentation (IEEE 2024). _Unverified flags: NetWarden line-rate seq/ack and on-chip checksum
recompute cited from repo docs; padding's runtime-Δ TCP-checksum carry sits in the bf-p4c Class-6
zone, unproven until first compile._
