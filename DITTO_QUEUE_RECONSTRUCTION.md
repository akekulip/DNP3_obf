# DITTO_QUEUE_RECONSTRUCTION.md — Source-grounded reconstruction of Ditto's queue design

_Master direction Phase 2 / §5A. Produced 2026-07-21 on branch `research/caseA-ditto-queue`._

**Source:** Roland Meier, Vincent Lenders, Laurent Vanbever, *"ditto: WAN Traffic Obfuscation at
Line Rate,"* NDSS 2022. Read in full (17 pp.) from the repository copy
`2022_NDSS_ditto WAN Traffic Obfuscation at Line Rate.pdf`. Page numbers below are the paper's
own printed page numbers. Open-source: https://github.com/nsg-ethz/ditto.

> **★ NON-DETERMINISM CAVEAT (master direction §5A, meeting §9) — read first.**
> Ditto does **not** provide exact deterministic per-packet delay. The paper states plainly that
> today's switch shapers hold their configured rate only **"on average,"** and that **bursts of
> too much traffic lead to dropped packets** (§IX-B, p9). The round-robin scheduler follows the
> pattern **"on average, not necessarily in microscopic detail"** (§IX-C, p11), and the residual
> scheduling error **"originates from the approximation of the 2-level hierarchical queueing and
> [the] required precise rate-control, which is more error-prone for small packets"** (§IX-C,
> p12, Fig 9). **Therefore any DNP3 queue timing built on this mechanism must be measured on our
> own Tofino, not assumed from the paper** (this is Phase 4). Every claim that Ditto's queue is
> "predictable" is an *average-case* claim with a measured error term, never a per-packet
> guarantee.

---

## 1. What Ditto is (one paragraph)

Ditto is an **in-network, data-plane** traffic-obfuscation system for WAN links. It shapes the
outgoing traffic of a link so that its **packet sizes, inter-packet timing, and volume become a
fixed, repeating pattern that is independent of the real traffic** underneath. It does this with
three data-plane operations — **packet padding, packet delaying, and chaff (dummy) packet
insertion** — running entirely on off-the-shelf **programmable switches (Intel Tofino)**, with
**no changes to end hosts** (§I, p1–2; Fig 1). It targets a passive WAN eavesdropper and provides
three security goals: **volume anonymity, timing anonymity, path anonymity** (§II-C, p2–3).

This is the mechanism Dr. Lin wants adapted — Ditto's **queue-and-schedule** shaping — as a more
defensible alternative to our current **recirculation-until-event/deadline** timing mechanism for
DNP3 Case A. Ditto is *size+volume* shaping for high-rate WAN aggregate; our problem is *timing*
control for a low-rate DNP3 request/response transaction. The mapping (what transfers, what does
not) is in `DITTO_TO_DNP3_MAPPING.md`.

---

## 2. The 14 required explanations (master direction Phase 2)

### 2.1 What a Ditto "pattern" is
An **obfuscation pattern** `P = [P_0, P_1, …, P_{L-1}]` is an **ordered list of `L` packet sizes
(the "pattern states")** that the protected link emits **repeatedly and infinitely at a fixed
rate** (§IV "Architecture," p3; §V eqn (1), p5). Example: pattern `[500,1000]` makes the outgoing
sizes `[500,1000,500,1000,…]` at a constant rate (§IV, p3). The `j`-th outgoing packet is padded
to size `P_{j mod L}` (§V, p5). Because the pattern is **static and independent of the real
traffic**, an attacker learns nothing from it beyond the (public) link capacity (§VII-A "Volume
anonymity," p6). Patterns of **length L = 3–6** give good results across all metrics (§IV, p4;
§V, p5).

### 2.2 How pattern states are chosen
The pattern is computed **offline in Python** from the **expected packet-size distribution `D`**
of the link (§IV "Architecture," §VIII, p7). The state values are set at percentiles of `D`:

> `P_i = percentile_{(i+1)·100/L}(D)`,  for `i ∈ {0,…,L-1}`  — eqn (2), §V, p5.

so each state carries ~`100/L`% of packets (uniform load per state → minimal average padding).
`D` is recorded from real traffic beforehand (or taken from public data); it "usually reveals only
average traffic characteristics" so it "is usually not confidential." If `D` drifts, the operator
**recomputes and hot-swaps the pattern without interrupting the switch** (§V "When to compute…,"
p5); Fig 13 shows the same pattern stays efficient for **10 months** (§IX-D, p13).

### 2.3 How real packets are assigned to a pattern state
Ditto can only make packets **larger** (it cannot split — §III, non-constant-time ops are
impossible, p3; §IV footnote 2, p4). So each real packet of size `s` is assigned to the
**next-larger** state — the one requiring **minimal padding**:

> `i = argmin_i (P_i − s | s ≤ P_i)`  — eqn (3), §VI, p6.

Ties (equal padding to two states) are broken randomly (§VI, p6). Example: an 800 B packet with
pattern `[500,1000,1500,1500]` is assigned to state `1000` and padded by 200 B (§IV, p4; §V, p5).

### 2.4 Why each pattern state has a real queue AND a chaff queue
Plain round-robin scheduling has a fatal property for Ditto: **it skips a queue that is empty**,
which **skips a pattern state and breaks the pattern** (§VI "Round-robin scheduling," p6). Ditto's
fix is **hierarchical (2-level) queueing**: for **each** pattern state `P_i` there is a **pair of
priority queues** — a **high-priority queue `q_{i,r}` for real packets** and a **low-priority
queue `q_{i,c}` flooded with chaff packets** (§IV, p4; §VI "Priority queuing…," p6). Because the
chaff queue is never empty, the scheduler **always has a packet of the right size to send for
every state**, so the emitted pattern never breaks. Priority guarantees a **real** packet is
preferred whenever one is available; chaff fills the slot only when no real packet is waiting (§IV,
p4; §VI, p6). Chaff packets are generated **"by continuously recirculating chaff packets and
cloning them into the low-priority queues"** (§IV, p4) — this needs one switch port for the chaff
recirculation loop but no dedicated traffic generator.

### 2.5 How priority scheduling works
Within a pattern state's pair, the two queues have **different priorities**: `q_{i,r}` (real) is
high, `q_{i,c}` (chaff) is low. The pair therefore emits a **constant stream of packets of that
state's size, preferring real over chaff** (§VI "Priority queuing to mix real and chaff packets,"
p6). This is the mechanism that lets Ditto **mix real and chaff without ever stalling a state**.

### 2.6 How round-robin scheduling works
The `L` per-state priority-pair outputs are fed into a **round-robin scheduler** across the `L`
queues of the egress port, configured with **equal priority** so the TM iterates queue-0, queue-1,
…, queue-`L-1`, queue-0, … sending **one packet from each non-empty queue per round** (§VI
"Round-robin scheduling to implement the pattern," p6; §III, TM strategies, p3). Because the queue
order matches the pattern order, the output stream **follows the pattern** `[P_0,P_1,…,P_{L-1}]`
repeatedly. Each pair outputs at **1/L of the port's total rate** so the concatenated output is a
constant-rate pattern (§IV, p4; §VIII, p7).

### 2.7 How the two-stage (2-level) hierarchy is approximated
The hardware TM does not natively provide the 2-level "priority-pair → round-robin" hierarchy, and
**it cannot inject a chaff packet into an empty round-robin slot** (§VIII "Approximating
hierarchical queueing," p7). Ditto approximates it by **sending each packet through the switch
data plane twice** (two queueing stages) — Fig 4:
- **Stage 1 (first pass):** the per-state **priority pairs** (high=real, low=chaff-flooded).
- **Stage 2 (second pass):** the **round-robin** over the stage-1 outputs, then egress.
The stage-1 outputs are physically **fed back into the switch via loopback ports** to be processed
a second time (§VIII, p7; Fig 4, p8).

### 2.8 Why loopback ports are used
Loopback ports are the physical means of the **two-pass** architecture (§2.7): the output of the
first queueing stage is looped back into the pipeline for the second stage (§VIII, p7). The rate
math:
- each priority-pair transmits **1/L of the port rate** (e.g. 10 Mpps aggregate, L=4 → 2.5 Mpps
  per pair; §VIII, p7);
- per-loopback-subport bandwidth: `bw = 100 (L=1), 50 (L=2 or 3), 25 (L≥4)` Gbps — eqn (4), p7
  (a 100 G QSFP port splits into 2 or 4 sub-ports at 50/25 G);
- number of loopback ports: `n = ⌈L·bw/100⌉` — eqn (5), p7. **Patterns of length 3 and 6 need 2
  loopback ports per obfuscated port** (§VIII, p8). A 64-port switch → ~20 obfuscated WAN links.

### 2.9 Which packets use recirculation (distinct from loopback!)
Two different uses, do not conflate them:
1. **Chaff generation:** chaff packets are **continuously recirculated and cloned** into the
   low-priority queues (§IV, p4) — a permanent background loop.
2. **Padding overflow:** the switch can add only **≤254 B of padding per pipeline pass** (limited
   by PHV + deparser). If a packet needs more padding than that, it is **recirculated** (sent
   through the pipeline again) to add another ≤254 B (§VIII "Recirculate packets if needed," p8).
   Removing padding at the receiver can likewise require recirculation (§VIII, p8).
Recirculation **increases reordering and delay and can cause drops** (its bandwidth is capped,
default two 100 G ports), so Ditto **minimizes the number of recirculations** — see the measured
counts in §4 below (§VIII p8; §IX-B p10).

### 2.10 What is performed in the ingress pipeline
Per Fig 3/4 and §VIII (p7): (i) parse the IP header; (ii) determine the **egress port** from the
destination; (iii) check whether that egress port is **one Ditto obfuscates**; (iv) check whether
the packet is **real vs chaff**; (v) **assign it to the right queue** (the minimal-padding pattern
state, eqn (3)); and (vi) decide whether the needed padding **fits one pass or requires
recirculation**. The ingress also handles **queue selection** (Fig 3, "queue selection," p4).

### 2.11 What is performed in the Traffic Manager
The TM does the **buffering and scheduling**: it holds packets in the per-state **priority-pair
FIFO queues** and applies **priority (real>chaff) within a state** and **round-robin across
states** to emit the pattern (§III p3; §VI p6; Fig 3/4). This is where the **timing shaping**
physically happens — and where the **rate is only correct "on average"** (§IX-B, p9). The TM is
traversed **twice** via loopback (§2.7).

### 2.12 What is performed in the egress pipeline / deparser
After the TM has produced the correct **order** and each packet is marked with its **target size**,
the **egress pipeline adds the padding** to reach that size (§V p5; §VI p6). Padding is added as
**custom headers of sizes 32,16,8,4,2,1 B**, inserted largest-first to limit match-action-table
entries; the padded region is marked in the **EtherType** field so the **receiving Ditto switch
can strip it** and restore the original EtherType (§VI "Custom headers…/Removing padding," p6;
§VIII, p8). The packet is then encrypted (MACsec/IPsec) and leaves the port.

### 2.13 How rates are configured
- The obfuscated egress port runs at a fixed **total sending rate**; each of its `L`
  priority-pairs is configured to **1/L of that rate** so the round-robin output is constant-rate
  (§IV p4; §VIII p7).
- Loopback sub-port bandwidth follows eqn (4); loopback port count follows eqn (5) (§VIII p7).
- The **shaper rates are the load-bearing configuration** and the source of the "correct on
  average" error — this is exactly what Phase 4's microbenchmark must measure on our hardware.

### 2.14 What Ditto measured, and its reported limitations
See §4 (measured results) and §5 (limitations) below.

---

## 3. Source map (claim / section / page / passage-or-paraphrase / DNP3 relevance)

| # | Claim | § / page | Supporting passage (paraphrase unless quoted) | Relevance to our DNP3 Case A design |
|---|---|---|---|---|
| S1 | Ditto shapes traffic to a **fixed repeating pattern** independent of real traffic, via padding+delay+chaff | §I p1; Fig 1 | "ditto shapes traffic according to a predefined pattern (a periodic sequence of packet sizes at a fixed rate) using three instances: (i) packet padding; (ii) packet delaying; and (iii) chaff packet insertion." | The *delay* instance is the timing lever we adapt; the *pattern/rate* idea is Defense-2 "release response in a scheduled slot." |
| S2 | Runs **in-network on programmable switches, no end-host changes** | §I p1–2; §IV p3 | "ditto runs on the gateway network devices … and does not require any modification to the end hosts." | Matches our hard constraint: no SEL-751, master, TCP, or DNP3 modification (§meeting_direction §3). |
| S3 | Pattern = ordered size list repeated infinitely; **L=3–6** good | §IV p3–4; §V p5 | "We define it as an ordered list of packet sizes … ditto then repeats this pattern infinitely." / "patterns of length 3 to 6 achieve good results." | A DNP3 *timing* pattern would be a short list of **release slots**, not sizes — see mapping. |
| S4 | State selection by **percentile of size distribution**, eqn (2) | §V p5 | `P_i = percentile_{(i+1)·100/L}(D)` | For timing we would choose **slot offsets** from the SEL-751 **ACK-to-response readiness distribution**, not sizes. |
| S5 | Packets assigned to **next-larger** state, minimal padding, eqn (3); **cannot split** | §III p3; §IV fn2 p4; §VI p6 | `i = argmin_i(P_i − s | s ≤ P_i)`; "Since ditto can only make packets larger…" | Timing analogue: a response is assigned to the **next available release slot ≥ its readiness time** (monotone, never earlier — preserves ACK-before-response). |
| S6 | **2-level hierarchical queueing:** each state has real(high) + chaff(low) priority queues | §IV p4; §VI p6 | "For each pattern state, there is a pair of priority queues. A high-priority queue q_{i,r} … and a low-priority queue q_{i,c} which ditto floods with chaff packets." | The **priority-pair-never-empty** trick is why the schedule holds. For DNP3 we likely do **not** want chaff initially (meeting §8) — so we must handle the *empty-slot* problem differently (open question, Phase 3). |
| S7 | **Round-robin over states** emits the pattern; RR **skips empty queues** (the core problem chaff solves) | §VI p6 | "typical round-robin scheduling … skips a queue if it does not contain a packet. This is problematic … it leads to skipped states in the pattern." | Central design tension: a DNP3 slot with no real packet either emits chaff (Ditto's answer) or the slot is skipped (breaks a fixed schedule). Drives Phase-3 Question 1. |
| S8 | **Two-pass via loopback** approximates the hierarchy; eqns (4),(5) for loopback bw/count | §VIII p7–8; Fig 4 | "we implemented an approximation of hierarchical queueing, where a packet traverses two queueing stages … we achieve this by sending each packet through the switch data plane twice … fed back to the switch via loopback ports." | Loopback/2-pass is a **port-cost** we must budget on our shared switch; for a single low-rate DNP3 flow the port cost may be far smaller (mapping). |
| S9 | **Padding ≤254 B/pass**, else **recirculate**; recirc adds reorder/delay/drops | §VIII p8 | "ditto can add up to 254 B of padding in one pipeline pass … If the required amount of padding is larger … ditto recirculates the packet." | Confirms recirculation is a *cost*, not a virtue — supports Dr. Lin's preference to move timing off recirculation. Padding overflow is a **size**-obfuscation (Part 1) concern, not timing. |
| S10 ★ | **Shaper rate correct only "on average"; bursts → drops** | §IX-B p9 | "ditto relies on precisely controlled output rates … However, today's switches are typically not designed for that (they offer traffic shaping, but the rate is only correct 'on average'). In our case, bursts of too much traffic lead to dropped packets." | **The** load-bearing caveat: our queue timing target cannot be assumed deterministic; Phase-4 must measure variance, drops, drain behavior. |
| S11 | If packets are **not dropped**, Ditto has **no significant effect on jitter/RTT** | §IX-B p10; Fig 7 | "we highlight that ditto has no significant effect on timing-related metrics such as jitter and Round-Trip Time (RTT)" [when packets are not dropped] | Encouraging for a **low-rate** DNP3 flow (far from the drop regime): the queue may add little jitter — but must be measured. |
| S12 | Emitted **timing (IPG) independent of input rate**; attacker at ±3.2 ns can't distinguish 92–97% | §IX-C p11; Fig 8 | "the IPG does not depend on the input rate (the 11 lines … are overlapping)." | The *security* evidence that a scheduled output hides the native timing — the property we want for CLRT normalization (Defense 2). |
| S13 | Round-robin follows pattern **on average, not microscopic**; residual error from **2-level approximation + precise rate-control, worse for small packets** | §IX-C p11–12; Fig 9 | "Round-robin scheduling in today's switches is designed to follow round-robin behavior on average, not necessarily in microscopic detail." | DNP3 packets are **small** → the regime where Ditto reports the **largest** rate-control error. Direct warning for our Phase-4 measurement. |
| S14 | **Deep-Fingerprinting attack → random-guessing** accuracy under Ditto | §IX-C p12; Fig 10 | "the attack is unsuccessful on ditto-protected traffic: the accuracy is on-par with random guessing." | Template for our Phase-9 classifier eval (but ours is CLRT/timing on SEL-751, not website DF). |
| S15 | Recirculation **counts** measured; decrease with longer patterns | §IX-B p10 | "A pattern of length 1 requires 1.59 (CAIDA) or 0.99 (UNIFORM) recirculations on average. This … decrease[s] to 0.23 and 0.40 for a pattern of length 3 and 0.18 and 0.03 for length 6." | Quantifies recirc cost we compare our recirc-hold against (Phase 8). |

---

## 4. What Ditto measured (evaluation results, §IX)

**Setup (§IX-A, p9; Fig 5):** two Tofino switches (32×100 G), two proxy switches for timestamping,
two servers (Moongen generator + collector). Datasets: **CAIDA** (real Internet, Jan 2019, first
100 M IPv4 pkts), **CONSTANT** (1480 B, best case), **UNIFORM** (60–1480 B, worst case). A Python
**simulator** models "future hardware."

- **Throughput (§IX-B, p9; Fig 6):** outgoing rate is always 100 G; near-lossless until **~90 %
  (CONSTANT), ~70 % (UNIFORM), ~60 % (CAIDA)** input load. Ditto beats HORNET/TARANET/BuFLO even
  ignoring their compute overhead — because it pads to a *pattern* (not all-equal) and works
  *per-link* (not per-flow).
- **Recirculations (§IX-B, p10):** see S15 — 1.59→0.18 avg as L grows 1→6 (CAIDA); CONSTANT needs
  none.
- **Application performance (§IX-B, p10; Fig 7):** 50 runs per input rate; **no significant impact
  up to ~80 G** input; when packets are not dropped, **no significant jitter/RTT effect** (S11).
- **Timing independence (§IX-C, p11; Fig 8):** IPG distributions overlap across all input rates;
  IPG adjusted by eqn (6) `IPG = t1 − t0 + s0·8/(100·10⁹)`.
- **Round-robin fidelity (§IX-C, p12; Fig 9):** RMSE vs uniform distribution is small and **does
  not depend on input rate**; residual error from the 2-level approximation, **worse for small
  packets** (S13).
- **DF attack (§IX-C, p12; Fig 10):** random-guessing accuracy under Ditto (S14).
- **Future-hardware simulation (§IX-D, p12–13; Figs 11–15):** longer patterns → less chaff+padding
  overhead but **more buffer + switching delay + reordering**; **1 MB buffer** → 90 % (CAIDA)/99 %
  (UNIFORM) load; same pattern usable **10 months** at ~constant overhead; even fully loaded
  **<8 % of packets reordered** (≤47 % of flows have ≥1 reorder, mostly short flows); **92 % of
  packets stay in order at the highest load** (§IX-D, p13; Table I, p8).
- **Resource use (§VIII, p8):** main bottleneck is padding-per-pass (254 B, PHV/deparser-limited);
  SRAM/TCAM **< 10 % average over all stages**.

---

## 5. Limitations Ditto reports (its own words, §VII-B, §IX)

1. **Rate only correct on average; bursts drop packets** (S10, §IX-B p9). *The* limitation for us.
2. **Padding is expensive** (custom headers cost PHV + deparser resources); ≤254 B/pass, recirc
   for more, and recirc has capped bandwidth → drops under multiple recirculations (§VIII p8;
   §IX-B p9).
3. **Round-robin fidelity is average, not microscopic; error grows for small packets** (S13). DNP3
   packets are small — the adverse regime.
4. **Malicious insider / DoS** (§VII-B, p6–7): an insider who knows the pattern can estimate the
   real volume from its own probe traffic or force worst-case padding for a DoS; outside the
   threat model, mitigations sketched.
5. **Trusted hardware assumption** (§VII-B, p7): a compromised switch or weak encryption breaks the
   guarantees.
6. **Reordering grows with pattern length and load** (§IX-D p13–14, Figs 14–15).
7. **Volume anonymity is only an upper bound** against an attacker who sees multiple links + has
   background knowledge (§VII-A p6).

---

## 6. Key numbers (quick reference)

| Quantity | Value | Source |
|---|---|---|
| Good pattern length `L` | 3–6 | §IV p4, §V p5 |
| Padding per pipeline pass | ≤ 254 B | §VIII p8 |
| Padding header sizes | 32,16,8,4,2,1 B | §VI p6, §VIII p8 |
| Per-pair output rate | 1/L of port rate | §IV p4, §VIII p7 |
| Loopback sub-port bw | 100 (L=1)/50 (L=2,3)/25 (L≥4) G | eqn (4) p7 |
| Loopback ports needed | ⌈L·bw/100⌉ (2 for L=3,6) | eqn (5) p7 |
| Recirc avg (CAIDA) | 1.59 (L=1) → 0.18 (L=6) | §IX-B p10 |
| Near-lossless load | 90/70/60 % (CONST/UNIF/CAIDA) | §IX-B p9 |
| Buffer for 90–99 % load | 1 MB | §IX-D p13 |
| SRAM/TCAM use | < 10 % avg | §VIII p8 |
| Packets in order (max load) | 92 % | §IX-D p13, Table I |

---

## 7. Immediate takeaways for the DNP3 queue direction (feeds Phase 3)

1. Ditto's queue is a **size+volume** shaper for a **high-rate aggregate**; our need is **timing**
   control for a **low-rate single transaction**. The reusable core is **priority-pair (never-empty)
   + round-robin over scheduled slots**, not the padding/chaff-volume machinery.
2. The **empty-slot problem** (S7) is the crux: Ditto keeps slots full with **chaff**; the meeting
   (§8) says start **without** chaff. So mapping Defense-1's event-driven release onto a periodic
   schedule (meeting §12, the "major unresolved design question") must solve empty slots another
   way — this is Phase-3 Question 1.
3. The **"correct on average"** caveat (S10, S13) means our queue timing target must be **measured**
   (Phase-4 microbenchmark) before any security claim — and small DNP3 packets sit in Ditto's
   **worst** rate-control regime.
4. Loopback/2-pass is a **port budget** item on the shared switch; for one low-rate DNP3 flow it
   may be far cheaper than Ditto's WAN case — to be sized in `CASE_A_QUEUE_DESIGN.md`.

_Continues in `DITTO_TO_DNP3_MAPPING.md` (per-mechanism reusable/modify/unnecessary/unsuitable/
unresolved) and `CASE_A_QUEUE_DESIGN.md` (Phase 3)._
