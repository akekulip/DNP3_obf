# Offline leakage measurements — workstream W4 (H1, H2, H3, H5)

**Author:** research-scientist · **Date:** 2026-08-10 · **Silicon contact:** none · **Relay contact:** none
**Scope:** offline analysis of the six existing captures only.
**Code + outputs:** `/home/philip/Projects/DNP3/research/size_timing_coresidency/evidence/leakage/`
**Seed:** 20260810 (single seed, threaded explicitly through every estimator; no global RNG state)

---

## 0. Bottom line

| # | Question | Verdict | Headline number |
|---|---|---|---|
| M1 | Perfect-defense oracle (H5) | **Program ceiling is total.** A flawless size+timing defense changes nothing. | Balanced accuracy **1.0000**, CI95 **[1.0000, 1.0000]**, n = 11,494, 6 flows |
| M2 | Does unpadded CRC-boundary splitting reduce leakage? (H2) | **H2 confirmed. Splitting relocates the leak; it removes none of it.** | ΔMI = **+0.0000 bits**, CI95 **[−0.0000, +0.0000]**; device BA unchanged at **0.5004** |
| M3 | Is there a usable knee on the quantised grid? (H1) | **Knee exists but is not a closure point. Pre-registered Verdict B.** | Knee at c = 61: 30.2 % overhead, residual MI 0.0687 bits = **8.9× the null**; closure only at **287 % overhead** |
| M4 | Does the composed defense push size into timing? (H3) | **H3 is broken for segmentation — and the fix is measurable.** | Split + perfect timing normaliser re-encodes **60.6 %** of H(response size) into duration; fixed-K re-encodes **0.0 %** |
| M5 | Reconcile 0.99 vs 0.493 | **0.493 is right and is at the analytic ceiling. 0.99 is a regression R², not a classifier.** | Bayes-optimal size-only device BA = **0.5082** |

Two claims on the record were checked directly. **The TCP-stack fingerprint at balanced accuracy
1.000 is confirmed** — and is stronger than reported, because it needs no classifier at all. **The
ACK-mode claim at 1.000 is refuted as stated**: on the three-device task ACK mode gives 0.6666,
and 1.000 only for the binary question "is this the SEL-751?".

A third, unasked finding turned up while building the harness and changes how the corpus should be
described in any paper: **half of this corpus is DIRECT_OPERATE control traffic, not READ traffic**,
and the control-vs-read distinction is recoverable at balanced accuracy 1.000 from the *request*
size, which an outstation-edge response shaper never touches.

---

## 1. Method, so every number below is checkable

**Data.** All six captures in `/home/philip/Projects/DNP3/Traffic Trace/`, SHA-256 of each recorded in
`evidence/leakage/out/ENVIRONMENT.json`. Extraction produced **22,988 transactions**, which matches
the row count of the pre-existing `dnp3_split_harness/reports/ack_trace_characterization.csv`
exactly — an independent cross-check that the extractor sees the same events prior work saw.

**Unit of analysis.** One DNP3 request/response transaction. A transaction begins at a master →
outstation packet carrying payload and ends at the packet before the next such packet; every
outstation → master packet in between (pure ACKs and data segments) belongs to it.

**The two label sets.** Every capture contains **two** TCP flows, not one: the real device, and a
software outstation at `10.0.0.2` that is present in all six captures with an identical TCP stack
(TTL 64, window 227, `data_offset` 8, MSS 1460, timestamps + SACK). Prior work pooled both and
labelled them by the capture's device name.

- **D-REAL** (primary, n = 11,494, 6 flows): the real-device flows only — `10.0.0.1` (SEL-751),
  `10.0.0.12` (AB1400), `10.0.0.11` (ION7550). This is the adversary's actual task.
- **D-ALL** (secondary, n = 22,988, 12 flows): both flows pooled, reproducing the prior labelling.

Reporting both matters: under D-ALL the software twin is stack-identical across all three labels, so
the stack channel reads 0.5000 rather than 1.0000. That difference is an artefact of the labelling,
not a property of any device.

**Cross-validation.** Leave-one-flow-out. Each fold holds out one entire TCP flow, so no fold can
exploit a flow-constant nuisance value it also saw in training for the same session. Six folds for
D-REAL, twelve for D-ALL. Pooled out-of-fold predictions give the reported balanced accuracy.

**Adversary model.** Random forest (300 trees) as the pre-registered primary, with a depth-6 decision
tree and multinomial logistic regression as sensitivity. All use `class_weight="balanced"`. That is
not cosmetic: under leave-one-flow-out the training prior is dominated by the devices that are *not*
held out, so an unweighted model driven by an uninformative feature set scores balanced accuracy
0.000 instead of the 1/3 chance line. With balancing, the empirical no-information floor lands at
**0.3888, CI95 [0.3333, 0.6667]** (the all-features-blanked condition), which contains chance — this
doubles as the pipeline's negative control.

**Confidence intervals.** Cluster bootstrap over flows, B = 2,000, percentile method. Flows are the
resampling unit because transactions within a flow are not independent. For mutual information
estimated within flows, the resampling is stratified within flow and the interval is the **pivotal
(basic)** form; resampling with replacement thins the joint support and biases plug-in MI upward,
which makes a naive percentile interval sit entirely above its own point estimate.

**Mutual information.** Discrete plug-in with the **Miller–Madow** correction propagated through
`I = H(X) + H(Y) − H(X,Y)`, i.e. `MI_MM = MI_plugin + (m_x + m_y − m_xy − 1)/(2N ln2)`. Continuous
quantities are discretised into 16 equal-frequency bins.

**Permutation nulls — two schemes, chosen by what the secret is.**

- Secret varies *within* a flow (response size): circular block-shift within each flow, B = 1,000.
  This preserves the alternating control/read serial structure while destroying its alignment with
  the features.
- Secret is *constant* within a flow (device label): an i.i.d. row permutation here would be grossly
  anti-conservative, so the null permutes the flow-label assignment **exhaustively** — 6!/(2!)³ = 90
  distinct assignments, an exact rather than sampled null.

No raw MI is reported as significant without its own null. Where the effect is small relative to the
estimator's bias floor, the effect size reported is **MI minus the null mean**, not raw MI.

**Environment.** `$RESEARCH_PYTHON` = `/home/philip/.venvs/research/bin/python`, Python 3.12.13;
numpy 2.3.5, scipy 1.16.3, pandas 2.3.3, scikit-learn 1.9.0, scapy 2.7.0, matplotlib 3.11.0.
Repo commit `a42c9c554dee390accdbb92bc5a07cc92d6e1875`; working tree clean apart from this new
directory. `defense3/`, `defense4/` and `dnp3_split_harness/` were **not modified** (verified by
`git status` on those paths); the splitter was imported read-only.

---

## 2. Three corrections to the corpus description, found while building the harness

These are cheap to state and expensive to discover late, so they come before the results.

### 2.1 Half this corpus is control traffic, not READ traffic

`research/inline_dnp3_size_normalization/s0_results/S0_FINDINGS.md:54-60` describes the six captures
as "**READ-response** traces" and says the strong control-response size axis is "**not** in this
dataset". Decoding the request payloads refutes that:

| device | fc = 1 (READ) | fc = 5 (DIRECT_OPERATE) |
|---|---:|---:|
| SEL751 | 2,098 | 2,200 |
| AB1400 | 1,198 | 1,200 |
| ION7550 | 2,398 | 2,400 |

The 35-byte request decodes as `fc 0x05` DIRECT_OPERATE carrying one g12v1 CROB
(`... c7 05 0c 01 28 01 00 01 00 03 01 64 00 00 00 ...` — control code 0x03, on-time 100 ms), and the
37-byte response is its g12v1 status echo. The 22-byte request is `fc 0x01` READ of g30v3 over
indices 1–7, and the 54/61-byte response carries those seven analog values. The corpus is a 1 Hz
alternation of one single-point control and one seven-point read.

That does not make the CROB-count size law measurable here — N = 1 throughout, so the response is a
constant 37 bytes — but it does mean the corpus is not what the record says it is.

### 2.2 The request direction leaks the operator's action, and no response shaper touches it

Control versus read is recoverable **from the request size alone**: 22 bytes for the READ, 35 bytes
for the DIRECT_OPERATE, with no overlap. Balanced accuracy **1.0000, CI95 [1.0000, 1.0000]**, n =
11,494. A switch at the outstation edge shaping *responses* leaves this channel completely intact.
If "a passive observer should not learn that the operator issued a control" is ever a claim, it is
already false in the master → outstation direction, before any response shaping is considered.

### 2.3 `ip.len` is a joint size/stack observable, and treating it as pure "size" inflates the size channel

`ip.len = payload + 20 + 4·data_offset`. The SEL-751 negotiates RFC 7323 timestamps and so runs
`data_offset = 8`; AB1400 and ION7550 run 5. Including a per-transaction IP-byte total in the *size*
feature family therefore smuggles `data_offset` — a stack property — across the family boundary. With
it in, the size-only classifier read **0.8377**; with it out, **0.5004**, which is where the analytic
ceiling says it belongs (§6). Any per-family decomposition in a paper has to make this split
explicitly, or the size channel will be credited with the stack channel's information.

One further consistency note: the SEL-751's CLRT in this corpus is median **12.21 ms**, p95 17.15 ms,
p99 25.11 ms — not the ~1.4–1.9 ms the physical relay measures (`CLAUDE.md`). That matches
`COMPREHENSIVE_REPORT.md:§3.4`'s "native ~12.9 ms corpus / ~2 ms relay" and confirms the corpus is a
lab configuration, not the physical relay.

---

## 3. M1 — the perfect-defense oracle (H5)

**Design.** Take the full realistic passive metadata feature set (size, timing, TCP/IP stack, ACK
mode), replace **every** size feature and **every** timing feature with the constant 0 — a defense
better than any implementable one, because it removes byte totals, segment counts, first-byte
latency, CLRT, inter-segment gaps, transaction duration and poll cadence simultaneously — and re-run
the device classifier.

### 3.1 Result

**D-REAL, n = 11,494, 6 flows, leave-one-flow-out, random forest, cluster bootstrap B = 2,000:**

| condition | balanced accuracy | CI95 | per-flow accuracy |
|---|---:|---|---|
| full metadata (no defense) | 1.0000 | [1.0000, 1.0000] | 1.0 × 6 |
| **ORACLE — size + timing constant** | **1.0000** | **[1.0000, 1.0000]** | **1.0 × 6** |
| ORACLE + TCP stack also constant | 0.6666 | [0.3333, 0.9999] | 0, 0, 1.0, 1.0, 1.0, 1.0 |
| ORACLE + stack + ACK mode also constant | 0.3888 | [0.3333, 0.6667] | *(no-information floor; contains chance 0.3333)* |
| size only | 0.5004 | [0.4464, 0.5118] | |
| timing only (incl. ACK-conditional features) | 0.6133 | [0.5794, 0.7828] | |
| timing magnitude only (defined for all devices) | 0.2362 | [0.1990, 0.4501] | |
| stack only | 1.0000 | [1.0000, 1.0000] | 1.0 × 6 |
| ACK mode only | 0.6666 | [0.3333, 0.9999] | |
| size + timing | 0.7976 | [0.7804, 0.8838] | |
| DNP3 payload content (DPI) only | 1.0000 | [1.0000, 1.0000] | |

Model sensitivity on the oracle condition: decision tree **1.0000** [1.0000, 1.0000]; logistic
regression **1.0000** [1.0000, 1.0000]. The result is not a random-forest artefact.

### 3.2 The oracle result does not need a classifier at all

The map from device to `(TTL, data_offset)` is **injective** on this corpus:

| (TTL, data_offset) | device |
|---|---|
| (64, 5) | ION7550 |
| (64, 8) | SEL751 |
| (128, 5) | AB1400 |

A two-field lookup table, with **zero training**, gives balanced accuracy **1.0000** over all 11,494
transactions. Adding window ranges (AB1400 constant 2048 on every one of its 2,398 transactions; ION7550 2922–4380; SEL-751 7253–8688) and
SYN MSS (1478 / 1460 / 1460) makes the separation redundant several times over.
`I(stack signature ; device) = 1.5286 bits = H(device) = 1.5286 bits` — the stack signature carries
**100 %** of the device entropy.

### 3.3 Verification and refutation of the two claims on record

- **TCP-stack fingerprint at 1.000 — CONFIRMED**, and stronger than reported: it is deterministic,
  not learned, and survives leave-one-flow-out on every fold.
- **ACK mode at 1.000 — REFUTED as stated.** On the three-device task ACK mode gives **0.6666**
  [0.3333, 0.9999], because it perfectly recalls the SEL-751 (the only separate-ACK device: 4,298 of
  4,298 transactions) and cannot separate AB1400 from ION7550 at all. This is independently
  corroborated inside the repo: `dnp3_split_harness/reports/attacker_eval_results.json` records
  `ackmode_only` at `recall_macro = 0.6666–0.6667` across all four of its models. The 1.000 in
  `PANEL_SYNTHESIS_WAY_FORWARD.md:38` is the binary "is it the relay?" number placed in a three-class
  table. Both numbers are true of different questions; only one belongs in that table.

### 3.4 A cautionary note on the prior timing-only number

The prior artefact reports `timing_only` at 0.797–0.855 accuracy. Two mechanisms inflate it. First,
`req_to_ack_ms` and `ack_to_resp_ms` exist **only** for a separate-ACK device, so the timing family
carries the ACK-mode categorical through its own missingness pattern — the prior file's own
permutation importance puts 0.356 of 0.797 on `req_to_ack_ms`. Second, session-specific latency does
not transfer. Median-imputing the missing values does not fix this — it gives **0.6113**, CI95 [0.5769, 0.7833],
essentially unchanged, because only the SEL-751 has those columns at all so the median *is* the
SEL-751's own value. The fix is to drop the columns. Restricting the timing family to features
defined for every device gives **0.2362**, CI95 [0.1990, 0.4501] — a CI containing chance, with the point estimate *below* it. There is no
generalising timing-magnitude fingerprint in this corpus once ACK mode is removed from it.

### 3.5 What this means

**The hard ceiling on this program's achievable benefit against device identification is zero.** A
defense that perfectly closes both the size and the timing axis leaves balanced accuracy at 1.0000
with a zero-width confidence interval. The charter's goal sentence
(`CHARTER.md:8-9` — "a passive on-path observer cannot fingerprint the SEL-751 by *either* channel")
is not reachable as written. Closing the stack channel too gets to 0.6666; closing stack **and** ACK
mode gets to the chance floor. Those are the only two levers that move the number, and neither is a
size or timing mechanism.

---

## 4. M2 — the split null (H2)

**Design.** Run the existing splitter — `dnp3_split_harness/split_server.py::DNP3CRCSplitter`,
imported read-only with its `b"".join(chunks) == data` assertion active — over all 11,494 real-device
responses at 1, 2 and 4 CRC blocks per chunk. The assertion passed on every response at every
granularity. Compare native against split for two observer models: an **aggregating** observer that
groups packets into transactions and sums (realistic), and a **non-aggregating** observer that sees
one packet length (a bounding case).

### 4.1 Result

| mode | device BA (size family) | CI95 | I(total, count ; native size) | I(segment count ; native size) | I(one packet length ; native size) |
|---|---:|---|---:|---:|---:|
| native | 0.5004 | [0.4464, 0.5118] | **1.5511** | 0.0687 | 1.4865 |
| split, 1 block/chunk | 0.5004 | [0.4464, 0.5118] | **1.5511** | **1.0678** | 0.6567 |
| split, 2 blocks/chunk | 0.5004 | [0.4464, 0.5118] | **1.5511** | 0.0758 | 0.7769 |
| split, 4 blocks/chunk | 0.5004 | [0.4464, 0.5118] | **1.5511** | 0.0687 | 1.5308 |

`H(native response size) = 1.5511 bits`. All MI values are Miller–Madow corrected; every entry in the
`I(total, count ; native size)` and `I(segment count ; native size)` columns has permutation
`p = 0.0005` (B = 2,000, block-shift within flow).

**Paired cluster-bootstrap deltas, split minus native, B = 1,000:**

| mode | ΔMI(total, count ; native size) | CI95 |
|---|---:|---|
| split bpc 1 | **+0.0000 bits** | [−0.0000, +0.0000] |
| split bpc 2 | **+0.0000 bits** | [−0.0000, +0.0000] |
| split bpc 4 | **+0.0000 bits** | [+0.0000, +0.0000] |

### 4.2 Reading

**H2 is confirmed, on both of its clauses, exactly.**

1. *Total bytes are preserved.* `I(total, count ; native size) = 1.5511 bits = H(native size)` in
   every mode. The observation determines the secret **exactly**, because the transform is invertible
   from the observation — summing the chunks returns the original length. This is not an approximate
   finding; the delta is identically zero with a zero-width interval.
2. *Chunk count is proportional to size.* At the finest granularity the leak **moves into the packet
   count**: `I(segment count ; native size)` rises from 0.0687 to **1.0678 bits**, a 15.5-fold
   increase, so a count-only observer goes from learning almost nothing to learning 69 % of
   `H(response size)`. That is the "beacon" the record predicted
   (`docs/project-memory/split-pad-timing-policy-study.md:26-28`), quantified.

3. *Device identification does not move at all.* 0.5004 with an identical CI in all four modes.

The one place splitting helps is against an observer who does **not** aggregate: single-packet-length
information drops from 1.4865 to 0.6567 bits at bpc = 1 (−56 %). At bpc = 4 it is 1.5308 bits, i.e.
no better than native, because a 4-block chunk is the whole response for the common sizes. A
non-aggregating observer is not a credible threat model for a 1 Hz polled link with one transaction
in flight, so this is reported as a bound, not a benefit.

**Unpadded CRC-boundary splitting is retired as a size defense on this evidence.**

---

## 5. M3 — the quantised grid frontier (H1)

**Design.** Emit every response as K segments of exactly c bytes with the tail padded up. Two
policies: **adaptive-K** (`K = ceil(L/c)`, so the byte dimension is quantised but the segment count
still moves with L) and **fixed-K** (`K = K_fix ≥ ceil(L_max/c)` for every response, so the emitted
shape is constant by construction). Sweep c over
{16, 18, 24, 32, 36, 48, 54, 61, 64, 72, 96, 128, 192, 256}.

Native response-size distribution (real-device flows): {37: 5,736; 54: 3,296; 61: 2,369; 74: 64;
122: 28; 183: 1}. Mean 47.25 B, max 183 B, `H = 1.5511 bits`.

### 5.1 Result — adaptive K

| c | mean added bytes | overhead % | MI(shape ; size) | null p95 | MI(shape ; device) | device BA | anonymity k |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16 | 9.02 | 19.1 | 1.0678 | 0.2913 | 0.0103 | 0.3358 | 1 |
| 18 | 10.85 | 23.0 | 0.8072 | 0.4986 | 0.3322 | 0.5004 | 1 |
| 24 | 13.10 | 27.7 | 1.0678 | 0.2913 | 0.0103 | 0.3358 | 1 |
| 32 | 17.10 | 36.2 | 0.0758 | 0.0111 | 0.0103 | 0.3358 | 1 |
| 48 | 24.92 | 52.8 | 1.0236 | 0.2838 | 0.0033 | 0.3358 | 1 |
| 54 | 18.46 | 39.1 | 0.7700 | 0.4903 | 0.3322 | 0.5004 | 1 |
| **61** | **14.25** | **30.2** | **0.0687** | 0.0077 | 0.0103 | 0.3358 | 1 |
| 64 | 17.28 | 36.6 | 0.0687 | 0.0077 | 0.0103 | 0.3358 | 1 |
| 96 | 48.99 | 103.7 | 0.0255 | 0.0045 | 0.0032 | 0.3313 | 1 |
| 128 | 80.76 | 170.9 | 0.0014 | 0.0002 | 0.0001 | 0.3570 | 1 |
| **192** | **144.75** | **306.4** | **0.0000** | 0.0000 | 0.0000 | 0.3294 | **3** |

Every fixed-K configuration has `MI = 0.0000` by construction; the cheapest is **c = 61, K = 3:
135.75 B mean added, 287.3 % overhead**.

Figure: `evidence/leakage/figs/m3_frontier.png`.

### 5.2 Reading — there is a knee, and it is not a closure point

The Kneedle-style maximum-distance-to-chord knee on the monotone Pareto set sits at **c = 61: 14.25 B
mean overhead (30.2 %), residual `I(shape ; size)` = 0.0687 bits**, which is 4.4 % of
`H = 1.5511 bits`. That looks attractive until it is compared with its own null: the permutation null
p95 at that point is **0.0077 bits**, so the knee sits **8.9× above the noise floor** and the
anonymity set is **k = 1** — ION7550's 74/122/183-byte tail maps to shapes no other device produces.
The knee buys most of the reduction cheaply and then stops; it does not close the channel.

**Exact closure — MI inside the null and k = 3 — happens only at the degenerate configuration.**
Adaptive-K requires c ≥ 192 ≥ L_max, i.e. K = 1 for every response, at 144.75 B (306.4 %) mean
overhead. The cheapest zero-leakage configuration overall is fixed-K at c = 61, K = 3, at 135.75 B
(287.3 %) — a 3.9× byte inflation. This is precisely pre-registered **Verdict B**
(`research_design.md:186-192, 254-264`): closure only at the degenerate point, with a heavy-tail
device holding k = 1 everywhere short of it.

### 5.3 The finding I did not expect — leakage is not monotone in the grid unit

Coarsening the grid does not monotonically buy privacy. c = 32 leaves 0.0758 bits; c = 48, which is
*coarser and 46 % more expensive*, leaves 1.0236 bits — thirteen times more. c = 18 and c = 54 both
leave the device channel wide open (MI 0.3322, device BA 0.5004) while c = 16, 24, 32 and 61 close it
(device BA at chance). What matters is the arithmetic relation between c and the corpus's size
support, not how coarse c is: a grid line falling between 54 and 61 preserves the SEL/AB-vs-ION
distinction, one falling above both destroys it.

This is the same phenomenon S0 found for constant-block padding
(`S0_FINDINGS.md:35-45` — "a constant baked-CRC block cannot normalize a size distribution whose
values are not congruent modulo the block") generalised to the grid: **the grid unit must be chosen
against the measured size support, and any tuning that treats c as a smooth privacy dial is wrong.**

### 5.4 Two different secrets close at two different prices

The device channel closes earlier and cheaper than the response-size channel. At c = 61,
`MI(shape ; device)` is 0.0103 bits and device balanced accuracy is 0.3358 (chance 0.3333) while
`MI(shape ; size)` is still 0.0687 bits. If the claim is about device anonymity, the grid is cheap —
and irrelevant, because M1 says the stack channel holds device identity at 1.000 regardless. If the
claim is about the *content* of a response (point count, operator action), the grid is expensive.

---

## 6. M4 — the cross-axis composition test (H3)

**Design.** Apply a size transform, then apply the timing release policy on top in software, and emit
a feature vector containing **both** size and timing observables. Nothing in the timing engine governs
segments 2..K — that is exactly what the test probes.

The headline conditions use an **idealised first-byte normaliser**: `t_first` is a single constant for
every transaction and every device. This is strictly better than D1 or D3 can achieve on hardware
(`defense4/TIMING_SPEC.md:§5` makes `release_error_A`, `release_error_R` and `ordering_gap` quantities
to be measured, not assumed), so any residual `I(timing ; response size)` under it can only have come
from segment structure the size axis introduced. The realistic D3 policy is reported as sensitivity,
applied only to the separate-ACK device, since Case B has no CLRT and is out of scope.

Inter-segment interval δ is grounded in the corpus: 93 natively multi-segment responses give an
empirical gap distribution with median 13.554 ms and range [0.033, 24.060] ms. The configured
alternative is the split harness default `DEFAULT_CHUNK_DELAY_MS = 10` (`lab_config.py:40`).

### 6.1 Result

`H(native response size) = 1.5511 bits`, n = 11,494.

| condition | I(timing ; size) | pivotal CI95 | null p95 | perm p | excess over null mean | % of H | paired ΔMI vs P0 (CI95) |
|---|---:|---|---:|---:|---:|---:|---|
| **P0** native, perfect timing (no size axis) | 0.0000 | [0.0000, 0.0000] | 0.0000 | 1.000 | 0.0000 | 0.0 % | reference |
| **P1** CRC split, δ = 10 ms | **1.0599** | [1.0498, 1.0705] | 0.2904 | 0.001 | 0.9406 | **60.6 %** | **+1.0624 [+0.9997, +1.1534]** |
| **P2** CRC split, empirical δ | 1.0480 | [1.0126, 1.0387] | 0.3372 | 0.001 | 0.8832 | 56.9 % | +1.0667 [+0.9829, +1.1950] |
| **P3** CRC split, back-to-back (δ = 0.033 ms) | **1.0599** | [1.0498, 1.0705] | 0.2904 | 0.001 | 0.9406 | **60.6 %** | +1.0624 [+0.9997, +1.1534] |
| **P4** grid adaptive-K, c = 64 | 0.0679 | [0.0561, 0.0803] | 0.0076 | 0.001 | 0.0623 | 4.0 % | +0.0717 [+0.0000, +0.1809] |
| **P5** grid fixed-K, c = 64, K = 3 | **0.0000** | [0.0000, 0.0000] | 0.0000 | 1.000 | 0.0000 | **0.0 %** | **+0.0000 [+0.0000, +0.0000]** |
| **P6** grid fixed-K, randomised δ | 0.0123 | [−0.0245, −0.0110] | 0.0141 | **0.315** | 0.0008 | 0.05 % | +0.0365 [+0.0075, +0.1233] |

Figure: `evidence/leakage/figs/m4_composition.png`.

### 6.2 H3 is broken for segmentation-based size axes

Composing CRC-boundary splitting with a **perfect** first-byte timing normaliser re-encodes
**1.0599 of 1.5511 bits — 60.6 % of the response-size entropy — into transaction duration and
inter-segment gap structure.** Permutation p = 0.001; the paired cluster-bootstrap ΔMI is
+1.0624 bits with CI95 [+0.9997, +1.1534], excluding zero by a wide margin. The defense normalises
the time channel and the size mechanism refills it in the same pass, one layer up. This is the first
joint size+timing measurement in the repository and it lands on the negative side.

**Both horns of the PI's §5 argument are now closed by measurement, not by reasoning.**

- *Pace the segments* (P1, δ = 10 ms): MI = 1.0599 bits.
- *Do not pace them* (P3, δ = 0.033 ms, the smallest gap actually observed in this corpus): MI =
  **1.0599 bits — identical**. Not pacing does not help, because duration = (K−1)·δ is proportional
  to K whatever δ is; shrinking δ shrinks the absolute durations but not their information content.

### 6.3 Jitter attenuates the re-encoded channel; it never closes it

Randomising each gap as 10 ms + N(0, σ), split at 1 block/chunk, perfect first byte:

| σ (ms) | 0.0 | 0.5 | 1.0 | 2.0 | 5.0 | 10.0 | 20.0 | 50.0 | 100.0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| I(duration ; size) bits | 1.0599 | 1.0181 | 1.0181 | 0.8274 | 0.2886 | 0.1283 | 0.0792 | 0.0584 | 0.0518 |
| null p95 | 0.2904 | 0.2814 | 0.2814 | 0.2347 | 0.0871 | 0.0384 | 0.0240 | 0.0183 | 0.0164 |
| inside null? | no | no | no | no | no | no | no | no | **no** |

At σ = 100 ms — ten times the nominal gap, and roughly a tenth of the 1 s poll interval — the channel
is attenuated 20-fold but is still 3.2× its own null. The reason is structural: `E[duration] =
δ·(K−1)` scales with K no matter how large the variance is, so randomisation buys attenuation
asymptotically and closure never. **Gap randomisation is not a fix for the re-encoding.**

### 6.4 Fixing the segment count removes the re-encoding entirely — measured, not argued

P5 (fixed K = 3, constant c = 64) gives `I(timing ; size) = 0.0000` exactly, with a paired ΔMI of
+0.0000 and a zero-width CI. P6 adds randomised gaps on top of a fixed K and gives permutation
**p = 0.3147 — inside the null band**, with an excess over the null mean of 0.0008 bits (0.05 % of H).

P6's paired ΔMI against P0 (+0.0365, CI95 [+0.0075, +0.1233]) formally excludes zero while its own
permutation test says the channel carries nothing. That disagreement is informative rather than
contradictory: P0's MI is exactly and degenerately zero, so *any* positive estimator bias in P6 shows
up as a positive delta. The permutation null is the correct test of "does this carry information",
and it says no. This is exactly why the brief's rule — never report raw MI as if it were significant —
matters here.

So `pi-scoping.md:§6`'s claim that quantised emission means "the cross-axis re-encoding cannot occur
by construction — it is designed out rather than measured away" is **correct, and now measured**. It
is correct only for **fixed** K: the adaptive-K grid (P4) still leaks 4.0 % of H with permutation
p = 0.001, and its paired ΔMI interval [+0.0000, +0.1809] merely touches zero.

### 6.5 Sensitivity — the real D3 policy makes the composed device channel worse

With D3 applied only to the separate-ACK device (the in-scope Case A), composed device balanced
accuracy over size + timing observables rises from **0.3968** [0.3708, 0.5799] with no defense to
**0.7957** [0.7803, 0.8723] with split + D3. Holding one device class and not the others makes the
held class *more* identifiable in a mixed population, not less. Fixed-K grid + D3 lands at 0.6511
[0.6269, 0.7724].

This is the measured form of the residual `pi-scoping.md:§3` already names — "the fact that this link
is defended at all, a signature no other link carries". It does not change the M1 ceiling (the stack
channel is already at 1.000), but it does mean the composed defense cannot be described as reducing
device identifiability on any channel.

---

## 7. M5 — reconciling the 0.99 and the 0.493

### 7.1 The 0.493 side is right, and it is at the analytic ceiling

Response byte-total distributions on the real-device flows:

| device | distribution |
|---|---|
| AB1400 | {37: 1,200; 54: 1,198} |
| SEL751 | {37: 2,200; 54: 2,098} |
| ION7550 | {37: 2,336; 61: 2,369; 74: 64; 122: 28; 183: 1} |

SEL751 and AB1400 have **identical support** and near-identical proportions. No size-based rule can
separate them. The balanced-accuracy-optimal decision rule under a balanced prior — which no
classifier can beat — achieves:

**Bayes-optimal size-only device balanced accuracy = 0.5082** (per-class recall AB1400 0.4996,
ION7550 0.5131, SEL751 0.5119). Adding request size and segment count to the observation changes
nothing: still 0.5082.

Reproductions on the same corpus:

| scheme | features | balanced accuracy |
|---|---|---:|
| prior capture-level split (train = base pcaps, test = L pcaps) | req_size, resp_size | 0.5028 |
| leave-one-flow-out CV | req_size, resp_size | 0.5004, CI95 [0.4464, 0.5118] |
| leave-one-flow-out CV | full size family | 0.5004, CI95 [0.4464, 0.5118] |
| prior record (`S0_FINDINGS.md`, `PANEL_SYNTHESIS:38`) | — | 0.493 |
| prior record (`attacker_eval_results.json`, size_only) | req_size, resp_size | 0.4999 |

Everything lands in 0.493–0.508 and the ceiling is 0.5082. **The 0.493 is correct and essentially
exhausts what the size channel can do for device identification on this corpus.**

### 7.2 The 0.99 side is not a classifier number

`research/inline_dnp3_size_normalization/research_design.md:55` states "a size-only classifier ≈ 0.99,
driven by ~14.6 B/CROB (control) and ~5.7 B/analog-point (read) **[M]**", repeated verbatim at
`agent_contributions/pi_framing.md:6`. There is no such measurement anywhere in the tree. The number
traces to:

| artefact | statistic | what it actually is | dataset | secret | n |
|---|---|---|---|---|---|
| `research/split_pad_timing_policy/measured_evidence.md:26` | **R² = 0.9999** | coefficient of determination of a **linear regression** of operate-response size on CROB count N (slope 14.6 B/CROB, intercept 22.5 B, 37→256 B over N = 1..16) | `dnp3_multicrob_harness/captures/sweep/multicrob_n{N}.pcapng` — the multi-CROB SBO sweep against the harness outstation, **not** the six device captures | CROB count N (operator action complexity) | 1 SBO per N level, 16 points, one device |
| `research/split_pad_timing_policy/GROUNDING.md:49-51` | **R² ≈ 0.99** | coefficient of determination of response **timing** on CROB count (0.179 / 0.214 ms per CROB) | same sweep | CROB count N | 1 per level, one device |

Three things differ simultaneously: the **statistic** (a regression R², not a balanced accuracy), the
**secret** (CROB count, not device identity), and the **dataset** (a synthetic 16-point SBO sweep
against a software outstation, not the six device captures). The `[M]` tag is carried over from the
genuine regression measurement, which is why it survived review.

### 7.3 Verdict on the reconciliation

**They were never measuring the same thing, so they were never in contradiction — but the 0.99 is a
transcription error and must not appear in a paper as a classifier number.**

- Size-only **device** identification on the six-capture corpus: **0.493–0.508, ceiling 0.5082**, and
  it is the number that belongs in any device-anonymity table.
- Size-vs-**CROB-count** on the multi-CROB sweep: a near-perfect bijection (R² = 0.9999, 14.6 B/CROB)
  for the operator-action secret, from 16 points with one sample each, and it belongs only in a
  content-confidentiality argument with that n stated.
- Recommended repair: strike "size-only classifier ≈ 0.99" from `research_design.md:55` and
  `agent_contributions/pi_framing.md:6`, and replace it with the two statements above.

---

## 8. Threats to validity

Ordered by how much they could change a conclusion.

1. **One physical unit per device model.** Every 1.000 in §3 is a statement about three specific
   units in one lab configuration, not three device *families*. The cluster bootstrap over flows
   measures session-to-session generalisation only. A second SEL-751 with different firmware, or the
   same relay behind a router that rewrites TTL, could change the stack result. This is the
   pre-existing R10 ceiling (`research_design.md:281`) and no analysis of this corpus can lift it.

2. **Six flows make the flow-level permutation test structurally under-powered.** With 6 flows and 3
   labels, the exhaustive flow-label null has 90 assignments of which 6 attain maximal MI, so the
   smallest attainable p-value is 7/91 = **0.0769**. `MI(stack ; device)` = 1.5286 bits = H(device)
   therefore reports p = 0.0769 — the floor, not a weak effect. The stack result rests on
   injectivity plus leave-one-flow-out CV, not on that test. The same limit makes
   `I(size ; device) = 0.4936` (null p95 0.4944, p ≈ 0.20) untestable at the flow level; the
   classifier CI [0.4464, 0.5118], which excludes chance 0.3333, is the better-powered statement.
   **More independent capture sessions are the only fix, and they are cheap.**

3. **The corpus maximum response is 183 bytes, so §5's overhead figures are optimistic.** Fixed-K
   overhead is set by `L_max`. This corpus contains no integrity poll and no large READ, while the
   repo records a **12,204 B / 49-link-frame / 20-TCP-segment** large READ on this class of device
   (`dnp3_split_harness/reports/baseline_segmentation.md`). If such polls occur on the protected
   link, the zero-leakage fixed-K overhead rises by roughly two orders of magnitude. The 287 %
   should be read as a floor for this traffic mix, not as the deployment cost.

4. **Absolute overhead is small even where the ratio is large.** 135.75 B added per response at a
   1 Hz poll is about 136 B/s. The 287 % is a ratio on a 47-byte base. Whether that matters is an
   engineering judgement about the link, not something this measurement settles.

5. **Segment-to-packet mapping is assumed 1:1.** The split harness sets `TCP_NODELAY` and a non-zero
   inter-chunk delay, so each write becomes its own segment. At δ = 0 the kernel may coalesce writes,
   which would collapse the observation back to the native single segment and make the split a no-op
   rather than a leak relocation. Both bounds are covered: P1 (δ = 10 ms) and P3 (δ = 0.033 ms) give
   identical MI, so the §6 conclusion is insensitive to δ; the §4 count-relocation result does depend
   on the writes surviving as separate segments, which is what the harness is built to do.

6. **The timing simulation is model-level.** `TIMING_SPEC.md:§5` explicitly leaves `release_error_A`,
   `release_error_R` and `ordering_gap` to hardware measurement. The headline M4 conditions use an
   idealised constant `t_first`, which is strictly better than any of them, so the measured
   re-encoding is a **lower bound** on the composed leak. The realistic-D3 sensitivity (§6.5) is
   correspondingly worse.

7. **Prior numbers pooled the software twin.** `10.0.0.2` appears in all six captures with an
   identical stack and was labelled by the capture's device. My primary analysis excludes it, which
   changes several published values (stack 0.5000 → 1.0000, full-metadata 0.6207 → 1.0000). Which
   labelling is right depends on what "device" means in the claim; for a passive observer watching
   one relay's link, D-REAL is the right one. Both are reported.

8. **Plug-in MI has a positive bias floor.** Over a 16-bin joint with continuous jittered gaps that
   floor is around 0.5 bits — large enough to look like a finding. Every MI in this report is
   therefore quoted against its own permutation null and, where the effect is small, as an excess
   over the null mean. The v1 run of M4 (preserved at
   `out/m4_composition_v1_ackholdartifact.json`) is retained as the audit trail for a superseded
   release model, in which applying an ACK-hold to combined-ACK devices manufactured a
   device-discriminating offset; that condition was removed, not silently corrected.

9. **The `req_to_ack` missingness confound is real and is present in prior artefacts.** Any timing
   ablation that fills a separate-ACK-only feature with a sentinel is reporting ACK mode, not timing.

---

## 9. What follows for the program

### 9.1 What is now closed

- **H5 is falsified with a zero-width interval.** A perfect size+timing defense leaves device
  identification at 1.0000. No mechanism in this program's scope moves that number.
- **H2 is confirmed.** Unpadded CRC-boundary splitting preserves the leak exactly (ΔMI = 0.0000,
  CI [−0.0000, +0.0000]) and relocates it into packet count (0.0687 → 1.0678 bits). Retire it.
- **H1 is Verdict B.** A knee exists at c = 61 / 30.2 % overhead, but it sits 8.9× above the
  permutation null with anonymity k = 1. Closure only at the degenerate configuration, 287–306 %
  overhead — and that figure is optimistic because this corpus has no large READ.
- **H3 is broken for segmentation, and repairable only by fixing K.** Splitting re-encodes 60.6 % of
  H(response size) into the timing channel under a better-than-achievable timing defense. Pacing and
  not pacing are indistinguishable. Jitter attenuates and never closes. Fixed-K gives exactly zero.

### 9.2 The one surviving mechanism, and the measurement it now needs

The only configuration consistent with all four results is **fixed-K quantised emission** — constant
K and constant c, so the emitted shape is invariant in both the byte and the time dimension. It is
the only point with zero size leakage **and** zero cross-axis re-encoding, and §6.4 turns
`pi-scoping.md:§6`'s "by construction" argument into a measurement.

Its cost is set entirely by the maximum response the link ever carries, and this corpus's maximum
(183 B) is almost certainly unrepresentative. **The next measurement the program needs is the
response-size distribution of the real polling profile including integrity polls and large READs.**
Until that exists, the 287 % overhead figure cannot be defended in a paper.

### 9.3 Ranked next experiments

1. **TCP-stack normalisation feasibility (highest value).** It is the only lever that moves the 1.000.
   TTL rewrite, MSS clamp, window normalisation and option-set normalisation are all cheap in a data
   plane, and §3 shows that closing the stack channel takes the ceiling from 1.0000 to 0.6666, and
   closing ACK mode as well takes it to chance. Without it the charter's goal sentence stays
   unreachable. This is Philip's open question 4 (`pi-scoping.md:§7`) and the measurement above
   answers it in favour of "yes, or restate the claim".
2. **Capture more independent sessions of the same three devices.** Six flows is what makes the
   permutation test bottom out at p = 0.0769 and what makes every flow-level CI as wide as it is.
   This is the cheapest possible improvement to the statistical strength of everything above, and it
   needs no hardware change — just more capture runs.
3. **Measure the real response-size distribution including large READs** (§9.2), because the fixed-K
   overhead claim depends entirely on it.
4. **Re-scope the claim to content confidentiality rather than device anonymity.** The size channel
   holds 0.4936 bits about device identity and, on the multi-CROB sweep the prior record measured, up to H(N) = 4.0 bits about CROB count on the control path.
   The defensible protected quantity is *what the operator did*, not *which device this is* — and §2.2
   shows even that leaks in the request direction, which an outstation-edge response shaper does not
   touch. Any control-path claim must cover both directions or it is not a claim.

---

## 10. Artefacts

All under `/home/philip/Projects/DNP3/research/size_timing_coresidency/evidence/leakage/`.

| path | contents |
|---|---|
| `scripts/extract_transactions.py` | pcap → 22,988 transaction rows + per-transaction response payloads |
| `scripts/leakage_lib.py` | Miller–Madow MI, the three permutation nulls, cluster/stratified/paired bootstraps, LOFO CV |
| `scripts/m1_oracle.py` | M1 perfect-defense oracle + family breakdown + deterministic stack rule |
| `scripts/m2_split_null.py` | M2 split null (imports the harness splitter read-only) |
| `scripts/m3_grid_frontier.py` | M3 (c, K) sweep, Pareto frontier, knee detection |
| `scripts/m4_composition.py` | M4 composed size+timing simulation, jitter sweep |
| `scripts/m5_reconcile.py` | M5 Bayes-optimal ceiling, reproductions, provenance of the 0.99 |
| `scripts/make_figures.py` | exploratory figures (not manuscript figures) |
| `out/transactions.csv` | the extracted feature table (22,988 rows) |
| `out/m1_oracle.json` … `out/m5_reconcile.json` | every number in this report, machine-readable |
| `out/*.log` | stdout of each run |
| `out/m4_composition_v1_ackholdartifact.json` | superseded M4 release model, retained for audit |
| `out/ENVIRONMENT.json` | seed, interpreter, package versions, pcap SHA-256, script hashes, commit |
| `figs/m3_frontier.png`, `figs/m4_composition.png` | frontier and composition figures |

Reproduce in order: `extract_transactions.py` → `m1` → `m2` → `m3` → `m4` → `m5` → `make_figures.py`,
all with `$RESEARCH_PYTHON`. Total runtime approximately 45–60 minutes on this host.
