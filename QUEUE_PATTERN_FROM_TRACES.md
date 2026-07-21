# QUEUE_PATTERN_FROM_TRACES.md — TM queue timing pattern from the SEL-751 traces

_Step 1 of the queue work (Philip 2026-07-21: "run the pcap traces and determine the pattern for the
TM queue"). Produced on `research/caseA-ditto-queue`. Analysis:
`research/tofino_dcrn_feasibility/p4/ack_delay/determine_queue_pattern.py` →
`.../queue_pattern.json`. Reuses `sel751_extract.py`._

> **★ TERMINOLOGY (reframed 2026-07-21, Dr. Lin lock).** Under the locked architecture the **"pattern"
> is the ordered SIZE-state list `P = [S0…S(L-1)]`** (a separate, size-based determination — still
> TBD), and **timing is the scheduler's interval `τ` / rate `R`, NOT a "timing pattern."** So this
> document does **not** define "the pattern." It **characterizes the native SEL-751 CLRT timing
> behaviour** and derives **candidate timing TARGETS** (17 ms p95 / 25 ms p99) the scheduler must
> reshape toward — trace-derived candidates, **NOT locked**, and **not** a size pattern. Read "pattern"
> below as "candidate timing target/schedule." See `CASE_A_QUEUE_DESIGN.md` §1a, §5.

> **What this is.** The timing analogue of Ditto's offline pattern computation (NDSS'22 §V, eqn 2:
> `P_i = percentile_{(i+1)·100/L}(D)`) applied to **our** SEL-751 traces. For **Defense 2** the TM
> queue forwards the ACK and holds the **response** to `t_ack + G`, so the attacker-observed CLRT = G
> and the "pattern" is an ordered set of **target CLRT (release-gap) values**. A response with native
> readiness-relative-to-ACK `r` (= its native CLRT) is released at the smallest slot `≥ r` (monotone
> "next-larger" slot — the queue can only ADD delay); if `r` exceeds the top slot it **fails open**
> (released at natural readiness). This is a **trace-derived first pattern to implement and test the
> queue with**, not the final defensible policy (that is chosen at Phase 4.5/5.5 with the physical
> device + microbench).

---

## 1. Input: pooled native SEL-751 CLRT distribution (both captures, n=4298)

Pooled over `Traffic Trace/SEL751.pcap` (n=299) + `SEL751L.pcap` (n=3999), separate-ACK w/ CLRT:

| metric | native CLRT (ACK→response) ms | readiness (request→response) ms |
|---|---|---|
| min | 0.74 | 14.28 |
| p25 | 11.78 | 15.55 |
| **median** | **12.21** | **16.13** |
| p75 | 13.74 | 17.82 |
| p90 | 15.81 | 19.91 |
| p95 | 17.15 | 21.08 |
| p99 | 25.11 | 29.52 |
| **max** | **165.98** | **170.80** |
| mean / std | 13.45 / 6.73 | 17.40 / 6.76 |

Per-capture medians agree (SEL751 12.90 ms / SEL751L 12.18 ms — the ~12–13 ms cluster). The
distribution is **tight around 12–17 ms with a thin heavy tail** to ~166 ms (a few outliers).
Response sizes are `{37 B, 54 B}` (unchanged — timing path is byte-preserving).

**Constraint:** TCP `RTO_MIN ≈ 207 ms` (rig-measured, `ASSUMPTIONS_AND_UNKNOWNS.md` #12) → every
slot must stay under a **187 ms ceiling** (20 ms margin) or the outstation retransmits mid-hold. All
candidate values below are RTO-safe.

---

## 2. Candidate patterns (real numbers)

### P-A — fixed single target G (output CLRT = G for covered responses; tail fails open)
| G (=percentile) | value ms | coverage | fail-open tail (of 4298) | added latency @ median |
|---|---|---|---|---|
| p90 | 15.81 | 90.0 % | 430 | +3.60 ms |
| **p95** | **17.15** | 95.0 % | 215 | +4.94 ms |
| **p99** | **25.11** | 99.0 % | 43 | +12.90 ms |
| max | 165.98 | 100.0 % | 0 | +153.77 ms |

### P-B — common bounded band `[low, high] = [12.21, 17.15] ms` (= [median, p95]); RTO-safe.

### P-C — Ditto-style repeating percentile schedule (naïve eqn 2)
| L | slots (ms) | output CLRT mean / median / max | fail-open | note |
|---|---|---|---|---|
| 3 | `[11.91, 12.78, 165.98]` | 63.49 / 12.78 / 165.98 | 0 | **top slot = outlier max → inflates output** |
| 6 | `[11.63, 11.91, 12.21, 12.78, 14.90, 165.98]` | 38.22 / 12.50 / 165.98 | 0 | still dragged by the 165.98 top slot |

---

## 3. ★ Key finding — naïve Ditto percentiles are UNSUITABLE for our heavy-tailed CLRT

Ditto's `P_i = percentile_{(i+1)·100/L}(D)` puts the **top slot at the 100th percentile = max(D)**.
Ditto's `D` is a **bounded** packet-size distribution (MTU 1500 B), so its top slot is fine. **Our
CLRT `D` has a thin, heavy tail** (median 12 ms, but max 166 ms from a few outliers), so the naïve
top slot becomes **165.98 ms** and **drags the mean output CLRT to 38–63 ms** and adds ~25–50 ms of
latency to *every* transaction — for a tail that is <1 % of traffic. That is both high-overhead and a
near-RTO risk.

**Fix (already reflected in P-A/P-B):** **cap the pattern at a high percentile (p95–p99) and
fail-open the rare tail** (release those few responses at their natural readiness). This keeps the
output CLRT a stable low value for 95–99 % of traffic at 5–13 ms added latency, and treats the
outliers as fail-open — consistent with the master direction's "MAX_PASS/fail-open is a safety valve,
not the normal path." Any Ditto-style repeating schedule we use must be **capped**, not raw-max.

---

## 4. Recommended FIRST-implementation pattern (trace-derived, caveated)

**P-A fixed, `G = p99 = 25.11 ms`** (99 % coverage, +12.9 ms median added latency, RTO-safe) — or
**`G = p95 = 17.15 ms`** if lower latency is preferred (95 % coverage, +4.9 ms). Use this single
target to **implement the queue and test it against the traces** (steps 2–3). It is a **calibration
baseline**, not the final policy — a fixed G creates a new constant fingerprint (meeting §11), so the
defensible final policy (bounded band P-B or a capped Ditto schedule) is selected at **Phase
4.5/5.5** with the microbench precision + the **physical** SEL-751 readiness distribution.

**Notable:** the real-device target (17–25 ms) is **far smaller than the prior recirculation rig
value of 60 ms**. That 60 ms came from a rig `dev2` profile with a 40 ms tail; the **real** SEL-751
p99 is 25 ms. This confirms the value of deriving the pattern from the real traces rather than reusing
the rig constant (`ASSUMPTIONS_AND_UNKNOWNS.md` #11).

**Defense 1 note.** Defense 1 (delay the ACK) collapses CLRT to ~0 (release the ACK adjacent to the
response), so its "pattern" is degenerate — a near-zero guard-delta, i.e. the D1-C adjacent-slot case
in `CASE_A_QUEUE_DESIGN.md`. The distribution-derived pattern above is a **Defense-2** artifact.

---

## 5. What feeds forward
- `queue_pattern.json` — machine-readable distributions + all candidate patterns + the recommended
  first-impl target, for the queue **control plane** to load (step 2).
- Before implementing (step 2), **audit the former GridCloak TM-queue implementation**
  (`GRIDCLOAK_TM_QUEUE_AUDIT.md`, in progress) to reuse its working shaper/queue setup and avoid its
  known problems.
- Re-run this analysis on the **physical** SEL-751 capture (Phase 5) to confirm the pattern on the
  live device before finalizing the policy (Phase 4.5/5.5).
