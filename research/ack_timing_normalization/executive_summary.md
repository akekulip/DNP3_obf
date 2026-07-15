# Executive Summary — Timing Normalization of ACK-Bearing DNP3 Responses

_For Philip and Dr. Lin. Synthesis of a seven-agent evidence study (2026-07-13) on randomized
timing normalization of TCP ACK-bearing DNP3 responses. Research and design only — no harness
source code was changed. Full deliverables in `research/ack_timing_normalization/`._

## Which ACK is being studied

Not a bare TCP acknowledgment, and not a DNP3 link-layer ACK. On this rig the outstation
**piggybacks its DNP3 RESPONSE onto the same TCP segment that acknowledges the request** (9/9
requests, measured), so the ACK time and the response time are the *same wire observable*. The
subject is therefore **response-time normalization of the ACK-bearing DNP3 response**, not "delay
the ACK." Agent C re-verified in the OpenDNP3 source that there is **no link-layer ACK on this
wire at all** (unconfirmed link service only), so the manipulable timing surface reduces to
exactly two things: (a) the TCP-ACK-fused outstation response, and (b) the application CONFIRM
handshake for multi-fragment reads.

## Why the timing leaks — and the measured evidence

A passive on-path observer that reads unencrypted DNP3 can fingerprint the outstation from the
**request→response processing time**. We did not assume this leak; we **measured** it this session
by running the existing `analyze_ack.py` over real Vision↔Hulk rig captures (no code changed):

- **Baseline large READ:** 9/9 piggyback, mean request→ACK 0.239 ms, request→response 1.014 ms.
- **CROB-count sweep — the crown-jewel result:** the response processing time is a
  **near-perfectly linear function of request complexity**. SELECT-response: slope 0.179 ms per
  CROB, **R² = 0.9985**. OPERATE-response: slope 0.214 ms per CROB, **R² = 0.9954**. The
  OPERATE-response grows from 1.62 ms (N=1) to 4.90 ms (N=16) — a 3× swing that linearly encodes
  the number of control points.

This is a real, regression-recoverable **device-configuration / request-complexity** timing
signal on a fielded software outstation. It corroborates the published attack of Formby et al.
(NDSS 2016, "Cross-Layer Response Time" fingerprinting) and the recent PLC result TIDF (NPC 2025).
**Two caveats that bound the claim.** (1) The sweep is **one sample per N-level** — the R² values
describe a clean 10-point line, not a replicated near-deterministic law; a replicated sweep with
confidence intervals is the first planned experiment, and "near-deterministic / R²>0.99 law"
wording waits for it. (2) One device, one rig — a legitimate information-theoretic/regression
result on a single outstation, **not** a device-identification claim (that needs ≥2 stacks). Note
also that this measured leak sits on **control responses** (SELECT/OPERATE); the *database-size*
leak the study is named for lives on the Class-0 read plane and is still **unmeasured** (a
separate planned experiment). CROB count is control-command complexity, not a database-size proxy.

## Normalization vs randomization — why normalization, and why it matters here

- **Randomization** (add i.i.d. jitter to each response) is **averageable**: a repeated-poll
  observer — exactly the SCADA case — recovers the true class mean as √n error shrinks (Crosby
  2009; Brumley–Boneh 2005). It raises the sample count, not what is asymptotically learnable.
- **Normalization** reshapes the *released distribution* to be **class-independent** (constant,
  bucketed, or a decoy device's distribution), so averaging converges to the same target for
  every class and recovers nothing. This is the information-theoretic goal `I(processing_time;
  request_complexity) → 0`, backed by predictive mitigation (CCS 2010/2011) and bucketing
  (CSF 2009).

This is also the clean, structural differentiation from **RAINCOAT** (Dr. Lin's own IEEE TSG 2019
work, citation verified): RAINCOAT **randomizes** control-center acquisition to **misdirect** an
attacker about **grid content**; this work **normalizes** an outstation's response latency to make
its configuration-complexity signature **indistinguishable** — different locus, leaked quantity,
and mechanism. Lead the paper with this wedge.

## Why *bounded* randomized normalization may be preferable

Full constant-time normalization kills the leak but pays maximum latency (pad every response to
the worst case). Pure jitter is cheap but averageable. **Bounded randomized normalization** —
draw a target release time from a class-independent distribution and release at
`max(response_ready, request_time + target)`, under a strict latency budget with immediate
pass-through when the budget cannot be met — is the sweet spot: it removes the *class-dependence*
(the averageable secret) at far lower added latency than constant-time, because it need only make
the distribution class-independent, not degenerate. The evaluation is designed to **test** (not
assume) whether size-decorrelation (policy P6) dominates additive jitter (P2) at equal privacy and
lower latency.

## Operational safety — the binding constraint is TCP RTO, not DNP3

Every DNP3 application/link timer in this stack is **5–60 s** (re-verified in the OpenDNP3 source,
file:line). The binding constraint is two-plus orders of magnitude tighter: the master's
**effective TCP RTO** — the Linux floor `TCP_RTO_MIN` ≈ **200 ms**, though this is a rig
consequence and **must be measured on Vision**, not assumed (`sysctl net.ipv4.tcp_retries2` plus
the observed request→first-retransmit delta). Overshoot the RTO and the master spuriously
retransmits — the single loudest tell to **both** a passive observer and a Zeek `dnp3` correctness
IDS (which is otherwise blind to timing-only manipulation). "Stay under the measured RTO" is
therefore simultaneously the **correctness** bound and the **stealth** bound. A fixed 15–25 ms
normalization deadline would flatten the ms-scale leak while keeping a comfortable margin on the
(to-be-measured) RTO and 100×+ margin on every DNP3 timer — with the hard release-watchdog set to a
fraction (≈0.5×) of the *measured* effective RTO, never a fixed 150 ms guessed against 200 ms.

**Traffic-class safety rule (Agent C):** fully shape the read plane (integrity/Class-0 and event
reads); shape SELECT/OPERATE *responses* only to a fixed, N-independent deadline, gated by an
**operator-supplied criticality allowlist**; **bypass** the application CONFIRM, unsolicited
responses, and any control flagged critical. DNP3 fields reveal operation *type*, never physical
*criticality*, so the element must default to bypassing controls unless explicitly whitelisted —
**safety dominates privacy**. True protection tripping is sub-cycle and not carried by DNP3, so a
DNP3 shaping element is architecturally upstream of any protection loop.

## Recommended first implementation

A **software timing-policy scheduler inside `split_server.py`** (Agent D). Because the replay
server *generates* its response bytes, it schedules `send()` directly — there is **no live packet
to intercept**, which rules out `tc`/netem, eBPF/XDP, DPDK, and proxies for this deliverable and
puts the scheduler at the application layer. A single absolute-deadline release stage using
`time.monotonic_ns` + one `time.sleep` (clock_nanosleep-backed) meets the sub-ms precision
requirement by 2+ orders of magnitude — no thread-per-packet, no busy-wait, timing wheels/DPDK
cited *to reject* as over-engineered for DNP3's single-digit-kbps rate. It must: preserve every
byte; support configurable target distributions (constant / uniform / bucketed / size-decorrelation
/ decoy-match); enforce a strict budget with immediate-release fallback; record requested delay,
actual delay, deadline miss, and release reason; use reproducible seeds; export CSV/JSON. This is
zero-hardware and rig-validatable on the existing setup. **The ~200 ms RTO guard is a placeholder
until measured on Vision.** Hardware realizations (BlueField Accurate Send Scheduling and FPGA
calendar queues are the native homes; Tofino only via an unbuilt recirculation+deadline loop) are
de-risking follow-ons — see `hardware_design.md`.

## Strongest research contribution

A **byte-preserving, release-timing-only** normalization defense **designed to destroy** a
**measured** device-configuration processing-time leak in a **live DNP3/SCADA** session, in-network,
under a TCP-RTO correctness/stealth budget — to be demonstrated by the planned defended runs (no
defense has been executed yet). The lead of the paper is the **measured OT leak and its removal**;
the byte-preserving constraint — forced by DNP3's CRCs and live-master transparency, which forbid
the padding every WF/shaping defense relies on — is the differentiator. Note that **NetWarden**
(USENIX Security 2020) already does in-network timing-only shaping on Tofino, so the honest delta
is not "byte-preserving" alone but the **combination**: a measured OT device-configuration leak +
first-packet absolute-deadline release + a live-DNP3/TCP-RTO correctness bound; that specific
combination is unoccupied in the verified literature. **Recommended framing for THIS paper:** add
the timing characterization + the software-**designed** normalization primitive + the
**provisional (to-be-measured)** timing budget to the existing paper now (makes the title's "and
timing" honest, low marginal cost); hold the Tofino line-rate realization and a real multi-device
classifier study for a follow-on systems paper.

## The five things that still need Dr. Lin's decision

(1) the RAINCOAT framing sign-off; (2) whether to relax the phase rule toward ACK-decoupling/proxy
or stay byte-preserving; (3) one paper vs two; (4) whether a second DNP3 stack / real relay can be
obtained for a cross-device gesture; (5) the target venue. These are developed in `advisor_brief.md`.
