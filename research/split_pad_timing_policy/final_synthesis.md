# Final Synthesis — Split / Pad / Timing Combined Policy

_The spec's §16 closeout, after the Agent-J hostile-review pass and the corrections it required.
Reviewer verdict: **major-revision** — unusually honest package that holds on 8 of 9 attack points, all
5 flagged new citations verified, no codename leak; the required fixes are applied (RTO three-inequality
model replacing the wrong cumulative bound; the cleartext-now/tunnel-later threat-model reconciliation +
the A0 direct-read baseline experiment; the malformed matrix rows realigned; [M]-label and n=1/N-caveat
slips fixed; size-decorrelate default conditioned on the self-leak test). Evidence tags: [M] measured ·
[S] standard · [V] vendor · [P] paper (abstract-level) · [I] inference · [H] hypothesis._

## Main fingerprinting channels
Request complexity / CROB count leaks on **two channels measured this rig** (n=1 per N; one device):
**size** (14.6 B/CROB, R²=0.9999) and **timing** (0.18–0.21 ms/CROB, R²≈0.99). Read-plane database size
leaks on **size** (~5.7 B/point). Segmentation (frame/segment/fragment counts) and packet count are
secondary size-axis channels; polling cadence and silence are activity channels. **On cleartext DNP3 a
full-DPI observer also reads CROB count directly off the payload** — so the metadata defense targets a
**no-DPI / NetFlow-grade** observer now, and a full observer only under a future encrypted tunnel (A0
quantifies the gap).

## When to split
When the natural packet/frame size is a distinguishing feature, the response is large enough to
repartition (read plane), a safe boundary exists (always), the packet-count increase is within budget,
**and** timing normalization is applied so the chunk schedule isn't a new fingerprint.
## What to split
Read-plane responses (Class-0/event READs, multi-fragment). Not small control responses (few chunks).
## How to split
On **CRC-block boundaries (B1)** for auditability (any byte offset also reassembles — CRC-alignment is
a defense choice, not a master requirement), at a **decoy-/target-matched, not fixed** granularity,
**paced** (pacing, not `TCP_NODELAY`, is what keeps it split on the wire), created **upstream** (software/
DPU — Tofino can pace but not create the split). RTO binds per-hop (gap + initial), not cumulatively;
bpc=1 is measured-feasible.
## When not to split
Small control responses (no size benefit); fixed granularity (self-fingerprint); without pacing
(re-merges); as a claim to hide total size (it never does — sum-the-chunks recovers it, and at bpc=1 the
chunk count itself re-leaks magnitude).

## When to pad
Only to close the size leak — which nothing byte-preserving can do now.
## What to pad
(Future) the total volume of small responses, to a class-independent target.
## How to pad
(Future) in an encrypted tunnel envelope (inner DNP3 bytes untouched).
## Why current padding may be unavailable
**No byte-preserving, semantically-inert DNP3 padding exists at any layer** [M][S]: invalid filler is
rejected (OUT_OF_RANGE; partial SELECT blocks OPERATE), valid filler becomes real data/control, and the
APDU has no length field, no NUL/padding object, and a 7-value qualifier whitelist. A measured +
parser-level **negative result**.
## Future safe padding options (ranked, safety first)
1. Encrypted tunnel with shaped padding (safest, ~+590% bw to close N=1→16, tunable via DP shaping);
2. gateway/RTAC inert read-plane points (distinguishability caveat [H]); 3. read-plane decoy reads;
4. active in-path proxy (least safe). **Never pad a live control.**

## When to normalize timing
Whenever timing depends on the secret and the observer repeats the poll (SCADA); skip on critical/urgent
traffic, insufficient budget, uncertain RTO margin, ordering risk, or when it would create a beacon.
## Which timing signals
Request→response delay (primary), inter-chunk/inter-fragment gaps (whenever splitting), transaction
duration, SELECT→OPERATE interval; leave the CONFIRM verbatim.
## Recommended timing policy
**Class-independent bounded normalization** (uniform-within-budget / size-complexity-decorrelation toward
a common target) — un-averageable, unlike jitter — **conditioned on the self-leak test** `I(choice;S|Y)≈0`
(until it passes on the rig, the class worst-case **constant** is the safe default). Applied to O→M
response classes only, under an operator allowlist.
## Traffic classes to bypass
Application CONFIRM; unsolicited responses; any control (SELECT/OPERATE/DIRECT_OPERATE) not allowlisted
for shaping; critical/protection traffic (never delayed). Default-deny controls; fail open.
## Deadline and RTO policy
Three separate inequalities, not one sum: initial hold < measured RTO; each per-hop gap < measured RTO;
cumulative < operational deadline (5 s app / 10 s SBO). RTO measured on **Hulk** for splits, **Vision**
for holds; watchdog ≈0.5× the *measured* RTO. Overshoot a per-hop bound → retransmit = loudest tell.

## Recommended combined decision rule
`classify → bypass if critical/unsupported/uncertain → choose public class-independent target profile →
split large read-plane responses (B1, paced, decoy-matched) → pad if a safe mechanism exists else record
residual size leak → release on a class-independent timing schedule under the three-inequality budget,
per-flow FIFO, fail-open.` Dominant strategy: **shape the read plane, bypass the control plane** (control
is lowest-privacy-value + highest-safety-cost; read plane is high-value + low-risk).

## Recommended software implementation
Application-layer engine in the replay/split server (generates bytes → schedules `send()`; no
kernel/eBPF/DPDK): per-flow FIFO deque (not a global min-heap), monotonic-deadline sleep (Python 3.8
target host; `random.Random`), measured-RTO-fraction watchdog, immediate-release fallback, residual-size-
leak telemetry, reproducible seeds. Timing wheels/DPDK cited to reject.
## Recommended Tofino implementation
Stage 1 (classify + telemetry) + Stage 2 (pace already-split chunks, TM gap-normalization) — buildable
in-phase (~4–5 stages, 2 queues, 3 SALUs). Cannot create the split; first-response absolute delay is an
**unbuilt** recirc-hold (inference, future).
## Recommended DPU/FPGA implementation
BlueField Accurate Send Scheduling (500 ns–1 ms granularity, ~4.19 s window — HW fastpath, avoids the ARM
ceiling) or FPGA calendar queue for native absolute-delay timed release; the future home for tunnel
padding. Both [V]/[P], not measured on our hardware.

## Expected privacy benefit
Timing channel: `I(T;N|size)→0` under class-independent normalization (un-averageable). Size channel:
**none in-phase** (residual). Net: closes the timing side channel against a repeated-poll no-DPI observer;
the size side channel and the cleartext payload remain until a future tunnel phase.
## Expected latency overhead
15–25 ms per shaped response (bounded by measured RTO per-hop); split adds inter-chunk gaps (per-hop <
RTO).
## Expected bandwidth overhead
Timing: 0. Split: 0 app bytes, +packet/header overhead (~3–7× wire bytes at finest granularity, ~5–10×
packets). Padding (future): +up to ~590% to close the size leak.
## Expected hardware overhead
Software: ≪0.1% core, <1 held frame. Tofino S1–2: ~4–5 stages / 2 queues / 3 SALUs; recirc-hold <0.1%
pipe (unbuilt). DPU/FPGA: within one held-frame table; ~3 orders of margin on the ASS timing window.

## Strongest contribution
A **criticality-aware conditional split/pad/timing decision policy** grounded in the **dual-channel
measurement** (same secret leaks on size R²=0.9999 AND timing R²≈0.99), with the honest asymmetry —
**timing closeable now, size a future-phase residual** — as the organizing result.
## Strongest negative result
**No byte-preserving DNP3 padding exists at any layer** (measured + parser-level), and **splitting
relocates the size leak to packet count rather than removing it** (`I(chunks;N)≈I(size;N)`) — so the size
channel cannot be closed in the current phase.
## Main reviewer concern
The current-phase motivation under cleartext DNP3 (a full-DPI observer reads CROB count directly), and
that both flagship leaks are n=1 per N-level with **no defended run yet** — capping the claim to a
design + preliminary-measurement paper until Precondition #0 + A0 + one defended run land.
## Immediate next experiment
**A0 — the direct-payload-read baseline** (how much a cleartext-parsing observer already recovers),
alongside measuring the effective RTO (Vision + Hulk) and **replicating the n=1/N leaks** (E1/E1′, ≥30/N,
bootstrap CI). These gate every downstream claim and answer the main reviewer concern.
## Evidence confidence
Dual-channel leak: **medium** as single-device 10-point lines (**n=1/N** — replicate before "law").
Padding negative result: **high** (measured + source-grounded). Split relocation / total-bytes-not-hidden:
**high** ([M]). Transport/DNP3 constraints: **high** ([S]/[V]). Literature: **high** integrity
(abstract-level; 14 new verified; 2 preprints flagged). Software design: **high** as design, unbuilt.
Tofino S1–2: medium (sketch); recirc-hold: low/inference (unbuilt). DPU/FPGA: high for native capability
([V]/[P]), unmeasured on our HW. The defense's efficacy: **untested** (no defended run).
