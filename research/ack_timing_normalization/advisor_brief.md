# Advisor Brief — ACK-Bearing DNP3 Response Timing Normalization

_A concise meeting brief for Dr. Lin. Backed by a seven-agent evidence study, 2026-07-13.
Research/design only; no code changed. Details in the companion deliverables._

## What Dr. Lin asked

To study **randomized timing normalization of TCP ACK-bearing DNP3 responses** in software and
programmable hardware: what the leak is, what prior work exists, whether normalization beats
jitter, what is implementable on a software server vs Tofino/DPU/SmartNIC/FPGA, how to evaluate it
rigorously, and what is genuinely novel — with verified citations and no overclaiming.

## What was found (headline)

1. **The leak is real and measured.** On the Vision↔Hulk rig, response processing time rises
   linearly with CROB count: SELECT-response R² = 0.9985 (0.179 ms/CROB), OPERATE-response
   R² = 0.9954 (0.214 ms/CROB), a 3× swing over N = 1→16. The response is piggybacked on the TCP
   ACK (9/9), so "ACK timing" and "response processing time" are one observable. Corroborates
   Formby et al. (NDSS 2016). **Bounds:** one sample per N (R² = a clean 10-point line, not a
   replicated law — replication with CIs is planned experiment E1); one device/one rig
   (regression result, **not** device identification — that needs ≥2 stacks); and this leak is on
   **control** responses, whereas the *database-size* leak the study is named for is on the Class-0
   read plane and is still **unmeasured**. CROB count ≠ database size.
2. **Normalization beats jitter for our attacker.** A repeated-poll passive observer (the SCADA
   case) averages i.i.d. jitter away; class-independent normalization it cannot. This is also the
   clean structural differentiation from RAINCOAT (randomize/misdirect grid-content vs
   normalize/indistinguish the device's configuration-complexity signature).
3. **The binding constraint is the master's effective TCP RTO (~200 ms floor, must be measured),
   not any DNP3 timer (5–60 s).** Overshoot → TCP retransmit = the loudest tell to observer and
   IDS alike. A fixed 15–25 ms deadline would flatten the leak with comfortable margin on the
   *measured* RTO (watchdog ≈0.5× measured RTO, not a fixed 150 ms guess).
4. **The proposed contribution is byte-preserving, release-timing-only normalization designed to
   remove a measured device-configuration leak in a live DNP3 session, in-network** (no defense run
   yet). NetWarden (USENIX 2020) already does in-network timing-only Tofino shaping, so the honest
   delta is the **combination** — measured OT config leak + first-packet absolute-deadline release
   + live-DNP3/TCP-RTO bound — not "byte-preserving" alone.

## Which ACK should be targeted

The **ACK-bearing DNP3 RESPONSE** (the piggybacked outstation→master response), on the
**response classes only**: fully shape integrity/event READs; shape SELECT/OPERATE responses to a
fixed N-independent deadline under a criticality allowlist; leave the application CONFIRM and
unsolicited responses alone. There is no link-layer ACK to target (verified absent).

## What is directly supported by literature/measurement vs still hypothesis

| Directly supported | Still hypothesis / to test |
|---|---|
| Processing-time↔CROB-count leak (measured, R²>0.99) | Processing-time↔database-size correlation (needs the DB-size experiment) |
| Jitter is averageable; normalization is not (Crosby, Brumley–Boneh; predictive mitigation) | Size-decorrelation (P6) dominates jitter (P2) at lower latency (pre-registered test) |
| TCP RTO is the binding bound; DNP3 timers 5–60 s (RFCs + OpenDNP3 source) | The *effective* RTO value on Vision (must be measured) |
| Native pacing/gap normalization on Tofino (ditto, NetWarden, TM) | First-packet absolute delay on Tofino (unbuilt recirc-hold; costs are inference) |
| Software absolute-deadline scheduler meets precision (kernel/Python docs) | Whether a device-classification claim holds (needs ≥2 stacks) |

## Three implementation options

- **Option 0 — Software scheduler in `split_server.py` (RECOMMENDED FIRST).** Application-layer
  absolute-deadline release; configurable policies; strict budget + immediate-release fallback;
  full timing telemetry; reproducible seeds. Zero hardware, low risk, rig-validatable now.
  Produces the headline results (the leak, I(T;N)→0 under normalization, the timing budget, the
  Pareto).
- **Option A — In-network pacing / inter-frame-gap normalization on Tofino.** Native via the
  Traffic Manager; byte-preserving; validates in-network control. Does **not** by itself fix
  first-response latency.
- **Option D — Constant-time normalizer on a BlueField DPU (or FPGA).** Native absolute-delay
  (Accurate Send Scheduling / calendar queue); the clean hardware reference and the ground truth
  the Tofino approximations are measured against. Gated on hardware access.
  _(Tofino first-packet absolute delay via recirculation+deadline is a de-risked follow-on, not a
  near-term option — unbuilt and unmeasured on our chip.)_

## Recommended next experiment

Build **Option 0** and run the software policy sweep on the rig: policies P0 (native), P2
(jitter), P3 (constant-time), P6 (size-decorrelation) against the attacker ladder A1–A8, reporting
**I(released_time; CROB-count | size)** (conditional, per Agent F — the size channel stays open in
the byte-preserving phase, so the marginal I(T;N) would inflate the closure claim), the regression
β/R² before/after, and the privacy-vs-latency Pareto with the safe-operating region. Success bar =
the splitting bar: identical measurements, DNP3 CONFIRM, 0 retransmits / 0 resets,
byte-preservation asserted. **Precondition:** measure the effective RTO on Vision first.

## Five questions requiring advisor approval

1. **RAINCOAT framing.** Do you approve the "complementary, not competing — normalization not
   randomization, device-identity not grid-content" positioning, with your RAINCOAT (TSG 2019) as
   the explicit differentiation anchor? (Academically correct; socially your call.)
2. **Phase rule.** Keep this contribution **byte-preserving** (pass-through response delay,
   tighter latency budget), or authorize relaxing to **ACK-decoupling / seq-ack rewrite**
   (proxy-adjacent, more capability, more risk)? The current spec forbids proxy/MITM — this is a
   scope decision only you can make.
3. **One paper or two.** Add the timing characterization + software normalization + budget to
   **this** paper now (makes "and timing" honest, low cost), and hold the Tofino line-rate
   realization + multi-device classifier study for a **follow-on** systems paper (NDSS/CCS/NSDI/
   ToN)? (Recommended.)
4. **Second device.** Can a second DNP3 stack (a different implementation) or the real SEL relay /
   RTAC be obtained for even a gestural cross-device classification result? It is the single
   highest-value missing asset and gates any device-classification claim.
5. **Target venue** for the current paper (drives journal adaptation): TSG / TDSC / ToN short, vs
   a security workshop?
