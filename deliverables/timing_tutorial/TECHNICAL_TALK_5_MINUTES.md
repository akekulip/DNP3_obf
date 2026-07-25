# TECHNICAL_TALK_5_MINUTES.md (directive §9)

A five-minute technical explanation for a networking/security audience who knows P4 and TCP but not
this project. Section headers are cue cards; the prose is what to say. Pair with Figs 1, 2, 3, 6, 8, 9.

---

## 1. Threat and metric (0:00–1:00)

Device fingerprinting on ICS networks is passive reconnaissance: an observer who sees only headers and
timing infers the outstation model, then its known weaknesses. One robust feature is Formby's
**Cross-Layer Response Time** — the interval between the transport ACK of a DNP3 request and the
application-layer response. The ACK is emitted by the TCP stack on receipt; the response comes after
the firmware scans I/O and builds the frame. The gap measures internal processing latency, which is
stable per device and distinct across devices. On our physical SEL-751: median 2.03 ms, sd 10.33 ms,
**2.73 bits** of observer entropy at 1 ms resolution (Fig 3, Fig 6).

## 2. Design constraints (1:00–1:45)

Three constraints shaped the design. **Non-cooperative:** the outstation is a certified relay we
cannot reflash — the defense must work on an unmodified device. **No fast-path control plane:** a
controller that re-times each response adds software jitter and puts a CPU in the SCADA critical path;
we allow the control plane to set exactly one policy value, G, once. **Byte-preserving:** we must not
recompute CRCs or edit DNP3 fields, so the *original* response packet has to survive untouched. Those
rule out endpoint shims, proxy/MITM re-injection, and any rewrite-based padding.

## 3. Mechanism (1:45–3:15)

The classifier runs in the Tofino ingress pipeline (Fig 1). It recognizes the DNP3 transaction — the
request, its transport ACK, and the response — from the real frame structure (data_offset=8 framing on
this relay). Three moving parts (Fig 2):

- **Queue-resident hold.** When the real response arrives, we steer the original packet into a
  *low*-priority TM queue (Q_RESP, qid 1) and simply don't schedule it. The packet sits in silicon,
  unmodified. Byte-identity verified 100/100.

- **Blocker reservoir + strict priority.** A reservoir of internal "blocker" tokens (EtherType
  0x88c1, K ≥ 64) recirculates through a *high*-priority queue (Q_BLOCK, qid 7) on internal loopback
  port dp8. Strict priority means: while Q_BLOCK is non-empty, the scheduler never serves Q_RESP — the
  response is starved, i.e. held. The tokens never egress; the master sees zero of them. Holding is
  therefore an emergent scheduling property, not a software timer.

- **Data-plane deadline.** The transport ACK arms a per-transaction deadline t_ack + G, written once
  (idempotent first-ACK `RegisterAction`, so retransmits can't move it), tick-aligned to 256 ns
  because the armed marker lives in the packed state word's low bit. Each recirculating blocker
  compares now to the deadline via a **sign-bit ternary** on `now − deadline` (the target can't do a
  32-bit magnitude compare in one gateway). Past the deadline the token is terminated instead of
  re-injected; the reservoir drains, Q_BLOCK empties, strict priority releases Q_RESP, and the
  untouched response egresses.

## 4. Results (3:15–4:15)

At G = 25 ms over 100 reps on the SEL-751's real frames (Fig 3): median 24.999 ms, sd **0.010 ms** —
a 1000× spread collapse. Leakage (Fig 6, Miller-Madow with bootstrap CIs): **2.73 → 0.00 bits** at
1 ms and 500 µs; residual entropy only appears below 100 µs and is the fixed implementation tail, not
device behaviour. That tail (Fig 8) decomposes into c1 = 14.4 ns (deadline → first blocker sees it)
and c2 = 1720.1 ns (termination → egress), total 1734.5 ns, sd 7.34 ns — identical regardless of
device, so it carries no fingerprint. Fail-open: a token that exhausts its pass budget releases the
response rather than dropping it. The G-guard (Fig 9) flags G below native CLRT as zero-hold.
Footprint: 10/12 ingress stages, 0 egress, 0 TCAM.

## 5. Honesty and scope (4:15–5:00)

Claim discipline matters here. This closes the **CLRT-magnitude channel** — a within-channel entropy
reduction and a working mechanism on real silicon. It does **not** deliver device anonymity: ACK mode
(the SEL-751 uniquely sends a separate ACK) and TCP-stack signature (TTL/MSS/window) are independent
channels we don't touch, and on our 3-device corpus they already identify the relay at accuracy 1.000.
Because only the SEL-751 has a CLRT at all here, closing it is an anonymity-set-of-one result. It is
also replay of the relay's real frames, not a live inline session held in real time, and it is not
size obfuscation — that's a separate, unproven axis, out of scope this week. The contribution is the
timing axis: proven, byte-preserving, controller-free, chaff-free, on Tofino-1. Turning it into an
end-to-end security result needs a fleet of separate-ACK devices normalized to a shared G with the
other channels held constant — that's the next step.
