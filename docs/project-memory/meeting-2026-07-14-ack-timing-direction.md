---
name: meeting-2026-07-14-ack-timing-direction
description: "Advisor meeting 2026-07-14 — agreed direction: add ACK/latency timing obfuscation (3rd primitive alongside split+pad), decoy-via-configured-index padding, request/response direction-awareness; socket-first then P4"
metadata: 
  node_type: memory
  type: project
  originSessionId: c3ef1508-9e17-4f79-bd13-7384aa7ff5ab
---

Advisor meeting, 2026-07-14 (DNP3 obfuscation line). Three threads + agreed next steps.

**1. Multi-CROB invalid-index (reported, DONE):** confirmed OUT_OF_RANGE(12) fires for any
unconfigured binary-output index regardless of position (start/mid/end); an invalid index makes
the stack send SELECT+response but NO OPERATE (partial select blocks operate). Distinct from
TOO_MANY_OPS(8) at 16+ CROBs. See [[multicrob-invalid-index-padding]],
[[multicrob-invalid-index-status-refactor]].

**2. Decoy padding — new decision:** do NOT pad with *invalid* indices (the OUT_OF_RANGE error
is a giveaway that padding is happening). Instead **configure extra binary-output points on the
outstation that exist but drive no physical IO** (accept the control, return SUCCESS, trip
nothing). Both request AND response grow → clean padding, no error signature. Do it on the
OpenDNP3 sim first, then verify on the real SEL-751 (attach the object to no output/IO).

**3. Split-vs-pad policy (agreed):** big READ / class-0 integrity responses → SPLIT the response
(you can't pad a read request). Small commands → PAD. See [[split-pad-timing-policy-study]].

**4. Direction-awareness (novelty angle):** existing obfuscation work does NOT distinguish
request vs response or operation type; treat the two directions as separate flows. Potential
contribution.

**5. ACK/latency timing — THE new primitive (main task this week):** Defends against Formby-style
(Georgia Tech, NDSS'16) cross-layer response-time (CLRT) device fingerprinting = the gap between
the outstation's TCP ACK and its DNP3 application response. Two device regimes exist and I
VERIFIED them in Traffic Trace/: **SEL-751 (10.0.0.1) sends a SEPARATE standalone ACK** (~300
pure ACKs / 299 responses) with a measurable CLRT ≈ **11 ms typical (mean 14.6, max 166)** — the
attack works. **AB1400, ION7550, and the 10.0.0.2 reference PIGGYBACK the ACK** onto the response
(≈0-1 pure ACKs) → CLRT≈0, attacker falls back to RTT (~16-17 ms). Defense mechanics: you can
only ADD per-packet delay, never remove. Separate-ACK case → **delay the ACK toward the response
to SHRINK the measured CLRT** (move the fingerprint down), or delay the response to grow it;
combined case → delay the whole response (adds to RTT) or craft a fake separate ACK (hard —
needs P4 recirculation, appendix-only). Add a **randomized delay within a bound (e.g. 10-15 ms)**
so the measured time varies per transaction and no stable fingerprint range forms.
See [[ack-timing-normalization-study]].

**Agreed roadmap:** implement the ACK-separation + latency injection in **Python sockets first**
(reproduce the separate-ACK case, add 10/50 ms delays, shrink/grow the ACK↔response gap), get
results, THEN port to **P4/Tofino**; a SmartNIC (CPU/NPU-based, "not ASIC" — likely Netronome,
name garbled in transcript) implementation by another team member is a later stretch. Paper:
the fabricated-ACK / separate-ACK edge case goes in the APPENDIX; keep split+pad+timing as the
core contribution. Move real-device testing off simulation onto the SEL-751 after the socket PoC.

**Open/ambiguous (confirm with advisor):** exact identity of the "record/Roomput" paper he read;
the SmartNIC model + which team member; whether "our trace" in his note means a specific new pcap
or the combined-ACK devices already in Traffic Trace/.
