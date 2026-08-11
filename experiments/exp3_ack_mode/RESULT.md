# Experiment 3 — ACK-mode normalization: result

**Verdict: ACK-MODE COLLAPSE verified offline + compiles (9.13.1/9.13.2) + confirmed on real Tofino-1.**
Closes the highest-value residual from `../exp2_handshake_normalizer/CROSS_AXIS_INDISTINGUISHABILITY.md`.

- **Distinguisher:** Case-A SEL-751 emits a standalone pure ACK **then** the response (2 packets);
  Case-B ION7550 emits 1 combined ACK+response. This survives handshake + CLRT normalization.
- **Mechanism:** suppress the outstation's standalone pure ACK (payload-less, ACK-only, not
  SYN/FIN/RST); the DNP3 response that follows within the CLRT re-ACKs, so the master is
  acknowledged inside its RTO. The Case-A outstation then emits ONE observable packet — matching
  Case B on the ACK-mode axis. Packet-bounded, no reassembly (`ig_dprsr.drop_ctl`).
- **Offline oracle (`oracle_ackmode.py`): 10/10** — Case A 2→1 packet, no standalone ACK remains,
  Case B unchanged, **axis COLLAPSES** (both `(1 packet, no standalone ACK)`); surviving response
  keeps its ack + bytes; master→outstation ACK never suppressed.
- **Compile: PASS** — `p4src/ack_mode_normalizer.p4`, bf-p4c 9.13.1 (`tofino.bin` 1.34 MB) and 9.13.2
  on the switch host, 0 errors.
- **Silicon: 3/3** (`evidence/asic_ackmode.log`, via pktgen + hardware counters): outstation pure
  ACK → suppressed (ctr 1); outstation response → forwarded (ctr 0); master ACK → forwarded (ctr 0).
- **Safety envelope (documented):** safe for the DNP3 request→ACK→response pattern within the CLRT
  budget; a fully robust deployment needs light per-flow "response pending" state for CONFIRM /
  keepalive ACKs that are not followed by data (the store-and-forward boundary) — the analogue of
  the handshake normalizer's endpoint-safety (Experiment-3) question.

## Axis scorecard update
handshake header ✅ · CLRT magnitude ✅ (Defense 4) · **ACK-mode ✅ (this experiment)** ·
READ size 🔶 (primitive built) · segmentation 🔶 · SBO presence-of-controls ❌ (class fingerprint).
