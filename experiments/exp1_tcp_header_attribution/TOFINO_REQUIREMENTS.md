# Experiment 1 — Tofino requirements for the surviving candidate

> **CORRECTION (Experiment 2A design).** This document framed the live-safe path as per-flow option
> *translation* (TSval/ISN offsets), which it flagged as resource-tight. That framing is superseded: the
> realizable, endpoint-safe mechanism is **handshake normalization** (suppress TS/WScale/SACK in the SYN
> and SYN-ACK, so the endpoints negotiate a canonical minimal option set and do not emit those options
> thereafter), which is **stateless / packet-bounded** and needs no per-flow translation registers. The
> "operations requiring per-flow state" and "translation" discussion below applies only to alternatives
> that keep options and rewrite their values; the recommended mechanism does not. The authoritative
> requirements are in `../exp2_handshake_normalizer/EXPERIMENT_2A_DESIGN.md`.

Without compiling or implementing P4, this maps the offline T2 transformation (canonical TCP option
layout) to the state and operations a future Tofino implementation would need. This is analysis, not a
feasibility claim; the compile question is Experiment 2 and the endpoint-safety question is Experiment 3.

## The surviving candidate

Normalize the outstation's TCP option layout to a public canonical profile: SYN/SYN-ACK carry only a
public MSS at a public `data_offset`; established segments carry no options; TTL, IP-ID, and MSS value
are canonicalized; IPv4/TCP checksums corrected; Ethernet minimum-length padding applied. Offline this
removes the dominant header fingerprint (handshake distinct 3 -> 1). Two ways to realize the option
change matter very differently on hardware, and the offline result used the first:

- **Suppression** (what the offline T2 did): strip the option bytes so the observer sees a canonical
  header. Packet-bounded, but on a live connection it removes options the endpoints negotiated and rely
  on end-to-end, so it is an endpoint-safety hazard (below).
- **Translation** (the likely live-safe path): keep the options but rewrite their values to public
  constants, preserving the end-to-end semantics the endpoints need (e.g., TSval offset with correct
  echo). This needs per-flow bidirectional state.

## Packet-bounded operations (no per-flow state)

- Rewrite the SYN/SYN-ACK option region to a canonical layout; rewrite the MSS option value to a public
  constant.
- Strip or canonicalize TCP options on each segment (suppression path).
- Canonicalize TTL and set IP-ID per a public policy; set DF.
- Ethernet minimum-length padding to 60 bytes.
- Incremental IPv4 checksum update (header-only delta) and incremental TCP checksum update for the
  changed/removed option bytes (the removed bytes are known, so no payload read is required).

## Operations requiring per-flow (connection) state

- **TSval/TSecr translation** (the live-safe alternative to suppression): a per-flow, per-direction
  32-bit offset with correct TSecr echo on the reverse direction. This is the state the frozen resource
  audit flags as landing on the saturated ingress tail (stages 8-11 at 16/16 logical tables) and the
  exhausted 32-bit PHV group (W0-15 at 512/512).
- **ISN / sequence normalization** (T3): a per-flow seq delta in the sender direction and the matching
  ack delta on the reverse direction; wraparound handling; SYN/FIN/retransmission consistency.
- **Window-value normalization**: the residual window tell (AB1400 constant 2048, ION7550 small/zero,
  SEL751 scaled) needs per-flow flow-control awareness to normalize safely; a naive fixed public window
  changes flow control.
- **Negotiated-option tracking**: to keep the observable stream self-consistent (a connection that
  "did not negotiate TS" must not later show TS), the switch must track each flow's canonicalized
  negotiation state.

## Operations requiring byte insertion or deletion

- Stripping TCP options shortens the TCP header and shifts the payload boundary (deletion); padding a
  short header to a public `data_offset` inserts option bytes. This is a variable-length header edit
  with payload preserved: it needs a variable-length TCP-option parser and a deparser that emits the
  canonical option region. It does not need payload reassembly (the DNP3 bytes are untouched), which is
  what distinguishes it from the size/count problem.

## Operations that might exceed Tofino parser / PHV / stage resources

- A variable-length TCP-option parser (up to 40 option bytes) consumes parser states / TCAM.
- The per-flow TS/ISN/window state is 32-bit-per-flow register state on the already-saturated W0-15
  group and tail stages.
- The runtime-delta TCP checksum is the specific compile risk flagged in the frozen resource audit.

## Fail-open, counters (design placeholders, not implemented)

A real normalizer would need fail-open on any packet it cannot canonicalize (forward unchanged and
count it), a privacy-failure counter per departure from the canonical profile, and flow-table cleanup on
teardown/timeout/reuse. These are named here so Experiment 2's compile probe includes them rather than
an inert skeleton.

## What Experiment 2 must answer (compile-only, standalone)

Whether the variable-length option parser + canonical deparser + the per-flow state (for the translation
path) + the runtime-delta TCP checksum + the counters **compile standalone on the target** within
stages, logical tables, PHV groups, stateful ALUs, and parser resources, measured before any Defense 4
co-residency. A compile failure would be a bounded result for this normalizer, not a universal
impossibility.

## What Experiment 3 must answer (endpoint safety)

Whether the suppression path (which produced the offline collapse) is endpoint-safe on a live
connection, or whether removing negotiated options breaks PAWS/RTTM, flow control, and retransmission,
forcing the per-flow translation path instead. The offline result shows the fingerprint *can* be made to
disappear from a trace; it does not show the endpoints would still work, and the honest expectation is
that the live-safe realization needs the per-flow state the resource audit flags as tight.
