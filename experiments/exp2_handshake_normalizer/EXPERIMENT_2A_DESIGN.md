# Experiment 2A — handshake TCP-header normalizer: design (revised after review)

**Design phase. No P4 implementation, no compile, no hardware, no endpoint testing.** This specifies the
mechanism, the exact per-packet transformations, the flow-state machine, the failure behavior, a resource
estimate, and the compile success criteria for a standalone Tofino TCP handshake normalizer. The compile
itself (Experiment 2) is authorized only after this design survives review; the review outcome and the
changes it forced are in `REVIEW.md`.

Grounded in Experiment 1 (`../exp1_tcp_header_attribution/`): the outstation TCP-stack fingerprint is
carried by the TCP option layout (SYN-ACK options, established `data_offset`). This design normalizes
**only the handshake** and relies on the endpoints' own RFC option-negotiation fallback to keep
established segments clean, which is stateless, packet-bounded, and (argued here, proven in Experiment 3)
endpoint-safe.

## 0. Scope, threat, assumptions, non-goals

- Testbed: `Master <-> Tofino-1 <-> Outstation`, unchanged endpoints, no encryption, no peer.
- Observable: a passive master-facing observer reading TCP/IP headers. Secret: outstation identity via
  its TCP-option fingerprint. Public: the transaction and its DNP3 semantics.
- **Deployment assumption (load-bearing, from review):** the switch is **in-path from connection setup
  with symmetric routing**, so it sees the SYN of every flow it normalizes. Under this assumption the
  "detect a non-compliant SYN-ACK statelessly" rule (below) is sound. For mid-stream adoption, asymmetric
  paths, or a switch reboot mid-connection, that invariant fails and per-flow SYN-seen state would be
  needed; those cases are handled by fail-open (§4), not by rewriting.
- Addresses **only** the TCP-option-layout fingerprint plus the cheap L3 tells (TTL, IP-ID). Does **not**
  address the TCP window value (declared residual), size, count, or interarrival timing.
- Non-goals for the Experiment 2 compile: no endpoint testing, no hardware, no Defense 4 co-residency.

## 1. Mechanism

### 1.1 The public canonical profile P*

Every connection is forced to the pre-RFC-1323 baseline (the minimal option set every stack supports),
which also matches the ION7550 native profile, so a normalized packet is a plausible real stack:

- **IPv4:** `TTL = 64`; `IP-ID = 0` **only when DF is set** (RFC 6864); **DF preserved** from the original
  packet (not forced), so PMTU behavior is unchanged.
- **TCP SYN and SYN-ACK:** the observable option set is `[MSS]` only (`data_offset = 6`), no Timestamps,
  Window Scale, or SACK-permitted.
- **TCP established (DATA / ACK / FIN):** no options (`data_offset = 5`), produced by the endpoints
  themselves (§1.2), enforced not rewritten (§2).
- **MSS is clamped, never set:** advertised MSS becomes `min(original_MSS, 1460)`. Clamping down is always
  safe (the peer sends smaller segments); a set could *raise* an endpoint's advertised MSS and, with DF,
  create a PMTU blackhole (review objection). If the real egress MTU is known it bounds the clamp further.
- Checksums recomputed on every modified packet (§5).

### 1.2 Why normalizing the handshake is sufficient and safe (argued; proven in Experiment 3)

Timestamps and Window Scale (RFC 7323) and SACK-permitted (RFC 2018) are **negotiated**: used only if
**both** SYN and SYN-ACK carry them. RFC 1122 §4.2.2.5 requires a TCP to tolerate absent/unknown options
without error. So stripping these from the **SYN** (master -> outstation) forces a compliant outstation to
reply with a minimal SYN-ACK, and neither endpoint uses those options thereafter; established segments
carry no options **without per-segment rewrite**. Consequences (argued acceptable on a low-rate, low-BDP
DNP3 link, to be **proven** in Experiment 3, not inferred from Experiment 1): no PAWS (no wrap risk at
DNP3 rates), coarser RTT (Karn's-algorithm RTO), no window scaling (65535 window covers even the
12,204-byte READ), and RTO-driven loss recovery without SACK. Experiment 1 observed the devices declining
options in reply to a **full** SYN; it did **not** observe their fallback to a **stripped** SYN, which is
exactly Experiment 3's job. Sequence-space note (confirmed by both reviews): SYN options are outside the
TCP sequence space (SEQ counts payload plus the SYN/FIN phantom byte), so shortening the SYN header
changes no seq/ack on that or any later packet.

### 1.3 What the switch rewrites

- The **SYN** option region -> canonical `[MSS(clamped)]` (the authoritative act).
- The **SYN-ACK**: canonicalize the **MSS value only** (clamp) and layout **when it is already minimal**;
  **never strip a negotiated option from a SYN-ACK** (§2, §4).
- Per-packet **TTL**; **IP-ID** when DF is set.
- It does **not** rewrite established-segment options (enforce + count instead), does **not** touch TCP
  sequence/acknowledgment numbers, and does **not** touch payload. Stateless / packet-bounded; no per-flow
  translation registers.

## 2. Exact packet transformations

All modified packets recompute IPv4 total length, TCP `data_offset`, and IPv4 + TCP checksums. An
**option allow/deny list** governs every rewrite: allowed in the canonical output = MSS only; any
**unknown option kind, or TCP-MD5 (RFC 2385) / TCP-AO (RFC 5925)** seen anywhere = **fail-open, forward
unchanged, count** (MD5/AO are per-segment security associations, not handshake negotiations, and must
never be stripped).

| Packet (direction) | action |
|---|---|
| **SYN (master -> outstation)**, no payload, no TFO cookie | replace option region with `[MSS(min(orig,1460))]` (`data_offset` -> 6); TTL=64; IP-ID=0 if DF; recompute checksums |
| **SYN or SYN-ACK carrying payload or a TFO cookie (RFC 7413)** | **fail-open**: forward unchanged, count `tfo_or_data_syn_bypass` (payload in a SYN is in seq space; do not touch) |
| **SYN-ACK (outstation -> master), option set already minimal** (only MSS +/- NOP/EOL) | canonicalize the **MSS value** (clamp) and strip only NOP/EOL padding -> `[MSS]`; TTL; IP-ID if DF; recompute. No negotiated option is present, so nothing negotiated is removed |
| **SYN-ACK carrying a negotiated option** (TS/WScale/SACK present -> non-compliant outstation) | **fail-open**: forward unchanged, count `noncompliant_bypass`; do NOT strip (would desync window scale between the ends) |
| **DATA / bare ACK / FIN (both)** | **enforce**: expected `data_offset = 5`; if a disallowed option is present (e.g. a pre-existing flow still using TS), **forward unchanged** and count `established_leak`; never rewrite mid-stream. TTL; IP-ID if DF; recompute IPv4 checksum |
| **RST (both)** | TTL; IP-ID if DF; forward promptly |
| **MPTCP / simultaneous-open / any unhandled shape** | out of scope for DNP3 (client/server); fail-open forward unchanged + count |

Ethernet minimum-length padding is **not** a P4 concern: the Tofino MAC auto-pads runt frames on
transmit (review correction).

## 3. Flow-state machine

Confirmed stateless by both reviews. The core is **stateless per packet** (classify by TCP flags; rewrite
by §2). **For the first compile probe, use global counters and no flow table**, to isolate the
parser/checksum questions.

An **optional** minimal per-flow table (a few bits/flow: `state`, `noncompliant_seen`) may later support
per-flow accounting; it is compile-cheap (one SALU / one stage) and does **not** use 32-bit translation
registers. TF1 has no native data-plane idle eviction, so eviction is a control-plane sweep or
hash-overwrite (collision aliasing tolerated); if the table is omitted, counting is global. States, if
used: NEW --SYN--> SYN_SEEN --SYN-ACK--> ESTABLISHED --FIN/RST--> CLOSING --sweep--> evicted. Rewrite
decisions never depend on state (retransmitted SYN/SYN-ACK normalize identically and idempotently).

## 4. Failure behavior

**Fail-open is mandatory** — a live protection-relay link never loses or corrupts a packet for privacy.
Any packet the normalizer cannot safely canonicalize is **forwarded unchanged** and counted. States and
counters (consistent with `../../PROOF_OBLIGATIONS.md`):

- `PATTERN_NORMAL` — canonical profile enforced.
- `AVAILABILITY_BYPASS` — forwarded unchanged + counted for: a SYN-ACK carrying a negotiated option
  (`noncompliant_bypass`); a SYN/SYN-ACK carrying payload or a TFO cookie (`tfo_or_data_syn_bypass`); an
  MD5/AO or unknown option kind (`security_option_bypass`); any packet that cannot be rewritten.
- `PATTERN_LEAK` — a pre-existing/established flow still emitting a disallowed option; forwarded unchanged,
  `established_leak` incremented. Such flows **leak the fingerprint by design until they re-establish**;
  the normalizer never rewrites them mid-stream (that is the unsafe path Experiment 1's correction flagged).
- `PATTERN_DROP` — **not used**; the normalizer never drops.

No privacy is claimed for any flow whose bypass/leak counters are nonzero. Counters are real stateful ALU
counters (not inert), so the compile probe must include them.

## 5. Resource estimate (no compile; corrected by the Tofino review)

Standalone (no Defense 4 co-residency), the full pipe is available. The design is respecified to the
idioms the frozen codebase already compiles, which removes the two risks the first draft named:

- **Option handling by fixed-width extraction, not a TLV walk.** The normalizer does **not** decode
  options. It classifies SYN/SYN-ACK by flags and consumes the option region as a fixed-width blob keyed
  on `data_offset`, extending the frozen program's `opt4/8/12` chain to `data_offset in {6..15}`
  (24..60-byte TCP header, <=40 option bytes): about **10 fixed extract states, no kind/length decode, no
  runtime advance** (the frozen program's own comment notes "the TNA parser cannot advance by a runtime
  amount"). Frozen ingress parser baseline is 19 states / 103 of 256 rows; the extension adds a bounded
  ~10 states, far under 256. **This is the only non-trivial resource.**
- **Whole-region suppression via `setInvalid` + a fresh MSS header, not in-place rewrite.** `setInvalid`
  the extracted old-option blob (validity is metadata, free) and `setValid` a freshly built 4-byte
  canonical MSS header. Normal-PHV cost is then only the ~4-byte MSS header plus `data_offset` (4b), `ttl`
  (8b), and `ip.id` (16b) — it does **not** pull the <=40 old option bytes into normal PHV, avoiding the
  normal-PHV pressure that an in-place rewrite would cause (the frozen program keeps `tcp_opt*` in
  tagalong precisely because it never writes them).
- **Full deparser checksum recompute, not an incremental delta.** SYN/SYN-ACK carry no payload, so the
  entire TCP-checksum-covered region (pseudo-header + TCP header + the one MSS option) is in PHV; a full
  `Checksum.update()` over the canonical field set is used, with the TCP pseudo-header length a constant
  (24). No old option bytes, no payload read. IPv4 checksum is the textbook header-only deparser case.
  Established segments change only IPv4 fields, so only the IPv4 checksum updates. (Correction: the first
  draft's claim that "the resource audit flagged the TCP checksum" is **false** — the frozen audit never
  mentions checksum; that claim came from an assertion in Experiment 1's `TOFINO_REQUIREMENTS.md`, now
  retracted. The TNA checksum extern is lab-proven on this testbed.)
- **No per-flow 32-bit state** (SYN options outside the seq space); the optional flag table is one SALU /
  one stage. Stateful ALUs: the fail-open counters.

**Corrected expectation:** the normalizer **fits comfortably** standalone — a handful of MAU stages and
logical tables far under the 12-stage / 16-LTID envelope, minimal normal PHV, tagalong a non-issue; the
only resource to actually measure is the `data_offset`-keyed fixed option-extraction parser states.

## 6. Compile success criteria (for the Experiment 2 compile that follows)

Experiment 2 compiles this design with `bf-p4c` for the Tofino target, standalone, and passes if:

1. It compiles cleanly (no fitting error) with: the `data_offset`-keyed fixed option extraction
   (`data_offset` 6..15); the SYN option-suppression via `setInvalid` + a canonical MSS header; the
   SYN-ACK MSS-clamp-only path; the established-segment enforcement; the option allow/deny (MD5/AO/unknown
   -> fail-open); the full deparser TCP + IPv4 checksum recompute; and the real fail-open counters (an
   inert or counter-less skeleton does not count).
2. The resource report records numbers (not pass/fail) for stages, logical tables, PHV groups (normal +
   tagalong), **parser states / TCAM rows**, and stateful ALUs, and shows headroom.
3. A read-only **functional check on the Tofino behavioral model** (`tofino-model` driven by PTF/scapy, or
   p4testgen/STF — **not** BMv2, which does not run TNA, and not bf-p4c alone, which does no simulation)
   confirms on the Experiment 1 originals: SYN/SYN-ACK options become `[MSS(clamped)]`, established
   segments stay optionless, TTL/IP-ID canonical, IPv4/TCP checksums valid, and DNP3 payload byte-identical.

A compile failure is a **bounded target result** (this normalizer, this target), explicitly not a
universal impossibility. Passing authorizes only the next gate (endpoint-safety Experiment 3 and, later,
Defense 4 co-residency), never hardware implementation.

## What this design deliberately leaves open

- **Endpoint safety** (do the real relay/master honor the negotiation fallback to a stripped SYN; is
  losing PAWS/RTTM/SACK acceptable): Experiment 3, including a **required induced-loss availability test**
  — under multi-segment loss (e.g. the 12,204-byte READ), SACK-less RTO-driven recovery must stay inside
  the DNP3 master's application response timeout, or a loss event becomes a READ abort/retry, not merely a
  slower transfer.
- **The TCP window value residual** (device-specific): not addressed; normalizing it is a flow-control
  change with its own safety question.
- **Non-compliant / asymmetric / mid-stream cases:** handled by fail-open here; a design that must cover
  them needs per-flow SYN-seen state.
- **Defense 4 co-residency:** out of scope; this is a standalone normalizer.
