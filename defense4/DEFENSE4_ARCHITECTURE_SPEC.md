# Defense 4 — architecture specification

> **⛔ SUPERSEDED on the size/topology axes by [`DEFENSE4_CHECKPOINT_2026-08-04.md`](DEFENSE4_CHECKPOINT_2026-08-04.md) (Philip, 2026-08-04).** The controlling topology is now a **single Tofino-1 at the outstation** (master → observed WAN → switch → relay) — NOT the two-edge external-loop tunnel in §2. Size is normalized by **master-inserted real-plus-decoy CROBs (K = R + D)**, NOT the outer-encapsulation size plane in §5; there is no second decoder, no outer wrapper, no filler grid. The **timing plane (§3–§4, §7–§8) and the safety posture remain valid** and feed the unified timing engine. Read the checkpoint first; treat §2 and §5 here as historical feasibility evidence.


**2026-08-04. The frozen contract for the minimum viable Defense 4, plus the forward profiles.
Derived from `defense4_arch.md` reconciled against the four-specialist wave and the evidence ledger.
Every design choice carries a label; where evidence does not force a choice, two bounded alternatives
are given with a recommendation.**

---

## 1. Threat model and claim boundary

| element | specification |
|---|---|
| Observer | passive, on-path, sees BOTH directions on the protected link; knows the defense (Kerckhoffs) |
| Observer location | the **protected segment only** (the loop cable / inter-edge link), NOT the native endpoint ports. If the observer can also tap the master- or outstation-facing native ports, the defense is void — this MUST be pinned. |
| Payload | **plaintext** DNP3-over-TCP in the base contract. Opacity (MACsec) is a stated optional deployment assumption for the strong claim only. |
| Adversary goal | operation fingerprinting (READ vs SBO), device fingerprinting (Formby CLRT), request-complexity (CROB count) |
| Endpoints | DNP3 master and SEL-751 outstation **unmodified**; the operator owns both switch edges |
| **Claim (plaintext, base):** | Defense 4 **reduces** the size, timing, packet-count, and direction differences between READ and SBO (Profile A + Profile-B shape match). |
| **Claim (with external MACsec on the loop):** | Obs(READ) ≈ Obs(SBO) on the **shape** axes (size/timing/count/direction). NOT semantic indistinguishability even then (function code is opaque but operation *rate/occurrence* may remain). |
| **Never claimed:** | semantic READ/SBO indistinguishability on plaintext; device anonymity (k=1). |

Rationale (VERIFIED): the DNP3 function code is one byte at a fixed offset (offset 12 in the TCP
payload), an O(1) perfect READ-vs-SBO classifier; Tofino-1 cannot make the inner opaque (residual never
in PHV). See `agent_notes/size_and_topology.md`.

## 2. Testbed topology and port-role table

The protected link MUST be an **external front-panel cable** so it is genuinely observer-visible;
internal recirculation is invisible and would void the observer model.

```mermaid
flowchart LR
  M[Vision master 10.10.54.19 / 192.168.10.1<br/>DNP3 plaintext] <-->|dp9 native| SW
  subgraph SW[One Tofino-1 · pipe 0]
    ENC[ENCODE pass<br/>ingress dp9 / dp64<br/>classify → hold → pad → prepend-encap → filler]
    DEC[DECODE pass<br/>ingress LOOP<br/>decap → strip filler → restore byte-identical]
    PG[(pktgen dp68<br/>filler cells + grid tick)]
    ENC -->|egress LOOP| CABLE
    CABLE -->|ingress LOOP| DEC
    PG -.->|filler cells| ENC
  end
  CABLE{{external front-panel loopback cable<br/>= PROTECTED LINK · OBSERVER TAPS HERE}}
  DEC <-->|dp64 native| R[SEL-751 192.168.10.7 · outstation addr 0<br/>DNP3 plaintext · READ-ONLY]
  OBS[[on-path observer]] -.taps.-> CABLE
```

| dp | role | connects | pass logic |
|---|---|---|---|
| dp9 | master-facing | Vision master | ingress ⇒ encode; egress ⇒ decoded native to master |
| dp64 | outstation-facing (physical) | SEL-751 (addr 0, **READ-ONLY**) | ingress ⇒ encode; egress ⇒ decoded native to relay |
| dp11 | outstation-facing (emulator) | Hulk simulated outstation | SBO corpus / SELECT-OPERATE without the relay |
| dp10 ⇄ dp65 | **protected-link external loop (TAP HERE)** | FP15/2 ⇄ FP33/1 DAC | ingress(loop) ⇒ decode; egress(loop) ⇒ encoded cell |
| dp68 | pktgen (internal) | — | filler + grid tick |

**Terminology (directive §10): this is ONE pipeline image, traversed once per edge role.** There is a
single compiled program on the one Tofino-1. A given end-to-end packet passes through the chip **once as
the ENCODER** (ingress from master/outstation → hold/pad/prepend-encap → egress onto the loop) and
**again as the DECODER** (ingress from the loop → decap → strip filler → byte-identical restore → egress
native). "One pipeline image / single pass per edge role" is the correct framing — **not** "two
switches" and **not** a two-edge anonymity deployment. The single box shares one register file and one
epoch clock across both roles, so it is a lab stand-in for two edges, not a distance-link deployment.

All stateful ports pipe-0 (Registers/Counters are per-pipe). Pass discrimination: single ternary on
`ig_intr_md.ingress_port == LOOP` → decode; else encode. Cost: +2 front-panel ports + 1 DAC.
Label: PROPOSED; requires a `$PORT_HDL_INFO` readback (gated on authorization) to confirm the ports are
free before any build. If two free front-panel ports are unavailable, the closest alternative is an
inline media-converter on a single external cable.

## 3. READ and SBO state machines

Full mermaid in `agent_notes/dnp3_sbo_safety.md`. Key rules (VERIFIED against `multi_crob_sbo.pcap` and
opendnp3):

- **Transaction key (line-rate parseable):** canonical 5-tuple + DNP3 DEST + SRC + direction + phase
  (internal) + generation (internal). `app_seq` (offset 11 low nibble) and `func` (offset 12) are
  per-phase correlators; `tcp.len==0` + seq/ack are pure-ACK / ordering evidence.
- **SBO linkage MUST be state-table + generation, NEVER app-seq** — SELECT carries app-seq 3, OPERATE
  app-seq 4; the next M→O func=4 on the same flow+link+generation binds to the SBO entry regardless of
  app-seq. The CROB object list crosses block CRCs (variable length) → a **bounded max CROB count** or
  opaque treatment is required; it cannot be part of the key.
- **Absent/piggybacked ACK:** the response gate anchors to the **scheduled public ACK slot**, never
  waits for a nonexistent native ACK.
- **SELECT failure → suppress the OPERATE slot, abort the template, fail open.** OPERATE-after-slot →
  abort+fail-open (default). **Never invent, replay, or synthesize a real OPERATE.**

## 4. Timing modes, predicates, queue plan, state table

### 4.1 Unified release engine (one binary)

Per protected phase p, policy `Θ_p = (M_A,p, D_A,p, G_R,p, T_FO,p)` selects a mode:

| mode | ACK release | RESPONSE release | reproduces |
|---|---|---|---|
| IMMEDIATE | at once | at once, ordered | no shaping |
| MATCHING_RESPONSE_EVENT | on the matching RESPONSE event | after ACK | **Defense 1** |
| ABSOLUTE_DEADLINE | at `now ≥ T_A` | `T_R = A_ref + G_R` | **Defense 3** (ACK) / **Defense 2** (resp) |
| PREDECESSOR_PLUS_OFFSET | at grid slot `k` | at grid slot `k+N` | **Defense 4 grid** |
| bounded FAIL_OPEN | at `now ≥ T_FO,A` | at `now ≥ T_FO,R` | safety net for all modes |

Predicates (from `defense4_arch.md` §4):
```
ACK_release  = match ∧ [ M_A=IMMEDIATE ∨ (M_A=EVENT ∧ response_seen)
                         ∨ (M_A=DEADLINE ∧ now≥T_A) ∨ now≥T_FO,A ]
RESP_release = match ∧ ack_gone ∧ [ now≥T_R ∨ M_R=IMMEDIATE ∨ now≥T_FO,R ]
T_R = A_ref + G_R      A_ref = scheduled ACK-release point + characterized drain correction
```
Defense 4 does NOT sum three delays; it exposes one gate with selectable predicates.
`t_RESP ≈ max(t_RESP_ready, T_R, t_ACK_out + δ_ord) + ε_R` — neither release is "exact"; `ε` absorbs
the ~1.72 µs release tail.

### 4.2 Reverse-path four-queue plan (per phase, one scheduler domain)

`Q_ACK_BLOCK(7) > Q_ACK_HOLD(5) > Q_RESP_BLOCK(3) > Q_RESP_HOLD(0)` — a 4-level extension of the
silicon-proven 3-level strict priority (Part 11). The 4th level gives the RESPONSE its own
independently-terminable blocker, so it releases on `A_ref + G_R` regardless of the ACK's own deadline.
Rules (VERIFIED for the reverse path, Parts 11/12): response blocker primed before the ACK blocker
ends; **absolute timestamps** (a starved lower blocker accrues no recirc passes); pass-count only as
bounded fail-open; generation on every token; internal blockers never egress; real ACK/RESPONSE stay
queue-resident (do not recirculate). Queues are per-port: reverse 4 on the master port, forward ≤3 on
the outstation port — no contention, "8 shared queues" is a non-issue.

### 4.3 Bounded transaction state (arch doc §8)

`valid, generation, flow_tag, operation{READ,SBO}, phase{READ,SELECT,OPERATE}, app_seq, tcp_marker,
size_profile, slot_bitmap, ack_seen, response_seen, ack_gone, T_A, T_R, fail_open_time, error_flags`.
For SBO the entry links SELECT and OPERATE; `operate_window = t_SELECT_RESP + selectTimeout_margin`.

## 5. Size plane

- **Placement: EGRESS** (`egress_intrinsic_metadata_t.pkt_length`; ingress has no length field). Defense
  3's egress is 0/12 empty and PHV exhaustion is ingress-only → the size plane is ~2–4 egress stages,
  **zero ingress cost.**
- **Encapsulation: FROZEN format (b)** — a new **outer Ethernet header + an 8-byte D4 header (carrying a
  16-bit true `inner_len`, plus direction/txn_tag/slot_id/realfill and pad) + the COMPLETE inner Ethernet
  frame** + outer FCS. Decode = strip outer Ethernet + D4 header and truncate to `inner_len` → inner frame
  byte-identical (no inner-checksum recompute). This is the only option giving a valid Ethernet wire
  layout AND exact padding removal; `OUTER_OVERHEAD = 14+8+4 = 26 B`. (MB-1 v3 must materialize this exact
  8-byte header; v2's 6-byte header with no `inner_len` is a defect being fixed.)
- **Public size pattern** `P = [S_0..S_{L-1}]`, each `S_i` the cross-operation max for that slot's
  direction, expressed as **observer-visible outer Ethernet frame length at the loop tap** (padding
  cannot shrink). `C_i = S_i − H_outer`, `pad_i = C_i − L_i`, valid iff `0 ≤ L_i ≤ C_i`. Overflow
  (`L_i > C_i`): map to a larger state, or declared fail-open (v1); no arbitrary splitting.
- **Slot pattern is PROVISIONAL (directive §7/§8) — Candidate A3.** The candidate patterns are derived by
  the offline transaction oracle from the corrected corpus (incl. a persistent-connection SBO rerun) and
  are recorded — **not frozen** — in `PROVISIONAL_SLOT_CANDIDATES.md`. Recommended: a **6-slot unified
  grid** with per-slot public outer sizes = the cross-operation max inner `frame_len` + `OUTER_OVERHEAD`
  (26 B = 14 outer Ethernet + 8 D4 header + 4 FCS). READ fills slots 0/1/4/5 with filler at 2/3; SBO fills
  all six; **slot 5 is a real terminal ACK for both** (established by the persistent-connection rerun —
  the per-transaction teardown in the original harness had masked it). No pattern is committed until the
  oracle output is reviewed AND the MB-8 size-data-path gate passes.
- **Layer discipline (directive §5).** The measured envelope figures are **TCP payload** bytes
  (`tcp.len`): SELECT/OPERATE 35→254 B, responses 37→256 B (N=1..16, 14.6 B/CROB); READ 18 B, RESPONSE
  134 B. Observer **inner** Ethernet frame_len = tcp.len + 66; the **public outer** length = frame_len +
  `OUTER_OVERHEAD` (26 B). **Ethernet size terminology:** payload **MTU = 1500 B**; maximum standard frame
  = **1514 B excluding FCS / 1518 B including FCS**. A unit whose inner frame_len exceeds its slot target,
  or whose outer frame would exceed the max frame size, **FAILS OPEN (bypasses, unshaped)** — never
  clamped. A multi-fragment READ needing k cells is the cellization case, deferred (bounded READ envelope).
- **CROB-count concealment = outer-encapsulation size control ONLY.** The request and response are padded
  to the fixed public slot size via the **outer header + padding bytes** (the outstation echoes the CROBs,
  so both directions normalize once the outer size is fixed). **No decoy CROBs, no DNP3-object edits, no
  control ever injected by the switch** (directive safety boundary; the earlier decoy-CROB line is
  retired). Byte-identical inner restore on decode; MTU/oversize → fail-open.
- **Size mechanism is NOT YET PROVEN — MB-8 offline gate (directive §9).** MB-1's PHV overlay proved only
  that the outer-field *assignment* is inexpensive. The exact outer format, real padding bytes,
  observer-visible frame lengths, encoder/decoder ports, padding removal, byte-identical restoration,
  real/filler discrimination, and MTU/unsupported-size handling are the subject of MB-8, not yet run.

## 6. Control-plane vs data-plane responsibilities

Controller: installs policy `Θ_p`, seeds bounded state, configures queues/pktgen/size states, collects
offline telemetry. **The controller never participates in per-packet or per-transaction release.** All
gating, matching, generation, slot assignment, encap/decap and fail-open are data-plane.

## 7. Failure, cleanup, concurrency policy

- **Concurrency:** one active protected transaction per scheduler domain (shared FIFO cannot
  mid-release). A concurrent attempt **bypasses (fails open, unshaped)** until the bank frees.
- **Fail-open:** bounded absolute-deadline release of any held packet; the horizon `H = B·K/rate` must
  satisfy `H > N·T + a_bound + overhead + M` and `H < RTO_min − margin`, and for SBO additionally
  `2·(N+1)·T + turnaround + M < selectTimeout` (device value, BLOCKED until read).
- **Cleanup:** on RESP_OUT, FIN/RST, or fail-open, retire the entry and its generation; internal tokens
  die on their absolute deadline and never egress.
- **Corner cases:** the 22-row table (`agent_notes/dnp3_sbo_safety.md`) is the acceptance checklist;
  retransmission/duplicate handling must be idempotent (a duplicate OPERATE bound twice = double
  actuation risk); a fabricated CONFIRM is prohibited (permanent SOE deletion).

## 8. Phase-specific parameters (mandatory)

A single `D`/`G` must NOT serve all phases. `Θ_READ`, `Θ_SELECT`, `Θ_OPERATE` differ:
`G_R,SELECT` is bounded by the select-timeout budget (a SELECT-response hold delays the OPERATE);
`G_R,READ` is bounded only by RTO; `G_R,OPERATE` by the master app timeout. See
`agent_notes/dnp3_sbo_safety.md` for the inequality and measured emulator terms (SELECT-resp 1.37 ms,
master-proc 0.41 ms, OPERATE-resp 1.34 ms; total 3.12 ms vs 10 s emulator selectTimeout).
