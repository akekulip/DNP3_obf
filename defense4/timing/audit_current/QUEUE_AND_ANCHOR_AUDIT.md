# Queue and anchor audit — the exact P4 and control plane (2026-09-02)

Recovered from the frozen exact source
`defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`
(SHA-256 `7ce30494…`, loaded binary `33fa3a77…`) and the control plane
`implementation/control/defense4_rrc_bor_unified12_setup.py`. The frozen source is not modified
or renamed.

## 1. Ports (verified against the P4 `const PortId_t` declarations)

| port | name | role | direction |
|---|---|---|---|
| dp9 | `PORT_VISION` | master side | external, **the observation point** |
| dp64 | `PORT_RELAY` | live relay leg (E1/33, 1 Gb/s) | external, **no host-capturable tap** |
| dp8 | `PORT_L` | RRC loopback (READ/SELECT ACK+RESP scheduling) | internal |
| dp10 | `PORT_BOR_L` | BOR loopback (OPERATE scheduling) | internal, own scheduler |
| dp68 | `PORT_PGEN` | packet-generator / recirculation | internal, not an external tap |
| dp11 | `PORT_HULK` | replay injector | not used in the live-relay campaign |

All reported packet timestamps are master-facing (dp9). Relay-facing (dp64) and internal (dp68,
dp10, dp8) events were not captured. This is why nothing at `T0 + J` is observed.

## 2. Two strict-priority scheduling domains

Confirmed in both the P4 (`QID_*` constants) and the control-plane queue setup (label, qid,
max_priority tuples), descending priority = descending qid:

**dp8, RRC (READ/SELECT):**
`qid7 ACK_BLOCK` > `qid6 ACK_HOLD` > `qid5 RESP_BLOCK` > `qid4 RESP_HOLD`.
The real ACK and response stay queue-resident in qid6/qid4; only blocker tokens loop in
qid7/qid5. A held packet cannot leave until its blocker reservoir drains.

**dp10, BOR (OPERATE):**
`qid3 OP_BLOCK` > `qid2 OP_HOLD`. Placed on a **separate loopback port** so its reservoir cannot
be starved by the higher-priority dp8 ACK/RESP reservoirs; each Tofino port has its own egress
scheduler.

## 3. Anchors and deadlines — recovered, not assumed

| class | anchor | ACK deadline | response deadline | master-visible observable |
|---|---|---|---|---|
| READ / SELECT (RRC) | native ACK arrival `t_A` | `t_A + D_A` (`D_A`=20 ms) | `t_A + D_A + D_R` (`D_R`=4 ms) | CLRT `X' = D_R = 4 ms` |
| OPERATE (BOR) | request arrival `T0` | `T0 + A` (`A`=20 ms) | `T0 + R` (`R`=24 ms) | response-to-ACK `O = R − A = 4 ms` |

Answering the spec's §6 enumerated questions:

1. **READ/SELECT ACK and response deadlines share `t_A`** — yes. Both are armed off the native
   ACK's arrival; `reg_deadline` holds `t_A + D_A` and `reg_tresp` holds `t_A + D_A + D_R`.
2. **OPERATE deadlines share `T0`** — yes. `A` and `R` are absolute deadlines from the OPERATE
   request arrival, installed in `tbl_bor_params` (`A_DEFAULT_TICKS=20 ms`, `R_DEFAULT_TICKS=24 ms`).
3. **A=20 ms, R=24 ms are absolute deadlines from `T0`** — yes (BOR is request-anchored).
4. **READ/SELECT use a 20 ms ACK delay + 4 ms post-ACK interval, 24 ms horizon from `t_A`** —
   yes. This is why the read lane is a **replacement**: both egress instants derive from the one
   anchor `t_A`, so the native CLRT term drops out.
5. **Native response arrives after its deadline** — `if (expired) to_fwd()`: the held/late packet
   is forwarded when it arrives. It is not pinned; it becomes a tail observation. This is the
   coverage boundary, and it is why the protected distribution has a late tail rather than a hard
   cap.
6. **Two outstanding transactions** — not supported. Every state register (§4) is a single global
   slot, so a second in-flight transaction would overwrite the first. The driver serializes with
   `gap_ms` (20 ms) and an SBO minimum gap; the campaign never issues concurrent transactions.
7. **State indexing** — a single global slot, **not** per-flow, per-application-sequence, or
   per-point. See §4.
8. **Retransmission / segmentation / dedup** — the source carries explicit dedup: `V_ARM_DUP`
   and `CF_ARM_DUP` suppress a second burst on a duplicate READ; `CF_RESP_DUP_SUPP` suppresses a
   TCP-position-matched response retransmission; `OUT_OP_DUP` drops an OPERATE retransmit while
   held. `reg_exp_ack` and `reg_session_port` gate on the expected ACK number and the session's
   ephemeral port. These reduce, but the single-slot state (§4) still means an unsolicited
   response or a sequence wrap during an active transaction is a known risk, mitigated only by
   serialized driving.
9. **shape_enable** — 0 in both arms of `campaign_v1`. **The inference stated here was
   incomplete and has been corrected.** Single 49-byte payloads and identical frame and byte
   counts show only that the size path did not execute; because the program gates it on
   `do_shape = shape_enable & payload49`, that is equally consistent with `payload49 = 0`. The
   gap is closed in `CONFIGURATION_EVIDENCE.md` §1 by measuring the TCP data offset and IP
   total length of all 63,360 responses, every one of which is `(dofs 8, total_len 101)` and so
   lands in the parser's `opt12_p49` state with `payload49 = 1`; with that fixed, and with
   `do_shape` a key of both decide tables, the absence of a two-replica carve does imply
   `shape_enable = 0`. It remains a wire-plus-source result, not a device readback. In
   `final_read_sbo`, shape processing was active in both arms (a held constant there, not a
   confound, but that Timing OFF arm is not an unmodified relay baseline).
10. **Priority starvation** — the two-domain design (dp8, dp10) exists specifically so the BOR
    reservoir is not starved by the RRC reservoirs. Within a domain, strict priority realizes the
    deadline when the matching packet is present; a late packet fails open (question 5).

## 4. State registers — every one is a single global slot

All 22 timing/control registers are declared `Register<bit<W>, bit<1>>(1, init)`: **size 1, index
type `bit<1>`.** There is no per-flow, per-sequence, or per-point index anywhere. The load-bearing
ones:

| register | width | role | clear condition |
|---|---|---|---|
| `reg_tag` | 8 | active-transaction generation (`TAG_INACTIVE=0x00`, else `0xC0..0xCF`) | next READ arms a new generation |
| `reg_deadline` | 32 | `t_A + D_A` (ACK release) | overwritten on next arm |
| `reg_tresp` | 32 | `t_A + D_A + D_R` (response release) | overwritten on next arm |
| `reg_failopen` | 8 | budget-zero fail-open generation guard (R2 repair) | generation-qualified |
| `reg_bor_epoch/ready/gen/topj` | 8/8/8/32 | OPERATE hold state and `T0 + J` | per BOR epoch |
| `reg_exp_ack`, `reg_session_port` | 32/16 | expected ACK number, session ephemeral port | per session |

Single-slot state is the reason concurrency is one transaction (§3, q6).

## 5. What this establishes and what it does not

**Establishes (from code + config):** the read lane is a genuine common-anchor replacement, not a
per-packet shift; the control lane is request-anchored so `J` is absent from the master-visible
`O`; late responses fail open; the design supports exactly one outstanding transaction.

**Does not establish (no relay-facing or physical capture):** the realized per-transaction `J`,
the relay-facing release at `T0 + J`, exactly-once delivery to the relay, or any physical
actuation. Those need a dp64 tap or an external contact measurement, neither of which exists in
this evidence.
