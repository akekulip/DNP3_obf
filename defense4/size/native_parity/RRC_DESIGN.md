# Release–Replicate–Carve (RRC) — the native Tofino transaction primitive

## Architectural correction (read first)

The `defense4_joint_size_time_kernel.p4` at `8640b89`/`33009e4` is **NOT literally one native primitive**,
and prior docs overstated it. The honest facts:

- `do_shape` is computed **only in egress**, per-packet.
- caseA timing admission is computed **separately in ingress**.
- The caseA ingress **arms only on DNP3 READ function `0x01`**.
- **SELECT `0x03` and OPERATE `0x04` do not arm the timing state.**
- One **global `read_len = 18`** predicts the relay's pure-TCP-ACK, valid only for the current READ.
- Therefore an **SBO exchange cannot traverse the same timing path** merely because its response is 49 B.

A packet-local egress bit cannot retroactively admit the earlier request or control the ingress
transaction state. So the current kernel proved (on silicon) that **caseA-ingress forwarding + timing
compose correctly and a 49 B READ forwards intact** — but the "one primitive drives both timing and size"
claim is withdrawn. This document replaces it with the real primitive.

## The primitive: ADMIT → HOLD → RELEASE → REPLICATE → CARVE

```
  ADMIT(request profile)              [ingress caseA transaction state machine, extended to 0x01/0x03/0x04]
    → HOLD(response to deadline)      [caseA queues + deadline release, unchanged]
    → RELEASE into PRE replication    [ingress destination multicast at the caseA release branch]
    → RID 1 carves the prefix window  [egress, RID-driven]
    → RID 2 carves the suffix window  [egress, RID-driven]
```

**The timing-release event itself invokes the size operation.** This is not a splitter appended behind
timing. Mechanisms used / forbidden:

- USE: caseA ingress transaction + timing state; caseA queues + deadline release; **ingress destination
  multicast**; the Tofino **Packet Replication Engine (PRE)**; per-node **replication IDs (RID)**; a small
  RID-driven **egress carve**.
- FORBID: egress mirror; source-copy drop; segmentation register; TCP sequence ledger; any DNP3 READ/SBO
  branch in the response carve.

## Implementation plan (sections map to the directive)

1. **Multi-function admission.** READ `0x01`, SELECT `0x03`, OPERATE `0x04` enter the **same** generic
   transaction-admission state machine (different request-length profiles, shared timing lifecycle). No
   Direct-Operate. Use parser constants / the existing table — **no new ingress MAU stage** (caseA already
   fills 12). Preserve app-seq isolation, arm-once, duplicate handling, ACK-before-response ordering,
   deadline, fail-open, cleanup, retransmit, all caseA counters/safety gates. SELECT and OPERATE are two
   independent transactions (each arms, ACKs, releases, retires on its own).
2. **Per-function expected-ACK.** Replace the global `expected_ack = seq + read_len` with a per-profile
   request length selected from the admitted function, reusing `tbl_build_exp_ack` (constant-add actions,
   **no register**). Measure the real request payloads (READ / 2-CROB SELECT / OPERATE) from vectors or
   captures. Retire `read_len` as a global; reuse its metadata capacity for `shape_enable`.
   Mode table:
   | Timing | shape | Result |
   |---|---|---|
   | OFF | 0 | transparent caseA forwarding |
   | OFF | 1 | immediate RRC carve for eligible 49 B responses |
   | D2/D3/D4 | 0 | timing only |
   | D2/D3/D4 | 1 | hold → deadline release → RRC carve |
   Shaping-off MUST choose **unicast forwarding**, never an empty multicast group (which would drop).
3. **payload49 eligibility with options.** Do NOT match only `ip.total_len == 89`. Support at least
   `(dofs=5,total_len=89)` and `(dofs=8,total_len=101)` (and 6→93, 7→97 if the parser already handles them),
   via parser select states / compile-time constants — no MAU arithmetic. Require IHL 5, TCP, no frag, ACK
   set, no SYN/RST, correct protected relay→master session, complete single-frame 49 B DNP3 payload.
   **Preserve and re-emit the actual TCP options.**
4. **Direct PRE release (delete the mirror).** Remove `Mirror()/SHAPE_SESSION/mirror.emit/drop_ctl/rid==0
   source branch`. At the caseA response-release branch, choose `native → unicast dp9` vs `shape →
   mcast_grp_a = RRC_MGID_49_28`. Shaped branch: set only the mcast destination, qid 0, `bypass_egress=0`,
   `drop_ctl=0`, no mirror, no rid-0 source copy. One PRE group, two level-1 nodes both → dp9, RID 1 and
   RID 2 (same port, distinct RID). Dedicated MGID/node IDs not colliding with caseA pktgen mirrors.
   Read `$pre.node`/`$pre.mgid` schemas from the running program before writing; read back MGID/node/RID/
   ports. Confirm the same-port/two-RID PRE behavior on the testbed.
5. **Egress = RID interpreter.** Preserve caseA byte-identical egress for ordinary unicast. If
   `egress_rid ∈ {1,2}`: parse IPv4/TCP/options/49 B payload and carve; else accept residual. Do NOT re-run
   ownership/policy in egress — the RID is the instruction. RID 1 = payload `[0:28]`, seq = orig, clear
   PSH/FIN, preserve ACK/window. RID 2 = payload `[28:49]`, seq = orig+28, keep final-segment flags.
   Recompute IPv4 total-len/checksum + TCP checksum per replica (checksum input includes the emitted TCP
   options). Never alter Eth/IP/ports/ACK/window/timestamp-option values/DNP3 bytes/CRC. `concat == 49 B`.
6. **No false configurability.** Profile `RRC_49_CUT28`: input 49 → `[28,21]`. Remove the unused `cut`
   param or reject any value ≠ 28. Do not report cut as runtime-configurable.
7. **Complete setup.** Actually install the PRE config (not prose). Remove the nested gRPC subscription
   conflict (one ClientInterface through all functions, or finish caseA config + release its client, then
   connect once for RRC/PRE). Ops: `dry-run / configure-timing / configure-rrc / configure-all /
   evidence-dump / rollback-rrc`. `configure-all` stops on timing failure (no false PASS). `rollback-rrc`
   disables shape first, restores native unicast, deletes only the RRC-owned MGID/nodes. All writes gated
   behind `DEFENSE4_HW_AUTHORIZED=1`.
8. **Counters (egress array, no new ingress register):** `RRC_RID1, RRC_RID2, RRC_UNEXPECTED_RID,
   RRC_PARSE_REJECT`. A clean shaped response: RID1+=1, RID2+=1, no unexpected/reject.
9. **Emulator replacement.** Drive complete request sequences (READ / SELECT / OPERATE each: request →
   pure ACK → 49 B response), asserting all three arm the same engine, per-function expected-ACK, hold to
   deadline, exactly one PRE group producing RID 1 and RID 2 (no source copy), both TS-option fixtures →
   `[28,21]`, byte-exact reassembly, correct checksums, SELECT retires before OPERATE arms, no object-type
   branch in carve. Mutants (all killed): READ-only admission, global read_len=18, total_len==89-only,
   missing options in checksum, source-unicast+mcast duplication, one PRE node, swapped RIDs, split-before-
   release.
10. **Compile (BF-SDE 9.13.2 on the switch):** 0 errors, ingress ≤ 12 stages, 0 new ingress registers,
    PRE (not MAU) replication, egress fits; fewer egress policy tables than the current joint kernel.
    Commit + push compile-clean before loading.
11. **Hardware gates R1 (PRE two-node/same-port) → R2 (100-pkt stress) → R3 (physical READ size) → R4
    (physical READ timing+size — first full-RRC proof) → R5 (OpenDNP3 SBO timing+size) → R6 (physical SEL
    SELECT-only, isolation-gated).** Physical OPERATE only under separate authorization. Rollback armed.

## Status
Architectural claim corrected (this doc). The RRC kernel/setup/emulator build (sections 1–10) and the
hardware gates (11) are the active implementation work on this branch.
