# Internal Seeding of the K=64 Blocker Reservoir — Time-Boxed Feasibility Spike

**Date:** 2026-07-25
**Branch:** `research/timing-inline-corrected-v2`
**Scope:** roughly half a working day. Read-only on the switch; nothing was loaded, restarted, or
recompiled there. The live experiment (`dnp3_timing_normalizer_inline`, `bf_switchd` PID 228141)
was not touched.
**Compiler used:** `bf-p4c 9.13.1` (local, `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c`).

---

## 1. The question

Today the K=64 blocker reservoir is seeded by Vision, which transmits 64 raw AF_PACKET frames with
ethertype `0x88C1` over the master leg. Because those seed frames cross an external link, we cannot
claim "no external blocker traffic" or "fully autonomous in-switch operation".

Can the reservoir be established **entirely inside the Tofino**, triggered by the transaction
itself, with no host packet and no controller action per transaction?

## 2. Verdict

**FEASIBLE-AND-COMPILED.**

A construction exists, it is written, and it compiles clean on bf-p4c 9.13.1 with **no increase in
ingress stage count** (10/12, unchanged) and 2 of 12 previously-empty egress stages consumed. It has
**not** been run on silicon — that gating remains.

The recommended mechanism is **not** the packet generator. It is an **ingress mirror session whose
destination is a multicast group containing exactly 64 replication nodes on the internal loopback
port dp8**. The DNP3 READ that opens the transaction mints its own reservoir, and each token carries
the READ's own DNP3 application-control byte as the generation because each token *is* a copy of
that READ.

Tofino-1 pktgen **can** be data-plane triggered (this is a genuine capability, cited below, and my
prior assumption otherwise was wrong), but for this topology it is the worse of the two options.

---

## 3. What each mechanism can and cannot do on Tofino-1

### 3.1 Packet generator trigger types

Four trigger types exist on Tofino-1. From
`/home/philip/bf-sde-9.13.1/install/include/pipe_mgr/pktgen_intf.h:121-147`:

```c
typedef enum bf_pktgen_trigger_type {
  BF_PKTGEN_TRIGGER_TIMER_ONE_SHOT = ...
  BF_PKTGEN_TRIGGER_TIMER_PERIODIC = ...
  BF_PKTGEN_TRIGGER_PORT_DOWN = ...          /* "A packet will be generated on a port-down event." */
  BF_PKTGEN_TRIGGER_RECIRC_PATTERN = ...     /* "Generate a packet on receiving a recirculated packet." */
  BF_PKTGEN_TRIGGER_DPRSR = ...              /* "Only for tofino2." */
  BF_PKTGEN_TRIGGER_PFC = ...                /* "Only for tofino2." */
}
```

The two Tofino-2-only triggers (`DPRSR`, `PFC`) are also absent from the Tofino-1 BfRt schema — the
only actions in `tf1.pktgen.app_cfg` are `trigger_timer_one_shot`, `trigger_timer_periodic`,
`trigger_port_down`, `trigger_recirc_pattern`
(`/home/philip/bf-sde-9.13.1/install/share/bf_rt_shared/bf_rt_pktgen_tf1.json:118,134,150,155`).

**So the answer to "can a pktgen application be armed by a data-plane event rather than only by the
control plane" is YES**, via `BF_PKTGEN_TRIGGER_RECIRC_PATTERN`. That is a real, supported,
data-plane-driven trigger on Tofino-1.

### 3.2 Recirculation-triggered packet generation — what it actually does

**The comparison.** `/home/philip/bf-sde-9.13.1/install/share/p4c/p4include/tofino1_base.p4:339-340`:

> `// For recirculated packets, the event fires when the first 32 bits of the`
> `// recirculated packet matches the application match value and mask.`

and `pktgen_intf.h:152-166`: "this is a ternary comparison; zero bits in the mask indicate
'don't care'. This comparison is performed against the first 32 bits of the recirculated packet."
The driver programs the two registers in
`/home/philip/bf-sde-9.13.1/pkgsrc/bf-drivers/src/pipe_mgr/pipe_mgr_tof_pktgen.c:2161-2167`, and
note it **inverts** the mask on the way to hardware (`~cfg->u.pattern.mask`), so through the API and
through BfRt the convention is `1 = compare`.

**Which ports can trigger it.** Only pipe-local ports 68-71. `pktgen_intf.h:400-405` documents
"legal values tofino: 68-71, 196-199, 324-327, and 452-455", and this is enforced in
`pipe_mgr_tof_pktgen.c:604-612`:

```c
static bool port_is_pktgenable(bf_dev_id_t dev, bf_dev_port_t p) {
  bf_dev_port_t lo = dev_info->dev_cfg.make_dev_port(pipe, 68);
  bf_dev_port_t hi = dev_info->dev_cfg.make_dev_port(pipe, 71);
  return (lo <= p) && (p <= hi);
}
```

The SDE's own PTF test states the consequence plainly
(`/home/philip/bf-sde-9.13.1/pkgsrc/p4-examples/p4_16_programs/tna_pktgen/test.py:778-782`):
"For Tofino-1 we are limiting ourselves to the last port group for recirculation. This is because on
the last port group supports Packet Generation so only packets recirculated on this port group can
trigger the recirc Packet Generator app."

**Direction.** The trigger fires on a packet the data plane *sent to* one of those ports. The
driver implements it as a snoop enable
(`pipe_mgr_tof_pktgen_reg_pgr_com_port17_ctrl2_snoop_en`, `pipe_mgr_tof_pktgen.c:705`), and the SDE
example produces the trigger by setting `ucast_egress_port` to the recirc port and prepending a
4-byte tag in the ingress deparser
(`.../tna_pktgen/tna_pktgen.p4:431-435`, with the comment at `:37-46` that the 4 bytes exist
"since that is the size the Packet Generator will match on for Recirculation triggers").

**How many packets.** `batch_count` and `packets_per_batch` are `uint16_t` and **zero-based**
(`pktgen_intf.h:256-259`; the PTF test spells it out at `test.py:904-908`: "a value of zero makes
one packet and a value of ten makes eleven packets"). So exactly 64 packets is
`packets_per_batch_cfg = 63`. There is no driver-side maximum below 65535
(I read the full validator, `pipe_mgr_tof_pktgen_cfg_app_conf_check`,
`pipe_mgr_tof_pktgen.c:1298-1408`). Recirc apps should use **one batch** on Tofino-1, because the
recirc header replaces `batch_id` with the key — documented at `tna_pktgen.p4:86-89` and
`test.py:704-705`, **but not enforced by the driver**.

**Carrying the generation.** This was the pleasant surprise:
`pktgen_recirc_header_t` (`tofino1_base.p4:367-375`) has `bit<24> key; // Key from the recirculated
packet`, and the key is **bytes 1-3 of the 32-bit compared word**, i.e. dynamic context lifted from
the triggering packet. `test.py:705-707`: "On Tofino-1 the three LSBs of the four byte pattern
(first four bytes of recirculated trigger packet) are placed into the six byte Packet Gen header",
and the test asserts `hdr.recirc.key == recirc_tag & 0x00FFFFFF` (`test.py:833`). The key is
identical for every packet in the batch; only `packet_id` varies. An 8-bit DNP3 generation fits
comfortably.

**Where generated packets appear.** On `(app's own pipe, pipe_local_source_port)`, forced to the
app's pipe by the driver (`pipe_mgr_tof_pktgen.c:1558-1560`), consuming **input buffer 17**
(`pktgen_intf.h:296-302`).

**Why this is nevertheless the worse option here.** Three concrete reasons, all specific to this
topology:

1. The trigger packet must egress **dev_port 68-71**. This program uses dp8 (loopback), dp9
   (master), dp11 (replay injector) and dp64 (live relay, front-panel 33/0 — the *adjacent* port
   group). Using pktgen means bringing the 68-71 recirc group into service and enabling
   `recirculation_enable` / `pktgen_enable` / `pattern_matching_enable` on it — a switch
   configuration change on ports the current experiment does not touch, and switch changes are
   gated.
2. The generated packets arrive on a **new ingress port**, so the parser's `ingress_port` select and
   the `port_ok` guard both have to grow a case, and generated packets contend for input buffer 17
   with the trigger traffic.
3. Producing the trigger frame at all still requires an ingress mirror or a rewritten clone, because
   the first four bytes of the recirculated packet must be a synthetic header we control. So the
   pktgen route needs the mirror machinery **plus** the pktgen machinery, where the mirror route
   needs only the former.

**Not determined:** there is no documented or code-visible **minimum inter-packet gap** for Tofino-1
pktgen anywhere in this tree. `ipg = 0` means "no additional delay" (`test.py:909-917`) and the
driver only saturates the ns-to-clock conversion at `0xFFFFFFFF`
(`pipe_mgr_rmt_cfg.c:1785-1795`); it never clamps upward from below. The `tofino-model` ships as a
stripped binary here, so the pacing logic could not be read. **Do not assume a number for how long
64 generated packets take to emerge.**

### 3.3 Multicast replication — the recommended multiplier

The PRE schema confirms the construction directly
(`/home/philip/bf-sde-9.13.1/install/share/bf_rt_shared/bf_rt_pre_tf1.json`):

```
TABLE $pre.mgid  keys: ['$MGID']
  data: ['$MULTICAST_NODE_ID', '$MULTICAST_NODE_L1_XID_VALID', '$MULTICAST_NODE_L1_XID', ...]
TABLE $pre.node  keys: ['$MULTICAST_NODE_ID']
  data: ['$MULTICAST_RID', '$MULTICAST_LAG_ID', '$DEV_PORT']
TABLE $pre.prune keys: ['$MULTICAST_L2_XID']   data: ['$DEV_PORT']
```

`$pre.mgid` holds a **list** of node ids; each `$pre.node` carries its own `$MULTICAST_RID` and its
own `$DEV_PORT` port list. Nothing forbids the same `$DEV_PORT` appearing in many nodes — 64 L1
nodes each with the one-port list `[8]` and distinct RIDs produce **exactly 64 copies to dp8**. K is
therefore a control-plane constant, fixed at group-install time, not a runtime quantity that can
drift.

`qid` is a single scalar in `ingress_intrinsic_metadata_for_tm_t`
(`tofino1_base.p4:139-140`) and therefore applies to the whole replication, which matters below.

### 3.4 Mirror sessions — the trigger, and why they solve the qid problem

The decisive finding of this spike is the Tofino-1 mirror session schema
(`bf_rt_mirror_tf1.json`, table `$mirror.cfg`, key `$sid`):

```
$session_enable(bool)  $direction(INGRESS|EGRESS|BOTH)
$ucast_egress_port(uint32)  $ucast_egress_port_valid(bool)
$egress_port_queue(uint32)      <-- the mirrored copy's own qid
$ingress_cos  $packet_color  $level1_mcast_hash  $level2_mcast_hash
$mcast_grp_a(uint16)  $mcast_grp_a_valid(bool)   <-- a session can target a multicast group
$mcast_grp_b(uint16)  $mcast_grp_b_valid(bool)
$mcast_l1_xid  $mcast_l2_xid  $mcast_rid
$icos_for_copy_to_cpu  $copy_to_cpu  $max_pkt_len(uint16)
```

A mirror session can therefore (a) target a multicast group, (b) carry **its own queue id**
independent of whatever the original packet's `ig_tm_md.qid` was, and (c) truncate the copy.

That last point is what makes the design clean. A naive "multicast the READ itself to 65 members
(1 relay + 64 loopback)" would force the forwarded READ onto the same qid as the tokens, creating a
genuine reordering hazard against ACKs already queued on the relay port. Routing the tokens through
a **mirror session** instead leaves the forwarded READ completely untouched on its normal path and
queue.

The P4 side is the standard TNA idiom (`tofino1_base.p4:769-783`): `Mirror() mirror;` in the ingress
deparser, `ig_dprsr_md.mirror_type` set in ingress, `mirror.emit<T>(session_id, {...})` in the
deparser. Both the SDE example (`tna_mirror.p4:108-113`) and switch.p4
(`pkgsrc/switch-p4-16/p4src/shared/parde.p4:1410-1415`) use exactly this shape.

**Two bf-p4c constraints found by compiling, not by reading:**

- `Mirror(MIRROR_TYPE_I2E) m;` (the non-deprecated constructor) produced
  `error: Inconsistent mirror selectors, ig_intr_md_for_dprsr.mirror_type and
  ig_intr_md_for_dprsr.mirror_type`. Use the no-argument `Mirror()` form, which is what both SDE
  reference programs use.
- A constant session id is rejected:
  `error: Non-zero constant value 10w7 in digest field list is not supported on tofino.`
  The session id must come from a PHV field, so it is assigned to a metadata field in the ingress
  action.

### 3.5 Externally seeded fallback

The current host injector remains available and is unchanged; the new path is a compile-time
variant in a separate file. Nothing in `dnp3_timing_normalizer_inline.p4` was modified. If the
internal seed is disabled (mirror session not installed, or `$session_enable=false`), the program
degrades to accepting host-injected `0x88C1` frames exactly as today, because the ingress
`ROLE_BLOCK` path is untouched. That is the explicit fallback flag: **it lives in the control plane,
not in the P4**.

---

## 4. Recommended construction

**File:** `/home/philip/Projects/DNP3/research/timing_final/p4/dnp3_timing_normalizer_selfseed.p4`
(a copy of `dnp3_timing_normalizer_inline.p4` plus the deltas below;
**the inline program itself was not modified**).

### 4.1 Mechanism in one paragraph

A DNP3 READ arriving from the master is classified `ROLE_ARM` exactly as today and forwarded to the
relay byte-identically. In addition, the ingress deparser mirrors it into session 7. That session's
destination is multicast group `MCG_SEED`, which holds 64 L1 nodes each pointing at dp8, so the PRE
makes exactly 64 copies. Each copy traverses egress, where a single table rewrites it into an
`0x88C1` blocker token whose `gen` field is the READ's own DNP3 application-control byte, carried
across the gress boundary in one byte of mirror metadata. The tokens egress dp8, loop back through
the MAC-near loopback, re-enter ingress as `ROLE_BLOCK`, and from that instant on they are handled
by the **frozen, unmodified** blocker logic — same tag check, same deadline check, same budget, same
termination.

### 4.2 P4 deltas

```p4
/* new constants */
const MirrorType_t MIRROR_TYPE_I2E = 1;
const MirrorId_t   SEED_SESSION    = 7;          /* CP: $mirror.cfg $sid = 7 */
const bit<32>      SEED_BUDGET     = 32w200000;  /* fail-open pass budget    */

/* one-byte mirror metadata: the READ's generation */
header seed_md_h { bit<8> gen; }

/* ingress, inside the existing ROLE_ARM branch — the forwarded READ is untouched */
} else if (meta.role == ROLE_ARM) {
    to_fwd();
    ctr_arm.count(0);
    /* RETRANSMISSION GATE: meta.tag_ok == 1 means reg_tag ALREADY held this
     * generation, i.e. this READ is a TCP retransmission we have already seeded.
     * Only the first READ of a generation mints. This is what keeps K == 64
     * under a data-plane trigger. */
    if (meta.tag_ok == 8w0) {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        meta.mir_ses            = SEED_SESSION;
        ctr_seed_mint.count(0);
    } else {
        ctr_seed_suppress.count(0);
    }
}

/* ingress deparser */
Mirror() seed_mirror;                                  /* NOT Mirror(MIRROR_TYPE_I2E) */
if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
    seed_mirror.emit<seed_md_h>(meta.mir_ses, { meta.gen_in });
}

/* egress parser — how a seed copy is recognised without bridged metadata */
state start {
    pkt.extract(eg_intr_md);
    transition select(eg_intr_md.egress_port) {
        PORT_L  : parse_seed;    /* see the argument in 4.3 */
        default : parse_eth;
    }
}
state parse_seed { pkt.extract(hdr.seed); pkt.extract(hdr.eth); transition accept; }

/* egress — one table turns a copy into a token */
action make_token() {
    hdr.eth.etype = ETHERTYPE_IBSPG_TOKEN;   /* 0x88C1 */
    hdr.ib.setValid();
    hdr.ib.role = ROLE_BLOCK;
    hdr.ib.slot = 8w0;
    hdr.ib.gen  = hdr.seed.gen;
    hdr.ib.seq  = SEED_BUDGET;
    hdr.seed.setInvalid();
}
table tbl_make_token {
    key = { hdr.seed.isValid() : exact; }
    actions = { make_token; NoAction; }
    const entries = { true : make_token(); }
    const default_action = NoAction();
    size = 2;
}
```

### 4.3 Why the egress-port test is a sound discriminator

Adding bridged metadata to every packet would have perturbed the byte-preserving forwarding path,
which is the last thing we want to touch. It is not necessary. Every packet the hold mechanism sends
to dp8 sets `bypass_egress = 1` and therefore never reaches egress at all — verified by reading the
only two writers of `ucast_egress_port = PORT_L` in the program (`to_block` at :595-597 and
`to_resp` at :600-602, both setting `bypass_egress = 1w1`), and by confirming that `to_fwd` uses
`meta.fwd_port`, which the parser only ever sets to `PORT_VISION` or `PORT_RELAY` (:328-333).

Therefore **a packet that arrives in the egress pipeline with `egress_port == dp8` can only be a
mirrored seed copy.** No other packet in this program can produce that combination.

### 4.4 Control-plane objects (installed once at setup, never per transaction)

```python
# --- 64 replication nodes, all pointing at the loopback dp8 -------------------
PORT_L, MCG_SEED, K = 8, 0x0064, 64
node  = bfrt.pre.node
mgid  = bfrt.pre.mgid
mirror = bfrt.mirror.cfg

for i in range(K):
    node.entry(MULTICAST_NODE_ID=1000+i,
               MULTICAST_RID=1000+i,        # distinct RID per copy
               MULTICAST_LAG_ID=[],
               DEV_PORT=[PORT_L]).push()

mgid.entry(MGID=MCG_SEED,
           MULTICAST_NODE_ID=[1000+i for i in range(K)],
           MULTICAST_NODE_L1_XID_VALID=[False]*K,
           MULTICAST_NODE_L1_XID=[0]*K).push()

# --- the mirror session that fires per READ ----------------------------------
mirror.entry_with_normal(
    sid                    = 7,
    session_enable         = True,
    direction              = 'INGRESS',
    ucast_egress_port_valid= False,       # destination comes from the group
    mcast_grp_a            = MCG_SEED,
    mcast_grp_a_valid      = True,
    mcast_grp_b_valid      = False,
    egress_port_queue      = 7,           # QID_BLOCK; see the caveat in 6.2
    mcast_rid              = 0xFFFF,      # must not collide with any node RID
    mcast_l1_xid           = 0,
    mcast_l2_xid           = 0,           # $pre.prune[0] must stay empty
    max_pkt_len            = 64,
).push()
```

Two control-plane hazards worth stating explicitly, both visible in the SDE's own multicast test
(`.../tna_multicast/test.py:342`, `:474`):

- If the session's `$mcast_rid` equals a node's RID, that node's copy is subject to L2 (yid)
  pruning. Keep `$mcast_rid` outside the node RID range — hence `0xFFFF` above.
- `$pre.prune` entry for the chosen `$mcast_l2_xid` must not contain dp8, or copies get pruned.
  Leaving the prune table empty is sufficient.

---

## 5. The ordering hazard, and how the seed gets the generation

### 5.1 The generation

This is the part the packet generator would have made awkward and the mirror makes trivial.

The generation is the READ's DNP3 application-control byte, already extracted by the ingress parser
into `meta.gen_in` (`parse_dnp3_app`, :399-401 — "the DNP3 application control byte ... is this
transaction's generation"). The seed copies are copies of that very READ, and the mirror metadata
carries the byte across the gress boundary explicitly. **The internal seed obtains the generation by
construction: the tokens are minted from the packet that defines the generation.** There is no
lookup, no register read, no timing window in which the generation could be wrong.

(For contrast: with pktgen the generation would have to be smuggled through the 24-bit
`pktgen_recirc_header_t.key`, which works — the key is genuinely dynamic per trigger — but requires
a synthetic 4-byte trigger header and an extra rewrite stage to inject the byte into it.)

### 5.2 The ordering requirement

**Requirement:** the reservoir must exist in `QID_RESP`'s way before the RESPONSE is admitted, which
on this relay is 1-5 ms after the READ.

Timeline of the recommended construction:

| t | event |
|---|---|
| `t0` | READ ingresses dp9. `reg_tag` is written with the new generation; the deadline is cleared to `UNARMED_WORD`; the READ is forwarded to the relay. |
| `t0 + deparser` | Mirror request emitted. PRE makes 64 copies. |
| `t0 + PRE + egress` | 64 copies traverse egress, get rewritten to tokens, egress dp8. |
| `t0 + one loopback pass` | Tokens re-enter ingress as `ROLE_BLOCK`, pass the tag check (their gen matches the tag written at `t0`), fail the expiry check (deadline unarmed), and are enqueued to `QID_BLOCK`. **Reservoir established.** |
| `t0 + ~1-5 ms` | Outstation ACK arrives, arms the deadline. |
| later | RESPONSE arrives, is admitted to `QID_RESP`, and is held because `QID_BLOCK` is backlogged. |

The margin is roughly three orders of magnitude: a single dp8 loopback pass was previously measured
at ~408 ns, and even a pessimistic 100 ns per PRE copy puts the whole seed at ~6.4 µs against a
1-5 ms budget. The ordering requirement is met with very large slack — **but this is an argument
from measured constants, not a silicon measurement of this construction.**

Note also that the tag is written by the READ in the *same ingress pass* that requests the mirror,
so the tokens cannot possibly loop back before their own generation is installed. That dependency is
structural, not a race.

### 5.3 K bounded at exactly 64

Three separate things bound K:

1. **The group is a constant.** 64 L1 nodes, installed once. The data plane cannot make 65.
2. **The retransmission gate.** A data-plane trigger introduces a hazard the host injector did not
   have: if the master retransmits the READ, the mirror would fire twice and put 128 same-generation
   tokens in the reservoir. The gate `if (meta.tag_ok == 8w0)` suppresses this by minting only when
   the generation actually changed — `meta.tag_ok` is already computed by the existing SALU, so this
   costs nothing new. `ctr_seed_suppress` counts the suppressions, which is also a useful health
   signal.
3. **Cross-generation overlap is unchanged from today.** Tokens from generation *n-1* still in
   flight when generation *n* arrives fail the tag check and are dropped
   (`ctr_block_term_stale`). Transient overlap during that handover is identical in kind and
   duration to the current host-seeded behaviour.

### 5.4 Termination and external visibility

Unchanged. Tokens terminate through the same three frozen paths (stale tag / deadline expired /
budget exhausted), all of which `drop_pkt()`. The multicast group's only member port is dp8, an
internal MAC-near loopback with no cable, so **no token can reach a front-panel port by
construction** — there is no forwarding decision involved that could be got wrong.

---

## 6. Does it compile?

Yes. Compiled locally, exactly as run:

```bash
cd /home/philip/Projects/DNP3/research/timing_final/p4
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out_selfseed dnp3_timing_normalizer_selfseed.p4
# 0 errors, 3 warnings generated.
```

The 3 warnings are the same benign ones the baseline emits (uninitialised `meta` out-param by
design, and two parser loop-unroll notes).

### 6.1 Resource fit against the current 10/12

Measured from `out_selfseed/pipe/logs/metrics.json` and the `.bfa` stage headers, against the frozen
inline baseline in `build_inline_local/`:

| Resource | inline baseline | selfseed | Δ |
|---|---|---|---|
| **Ingress MAU stages** | **10 / 12** | **10 / 12** | **0** |
| **Egress MAU stages** | 0 / 12 | **2 / 12** | +2 |
| Ingress latency (cycles) | 221 | 221 | 0 |
| Egress latency (cycles) | 168 | 170 | +2 |
| SRAM (of 480) | 55 | 61 | +6 |
| Map RAM (of 384) | 54 | 60 | +6 |
| TCAM (of 288) | 1 | 1 | 0 |
| Logical tables | 60 | 64 | +4 |
| Exact crossbar bytes | 70 | 72 | +2 |
| Action bus bytes | 18 | 18 | 0 |

**The headline is that the ingress stage count does not move.** The seeding logic is a deparser
action plus two counters in ingress, and one table plus one counter in the previously empty egress.
The 10/12 ingress budget — the tight resource in this program — is preserved intact, which means the
internal-seeding variant does not trade away any of the timing mechanism's headroom.

### 6.2 What compiling does *not* prove

Honestly enumerated:

- **`$egress_port_queue` on a multicast mirror session.** The field exists in the Tofino-1 mirror
  schema; whether it is honoured for *multicast* copies (as opposed to unicast) is not stated in any
  file I read, and I did not run it. **The design tolerates failure here:** if the copies land on
  some other queue on dp8, they simply drain, loop back, and the existing `ROLE_BLOCK` dequeued
  branch enqueues them to `QID_BLOCK` on their next pass. The cost is one extra loopback pass
  (~408 ns), not a functional break.
- **PRE replication latency for 64 same-port nodes.** Not documented in this tree. Estimated
  sub-10 µs; unmeasured.
- **Whether `$max_pkt_len` counts the mirror metadata byte.** Unknown; set to 64 so it does not
  matter either way.
- **Whether the egress-port discriminator holds on silicon.** The argument in §4.3 is airtight
  against the *source code*, but has not been observed on hardware.
- **The tokens' on-wire shape.** The rewritten copy is `eth(14) + ib(7) + residual`, where the
  residual is whatever survives truncation of the original READ. The ingress `parse_token` state
  extracts only `hdr.ib` and ignores the rest, so the residual is harmless by inspection — but
  unobserved.

---

## 7. Verdict and what silicon validation would still require

**VERDICT: FEASIBLE-AND-COMPILED.**

Against the stated PASS criteria:

| Criterion | Status | Basis |
|---|---|---|
| No host `0x88C1` transmission per transaction | **Met by construction** | tokens are minted by the PRE from the READ; the host sends nothing |
| No controller action per transaction | **Met by construction** | mirror session + multicast group installed once at setup |
| K bounded and equal to 64 | **Met by construction** | 64 static L1 nodes + retransmission gate |
| Reservoir established before RESPONSE admitted | **Argued, ~3 orders of magnitude margin** | not measured on silicon |
| Zero external token visibility | **Met by construction** | group's only member is dp8, an internal loopback |
| Clean termination, no residual tokens | **Unchanged from frozen mechanism** | same three drop paths |

Four of six are structural. Two rest on design argument rather than measurement, which is why the
verdict stops short of "validated".

**Silicon validation would require, in order:**

1. Install the 64 `$pre.node` entries + `$pre.mgid` group + `$mirror.cfg` session 7, then confirm
   with `ctr_seed_mint == 1` and `ctr_seed_emit == 64` per READ that exactly 64 copies are made.
2. Confirm the tokens actually reach `QID_BLOCK` — the existing `ctr_block_enq` / `ctr_block_loop`
   counters answer this directly, and `ctr_block_enq` should read 64 per transaction.
3. Confirm the seed completes before the ACK: read `reg_ts_first_block` (already in the program) and
   compare against `reg_ts_ack_arm`. `ts_first_block < ts_ack_arm` is the ordering proof, and it is
   already instrumented — no new telemetry needed.
4. Confirm zero escape with per-port counters on dp9/dp11/dp64: no `0x88C1` frame may appear on any
   front-panel port. This must be a *port counter* check, not a host capture, since the point is
   that the host is no longer involved.
5. Re-run the existing CLRT-normalisation campaign and confirm the released-response timing
   distribution is statistically indistinguishable from the host-seeded baseline. The seeding change
   must be invisible in the defended observable.
6. Deliberately retransmit a READ and confirm `ctr_seed_suppress` increments while `ctr_block_enq`
   stays at 64.

All of the above requires loading a program, which is gated on explicit authorisation and would
displace the currently running experiment.

**On the packet generator specifically:** it is not ruled out and it is not "control-plane only" —
`BF_PKTGEN_TRIGGER_RECIRC_PATTERN` is a genuine Tofino-1 data-plane trigger and would also satisfy
the criteria. It is simply the more expensive route here (a new port group, a parser change, buffer
contention, and an undocumented emission rate), and it still needs a mirror to build its trigger
frame. If the multicast route fails on silicon for a reason we have not anticipated, pktgen is the
documented fallback rather than a dead end.

---

## 8. Files

- `/home/philip/Projects/DNP3/research/timing_final/p4/dnp3_timing_normalizer_selfseed.p4` — the
  candidate construction (new file; the inline program is untouched).
- `/home/philip/Projects/DNP3/research/timing_final/p4/out_selfseed/` — its build output
  (`pipe/logs/metrics.json`, `pipe/dnp3_timing_normalizer_selfseed.bfa`).
- `/home/philip/Projects/DNP3/research/timing_final/p4/dnp3_timing_normalizer_inline.p4` — unchanged.
