# CODE_WALKTHROUGH.md (direcr2 §17)

How the in-network DNP3 timing normalizer works, **in execution order** — the order a packet
actually flows through the Tofino-1 pipeline — not file order. Each excerpt gives the file, the exact
table/action/RegisterAction name, what it does, why it is needed, what would fail without it, and the
evidence that exercises it.

The complete program is `research/timing_final/p4/dnp3_timing_normalizer.p4` (923 lines, sha
82f572ce); the control plane is `research/ibspg_dnp3_replay/harness/p13_guard.py` plus the numbered
lab scripts. Only short excerpts appear here; read the full file for the surrounding context.

**Acronyms, defined once.** *DNP3* — Distributed Network Protocol 3, the SCADA protocol between a
*master* (control room) and an *outstation* (field device such as a relay). *CLRT* — Cross-Layer
Response Time, the interval between the transport-layer ACK of a DNP3 request and the application-layer
DNP3 response. *TNA* — Tofino Native Architecture, the P4 programming model for this switch. *TM* —
Traffic Manager, the switch's queueing/scheduling block. *MAU* — Match-Action Unit, one pipeline
"stage"; the program must fit in 12. *PHV* — Packet Header Vector, the fixed set of containers
carrying fields through the pipeline. *SALU* — Stateful ALU, the unit that reads-modifies-writes one
register per packet, limited to two PHV inputs. *qid* — queue identifier within a port.

---

## 1. Parser and packet classification

**File:** `dnp3_timing_normalizer.p4`, `parser IgParser` (lines 262–413).

The parser first branches on **ingress port** to set direction, then extracts Ethernet → (blocker
token | IPv4 → TCP → DNP3). A frame with EtherType `0x88c1` is a blocker token and parses as
`parse_token` (line 331); everything else parses as IPv4/TCP. Within TCP it extracts options
(`opt4/opt8/opt12`, lines 374–376) so the DNP3 data-link layer is found at the right offset, then
classifies the application role:

```p4
state set_role_ack  { meta.role = ROLE_ACK;  transition accept; }   // pure TCP ACK, no DNP3 payload
state set_role_resp { meta.role = ROLE_RESP; transition accept; }   // DNP3 RESPONSE (func 129)
state set_role_arm  { meta.role = ROLE_ARM;  transition accept; }   // DNP3 READ    (func 1)
```

**Why:** every later decision keys off `meta.role`. **Without it** the pipeline could not tell a READ
from an ACK from a RESPONSE and could not know which frames to hold. **Evidence:** the analyzer
classifies the same roles from the captured frames (`scripts/analyze_clrt.py`); the campaign's
per-transaction summary shows all three roles present (`evidence/packet_identity/`).

## 2. Direction classification from ingress port

**File:** parser states `from_loopback` / `from_outstation` / `from_master` (lines 313–318); the
`apply` guard `meta.port_ok` (line 693).

Direction is derived from the physical ingress port, not from IP addresses: dp8 → `DIR_OUT` and
`meta.dequeued = 1` (a frame returning from the internal loopback); dp11 (outstation side) → `DIR_OUT`;
dp9 (master side) → `DIR_MASTER`. Any other port is out of topology:

```p4
if (meta.port_ok == 8w0) { ctr_bypass.count(8w1); drop_pkt(); }     // isolate the pipeline
```

**Why:** the mechanism must act only on the three lab ports and must distinguish a *fresh* arrival from
a *dequeued* (looped-back) frame. **Without it** stray traffic on other ports would enter the state
logic. **Evidence:** `ctr_bypass` index 1 counts out-of-topology drops (readable via `make status`).

## 3. READ transaction arming

**File:** `apply` level 1 (lines 712–716); decode action `dec_arm` (line 629); TM action `to_fwd`
(line 579); state register `reg_tag` / `tag_rmw` (lines 428–434).

A DNP3 READ from the master (`ROLE_ARM && DIR_MASTER`) is classified `CLASS_ARM` and claims the
transaction by writing its generation into the packed tag. The READ itself is **forwarded** to the
outstation (`to_fwd`, line 771), never consumed:

```p4
meta.pkt_class = CLASS_ARM;
meta.tag_val   = meta.gen_in;      // ARM takes ownership; generation 0xCn from the DNP3 app-control byte
```

**Why:** the transaction needs a per-transaction identity so a later ACK/RESPONSE can be matched to
*this* READ. The generation is the DNP3 application-control sequence byte (0xC0..0xCF), so
retransmissions and overlapping transactions stay distinct. **Without it** the switch could not tell
which response belongs to which request. **Evidence:** `ctr_arm` counts forwarded READs.

## 4. Pure TCP ACK qualification

**File:** decode table `tbl_state_decode` (lines 633–647); action `dec_ack_arm` (line 630).

A pure ACK (`ROLE_ACK && DIR_OUT`) is classified `CLASS_ACK`. The decode table qualifies it **only if a
transaction is live**, using a ternary match on the tag difference — entry order is priority, so the
"no live transaction" reject pattern precedes the "accept" pattern:

```p4
(CLASS_ACK, 8w0x00 &&& 8w0xFE) : dec_none();     // tag_diff in {0,1}: no live transaction -> ignore
(CLASS_ACK, 8w0x00 &&& 8w0x00) : dec_ack_arm();  // live: this is the qualifying ACK -> arm
```

**Why:** only the ACK that belongs to a live transaction may arm the deadline; a stray ACK must write
nothing. **Without it** any ACK could move a release time. **Evidence:** `ctr_ack_arm` (qualifying)
vs `ctr_ack_bypass` (non-qualifying) separate the two on-chip.

## 5. Packed transaction state

**File:** `reg_tag` / `tag_rmw` (lines 428–434); `reg_deadline` (lines 454–471).

Two registers hold all per-transaction state. The **tag** packs generation + "active" into one byte;
the SALU returns the *difference* against this frame's generation, so "active AND my generation" is a
single `tag_diff == 0` test computed inside the ALU (two PHV inputs, within budget):

```p4
rv = meta.gen_in - v;                              // difference computed in the SALU
if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
```

The **deadline** word carries 24 bits of 256 ns ticks in [31:8] and the *armed marker* in bit 0, so
the "is it armed?" test and the "how old is it?" test share one register access. **Why:** the Tofino
allows very few stateful accesses per packet; packing two facts per word is what makes the program
fit. **Without it** the state would need more SALUs/stages than the 12-stage budget allows.
**Evidence:** the resource report — 10/12 ingress stages (`evidence/build/`, Fig 10).

## 6. Deadline calculation

**File:** `tbl_guard` / `set_guard` (lines 589–594); `tbl_build_now` (601–606); `tbl_build_cand`
(611–616).

G is supplied by the control plane in 256 ns ticks with a zero low byte (so it cannot disturb the
armed marker). The "now" word is built with the marker set, and the candidate armed deadline is
`now + G`:

```p4
action set_guard(bit<32> g_ticks) { meta.seq_m = g_ticks; }        // G from tbl_guard (policy)
action build_now()  { meta.now_word = meta.ts_m | ARMED_MARK; }    // level 1
action build_cand() { meta.dl_cand  = meta.now_word + meta.seq_m; }// level 2: deadline = now + G
```

Each is its own one-entry table because bf-p4c otherwise merges the statements into one action and
rejects the intra-action dependency ("action spanning multiple stages", measured on 9.13.1). **Why:**
the deadline is what every blocker token later compares against. **Without it** there would be no
release time. **Evidence:** the emitted interval tracks G across the sweep G∈{5..40} ms
(`evidence/protected/sweep_g*`).

## 7. RESPONSE queue assignment

**File:** action `to_resp` (lines 571–575); `apply` (lines 755–758).

A fresh RESPONSE from the outstation is steered onto the **low-priority** response queue on the
internal loopback port, and the G-guard is armed for it:

```p4
} else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
    to_resp();                 // enqueue Q_RESP (qid 1, LOW) on loopback dp8
    ctr_resp_enq.count(0);
    meta.is_fresh_resp = 8w1;  // arm the G-selection guard for this response
}
```

`to_resp` sets `ig_tm_md.qid = QID_RESP` and `bypass_egress = 1` — the *original* packet is enqueued
once, unmodified; it does not recirculate. **Why:** holding is done by *not scheduling* this queue,
not by copying the packet. **Without it** the response would egress immediately at native timing.
**Evidence:** byte-identity 100/100 (`evidence/packet_identity/`); `ctr_resp_enq`.

## 8. Blocker-token processing

**File:** action `to_block` (566–570); `apply` fresh-token branch (751–754) and dequeued-loop branch
(793–798).

Blocker tokens ride the **high-priority** queue on the same loopback. A fresh token is enqueued to
Q_BLOCK; a looped-back token that is still valid decrements its pass budget and re-enqueues, keeping
the reservoir full:

```p4
hdr.ib.seq = hdr.ib.seq - 32w1;    // consume one budget unit
to_block();                        // re-enqueue Q_BLOCK (qid 7, HIGH)
ctr_block_loop.count(0);
```

**Why:** a non-empty high-priority queue is what starves Q_RESP under strict priority — that is the
"hold". A *reservoir* (K ≥ 64) is required, not one token, or the queue can momentarily empty and leak
the response early (established in the IBSPG work). **Without it** there is no holding pressure.
**Evidence:** `ctr_block_loop` / `ctr_block_enq`; 0 blocker frames ever seen by the master
(STAGE_B_RESULT.md).

## 9. Deadline expiry

**File:** `tbl_deadline_expiry` (656–664).

Expiry is one ternary entry over the age word returned by the deadline SALU. The word reads as expired
only when the armed marker cancelled cleanly (low byte 0x00) **and** the tick difference is
non-negative (bit 31 clear):

```p4
(32w0x00000000 &&& 32w0x800000FF) : mark_expired();   // armed AND now >= deadline
```

**Why:** the target cannot do a 32-bit magnitude compare in one gateway, so the sign/marker test is
done as a TCAM mask on the whole container — not a bit slice (a bit slice breaks PHV allocation).
**Without it** tokens could not tell when to stop. **Evidence:** `ctr_block_term_deadline` counts
deadline-driven terminations; deadline-error distribution (Fig 7).

## 10. RESPONSE release

**File:** `apply` dequeued RESPONSE branch (799–810); action `to_fwd` (579).

Once the reservoir drains (all tokens terminated), strict priority no longer favours Q_BLOCK and the
TM finally schedules Q_RESP. The looped-back response is forwarded to the master byte-identically, and
the release cause is attributed:

```p4
to_fwd();
ctr_resp_release.count(0);
if (meta.expired == 8w1) { ctr_release_deadline.count(0); }  // drained on the deadline
else                     { ctr_release_fail_open.count(0); } // drained early on pass budget
```

**Why:** this is the moment the normalized response leaves. **Without it** the held packet would never
egress. **Evidence:** `ctr_resp_release`; release-tail decomposition 1734.5 ns (Fig 8); protected
CLRT sits at G within ~1.7 µs.

## 11. Pass-budget fail-open

**File:** `apply` (707, 721–723); dequeued-token branch (789–792).

Each token carries a finite pass budget (`hdr.ib.seq`). If it reaches zero before the deadline, the
transaction is retired and the response is released rather than held forever:

```p4
if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }   // token exhausted its passes
...
} else if (meta.budget_zero == 8w1) {
    drop_pkt(); ctr_block_term_timeout.count(0);       // fail-open path
}
```

**Why:** a stuck-closed queue would drop a real SCADA response — operationally unacceptable.
**Without it** a fault (e.g. a lost ACK) could black-hole a genuine response. **Evidence:**
`ctr_block_term_timeout` and `ctr_release_fail_open`.

## 12. State cleanup

**File:** decode action `dec_arm` (629); `tag_rmw` write (432); `t_ack_reset` (513–518).

A new READ disarms the previous deadline (`dl_val = UNARMED_WORD`) and resets the shadow t_ack, so the
next transaction starts clean. The tag is rewritten by the next ARM. **Why:** transactions must not
bleed into one another. **Without it** a stale deadline could hold a later, unrelated response.
**Evidence:** back-to-back transactions in the 100-rep campaign each normalize independently
(`evidence/protected/final100_g25.summary.json`).

## 13. Counters and timestamp registers

**File:** counters (544–563); sparse timestamp registers `reg_ts_*` (479–494); shadow t_ack
(512–529); readout registers `reg_native_clrt` / `reg_protection` (534–541).

Four write-if-zero timestamp registers capture first-occurrence latencies (first block, ACK-arm, block
termination, first response release); their differences give G_observed, deadline error, and the
release tail. The G-guard registers expose native CLRT and the protection flag to the control plane.
**Why:** these are the on-chip evidence the analysis reads back. **Without them** the release-tail and
G-guard numbers could not be measured on silicon. **Evidence:** Fig 8 (tail) and Fig 9 (guard) are
built from these; `make status` reads the counters live.

## 14. Traffic Manager configuration

**File:** control plane `scripts/03_configure_tm.py`; policy setter
`research/ibspg_dnp3_replay/harness/p13_guard.py`.

The data plane assumes Q_BLOCK (qid 7) is strict-priority above Q_RESP (qid 1) on the loopback port;
the control plane installs that TM strict-priority configuration and sets the max_priority field (the
IBSPG root-cause fix — without it the queues split fairly and holding fails). `p13_guard.py` sets G as
a keyless-table default action, tick-aligned and read-back-verified:

```python
g_ticks_ns = g_ns & 0xFFFFFF00        # low byte zero so it cannot corrupt the armed marker
```

**Why:** the whole hold depends on the strict-priority relationship and on a correctly aligned G.
**Without it** either the response is never held (fair split) or the armed marker is corrupted (bad G).
**Evidence:** queue-priority readback in `make status`; `p13_guard.py` prints `verified: true` only
when the aligned value reads back.

## 15. Packet-verification logic

**File:** `scripts/08_verify.py`; `scripts/analyze_clrt.py`; `scripts/fingerprint_eval.py`.

Verification is deliberately **off-switch and independent** of the P4: `analyze_clrt.py` reassembles
transactions from the raw PCAP and rejects ambiguous pairings rather than guessing; `08_verify.py`
checks byte-identity and the expected transaction count; `fingerprint_eval.py` computes the entropy
before/after and is cross-checked against tshark field extraction (`DNP3_TSHARK_FIELDS.md`). **Why:**
the headline numbers must not depend on the same code that produced the behaviour. **Without it** a
parser bug could flatter the result. **Evidence:** the fingerprinting table and CIs
(`evidence/fingerprinting/fingerprint_eval.json`; TIMING_FINGERPRINTING_ANALYSIS.md).

---

## Code-to-mechanism table

| Mechanism | P4 component | Setup component | Test / evidence component |
|---|---|---|---|
| READ classification | `set_role_arm`, `dec_arm`, `tbl_state_decode` (CLASS_ARM) | ports in `lab.env` | `ctr_arm`; `analyze_clrt.py` role count |
| ACK qualification | `set_role_ack`, `dec_ack_arm`, `tbl_state_decode` (CLASS_ACK entries) | — | `ctr_ack_arm` vs `ctr_ack_bypass` |
| Deadline arm | `deadline_arm_once` (first-ACK idempotent), `tbl_build_cand` | `p13_guard.py --set-g-ms` | `evidence/protected/sweep_g*`; Fig 5 |
| Response hold | `to_resp` (Q_RESP qid1), strict priority | `03_configure_tm.py` (max_priority) | `ctr_resp_enq`; byte-identity 100/100 |
| Release | dequeued RESPONSE branch, `to_fwd`, `tbl_deadline_expiry` | — | `ctr_resp_release`; Fig 8 release tail |
| Fail-open | `budget_zero`, `ctr_block_term_timeout` | token reservoir depth K | `ctr_release_fail_open` |
| Token isolation | `to_block` (bypass_egress), EtherType 0x88c1 on dp8 | loopback dp8 config | 0 blocker frames at master (STAGE_B_RESULT.md) |
| G-selection guard | `t_ack_capture`, `tbl_clrt_guard`, `reg_native_clrt` | `p13_guard.py` | `ctr_response_actually_held`/`zero_hold`; Fig 9 |

The complete P4 source is included in the package under `source/` and at
`research/timing_final/p4/dnp3_timing_normalizer.p4`.
