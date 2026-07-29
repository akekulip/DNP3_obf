/* ============================================================================
 * case_a_dual_min.p4 — the MINIMAL SYNTHETIC DUAL-RELEASE GATE for Tofino-1.
 *
 * PURPOSE: prove ONE complete two-deadline transaction end to end, on chip,
 * with nothing external. Not the full test matrix, not the DNP3 defense.
 *
 *   one synthetic READ  -> record t_READ, store d_ACK = t_READ + A and
 *                          d_RESP = t_READ + R, trigger ONE 128-token pktgen
 *                          batch
 *   packet_id   0.. 63  -> ACK-deadline blockers      -> Q_ABLOCK (qid 7)
 *   packet_id  64..127  -> response-deadline blockers -> Q_RBLOCK (qid 5)
 *   one synthetic ACK   -> Q_ACK  (qid 6)
 *   one synthetic RESP  -> Q_RESP (qid 4)
 *
 *   before d_ACK        Q_ABLOCK effective; ACK and RESPONSE held
 *   at d_ACK            ACK blockers terminate; Q_ACK releases the ACK
 *   after ACK release   ack_commit_gen = current generation
 *   d_ACK .. d_RESP     Q_RBLOCK effective; RESPONSE held
 *   at d_RESP           response blockers terminate ONLY when
 *                         now >= d_RESP AND ack_commit_gen == blocker_generation
 *   after Q_RBLOCK      Q_RESP releases the RESPONSE
 *
 * ---------------------------------------------------------------------------
 * DERIVATION. This is a MINIMAL VARIANT of p4/case_a_dual_release_skeleton.p4
 * (9 ingress / 0 egress, critical path 8), not an edit of it — that file stays
 * exactly as it was when it produced the Phase-0 fit answer. Carried over
 * VERBATIM in construction, each marked "FROM SKELETON":
 *   - the 256 ns deadline-word encoding (24 ticks in [31:8], ARMED marker in
 *     bit 0) and the two absolute READ-anchored deadline registers;
 *   - the whole-container expiry ternary 0x00000000 &&& 0x800000FF, one table
 *     per deadline, NO NEW BIT-SLICE;
 *   - the full-width packet_id ternary 0x0000/0x0040 &&& 0xFFC0;
 *   - reg_tag generation idempotency and the tag_rmw / tag_read split;
 *   - the one-decode table that folds stale / qualify / anchor into one lookup;
 *   - per-class per-token fail-open budgets carried in the token's own seq;
 *   - the request-triggered mirror clone (0xE1 marker) that fires the batch.
 *
 * DELETED relative to the skeleton, because everything here is synthetic:
 * the IPv4 / TCP / TCP-options / DNP3 parse chain, the pure-ACK flag and
 * length gates, the host ports (dp9 / dp11 / dp64), the host-injected token
 * path, and the two 16-slot counter arrays (replaced by ONE indexed reason
 * counter, per the instrumentation budget).
 *
 * ADDED, and it is the one genuinely new mechanism:
 *   GENERATION-BOUND ACK COMMITMENT. The skeleton stored a BOOLEAN
 *   ack_committed_to_master. A boolean left over from a previous transaction
 *   reads "committed" for the NEXT one, so a response blocker could terminate
 *   against a stale commit. reg_ackc_gen stores the GENERATION whose ACK was
 *   committed, and a response blocker terminates only when that generation
 *   equals ITS OWN. See "GENERATION-BOUND ACK COMMITMENT" below for where it
 *   is written and where it is tested.
 *
 * ---------------------------------------------------------------------------
 * TOPOLOGY — TWO PORTS, BOTH INTERNAL. NO HOST PORT APPEARS AT ALL.
 *
 *   pktgen app 2 (timer one-shot, 3 packets, ipg apart)
 *        pid 0 = READ, pid 1 and pid 2 = the ACK and the RESPONSE
 *        (which of pid 1 / pid 2 is which is CONTROL-PLANE assigned; that is
 *         how the early-response safety test is expressed without a recompile)
 *                                |
 *   dp68 --------------------> [ingress] --- mirror 0xE1|gen ---> dp68
 *                                |                                  |
 *                                |                    pktgen app 1 (recirc
 *                                |                    pattern) 1 batch x 128
 *                                v
 *                        dp8 queues 7 / 6 / 5 / 4 / 3
 *                                |
 *                     dp8 egress -> MAC-near loopback -> dp8 ingress
 *
 * dp9 (Vision), dp11 (Hulk) and dp64 (the SEL-751 leg) DO NOT APPEAR IN THIS
 * FILE — not as a constant, not as a parser transition, not as action data.
 * The isolation is STRUCTURAL: ig_tm_md.ucast_egress_port is assigned from
 * exactly ONE compile-time immediate, PORT_L, in exactly five actions, and is
 * never assigned from metadata, a header field, or table action data. That is
 * checkable in pipe/context.json rather than merely asserted here. PORT_PGEN
 * is INGRESS-ONLY: it appears in one parser select and in no action.
 *
 * ---------------------------------------------------------------------------
 * THE FINAL FIFO — AND ONE HONEST FIDELITY NOTE
 *
 * Design §4 requires the released ACK and the released RESPONSE to reach the
 * SAME master-facing FIFO, ACK first. There is no master here, so the surrogate
 * is Q_FINAL, a fifth dp8 queue that both released frames are committed to and
 * that they are dropped out of on their next pass. reg_final_first latches the
 * role of whichever leaves it first and must read ROLE_ACK.
 *
 * FIDELITY NOTE, stated rather than hidden: Q_FINAL is configured BELOW Q_RESP
 * (max_priority 3), so a committed frame does not physically leave dp8 until
 * the blockers above it are done. In the real defense the master-facing FIFO is
 * on a different port and is not in contention with the blockers. This changes
 * WHEN a committed frame departs; it does not change the COMMITMENT order,
 * which is what reg_ts_ack_commit / reg_ts_resp_commit measure and what the
 * single shared FIFO then preserves. Raising Q_FINAL above Q_ABLOCK was
 * rejected because it would tie two queues at max_priority 7, and the
 * four-queue oracle's control D measured that ties interleave.
 *
 * ---------------------------------------------------------------------------
 * TOKEN ACCOUNTING. Every admitted token leaves by exactly one of three
 * counted doors — deadline, budget, stale — so per class
 *
 *     admitted == terminated_deadline + terminated_budget + terminated_stale
 *
 * closes if and only if no token is still circulating. That conservation
 * identity is the cleanup and trial-isolation test, and it is deliberately NOT
 * `usage_cells`: the four-queue oracle measured usage_cells reading 0 on every
 * dp8 queue in all five shaper settings including one that demonstrably leaked,
 * so a drain check built on it can never fail.
 *
 * ---------------------------------------------------------------------------
 * NOT CLAIMED. Nothing here has been loaded or run. Authored and compiled
 * off-switch with bf-p4c 9.13.1. The switch was NOT touched: it is running
 * Defense 2 (dnp3_timing_normalizer_pktgen) and loading this program would
 * displace it, which is a separate and explicitly authorized step.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertype ------------------------------------------------------------
 * A FRESH value, so a frame from this program can never be confused with one
 * from any other in the tree:
 *   0x88C0 IBSPG "real"        0x88C1 IBSPG blocker token
 *   0x88C2 four_queue_oracle   0x88C3 four_queue_dequeue_oracle
 *   0x88C5 THIS program                                                    */
const bit<16> ETHERTYPE_DUAL = 0x88C5;

/* ---- ports — the COMPLETE set --------------------------------------------
 * PORT_PGEN (dp68) is Tofino-1's pipe-0 packet-generator / recirculation port,
 * used here for BOTH generated packets and the recirculating trigger clone.
 * PORT_L (dp8) is the MAC-near loopback that owns all five queues, and is the
 * only value ever assigned to ucast_egress_port.                            */
const PortId_t PORT_PGEN = 9w68;
const PortId_t PORT_L    = 9w8;

/* ---- the five queues on PORT_L -------------------------------------------
 * QUEUE ID DOES NOT IMPLY PRIORITY. P4 selects only the qid; the strict
 * ordering is control-plane configuration (tf1.tm.queue.sched_cfg
 * max_priority 7 / 6 / 5 / 4 / 3). The IBSPG root-cause repair established
 * that min_priority is inert unless min_rate_enable is true, and that leaving
 * max_priority unset degrades SILENTLY to a fair DWRR split. The four-queue
 * dequeue oracle then established the 7/6/5/4 ladder behaviourally on this
 * silicon (control C reversed the order by reversing only max_priority).   */
const bit<5> QID_ABLOCK = 5w7;   /* ACK-deadline blocker reservoir           */
const bit<5> QID_ACK    = 5w6;   /* the held synthetic ACK                   */
const bit<5> QID_RBLOCK = 5w5;   /* response-deadline blocker reservoir      */
const bit<5> QID_RESP   = 5w4;   /* the held synthetic RESPONSE              */
const bit<5> QID_FINAL  = 5w3;   /* the ONE shared master-facing FIFO        */

/* ---- packet generator ----------------------------------------------------
 * Byte 0 of the 6-byte generator header is pad(3) ++ pipe_id(2) ++ app_id(3),
 * so a pipe-0 app id N appears as the byte value N. Two apps:
 *   app 1  the 128 blocker tokens, fired by a recirculation-PATTERN trigger on
 *          the READ's mirror clone (the mechanism Defense 2 proved on silicon)
 *   app 2  the three synthetic events, fired by a one-shot TIMER, ipg apart
 * A packet from any other pipe carries pipe_id != 0 and therefore a different
 * byte 0, matches neither classification table, and is dropped and counted. */
const bit<8> APP_BLOCK_BYTE = 8w0x01;
const bit<8> APP_EVENT_BYTE = 8w0x02;

/* the trigger clone: 4 bytes, MARKER(byte 0) | gen(low byte). The control
 * plane pins pattern_value 0xE1000000 / pattern_mask 0xFF000000, exactly as
 * the frozen Defense 2 setup does. Generated packets lead with byte 0 = 0x01
 * or 0x02, so they can never re-trigger the app.                            */
const bit<32> CLONE_TAG_MARKER = 32w0xE1000000;
typedef bit<3> mirror_type_t;                 /* mirror_type is bit<3> on TF1 */
const mirror_type_t MIRROR_TYPE_CLONE = 1;
const MirrorId_t    CLONE_SESSION_ID  = 10w7;

/* the first 4 bytes of the generator header (pad/pipe/app + key) are consumed
 * by extracting pipe_app and key_or_batch; only packet_id is read for the
 * blocker split, and pipe_app for the app discrimination above.             */

/* ---- roles, carried in the frame's own header so they survive the queue ---
 * All 128 generated blockers are byte-identical copies of ONE buffer template
 * and all 3 events are copies of another; their only hardware distinguishing
 * mark is packet_id, which lives in the generator header — and that header is
 * STRIPPED at the ingress deparser. So the enqueue pass stamps the role into
 * the frame, where it survives the loopback.                                */
const bit<8> ROLE_NONE   = 8w0;
const bit<8> ROLE_ABLOCK = 8w1;
const bit<8> ROLE_ACK    = 8w2;
const bit<8> ROLE_RBLOCK = 8w3;
const bit<8> ROLE_RESP   = 8w4;
const bit<8> ROLE_READ   = 8w5;

/* ---- phase: where in its life the frame is -------------------------------
 * PH_NEW   as generated (the template carries 0)
 * PH_HELD  parked in Q_ABLOCK / Q_ACK / Q_RBLOCK / Q_RESP
 * PH_FINAL committed to Q_FINAL; dropped and counted on its next pass       */
const bit<8> PH_NEW   = 8w0;
const bit<8> PH_HELD  = 8w1;
const bit<8> PH_FINAL = 8w2;

/* ---- packed-state constants — FROM SKELETON ------------------------------ */
const bit<32> TICK_MASK   = 32w0xFFFFFF00;  /* keep 24 tick bits, clear marker */
const bit<32> ARMED_MARK  = 32w0x00000001;  /* bit 0 of a deadline word = armed */
const bit<32> DL_NO_WRITE = 32w0;           /* SALU sentinel: leave deadline be */
const bit<8>  TAG_NO_WRITE = 8w0;           /* SALU sentinel: leave the tag be  */
const bit<8>  TAG_INACTIVE = 8w0xFF;        /* explicit "no transaction"        */

/* GENERATION-BOUND ACK COMMITMENT — the constants.
 * reg_ackc_gen stores the GENERATION whose ACK has been committed, never a
 * boolean. 0 is the SALU no-write sentinel, so "cleared" must be a distinct
 * non-zero value; ACKC_NONE = 0xFF is outside the generation domain
 * 0xC0..0xCF that the control plane writes into the event template, and is
 * therefore a value no blocker's own generation can ever equal.             */
const bit<8> ACKC_NO_WRITE = 8w0;
const bit<8> ACKC_NONE     = 8w0xFF;

/* ---- the two READ-anchored offsets, ALREADY IN DEADLINE-WORD FORM --------
 * design §6 first proof-of-mechanism operating point: A = 3 ms, R = 13 ms.
 *   A = 3 ms  -> 0x002DC6 ticks ->  2 999 808 ns (quantization error -192 ns)
 *   R = 13 ms -> 0x00C65D ticks -> 12 999 936 ns (quantization error  -64 ns)
 * The low byte MUST be zero so the ARMED marker survives the add. The control
 * plane rewrites tbl_guard's default action parameters for an (A, R) sweep
 * with no recompile.                                                        */
const bit<32> A_DEFAULT_WORD = 32w0x002DC600;
const bit<32> R_DEFAULT_WORD = 32w0x00C65D00;

/* ---- fail-open pass budgets, per class, runtime-settable -----------------
 * These are the BACKSTOP, not the release mechanism: a token normally
 * terminates on its own deadline (priority stale > deadline > budget). They
 * also bound cleanup — a trial that goes wrong is self-clearing within one
 * budget, with no control-plane action.
 *
 * Sizing, from the one hard rate fact: dp8 runs at 25G and a 64-byte frame
 * plus preamble and inter-frame gap is 84 B = 672 bit, so dp8 cannot dequeue
 * faster than ~37.2 Mpps. With 64 tokens sharing that queue, one token comes
 * around no faster than 64 / 37.2e6 = 1.72 us, so
 *     A = 3 ms  -> at most ~1 744 passes per ACK  blocker
 *     R = 13 ms -> at most ~7 560 passes per RESP blocker
 * (the response blockers are starved by Q_ABLOCK until d_ACK, so their real
 * exposure is S = R - A, but the bound is taken over R). The defaults below
 * are ~11x and ~10x those, matching design §10's "horizon ~10x the deadline",
 * and both are action data so the driver can retune from measurement.       */
const bit<32> BUDGET_A_DEFAULT = 32w20000;
const bit<32> BUDGET_R_DEFAULT = 32w80000;

/* ---- packet classes: the ONE decode key ---------------------------------- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;  /* fresh READ event                      */
const bit<8> CLASS_ACK_NEW   = 8w2;  /* fresh ACK event                       */
const bit<8> CLASS_RESP_NEW  = 8w3;  /* fresh RESPONSE event                  */
const bit<8> CLASS_BLOCK_NEW = 8w4;  /* fresh generated blocker (needs tag_read) */
const bit<8> CLASS_BLOCK_DEQ = 8w5;  /* blocker back from the loopback        */
const bit<8> CLASS_ACK_DEQ   = 8w6;  /* the held ACK on its release pass      */
const bit<8> CLASS_RESP_DEQ  = 8w7;  /* the held RESPONSE on its release pass */
const bit<8> CLASS_FINAL     = 8w8;  /* a committed frame leaving Q_FINAL     */

/* ---- the ONE indexed reason counter --------------------------------------
 * Deliberately ONE Counter object with compile-time-constant indices. The
 * four-queue oracle became logical-table-ID bound from action-block breadth,
 * and the skeleton's own probe B measured that 6 extra counter branches cost
 * exactly one more stage. Every site below is a LEAF of one if/else chain, so
 * all sites are mutually exclusive per packet — bf-p4c hard-errors otherwise.
 * There is no "total" slot: a total plus its own subset is exactly the shape
 * that is not mutually exclusive.                                           */
const bit<8> C_DROP_BAD_PORT     = 8w0;   /* ingress port is neither dp68 nor dp8 */
const bit<8> C_DROP_NON_DUAL     = 8w1;   /* not ethertype 0x88C5                 */
const bit<8> C_ARM_FRESH         = 8w2;   /* READ anchored both deadlines, cloned */
const bit<8> C_ARM_DUP           = 8w3;   /* duplicate READ: no re-anchor, no clone */
const bit<8> C_ADMIT_ABLOCK      = 8w4;   /* pid   0.. 63 -> Q_ABLOCK             */
const bit<8> C_ADMIT_RBLOCK      = 8w5;   /* pid  64..127 -> Q_RBLOCK             */
const bit<8> C_PGEN_NOTXN        = 8w6;   /* generated token, no active txn       */
const bit<8> C_ACK_HELD          = 8w8;   /* synthetic ACK  -> Q_ACK              */
const bit<8> C_ACK_NOTXN         = 8w9;   /* ACK  with no active txn: dropped     */
const bit<8> C_RESP_HELD         = 8w10;  /* synthetic RESP -> Q_RESP             */
const bit<8> C_RESP_NOTXN        = 8w11;  /* RESP with no active txn: dropped     */
const bit<8> C_FRESH_BAD         = 8w12;  /* fresh generated frame in no class    */
const bit<8> C_LOOP_ABLOCK       = 8w13;  /* ACK  blocker re-enqueued             */
const bit<8> C_LOOP_RBLOCK       = 8w14;  /* RESP blocker re-enqueued             */
const bit<8> C_TERM_ABLOCK_DL    = 8w15;  /* ACK  blocker terminated at d_ACK     */
const bit<8> C_TERM_ABLOCK_TMO   = 8w16;  /* ACK  blocker budget expired          */
const bit<8> C_TERM_ABLOCK_STALE = 8w17;  /* ACK  blocker, stale generation       */
const bit<8> C_TERM_RBLOCK_DL    = 8w18;  /* RESP blocker terminated at d_RESP    */
const bit<8> C_TERM_RBLOCK_TMO   = 8w19;  /* RESP blocker budget expired          */
const bit<8> C_TERM_RBLOCK_STALE = 8w20;  /* RESP blocker, stale generation       */
const bit<8> C_ACK_COMMIT        = 8w21;  /* ACK  committed to Q_FINAL            */
const bit<8> C_RESP_COMMIT       = 8w22;  /* RESP committed to Q_FINAL            */
const bit<8> C_FINAL_DRAIN       = 8w23;  /* a committed frame left Q_FINAL       */
const bit<8> C_DEQ_BAD           = 8w24;  /* dequeued frame in no class           */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* the 4-byte recirc tag, prepended onto the MIRROR (clone) copy only. */
header recirc_tag_h { bit<32> tag; }

/* The 6-byte hardware packet-generator header, as a byte-exact overlay.
 * Written as a local header rather than using tofino1_base.p4's
 * pktgen_timer_header_t / pktgen_recirc_header_t on purpose: those two types
 * have the SAME width and the SAME packet_id placement (bytes 4..5) but differ
 * in bytes 1..3 (timer: pad(8) ++ batch_id(16); recirc: a 24-bit key lifted
 * from the trigger packet). This program uses BOTH trigger kinds — a timer app
 * for the events and a recirc-pattern app for the blockers — so naming bytes
 * 1..3 `key_or_batch` and never reading them is what keeps it honest. */
header pktgen_hdr_h {
    bit<8>  pipe_app;      /* pad(3) ++ pipe_id(2) ++ app_id(3) — app discriminator */
    bit<24> key_or_batch;  /* timer: pad ++ batch_id ; recirc: key — NEVER read     */
    bit<16> packet_id;     /* 0..127 within the batch — the blocker discriminator   */
}

/* the frame's own state, 7 bytes, immediately after the ethertype.
 *   role  0 in both templates; stamped by the classification tables on the
 *         enqueue pass and read back on every later pass
 *   phase PH_NEW -> PH_HELD at admission -> PH_FINAL at commitment
 *   gen   the TRANSACTION GENERATION. The control plane writes it into the
 *         event template once per transaction; blockers get it stamped from
 *         reg_tag at admission, so a token generated a hair after a new READ
 *         still carries the live generation.
 *   seq   the per-class fail-open pass budget, decremented on every loop      */
header dual_h { bit<8> role; bit<8> phase; bit<8> gen; bit<32> seq; }

struct headers_t {
    pktgen_hdr_h pgen;     /* consumed on the dp68 path, NEVER emitted */
    ethernet_h   eth;
    dual_h       dl;
}

/* Flags are bit<8> rather than bool/bit<1> deliberately: sub-byte fields packed
 * next to 32-bit register outputs invite SuperCluster allocation failures, and
 * every downstream gate is then a cheap 8-bit equality. */
struct ig_meta_t {
    /* ---- level 0: parser-derived ---- */
    bit<8>  src_ok;        /* 1 = arrived on dp68 or dp8                      */
    bit<8>  dequeued;      /* 1 = arrived on dp8, i.e. it just dequeued       */
    bit<8>  is_pgen;       /* 1 = a freshly generated packet                  */
    bit<8>  is_dual;       /* 1 = ethertype 0x88C5 and hdr.dl parsed          */
    bit<8>  my_gen;        /* hdr.dl.gen — this frame's own generation        */
    bit<32> ts32;          /* ingress_mac_tstamp[31:0] — the ONLY slice       */
    bit<32> ts_m;          /* ts32 & TICK_MASK                                */
    bit<8>  budget_zero;   /* 1 if hdr.dl.seq == 0 as dequeued                */
    bit<32> a_word;        /* A offset in deadline-word form  (tbl_guard)     */
    bit<32> r_word;        /* R offset in deadline-word form  (tbl_guard)     */
    bit<32> budget_a;      /* ACK-blocker  pass budget        (tbl_guard)     */
    bit<32> budget_r;      /* RESP-blocker pass budget        (tbl_guard)     */

    /* ---- level 1 ---- */
    bit<32> now_word;      /* ts_m | ARMED_MARK — the deadline-aligned "now"  */
    bit<8>  pkt_class;     /* tbl_class                                       */
    bit<8>  need_tag_read; /* 1 = raw tag read (blocker admission), else rmw   */
    bit<8>  tag_val;       /* PHV input 2 of reg_tag: 0 = do not write        */

    /* ---- level 2 ---- */
    bit<32> dl_cand_a;     /* now_word + A = this READ's d_ACK  word          */
    bit<32> dl_cand_r;     /* now_word + R = this READ's d_RESP word          */
    bit<8>  tag_diff;      /* SALU result: my_gen - stored_tag                */
    bit<8>  cur_gen;       /* raw stored generation (blocker admission)       */

    /* ---- level 3 ---- */
    bit<32> dl_val_a;      /* PHV input 2 of reg_d_ack  : 0 = do not write    */
    bit<32> dl_val_r;      /* PHV input 2 of reg_d_resp : 0 = do not write    */
    bit<8>  ackc_w;        /* PHV input 2 of reg_ackc_gen: 0 = do not write   */
    bit<8>  arm_fresh;     /* 1 = this READ advanced the generation           */
    bit<8>  tag_ok;        /* 1 = live AND this generation                    */
    bit<8>  ack_ok;        /* 1 = this ACK  qualified for the hold            */
    bit<8>  resp_ok;       /* 1 = this RESP qualified for the hold            */
    bit<8>  txn_active;    /* 1 = reg_tag holds a 0xCn generation             */

    /* ---- level 4 ---- */
    bit<32> age_a;         /* now_word - d_ACK,  straight out of the SALU     */
    bit<32> age_r;         /* now_word - d_RESP, straight out of the SALU     */
    bit<8>  ackc_diff;     /* my_gen - ack_commit_gen; 0 <=> committed TO ME  */

    /* ---- level 5 ---- */
    bit<8>  expired_a;     /* 1 = d_ACK  armed AND due                        */
    bit<8>  expired_r;     /* 1 = d_RESP armed AND due                        */

    /* ---- the eight sparse instrumentation events ---- */
    bit<8>  ev_read;        /* t_READ                                         */
    bit<8>  ev_ablock_term; /* first / final ACK-blocker termination          */
    bit<8>  ev_rblock_term; /* first / final response-blocker termination     */
    bit<8>  ev_ack_commit;  /* ACK forward commitment                         */
    bit<8>  ev_resp_commit; /* RESPONSE forward commitment                    */
    bit<8>  ev_final;       /* a committed frame left the shared final FIFO   */

    /* ---- the trigger clone ---- */
    bit<32>    clone_tag;
    MirrorId_t clone_ses;
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    /* The control plane loads this with the generated packets' leading byte
     * for BOTH apps (0x01 and 0x02). It is the pipe/app admission check: the
     * recirculating trigger clone leads with 0xE1 and therefore does not
     * match, so it falls through with src_ok = 0 and is dropped in the MAU. */
    value_set<bit<8>>(2) pgen_app;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* src_ok, dequeued, is_pgen, is_dual and my_gen are deliberately NOT
         * initialized here: the TNA parser has no clear-on-write, so assigning
         * a field in `start` and again later on the same path is a hard
         * compile error. Every default is the all-zero encoding the compiler's
         * own metadata initialization supplies, and every zero default is the
         * SAFE one — not a valid source, not dequeued, not generated, not a
         * dual frame, generation 0 (which is outside the 0xCn domain). */
        meta.ts32          = 32w0;
        meta.ts_m          = 32w0;
        meta.budget_zero   = 8w0;
        meta.a_word        = 32w0;
        meta.r_word        = 32w0;
        meta.budget_a      = 32w0;
        meta.budget_r      = 32w0;
        meta.now_word      = 32w0;
        meta.pkt_class     = CLASS_OTHER;
        meta.need_tag_read = 8w0;
        meta.tag_val       = TAG_NO_WRITE;
        meta.dl_cand_a     = 32w0;
        meta.dl_cand_r     = 32w0;
        meta.tag_diff      = 8w0;
        meta.cur_gen       = 8w0;
        meta.dl_val_a      = DL_NO_WRITE;
        meta.dl_val_r      = DL_NO_WRITE;
        meta.ackc_w        = ACKC_NO_WRITE;
        meta.arm_fresh     = 8w0;
        meta.tag_ok        = 8w0;
        meta.ack_ok        = 8w0;
        meta.resp_ok       = 8w0;
        meta.txn_active    = 8w0;
        meta.age_a         = 32w0;
        meta.age_r         = 32w0;
        meta.ackc_diff     = 8w0;
        meta.expired_a     = 8w0;
        meta.expired_r     = 8w0;
        meta.ev_read        = 8w0;
        meta.ev_ablock_term = 8w0;
        meta.ev_rblock_term = 8w0;
        meta.ev_ack_commit  = 8w0;
        meta.ev_resp_commit = 8w0;
        meta.ev_final       = 8w0;
        meta.clone_tag     = 32w0;
        meta.clone_ses     = 10w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_PGEN : from_pgen;
            PORT_L    : from_loopback;
            default   : accept;    /* src_ok stays 0 -> dropped in the MAU */
        }
    }

    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_app : parse_pgen;
            default  : accept;     /* the 0xE1 trigger clone -> dropped */
        }
    }

    state parse_pgen {
        meta.src_ok  = 8w1;
        meta.is_pgen = 8w1;
        pkt.extract(hdr.pgen);
        transition parse_eth;
    }

    /* A frame that has just been dequeued from one of the five queues and
     * looped back. It carries NO generator header — the ingress deparser
     * stripped it on the enqueue pass. */
    state from_loopback {
        meta.src_ok   = 8w1;
        meta.dequeued = 8w1;
        transition parse_eth;
    }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_DUAL : parse_dual;
            default        : accept;   /* is_dual stays 0 -> dropped */
        }
    }

    state parse_dual {
        pkt.extract(hdr.dl);
        meta.is_dual = 8w1;
        meta.my_gen  = hdr.dl.gen;
        transition accept;
    }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ================= state register 1: the TAG — FROM SKELETON ==========
     * One byte holding the transaction generation. The SALU returns the
     * DIFFERENCE against this frame's generation, so the comparison happens
     * inside the stateful ALU: tag_diff == 0 <=> a transaction is active AND
     * it is this frame's generation. PHV inputs: my_gen, tag_val — exactly 2. */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.my_gen - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };
    /* raw read of the stored generation, for a blocker being admitted;
     * mutually exclusive with tag_rmw per packet (one SALU access). */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ================= state registers 2 and 3: the TWO DEADLINES =========
     * FROM SKELETON. 24 bits of 256 ns ticks in [31:8]; bit 0 is the ARMED
     * marker. Each SALU returns the age of ITS OWN deadline directly, so there
     * is no separate "age = now - deadline" MAU level and no separate armed
     * test. PHV inputs per register: now_word plus its own write field —
     * exactly 2 each. Both are written ONCE per transaction, on the fresh
     * READ, from the SAME now_word, so d_ACK and d_RESP are two absolute
     * instants on one clock. The two registers are INDEPENDENT and are read in
     * PARALLEL: reg_d_resp is not derived from reg_d_ack, so the second
     * deadline adds width to the pipeline, not depth to the dependency chain. */
    Register<bit<32>, bit<1>>(1, 0) reg_d_ack;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_d_ack) d_ack_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val_a != DL_NO_WRITE) { v = meta.dl_val_a; }
        }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_d_resp;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_d_resp) d_resp_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val_r != DL_NO_WRITE) { v = meta.dl_val_r; }
        }
    };

    /* ================= GENERATION-BOUND ACK COMMITMENT ===================
     * *** THE ONE NEW MECHANISM IN THIS PROGRAM ***
     *
     * reg_ackc_gen stores the GENERATION whose ACK has been committed to the
     * shared final FIFO — never a boolean.
     *
     *   WRITTEN at: dec_ack_commit(), which sets ackc_w = my_gen. That action
     *               is reachable only from tbl_state_decode entry
     *               (CLASS_ACK_DEQ, tag_diff == 0), i.e. only for the held ACK
     *               on its dp8 release pass and only while its generation is
     *               still the current one. A fresh READ writes ACKC_NONE
     *               (dec_arm_fresh), which clears the state for the new
     *               transaction. Everything else supplies ACKC_NO_WRITE.
     *
     *   TESTED at:  the response-blocker termination branch in apply{}:
     *                   if (expired_r == 1 && ackc_diff == 0) -> terminate
     *               where ackc_diff is this SALU's return value,
     *               my_gen - stored. It is 0 if and only if the committed
     *               generation is EXACTLY this blocker's own generation.
     *
     * WHY THE GENERATION AND NOT A BOOLEAN. A boolean left set by transaction
     * N reads "committed" for transaction N+1, so an N+1 response blocker
     * could terminate at d_RESP with no ACK of its own ever having been
     * committed — a silent zero-hold that looks like a working run. With the
     * generation bound in, an N+1 blocker computes gen(N+1) - gen(N) != 0 and
     * keeps circulating. That protection is INDEPENDENT of the clear-on-READ:
     * either alone would be enough in the happy path, and the point is that
     * neither has to be trusted alone.
     *
     * ONE RegisterAction, ONE access per packet, TWO PHV inputs (my_gen,
     * ackc_w) — the skeleton's four bf-p4c constraints are all still met. */
    Register<bit<8>, bit<1>>(1, 0) reg_ackc_gen;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_ackc_gen) ackc_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.my_gen - v;
            if (meta.ackc_w != ACKC_NO_WRITE) { v = meta.ackc_w; }
        }
    };

    /* ================= the eight sparse instrumentation registers =========
     * Deliberately sparse: exactly the events the brief names, and nothing
     * else. d_ACK and d_RESP are not repeated here — they ARE reg_d_ack and
     * reg_d_resp, read directly by the control plane.
     *
     * "first" is write-if-zero, so it latches the first occurrence. "final" is
     * a plain write, so the last occurrence wins. Both are needed: together
     * they bound the drain of a whole 64-token reservoir. */
    Register<bit<32>, bit<1>>(1, 0) reg_t_read;               /* t_READ */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_t_read) t_read_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ablock_first;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ablock_first) ablock_first_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ablock_last;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ablock_last) ablock_last_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_commit;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_commit) ack_commit_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_rblock_first;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_rblock_first) rblock_first_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_rblock_last;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_rblock_last) rblock_last_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_resp_commit;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_resp_commit) resp_commit_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    /* the ORDER fact design §4 asks for, in one byte: whichever committed
     * frame leaves the shared final FIFO first latches its own role here. It
     * must read ROLE_ACK. */
    Register<bit<8>, bit<1>>(1, 0) reg_final_first;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_final_first) final_first_w = {
        void apply(inout bit<8> v) { if (v == 8w0) { v = hdr.dl.role; } }
    };

    /* ================= the ONE indexed reason counter ==================== */
    Counter<bit<64>, bit<8>>(32, CounterType_t.PACKETS) ctr_evt;

    /* ================= TM actions — five queues, ONE port =================
     * ucast_egress_port is assigned from the compile-time immediate PORT_L in
     * these five actions and NOWHERE else in the program. bypass_egress = 1 on
     * every one of them, so nothing traverses egress and egress cannot perturb
     * the ordering being measured. */
    action to_ablock() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ABLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_ack_q() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ACK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_rblock() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RBLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* THE ONE SHARED MASTER-FACING FIFO (design §4). Both the released ACK and
     * the released RESPONSE are committed here, and only here. */
    action to_final() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_FINAL;
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* MEASURED RESOURCE NOTE, so the next person does not have to rediscover it.
     * A bare action CALL in apply{} becomes its own logical table and does NOT
     * merge with the adjacent ctr_evt.count(), and Tofino-1 has only 16 logical
     * table IDs per stage. Dropping inline (`ig_dprsr_md.drop_ctl = 3w1;`)
     * instead of calling a drop_pkt() action merged 16 drop leaves with their
     * counters and took the program from 11 ingress stages to 10 — measured,
     * both builds, bf-p4c 9.13.1. Inlining these five queue actions the same way
     * measures 9 stages / 57 tables. That lever is deliberately NOT taken: the
     * named actions are what make "ucast_egress_port is assigned from the
     * compile-time immediate PORT_L in exactly five actions and nowhere else"
     * a claim checkable in pipe/context.json. It is recorded here as available
     * headroom if a later phase needs the stage. */

    /* Request one I2E mirror (the trigger clone) to dp68 and build the 4-byte
     * recirc tag = MARKER | gen. Called ONLY on the fresh-ARM path.
     *
     * The READ itself is then dropped: there is no relay to forward it to, and
     * tofino1_base.p4:203-206 documents ig_dprsr_md.drop_ctl bit 0 as
     * disabling "unicast, multicast, and resubmit" and bit 1 as disabling
     * copy-to-cpu — mirroring is a separate deparser function and is not
     * listed. TODO(silicon): that reading is from the header comment, not from
     * a measurement on this switch. RESOLVING CHECK: the blocker batch exists
     * only if the mirror survived the drop, so ctr_evt[C_ADMIT_ABLOCK] == 64
     * and the app's trigger_counter == 1 confirm it; both reading 0 while
     * ctr_evt[C_ARM_FRESH] == 1 would localize the failure to exactly this. */
    action arm_clone() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.my_gen;
    }

    /* ================= level 0: the policy words ==========================
     * ONE table, four action parameters — the control plane rewrites the
     * default action for an (A, R) or budget sweep with no recompile. A and R
     * are already in deadline-word form (ticks in [31:8], low byte zero) so
     * the ARMED marker survives the addition. */
    action set_guard(bit<32> a_word, bit<32> r_word,
                     bit<32> budget_a, bit<32> budget_r) {
        meta.a_word   = a_word;
        meta.r_word   = r_word;
        meta.budget_a = budget_a;
        meta.budget_r = budget_r;
    }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(A_DEFAULT_WORD, R_DEFAULT_WORD,
                                   BUDGET_A_DEFAULT, BUDGET_R_DEFAULT);
        size = 1;
    }

    /* ================= level 0: blocker role from packet_id ===============
     * FROM SKELETON, verbatim in construction. FULL-WIDTH TERNARY on the whole
     * 16-bit container. Branching on packet_id[6] in P4 would be a bit-slice
     * and would hit the gateway-complexity trap ("condition expression too
     * complex"); slicing a 32-bit arithmetic field breaks PHV allocation
     * outright. The entries are `const` precisely so the required masks are
     * auditable in this source file rather than in a control-plane script.
     *
     * The action stamps the role INTO THE FRAME, which is what makes one
     * uniform downstream classification possible for fresh and dequeued
     * frames alike. */
    action set_ablock() { hdr.dl.role = ROLE_ABLOCK; }
    action set_rblock() { hdr.dl.role = ROLE_RBLOCK; }
    action set_blk_bad() { hdr.dl.role = ROLE_NONE; ig_dprsr_md.drop_ctl = 3w1; }
    table tbl_blocker_role {
        key = { hdr.pgen.packet_id : ternary; }
        actions = { set_ablock; set_rblock; set_blk_bad; }
        const default_action = set_blk_bad();
        const entries = {
            (16w0x0000 &&& 16w0xFFC0) : set_ablock();   /* packet_id   0.. 63 */
            (16w0x0040 &&& 16w0xFFC0) : set_rblock();   /* packet_id  64..127 */
        }
        size = 4;
    }

    /* ================= level 0: event role from packet_id =================
     * The three synthetic events. packet_id 0 is ALWAYS the READ; which of
     * packet_id 1 and 2 is the ACK and which is the RESPONSE is written by the
     * CONTROL PLANE, and swapping them is exactly how the `early-response`
     * safety test is expressed — no recompile, no second P4 variant, and the
     * generator's emission order is untouched. The setup script reads all
     * three entries back and records them in the trial manifest. */
    action set_ev_read() { hdr.dl.role = ROLE_READ; }
    action set_ev_ack()  { hdr.dl.role = ROLE_ACK;  }
    action set_ev_resp() { hdr.dl.role = ROLE_RESP; }
    action set_ev_bad()  { hdr.dl.role = ROLE_NONE; ig_dprsr_md.drop_ctl = 3w1; }
    table tbl_event_role {
        key = { hdr.pgen.packet_id : exact; }
        actions = { set_ev_read; set_ev_ack; set_ev_resp; set_ev_bad; }
        const default_action = set_ev_bad();
        size = 8;
    }

    /* ================= level 1: the deadline-aligned "now" ================
     * FROM SKELETON. Must be an explicit table rather than a plain statement
     * beside the level-0 assignments: bf-p4c merges consecutive unconditional
     * statements into ONE action and then rejects the intra-action dependency
     * with "action spanning multiple stages" (measured on 9.13.1). */
    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    /* ================= level 1: ONE class decode ==========================
     * (dequeued, role, phase) -> class, as an exact-match table rather than a
     * chain of gateways. This is a deliberate resource choice: the four-queue
     * oracle became LOGICAL-TABLE-ID bound (16 per stage on Tofino-1) from
     * action-block breadth, and the skeleton's probe B measured ~16 logical
     * tables per stage in exactly this region. Nine gateway branches would
     * cost nine logical tables; one table costs one.
     *
     * The role read here was stamped into the frame at level 0 for a generated
     * packet, and survives the queue for a dequeued one, so the same key works
     * for both directions. */
    action cls_arm()       { meta.pkt_class = CLASS_ARM;
                             meta.tag_val   = meta.my_gen; }
    action cls_ack_new()   { meta.pkt_class = CLASS_ACK_NEW;   }
    action cls_resp_new()  { meta.pkt_class = CLASS_RESP_NEW;  }
    action cls_block_new() { meta.pkt_class = CLASS_BLOCK_NEW;
                             meta.need_tag_read = 8w1; }
    action cls_block_deq() { meta.pkt_class = CLASS_BLOCK_DEQ; }
    action cls_ack_deq()   { meta.pkt_class = CLASS_ACK_DEQ;   }
    action cls_resp_deq()  { meta.pkt_class = CLASS_RESP_DEQ;  }
    action cls_final()     { meta.pkt_class = CLASS_FINAL;     }
    action cls_none()      { meta.pkt_class = CLASS_OTHER;     }
    table tbl_class {
        key = {
            meta.dequeued : exact;
            hdr.dl.role   : exact;
            hdr.dl.phase  : exact;
        }
        actions = { cls_arm; cls_ack_new; cls_resp_new; cls_block_new;
                    cls_block_deq; cls_ack_deq; cls_resp_deq; cls_final;
                    cls_none; }
        const default_action = cls_none();
        const entries = {
            /* freshly generated (dequeued == 0) */
            (8w0, ROLE_READ,   PH_NEW)  : cls_arm();
            (8w0, ROLE_ACK,    PH_NEW)  : cls_ack_new();
            (8w0, ROLE_RESP,   PH_NEW)  : cls_resp_new();
            (8w0, ROLE_ABLOCK, PH_NEW)  : cls_block_new();
            (8w0, ROLE_RBLOCK, PH_NEW)  : cls_block_new();
            /* back from the loopback (dequeued == 1) */
            (8w1, ROLE_ABLOCK, PH_HELD) : cls_block_deq();
            (8w1, ROLE_RBLOCK, PH_HELD) : cls_block_deq();
            (8w1, ROLE_ACK,    PH_HELD) : cls_ack_deq();
            (8w1, ROLE_RESP,   PH_HELD) : cls_resp_deq();
            (8w1, ROLE_ACK,    PH_FINAL): cls_final();
            (8w1, ROLE_RESP,   PH_FINAL): cls_final();
        }
        size = 16;
    }

    /* ================= level 2: both candidate deadlines ==================
     * FROM SKELETON. Two INDEPENDENT adds off the same now_word (no
     * intra-action dependency, so they legitimately co-locate in one action
     * and one stage). The low byte of each addend is zero, so the ARMED marker
     * survives and the tick fields add. */
    action build_cand() {
        meta.dl_cand_a = meta.now_word + meta.a_word;
        meta.dl_cand_r = meta.now_word + meta.r_word;
    }
    table tbl_build_cand {
        actions = { build_cand; }
        const default_action = build_cand();
        size = 1;
    }

    /* ================= level 3: the ONE state decode ======================
     * FROM SKELETON. One lookup on the packet class and the tag difference
     * replaces the gen-mismatch compare level, the active-clear driver level
     * and the qualify / anchor level. The match unit reads the whole container
     * under a TCAM mask — nothing is sliced.
     *
     *   ARM      : tag_diff == 0 <=> a DUPLICATE READ (the generation did not
     *              move), so it writes NOTHING and cannot re-anchor either
     *              deadline or fire a second batch. Entry order IS priority,
     *              so the exact-zero reject pattern precedes the accept-any
     *              pattern.
     *   ACK/RESP : admitted only while tag_diff == 0, i.e. a transaction is
     *              active and it is this event's generation.
     *   ACK_DEQ  : the release pass. Requires tag_diff == 0, so a held ACK
     *              whose transaction has already been superseded commits
     *              nothing.
     *   BLOCK_DEQ: tag_diff == 0 <=> active AND my generation. */
    action dec_arm_fresh() {
        meta.dl_val_a  = meta.dl_cand_a;
        meta.dl_val_r  = meta.dl_cand_r;
        meta.ackc_w    = ACKC_NONE;      /* new transaction: nothing committed */
        meta.arm_fresh = 8w1;
    }
    action dec_arm_dup() {
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_NO_WRITE;
    }
    action dec_ack_admit() {
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_NO_WRITE;
        meta.ack_ok   = 8w1;
    }
    action dec_resp_admit() {
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_NO_WRITE;
        meta.resp_ok  = 8w1;
    }
    /* *** the generation-bound commit write *** */
    action dec_ack_commit() {
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = meta.my_gen;
    }
    action dec_live() {
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_NO_WRITE;
        meta.tag_ok   = 8w1;
    }
    action dec_none() {
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_NO_WRITE;
    }
    table tbl_state_decode {
        key = {
            meta.pkt_class : exact;
            meta.tag_diff  : ternary;
        }
        actions = { dec_arm_fresh; dec_arm_dup; dec_ack_admit; dec_resp_admit;
                    dec_ack_commit; dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0x00 &&& 8w0xFF) : dec_arm_dup();
            (CLASS_ARM,       8w0x00 &&& 8w0x00) : dec_arm_fresh();
            (CLASS_ACK_NEW,   8w0x00 &&& 8w0xFF) : dec_ack_admit();
            (CLASS_RESP_NEW,  8w0x00 &&& 8w0xFF) : dec_resp_admit();
            (CLASS_ACK_DEQ,   8w0x00 &&& 8w0xFF) : dec_ack_commit();
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live();
        }
        size = 16;
    }

    /* ================= level 3: is a transaction active? ==================
     * FROM SKELETON. A generated blocker is admitted only while a transaction
     * is live. reg_tag's raw value is provably in {0x00, 0xC0..0xCF, 0xFF};
     * "active" == it is a 0xCn generation. A masked-equality ternary on the
     * whole container — not a magnitude compare. */
    action mark_txn_active()   { meta.txn_active = 8w1; }
    action mark_txn_inactive() { meta.txn_active = 8w0; }
    table tbl_txn_active {
        key = { meta.cur_gen : ternary; }
        actions = { mark_txn_active; mark_txn_inactive; }
        const default_action = mark_txn_inactive();
        const entries = {
            (8w0xC0 &&& 8w0xF0) : mark_txn_active();
        }
        size = 2;
    }

    /* ================= level 5: the two expiry tables =====================
     * FROM SKELETON. expired <=> the deadline word is ARMED (the low byte of
     * the age is 0x00, which happens only when the stored marker 0x01
     * cancelled the now-word marker with no borrow) AND the 24-bit tick
     * difference is non-negative (bit 31 clear). ONE ternary entry tests both,
     * on the WHOLE 32-bit container. A never-written register reads 0, giving
     * an age whose low byte is 0x01 — so an unarmed deadline can never read as
     * expired. NO NEW BIT-SLICE. */
    action mark_expired_a()     { meta.expired_a = 8w1; }
    action mark_not_expired_a() { meta.expired_a = 8w0; }
    table tbl_expiry_ack {
        key = { meta.age_a : ternary; }
        actions = { mark_expired_a; mark_not_expired_a; }
        const default_action = mark_not_expired_a();
        const entries = {
            (32w0x00000000 &&& 32w0x800000FF) : mark_expired_a();
        }
        size = 2;
    }
    action mark_expired_r()     { meta.expired_r = 8w1; }
    action mark_not_expired_r() { meta.expired_r = 8w0; }
    table tbl_expiry_resp {
        key = { meta.age_r : ternary; }
        actions = { mark_expired_r; mark_not_expired_r; }
        const default_action = mark_not_expired_r();
        const entries = {
            (32w0x00000000 &&& 32w0x800000FF) : mark_expired_r();
        }
        size = 2;
    }

    apply {
        if (meta.src_ok == 8w0) {
            /* Neither dp68 nor dp8. Nothing else is topology for this gate. */
            ctr_evt.count(C_DROP_BAD_PORT);
            ig_dprsr_md.drop_ctl = 3w1;
        } else if (meta.is_dual == 8w0) {
            /* Not 0x88C5 — including the 0xE1 trigger clone, which is meant to
             * be consumed by the packet generator's pattern matcher and must
             * never reach a queue. */
            ctr_evt.count(C_DROP_NON_DUAL);
            ig_dprsr_md.drop_ctl = 3w1;
        } else {
            /* ---------- level 0: packet-derived only ---------- */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            if (hdr.dl.seq == 32w0) { meta.budget_zero = 8w1; }
            tbl_guard.apply();
            if (meta.is_pgen == 8w1) {
                if (hdr.pgen.pipe_app == APP_BLOCK_BYTE) {
                    tbl_blocker_role.apply();
                } else {
                    tbl_event_role.apply();
                }
            }

            /* ---------- level 1 ---------- */
            tbl_build_now.apply();
            tbl_class.apply();

            /* ---------- level 2: tag access + both candidates in parallel -- */
            if (meta.need_tag_read == 8w1) {
                meta.cur_gen  = tag_read.execute(0);
            } else {
                meta.tag_diff = tag_rmw.execute(0);
            }
            tbl_build_cand.apply();

            /* ---------- level 3 ---------- */
            tbl_state_decode.apply();
            tbl_txn_active.apply();

            /* ---------- level 4: both deadlines and the commit state, all in
             * PARALLEL. Each returns its own age / difference; none feeds
             * another. */
            meta.age_a     = d_ack_rmw.execute(0);
            meta.age_r     = d_resp_rmw.execute(0);
            meta.ackc_diff = ackc_rmw.execute(0);

            /* ---------- level 5 ---------- */
            tbl_expiry_ack.apply();
            tbl_expiry_resp.apply();

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- freshly generated on dp68 ----- */
                if (meta.pkt_class == CLASS_ARM) {
                    /* The READ anchors both deadlines (above) and fires the
                     * batch. A duplicate reads tag_diff == 0, writes nothing
                     * and makes NO second burst. */
                    if (meta.arm_fresh == 8w1) {
                        arm_clone();
                        ctr_evt.count(C_ARM_FRESH);
                        meta.ev_read = 8w1;
                    } else {
                        ctr_evt.count(C_ARM_DUP);
                    }
                    ig_dprsr_md.drop_ctl = 3w1;
                } else if (meta.pkt_class == CLASS_BLOCK_NEW) {
                    /* Admit only while a transaction is active; STAMP the
                     * current generation from reg_tag (not from the template),
                     * the held phase and that class's fail-open budget, then
                     * park it on that class's own reservoir queue. */
                    if (meta.txn_active == 8w1) {
                        if (hdr.dl.role == ROLE_ABLOCK) {
                            hdr.dl.phase = PH_HELD;
                            hdr.dl.gen   = meta.cur_gen;
                            hdr.dl.seq   = meta.budget_a;
                            to_ablock();
                            ctr_evt.count(C_ADMIT_ABLOCK);
                        } else {
                            hdr.dl.phase = PH_HELD;
                            hdr.dl.gen   = meta.cur_gen;
                            hdr.dl.seq   = meta.budget_r;
                            to_rblock();
                            ctr_evt.count(C_ADMIT_RBLOCK);
                        }
                    } else {
                        ig_dprsr_md.drop_ctl = 3w1;
                        ctr_evt.count(C_PGEN_NOTXN);
                    }
                } else if (meta.pkt_class == CLASS_ACK_NEW) {
                    if (meta.ack_ok == 8w1) {
                        hdr.dl.phase = PH_HELD;
                        to_ack_q();
                        ctr_evt.count(C_ACK_HELD);
                    } else {
                        ig_dprsr_md.drop_ctl = 3w1;
                        ctr_evt.count(C_ACK_NOTXN);
                    }
                } else if (meta.pkt_class == CLASS_RESP_NEW) {
                    if (meta.resp_ok == 8w1) {
                        hdr.dl.phase = PH_HELD;
                        to_resp();
                        ctr_evt.count(C_RESP_HELD);
                    } else {
                        ig_dprsr_md.drop_ctl = 3w1;
                        ctr_evt.count(C_RESP_NOTXN);
                    }
                } else {
                    ig_dprsr_md.drop_ctl = 3w1;
                    ctr_evt.count(C_FRESH_BAD);
                }
            } else {
                /* ----- back from the dp8 loopback ----- */
                if (meta.pkt_class == CLASS_BLOCK_DEQ) {
                    /* Termination priority stale > deadline > budget, per
                     * class, each class decrementing ITS OWN budget (carried
                     * per token in hdr.dl.seq — no extra register) and
                     * returning to ITS OWN queue. */
                    if (hdr.dl.role == ROLE_ABLOCK) {
                        if (meta.tag_ok == 8w0) {
                            ig_dprsr_md.drop_ctl = 3w1;
                            ctr_evt.count(C_TERM_ABLOCK_STALE);
                            meta.ev_ablock_term = 8w1;
                        } else if (meta.expired_a == 8w1) {
                            ig_dprsr_md.drop_ctl = 3w1;                        /* now >= d_ACK */
                            ctr_evt.count(C_TERM_ABLOCK_DL);
                            meta.ev_ablock_term = 8w1;
                        } else if (meta.budget_zero == 8w1) {
                            ig_dprsr_md.drop_ctl = 3w1;
                            ctr_evt.count(C_TERM_ABLOCK_TMO);
                            meta.ev_ablock_term = 8w1;
                        } else {
                            hdr.dl.seq = hdr.dl.seq - 32w1;
                            to_ablock();
                            ctr_evt.count(C_LOOP_ABLOCK);
                        }
                    } else {
                        if (meta.tag_ok == 8w0) {
                            ig_dprsr_md.drop_ctl = 3w1;
                            ctr_evt.count(C_TERM_RBLOCK_STALE);
                            meta.ev_rblock_term = 8w1;
                        } else if (meta.expired_r == 8w1 && meta.ackc_diff == 8w0) {
                            /* *** the generation-bound gate is TESTED here ***
                             * now >= d_RESP AND the committed generation is
                             * exactly this blocker's own. */
                            ig_dprsr_md.drop_ctl = 3w1;
                            ctr_evt.count(C_TERM_RBLOCK_DL);
                            meta.ev_rblock_term = 8w1;
                        } else if (meta.budget_zero == 8w1) {
                            ig_dprsr_md.drop_ctl = 3w1;
                            ctr_evt.count(C_TERM_RBLOCK_TMO);
                            meta.ev_rblock_term = 8w1;
                        } else {
                            hdr.dl.seq = hdr.dl.seq - 32w1;
                            to_rblock();
                            ctr_evt.count(C_LOOP_RBLOCK);
                        }
                    }
                } else if (meta.pkt_class == CLASS_ACK_DEQ) {
                    /* THE ACK RELEASE. Q_ABLOCK has drained, so Q_ACK is the
                     * highest-priority non-empty queue. The commit write to
                     * reg_ackc_gen already happened at level 4, predicated on
                     * the CLASS, and this branch is the only thing that class
                     * can reach: it unconditionally commits to Q_FINAL and
                     * never re-enqueues, so design §4's conditions 3, 4 and 5
                     * hold STRUCTURALLY rather than by a later runtime test. */
                    hdr.dl.phase = PH_FINAL;
                    to_final();
                    ctr_evt.count(C_ACK_COMMIT);
                    meta.ev_ack_commit = 8w1;
                } else if (meta.pkt_class == CLASS_RESP_DEQ) {
                    hdr.dl.phase = PH_FINAL;
                    to_final();
                    ctr_evt.count(C_RESP_COMMIT);
                    meta.ev_resp_commit = 8w1;
                } else if (meta.pkt_class == CLASS_FINAL) {
                    ig_dprsr_md.drop_ctl = 3w1;
                    ctr_evt.count(C_FINAL_DRAIN);
                    meta.ev_final = 8w1;
                } else {
                    ig_dprsr_md.drop_ctl = 3w1;
                    ctr_evt.count(C_DEQ_BAD);
                }
            }

            /* ================= the eight sparse capture sites ============= */
            if (meta.ev_read        == 8w1) { t_read_w.execute(0);       }
            if (meta.ev_ablock_term == 8w1) { ablock_first_w.execute(0); }
            if (meta.ev_ablock_term == 8w1) { ablock_last_w.execute(0);  }
            if (meta.ev_ack_commit  == 8w1) { ack_commit_w.execute(0);   }
            if (meta.ev_rblock_term == 8w1) { rblock_first_w.execute(0); }
            if (meta.ev_rblock_term == 8w1) { rblock_last_w.execute(0);  }
            if (meta.ev_resp_commit == 8w1) { resp_commit_w.execute(0);  }
            if (meta.ev_final       == 8w1) { final_first_w.execute(0);  }
        }
    }
}

/* ============================ ingress deparser ==========================
 * hdr.pgen is EXTRACTED but never EMITTED, which is how the 6-byte generator
 * header is stripped — the behaviour the SDE's own tna_pktgen example relies
 * on. What is emitted is Ethernet + the dual header, followed by the
 * never-extracted residual of the template, verbatim. The only bytes this
 * program changes are dl.role, dl.phase, dl.gen and dl.seq. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    /* no-arg Mirror() — the typed constructor errors "Inconsistent mirror
     * selectors" on TF1. */
    Mirror() clone_mirror;
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) {
            clone_mirror.emit<recirc_tag_h>(meta.clone_ses, { meta.clone_tag });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.dl);
    }
}

/* ============================ egress ====================================
 * Unreachable by construction and deliberately empty: every frame that
 * reaches the TM carries bypass_egress = 1, and every frame that comes back is
 * either re-enqueued or dropped in ingress. No egress state of any kind
 * exists, so nothing in egress can perturb what is being measured, and every
 * deadline comparison is in ingress as design §5 requires. */
struct eg_meta_t { }

parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}
control Egress(inout headers_t hdr,
               inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}
control EgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    eg_meta_t meta,
                   in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;
