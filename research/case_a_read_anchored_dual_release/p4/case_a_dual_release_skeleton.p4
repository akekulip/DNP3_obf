/* ============================================================================
 * case_a_dual_release_skeleton.p4 — PHASE 0 FINAL GATE of the Case A READ-anchored
 *   dual-release work (design/CASE_A_READ_ANCHORED_DUAL_RELEASE.md §13, "Then compile
 *   an early skeleton: both blocker roles, both absolute deadlines, four queue
 *   assignments, ack_committed_to_master, no detailed telemetry").
 *
 * STARTING POINT: case_a_stripped_baseline.p4 (8 ingress / 0 egress stages, 57 tables,
 *   critical path 8, dependency-bound). That file is UNMODIFIED; this is a copy plus
 *   the dual-release structure. Every construct that differs carries a "DUAL:" comment.
 *
 * PURPOSE: a RESOURCE ANSWER, not a finished program. Does the dual-release mechanism
 *   fit on Tofino-1, and where does it land? Nothing here has been loaded or run.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS ADDS (the six items of the gate)
 *
 * 1. TWO ABSOLUTE DEADLINE REGISTERS, both READ-anchored (design §5):
 *        d_ACK  = t_READ + A     -> reg_d_ack
 *        d_RESP = t_READ + R     -> reg_d_resp
 *    Both are written ONCE, on a fresh READ, from the SAME now-word, so they share one
 *    time representation and neither is an elapsed-interval computation. The deadline
 *    word encoding is UNCHANGED from the baseline: 24 bits of 256 ns ticks in [31:8]
 *    with the ARMED marker in bit 0 of the low byte.
 *
 *    ARM-ONCE IDEMPOTENCY. The baseline had two idempotency devices:
 *      (a) reg_tag generation idempotency — a retransmitted READ reads tag_diff == 0
 *          and therefore makes no second pktgen clone; and
 *      (b) an in-SALU compare-and-arm-once (deadline_arm_once, "write only if the
 *          stored word is still UNARMED_WORD") which made the FIRST qualifying ACK the
 *          arming event.
 *    In the READ-anchored design the arming event is the READ, so (a) IS the arm-once
 *    pattern: tbl_state_decode splits CLASS_ARM by tag_diff and only the fresh arm
 *    supplies a non-sentinel write value. (b) is therefore retired — it cannot be kept,
 *    because the READ would have to disarm and re-arm the same register in one pass.
 *    This is the SAME idempotency guarantee, taken from the register that already
 *    decides freshness, and it costs one register access per deadline instead of two
 *    RegisterActions.
 *
 *    t_READ is kept SEPARATELY in reg_t_read for telemetry/validation only (design §8
 *    readiness measurements are all expressed against it). It is NEVER an operand of
 *    either release comparison — those read only reg_d_ack / reg_d_resp.
 *
 * 2. TWO DEADLINE-EXPIRY TERNARY TABLES, tbl_expiry_ack / tbl_expiry_resp, each with
 *    the proven whole-container mask 0x00000000 &&& 0x800000FF (bit 31 clear AND
 *    armed). NO NEW BIT-SLICE anywhere in this file: the only slice is the baseline's
 *    ig_intr_md.ingress_mac_tstamp[31:0], untouched.
 *
 * 3. TWO BLOCKER ROLES from the pktgen packet_id, classified by a FULL-WIDTH ternary
 *    table on the whole 16-bit container (tbl_blocker_role):
 *        packet_id 0x0000 &&& 0xFFC0 -> ACK blocker      (ids 0..63)
 *        packet_id 0x0040 &&& 0xFFC0 -> response blocker (ids 64..127)
 *        default                     -> DROP
 *    The parser now extracts the 16-bit packet_id out of the 6-byte
 *    pktgen_recirc_header_t instead of advancing over all of it (4 bytes advanced +
 *    2 bytes extracted = the same 48 bits consumed as the baseline). Admission still
 *    requires every existing check: internal pktgen source (dp68 plus the pgen_recirc
 *    value_set on the generated header's first byte, which IS the pipe_id/app_id
 *    check), an active transaction (tbl_pktgen_active over the raw reg_tag read), and
 *    the current generation (stamped from reg_tag at admission, exactly as before).
 *
 * 4. FOUR QUEUE ASSIGNMENTS on the dp8 loopback (design §3):
 *        QID_ABLOCK = 7   ACK-deadline blocker tokens
 *        QID_ACK    = 6   the original pure TCP ACK
 *        QID_RBLOCK = 5   response-deadline blocker tokens
 *        QID_RESP   = 4   the original DNP3 RESPONSE
 *    The baseline's two-queue to_block()/to_resp() become four analogous actions.
 *    STRICT PRIORITY IS CONTROL-PLANE CONFIGURATION (max_priority, design §3) — P4
 *    only selects the qid. Queue ID does not imply priority.
 *
 * 5. ack_committed_to_master (design §4) — reg_ackc, one persistent byte. Set on the
 *    ACK's dp8 release pass; cleared on a fresh READ; read by the response blocker.
 *    It also PREVENTS RE-HOLDING: a fresh ACK is admitted to Q_ACK only while the
 *    state still reads "not committed".
 *
 * 6. BLOCKER TERMINATION per design §10, per class, priority stale > deadline > budget:
 *        ACK blocker      terminates when now >= d_ACK
 *        response blocker terminates when now >= d_RESP AND ack_committed == 1
 *        otherwise each decrements ITS OWN budget and returns to ITS OWN queue
 *    Separate bounded pass budgets per class, carried per token in hdr.ib.seq exactly
 *    as the baseline does — no extra register. The blocker's class rides in the
 *    otherwise-unused hdr.ib.slot byte, stamped at admission.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DEFERRED TO PHASE 4 (deliberately absent — the fit measured here is NOT the
 * fit of the finished program; see the compile report for the stage estimate):
 *   - the exact ACK predicate (design §9.2 items 2, 5, 6, 7, 9, 11): reverse 5-tuple,
 *     the tightened (tcp.flags & 0x3F) == 0x10 mask, tcp.ack_no == EXP_ACK,
 *     tcp.seq == EXP_RELAY_SEQ (the keepalive discriminator), txn_state ==
 *     AWAITING_ACK, and the full one-shot admission latch;
 *   - the exact RESPONSE predicate (design §9.3 items 2, 5, 6, 8, 9);
 *   - the concurrent-transaction, multi-segment, late-ACK / late-RESPONSE and abort
 *     escape counters (design §11 terminal states B..H);
 *   - runtime-parameterized pass budgets (design §10) and all detailed telemetry.
 * Only the minimum counters needed to prove each path is REACHABLE are kept.
 *
 * ---- the stripped baseline's header follows, abridged; read case_a_stripped_baseline.p4
 *      for the full provenance chain of everything that survives ----
 *
 * PROVENANCE: ingress descends from p12_combined.p4 via the frozen inline Defense 2 and
 * the request-triggered pktgen variant; egress is ibspg_dnp3.p4's byte-preserving
 * pass-through (extract only ethernet, re-emit the residual). Preserved verbatim here:
 * request-triggered pktgen (mirror/clone path, value_set, admission), transaction
 * generation and reg_tag idempotency, exact matching, fail-open pass budgets, internal
 * token isolation (0x88C1 forced to ROLE_BLOCK), byte preservation, the empty egress,
 * the write-if-zero timestamp registers, the collapsed indexed counter arrays.
 *
 * SAFETY PROPERTIES (all carried, none weakened):
 *   generation safety    : reg_tag holds the generation; a blocker is tag_ok only on an
 *                          exact match, so only a token of the CURRENT generation loops.
 *   pass-budget fail-open: per-class budget in hdr.ib.seq; exhaustion retires the txn
 *                          (TAG_INACTIVE) and every later token then reads stale.
 *   blocker isolation    : ethertype 0x88C1 is FORCED to ROLE_BLOCK in the parser, so a
 *                          token can only reach to_ablock()/to_rblock() or drop_pkt(),
 *                          never a host port.
 *   byte preservation    : no MAU action reads or writes any byte of any host frame in
 *                          ingress OR egress. The only fields written anywhere are
 *                          hdr.ib.{role,slot,gen,seq} — the internal token's own bytes.
 *
 * NOT CLAIMED: nothing here has been loaded or run. This file answers a compile-fit
 * question only.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK(1) private marker, internal only */
const bit<16> ETHERTYPE_IPV4        = 0x0800;
const bit<8>  IP_PROTO_TCP          = 8w6;

/* ---- DNP3 ---- */
const bit<16> DNP3_START       = 0x0564;   /* link-layer start magic                      */
const bit<8>  DNP3_FC_READ     = 8w1;      /* master -> outstation : arms the transaction */
const bit<8>  DNP3_FC_RESPONSE = 8w129;    /* outstation -> master : the held frame       */

/* ---- roles ---- */
const bit<8> ROLE_BYPASS = 0;  /* forwarded unchanged, never held, never arms         */
const bit<8> ROLE_BLOCK  = 1;  /* 0x88C1 : blocker token, deadline-checking           */
const bit<8> ROLE_RESP   = 2;  /* DNP3 RESPONSE : enqueue Q_RESP; released at d_RESP  */
const bit<8> ROLE_ARM    = 6;  /* DNP3 READ     : takes the tag, anchors BOTH deadlines */
const bit<8> ROLE_ACK    = 7;  /* pure TCP ACK  : DUAL: now HELD on Q_ACK, not fwd'd  */

/* ---- direction ---- */
const bit<8> DIR_MASTER = 0;   /* arrived from the master side (dp9)                  */
const bit<8> DIR_OUT    = 1;   /* outstation side (dp11 / dp64) or the loopback       */

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)           */
const PortId_t PORT_VISION = 9w9;   /* master side (dp9)                                  */
const PortId_t PORT_HULK   = 9w11;  /* outstation side, REPLAY injector (dp11)            */
/* live inline: the physical SEL-751 hangs off front-panel E1/33 = dev_port 64 (pipe 0). */
const PortId_t PORT_RELAY  = 9w64;  /* outstation side, LIVE relay leg (E1/33)            */

/* ---- DUAL: FOUR queues on PORT_L (design §3) ------------------------------
 * Required strict ordering Q_ABLOCK > Q_ACK > Q_RBLOCK > Q_RESP, configured in the
 * CONTROL PLANE via max_priority. QUEUE ID DOES NOT IMPLY PRIORITY — the IBSPG
 * root-cause repair established that min_priority is inert and that leaving
 * max_priority unset degrades silently to a fair split. P4 only selects the qid. */
const bit<5> QID_ABLOCK = 5w7;   /* ACK-deadline blocker reservoir           */
const bit<5> QID_ACK    = 5w6;   /* the original pure TCP ACK, held          */
const bit<5> QID_RBLOCK = 5w5;   /* response-deadline blocker reservoir      */
const bit<5> QID_RESP   = 5w4;   /* the original DNP3 RESPONSE, held         */
/* the ONE normal master-facing FIFO used by every released / forwarded frame
 * (design §4: the released ACK and the released RESPONSE must share one external
 * queue, or the internal ordering can still be lost on the way out). */
const bit<5> QID_NORMAL = 5w0;

/* request-triggered internal packet generator. dp68 (pipe-local port 68, pipe 0) is
 * Tofino-1's packet-generator / recirculation port. BOTH the recirculated tagged clone
 * AND the generated blocker tokens enter ingress on dp68. */
const PortId_t PORT_PGEN = 9w68;

/* I2E mirror used to spawn the recirculating clone. mirror_type is bit<3> on TF1. */
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_CLONE = 1;
const MirrorId_t CLONE_SESSION_ID = 10w7;

/* the 4-byte recirc tag = MARKER(byte0) | gen(low byte); byte 0 = 0xE1 is the
 * distinctive marker the pktgen pattern matcher pins. */
const bit<32> CLONE_TAG_MARKER = 32w0xE1000000;

/* DUAL: the 6-byte pktgen_recirc_header_t (tofino1_base.p4) is
 *   _pad1(3) pipe_id(2) app_id(3) | key(24) | packet_id(16)
 * The baseline advanced over all 48 bits. The dual-release design must read packet_id
 * to split the single 128-token batch into two 64-token classes (design §7), so the
 * first 4 bytes are advanced over and the trailing 16-bit packet_id is extracted.
 * Total consumed is unchanged at 48 bits, and the pipe_id/app_id check is already
 * performed by the pgen_recirc value_set on byte 0. */
const bit<32> PGEN_PREFIX_BITS = 32w32;   /* _pad1 + pipe_id + app_id + key = 4 bytes */

/* DUAL: fail-open pass budgets, SEPARATE PER CLASS (design §10: horizon / measured loop
 * time, horizon ~10x the corresponding deadline; ~10 us per pass at the blocker-queue
 * shaper rate).
 *   ACK  blockers: 10 x A =  30 ms / 10 us =  3 000 passes
 *   RESP blockers: 10 x R = 130 ms / 10 us = 13 000 passes
 * These are the BACKSTOP only — tokens normally terminate on their own deadline
 * (termination priority stale > deadline > budget). Design §10 also asks for these to
 * be runtime parameters; that is DEFERRED to Phase 4 (it would add two 32-bit action
 * data fields to tbl_guard, and no stage). */
const bit<32> BUDGET_ABLOCK = 32w3000;
const bit<32> BUDGET_RBLOCK = 32w13000;

/* ---- packed-state constants ---- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the marker byte */
const bit<32> ARMED_MARK   = 32w0x00000001;  /* bit 0 of the deadline word = armed       */
const bit<32> DL_NO_WRITE  = 32w0;           /* SALU sentinel: leave the deadline be     */
const bit<8>  TAG_INACTIVE = 8w0xFF;         /* explicit "no transaction"                */
const bit<8>  TAG_NO_WRITE = 8w0;            /* SALU sentinel: leave the tag be          */
/* (UNARMED_WORD is gone with deadline_arm_once: in the READ-anchored design the READ
 * writes both deadline words outright, so there is no disarm-then-arm sequence and no
 * unarmed sentinel to compare against. A never-written register reads 0, whose age low
 * byte is 0x01 -> never expired: the same fail-safe the baseline relied on.) */

/* DUAL: ack_committed_to_master, stored as a byte so ONE RegisterAction with ONE PHV
 * operand can express clear / commit / leave-alone. The stored value is 0 (power-on,
 * not committed), ACKC_NO (explicitly cleared by a fresh READ) or ACKC_YES (committed).
 * The SALU returns v - ACKC_YES, so the MAU test is "ackc_diff == 0 <=> committed" — a
 * difference out of the stateful ALU rather than a second compare level. ACKC_NO_WRITE
 * = 0 is the write sentinel, which is why "committed" is encoded as 1 and "not
 * committed" as 2 rather than the other way round. */
const bit<8> ACKC_NO_WRITE = 8w0;   /* SALU sentinel: leave the state be        */
const bit<8> ACKC_YES      = 8w1;   /* stored: ACK committed to the master FIFO */
const bit<8> ACKC_NO       = 8w2;   /* stored: not committed (a fresh READ clears) */

/* DUAL: blocker class, stamped into hdr.ib.slot at admission and read back on every dp8
 * pass. slot is one of the two ibspg_h bytes the baseline kept for injector wire
 * compatibility and never read, so this costs no new header bytes and no register. */
const bit<8> BLK_NONE = 8w0;   /* packet_id outside both ranges -> dropped */
const bit<8> BLK_ACK  = 8w1;
const bit<8> BLK_RESP = 8w2;

/* DUAL: the two READ-anchored offsets, ALREADY EXPRESSED IN DEADLINE-WORD FORM (ticks
 * shifted into [31:8]; the low byte MUST be zero so the ARMED marker survives the add).
 * design §6 first proof-of-mechanism operating point: A = 3 ms, R = 13 ms.
 *   A = 3 ms  -> 0x002DC6 ticks ->  2 999 808 ns (quantization error -192 ns)
 *   R = 13 ms -> 0x00C65D ticks -> 12 999 936 ns (quantization error  -64 ns)
 * The control plane rewrites tbl_guard's default action parameters for an (A, R) sweep
 * with no recompile. */
const bit<32> A_DEFAULT_WORD = 32w0x002DC600;
const bit<32> R_DEFAULT_WORD = 32w0x00C65D00;

/* ---- packet classes (drive the one decode table) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;   /* DNP3 READ from the master                  */
const bit<8> CLASS_ACK       = 8w2;   /* fresh pure TCP ACK from the outstation     */
const bit<8> CLASS_BLOCK_DEQ = 8w3;   /* blocker token back from the loopback       */
const bit<8> CLASS_ACK_DEQ   = 8w4;   /* DUAL: released held ACK back from loopback */

/* ---- indexed-counter slots (COMPILE-TIME CONSTANTS ONLY) ==================
 * Stats-ALU occupancy is charged per (counter OBJECT, stage) pair, so the validation
 * counters live in two Counter arrays. Every packet touches ctr_fresh at most once and
 * ctr_deq at most once (bf-p4c hard-errors on non-mutually-exclusive count() sites on
 * one Counter object). */
/* ctr_fresh — sites on the FRESH (non-dequeued) path, plus the bad-port drop */
const bit<8> CF_BYPASS_FWD   = 8w0;   /* ROLE_BYPASS forwarded                          */
const bit<8> CF_BAD_PORT     = 8w1;   /* dropped, bad ingress port                      */
const bit<8> CF_ARM_FRESH    = 8w2;   /* fresh READ: anchored both deadlines, cloned    */
const bit<8> CF_ARM_DUP      = 8w3;   /* retransmitted READ: no re-anchor, no clone     */
const bit<8> CF_ACK_HELD     = 8w4;   /* DUAL: qualifying ACK -> Q_ACK                  */
const bit<8> CF_ACK_BYPASS   = 8w5;   /* non-qualifying / already-committed ACK -> fwd  */
const bit<8> CF_RESP_ENQ     = 8w6;   /* RESPONSE -> Q_RESP                             */
const bit<8> CF_BLOCK_ENQ    = 8w7;   /* host-injected token (A/B rollback path)        */
const bit<8> CF_ADMIT_ABLOCK = 8w8;   /* DUAL: token, packet_id   0..63  -> Q_ABLOCK    */
const bit<8> CF_ADMIT_RBLOCK = 8w9;   /* DUAL: token, packet_id  64..127 -> Q_RBLOCK    */
const bit<8> CF_PKTGEN_DROP  = 8w10;  /* token with no active transaction               */
const bit<8> CF_PKTGEN_BADID = 8w11;  /* DUAL: token whose packet_id matched no class   */
/* ctr_deq — sites on the DEQUEUED (dp8 loopback) path */
const bit<8> CD_LOOP_ABLOCK      = 8w0;  /* DUAL: ACK blocker re-enqueued to Q_ABLOCK  */
const bit<8> CD_LOOP_RBLOCK      = 8w1;  /* DUAL: resp blocker re-enqueued to Q_RBLOCK */
const bit<8> CD_TERM_STALE       = 8w2;  /* either class, stale generation             */
const bit<8> CD_TERM_ABLOCK_DL   = 8w3;  /* DUAL: ACK blocker terminated at d_ACK      */
const bit<8> CD_TERM_RBLOCK_DL   = 8w4;  /* DUAL: resp blocker terminated at d_RESP    */
const bit<8> CD_TERM_ABLOCK_TMO  = 8w5;  /* DUAL: ACK  budget expired (fail-open)      */
const bit<8> CD_TERM_RBLOCK_TMO  = 8w6;  /* DUAL: RESP budget expired (fail-open)      */
const bit<8> CD_ACK_COMMIT       = 8w7;  /* DUAL: held ACK committed to the master FIFO */
const bit<8> CD_RELEASE_DEADLINE = 8w8;  /* RESPONSE released on the deadline          */
const bit<8> CD_RELEASE_FAILOPEN = 8w9;  /* RESPONSE released early (budget fail-open) */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* the 4-byte recirc tag prepended onto the MIRROR (clone) copy only. */
header recirc_tag_h { bit<32> tag; }

/* DUAL: the trailing 16 bits of pktgen_recirc_header_t. Extracted (not advanced over)
 * so the blocker role can be classified from packet_id; consumed and never emitted, so
 * the frame that reaches the loopback is byte-for-byte what the baseline produced. */
header pgen_id_h { bit<16> packet_id; }

/* internal blocker token. seq = per-class pass budget, gen = transaction generation.
 * DUAL: slot now carries the blocker CLASS (BLK_ACK / BLK_RESP). role is kept for wire
 * compatibility with the Part 9/11/12 injector but is NOT read — an 0x88C1 frame is
 * FORCED to ROLE_BLOCK in the parser. */
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

header ipv4_h {
    bit<4>  version; bit<4>  ihl;      bit<8>  diffserv;    bit<16> total_len;
    bit<16> identification; bit<3> flags; bit<13> frag_offset;
    bit<8>  ttl;     bit<8>  protocol; bit<16> hdr_checksum;
    bit<32> src_addr; bit<32> dst_addr;
}

header tcp_h {
    bit<16> src_port; bit<16> dst_port; bit<32> seq_no; bit<32> ack_no;
    bit<4>  data_offset; bit<4> res; bit<8> flags;
    bit<16> window; bit<16> checksum; bit<16> urgent_ptr;
}

/* TCP options carried verbatim; one fixed-size header per data_offset. NEVER read. */
header tcp_opt4_h  { bit<32> data; }
header tcp_opt8_h  { bit<64> data; }
header tcp_opt12_h { bit<96> data; }

header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }
header dnp3_app_h { bit<8> app_control; bit<8> func_code; }

struct headers_t {
    ethernet_h  eth;
    pgen_id_h   pgen_id;      /* DUAL: consumed on the dp68 path, never emitted */
    ibspg_h     ib;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt4_h  tcp_opt4;
    tcp_opt8_h  tcp_opt8;
    tcp_opt12_h tcp_opt12;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

struct ig_meta_t {
    /* ---- piece 1: parser-computed classification ---- */
    bit<8>  role;
    bit<8>  dir;
    bit<9>  fwd_port;
    bit<8>  port_ok;
    bit<8>  gen_in;
    bit<8>  dequeued;

    bit<32> ts32;          /* full-resolution ns, for the timestamp bank only      */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 as dequeued (fail-open watchdog) */

    /* ---- piece 2: packed transaction state ---- */
    /* level 0 — packet-derived */
    bit<32> ts_m;          /* ts32 & TICK_MASK                                     */
    bit<32> a_word;        /* DUAL: A offset in deadline-word form (tbl_guard)     */
    bit<32> r_word;        /* DUAL: R offset in deadline-word form (tbl_guard)     */

    /* level 1 */
    bit<32> now_word;      /* ts_m | ARMED_MARK — the deadline-aligned "now"       */
    bit<8>  pkt_class;
    bit<8>  tag_val;       /* PHV input 2 of reg_tag: 0 = do not write             */

    /* level 2 */
    bit<32> dl_cand_a;     /* DUAL: now_word + A = the d_ACK  word for this READ   */
    bit<32> dl_cand_r;     /* DUAL: now_word + R = the d_RESP word for this READ   */
    bit<8>  tag_diff;      /* SALU result: gen_in - stored_tag                     */

    /* level 3 */
    bit<32> dl_val_a;      /* PHV input 2 of reg_d_ack  : 0 = do not write         */
    bit<32> dl_val_r;      /* PHV input 2 of reg_d_resp : 0 = do not write         */
    bit<8>  ackc_w;        /* DUAL: PHV input of reg_ackc: 0 = do not write        */
    bit<8>  arm_fresh;     /* DUAL: 1 = this READ advanced the generation          */
    bit<8>  tag_ok;        /* 1 = state is live AND is this generation             */
    bit<8>  ack_ok;        /* 1 = this ACK qualified for the hold                  */
    bit<8>  blk_class;     /* DUAL: BLK_ACK / BLK_RESP from tbl_blocker_role       */

    /* level 4 */
    bit<32> age_a;         /* DUAL: now_word - d_ACK,  straight out of the SALU    */
    bit<32> age_r;         /* DUAL: now_word - d_RESP, straight out of the SALU    */
    bit<8>  ackc_diff;     /* DUAL: reg_ackc - ACKC_YES; 0 <=> committed           */

    /* level 5 */
    bit<8>  expired_a;     /* DUAL: 1 = d_ACK  armed AND due                       */
    bit<8>  expired_r;     /* DUAL: 1 = d_RESP armed AND due                       */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;
    bit<8>  ev_ack_hold;
    bit<8>  ev_block_term;

    /* ---- request-triggered pktgen fields ---- */
    bit<8>     is_pktgen;    /* 1 = admitted from the pktgen source (dp68)                */
    bit<8>     cur_gen;      /* reg_tag raw read: the CURRENT stored generation byte      */
    bit<8>     txn_active;   /* 1 = a transaction is active (cur_gen is a 0xCn generation)*/
    bit<32>    clone_tag;    /* the 4-byte recirc tag placed on the mirror clone          */
    MirrorId_t clone_ses;    /* the mirror session id for the clone (dp68 via $mirror.cfg)*/
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    /* the control plane loads this with the generated packets' leading byte, =
     * pktgen_recirc_header_t byte0 = 000 ++ pipe_id(2) ++ app_id(3). This IS the
     * pipe / app_id admission check of design §7. */
    value_set<bit<8>>(1) pgen_recirc;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* role, dir, fwd_port, port_ok, gen_in, dequeued and is_pktgen are deliberately
         * NOT initialized here: Tofino's parser has no clear-on-write, so assigning a
         * field in `start` and again on the same path later is a hard compile error.
         * Every default is the all-zero encoding the compiler's own metadata init
         * supplies (ROLE_BYPASS = 0, DIR_MASTER = 0, port_ok = 0, ...). */
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.ts_m            = 32w0;
        meta.a_word          = 32w0;
        meta.r_word          = 32w0;
        meta.now_word        = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.tag_val         = TAG_NO_WRITE;
        meta.dl_cand_a       = 32w0;
        meta.dl_cand_r       = 32w0;
        meta.tag_diff        = 8w0;
        meta.dl_val_a        = DL_NO_WRITE;
        meta.dl_val_r        = DL_NO_WRITE;
        meta.ackc_w          = ACKC_NO_WRITE;
        meta.arm_fresh       = 8w0;
        meta.tag_ok          = 8w0;
        meta.ack_ok          = 8w0;
        meta.blk_class       = BLK_NONE;
        meta.age_a           = 32w0;
        meta.age_r           = 32w0;
        meta.ackc_diff       = 8w0;
        meta.expired_a       = 8w0;
        meta.expired_r       = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_ack_hold     = 8w0;
        meta.ev_block_term   = 8w0;
        meta.cur_gen         = 8w0;
        meta.txn_active      = 8w0;
        meta.clone_tag       = 32w0;
        meta.clone_ses       = 10w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_L      : from_loopback;
            PORT_HULK   : from_outstation;
            PORT_RELAY  : from_outstation;
            PORT_VISION : from_master;
            PORT_PGEN   : from_pgen;   /* dp68 = generated tokens + recirc clones */
            default     : accept;      /* port_ok stays 0 -> dropped in the MAU   */
        }
    }

    /* the loopback carries outstation-origin frames (the held ACK, the held RESPONSE)
     * and blocker tokens, so its direction is the outstation side and its transparent
     * forward target is the master. */
    state from_loopback   { meta.dequeued = 8w1; meta.dir = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_outstation { meta.dir      = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_master     { meta.dir      = DIR_MASTER; meta.fwd_port = PORT_RELAY;
                            meta.port_ok  = 8w1; transition parse_eth; }

    /* dp68 carries exactly two things — a generated blocker token (leads with the
     * 6-byte pktgen_recirc header, first byte in pgen_recirc) or a recirculated tagged
     * clone (leads with the 0xE1 marker). The token is admitted; anything else falls
     * through with port_ok = 0 and is dropped in the MAU. */
    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_recirc : parse_pktgen_token;
            default     : accept;      /* recirc clone / junk -> port_ok 0 -> dropped */
        }
    }
    /* DUAL: advance over _pad1/pipe_id/app_id/key (4 B, already validated by the
     * value_set) and EXTRACT the trailing 16-bit packet_id, which tbl_blocker_role
     * splits into the two blocker classes. 32 advanced + 16 extracted = the same 48
     * bits the baseline advanced over, so the frame handed to parse_eth is identical. */
    state parse_pktgen_token {
        meta.is_pktgen = 8w1;
        meta.port_ok   = 8w1;
        meta.dir       = DIR_OUT;
        meta.fwd_port  = PORT_VISION;
        pkt.advance(PGEN_PREFIX_BITS);
        pkt.extract(hdr.pgen_id);
        transition parse_eth;
    }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_TOKEN : parse_token;
            ETHERTYPE_IPV4        : parse_ipv4;
            default               : accept;    /* ARP / IPv6 / ... -> ROLE_BYPASS */
        }
    }

    /* 0x88C1 is internal and can only ever be a blocker token: the role is FORCED here,
     * so no injected frame can talk its way onto a host port. */
    state parse_token {
        pkt.extract(hdr.ib);
        meta.role   = ROLE_BLOCK;
        meta.gen_in = hdr.ib.gen;
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;   /* TCP with no IP options only */
            default             : accept;
        }
    }

    /* GATE 1 — TCP payload length, range-matched HERE because the TNA parser cannot
     * compute and matching total_len in a downstream state ICEs.
     * NOTE: the pure-ACK flags mask stays at the baseline's 0x17. Design §9.2 tightens
     * it to 0x3F together with the seq/ack predicates — DEFERRED to Phase 4 as one
     * coherent change. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x10 &&& 8w0x17, 4w5,  16w40) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w6,  16w44) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w7,  16w48) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w8,  16w52) : set_role_ack;   /* Linux TS — the corpus case */
            (8w0x10 &&& 8w0x17, 4w9,  16w56) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w10, 16w60) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w11, 16w64) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w12, 16w68) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w13, 16w72) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w14, 16w76) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w15, 16w80) : set_role_ack;
            (8w0x00 &&& 8w0x07, 4w5,  16w53 .. 16w65535) : parse_dnp3_dl;
            (8w0x00 &&& 8w0x07, 4w6,  16w57 .. 16w65535) : opt4;
            (8w0x00 &&& 8w0x07, 4w7,  16w61 .. 16w65535) : opt8;
            (8w0x00 &&& 8w0x07, 4w8,  16w65 .. 16w65535) : opt12;
            default                                      : accept;
        }
    }

    state opt4  { pkt.extract(hdr.tcp_opt4);  transition parse_dnp3_dl; }
    state opt8  { pkt.extract(hdr.tcp_opt8);  transition parse_dnp3_dl; }
    state opt12 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }

    state set_role_ack { meta.role = ROLE_ACK; transition accept; }

    /* GATE 2 — DNP3 link LEN. LEN == 5 is a well-formed LINK-ONLY frame: valid,
     * forwarded transparently. Transport(1) + application(2) need LEN >= 8. */
    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start, hdr.dnp3_dl.length) {
            (DNP3_START, 8w8 .. 8w255) : parse_dnp3_tp;
            default                    : accept;   /* LINK_OTHER or not DNP3 */
        }
    }

    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }

    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        meta.gen_in = hdr.dnp3_app.app_control;
        /* the ARM leaf requires app_control == 0xCn (FIR = FIN = 1, CON = UNS = 0),
         * which makes the tag domain provably {0x00, 0xC0..0xCF, 0xFF}: never the SALU
         * no-write sentinel 0x00, never TAG_INACTIVE 0xFF. */
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            default                               : accept;  /* DIRECT_OPERATE etc. */
        }
    }
    state set_role_resp { meta.role = ROLE_RESP; transition accept; }
    state set_role_arm  { meta.role = ROLE_ARM;  transition accept; }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ================= state register 1: the TAG ==========================
     * Packs generation and "active" into one byte. The SALU returns the DIFFERENCE
     * against this frame's generation, so the comparison happens inside the stateful
     * ALU: tag_diff == 0 <=> a transaction is active AND it is this generation.
     * PHV inputs: meta.gen_in, meta.tag_val — exactly 2. UNCHANGED. */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };
    /* raw read of the stored generation for an admitted pktgen token; mutually
     * exclusive with tag_rmw per packet (one SALU access). UNCHANGED. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_read = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
        }
    };

    /* ================= DUAL: state registers 2 and 3 — the TWO DEADLINES ===
     * 24 bits of 256 ns ticks in [31:8]; bit 0 is the ARMED MARKER. Each SALU returns
     * the age of ITS OWN deadline directly, so there is no separate "age = now -
     * deadline" MAU level and no separate armed test. PHV inputs per register:
     * meta.now_word plus its own write field — exactly 2 each.
     *
     * Both are written ONCE per transaction, on the fresh READ (design §5), from the
     * same now_word, so d_ACK and d_RESP are two absolute instants on one clock. A
     * retransmitted READ supplies DL_NO_WRITE and cannot move either deadline — the
     * arm-once idempotency, taken from reg_tag (see the file header).
     *
     * The two registers are INDEPENDENT and are read in PARALLEL: reg_d_resp is not
     * derived from reg_d_ack, so the second deadline adds width to the pipeline, not
     * depth to the dependency chain. */
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

    /* ================= DUAL: state register 4 — ack_committed_to_master ====
     * design §4. ONE RegisterAction, ONE PHV operand, one access per packet:
     *   fresh READ        -> ackc_w = ACKC_NO       (clear: a new transaction)
     *   released held ACK -> ackc_w = ACKC_YES      (commit)
     *   everything else   -> ackc_w = ACKC_NO_WRITE (read-only)
     * The SALU returns v - ACKC_YES so the MAU test is a single equality against zero
     * (ackc_diff == 0 <=> committed) rather than a second compare level.
     *
     * WHY IT IS SOUND TO SET THE STATE AT THIS LEVEL rather than after the forwarding
     * decision: the write is predicated on pkt_class == CLASS_ACK_DEQ, which is
     * (dequeued == 1 AND role == ROLE_ACK) — both parser-derived. For that class the
     * dequeued branch of the ACT block UNCONDITIONALLY calls to_fwd(), which assigns
     * PORT_VISION (fwd_port from `from_loopback`) and QID_NORMAL, and never re-enqueues
     * to the loopback. So conditions 3, 4 and 5 of design §4 are guaranteed
     * STRUCTURALLY by the class, not by a later runtime branch. Deferring the write
     * until after the ACT block would cost two stages and prove nothing extra. */
    Register<bit<8>, bit<1>>(1, 0) reg_ackc;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_ackc) ackc_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v - ACKC_YES;
            if (meta.ackc_w != ACKC_NO_WRITE) { v = meta.ackc_w; }
        }
    };

    /* ================= fixed-slot timestamp registers =====================
     * SPARSE latency capture, write-if-zero = first occurrence. Do NOT cut these to
     * chase a stage count (design §13): the ACK is held and the relay leg is
     * untappable, so on-chip registers are the only possible measurement of the hold. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_hold;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_hold) ts_ack_hold_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_resp_release) ts_first_resp_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    /* DUAL: t_READ, kept SEPARATELY (design §5 / §8). It is the anchor every readiness
     * measurement is expressed against (t_first_ABLOCK_admitted - t_READ, ...). It is
     * write-only from the data plane and is NEVER an operand of either release
     * comparison — those read reg_d_ack / reg_d_resp only. Unlike the four registers
     * above, this one must track the CURRENT transaction, so it is a plain write under
     * the fresh-READ predicate, not write-if-zero. */
    Register<bit<32>, bit<1>>(1, 0) reg_t_read;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_t_read) t_read_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };

    /* ================= counters (Stats ALU) ===============================
     * Two indexed Counter arrays; every index is a compile-time constant and every
     * object is touched AT MOST ONCE per packet on any path. */
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) ctr_fresh;  /* CF_* slots */
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) ctr_deq;    /* CD_* slots */

    /* ================= DUAL: TM actions — FOUR queues =====================
     * design §3. Priorities are control-plane configuration (max_priority); P4 only
     * selects the queue. bypass_egress = 1 on every held / parked frame, so nothing on
     * the loopback traverses egress. */
    action to_ablock() {                      /* ACK-deadline blocker      -> qid 7 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ABLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_ack_q() {                       /* the original pure ACK     -> qid 6 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ACK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_rblock() {                      /* response-deadline blocker -> qid 5 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RBLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {                        /* the original RESPONSE     -> qid 4 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* transparent forward to this frame's peer port on the ONE normal master-facing
     * FIFO (design §4): the released ACK, the released RESPONSE, the forwarded READ and
     * all bypass traffic. bypass_egress = 0, so these — and only these — traverse
     * egress (a byte-preserving pass-through). */
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = QID_NORMAL;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* request one I2E mirror (the clone) to dp68 and build the 4-byte recirc tag =
     * MARKER | gen. Touches only the mirror copy. Called ONLY on the fresh-ARM path. */
    action arm_clone() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.gen_in;
    }

    /* ================= DUAL: the two READ-anchored offsets ================
     * ONE table, two action parameters — the control plane rewrites the default action
     * for an (A, R) sweep with no recompile. Both are already in deadline-word form
     * (ticks in [31:8], low byte zero) so the ARMED marker survives the addition. */
    action set_guard(bit<32> a_word, bit<32> r_word) {
        meta.a_word = a_word;
        meta.r_word = r_word;
    }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(A_DEFAULT_WORD, R_DEFAULT_WORD);
        size = 1;
    }

    /* ---- level 1: build the deadline-aligned "now" ----
     * Must be an explicit table rather than a plain statement beside the level-0
     * assignments: bf-p4c merges consecutive unconditional statements into ONE action
     * and then rejects the intra-action dependency with "action spanning multiple
     * stages" (measured on 9.13.1). */
    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    /* ---- level 2: DUAL: BOTH candidate deadline words for a fresh READ ----
     * Two INDEPENDENT adds off the same now_word (no intra-action dependency, so they
     * co-locate in one action and one stage). The low byte of each addend is zero, so
     * the ARMED marker survives and the tick fields add. */
    action build_cand() {
        meta.dl_cand_a = meta.now_word + meta.a_word;
        meta.dl_cand_r = meta.now_word + meta.r_word;
    }
    table tbl_build_cand {
        actions = { build_cand; }
        const default_action = build_cand();
        size = 1;
    }

    /* ================= the ONE decode table ==============================
     * One lookup on the packet class and the tag difference replaces the gen-mismatch
     * compare level, the active-clear driver level and the qualify / deadline-driver
     * level. The match unit reads the whole container under a TCAM mask — nothing is
     * sliced.
     *
     *   ARM    : tag_diff == 0 <=> a RETRANSMITTED READ (the generation did not move),
     *                              so it writes NOTHING and cannot re-anchor either
     *                              deadline. Any other tag_diff is a FRESH READ, which
     *                              anchors d_ACK and d_RESP and clears the commit
     *                              state. Entry order IS priority, so the exact-zero
     *                              reject pattern precedes the accept-any pattern.
     *   ACK    : tag_diff NOT IN {0x00, 0x01} <=> a transaction is live.
     *   BLOCK  : tag_diff == 0                <=> active AND my generation.
     *   ACK_DEQ: unconditional — the released held ACK commits to the master FIFO. */
    action dec_arm_fresh() {                       /* DUAL: READ anchors BOTH deadlines */
        meta.dl_val_a  = meta.dl_cand_a;
        meta.dl_val_r  = meta.dl_cand_r;
        meta.ackc_w    = ACKC_NO;                  /* new transaction: not committed    */
        meta.arm_fresh = 8w1;
    }
    action dec_arm_dup() {                         /* DUAL: retransmitted READ: no-op   */
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_NO_WRITE;
    }
    action dec_ack_hold() {                        /* DUAL: ACK qualified for the hold  */
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_NO_WRITE;
        meta.ack_ok   = 8w1;
    }
    action dec_ack_commit() {                      /* DUAL: released ACK -> committed   */
        meta.dl_val_a = DL_NO_WRITE;
        meta.dl_val_r = DL_NO_WRITE;
        meta.ackc_w   = ACKC_YES;
    }
    action dec_live() {                            /* live blocker of my generation     */
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
        actions = { dec_arm_fresh; dec_arm_dup; dec_ack_hold; dec_ack_commit;
                    dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0x00 &&& 8w0xFF) : dec_arm_dup();    /* retransmit: no re-anchor */
            (CLASS_ARM,       8w0x00 &&& 8w0x00) : dec_arm_fresh();  /* fresh: anchor A and R    */
            (CLASS_ACK,       8w0x00 &&& 8w0xFE) : dec_none();       /* no live transaction      */
            (CLASS_ACK,       8w0x00 &&& 8w0x00) : dec_ack_hold();   /* live: qualified          */
            (CLASS_ACK_DEQ,   8w0x00 &&& 8w0x00) : dec_ack_commit(); /* DUAL: commit the ACK     */
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live();       /* my generation, live      */
        }
        size = 8;
    }

    /* ================= pktgen token active check =========================
     * A pktgen token is admitted only while a transaction is live. reg_tag's raw value
     * is provably in {0x00, 0xC0..0xCF, 0xFF}; "active" == it is a 0xCn generation.
     * A masked-equality ternary on the whole container — not a magnitude compare. */
    action mark_txn_active()   { meta.txn_active = 8w1; }
    action mark_txn_inactive() { meta.txn_active = 8w0; }
    table tbl_pktgen_active {
        key = { meta.cur_gen : ternary; }
        actions = { mark_txn_active; mark_txn_inactive; }
        const default_action = mark_txn_inactive();
        const entries = {
            (8w0xC0 &&& 8w0xF0) : mark_txn_active();   /* generation 0xCn => active */
        }
        size = 2;
    }

    /* ================= DUAL: blocker role from packet_id =================
     * design §7. One recirculation-triggered application, ONE batch of 128 tokens, so
     * packet_id is unique across the whole burst (batch_id is unidentifiable and
     * packet_id restarts per batch — see evidence/phase0/pktgen_batch_limits.md).
     *
     * FULL-WIDTH TERNARY on the whole 16-bit container. Branching on packet_id[6] in P4
     * would be a bit-slice and would hit the gateway-complexity trap (a slice in a
     * gateway condition gives "condition expression too complex") — design §5.2.
     *
     * Applied under the parser-derived is_pktgen gate so the DEFAULT ACTION CAN DROP:
     * an unclassifiable generated packet is killed at the classification table rather
     * than reaching the admission branch. */
    action set_ack_blocker()  { meta.blk_class = BLK_ACK;  }
    action set_resp_blocker() { meta.blk_class = BLK_RESP; }
    action set_blk_drop()     { meta.blk_class = BLK_NONE; ig_dprsr_md.drop_ctl = 3w1; }
    table tbl_blocker_role {
        key = { hdr.pgen_id.packet_id : ternary; }
        actions = { set_ack_blocker; set_resp_blocker; set_blk_drop; }
        const default_action = set_blk_drop();
        const entries = {
            (16w0x0000 &&& 16w0xFFC0) : set_ack_blocker();   /* packet_id   0.. 63 */
            (16w0x0040 &&& 16w0xFFC0) : set_resp_blocker();  /* packet_id  64..127 */
        }
        size = 4;
    }

    /* ================= DUAL: TWO deadline-expiry tables ==================
     * expired <=> the deadline word is ARMED (the low byte of the age is 0x00, which
     * happens only when the stored marker 0x01 cancelled the now-word marker with no
     * borrow) AND the 24-bit tick difference is non-negative (bit 31 clear). ONE
     * ternary entry tests both, on the WHOLE 32-bit container. A never-written register
     * reads 0, giving an age whose low byte is 0x01 — so an unarmed deadline can never
     * read as expired. Design §5.2: two such tables, one per deadline, NO NEW SLICE. */
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
        if (meta.port_ok == 8w0) {
            /* isolate the pipeline: only dp8 / dp9 / dp11 / dp64 / dp68 are topology */
            ctr_fresh.count(CF_BAD_PORT);
            drop_pkt();
        } else {
            /* ---------- level 0: packet-derived only ---------- */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            /* hdr.ib is valid ONLY on blocker tokens; budget_zero has exactly two
             * consumers per class and all of them sit inside a ROLE_BLOCK branch. Do
             * not read it outside one. */
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }  /* isolated 32b compare */
            tbl_guard.apply();                                   /* the A and R offsets  */
            /* DUAL: classify the generated token's blocker role. Guarded on the
             * parser-derived is_pktgen so the table's default action can drop. */
            if (meta.is_pktgen == 8w1) { tbl_blocker_role.apply(); }

            /* ---------- level 1: now-word, class, tag write driver ---------- */
            tbl_build_now.apply();
            if (meta.dequeued == 8w0) {
                if (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                    meta.pkt_class = CLASS_ARM;
                    meta.tag_val   = meta.gen_in;      /* ARM takes ownership; 0xCn by gate */
                } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                    meta.pkt_class = CLASS_ACK;
                }
            } else if (meta.role == ROLE_BLOCK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
                if (meta.budget_zero == 8w1) {
                    meta.tag_val = TAG_INACTIVE;       /* fail-open: retire the txn */
                }
            } else if (meta.role == ROLE_ACK) {
                /* DUAL: the held ACK on its dp8 release pass. Both conjuncts are
                 * parser-derived, so this class is settled at level 1. */
                meta.pkt_class = CLASS_ACK_DEQ;
            }

            /* ---------- level 2: tag access (+ both deadline candidates in parallel) */
            if (meta.is_pktgen == 8w1) {
                meta.cur_gen  = tag_read.execute(0);
            } else {
                meta.tag_diff = tag_rmw.execute(0);
            }
            tbl_build_cand.apply();

            /* ---------- level 3: one decode for stale / qualify / anchor ---------- */
            tbl_state_decode.apply();
            tbl_pktgen_active.apply();

            /* ---------- level 4: DUAL: both deadlines and the commit state, all in
             * PARALLEL. Each returns its own age / difference; none feeds another. */
            meta.age_a     = d_ack_rmw.execute(0);
            meta.age_r     = d_resp_rmw.execute(0);
            meta.ackc_diff = ackc_rmw.execute(0);
            if (meta.arm_fresh == 8w1) { t_read_w.execute(0); }   /* telemetry only */

            /* ---------- level 5: expiry, one table per deadline ---------- */
            tbl_expiry_ack.apply();
            tbl_expiry_resp.apply();

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from a host port (or the pktgen source dp68) ----- */
                if (meta.role == ROLE_BLOCK) {
                    if (meta.is_pktgen == 8w1) {
                        /* PKTGEN admission: admit only while a transaction is active;
                         * STAMP the current generation, the blocker CLASS and that
                         * class's fail-open budget, then enqueue to that class's own
                         * reservoir queue. Stamping the generation from reg_tag (not
                         * from the template) means a token generated a hair after a new
                         * READ still gets the live generation, and a stale-generation
                         * token self-terminates on its first loop. to_ablock() and
                         * to_rblock() are the ONLY egresses a token can reach. */
                        if (meta.txn_active == 8w1) {
                            if (meta.blk_class == BLK_ACK) {
                                hdr.ib.role = ROLE_BLOCK;
                                hdr.ib.slot = BLK_ACK;           /* the class rides the token */
                                hdr.ib.gen  = meta.cur_gen;
                                hdr.ib.seq  = BUDGET_ABLOCK;
                                to_ablock();
                                ctr_fresh.count(CF_ADMIT_ABLOCK);
                                meta.ev_first_block = 8w1;
                            } else if (meta.blk_class == BLK_RESP) {
                                hdr.ib.role = ROLE_BLOCK;
                                hdr.ib.slot = BLK_RESP;
                                hdr.ib.gen  = meta.cur_gen;
                                hdr.ib.seq  = BUDGET_RBLOCK;
                                to_rblock();
                                ctr_fresh.count(CF_ADMIT_RBLOCK);
                            } else {
                                drop_pkt();   /* already dropped by the classifier default */
                                ctr_fresh.count(CF_PKTGEN_BADID);
                            }
                        } else {
                            drop_pkt();                          /* no active transaction */
                            ctr_fresh.count(CF_PKTGEN_DROP);
                        }
                    } else {
                        /* host-injected token (kept for A/B rollback). It carries its
                         * own class byte from the injector; anything not explicitly
                         * marked as a response blocker joins the ACK reservoir. */
                        if (hdr.ib.slot == BLK_RESP) {
                            to_rblock();
                        } else {
                            hdr.ib.slot = BLK_ACK;
                            to_ablock();
                        }
                        ctr_fresh.count(CF_BLOCK_ENQ);
                        meta.ev_first_block = 8w1;
                    }
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    to_resp();                        /* held on Q_RESP (qid 4) */
                    ctr_fresh.count(CF_RESP_ENQ);
                } else if (meta.role == ROLE_ACK) {
                    /* DUAL: the ACK is now HELD on Q_ACK (qid 6) instead of being
                     * forwarded immediately. It is admitted only while a transaction is
                     * live (ack_ok) AND the commit state still reads "not committed"
                     * (ackc_diff != 0) — the latter is the minimal one-shot that
                     * PREVENTS RE-HOLDING. Anything else is forwarded transparently, so
                     * a keepalive or a duplicate can never be captured. */
                    if (meta.ack_ok == 8w1 && meta.ackc_diff != 8w0) {
                        to_ack_q();
                        ctr_fresh.count(CF_ACK_HELD);
                        meta.ev_ack_hold = 8w1;
                    } else {
                        to_fwd();
                        ctr_fresh.count(CF_ACK_BYPASS);
                    }
                } else if (meta.role == ROLE_ARM) {
                    /* a real DNP3 READ: it took the tag and anchored both deadlines
                     * above, and must reach the outstation, so it is forwarded
                     * byte-identically (the clone is a separate mirror copy). */
                    to_fwd();
                    /* spawn the trigger clone ONLY on a FRESH arm: a retransmitted READ
                     * reads tag_diff == 0 and makes NO second burst. */
                    if (meta.tag_diff != 8w0) {
                        arm_clone();
                        ctr_fresh.count(CF_ARM_FRESH);
                    } else {
                        ctr_fresh.count(CF_ARM_DUP);
                    }
                } else {
                    to_fwd();                         /* ROLE_BYPASS: transparent */
                    ctr_fresh.count(CF_BYPASS_FWD);
                }
            } else {
                /* ----- DEQUEUED (looped back from dp8) ----- */
                if (meta.role == ROLE_BLOCK) {
                    /* DUAL: design §10, PER CLASS, with the termination priority
                     * stale > deadline > budget preserved inside each class. The class
                     * rides in hdr.ib.slot, stamped at admission; each class decrements
                     * ITS OWN budget (hdr.ib.seq, carried per token — no extra
                     * register) and returns to ITS OWN queue. */
                    if (meta.tag_ok == 8w0) {
                        drop_pkt();
                        ctr_deq.count(CD_TERM_STALE);
                        meta.ev_block_term = 8w1;
                    } else if (hdr.ib.slot == BLK_ACK) {
                        if (meta.expired_a == 8w1) {
                            drop_pkt();                       /* now >= d_ACK */
                            ctr_deq.count(CD_TERM_ABLOCK_DL);
                            meta.ev_block_term = 8w1;
                        } else if (meta.budget_zero == 8w1) {
                            drop_pkt();
                            ctr_deq.count(CD_TERM_ABLOCK_TMO);
                            meta.ev_block_term = 8w1;
                        } else {
                            hdr.ib.seq = hdr.ib.seq - 32w1;
                            to_ablock();
                            ctr_deq.count(CD_LOOP_ABLOCK);
                        }
                    } else {
                        /* RESPONSE blocker: terminates ONLY when the response deadline
                         * has passed AND the ACK has been committed to the master FIFO
                         * (design §4 / §10). ackc_diff == 0 <=> committed. */
                        if (meta.expired_r == 8w1 && meta.ackc_diff == 8w0) {
                            drop_pkt();
                            ctr_deq.count(CD_TERM_RBLOCK_DL);
                            meta.ev_block_term = 8w1;
                        } else if (meta.budget_zero == 8w1) {
                            drop_pkt();
                            ctr_deq.count(CD_TERM_RBLOCK_TMO);
                            meta.ev_block_term = 8w1;
                        } else {
                            hdr.ib.seq = hdr.ib.seq - 32w1;
                            to_rblock();
                            ctr_deq.count(CD_LOOP_RBLOCK);
                        }
                    }
                } else if (meta.role == ROLE_ACK) {
                    /* DUAL: the released held ACK. to_fwd() assigns PORT_VISION (from
                     * `from_loopback`) and QID_NORMAL — the same external FIFO the
                     * RESPONSE will later use — and never re-enqueues, which is what
                     * makes the ack_committed_to_master write at level 4 sound. */
                    to_fwd();
                    ctr_deq.count(CD_ACK_COMMIT);
                } else if (meta.role == ROLE_RESP) {
                    /* RELEASED RESPONSE: forwarded to the master byte-identically, on
                     * the same QID_NORMAL FIFO the ACK already entered. The release
                     * cause is attributed by the response deadline state at dequeue.
                     * ctr_resp_release == ctr_deq[CD_RELEASE_DEADLINE]
                     *                   + ctr_deq[CD_RELEASE_FAILOPEN]. */
                    to_fwd();
                    if (meta.expired_r == 8w1) { ctr_deq.count(CD_RELEASE_DEADLINE); }
                    else                       { ctr_deq.count(CD_RELEASE_FAILOPEN); }
                } else {
                    drop_pkt();   /* nothing else may loop back */
                }
            }

            /* ================= SPARSE latency capture (single call site each) ===
             * PREDICATE FLOAT (measured on the baseline): only ts_first_resp_w has a
             * predicate expressible in PARSER-produced fields, so only it floats to an
             * early stage. The other three each carry a conjunct derived from a
             * register or a match table and cannot be floated without changing which
             * event is timestamped. */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_hold     == 8w1) { ts_ack_hold_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.dequeued == 8w1 && meta.role == ROLE_RESP) { ts_first_resp_w.execute(0); }
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emission order == extraction order, so every forwarded frame is byte-identical.
 * DUAL: hdr.pgen_id is deliberately NOT emitted — the 6-byte pktgen header is consumed
 * exactly as the baseline's advance(48) consumed it, so the token that reaches the
 * loopback is the same eth + ibspg frame as before. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    /* no-arg Mirror() (the typed ctor errors "Inconsistent mirror selectors" on TF1). */
    Mirror() clone_mirror;
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) {
            clone_mirror.emit<recirc_tag_h>(meta.clone_ses, { meta.clone_tag });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt4);
        pkt.emit(hdr.tcp_opt8);
        pkt.emit(hdr.tcp_opt12);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/* ============================ egress ====================================
 * BYTE-PRESERVING PASS-THROUGH, VERBATIM from the baseline. The released ACK, the
 * forwarded READ, the released RESPONSE and all bypass traffic traverse egress
 * (bypass_egress = 0); egress extracts only ethernet, so everything after it is
 * residual and re-emitted verbatim. NO EGRESS STATE OF ANY KIND — design §17 forbids
 * load-bearing egress registers, and every deadline comparison is in ingress. */
struct eg_meta_t { }

parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
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
    apply {
        pkt.emit(hdr.eth);
    }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;
