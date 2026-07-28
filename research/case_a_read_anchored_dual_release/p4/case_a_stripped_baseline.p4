/* ============================================================================
 * case_a_stripped_baseline.p4 — PHASE 0 GATE 2 (stage reclamation) of the Case A
 *   READ-anchored dual-release work. This is a PURE DELETION / REFACTOR pass over
 *   research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4 (frozen, untouched).
 *   NO dual-release logic is added here: no second deadline, no second blocker class,
 *   no four queues. That is the NEXT gate.
 *
 * WHAT WAS REMOVED (the obsolete G-SELECTION GUARD — the new READ-anchored design
 * never branches on it; the compiler's own allocation showed ingress stage 9 was 100%
 * these objects):
 *   - Register reg_native_clrt  + RegisterAction native_clrt_w
 *   - Register reg_protection   + RegisterAction protection_w
 *   - Register reg_t_ack        + RegisterActions t_ack_reset / t_ack_capture / t_ack_read
 *   - table tbl_clrt_guard      + actions mark_held / mark_zero_hold
 *   - table tbl_build_clrt_diff + action build_clrt_diff
 *   - Counters ctr_response_actually_held, ctr_response_at_or_after_deadline,
 *              ctr_response_before_deadline, ctr_response_zero_hold
 *   - metadata fields is_fresh_resp, native_clrt, clrt_diff, protection (all became
 *     unused once the above went)
 *   - the whole "G-selection guard" section at the tail of the ingress apply block
 *
 * WHAT WAS COLLAPSED (the Stats-ALU lever). Stats-ALU occupancy is charged per
 * (counter OBJECT, stage) pair, not per object, so five consecutive stages sat at
 * 4/4 Stats ALU purely to host 16 single-entry counters. The surviving counters are
 * collapsed into TWO indexed Counter arrays addressed with COMPILE-TIME-CONSTANT
 * indices — the idiom the baseline already used for ctr_bypass.count(8w0/8w1).
 *
 *   old counter name                    -> (array, index)          constant
 *   ------------------------------------------------------------------------------
 *   ctr_bypass[0]  (ROLE_BYPASS fwd)    -> ctr_fresh[0]            CF_BYPASS_FWD
 *   ctr_bypass[1]  (bad ingress port)   -> ctr_fresh[1]            CF_BAD_PORT
 *   ctr_arm_clone  (fresh READ+clone)   -> ctr_fresh[2]            CF_ARM_FRESH
 *   (new split)    (retransmitted READ) -> ctr_fresh[3]            CF_ARM_DUP
 *   ctr_arm        (all READs fwd)      -> ctr_fresh[2] + ctr_fresh[3]  (sum)
 *   ctr_ack_arm                         -> ctr_fresh[4]            CF_ACK_ARM
 *   ctr_ack_bypass                      -> ctr_fresh[5]            CF_ACK_BYPASS
 *   ctr_resp_enq                        -> ctr_fresh[6]            CF_RESP_ENQ
 *   ctr_block_enq  (host-injected tok)  -> ctr_fresh[7]            CF_BLOCK_ENQ
 *   ctr_pktgen_admit                    -> ctr_fresh[8]            CF_PKTGEN_ADMIT
 *   ctr_pktgen_drop                     -> ctr_fresh[9]            CF_PKTGEN_DROP
 *   ctr_block_loop                      -> ctr_deq[0]              CD_BLOCK_LOOP
 *   ctr_block_term_stale                -> ctr_deq[1]              CD_BLOCK_TERM_STALE
 *   ctr_block_term_deadline             -> ctr_deq[2]              CD_BLOCK_TERM_DL
 *   ctr_block_term_timeout              -> ctr_deq[3]              CD_BLOCK_TERM_TMO
 *   ctr_release_deadline                -> ctr_deq[4]              CD_RELEASE_DEADLINE
 *   ctr_release_fail_open               -> ctr_deq[5]              CD_RELEASE_FAILOPEN
 *   ctr_resp_release (all releases)     -> ctr_deq[4] + ctr_deq[5] (sum)
 *
 *   TWO counters became a mutually-exclusive PARTITION rather than a total plus a
 *   subset, so that no packet ever touches the same Counter object twice (one Stats
 *   ALU access per counter per packet). Both originals are exactly recoverable by
 *   addition, so no semantic meaning is lost:
 *       ctr_arm          == ctr_fresh[2] + ctr_fresh[3]
 *       ctr_resp_release == ctr_deq[4]   + ctr_deq[5]
 *
 *   ctr_fresh[1] is counted at the top-of-apply bad-port branch and the rest of
 *   ctr_fresh deep in the ACT block, so ctr_fresh is allocated in two stages exactly
 *   as the baseline's ctr_bypass already was. That is the baseline's own proven
 *   idiom, not a new construction.
 *
 * WHAT WAS PRESERVED (verbatim, load-bearing): request-triggered pktgen (mirror/clone
 * path, value_set, admission), transaction generation and reg_tag idempotency, exact
 * matching, queue selection, fail-open (pass budget + termination priority
 * stale > deadline > budget), the deadline comparison and tbl_deadline_expiry,
 * cleanup, token isolation (ROLE_BLOCK forcing -> only to_block()/drop_pkt()), byte
 * preservation, the empty egress, the four write-if-zero timestamp registers, and the
 * lightweight validation counters. The deadline word encoding and the 256 ns
 * quantization are UNCHANGED. NO new bit-slice was introduced; the one existing slice
 * (ig_intr_md.ingress_mac_tstamp[31:0]) is untouched.
 *
 * ---- the original file header follows, verbatim except where the removed G-guard
 *      is described; read it for the provenance of everything that survives ----
 *
 * dnp3_timing_normalizer_pktgen.p4 — REQUEST-TRIGGERED INTERNAL PKTGEN variant of
 *   the frozen inline Defense 2 (dnp3_timing_normalizer_inline / dcrn_defense2).
 *
 *   PURPOSE: replace host-seeded (Vision AF_PACKET) blocker-token injection with an
 *   in-switch Tofino-1 packet-generator burst. A fresh, eligible master-side DNP3
 *   Class-0 READ triggers exactly ONE pktgen batch of K=64 blocker tokens (0x88C1).
 *   The proven HOLD (ACK -> t_ack, deadline = t_ack + G, RESPONSE held on Q_RESP
 *   behind the Q_BLOCK reservoir, deadline / fail-open release) is UNCHANGED.
 *
 * BUILD AND LOAD STATUS:
 *   COMPILE-FIT ONLY. This file began as a verbatim copy of the frozen inline
 *   Defense 2 and adds the request-triggered pktgen path. Every line that differs
 *   from that baseline is marked "PKTGEN:" in a comment. NOTHING here has been
 *   loaded or run; this answers a local bf-p4c 9.13.1 compile-fit question only.
 *   The frozen inline binary and its provenance chain are UNTOUCHED (dcrn_defense2.p4
 *   and dnp3_timing_normalizer_inline remain the loaded/frozen artifacts).
 *
 * FOUR FORWARDING INVARIANTS (by construction; grep "PKTGEN:" for each site):
 *   (1) The original READ is forwarded byte-identically to PORT_RELAY (dp64): the
 *       ROLE_ARM branch calls to_fwd() (ucast=dp64, bypass_egress=0); the ingress
 *       deparser emits the original headers in extraction order; clone_mirror.emit
 *       shapes ONLY the mirror copy, never the main copy.
 *   (2) One tagged clone is emitted to dp68 ONLY on the fresh-ARM path (the one that
 *       advances the generation in reg_tag): the ROLE_ARM branch gates arm_clone()
 *       on (meta.tag_diff != 0), reusing the baseline reg_tag idempotency so a
 *       retransmitted READ makes NO second clone/trigger. arm_clone() sets an I2E
 *       mirror to session CLONE_SESSION_ID and the ingress deparser prepends a
 *       4-byte recirc tag via clone_mirror.emit -> 0 egress stages.
 *   (3) A pktgen-generated token (parsed on dp68 via value_set pgen_recirc, role
 *       forced ROLE_BLOCK) has the CURRENT generation + fail-open budget stamped on
 *       admission (reg_tag raw read tag_read + tbl_pktgen_active) and is enqueued to
 *       dp8/Q_BLOCK via the baseline to_block(); a token with NO active transaction
 *       is dropped.
 *   (4) A token is NEVER forwarded to dp9/dp11/dp64: role is forced ROLE_BLOCK in the
 *       parser and every ROLE_BLOCK branch reaches only to_block() or drop_pkt(); the
 *       recirculated clone re-entering on dp68 is dropped (port_ok = 0 in from_pgen).
 *
 * ---- the following describes the FROZEN BASE logic (carried over; the "VERBATIM"
 *      claims below mean "verbatim base plus the additive PKTGEN: changes marked
 *      inline") ----
 *
 * PROVENANCE (nothing here is invented):
 *   - INGRESS is p12_combined.p4's ingress, VERBATIM: parser DNP3 classification,
 *     packed transaction state (reg_tag = generation+active, armed-bit in the low
 *     byte of reg_deadline), HOLD_RESPONSE deadline logic, blocker reservoir,
 *     pass-budget fail-open, internal-token isolation (0x88C1 forced to ROLE_BLOCK),
 *     data_offset 5-15 classification. The timing mechanism is UNCHANGED except for one
 *     deliberate correctness fix (finding B-D1): the deadline and its shadow t_ack are
 *     now armed/captured on the FIRST qualifying ACK and are idempotent to duplicate
 *     ACKs (see reg_deadline / reg_t_ack below). No other behavior changes.
 *   - EGRESS is ibspg_dnp3.p4's egress, VERBATIM: a byte-preserving pass-through
 *     (extract only ethernet; the rest is residual and re-emitted automatically), so
 *     a released ACK or RESPONSE (bypass_egress=0) egresses byte-identical.
 *   - The G-SELECTION GUARD was the only new logic there, and it was ADDITIVE to the
 *     ingress. STRIPPED IN THIS FILE (see the removal list above); because it never
 *     changed any existing register, table, action, gateway, counter or metadata field
 *     of the timing mechanism, removing it cannot change the timing mechanism either.
 *
 * WHAT WAS REMOVED vs p12_combined.p4 (all EGRESS-only, out of scope this week and a
 * corruption hazard):
 *   - the pay.. and pad.. payload-chunk headers and the eg_headers_t that held them,
 *   - the EgParser payload-chunking + total_len select,
 *   - the size_norm table and its 14 pad_* actions,
 *   - ctr_size_normalized / ctr_size_failopen and the meta.normalized logic,
 *   - the pad emission in EgDeparser.
 *   None of these touched any ingress construct, so removing them cannot change the
 *   ingress stage count; it only shrinks the egress.
 *
 * THE G-SELECTION GUARD IS GONE. It measured native_clrt = t_response_arrival - t_ack
 * in a shadow register (reg_t_ack), compared it against G through a second sign-bit
 * ternary (tbl_build_clrt_diff -> tbl_clrt_guard), stored the verdict in
 * reg_native_clrt / reg_protection and counted it in four ctr_response_* counters. The
 * READ-anchored dual-release design never branches on any of that: its deadlines are
 * computed from t_READ, not from t_ack, so "was the native CLRT below G" is not a
 * question the new mechanism asks. All of it is deleted here.
 *
 * RELEASE-CAUSE COUNTERS ARE KEPT (they are correctness telemetry, not G-selection).
 * At the response-release site (the dequeued ROLE_RESP branch) the release cause is
 * attributed by the already-computed meta.expired of the dequeued response: expired =>
 * the reservoir drained on the deadline; not expired => it drained early on its pass
 * budget (fail-open). In this file the two causes are ctr_deq[CD_RELEASE_DEADLINE] and
 * ctr_deq[CD_RELEASE_FAILOPEN], and their sum is the old ctr_resp_release. The
 * per-blocker ctr_block_term_* view (K increments per drain) is likewise kept, as
 * ctr_deq[1..3].
 *
 * SAFETY PROPERTIES — each one, and where it lives in this file (all carried from
 * p12_combined UNCHANGED by the guard):
 *   generation safety      : reg_tag holds the generation; the blocker decode entry
 *                            (CLASS_BLOCK_DEQ, 0x00 &&& 0xFF) fires only on an exact
 *                            tag match, so only a token of the CURRENT generation is
 *                            ever tag_ok. The ACK path keeps out of this (JOIN B).
 *   pass-budget fail-open  : meta.budget_zero -> TAG_INACTIVE at the tag write and
 *                            ctr_block_term_timeout at the act; every later token then
 *                            reads a stale tag and terminates.
 *   blocker isolation      : ethertype 0x88C1 is FORCED to ROLE_BLOCK in the parser,
 *                            so a token can only reach to_block() or drop_pkt(), never
 *                            a host port.
 *   byte preservation      : no MAU action reads or writes any byte of any host frame
 *                            in ingress OR egress. The single field written anywhere
 *                            is hdr.ib.seq, the internal token's own pass counter.
 *                            Ingress emits in extraction order; egress extracts only
 *                            ethernet and re-emits the rest as residual.
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
const bit<8> ROLE_BYPASS = 0;  /* forwarded unchanged, never held, never arms        */
const bit<8> ROLE_BLOCK  = 1;  /* 0x88C1 : enqueue Q_BLOCK (qid7); deadline-checking  */
const bit<8> ROLE_RESP   = 2;  /* DNP3 RESPONSE : enqueue Q_RESP (qid1); released     */
const bit<8> ROLE_ARM    = 6;  /* DNP3 READ     : takes the tag, clears the deadline  */
const bit<8> ROLE_ACK    = 7;  /* pure TCP ACK  : forwarded NOW; arms the deadline    */

/* ---- direction ---- */
const bit<8> DIR_MASTER = 0;   /* arrived from the master side (dp9)                  */
const bit<8> DIR_OUT    = 1;   /* arrived from the outstation side (dp11) or loopback */

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)           */
const PortId_t PORT_VISION = 9w9;   /* master side (dp9)                                  */
const PortId_t PORT_HULK   = 9w11;  /* outstation side, REPLAY injector (dp11)            */
/* live inline: the physical SEL-751 hangs off front-panel E1/33 = dev_port 64, reached
 * through an unmanaged switch whose only other active port is the relay's 100M RJ45.
 * Measured to link at BF_SPEED_1G / FEC none / AN force-disable. dev_port 64 is pipe 0
 * (64 < 128), so the dp8 loopback blocker ring is unaffected. */
const PortId_t PORT_RELAY  = 9w64;  /* outstation side, LIVE relay leg (E1/33)            */

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH (max_priority=7) : blocker reservoir   */
const bit<5> QID_RESP  = 5w1;   /* LOW  (max_priority=0) : response held queue */

/* PKTGEN: request-triggered internal packet generator.
 * dp68 (pipe-local port 68, pipe 0) is Tofino-1's packet-generator / recirculation
 * port. BOTH the recirculated tagged clone AND the generated blocker tokens enter
 * ingress on dp68; no ordinary host traffic ever arrives here. */
const PortId_t PORT_PGEN = 9w68;

/* PKTGEN: I2E mirror used to spawn the recirculating clone. mirror_type is bit<3> on
 * Tofino-1 (matches the SDE tna_mirror example). Value 0 = no mirror; CLONE = 1. */
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_CLONE = 1;

/* PKTGEN: mirror session id that the control plane binds to egress dp68 ($mirror.cfg).
 * Held in a metadata field (never passed to mirror.emit as a literal — bf-p4c rejects a
 * constant session selector). */
const MirrorId_t CLONE_SESSION_ID = 10w7;

/* PKTGEN: the 4-byte recirc tag = MARKER(byte0) | gen(low byte). The pktgen pattern
 * matcher fires on the first 32 bits of the recirculated clone; the 24-bit key it copies
 * into each generated packet is bytes 1..3 (tag[23:0]) — so the generation rides in the
 * key's low byte. Byte 0 (0xE1) is the distinctive marker: distinct from any DNP3/host
 * leading byte and from the generated packets' own pktgen-header first byte (0x00..0x07),
 * so generated packets can never re-trigger the app. Control-plane pattern_value/mask pin
 * byte 0 == 0xE1. */
const bit<32> CLONE_TAG_MARKER = 32w0xE1000000;

/* PKTGEN: 6-byte pktgen_recirc_header_t (tofino1_base.p4) prefix on every generated packet;
 * skipped with advance() in the parser (we re-stamp gen from reg_tag, so its 24-bit key is
 * not needed here). 6 bytes = 48 bits. */
const bit<32> PGEN_HDR_BITS = 32w48;

/* PKTGEN: fail-open pass budget stamped into a freshly admitted token's hdr.ib.seq. This is
 * the BACKSTOP only — tokens normally terminate on the deadline (t_ack + G), which dominates
 * (termination priority stale > deadline > budget). Must exceed G / per-pass-time so it does
 * not drain before the deadline; control-plane / measurement tunable. ~100k passes ~= 1 s at
 * the ~10 us/pass Q_BLOCK shaper rate. */
const bit<32> INITIAL_BUDGET = 32w100000;

/* ---- packed-state constants (piece 2) ---- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the marker byte */
const bit<32> ARMED_MARK   = 32w0x00000001;  /* bit 0 of the deadline word = armed       */
const bit<32> UNARMED_WORD = 32w0x00000002;  /* explicit "armed nothing" (marker clear)  */
const bit<32> DL_NO_WRITE  = 32w0;           /* SALU sentinel: leave the deadline be     */
const bit<8>  TAG_INACTIVE = 8w0xFF;         /* explicit "no transaction"                */
const bit<8>  TAG_NO_WRITE = 8w0;            /* SALU sentinel: leave the tag be          */

/* Guard interval G, ALREADY EXPRESSED IN 256 ns TICKS (low byte MUST be zero — see
 * JOIN C). 0x017D7800 = 24 999 936 ns = 25 ms rounded down to one tick, which sits
 * above the SEL-751 corpus CLRT p95 of 16.5 ms (median 12.9 ms). The control plane
 * rewrites tbl_guard's default action parameter for a G sweep — no recompile. */
const bit<32> G_DEFAULT_TICKS = 32w0x017D7800;

/* ---- packet classes (drive the one decode table) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;   /* fresh DNP3 READ from the master     */
const bit<8> CLASS_ACK       = 8w2;   /* fresh pure TCP ACK from outstation  */
const bit<8> CLASS_BLOCK_DEQ = 8w3;   /* blocker token back from loopback    */

/* ---- indexed-counter slots (COMPILE-TIME CONSTANTS ONLY) ==================
 * Stats-ALU occupancy is charged per (counter OBJECT, stage) pair, so the surviving
 * validation counters are collapsed into two Counter arrays. Every index below is a
 * compile-time constant, exactly like the baseline's ctr_bypass.count(8w0/8w1), so
 * no index is ever computed in the MAU. Old-name mapping: see the file header. */
/* ctr_fresh — sites on the FRESH (non-dequeued) path, plus the bad-port drop */
const bit<8> CF_BYPASS_FWD   = 8w0;   /* was ctr_bypass[0]     : ROLE_BYPASS forwarded */
const bit<8> CF_BAD_PORT     = 8w1;   /* was ctr_bypass[1]     : dropped, bad port     */
const bit<8> CF_ARM_FRESH    = 8w2;   /* was ctr_arm_clone     : fresh READ, cloned    */
const bit<8> CF_ARM_DUP      = 8w3;   /* (partition of ctr_arm): retransmitted READ    */
const bit<8> CF_ACK_ARM      = 8w4;   /* was ctr_ack_arm       : qualifying ACK        */
const bit<8> CF_ACK_BYPASS   = 8w5;   /* was ctr_ack_bypass    : non-qualifying ACK    */
const bit<8> CF_RESP_ENQ     = 8w6;   /* was ctr_resp_enq      : RESPONSE -> Q_RESP    */
const bit<8> CF_BLOCK_ENQ    = 8w7;   /* was ctr_block_enq     : host-injected token   */
const bit<8> CF_PKTGEN_ADMIT = 8w8;   /* was ctr_pktgen_admit  : token -> Q_BLOCK      */
const bit<8> CF_PKTGEN_DROP  = 8w9;   /* was ctr_pktgen_drop   : token, no active txn  */
/* ctr_deq — sites on the DEQUEUED (dp8 loopback) path */
const bit<8> CD_BLOCK_LOOP       = 8w0; /* was ctr_block_loop                          */
const bit<8> CD_BLOCK_TERM_STALE = 8w1; /* was ctr_block_term_stale                    */
const bit<8> CD_BLOCK_TERM_DL    = 8w2; /* was ctr_block_term_deadline                 */
const bit<8> CD_BLOCK_TERM_TMO   = 8w3; /* was ctr_block_term_timeout                  */
const bit<8> CD_RELEASE_DEADLINE = 8w4; /* was ctr_release_deadline                    */
const bit<8> CD_RELEASE_FAILOPEN = 8w5; /* was ctr_release_fail_open                   */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* PKTGEN: the 4-byte recirc tag prepended onto the mirror (clone) copy by
 * clone_mirror.emit at the ingress deparser. It is emitted ONLY on the mirror copy, so
 * it never appears in headers_t and never touches the byte-identical main forward copy.
 * The pktgen recirc trigger matches its 32 bits. */
header recirc_tag_h { bit<32> tag; }

/* internal blocker token: seq = pass budget, gen = transaction generation.
 * role/slot are kept for wire compatibility with the Part 9/11/12 injector but are
 * NOT read — an 0x88C1 frame is FORCED to ROLE_BLOCK in the parser. */
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

/* TCP options carried verbatim; one fixed-size header per data_offset (the TNA
 * parser cannot advance by a runtime amount). NEVER read in the MAU. */
header tcp_opt4_h  { bit<32> data; }
header tcp_opt8_h  { bit<64> data; }
header tcp_opt12_h { bit<96> data; }

/* DNP3 data-link header, 10 B. `start` is the two magic bytes as ONE 16-bit field so
 * the magic and the LEN gate fit one 16-bit + one 8-bit parser match register in a
 * single select. */
header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }                      /* transport header, 1 B */
header dnp3_app_h { bit<8> app_control; bit<8> func_code; } /* classification only   */

struct headers_t {
    ethernet_h  eth;
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
    bit<8>  role;          /* ROLE_*                                              */
    bit<8>  dir;           /* DIR_MASTER / DIR_OUT                                */
    bit<9>  fwd_port;      /* transparent-forward peer port for this ingress port */
    bit<8>  port_ok;       /* 1 if the ingress port is dp8 / dp9 / dp11           */
    bit<8>  gen_in;        /* generation carried by this frame (PHV input 1 of reg_tag) */
    bit<8>  dequeued;      /* 1 if ingress_port == PORT_L                         */

    bit<32> ts32;          /* full-resolution ns, for the timestamp bank only     */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 as dequeued (fail-open watchdog)*/

    /* ---- piece 2: packed transaction state ---- */
    /* level 0 — packet-derived */
    bit<32> ts_m;          /* ts32 & TICK_MASK                                    */
    bit<32> seq_m;         /* G in ticks, from tbl_guard (low byte zero)          */

    /* level 1 */
    bit<32> now_word;      /* ts_m | ARMED_MARK — the deadline-aligned "now"      */
    bit<8>  pkt_class;
    bit<8>  tag_val;       /* PHV input 2 of reg_tag: 0 = do not write            */

    /* level 2 */
    bit<32> dl_cand;       /* now_word + seq_m = the armed word for this ACK      */
    bit<8>  tag_diff;      /* SALU result: gen_in - stored_tag                    */

    /* level 3 */
    bit<32> dl_val;        /* PHV input 2 of reg_deadline: 0 = do not write       */
    bit<8>  tag_ok;        /* 1 = state is live AND is this generation            */
    bit<8>  ack_ok;        /* 1 = this ACK qualified and armed the deadline       */

    /* level 4 */
    bit<32> age;           /* now_word - deadline_word, straight out of the SALU  */
    bit<8>  expired;       /* 1 = armed AND due                                   */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;
    bit<8>  ev_ack_arm;
    bit<8>  ev_block_term;   /* (ev_resp_release deleted: its predicate is now parser-derived) */

    /* (REMOVED: is_fresh_resp / native_clrt / clrt_diff / protection — the four
     * G-selection-guard scratch fields. They became unused with the guard.) */

    /* ---- PKTGEN: request-triggered pktgen fields ---- (all bit<8> per constraint class 3;
     * clone_ses/clone_tag are control/deparser fields, NOT parser-path-assigned, so they are
     * safely zero-init in `start`. is_pktgen is assigned ONCE on the parser pktgen path and is
     * therefore left uninitialized in `start` — it defaults to 0 on every other path, exactly
     * like role/dir/port_ok/dequeued.) */
    bit<8>     is_pktgen;    /* 1 = admitted from the pktgen source (dp68)                */
    bit<8>     cur_gen;      /* reg_tag raw read: the CURRENT stored generation byte      */
    bit<8>     txn_active;   /* 1 = a transaction is active (cur_gen is a 0xCn generation)*/
    bit<32>    clone_tag;    /* the 4-byte recirc tag placed on the mirror clone          */
    MirrorId_t clone_ses;    /* the mirror session id for the clone (dp68 via $mirror.cfg)*/
}

/* ============================ ingress parser =============================
 * PIECE 1, carried over VERBATIM from p12_combined. Every role decision is taken
 * here; the MAU sees only meta.role / meta.dir / meta.dequeued / meta.fwd_port /
 * meta.port_ok / meta.gen_in. */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    /* PKTGEN: the control plane loads this with the generated packets' leading byte,
     * = pktgen_recirc_header_t byte0 = 000 ++ pipe_id(2) ++ app_id(3) (0x00..0x07 for
     * pipe 0). Only consulted for dp68 packets, so a collision with a host MAC's first
     * octet is impossible (host traffic never reaches from_pgen). */
    value_set<bit<8>>(1) pgen_recirc;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* NOTE — role, dir, fwd_port, port_ok, gen_in and dequeued are deliberately
         * NOT initialized here. Tofino's parser has no clear-on-write: assigning a
         * field in `start` and again in a later state on the same path is a hard
         * compile error. Each is assigned exactly ONCE per path and every default is
         * the all-zero encoding the compiler's own metadata init supplies:
         * ROLE_BYPASS=0, DIR_MASTER=0, port_ok=0, gen_in=0, dequeued=0. fwd_port is
         * written on every path that sets port_ok=1, and a frame from any other port
         * is dropped before it is read. */
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.ts_m            = 32w0;
        meta.seq_m           = 32w0;
        meta.now_word        = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.tag_val         = TAG_NO_WRITE;
        meta.dl_cand         = 32w0;
        meta.tag_diff        = 8w0;
        meta.dl_val          = DL_NO_WRITE;
        meta.tag_ok          = 8w0;
        meta.ack_ok          = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_ack_arm      = 8w0;
        meta.ev_block_term   = 8w0;
        /* PKTGEN: control/deparser fields — safe to zero-init here (not parser-path-assigned).
         * is_pktgen is deliberately NOT initialized (assigned once on the pktgen path). */
        meta.cur_gen         = 8w0;
        meta.txn_active      = 8w0;
        meta.clone_tag       = 32w0;
        meta.clone_ses       = 10w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_L      : from_loopback;
            PORT_HULK   : from_outstation;
            PORT_RELAY  : from_outstation;
            PORT_VISION : from_master;
            PORT_PGEN   : from_pgen;   /* PKTGEN: dp68 = generated tokens + recirc clones */
            default     : accept;      /* port_ok stays 0 -> dropped in the MAU */
        }
    }

    /* the loopback carries only outstation-origin frames (held responses) and
     * blocker tokens, so its direction is the outstation side and its transparent
     * forward target is the master. */
    state from_loopback   { meta.dequeued = 8w1; meta.dir = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_outstation { meta.dir      = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_master     { meta.dir      = DIR_MASTER; meta.fwd_port = PORT_RELAY;
                            meta.port_ok  = 8w1; transition parse_eth; }

    /* PKTGEN: dp68 carries exactly two things — a generated blocker token (leads with the
     * 6-byte pktgen_recirc header, first byte in pgen_recirc) or a recirculated tagged clone
     * (leads with the 0xE1 marker). The token is admitted; anything else (the clone, or junk)
     * falls through with port_ok = 0 and is dropped in the MAU (invariant 4: the clone is
     * never forwarded, and the recirc trigger already fired in HW before this pass). */
    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_recirc : parse_pktgen_token;
            default     : accept;      /* recirc clone / junk -> port_ok 0 -> dropped */
        }
    }
    /* PKTGEN: a generated blocker token. Skip the 6-byte pktgen header (we re-stamp gen from
     * reg_tag on admission, so its 24-bit key is not read), mark it admissible + pktgen-sourced,
     * then fall into the SHARED parse_eth path: etype 0x88C1 -> parse_token FORCES role = BLOCK
     * (invariant 4). dir/fwd_port are set but never read on the token path (it only ever
     * to_block()s). Each field is assigned once on this path (no parser write-once violation). */
    state parse_pktgen_token {
        meta.is_pktgen = 8w1;
        meta.port_ok   = 8w1;
        meta.dir       = DIR_OUT;
        meta.fwd_port  = PORT_VISION;
        pkt.advance(PGEN_HDR_BITS);
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

    /* 0x88C1 is internal and can only ever be a blocker token: the role is FORCED
     * here, so no injected frame can talk its way onto a host port. */
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

    /* GATE 1 — TCP payload length. Range-matched HERE (total_len live-range = one
     * state) because the TNA parser cannot compute, and matching total_len in a
     * downstream state ICEs.
     *   pure ACK      : total_len == 20 + 4*data_offset, ACK=1, SYN=FIN=RST=0
     *   DNP3-capable  : total_len >= 20 + 4*data_offset + 13, SYN=FIN=RST=0
     * Anything else falls through to `accept` and is forwarded as ROLE_BYPASS. */
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

    /* GATE 2 — DNP3 link LEN. LEN counts ctrl+dst+src+user data, so LEN == 5 is a
     * well-formed LINK-ONLY frame: valid, forwarded transparently, never dropped.
     * Transport(1) + application(2) need LEN >= 8. */
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
        /* the DNP3 application control byte (FIR/FIN/CON/UNS + the 4-bit application
         * sequence, which increments per poll) is this transaction's generation. */
        meta.gen_in = hdr.dnp3_app.app_control;
        /* JOIN B: the ARM leaf additionally requires app_control == 0xCn, i.e.
         * FIR = FIN = 1 and CON = UNS = 0 — which IEEE 1815 mandates for a request,
         * requests being single-fragment. This costs nothing (the select already
         * holds both bytes) and it is what makes the tag domain provably
         * {0x00, 0xC0..0xCF, 0xFF}: never the SALU no-write sentinel 0x00, never
         * TAG_INACTIVE 0xFF. A READ outside that range simply does not arm and is
         * forwarded as ROLE_BYPASS. */
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

    /* ================= state register 1 of 2: the TAG =====================
     * Packs generation and "active" into one byte. The SALU returns the DIFFERENCE
     * against this frame's generation, so the comparison happens inside the stateful
     * ALU:  tag_diff == 0  <=>  a transaction is active AND it is this generation.
     * PHV inputs: meta.gen_in, meta.tag_val — exactly 2. */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };
    /* PKTGEN: raw read of the stored generation for an admitted pktgen token. Returns v
     * unconditionally (no in-SALU sentinel branch -> no constraint class 8), adds 0 PHV
     * inputs (reg_tag still references only gen_in + tag_val across all its actions, within
     * the 2-input SALU budget), and is mutually exclusive with tag_rmw per packet (one SALU
     * access). The active/generation test is done by tbl_pktgen_active in the MAU, not here. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_read = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
        }
    };

    /* ================= state register 2 of 2: the DEADLINE ================
     * 24 bits of 256 ns ticks in [31:8]; bit 0 is the ARMED MARKER. The SALU returns
     * the age directly, so the separate `age = now - deadline` level is gone, and
     * because the marker rides in the same word the separate `dl_armed` test is gone.
     * PHV inputs: meta.now_word, meta.dl_val — exactly 2.
     *
     * TWO RegisterActions, mutually exclusive per packet (one access):
     *   deadline_rmw       — every non-arming packet, INCLUDING the ARM (which disarms
     *                        with dl_val = UNARMED_WORD). Unchanged. dl_val == 0 for
     *                        blockers/responses/bypass => read-only.
     *   deadline_arm_once  — ONLY the qualifying ACK (meta.ack_ok == 1). Arms FIRST-ACK
     *                        idempotently: writes dl_cand ONLY if the stored word is
     *                        still the unarmed sentinel (v == UNARMED_WORD, the state
     *                        the ARM leaves behind). A duplicate/retransmitted ACK for
     *                        the same armed transaction reads v == dl_cand (marker set,
     *                        != UNARMED_WORD) and leaves the deadline untouched — so it
     *                        can no longer push t_ack+G out. Both return the age
     *                        rv = now_word - v identically. */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };
    /* FIRST-ACK idempotency (finding B-D1). Compare-and-arm-once inside the SALU: the
     * armed word is written atomically only when the current stored word is the unarmed
     * sentinel. `v == UNARMED_WORD` is a memory-vs-constant compare (same shape the ts
     * registers use, and the FULL 32-bit word is compared — no bit-slice, no gateway
     * slice). PHV inputs: meta.now_word, meta.dl_val — exactly 2. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_arm_once = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (v == UNARMED_WORD) { v = meta.dl_val; }
        }
    };

    /* ================= fixed-slot timestamp registers (4) =================
     * SPARSE latency capture, write-if-zero = first occurrence. UNCHANGED from
     * p12_combined; part of the frozen timing mechanism.
     *   G_observed     = reg_ts_first_resp_release - reg_ts_ack_arm
     *   deadline error = G_observed - G
     *   release tail   = reg_ts_first_resp_release - reg_ts_block_term */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
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

    /* (REMOVED: reg_t_ack + t_ack_reset / t_ack_capture / t_ack_read, and the two
     * G-selection readout registers reg_native_clrt / reg_protection with their
     * RegisterActions. reg_t_ack shared stage 4's Meter ALU with reg_deadline;
     * reg_native_clrt / reg_protection were the only Meter-ALU users in stage 9.) */

    /* ================= counters (Stats ALU) ===============================
     * COLLAPSED: two indexed Counter arrays instead of sixteen single-entry objects.
     * Stats-ALU occupancy is per (counter OBJECT, stage) pair, so with one object per
     * path the whole ACT block needs one Stats ALU per stage it occupies instead of
     * four. Every count() index below is a compile-time constant (see CF_* / CD_*).
     * Each object is touched AT MOST ONCE per packet on any path — the two originals
     * that were a total-plus-subset (ctr_arm/ctr_arm_clone and
     * ctr_resp_release/ctr_release_*) are re-expressed as mutually exclusive
     * partitions whose sums reproduce the originals exactly. */
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) ctr_fresh;  /* CF_* slots */
    Counter<bit<64>, bit<8>>(8,  CounterType_t.PACKETS) ctr_deq;    /* CD_* slots */

    /* ================= TM actions ================= */
    action to_block() {                       /* enqueue Q_BLOCK on loopback dp8 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {                        /* enqueue Q_RESP on loopback dp8  */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* transparent forward to this frame's peer port: the immediate ACK, the released
     * RESPONSE, the forwarded READ, and all bypass traffic. bypass_egress = 0, so
     * these — and only these — traverse egress (a byte-preserving pass-through). */
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* PKTGEN: request one I2E mirror (the clone) to dp68. Sets the mirror type + session and
     * builds the 4-byte recirc tag = MARKER | gen (single const|runtime OR, one ALU op ->
     * no constraint class 5). The tag is emitted onto the mirror copy at the ingress deparser
     * (clone_mirror.emit), so this touches only the mirror copy — the main READ copy that
     * to_fwd() sends to dp64 stays byte-identical. Called ONLY on the fresh-ARM path. */
    action arm_clone() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.gen_in;
    }

    /* ================= guard interval G (JOIN C) =================
     * G already in 256 ns ticks; the low byte MUST be zero. No dependencies, so this
     * lands at or before the level that builds now_word and costs no depth. */
    action set_guard(bit<32> g_ticks) { meta.seq_m = g_ticks; }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(G_DEFAULT_TICKS);
        size = 1;
    }

    /* ---- level 1: build the deadline-aligned "now" ----
     * Constants only on the packing side. This must be an explicit table rather than
     * a plain statement beside the level-0 assignments: bf-p4c merges consecutive
     * unconditional statements into ONE action and then rejects the intra-action
     * dependency with "action spanning multiple stages" (measured on 9.13.1). */
    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    /* ---- level 2: the candidate armed word for an ACK ----
     * dl_cand = now_word + G_ticks: the low byte of the addend is zero, so the ARMED
     * marker survives the addition untouched and the tick fields add. */
    action build_cand() { meta.dl_cand = meta.now_word + meta.seq_m; }
    table tbl_build_cand {
        actions = { build_cand; }
        const default_action = build_cand();
        size = 1;
    }

    /* ================= the ONE decode table ==============================
     * Replaces the gen_mismatch compare level, the active-clear driver level and the
     * ACK-qualify / deadline-driver level with a single lookup on the packet class
     * and the tag difference. The match unit reads the whole container under a TCAM
     * mask, so nothing is sliced.
     *
     *   BLOCK : tag_diff == 0                <=> active AND my generation.
     *   ACK   : tag_diff NOT IN {0x00,0x01}  <=> a transaction is live (JOIN B).
     * Entry order IS priority: the CLASS_ACK reject pattern precedes the CLASS_ACK
     * accept-any pattern. A non-qualifying ACK writes NOTHING, so it cannot move any
     * release time. */
    action dec_arm()     { meta.dl_val = UNARMED_WORD; }                       /* ARM disarms  */
    action dec_ack_arm() { meta.dl_val = meta.dl_cand; meta.ack_ok = 8w1; }    /* ACK arms     */
    action dec_live()    { meta.dl_val = DL_NO_WRITE;  meta.tag_ok = 8w1; }    /* live blocker */
    action dec_none()    { meta.dl_val = DL_NO_WRITE; }
    table tbl_state_decode {
        key = {
            meta.pkt_class : exact;
            meta.tag_diff  : ternary;
        }
        actions = { dec_arm; dec_ack_arm; dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0x00 &&& 8w0x00) : dec_arm();      /* any tag: ARM takes over  */
            (CLASS_ACK,       8w0x00 &&& 8w0xFE) : dec_none();     /* no live transaction      */
            (CLASS_ACK,       8w0x00 &&& 8w0x00) : dec_ack_arm();  /* live: qualified, arm     */
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live();     /* my generation, still live */
        }
        size = 8;
    }

    /* ================= PKTGEN: token active check =========================
     * A pktgen token is admitted only while a transaction is live. reg_tag's raw value is
     * provably in {0x00 (never armed), 0xC0..0xCF (a generation), 0xFF (retired fail-open)};
     * "active" == it is a 0xCn generation. Tested as a masked-equality ternary on the whole
     * container (NOT a magnitude compare, so no gateway/range cost — cf. constraint class 1),
     * mirroring how tbl_state_decode reads a masked tag. */
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

    /* ================= deadline expiry =================================
     * expired <=> the deadline word is ARMED (low byte of the age is 0x00, which
     * happens only when the stored marker 0x01 cancelled the now-word marker with no
     * borrow) AND the 24-bit tick difference is non-negative (bit 31 clear). ONE
     * ternary entry tests both; unarmed words can never read as expired. */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (32w0x00000000 &&& 32w0x800000FF) : mark_expired();
        }
        size = 2;
    }

    /* (REMOVED: tbl_build_clrt_diff / build_clrt_diff and tbl_clrt_guard /
     * mark_held / mark_zero_hold — the second sign-bit ternary of the G-selection
     * guard. The FIRST sign-bit ternary, tbl_deadline_expiry, is the release
     * comparison itself and is PRESERVED verbatim above.) */

    apply {
        if (meta.port_ok == 8w0) {
            /* isolate the pipeline: only dp8 / dp9 / dp11 are in the topology */
            ctr_fresh.count(CF_BAD_PORT);
            drop_pkt();
        } else {
            /* ---------- level 0: packet-derived only ----------
             * role / dir / dequeued / fwd_port / gen_in already came from the parser. */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            /* hdr.ib is valid ONLY on blocker tokens, so on every other frame this
             * compares a stale tagalong container and budget_zero is MEANINGLESS.
             * Safe because budget_zero has exactly two consumers and both sit inside
             * a ROLE_BLOCK branch, and ROLE_BLOCK implies the token header is valid.
             * Do not read budget_zero outside a ROLE_BLOCK branch. */
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }  /* isolated 32b compare */
            tbl_guard.apply();                                   /* meta.seq_m = G ticks */

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
            }

            /* ---------- level 2: tag access (+ ACK candidate in parallel) ------
             * PKTGEN: an admitted token reads the CURRENT generation raw (tag_read); every
             * other packet keeps the baseline tag_rmw (returns gen_in - stored). Mutually
             * exclusive -> one SALU access on reg_tag per packet. */
            if (meta.is_pktgen == 8w1) {
                meta.cur_gen  = tag_read.execute(0);
            } else {
                meta.tag_diff = tag_rmw.execute(0);
            }
            tbl_build_cand.apply();

            /* ---------- level 3: one decode for stale / qualify / disarm ------- */
            tbl_state_decode.apply();
            tbl_pktgen_active.apply();   /* PKTGEN: txn_active from cur_gen (token path only) */

            /* ---------- level 4: deadline access, returning the age ------------
             * The qualifying ACK arms first-ACK idempotently (deadline_arm_once writes
             * only if v is still UNARMED_WORD); every other packet — including the ARM,
             * which disarms via dl_val = UNARMED_WORD — uses the unchanged deadline_rmw.
             * ack_ok == 1 <=> dec_ack_arm fired <=> dl_val == dl_cand, so arm_once always
             * sees a valid armed word. Both return the same age; only one runs per pkt. */
            if (meta.ack_ok == 8w1) {
                meta.age = deadline_arm_once.execute(0);
            } else {
                meta.age = deadline_rmw.execute(0);
            }

            /* ---------- level 5: expiry ---------- */
            tbl_deadline_expiry.apply();

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from a host port (or the pktgen source dp68) ----- */
                if (meta.role == ROLE_BLOCK) {
                    if (meta.is_pktgen == 8w1) {
                        /* PKTGEN admission (invariant 3): admit only while a transaction is
                         * active; STAMP the current generation + a fail-open budget so the
                         * token matches on its first dp8 loop, then enqueue Q_BLOCK via the
                         * baseline to_block(). Stamping from reg_tag (not the template) means a
                         * token generated a hair after a new READ still gets the live gen, and a
                         * stale-gen token self-terminates on its first loop exactly as before.
                         * to_block() is the ONLY egress a token can reach (invariant 4). */
                        if (meta.txn_active == 8w1) {
                            hdr.ib.role = ROLE_BLOCK;        /* wire role (parser already forced)*/
                            hdr.ib.gen  = meta.cur_gen;      /* stamp CURRENT generation         */
                            hdr.ib.seq  = INITIAL_BUDGET;    /* stamp fail-open pass budget      */
                            to_block();
                            ctr_fresh.count(CF_PKTGEN_ADMIT);
                            meta.ev_first_block = 8w1;
                        } else {
                            drop_pkt();                      /* no active txn: drop (invariant 3)*/
                            ctr_fresh.count(CF_PKTGEN_DROP);
                        }
                    } else {
                        /* baseline host-injected token path (kept for A/B rollback) */
                        to_block();
                        ctr_fresh.count(CF_BLOCK_ENQ);
                        meta.ev_first_block = 8w1;
                    }
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    to_resp();                        /* held on Q_RESP (qid1, LOW) */
                    ctr_fresh.count(CF_RESP_ENQ);
                } else if (meta.role == ROLE_ACK) {
                    /* HOLD_RESPONSE: the ACK is NEVER held — forward it now. */
                    to_fwd();
                    if (meta.ack_ok == 8w1) {
                        ctr_fresh.count(CF_ACK_ARM);
                        meta.ev_ack_arm = 8w1;
                    } else {
                        ctr_fresh.count(CF_ACK_BYPASS);
                    }
                } else if (meta.role == ROLE_ARM) {
                    /* a real DNP3 READ: it took the tag above and must reach the
                     * outstation, so it is forwarded, not consumed (invariant 1:
                     * to_fwd() -> dp64, byte-identical; the clone is a separate mirror
                     * copy and never perturbs this one). */
                    to_fwd();
                    /* PKTGEN (invariant 2): spawn the trigger clone ONLY on a FRESH arm.
                     * tag_diff != 0 <=> this READ advanced the generation in reg_tag; a
                     * retransmitted READ reads tag_diff == 0 (baseline idempotency) and makes
                     * NO second clone/trigger, so exactly one 64-token burst per fresh READ.
                     * COUNTER COLLAPSE: the baseline counted ctr_arm on EVERY forwarded READ
                     * and ctr_arm_clone on the fresh subset. Here the same information is a
                     * PARTITION (fresh | duplicate) so this packet touches ctr_fresh once:
                     * ctr_arm == ctr_fresh[CF_ARM_FRESH] + ctr_fresh[CF_ARM_DUP], and
                     * ctr_arm_clone == ctr_fresh[CF_ARM_FRESH]. The FORWARDING is unchanged:
                     * to_fwd() above runs on both arms of the branch. */
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
                    /* terminate causes, priority: stale > deadline > budget */
                    if (meta.tag_ok == 8w0) {
                        drop_pkt();
                        ctr_deq.count(CD_BLOCK_TERM_STALE);
                        meta.ev_block_term = 8w1;
                    } else if (meta.expired == 8w1) {
                        drop_pkt();
                        ctr_deq.count(CD_BLOCK_TERM_DL);
                        meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();
                        ctr_deq.count(CD_BLOCK_TERM_TMO);
                        meta.ev_block_term = 8w1;
                    } else {
                        /* LOOP: consume one budget unit, re-enqueue Q_BLOCK */
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_deq.count(CD_BLOCK_LOOP);
                    }
                } else if (meta.role == ROLE_RESP) {
                    /* RELEASED RESPONSE: forward to the master, byte-identical.
                     * The release cause is attributed by the deadline state at dequeue —
                     * expired => the reservoir drained on the deadline; not-expired => it
                     * drained early on its pass budget (fail-open). meta.expired is already
                     * computed above for this packet.
                     * COUNTER COLLAPSE: the baseline counted ctr_resp_release on every
                     * release AND one of ctr_release_deadline / ctr_release_fail_open. The
                     * two causes already partition the releases, so the total is now the
                     * sum and this packet touches ctr_deq exactly once:
                     * ctr_resp_release == ctr_deq[CD_RELEASE_DEADLINE] + ctr_deq[CD_RELEASE_FAILOPEN]. */
                    to_fwd();
                    if (meta.expired == 8w1) { ctr_deq.count(CD_RELEASE_DEADLINE); }
                    else                     { ctr_deq.count(CD_RELEASE_FAILOPEN); }
                } else {
                    drop_pkt();   /* nothing else may loop back */
                }
            }

            /* (REMOVED: the whole G-selection-guard tail — the reg_t_ack access chain,
             * tbl_build_clrt_diff, tbl_clrt_guard, the two readout register writes and
             * the four ctr_response_* counts. Nothing above reads any of it.) */

            /* ================= SPARSE latency capture (single call site each) ===
             * The four registers and the values they capture are UNCHANGED from
             * p12_combined. Do NOT cut them to chase a stage count: the ACK is held and
             * the relay leg is untappable, so these on-chip registers are the only
             * possible measurement of the hold (design §13).
             *
             * PREDICATE FLOAT (measured, second lever). Each register is pinned to the
             * stage AFTER whatever writes its ev_* flag. Of the four flags, exactly ONE
             * has a predicate expressible in PARSER-produced fields:
             *   ev_resp_release <=> (dequeued == 1 && role == ROLE_RESP), because the
             *   dequeued ROLE_RESP branch sets it UNCONDITIONALLY. Both fields come out
             *   of the parser, so the register floats to stage 1 instead of stage 7. The
             *   captured value (meta.ts32) is level-0 and identical either way, the
             *   register is write-if-zero with a single call site, and nothing in the
             *   data plane reads it — so this is exactly behaviour-preserving.
             * The other three CANNOT be floated without changing behaviour, and are
             * therefore left exactly as they are:
             *   ev_first_block  additionally requires txn_active (from reg_tag, stage 3);
             *                   dropping it would timestamp a token that was DROPPED for
             *                   having no active transaction.
             *   ev_ack_arm      additionally requires ack_ok (tbl_state_decode, stage 3);
             *                   dropping it would timestamp a NON-qualifying ACK and
             *                   destroy the G_observed measurement.
             *   ev_block_term   additionally requires tag_ok / expired / budget_zero
             *                   (expired comes from tbl_deadline_expiry, stage 5);
             *                   dropping it would timestamp a token that kept looping.
             * MEASURED RESULT: the float frees one Meter ALU in the deepest stage
             * (4/4 -> 3/4) but does NOT free a stage — ts_first_block and ts_block_term
             * still sit one stage below their MAU-derived flags, and that chain is the
             * 8-deep critical path. */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.dequeued == 8w1 && meta.role == ROLE_RESP) { ts_first_resp_w.execute(0); }
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emission order == extraction order, so every forwarded frame is byte-identical.
 * Exactly one of {ib} / {ipv4 ...} is valid; unextracted bytes stay residual and are
 * emitted automatically. UNCHANGED from p12_combined. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    /* PKTGEN: no-arg Mirror() (the typed ctor errors "Inconsistent mirror selectors" on TF1). */
    Mirror() clone_mirror;
    apply {
        /* PKTGEN (invariant 2): on the fresh-ARM path arm_clone() set mirror_type = CLONE and
         * meta.clone_ses/clone_tag. emit prepends the 4-byte recirc tag to the MIRROR copy only
         * (session -> dp68 via $mirror.cfg); the main forwarded copy below is untouched. Session
         * id comes from a PHV field (meta.clone_ses), not a literal. Formatting the tag here (the
         * ingress deparser) costs ZERO egress stages. */
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
 * BYTE-PRESERVING PASS-THROUGH, carried over VERBATIM from ibspg_dnp3.p4 (which
 * carried it from Part 12). The immediately-forwarded ACK, the forwarded READ, the
 * released RESPONSE and all bypass traffic traverse egress (bypass_egress=0). Egress
 * extracts only ethernet: everything after it is residual and is re-emitted verbatim,
 * so the frame is byte-identical to what the ingress deparser produced. No field is
 * modified anywhere in egress. Blocker tokens and held responses set bypass_egress=1
 * and never arrive here, so the hold mechanism cannot be perturbed by this gress. */
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
