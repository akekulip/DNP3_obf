/* ============================================================================
 * p13_size_do8.p4 — p12_combined.p4 with the SIZE AXIS MADE LIVE ON REAL TRAFFIC.
 *                   (Tofino 1, TNA, bf-p4c 9.13.1, compile-only, never loaded)
 *
 * P12's egress normalizer was P6c verbatim and keyed its parser select on
 * (tcp.data_offset, ipv4.total_len) with data_offset == 5 on every entry. Measured
 * directly from `Traffic Trace/SEL751.pcap` (2104 packets, tshark):
 *
 *     ip.hdr_len  tcp.hdr_len  ip.len  frame.len   count
 *         20          32          52       66       906   pure ACK      (do = 8)
 *         20          32          74       88       198   DNP3 REQUEST  (do = 8)
 *         20          32          87      101       400   DNP3 RESPONSE (do = 8)
 *         20          32          89      103       400   DNP3 RESPONSE (do = 8)
 *         20          32         106      120       198   DNP3 RESPONSE (do = 8)
 *         20          40          60       74         2   SYN / SYN-ACK (do = 10)
 *
 * ZERO frames carry a 20-byte TCP header. So every real frame fell through the
 * select, kept its payload in the deparser residual, missed `size_norm` and took
 * the fail-open `pad_none` default: correct forwarding, no normalization at all.
 *
 * THE FIX, and it is a deletion rather than an addition. `data_offset` is removed
 * from the parser select key; `ipv4.total_len` alone selects the class. What the
 * pl_* states consume is every byte of the IP datagram after the FIXED 20-byte TCP
 * base header — `total_len - 40` bytes — which is a function of total_len only, and
 * the power-of-2 chunks are opaque to whether a given byte is a TCP option or DNP3
 * payload. One class set therefore covers EVERY data_offset. No new parser state, no
 * new header, no new pad action, no new tagalong byte.
 *
 * The safety property P6c got from a coincidence is now checked: `size_norm` keys on
 * (ipv4.total_len, eg_intr_md.pkt_length) and every entry is the pair (L, L+14), so
 * an entry can only fire when the parser really did consume the payload AND the frame
 * carries no pre-existing Ethernet trailer. See the table comment for the derivation.
 *
 * Coverage after the change: ALL 2104 packets of the measured corpus (6 of the 13
 * classes carry it), for data_offset 5..15, normalized to one fixed 128-byte output.
 * Everything outside the 13 classes still fails open, unchanged, never truncated.
 *
 * Ingress is BYTE-FOR-BYTE p12_combined: not one ingress table, action, register,
 * counter, metadata field, parser state or gate is touched, so every timing-side
 * property carries over by construction rather than by re-argument.
 * ------------------------------------------------------------------------------
 * INHERITED FROM p12_combined.p4 — THE CAMPAIGN QUESTION: does the full target
 *                   architecture fit, and at what measured ingress stage cost?
 *
 * Three pieces that each compiled ALONE are put into ONE program here for the
 * first time. Nothing is invented; each piece is carried over in the shape it was
 * measured in, and every deviation is a JOIN between two pieces, listed below.
 *
 *   (1) REAL DNP3 CLASSIFICATION IN THE INGRESS PARSER
 *       source: DNP3-part13 research/ibspg_dnp3_replay/p4/ibspg_dnp3/ibspg_dnp3.p4
 *       measured alone: 11/12 ingress stages, 9 ingress parser states, 86/256
 *       ingress parser TCAM rows.
 *       Produces meta.role / meta.dir / meta.dequeued / meta.fwd_port /
 *       meta.port_ok / meta.gen_in, with the two-gate parser hardening and the
 *       0x88C1 -> ROLE_BLOCK force.
 *
 *   (2) PACKED TRANSACTION STATE
 *       source: variants/p1_packed_state/p1_packed_state.p4
 *       measured alone: 12 -> 8 ingress stages.
 *       reg_tag (generation + active in one byte, the SALU returns the DIFFERENCE)
 *       + reg_deadline whose bit 0 is the ARMED marker, so ONE ternary entry
 *       `0x00000000 &&& 0x800000FF` tests armed-and-due together.
 *
 *   (3) EGRESS / DEPARSER SIZE NORMALIZATION
 *       source: variants/p6_egress_pad/p6c_true_trailer.p4
 *       measured alone: ingress unchanged, +2 egress stages, tagalong 89.8 %.
 *       The egress parser consumes the WHOLE payload into a shared power-of-2
 *       chunk set selected IN THE TCP-EXTRACT STATE, so the residual is empty and
 *       pad64..pad1 land after the complete inner datagram. Same 13 classes and the
 *       same one fixed 128 B target as P6c/P12; P13 changes only the select KEY
 *       (total_len alone, not (data_offset, total_len)) and the size_norm KEY, so no
 *       class, header, action or pad byte is added — see the P13 block at the top.
 *
 * ------------------------------------------------------------------------------
 * THE FOUR JOINS — everywhere pieces (1) and (2) disagreed, and how it was closed
 * without weakening anything. (Piece (3) needed no join: it touches only egress,
 * and no ingress table, action, register, counter or metadata field serves it.)
 *
 * JOIN A — WHERE THE GENERATION COMES FROM.  P1 read `hdr.ib.gen` from a synthetic
 *   header. A real frame has none, so the generation is the parser's `meta.gen_in`:
 *   the DNP3 APPLICATION CONTROL byte for DNP3 frames, `hdr.ib.gen` for blocker
 *   tokens (piece 1's rule, unchanged). meta.gen_in feeds the tag SALU DIRECTLY —
 *   P1's separate `exp_tag` copy is deleted, because gen_in is already a metadata
 *   field and one fewer 8-bit field is one fewer container in a program whose
 *   binding constraint is PHV. The SALU still sees exactly 2 PHV inputs.
 *
 * JOIN B — AN ACK HAS NO GENERATION, BUT THE PACKED TAG FUSES GENERATION WITH
 *   "ACTIVE".  This is the one real semantic collision between (1) and (2).
 *   Piece (1) qualifies an ACK on `active_now == 1` and deliberately does NOT check
 *   the generation: a pure TCP ACK carries no DNP3 application sequence. Piece (2)
 *   has no separate `active` bit to test — `tag_diff == 0` means active AND my
 *   generation, and a pure ACK's gen_in is 0, so `tag_diff == 0` would degenerate
 *   into "the register is still at its power-on value", i.e. exactly backwards.
 *
 *   Closed inside the SAME decode table, with one extra const entry and no extra
 *   MAU level, by reading the SALU difference for what it is. With exp = 0 the SALU
 *   returns `0 - v`, and the stored tag `v` has a CLOSED domain of three cases:
 *       v = 0x00        power-on, no transaction ever   ->  0 - v = 0x00
 *       v = 0xFF        TAG_INACTIVE, fail-open cleared ->  0 - v = 0x01
 *       v = g           a live generation               ->  0 - v = 0x100 - g
 *   so "a transaction is live" is exactly `tag_diff NOT IN {0x00, 0x01}`, which one
 *   ternary pattern `0x00 &&& 0xFE` captures. The table therefore reads:
 *       (CLASS_ACK, 0x00 &&& 0xFE) : dec_none()      <- no live transaction
 *       (CLASS_ACK, 0x00 &&& 0x00) : dec_ack_arm()   <- otherwise: live, so arm
 *   This reproduces piece (1)'s ACK qualification EXACTLY (armed-transaction test,
 *   no generation test) while the blocker path keeps the full generation test
 *   (`tag_diff == 0` exactly). Generation safety is not touched.
 *
 *   THE DOMAIN ARGUMENT IS LOAD-BEARING, so it is enforced, not assumed. `g` must
 *   never be 0x00 (which is P1's measured "do not write" SALU sentinel — a compare
 *   immediate must be small, so ZERO is the only cheap sentinel) and never 0xFF
 *   (TAG_INACTIVE). g is the DNP3 application control byte of a READ. IEEE 1815
 *   requires a request to be a SINGLE application fragment, so FIR = FIN = 1, and a
 *   request never sets CON or UNS: the byte is always 0xCn. That is turned from a
 *   protocol expectation into a parser gate at zero cost — the ARM entry of the
 *   existing func_code select gains an app_control mask `0xC0 &&& 0xF0`, using the
 *   parser match registers the select already holds. A READ whose application
 *   control byte is not 0xCn is not malformed-and-dropped; it simply does not arm
 *   and is forwarded as ROLE_BYPASS, which is this program's standing fail-open
 *   posture. So the tag domain is provably {0x00, 0xC0..0xCF, 0xFF} and the two
 *   ACK patterns above partition it exactly.
 *
 * JOIN C — WHERE G COMES FROM.  P1 read the guard interval out of `hdr.ib.seq` of
 *   the synthetic ACK and masked it (`seq_m = G & TICK_MASK`) in the parser-level
 *   assignments. A real ACK has no such field, so G comes from piece (1)'s
 *   `tbl_guard`, whose default action parameter the control plane rewrites for a G
 *   sweep with no recompile. tbl_guard has no dependencies, so it lands at or
 *   before the level that built P1's `now_word` and the merge costs no depth.
 *   CONTROL-PLANE CONTRACT: the parameter is G already expressed in 256 ns ticks,
 *   i.e. its LOW BYTE MUST BE ZERO, because bit 0 of the deadline word is the ARMED
 *   marker and only a zero low byte lets the marker survive the addition. The
 *   default 0x017D7800 = 24.999936 ms is 25 ms rounded down to a tick. Violating
 *   the contract is FAIL-OPEN, not fail-closed: a non-zero low byte makes the age's
 *   low byte non-zero, the expiry pattern never matches, and the blocker drains on
 *   its pass budget instead of on the deadline.
 *
 * JOIN D — THE STALE TEST.  Piece (1) wrote `active_now == 0 || gen_mismatch == 1`;
 *   piece (2) folds both into `tag_ok == 0`, set by the one decode table. Identical
 *   meaning, one level shallower. P1's one deliberate tightening comes with it: a
 *   stale token can no longer write state at all, so it can no longer clear
 *   `active` for a live generation and release that generation's response early.
 *
 * ------------------------------------------------------------------------------
 * SAFETY PROPERTIES — each one, and where it lives in this file.
 *   generation safety      : reg_tag holds the generation; the blocker decode entry
 *                            (CLASS_BLOCK_DEQ, 0x00 &&& 0xFF) fires only on an exact
 *                            tag match, so only a token of the CURRENT generation is
 *                            ever `tag_ok`. JOIN B keeps the ACK path out of this.
 *   stale/unrelated reject : anything that is not tag_ok on the dequeued BLOCK path
 *                            is dropped by ctr_block_term_stale; anything that is
 *                            not a BLOCK or a RESP on that path is dropped outright;
 *                            any frame from a port other than dp8/dp9/dp11 is
 *                            dropped on meta.port_ok.
 *   correct deadline rel.  : reg_deadline bit 0 = armed marker, tbl_deadline_expiry
 *                            entry 0x00000000 &&& 0x800000FF = armed AND due.
 *   pass-budget fail-open  : meta.budget_zero -> TAG_INACTIVE at the tag write and
 *                            ctr_block_term_timeout at the act; every later token
 *                            then reads a stale tag and terminates.
 *   blocker isolation      : ethertype 0x88C1 is FORCED to ROLE_BLOCK in the parser,
 *                            so a token can only ever reach to_block() or drop_pkt()
 *                            and never a host port.
 *   byte preservation      : no MAU action reads or writes any byte of any host
 *                            frame. The single field written anywhere is
 *                            hdr.ib.seq, the internal token's own pass counter.
 *                            Ingress emits in extraction order; egress re-emits the
 *                            payload chunks in the order they were extracted, and
 *                            the pads land after the last of them.
 *   two parser gates       : GATE 1 = the total_len range per data_offset in the
 *                            SAME state that extracts TCP; GATE 2 = DNP3 LEN >= 8,
 *                            with LEN == 5 a valid link-only frame that is forwarded.
 *
 * KNOWN CONSTRAINTS OBEYED (measured previously; not re-derived here)
 *   - a TF1 SALU takes at most 2 PHV inputs: both RegisterActions use exactly 2.
 *   - runtime fields may NOT be packed into a 32-bit arithmetic word (PHV slicing
 *     fails outright); only CONSTANTS are packed here (0x01, 0x02, TICK_MASK).
 *   - a bit-slice inside a gateway is rejected: every sub-field test is a ternary
 *     match under a TCAM mask. The only slice in the program is
 *     ingress_mac_tstamp[31:0], which every prior variant has too.
 *   - a select on ipv4.total_len after the TCP-extract state is a 9.13.x failure
 *     mode: both the ingress GATE 1 and the egress payload select sit IN the
 *     tcp-extract state.
 *   - the parser has no clear-on-write: role/dir/fwd_port/port_ok/gen_in/dequeued
 *     are assigned exactly ONCE per path and every default is the all-zero encoding.
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
const PortId_t PORT_HULK   = 9w11;  /* outstation side (dp11)                             */

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH (max_priority=7) : blocker reservoir   */
const bit<5> QID_RESP  = 5w1;   /* LOW  (max_priority=0) : response held queue */

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

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

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

/* ---- piece 3: shared power-of-2 EGRESS chunk sets ----
 * pay* consume the whole TCP payload so the deparser residual is empty;
 * pad* are emitted after them and are therefore a true Ethernet trailer.
 * Neither is ever read or written by an MAU action. */
header pay1_h  { bit<8>   f; }
header pay2_h  { bit<16>  f; }
header pay4_h  { bit<32>  f; }
header pay8_h  { bit<64>  f; }
header pay16_h { bit<128> f; }
header pay32_h { bit<256> f; }
header pay64_h { bit<512> f; }

header pad1_h  { bit<8>   f; }
header pad2_h  { bit<16>  f; }
header pad4_h  { bit<32>  f; }
header pad8_h  { bit<64>  f; }
header pad16_h { bit<128> f; }
header pad32_h { bit<256> f; }
header pad64_h { bit<512> f; }

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

struct eg_headers_t {
    ethernet_h eth;
    ipv4_h     ipv4;
    tcp_h      tcp;
    pay64_h pay64; pay32_h pay32; pay16_h pay16; pay8_h pay8;
    pay4_h  pay4;  pay2_h  pay2;  pay1_h  pay1;
    pad64_h pad64; pad32_h pad32; pad16_h pad16; pad8_h pad8;
    pad4_h  pad4;  pad2_h  pad2;  pad1_h  pad1;
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
    bit<8>  ev_block_term;
    bit<8>  ev_resp_release;
}

/* ============================ ingress parser =============================
 * PIECE 1, carried over. Every role decision is taken here; the MAU sees only
 * meta.role / meta.dir / meta.dequeued / meta.fwd_port / meta.port_ok / meta.gen_in.
 * The ONE change is the app_control mask on the ARM leaf (JOIN B). */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

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
        meta.ev_resp_release = 8w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_L      : from_loopback;
            PORT_HULK   : from_outstation;
            PORT_VISION : from_master;
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
    state from_master     { meta.dir      = DIR_MASTER; meta.fwd_port = PORT_HULK;
                            meta.port_ok  = 8w1; transition parse_eth; }

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

    /* ================= state register 2 of 2: the DEADLINE ================
     * 24 bits of 256 ns ticks in [31:8]; bit 0 is the ARMED MARKER. The SALU returns
     * the age directly, so the separate `age = now - deadline` level is gone, and
     * because the marker rides in the same word the separate `dl_armed` test is gone.
     * PHV inputs: meta.now_word, meta.dl_val — exactly 2. */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };

    /* ================= fixed-slot timestamp registers (4) =================
     * SPARSE latency capture, write-if-zero = first occurrence.
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

    /* ================= counters (Stats ALU — multi-site OK) ================ */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;               /* DNP3 READ forwarded */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_deadline;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_arm;      /* qualifying ACK     */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_bypass;   /* non-qualifying ACK */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;
    /* index 0 = ROLE_BYPASS forwarded transparently, index 1 = dropped (bad port) */
    Counter<bit<64>, bit<8>>(2, CounterType_t.PACKETS) ctr_bypass;

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
     * these — and only these — reach the egress size normalizer. */
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

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
     *           0x00 = the register is still at power-on, 0x01 = TAG_INACTIVE;
     *           the tag domain is {0x00, 0xC0..0xCF, 0xFF} by the parser gate, so
     *           `0x00 &&& 0xFE` partitions it exactly and the generation is NOT
     *           tested for an ACK — reproducing the DNP3 program's rule, which is
     *           what a pure TCP ACK (no application sequence) can support.
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

    apply {
        if (meta.port_ok == 8w0) {
            /* isolate the pipeline: only dp8 / dp9 / dp11 are in the topology */
            ctr_bypass.count(8w1);
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

            /* ---------- level 2: tag access (+ ACK candidate in parallel) ------ */
            meta.tag_diff = tag_rmw.execute(0);
            tbl_build_cand.apply();

            /* ---------- level 3: one decode for stale / qualify / disarm ------- */
            tbl_state_decode.apply();

            /* ---------- level 4: deadline access, returning the age ------------ */
            meta.age = deadline_rmw.execute(0);

            /* ---------- level 5: expiry ---------- */
            tbl_deadline_expiry.apply();

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from a host port ----- */
                if (meta.role == ROLE_BLOCK) {
                    to_block();
                    ctr_block_enq.count(0);
                    meta.ev_first_block = 8w1;
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    to_resp();                        /* held on Q_RESP (qid1, LOW) */
                    ctr_resp_enq.count(0);
                } else if (meta.role == ROLE_ACK) {
                    /* HOLD_RESPONSE: the ACK is NEVER held — forward it now. */
                    to_fwd();
                    if (meta.ack_ok == 8w1) {
                        ctr_ack_arm.count(0);
                        meta.ev_ack_arm = 8w1;
                    } else {
                        ctr_ack_bypass.count(0);
                    }
                } else if (meta.role == ROLE_ARM) {
                    /* a real DNP3 READ: it took the tag above and must reach the
                     * outstation, so it is forwarded, not consumed. */
                    to_fwd();
                    ctr_arm.count(0);
                } else {
                    to_fwd();                         /* ROLE_BYPASS: transparent */
                    ctr_bypass.count(8w0);
                }
            } else {
                /* ----- DEQUEUED (looped back from dp8) ----- */
                if (meta.role == ROLE_BLOCK) {
                    /* terminate causes, priority: stale > deadline > budget */
                    if (meta.tag_ok == 8w0) {
                        drop_pkt();
                        ctr_block_term_stale.count(0);
                        meta.ev_block_term = 8w1;
                    } else if (meta.expired == 8w1) {
                        drop_pkt();
                        ctr_block_term_deadline.count(0);
                        meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();
                        ctr_block_term_timeout.count(0);
                        meta.ev_block_term = 8w1;
                    } else {
                        /* LOOP: consume one budget unit, re-enqueue Q_BLOCK */
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_block_loop.count(0);
                    }
                } else if (meta.role == ROLE_RESP) {
                    /* RELEASED RESPONSE: forward to the master, byte-identical */
                    to_fwd();
                    ctr_resp_release.count(0);
                    meta.ev_resp_release = 8w1;
                } else {
                    drop_pkt();   /* nothing else may loop back */
                }
            }

            /* ================= SPARSE latency capture (single call site each) === */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_resp_release == 8w1) { ts_first_resp_w.execute(0); }
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emission order == extraction order, so every forwarded frame is byte-identical.
 * Exactly one of {ib} / {ipv4 ...} is valid; unextracted bytes stay residual and are
 * emitted automatically. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
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

/* ================= EGRESS — piece 3, with the P13 key change ==============
 * Fully consume the IP datagram past the 20-byte TCP base header so the deparser
 * residual is empty. Any frame that is not ihl = 5 / IPv4 / TCP / a known total_len
 * falls through to `accept` with those bytes still in the residual and NO pad valid
 * => forwarded byte-for-byte unchanged. data_offset is deliberately NOT tested: the
 * chunks are opaque bytes, so options and payload are consumed and re-emitted the
 * same way and one class set serves every data_offset.
 * Blocker tokens and held responses set bypass_egress = 1 and never arrive here, so
 * the hold mechanism cannot be perturbed by anything in this gress. */
struct eg_meta_t { bit<8> normalized; }

parser EgParser(packet_in pkt, out eg_headers_t hdr, out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (4w5, IP_PROTO_TCP) : parse_tcp;
            default             : accept;      /* options / non-TCP: fail open */
        }
    }
    /* THE P13 CHANGE — the select key is `ipv4.total_len` ALONE; `tcp.data_offset`
     * is GONE from it.
     *
     * P6c/P12 keyed on (data_offset, total_len) and only ever listed data_offset = 5.
     * The measured SEL-751 corpus carries a 32-byte TCP header (data_offset = 8,
     * TCP timestamps) on 2102 of 2104 frames and 40 bytes (data_offset = 10) on the
     * other 2, and NOT ONE frame with 20. So every real frame missed the select,
     * left its payload in the deparser residual, missed `size_norm`, and took
     * `pad_none`: the size axis was inert.
     *
     * data_offset does not belong in this key, because what these states consume is
     * not "the TCP payload" — it is "every byte of the IP datagram after the FIXED
     * 20-byte TCP base header", i.e. `total_len - 20 (ip) - 20 (tcp base)` bytes,
     * whatever mixture of TCP OPTION bytes and payload bytes that happens to be.
     * That count is a function of total_len ONLY. The chunks are opaque: they are
     * extracted descending and emitted descending, so any mixture is reconstructed
     * byte-identically regardless of where the option/payload boundary falls inside
     * it. One class set therefore covers EVERY data_offset with no new state, no new
     * header and no new tagalong byte.
     *
     * The select still lives IN the tcp-extract state: a select on ipv4.total_len in
     * a state placed AFTER the tcp extract is a known bf-p4c 9.13.x failure mode on
     * this toolchain. Dropping data_offset also frees the 4-bit match register the
     * old 2-tuple held. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.ipv4.total_len) {
            16w75  : pl_35;
            16w76  : pl_36;
            16w77  : pl_37;
            16w78  : pl_38;
            16w79  : pl_39;
            16w80  : pl_40;
            16w81  : pl_41;
            16w82  : pl_42;
            16w83  : pl_43;
            16w84  : pl_44;
            16w85  : pl_45;
            16w86  : pl_46;
            16w87  : pl_47;
            16w88  : pl_48;
            16w89  : pl_49;
            16w90  : pl_50;
            16w91  : pl_51;
            16w92  : pl_52;
            16w93  : pl_53;
            16w94  : pl_54;
            16w95  : pl_55;
            16w96  : pl_56;
            16w97  : pl_57;
            16w98  : pl_58;
            16w99  : pl_59;
            16w100 : pl_60;
            16w101 : pl_61;
            16w102 : pl_62;
            16w103 : pl_63;
            16w104 : pl_64;
            16w105 : pl_65;
            16w106 : pl_66;
            16w107 : pl_67;
            16w108 : pl_68;
            16w109 : pl_69;
            16w110 : pl_70;
            16w111 : pl_71;
            16w112 : pl_72;
            16w113 : pl_73;
            16w114 : pl_74;
            default : accept;                  /* unknown length: fail open */
        }
    }
    /* Chunks extracted DESCENDING; the deparser emits DESCENDING too, so every subset
     * reconstructs the consumed bytes byte-identically. pl_N consumes N = total_len-40
     * bytes; the state names are kept from P6c so the two programs stay diffable. */
    state pl_35 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_36 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay4); transition accept; }
    state pl_37 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay4); pkt.extract(hdr.pay1); transition accept; }
    state pl_38 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); transition accept; }
    state pl_39 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_40 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); transition accept; }
    state pl_41 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay1); transition accept; }
    state pl_42 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay2); transition accept; }
    state pl_43 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_44 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); transition accept; }
    state pl_45 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay1); transition accept; }
    state pl_46 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); transition accept; }
    state pl_47 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_48 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); transition accept; }
    state pl_49 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay1); transition accept; }
    state pl_50 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay2); transition accept; }
    state pl_51 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_52 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay4); transition accept; }
    state pl_53 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay4); pkt.extract(hdr.pay1); transition accept; }
    state pl_54 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); transition accept; }
    state pl_55 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_56 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); transition accept; }
    state pl_57 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay1); transition accept; }
    state pl_58 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay2); transition accept; }
    state pl_59 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_60 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); transition accept; }
    state pl_61 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay1); transition accept; }
    state pl_62 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); transition accept; }
    state pl_63 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_64 { pkt.extract(hdr.pay64); transition accept; }
    state pl_65 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay1); transition accept; }
    state pl_66 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay2); transition accept; }
    state pl_67 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_68 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay4); transition accept; }
    state pl_69 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay4); pkt.extract(hdr.pay1); transition accept; }
    state pl_70 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); transition accept; }
    state pl_71 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_72 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay8); transition accept; }
    state pl_73 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay8); pkt.extract(hdr.pay1); transition accept; }
    state pl_74 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay8); pkt.extract(hdr.pay2); transition accept; }
}

control Egress(inout eg_headers_t hdr, inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_size_normalized;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_size_failopen;

    action pad_none() { meta.normalized = 8w0; }
    action pad_d39() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d38() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d37() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d36() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; }
    action pad_d35() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d34() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d33() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d32() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; }
    action pad_d31() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d30() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d29() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d28() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; }
    action pad_d27() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d26() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d25() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d24() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; }
    action pad_d23() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d22() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d21() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d20() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; }
    action pad_d19() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d18() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d17() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d16() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; }
    action pad_d15() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d14() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d13() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d12() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; }
    action pad_d11() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d10() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d9() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d8() { meta.normalized = 8w1; hdr.pad8.setValid(); hdr.pad8.f = 0; }
    action pad_d7() { meta.normalized = 8w1; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d6() { meta.normalized = 8w1; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d5() { meta.normalized = 8w1; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d4() { meta.normalized = 8w1; hdr.pad4.setValid(); hdr.pad4.f = 0; }
    action pad_d3() { meta.normalized = 8w1; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d2() { meta.normalized = 8w1; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d1() { meta.normalized = 8w1; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d0() { meta.normalized = 8w1; }

    /* Two-field key: the DECLARED IP length and the MEASURED egress frame length.
     *
     *   total_len   proves THE PARSER CONSUMED THE PAYLOAD. The 13 values here are
     *               exactly the 13 values the egress parser selects on, so a match
     *               is a proof that this frame took a pl_* state and the deparser
     *               residual is empty. Without it the pads could be emitted BEFORE a
     *               non-empty residual, which would split the IP datagram in two.
     *               P6c got this property from a coincidence (pkt_length was in
     *               bijection with total_len for its corpus); here it is checked.
     *   pkt_length  supplies the TRUE measured total, so the pad amount is exact even
     *               though the two fields are redundant on a well-formed frame.
     *
     * Every entry is the pair (L, L+14) for a class L, so an entry can only fire when
     * pkt_length - 14 - total_len == 0, i.e. there is no Ethernet trailer already on
     * the frame. Anything else — unknown length, a pre-existing trailer, ihl != 5, a
     * non-TCP or non-IPv4 frame, or an OVERSIZE frame (total_len > 114) — has no entry
     * and takes `pad_none`: forwarded byte-for-byte unchanged, never truncated.
     *
     * Pad amount is 128 - (14 + L) = 114 - L, identical to P6c's for every class. */
    table size_norm {
        key = { hdr.ipv4.total_len   : exact;
                eg_intr_md.pkt_length : exact; }
        actions = { pad_none; pad_d39; pad_d38; pad_d37; pad_d36; pad_d35; pad_d34; pad_d33; pad_d32; pad_d31; pad_d30; pad_d29; pad_d28; pad_d27; pad_d26; pad_d25; pad_d24; pad_d23; pad_d22; pad_d21; pad_d20; pad_d19; pad_d18; pad_d17; pad_d16; pad_d15; pad_d14; pad_d13; pad_d12; pad_d11; pad_d10; pad_d9; pad_d8; pad_d7; pad_d6; pad_d5; pad_d4; pad_d3; pad_d2; pad_d1; pad_d0; }
        const entries = {
            (16w75  , 16w89  ) : pad_d39();
            (16w76  , 16w90  ) : pad_d38();
            (16w77  , 16w91  ) : pad_d37();
            (16w78  , 16w92  ) : pad_d36();
            (16w79  , 16w93  ) : pad_d35();
            (16w80  , 16w94  ) : pad_d34();
            (16w81  , 16w95  ) : pad_d33();
            (16w82  , 16w96  ) : pad_d32();
            (16w83  , 16w97  ) : pad_d31();
            (16w84  , 16w98  ) : pad_d30();
            (16w85  , 16w99  ) : pad_d29();
            (16w86  , 16w100 ) : pad_d28();
            (16w87  , 16w101 ) : pad_d27();
            (16w88  , 16w102 ) : pad_d26();
            (16w89  , 16w103 ) : pad_d25();
            (16w90  , 16w104 ) : pad_d24();
            (16w91  , 16w105 ) : pad_d23();
            (16w92  , 16w106 ) : pad_d22();
            (16w93  , 16w107 ) : pad_d21();
            (16w94  , 16w108 ) : pad_d20();
            (16w95  , 16w109 ) : pad_d19();
            (16w96  , 16w110 ) : pad_d18();
            (16w97  , 16w111 ) : pad_d17();
            (16w98  , 16w112 ) : pad_d16();
            (16w99  , 16w113 ) : pad_d15();
            (16w100 , 16w114 ) : pad_d14();
            (16w101 , 16w115 ) : pad_d13();
            (16w102 , 16w116 ) : pad_d12();
            (16w103 , 16w117 ) : pad_d11();
            (16w104 , 16w118 ) : pad_d10();
            (16w105 , 16w119 ) : pad_d9();
            (16w106 , 16w120 ) : pad_d8();
            (16w107 , 16w121 ) : pad_d7();
            (16w108 , 16w122 ) : pad_d6();
            (16w109 , 16w123 ) : pad_d5();
            (16w110 , 16w124 ) : pad_d4();
            (16w111 , 16w125 ) : pad_d3();
            (16w112 , 16w126 ) : pad_d2();
            (16w113 , 16w127 ) : pad_d1();
            (16w114 , 16w128 ) : pad_d0();
        }
        const default_action = pad_none();
        size = 80;
    }

    apply {
        size_norm.apply();
        if (meta.normalized == 8w1) { ctr_size_normalized.count(0); }
        else                        { ctr_size_failopen.count(0); }
    }
}

/* THE POINT: pads are emitted after the LAST payload chunk. When the parser consumed
 * the whole payload the residual is empty, so the pad bytes are the last bytes before
 * the FCS -> a true Ethernet trailer, outside the IP datagram that ipv4.total_len
 * delimits. */
control EgDeparser(packet_out pkt, inout eg_headers_t hdr, in eg_meta_t meta,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.pay64); pkt.emit(hdr.pay32); pkt.emit(hdr.pay16);
        pkt.emit(hdr.pay8);  pkt.emit(hdr.pay4);  pkt.emit(hdr.pay2); pkt.emit(hdr.pay1);
        pkt.emit(hdr.pad64); pkt.emit(hdr.pad32); pkt.emit(hdr.pad16);
        pkt.emit(hdr.pad8);  pkt.emit(hdr.pad4);  pkt.emit(hdr.pad2); pkt.emit(hdr.pad1);
    }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;
