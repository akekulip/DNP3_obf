/* ============================================================================
 * ibspg_dnp3.p4 — Part 13 gate 13.2: REAL DNP3 classification on top of the
 *                 validated Part 12 HOLD_RESPONSE state machine.
 *                 (Tofino-1, TNA, bf-p4c 9.13.x)
 *
 * WHAT THIS IS. ibspg_hold_response.p4 (Part 12) proved CLRT normalization with
 * SYNTHETIC role markers: every packet carried an `ibspg_h` header whose `role`
 * byte told the pipeline what it was. This program deletes that crutch on the
 * host-traffic path and derives the same role byte from REAL DNP3/TCP/IP frames,
 * leaving the Part 9/11/12 scheduler — its register chain, its discipline, its
 * queue assignment — unchanged in shape.
 *
 * WHERE THE CLASSIFIER LIVES, AND WHY IT HAS TO LIVE THERE.
 *   research/ibspg_dnp3_replay/STAGE_BUDGET_AUDIT.md measured Part 12 at 12/12
 *   ingress MAU stages with EXACTLY ONE table per stage: a 12-deep serial
 *   dependency chain, not a resource shortage (36 SRAM, 0 TCAM). Nothing can be
 *   placed in front of that chain for free, and the documented "drop a telemetry
 *   register" reclaim lever was measured to reclaim ZERO stages. The only real
 *   headroom in the program is the parser (2 of many ingress states used).
 *   Therefore ALL DNP3 role classification is done in the INGRESS PARSER and
 *   handed to the MAU as a pre-computed `meta.role` byte — the exact same input
 *   the 12-stage chain consumed from `hdr.ib.role` in Part 12.
 *
 * CLASSIFICATION (parser-only; direction is cross-checked in the MAU gateways)
 *   ROLE_ARM   (6) : DNP3 application function code 1 (READ)      — master  -> outstation
 *   ROLE_RESP  (2) : DNP3 application function code 129 (RESPONSE)— outstation -> master
 *   ROLE_ACK   (7) : pure TCP ACK (payload 0, ACK=1, SYN=FIN=RST=0)
 *   ROLE_BLOCK (1) : ethertype 0x88C1 — the internal blocker token
 *   ROLE_BYPASS(0) : EVERYTHING ELSE — forwarded unchanged, never held, never arms
 *   Function code alone fixes the direction of ARM/RESP (129 only ever travels
 *   outstation->master, 1 only ever master->outstation), so ONE shared parse chain
 *   serves both directions; the MAU gateways add the `dir` cross-check for free.
 *   A pure ACK travels in BOTH directions, so ROLE_ACK is direction-agnostic in the
 *   parser and the deadline-arming gateway requires `dir == DIR_OUT`. A master-side
 *   pure ACK is still forwarded correctly because the egress port is the parser's
 *   `meta.fwd_port`, not a hard-coded constant.
 *
 * PARSER HARDENING (load-bearing — a switch window was lost to violating it).
 *   Idiom reused verbatim from research/tofino_dcrn_feasibility/p4/ack_delay/
 *   dcrn_defense1.p4: an unconditional `extract(dnp3_dl)` on a zero-payload pure
 *   TCP ACK reads past end-of-packet -> parser error -> the frame is DROPPED in
 *   pipeline, which silently broke transport (retransmit storm) on real hardware.
 *   The TNA parser cannot do arithmetic, matching an upstream header field in a
 *   DOWNSTREAM state ICEs, and there is only one 16-bit parser match register — so
 *   the length gate is a RANGE MATCH on ipv4.total_len in the SAME state that
 *   extracts TCP (total_len live-range = one state), with the DNP3 port check
 *   deliberately absent from the select (it is not needed: the 0x0564 magic and the
 *   function code decide, and a non-DNP3 payload is simply re-emitted identically).
 *   Two gates, both required:
 *     1. TCP-payload gate — descend only if the payload can hold everything this
 *        parser extracts: dnp3_dl(10) + dnp3_tp(1) + dnp3_app(2) = 13 bytes, i.e.
 *        total_len >= 20 + 4*data_offset + 13 (ihl==5 is enforced upstream).
 *     2. DNP3 LEN gate — after the 0x0564 magic, descend into transport/application
 *        only when the link LEN field says those bytes exist: LEN >= 8 (= 5 + 1
 *        transport + 2 application). LEN == 5 is a WELL-FORMED link-only frame
 *        (LINK_OTHER): it is valid, it is NOT malformed, and it is forwarded
 *        transparently as ROLE_BYPASS. So is any frame that fails either gate.
 *
 * WHAT CHANGED vs ibspg_hold_response.p4 (and nothing else changed)
 *   + parser: full eth/IPv4/TCP/TCP-options/DNP3 chain, producing meta.role,
 *     meta.dir, meta.dequeued, meta.fwd_port, meta.gen_in, meta.port_ok.
 *   + `to_host()` -> `to_fwd()`: the egress port is the parser-computed peer port,
 *     so the SAME action serves the immediately-forwarded ACK, the released
 *     response, the forwarded READ and all bypass traffic (fewer distinct actions,
 *     same stage shape).
 *   ~ ROLE_ARM is now a REAL DNP3 READ, so it is FORWARDED to the outstation
 *     instead of being consumed (Part 12 dropped its synthetic ARM packet). A
 *     dropped READ would break the live transaction.
 *   ~ ROLE_BYPASS is FORWARDED instead of dropped (Part 12 dropped all non-IBSPG
 *     traffic to isolate the microbench; a real DNP3 session needs ARP, the TCP
 *     handshake, DIRECT_OPERATE, and the master's own ACKs to pass through).
 *     Traffic from any port other than dp8/dp9/dp11 is still dropped.
 *   ~ generation source: a real frame has no `hdr.ib.gen` byte. `meta.gen_in` is
 *     the DNP3 APPLICATION CONTROL byte (FIR/FIN/CON/UNS + the 4-bit application
 *     sequence, which increments per poll — DNP3's own per-transaction generation)
 *     for DNP3 frames, and `hdr.ib.gen` for blocker tokens. The ARM writes it to
 *     reg_gen exactly as Part 12 did; token staleness is checked exactly as Part 12
 *     did. CONTROL-PLANE/INJECTOR REQUIREMENT: a blocker token must carry
 *     gen = the application control byte of the READ whose transaction it guards.
 *   ~ the ACK-qualification gateway drops `slot` and `gen` (a pure TCP ACK carries
 *     neither a slot nor a DNP3 application sequence). It gains `dir == DIR_OUT`.
 *     Qualification is therefore: fresh, pure ACK, from the outstation, transaction
 *     armed. Generation safety itself — stale blocker tokens self-terminating — is
 *     untouched.
 *   ~ G is no longer carried in `hdr.ib.seq` of the ACK (a real ACK has no such
 *     field). It comes from `tbl_guard`, whose default action parameter the control
 *     plane can rewrite, so a G sweep still needs no recompile.
 *   ~ ethertype 0x88C1 is now FORCED to ROLE_BLOCK regardless of the role byte in
 *     the token header. This STRENGTHENS internal-token isolation: an 0x88C1 frame
 *     can only ever reach `to_block()` or `drop_pkt()`, never a host port.
 *   = unchanged: the three state registers and their serial order, one
 *     RegisterAction with one unconditional call site each, the metadata
 *     write-enable pattern, the four sparse timestamp registers, the ternary
 *     sign-bit expiry table, the pass-budget fail-open, the queue assignment
 *     (Q_BLOCK qid7 HIGH > Q_RESP qid1 LOW), and byte preservation.
 *
 * BYTE PRESERVATION. No field of any frame is written except the blocker token's
 * own pass-budget counter (`hdr.ib.seq`, an internal frame that never leaves the
 * pipe). Every extracted header is re-emitted in extraction order by the ingress
 * deparser; everything not extracted stays residual and is emitted automatically.
 * Egress is a pass-through and is carried over from Part 12 unchanged.
 *
 * DEADLINE TEST — why a subtraction and a sign bit, not a compare (carried from
 * Part 12, do NOT reintroduce a slice): meta.age = now - deadline (32-bit wrapping
 * ns), expired iff age[31:31]==0 and a deadline is armed. A bit-slice of a 32-bit
 * ARITHMETIC field, in a gateway OR in an assignment, imposes a [31:31]/[30:0]
 * split on every field sharing its PHV cluster and allocation then fails outright
 * (measured on 9.13.1: "12 field slices remain unallocated"). The ternary match
 * unit reads the whole container under a TCAM mask and creates no slicing
 * constraint.
 *
 * STATE-MACHINE DISCIPLINE (verbatim from Parts 9/11/12 — do not relax):
 *   - state registers (reg_gen -> reg_active -> reg_deadline) in that serial stage
 *     order, each ONE RegisterAction with ONE unconditional execute() call site,
 *     driven by upstream metadata write-enable/value fields.
 *   - timestamp registers are ONE RA / ONE guarded call site each.
 *   - all flags are bit<8>; every compare is isolated on its own line into its own
 *     metadata flag (no gateway exceeds the 44-bit predicate budget).
 *   - timestamp source ig_intr_md.ingress_mac_tstamp[31:0] (ns on TF1).
 *
 * SCOPE OF THIS GATE: ONE FIXED SLOT (slot 0), exactly as Parts 9/11/12. No
 * flow_id hash, no admitted-flow->slot lookup table — those are the two most
 * expensive new stages and belong to a later gate.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK(1) private marker, internal only */
const bit<16> ETHERTYPE_IPV4        = 0x0800;
const bit<8>  IP_PROTO_TCP          = 8w6;

/* ---- DNP3 ---- */
const bit<16> DNP3_START       = 0x0564;   /* link-layer start magic                     */
const bit<8>  DNP3_FC_READ     = 8w1;      /* master -> outstation : arms the transaction */
const bit<8>  DNP3_FC_RESPONSE = 8w129;    /* outstation -> master : the held frame       */

/* ---- roles (numbering kept compatible with Parts 9/11/12) ---- */
const bit<8> ROLE_BYPASS = 0;  /* forwarded unchanged, never held, never arms       */
const bit<8> ROLE_BLOCK  = 1;  /* 0x88C1 : enqueue Q_BLOCK (qid7); deadline-checking */
const bit<8> ROLE_RESP   = 2;  /* DNP3 RESPONSE : enqueue Q_RESP (qid1); released   */
const bit<8> ROLE_ARM    = 6;  /* DNP3 READ     : arms the slot, clears the deadline */
const bit<8> ROLE_ACK    = 7;  /* pure TCP ACK  : forwarded NOW; arms the deadline   */

/* ---- direction ---- */
const bit<8> DIR_MASTER = 0;   /* arrived from the master side (dp9)                 */
const bit<8> DIR_OUT    = 1;   /* arrived from the outstation side (dp11) or loopback */

/* ---- ports (compile constants; the run pins the measured dev_ports) ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)          */
const PortId_t PORT_VISION = 9w9;   /* master side (dp9) — ACK + released RESPONSE out    */
const PortId_t PORT_HULK   = 9w11;  /* outstation side (dp11) — READ + token injection in */

/* ---- queues on PORT_L (control plane sets the strict-priority levels) ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH (max_priority=7) : blocker reservoir   */
const bit<5> QID_RESP  = 5w1;   /* LOW  (max_priority=0) : response held queue */

/* ---- default guard interval G (ns). Control plane may rewrite tbl_guard's
 * default action parameter at runtime, so a G sweep needs no recompile.
 * 25 ms sits above the SEL-751 corpus CLRT p95 of 16.5 ms (median 12.9 ms). ---- */
const bit<32> G_DEFAULT_NS = 32w25000000;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* internal blocker token: seq = pass budget, gen = transaction generation.
 * role/slot are kept for wire compatibility with the Part 9/11/12 injector but are
 * NOT read — an 0x88C1 frame is forced to ROLE_BLOCK. */
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

/* TCP options carried verbatim. One fixed-size header per data_offset (the TNA
 * parser cannot advance by a runtime amount); exactly one is valid. NEVER read in
 * the MAU — extracted only so the DNP3 header can be reached, then re-emitted.
 * data_offset 5..8 covers a bare crafted frame (5) and the Linux TCP-timestamp
 * case (8), which is what every frame in the Gate 13.1 corpus uses. */
header tcp_opt4_h  { bit<32> data; }
header tcp_opt8_h  { bit<64> data; }
header tcp_opt12_h { bit<96> data; }

/* DNP3 data-link header, 10 B. `start` is the two magic bytes as one 16-bit field
 * so the magic and the LEN gate fit the one 16-bit + two 8-bit parser match
 * registers in a single select. */
header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }                      /* transport header, 1 B      */
header dnp3_app_h { bit<8> app_control; bit<8> func_code; } /* only what classification needs */

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
    /* ---- parser-computed classification (this is the Part 13 change) ---- */
    bit<8>  role;          /* ROLE_* — what hdr.ib.role used to be                */
    bit<8>  dir;           /* DIR_MASTER / DIR_OUT                                */
    bit<9>  fwd_port;      /* transparent-forward peer port for this ingress port */
    bit<8>  port_ok;       /* 1 if the ingress port is dp8 / dp9 / dp11           */
    bit<8>  gen_in;        /* generation carried by this frame                    */

    bit<8>  dequeued;      /* 1 if ingress_port == PORT_L (packet just dequeued)  */
    bit<32> ts32;          /* low 32 bits of ingress_mac_tstamp                   */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 as dequeued (fail-open watchdog)*/
    bit<32> guard_g;       /* G in ns, from tbl_guard                             */

    /* state-register write drivers (set upstream of each single execute) */
    bit<8>  gen_we;    bit<8>  gen_val;
    bit<8>  active_we; bit<8>  active_val;
    bit<8>  dl_we;     bit<32> dl_val;

    /* state-register read results */
    bit<8>  gen_now;
    bit<8>  active_now;
    bit<32> dl_now;

    /* derived */
    bit<8>  gen_mismatch;  /* 1 if gen_now != gen_in            */
    bit<8>  ack_ok;        /* 1 if this fresh ACK qualifies to arm the deadline */
    bit<8>  dl_armed;      /* 1 if dl_now != 0                  */
    bit<32> age;           /* now - deadline (wrapping)         */
    bit<8>  expired;       /* 1 if armed and age >= 0 (set by tbl_deadline_expiry) */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;  /* fresh BLOCK admitted (timeline start)             */
    bit<8>  ev_ack_arm;      /* qualifying ACK forwarded + deadline armed (t_ack) */
    bit<8>  ev_block_term;   /* a BLOCK terminated (any cause)                    */
    bit<8>  ev_resp_release; /* looped RESP released to the master                */
}

/* ============================ ingress parser =============================
 * Every role decision this program makes is taken here. The MAU sees only
 * meta.role / meta.dir / meta.dequeued / meta.fwd_port / meta.gen_in. */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* NOTE — the six classification fields (role, dir, fwd_port, port_ok,
         * gen_in, dequeued) are deliberately NOT initialized here. Tofino's parser
         * has no clear-on-write: assigning a field in `start` and again in a later
         * state on the same path is a hard compile error ("this re-assignment is not
         * supported by Tofino"). Each is instead assigned exactly ONCE per path, and
         * every default is the all-zero encoding the compiler's own metadata
         * initialization already supplies: ROLE_BYPASS=0, DIR_MASTER=0, port_ok=0,
         * gen_in=0, dequeued=0. fwd_port is written on every path that sets
         * port_ok=1; a frame from any other port is dropped before it is read. */
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.guard_g         = 32w0;
        meta.gen_we          = 8w0; meta.gen_val    = 8w0;
        meta.active_we       = 8w0; meta.active_val = 8w0;
        meta.dl_we           = 8w0; meta.dl_val     = 32w0;
        meta.gen_now         = 8w0;
        meta.active_now      = 8w0;
        meta.dl_now          = 32w0;
        meta.gen_mismatch    = 8w0;
        meta.ack_ok          = 8w0;
        meta.dl_armed        = 8w0;
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
     * downstream state ICEs. See the header comment.
     *   pure ACK      : total_len == 20 + 4*data_offset, ACK=1, SYN=FIN=RST=0
     *   DNP3-capable  : total_len >= 20 + 4*data_offset + 13, SYN=FIN=RST=0
     * Anything else (short payload, SYN/FIN/RST, data_offset > 8) falls through to
     * `accept` and is forwarded transparently as ROLE_BYPASS. */
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
        /* the DNP3 application control byte (FIR/FIN/CON/UNS + 4-bit application
         * sequence) is this transaction's generation. */
        meta.gen_in = hdr.dnp3_app.app_control;
        transition select(hdr.dnp3_app.func_code) {
            DNP3_FC_RESPONSE : set_role_resp;
            DNP3_FC_READ     : set_role_arm;
            default          : accept;   /* DIRECT_OPERATE etc. -> ROLE_BYPASS */
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

    /* ================= state registers (3) — one RA, one call site each ====
     * Metadata-write-enable pattern: the RA ALWAYS returns the old value and
     * conditionally overwrites v with a metadata value when the write-enable is 1.
     * The SALU predicate is on a METADATA field (not on v), within the TF1
     * stateful-ALU operand budget. */

    Register<bit<8>, bit<1>>(1, 0) reg_gen;        /* current generation */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.gen_we == 8w1) { v = meta.gen_val; }
        }
    };

    Register<bit<8>, bit<1>>(1, 0) reg_active;     /* txn armed */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.active_we == 8w1) { v = meta.active_val; }
        }
    };

    /* THE Part-12 register: armed by a qualifying ACK (t_ack + G), read by every
     * blocker pass. Same single-call-site RMW shape as the two above, 32-bit. */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (meta.dl_we == 8w1) { v = meta.dl_val; }
        }
    };

    /* ================= fixed-slot timestamp registers (4) =================
     * SPARSE latency capture, write-if-zero = first occurrence. Each is ONE RA with
     * ONE guarded call site (this exact form validated on silicon in Parts 9/11).
     *   G_observed      = reg_ts_first_resp_release - reg_ts_ack_arm   <-- the result
     *   deadline error  = G_observed - G
     *   release tail    = reg_ts_first_resp_release - reg_ts_block_term */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* t_ack — the deadline base, and the left edge of the observed interval */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* first blocker termination = the instant the reservoir starts draining */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* first response released = the right edge of the observed interval */
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
    /* transparent forward to this frame's peer port: the immediate ACK, the
     * released RESPONSE, the forwarded READ, and all bypass traffic. */
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;     /* run egress -> emit byte-identical frame */
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* ================= guard interval G =================
     * Part 12 carried G in hdr.ib.seq of the synthetic ACK. A real pure TCP ACK has
     * no such field, so G comes from this table's default action parameter, which
     * the control plane can rewrite between trials (no recompile for a G sweep). */
    action set_guard(bit<32> g) { meta.guard_g = g; }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(G_DEFAULT_NS);
        size = 1;
    }

    /* ================= deadline expiry decision =================
     * expired  <=>  a deadline is armed AND (now - deadline) >= 0, i.e. the sign bit
     * of the wrapping difference is 0.  Ternary match, NOT a bit-slice — see the
     * header comment; one TCAM entry, which the compiler folds into gateway logic. */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = {
            meta.dl_armed : exact;
            meta.age      : ternary;
        }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (8w1, 32w0 &&& 32w0x80000000) : mark_expired();
        }
        size = 2;
    }

    apply {
        if (meta.port_ok == 8w0) {
            /* isolate the pipeline: only dp8 / dp9 / dp11 are in the topology */
            ctr_bypass.count(8w1);
            drop_pkt();
        } else {
            /* ---------- classify (early) ----------
             * meta.role / meta.dir / meta.dequeued / meta.fwd_port / meta.gen_in
             * were all computed in the parser. */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            /* Kept verbatim from Part 12, but note the changed precondition: hdr.ib
             * is valid ONLY on blocker tokens now, so on every other frame this
             * compares a stale tagalong container and meta.budget_zero is MEANINGLESS.
             * That is safe because budget_zero has exactly two consumers and both sit
             * inside a `meta.role == ROLE_BLOCK` branch, and ROLE_BLOCK implies the
             * token header is valid. Do not read budget_zero outside a ROLE_BLOCK
             * branch without first re-qualifying it. */
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }  /* isolated 32b compare */
            tbl_guard.apply();                                   /* meta.guard_g = G     */

            /* ---------- ARM sets gen + active, and CLEARS any stale deadline ------
             * ARM is a real DNP3 READ from the master side. */
            if (meta.dequeued == 8w0 && meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                meta.gen_we    = 8w1; meta.gen_val    = meta.gen_in;
                meta.active_we = 8w1; meta.active_val = 8w1;
                meta.dl_we     = 8w1; meta.dl_val     = 32w0;
            }

            /* ---------- STAGE g: reg_gen read / conditional write ---------- */
            meta.gen_now = gen_rmw.execute(0);
            if (meta.gen_now != meta.gen_in) { meta.gen_mismatch = 8w1; }  /* isolated 8b */

            /* ---------- active clear driver: BLOCK terminates on stale/timeout ----
             * (deadline expiry does NOT clear active: the response is still queue-
             * resident and its own release path must stay reachable.) */
            if (meta.dequeued == 8w1 && meta.role == ROLE_BLOCK) {
                if (meta.gen_mismatch == 8w1 || meta.budget_zero == 8w1) {
                    meta.active_we = 8w1; meta.active_val = 8w0;
                }
            }

            /* ---------- STAGE a: reg_active read / conditional write ---------- */
            meta.active_now = active_rmw.execute(0);

            /* ---------- deadline write driver: a QUALIFYING fresh ACK only --------
             * qualification = pure TCP ACK, from the outstation, transaction armed.
             * (Part 12 also checked slot and generation; a pure TCP ACK carries
             * neither — it has no slot field and no DNP3 application sequence.)
             * A non-qualifying ACK is still forwarded but must not move the release
             * time of anything. */
            if (meta.dequeued == 8w0 && meta.role == ROLE_ACK && meta.dir == DIR_OUT
                && meta.active_now == 8w1) {
                meta.ack_ok = 8w1;
                meta.dl_we  = 8w1;
                meta.dl_val = meta.ts32 + meta.guard_g;   /* deadline = t_ack + G */
            }

            /* ---------- STAGE d: reg_deadline read / conditional write ---------- */
            meta.dl_now = deadline_rmw.execute(0);

            /* ---------- deadline expiry test (subtract + sign bit) ---------- */
            if (meta.dl_now != 32w0) { meta.dl_armed = 8w1; }   /* isolated 32b compare */
            meta.age = meta.ts32 - meta.dl_now;
            tbl_deadline_expiry.apply();                        /* sets meta.expired */

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
                    /* a real DNP3 READ: it armed the slot above and must reach the
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
                    if (meta.active_now == 8w0 || meta.gen_mismatch == 8w1) {
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

            /* ================= SPARSE latency capture (single call site each) ==== */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_resp_release == 8w1) { ts_first_resp_w.execute(0); }
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emission order == extraction order, so every forwarded frame is byte-identical.
 * Exactly one of {ib} / {ipv4 ...} is valid; unextracted bytes stay residual and
 * are emitted automatically. */
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

/* ============================ egress ====================================
 * Carried over from Part 12 unchanged. The immediately-forwarded ACK, the
 * forwarded READ, the released RESPONSE and all bypass traffic traverse egress
 * (bypass_egress=0). Egress extracts only ethernet: everything after it is
 * residual and is re-emitted verbatim, so the frame is byte-identical to what the
 * ingress deparser produced. No field is modified anywhere in egress. */
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
