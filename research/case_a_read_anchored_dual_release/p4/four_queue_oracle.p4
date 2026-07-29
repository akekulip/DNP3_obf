/* ============================================================================
 * four_queue_oracle.p4 — BEHAVIOURAL four-queue dequeue oracle for Tofino-1.
 *
 * PURPOSE. Prove BEHAVIOURALLY that the Traffic Manager serves
 *
 *     Q_ABLOCK(qid 7) > Q_ACK(qid 6) > Q_RBLOCK(qid 5) > Q_RESP(qid 4)
 *
 * in strict priority. A max_priority READBACK is NOT proof — it says what was
 * written, not what the scheduler did. The IBSPG root-cause repair
 * (research/ibspg_root_cause_repair/) established that the WRONG priority field
 * (min_priority, inert unless min_rate_enable) had been set for an entire
 * campaign and that the readback of it looked perfectly healthy while the
 * scheduler was actually doing a 50/50 DWRR split. This program exists so the
 * ordering claim rests on observed dequeue order instead.
 *
 * This is a MEASUREMENT INSTRUMENT, not a defense. It is deliberately NOT
 * derived from case_a_dual_release_skeleton.p4:
 *   - that program's release path hardcodes PORT_VISION, and oracle traffic must
 *     never touch the Vision <-> relay path;
 *   - that program classifies by DNP3/TCP structure, which would make the oracle
 *     depend on the very parser and ACK predicate it is supposed to be
 *     independent of.
 * Nothing here parses IP, TCP or DNP3. There is no deadline, no register, no
 * recirculation loop and no pktgen. The ONLY thing under test is the scheduler.
 *
 * ---------------------------------------------------------------------------
 * TOPOLOGY — ISOLATED, HULK ONLY.
 *
 *     Hulk (dp11) --inject--> [ingress: classify role -> qid] --> dp8 queues
 *                                                                    |
 *                                        (held while scheduling_enable = False)
 *                                                                    |
 *                                                            release (CP)
 *                                                                    |
 *                                   dp8 egress -> MAC-near loopback -+
 *                                                                    |
 *                             [ingress: dequeued == 1 -> pass = 1] --+
 *                                                                    |
 *                                                    dp11 --capture--> Hulk
 *
 * dp9 (Vision) and dp64 (the physical SEL-751 relay leg) DO NOT APPEAR IN THIS
 * PROGRAM AT ALL — not as a constant, not as a parser transition, not as an
 * action parameter. The isolation is STRUCTURAL, not a runtime check: the only
 * egress-port assignments in the whole file are the compile-time constants
 * PORT_L and PORT_HULK, and ucast_egress_port is never assigned from metadata,
 * from a header field, or from table action data. See to_ablock()/to_ack_q()/
 * to_rblock()/to_resp() and to_hulk() below — those five actions are the
 * complete set of non-drop fates a packet can have.
 *
 * EXACTLY ONE LOOPBACK PASS. A frame arriving on dp11 is enqueued to dp8. A
 * frame arriving on dp8 is forwarded to dp11 and is never re-enqueued to dp8:
 * the dequeued branch of apply{} calls only to_hulk(). Nothing loops repeatedly,
 * so there is no pass budget, no fail-open watchdog and no generation register.
 *
 * ---------------------------------------------------------------------------
 * WHY THE CAPTURE ORDER IS THE DEQUEUE ORDER (the oracle's validity argument)
 *
 * Every stage downstream of the dp8 dequeue is order-preserving and single-file:
 *   dp8 queue dequeue  (<- THE ORDER BEING MEASURED)
 *     -> dp8 egress MAC -> MAC-near loopback -> dp8 ingress MAC
 *     -> ingress pipeline (in-order for packets destined to one egress queue)
 *     -> dp11 queue QID_FWD  (ONE queue, FIFO — no arbitration)
 *     -> dp11 egress MAC -> Hulk NIC -> tcpdump
 * The four queues under test are the ONLY point in the path where more than one
 * queue competes, so any reordering observed at the capture is attributable to
 * the dp8 scheduler. All released traffic converges on a single dp11 queue
 * precisely so that the return path cannot reorder.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE DOES NOT ANSWER. It says nothing about deadlines, about
 * recirculation, or about reservoir depth. In particular a finite preloaded
 * non-recirculating oracle CANNOT reproduce the K=1 empty-gap failure, because
 * that failure is a recirculation-timing phenomenon this program deliberately
 * excludes. See reports/FOUR_QUEUE_ORACLE_REPORT.md §"Scoping".
 *
 * NOT CLAIMED: nothing here has been loaded or run. Authored off-switch; the
 * switch is running dnp3_timing_normalizer_pktgen and was not touched.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertype -----------------------------------------------------------
 * 0x88C2 is the ORACLE frame type. It is deliberately one value away from, and
 * distinct from, 0x88C1 (the IBSPG blocker-token marker used by the defense
 * programs) so that an oracle frame and a blocker token can never be confused
 * by a parser, a capture filter or a human reading a hex dump. This program
 * does not know about 0x88C1 at all: such a frame is not oracle traffic and is
 * dropped by the same path as any other non-oracle frame. */
const bit<16> ETHERTYPE_ORACLE = 0x88C2;

/* ---- ports — the COMPLETE set. dp9 and dp64 are absent by construction. ---- */
const PortId_t PORT_L    = 9w8;   /* dp8: MAC-near loopback; carries the four queues */
const PortId_t PORT_HULK = 9w11;  /* dp11: the ONLY host port. Inject and capture.   */

/* ---- the four queues under test, on PORT_L -------------------------------
 * Strict ordering ABLOCK > ACK > RBLOCK > RESP is CONTROL-PLANE configuration
 * (tf1.tm.queue.sched_cfg max_priority). QUEUE ID DOES NOT IMPLY PRIORITY —
 * P4 only selects the qid. That the qid numbers happen to descend with priority
 * here is a readability choice, not a mechanism. */
const bit<5> QID_ABLOCK = 5w7;
const bit<5> QID_ACK    = 5w6;
const bit<5> QID_RBLOCK = 5w5;
const bit<5> QID_RESP   = 5w4;

/* the single master-facing FIFO every released packet returns on. ONE queue, so
 * the return path is FIFO and cannot reorder what the dp8 scheduler produced. */
const bit<5> QID_FWD = 5w0;

/* ---- roles, as carried in the oracle header ------------------------------ */
const bit<8> ROLE_ABLOCK    = 8w1;
const bit<8> ROLE_HELD_ACK  = 8w2;
const bit<8> ROLE_RBLOCK    = 8w3;
const bit<8> ROLE_HELD_RESP = 8w4;

/* ---- counter slots (compile-time constants only) -------------------------
 * ONE Counter object. Every count() site below is in a MUTUALLY EXCLUSIVE
 * branch of apply{} or in an action of the one classification table, because
 * bf-p4c hard-errors on non-mutually-exclusive count() sites on a single
 * Counter object. */
const bit<8> C_DROP_BAD_PORT   = 8w0;  /* ingress port is not dp11 or dp8       */
const bit<8> C_DROP_NON_ORACLE = 8w1;  /* not ethertype 0x88C2                  */
const bit<8> C_ENQ_ABLOCK      = 8w2;  /* injected, role 1 -> Q_ABLOCK          */
const bit<8> C_ENQ_ACK         = 8w3;  /* injected, role 2 -> Q_ACK             */
const bit<8> C_ENQ_RBLOCK      = 8w4;  /* injected, role 3 -> Q_RBLOCK          */
const bit<8> C_ENQ_RESP        = 8w5;  /* injected, role 4 -> Q_RESP            */
const bit<8> C_DROP_BAD_ROLE   = 8w6;  /* oracle frame with role outside 1..4   */
const bit<8> C_RELEASED        = 8w7;  /* dequeued from dp8, forwarded to dp11  */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* The oracle header. 8 bytes, immediately after the ethertype. Every field must
 * survive to the capture so the analyzer can reconstruct the dequeue order:
 *   trial_id       groups a capture into trials (counters are cumulative)
 *   role           1..4, selects the queue; also the analyzer's ordering key
 *   per_role_seq   identifies a packet WITHIN its role (duplicate detection)
 *   global_inj_seq the injection order (randomized), so the analyzer can prove
 *                  the observed order is NOT merely the injection order
 *   pass           0 as injected; ingress sets 1 on the loopback pass, so a
 *                  captured frame with pass == 0 proves a packet reached the
 *                  host WITHOUT traversing the queues — a silent short-circuit
 *                  the analyzer would otherwise score as a valid dequeue. */
header oracle_h {
    bit<16> trial_id;
    bit<8>  role;
    bit<16> per_role_seq;
    bit<16> global_inj_seq;
    bit<8>  pass;
}

struct headers_t {
    ethernet_h eth;
    oracle_h   oracle;
}

/* The frame is padded to 64 bytes by the injector. The pad is NEVER extracted;
 * it stays in the residual and the deparser re-emits it verbatim. */
struct ig_meta_t {
    bit<8> port_ok;    /* 1 = arrived on dp11 or dp8                       */
    bit<8> dequeued;   /* 1 = arrived on dp8, i.e. this is the loopback pass */
    bit<8> is_oracle;  /* 1 = ethertype 0x88C2 and the oracle header parsed  */
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* port_ok, dequeued and is_oracle are deliberately NOT initialized here.
         * The TNA parser has no clear-on-write, so assigning a field in `start`
         * and again later on the same path is a hard compile error. Every
         * default is the all-zero encoding the compiler's own metadata init
         * supplies, and every zero default is the SAFE one (not a valid port,
         * not dequeued, not oracle traffic). */
        transition select(ig_intr_md.ingress_port) {
            PORT_HULK : from_host;
            PORT_L    : from_loopback;
            default   : accept;   /* port_ok stays 0 -> dropped in the MAU */
        }
    }

    state from_host     { meta.port_ok = 8w1; transition parse_eth; }
    state from_loopback { meta.port_ok = 8w1; meta.dequeued = 8w1; transition parse_eth; }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_ORACLE : parse_oracle;
            default          : accept;   /* is_oracle stays 0 -> dropped */
        }
    }

    state parse_oracle {
        pkt.extract(hdr.oracle);
        meta.is_oracle = 8w1;
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

    Counter<bit<64>, bit<8>>(32w8, CounterType_t.PACKETS) ctr_oracle;

    /* ---- the five non-drop fates. Note that ucast_egress_port is assigned
     * ONLY from the compile-time constants PORT_L and PORT_HULK — never from
     * metadata, a header field or action data. This is what makes the dp9/dp64
     * isolation structural rather than a runtime check. ---- */
    action to_ablock() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ABLOCK;
        ig_tm_md.bypass_egress     = 1w1;   /* held frames never traverse egress */
        ctr_oracle.count(C_ENQ_ABLOCK);
    }
    action to_ack_q() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ACK;
        ig_tm_md.bypass_egress     = 1w1;
        ctr_oracle.count(C_ENQ_ACK);
    }
    action to_rblock() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RBLOCK;
        ig_tm_md.bypass_egress     = 1w1;
        ctr_oracle.count(C_ENQ_RBLOCK);
    }
    action to_resp() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
        ctr_oracle.count(C_ENQ_RESP);
    }
    action drop_bad_role() {
        ig_dprsr_md.drop_ctl = 3w1;
        ctr_oracle.count(C_DROP_BAD_ROLE);
    }

    /* the ONE classification table: role byte -> queue. Exact match, four const
     * entries, drop by default. A role outside 1..4 cannot reach a queue. */
    table tbl_enqueue {
        key = { hdr.oracle.role : exact; }
        actions = { to_ablock; to_ack_q; to_rblock; to_resp; drop_bad_role; }
        const default_action = drop_bad_role();
        const entries = {
            ROLE_ABLOCK    : to_ablock();
            ROLE_HELD_ACK  : to_ack_q();
            ROLE_RBLOCK    : to_rblock();
            ROLE_HELD_RESP : to_resp();
        }
        size = 8;
    }

    /* the released packet's return leg: ONE host port, ONE FIFO. */
    action to_hulk() {
        ig_tm_md.ucast_egress_port = PORT_HULK;
        ig_tm_md.qid               = QID_FWD;
        ig_tm_md.bypass_egress     = 1w0;   /* traverses the pass-through egress */
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    apply {
        if (meta.port_ok == 8w0) {
            /* not dp11 and not dp8 — nothing else is topology for this oracle */
            ctr_oracle.count(C_DROP_BAD_PORT);
            drop_pkt();
        } else if (meta.is_oracle == 8w0) {
            /* not 0x88C2. Dropped rather than forwarded, so the oracle cannot
             * perturb, or be perturbed by, any other traffic on dp11. */
            ctr_oracle.count(C_DROP_NON_ORACLE);
            drop_pkt();
        } else if (meta.dequeued == 8w0) {
            /* FRESH from Hulk: classify the role and park it on that queue. */
            tbl_enqueue.apply();
        } else {
            /* THE LOOPBACK PASS: this packet has just been dequeued by the TM.
             * Stamp pass = 1 so the capture proves it went through a queue, and
             * forward it to Hulk. It is NEVER re-enqueued to dp8, which is what
             * bounds every packet to exactly one pass. */
            hdr.oracle.pass = 8w1;
            to_hulk();
            ctr_oracle.count(C_RELEASED);
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emission order == extraction order. The 42-byte pad was never extracted, so
 * it rides in the residual and is re-emitted verbatim: the only byte this
 * program ever changes on the wire is oracle.pass. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.oracle);
    }
}

/* ============================ egress ====================================
 * Byte-preserving pass-through. Only the released packets traverse egress
 * (bypass_egress = 0 on to_hulk() alone); everything parked on dp8 skips it.
 * Egress extracts only ethernet, so everything after it is residual and is
 * re-emitted verbatim. NO EGRESS STATE OF ANY KIND. */
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
