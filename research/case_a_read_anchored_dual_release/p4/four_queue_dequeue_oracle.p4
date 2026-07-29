/* ============================================================================
 * four_queue_dequeue_oracle.p4 — FOUR-QUEUE on-chip TM dequeue-ORDER oracle
 * for Tofino-1 (TNA).
 *
 * ---------------------------------------------------------------------------
 * WHAT IT PROVES (and what it does not)
 *
 * It records, ON CHIP and at nanosecond resolution, the ORDER in which packets
 * dequeue from FOUR TM queues that share one port, so the claim
 *
 *     Q_ABLOCK(qid 7) > Q_ACK(qid 6) > Q_RBLOCK(qid 5) > Q_RESP(qid 4)
 *
 * rests on OBSERVED SCHEDULER BEHAVIOUR rather than on a `max_priority`
 * readback. A readback says only what was WRITTEN. The IBSPG root-cause repair
 * (research/ibspg_root_cause_repair/) established that an entire campaign had
 * been run with the WRONG priority field set (`min_priority`, which is inert
 * unless `min_rate_enable` is true) while its readback looked perfectly
 * healthy and the scheduler was actually doing a fair DWRR split.
 *
 * It says NOTHING about reservoir depth, recirculation empty gaps, deadlines,
 * or the defense itself. A finite, preloaded, NON-recirculating oracle cannot
 * reproduce the K=1 empty-gap failure, because that failure is a recirculation
 * TIMING phenomenon this program deliberately excludes. Those remain separate
 * evidence (Part 9 / Part 12). See reports/FOUR_QUEUE_DEQUEUE_ORACLE_REPORT.md.
 *
 * ---------------------------------------------------------------------------
 * RELATIONSHIP TO PRIOR WORK
 *
 * Methodology is the two-queue P3 oracle, extended from two queues to four:
 *     research/ibspg_root_cause_repair/ibspg_dequeue_oracle.p4   (UNTOUCHED)
 * From it, verbatim in structure: the monotonic saturating `reg_event_ctr`, the
 * `reg_overflow` tally, the trace register arrays written at a dynamic index,
 * the one-RegisterAction-per-register placement discipline, the in-range 8-bit
 * flag, `ingress_mac_tstamp[31:0]` as the dequeue-time proxy, and "record then
 * DROP" so each packet takes exactly one pass.
 *
 * It is a NEW program, not an edit of that one, because the two-queue result
 * (P3_FINITE_BACKLOG_ORACLE_RESULT.md) is prior evidence that must remain
 * exactly as it was when it was produced.
 *
 * It also differs from p4/four_queue_oracle.p4 (the host-injected sibling in
 * this same directory) in the one respect that matters operationally: THERE IS
 * NO HOST. Packets are generated inside the chip by the Tofino packet
 * generator, and the dequeue order is read out of registers over bfrt. dp11 is
 * not configured, Hulk is not involved, and nothing needs a raw socket or a
 * packet capture.
 *
 * ---------------------------------------------------------------------------
 * TOPOLOGY — TWO PORTS, BOTH INTERNAL. NO HOST PORT APPEARS AT ALL.
 *
 *   pktgen (dp68) --128 generated pkts--> [ingress: packet_id -> role -> qid]
 *                                                       |
 *                                            dp8 queues 7 / 6 / 5 / 4
 *                                     (all four held by the dp8 PORT shaper)
 *                                                       |
 *                                          ONE release write opens the gate
 *                                                       |
 *                                    dp8 egress -> MAC-near loopback -+
 *                                                                     |
 *                    [ingress: ingress_port == dp8 => it JUST DEQUEUED]
 *                     record (trial_id, role, pkt_id, tstamp) at the next
 *                     monotonic trace index, then DROP. Single pass.
 *
 * dp9 (Vision), dp11 (Hulk) and dp64 (the physical SEL-751 leg) DO NOT APPEAR
 * IN THIS FILE — not as a constant, not as a parser transition, not as action
 * data. The isolation is STRUCTURAL: `ig_tm_md.ucast_egress_port` is assigned
 * from exactly ONE compile-time immediate, PORT_L, in exactly four actions, and
 * is never assigned from metadata, a header field, or table action data. That
 * is checkable in pipe/context.json rather than merely asserted here.
 *
 * PORT_PGEN is an INGRESS-ONLY constant: it is used in one parser select and
 * nowhere else. No packet can ever be sent to it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE TRACE ORDER IS THE DEQUEUE ORDER
 *
 * The four queues are the only point in the path where more than one queue
 * competes. Downstream of the dp8 dequeue every stage is single-file:
 *     dp8 dequeue (<- THE ORDER BEING MEASURED)
 *       -> dp8 egress MAC -> MAC-near loopback -> dp8 ingress MAC
 *       -> ingress pipeline -> reg_event_ctr allocates the next index -> DROP
 * `reg_event_ctr` is a single SALU: two packets cannot receive the same index,
 * and indices are handed out in pipeline arrival order. So trace[0..n-1] read
 * in index order IS the dequeue order.
 *
 * ---------------------------------------------------------------------------
 * WHY THE ROLE IS STAMPED INTO THE FRAME
 *
 * All 128 generated packets are byte-identical copies of ONE packet-buffer
 * template. Their only distinguishing mark is `packet_id` in the 6-byte
 * hardware packet-generator header — and that header is stripped at the ingress
 * deparser (it is extracted and never emitted), so it does NOT survive the trip
 * through the queue. Therefore the enqueue pass writes both the role and the
 * packet_id into the oracle header, where they DO survive the loopback and can
 * be read back on the return pass. Recording both is deliberate: `role` is what
 * the classification table actually did, `pkt_id` is what the hardware actually
 * generated, and the analyzer cross-checks the two against the control plane's
 * mapping file. A mismatch means the mapping and the silicon disagree.
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
 * 0x88C3 is the FOUR-QUEUE DEQUEUE ORACLE frame type, and it is a fresh value:
 *   0x88C0 = IBSPG "real"        (defense programs)
 *   0x88C1 = IBSPG blocker token (defense programs)
 *   0x88C2 = four_queue_oracle   (the host-injected sibling)
 *   0x88C3 = THIS program
 * Distinct values mean a frame from any of these programs can never be confused
 * with a frame from another by a parser, a capture filter, or a human reading a
 * hex dump. This program knows nothing about the other three: such a frame is
 * simply not oracle traffic and is dropped. */
const bit<16> ETHERTYPE_ORACLE4 = 0x88C3;

/* ---- ports — the COMPLETE set. dp9 / dp11 / dp64 are absent by construction.
 *
 * PORT_PGEN (dp68) is Tofino-1's pipe-0 packet-generator / recirculation port.
 * It is INGRESS-ONLY here: it appears in one parser select and in no action.
 *
 * PORT_L (dp8) is the MAC-near loopback that owns the four queues under test.
 * It is the ONLY value ever assigned to ucast_egress_port. */
const PortId_t PORT_PGEN = 9w68;
const PortId_t PORT_L    = 9w8;

/* ---- the four queues under test, all on PORT_L ---------------------------
 * QUEUE ID DOES NOT IMPLY PRIORITY. P4 selects only the qid; the strict
 * ordering ABLOCK > ACK > RBLOCK > RESP is control-plane configuration
 * (tf1.tm.queue.sched_cfg max_priority). That the qid numbers happen to descend
 * with the intended priority is a readability choice, NOT a mechanism — and the
 * whole point of the pilot's REVERSED control (mode C) is to prove exactly
 * that, by reversing the priorities while leaving these qids alone. */
const bit<5> QID_ABLOCK = 5w7;
const bit<5> QID_ACK    = 5w6;
const bit<5> QID_RBLOCK = 5w5;
const bit<5> QID_RESP   = 5w4;

/* ---- roles, as stamped into the oracle header on the enqueue pass -------- */
const bit<8> ROLE_ABLOCK = 8w1;
const bit<8> ROLE_ACK    = 8w2;
const bit<8> ROLE_RBLOCK = 8w3;
const bit<8> ROLE_RESP   = 8w4;

/* ---- trace geometry ------------------------------------------------------
 * 512 deep, exactly as the validated two-queue oracle. One trial generates 128
 * events, so the trace has 4x headroom and `reg_overflow` should never move;
 * an overflow is therefore a loud signal that something generated more packets
 * than the single configured batch. */
const int     TRACE_LEN   = 512;
const bit<32> TRACE_LEN_V = 32w512;

/* ---- counter slots (compile-time constants only) -------------------------
 * ONE Counter object. bf-p4c hard-errors when two count() sites on the same
 * Counter are not mutually exclusive, so every site below sits either in its
 * own branch of apply{} or in an action of the one classification table (whose
 * actions are mutually exclusive by construction). */
const bit<8> C_DROP_BAD_PORT   = 8w0;  /* ingress port is neither dp68 nor dp8  */
const bit<8> C_DROP_NON_ORACLE = 8w1;  /* not ethertype 0x88C3                  */
const bit<8> C_ENQ_ABLOCK      = 8w2;  /* generated, mapped to Q_ABLOCK         */
const bit<8> C_ENQ_ACK         = 8w3;  /* generated, mapped to Q_ACK            */
const bit<8> C_ENQ_RBLOCK      = 8w4;  /* generated, mapped to Q_RBLOCK         */
const bit<8> C_ENQ_RESP        = 8w5;  /* generated, mapped to Q_RESP           */
const bit<8> C_DROP_BAD_ID     = 8w6;  /* packet_id has no role-map entry       */
const bit<8> C_TRACED          = 8w7;  /* dequeued and recorded in the trace    */
const bit<8> C_TRACE_OVERFLOW  = 8w8;  /* dequeued but the trace was full       */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* The 6-byte hardware packet-generator header, as a byte-exact overlay.
 *
 * It is written as a local header rather than using tofino1_base.p4's
 * `pktgen_timer_header_t` / `pktgen_recirc_header_t` on purpose. Those two
 * types have the SAME total width and the SAME `packet_id` placement (bytes
 * 4..5) but differ in bytes 1..3 — timer carries pad(8) ++ batch_id(16), recirc
 * carries a 24-bit key lifted from the triggering packet:
 *
 *   tofino1_base.p4:343 pktgen_timer_header_t  { pad(3) pipe_id(2) app_id(3)
 *                                                pad(8) batch_id(16) packet_id(16) }
 *   tofino1_base.p4:367 pktgen_recirc_header_t { pad(3) pipe_id(2) app_id(3)
 *                                                key(24)           packet_id(16) }
 *
 * This program reads ONLY `packet_id`, which is identical in both layouts, so
 * the program is trigger-agnostic: the run uses a one-shot TIMER trigger (no
 * host packet is needed to start a batch), and a future recirc-pattern trigger
 * would work without touching the P4. Naming bytes 1..3 `key_or_batch` and
 * never reading them is what keeps that honest — a `batch_id` field name would
 * silently become a lie under a recirc trigger. */
header pktgen_hdr_h {
    bit<8>  pipe_app;      /* pad(3) ++ pipe_id(2) ++ app_id(3)  — NEVER read  */
    bit<24> key_or_batch;  /* timer: pad(8)++batch_id ; recirc: key — NEVER read */
    bit<16> packet_id;     /* 0..127 within the batch — THE ONLY FIELD READ    */
}

/* The oracle header, 5 bytes, immediately after the ethertype.
 *   trial_id  comes from the packet-buffer TEMPLATE. The control plane rewrites
 *             the template once per trial, so every packet of a trial carries
 *             that trial's id and a stale trace entry from a previous trial is
 *             detectable rather than silently scored.
 *   role      is 0 in the template; the enqueue pass stamps 1..4 from the
 *             classification table. This is the ordering key.
 *   pkt_id    is 0 in the template; the enqueue pass stamps the hardware
 *             `packet_id`. It survives where the pktgen header does not, and it
 *             is what makes duplicate detection and the mapping cross-check
 *             possible. */
header oracle4_h {
    bit<16> trial_id;
    bit<8>  role;
    bit<16> pkt_id;
}

struct headers_t {
    pktgen_hdr_h pgen;
    ethernet_h   eth;
    oracle4_h    oracle;
}

/* Flags are bit<8> rather than bool/bit<1> deliberately: sub-byte fields packed
 * next to 32-bit register outputs invite Tofino SuperCluster allocation
 * failures, and every downstream gate is then a cheap 8-bit equality. */
struct ig_meta_t {
    bit<8>  src_ok;     /* 1 = arrived on dp68 or dp8                          */
    bit<8>  dequeued;   /* 1 = arrived on dp8, i.e. this is the return pass     */
    bit<8>  is_oracle;  /* 1 = ethertype 0x88C3 and the oracle header parsed    */
    bit<9>  evt_idx;    /* trace write index, from reg_event_ctr               */
    bit<8>  in_range;   /* 1 if evt_idx < TRACE_LEN                            */
    bit<32> ts32;       /* low 32 bits of ingress_mac_tstamp (ns on TF1)        */
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* src_ok, dequeued and is_oracle are deliberately NOT initialized here.
         * The TNA parser has no clear-on-write: assigning a field in `start` and
         * again later on the same path is a hard compile error. Every default is
         * the all-zero encoding the compiler's own metadata initialization
         * supplies, and every zero default is the SAFE one — not a valid source,
         * not dequeued, not oracle traffic. evt_idx / in_range / ts32 are
         * assigned only in the MAU and are likewise left to zero-init. */
        transition select(ig_intr_md.ingress_port) {
            PORT_PGEN : from_pgen;
            PORT_L    : from_loopback;
            default   : accept;    /* src_ok stays 0 -> dropped in the MAU */
        }
    }

    /* A freshly generated packet. The hardware prepended the 6-byte packet
     * generator header, so it must be consumed before Ethernet. dp68 is the
     * generator's own port and nothing in this program can ever egress to it,
     * so a packet arriving here is a generated packet by construction. */
    state from_pgen {
        meta.src_ok = 8w1;
        pkt.extract(hdr.pgen);
        transition parse_eth;
    }

    /* A packet that has just been dequeued from one of the four queues and
     * looped back. It carries NO packet generator header (the ingress deparser
     * stripped it on the enqueue pass). */
    state from_loopback {
        meta.src_ok   = 8w1;
        meta.dequeued = 8w1;
        transition parse_eth;
    }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_ORACLE4 : parse_oracle;
            default           : accept;   /* is_oracle stays 0 -> dropped */
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

    Counter<bit<64>, bit<8>>(32w16, CounterType_t.PACKETS) ctr_oracle;

    /* --- event index: one RMW executed at most once per packet. Returns the
     * index for THIS dequeue and saturating-increments, so every event past the
     * end reads back TRACE_LEN and is steered to the overflow path instead of
     * wrapping and corrupting entry 0. --- */
    Register<bit<32>, bit<1>>(1, 0) reg_event_ctr;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_event_ctr) evt_ctr_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v < TRACE_LEN_V) { v = v + 32w1; }
        }
    };

    /* --- overflow tally: write-only increment --- */
    Register<bit<32>, bit<1>>(1, 0) reg_overflow;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_overflow) ovf_rmw = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };

    /* --- four trace arrays, each written at the dynamic event index. Each is
     * exactly ONE write-only RegisterAction executed at most once per packet,
     * per the one-RegisterAction-per-register placement discipline that made
     * the two-queue oracle place first try. --- */
    Register<bit<16>, bit<9>>(TRACE_LEN, 0) trace_trial;
    RegisterAction<bit<16>, bit<9>, bit<16>>(trace_trial) trace_trial_w = {
        void apply(inout bit<16> v) { v = hdr.oracle.trial_id; }
    };

    Register<bit<8>, bit<9>>(TRACE_LEN, 0) trace_role;
    RegisterAction<bit<8>, bit<9>, bit<8>>(trace_role) trace_role_w = {
        void apply(inout bit<8> v) { v = hdr.oracle.role; }
    };

    Register<bit<16>, bit<9>>(TRACE_LEN, 0) trace_pktid;
    RegisterAction<bit<16>, bit<9>, bit<16>>(trace_pktid) trace_pktid_w = {
        void apply(inout bit<16> v) { v = hdr.oracle.pkt_id; }
    };

    Register<bit<32>, bit<9>>(TRACE_LEN, 0) trace_ts;
    RegisterAction<bit<32>, bit<9>, bit<32>>(trace_ts) trace_ts_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };

    /* ---- the four enqueue fates. ucast_egress_port is assigned from the
     * compile-time immediate PORT_L and from nothing else, in these four
     * actions and nowhere else in the program. bypass_egress = 1 because a
     * parked frame has no business traversing the egress pipeline. ---- */
    action enq_ablock() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ABLOCK;
        ig_tm_md.bypass_egress     = 1w1;
        hdr.oracle.role            = ROLE_ABLOCK;
        hdr.oracle.pkt_id          = hdr.pgen.packet_id;
        ctr_oracle.count(C_ENQ_ABLOCK);
    }
    action enq_ack() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ACK;
        ig_tm_md.bypass_egress     = 1w1;
        hdr.oracle.role            = ROLE_ACK;
        hdr.oracle.pkt_id          = hdr.pgen.packet_id;
        ctr_oracle.count(C_ENQ_ACK);
    }
    action enq_rblock() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RBLOCK;
        ig_tm_md.bypass_egress     = 1w1;
        hdr.oracle.role            = ROLE_RBLOCK;
        hdr.oracle.pkt_id          = hdr.pgen.packet_id;
        ctr_oracle.count(C_ENQ_RBLOCK);
    }
    action enq_resp() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
        hdr.oracle.role            = ROLE_RESP;
        hdr.oracle.pkt_id          = hdr.pgen.packet_id;
        ctr_oracle.count(C_ENQ_RESP);
    }
    action drop_bad_id() {
        ig_dprsr_md.drop_ctl = 3w1;
        ctr_oracle.count(C_DROP_BAD_ID);
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* THE ROLE MAP. This is where the per-trial randomization lives: packet
     * generator emission order is fixed by hardware (packet_id counts 0,1,2,...),
     * so the only way to make the ROLE order differ from the EMISSION order is
     * to permute the packet_id -> role assignment. The control plane rewrites
     * all 128 entries per trial from a recorded seed, keeping exactly 32 entries
     * per role.
     *
     * The key is the FULL 16-bit packet_id, matched EXACT. It is deliberately
     * not a bit-slice of packet_id: a slice inside a gateway yields
     * "condition expression too complex", and slicing a 32-bit arithmetic field
     * breaks PHV allocation. A full-field exact match has neither problem.
     *
     * Default action drops, so a packet_id with no entry cannot reach a queue —
     * it lands on C_DROP_BAD_ID where the control plane can see it. */
    table tbl_role {
        key     = { hdr.pgen.packet_id : exact; }
        actions = { enq_ablock; enq_ack; enq_rblock; enq_resp; drop_bad_id; }
        const default_action = drop_bad_id();
        size    = 256;
    }

    apply {
        if (meta.src_ok == 8w0) {
            /* Neither dp68 nor dp8. Nothing else is topology for this oracle.
             * If the packet generator app were ever configured with an
             * all-pipes target, the pipe-1/2/3 generators would emit on their
             * own local port 68 (dev_port 196 / 324 / 452) and land here, which
             * is why this counter is read as part of the preload gate. */
            ctr_oracle.count(C_DROP_BAD_PORT);
            drop_pkt();
        } else if (meta.is_oracle == 8w0) {
            /* Not 0x88C3. Dropped rather than forwarded, so the oracle can
             * neither perturb nor be perturbed by any other traffic. */
            ctr_oracle.count(C_DROP_NON_ORACLE);
            drop_pkt();
        } else if (meta.dequeued == 8w0) {
            /* FRESHLY GENERATED: map packet_id -> role, stamp the frame, park
             * it on that role's queue. */
            tbl_role.apply();
        } else {
            /* THE RETURN PASS: this packet has just been dequeued by the TM.
             * Allocate the next monotonic trace index, record it, and DROP. It
             * is never re-enqueued, which is what bounds every packet to exactly
             * one pass and makes the trace a pure dequeue-order record. */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];

            bit<32> ev   = evt_ctr_rmw.execute(1w0);
            meta.evt_idx = ev[8:0];

            /* One isolated 32-bit magnitude compare in its own gateway, then an
             * 8-bit flag, so every downstream gate is a cheap equality. */
            if (ev < TRACE_LEN_V) { meta.in_range = 8w1; }

            /* Each execute sits in its own guarded block so the four SALUs place
             * independently. */
            if (meta.in_range == 8w1) { trace_trial_w.execute(meta.evt_idx); }
            if (meta.in_range == 8w1) { trace_role_w.execute(meta.evt_idx); }
            if (meta.in_range == 8w1) { trace_pktid_w.execute(meta.evt_idx); }
            if (meta.in_range == 8w1) { trace_ts_w.execute(meta.evt_idx); }

            if (meta.in_range == 8w1) {
                ctr_oracle.count(C_TRACED);
            } else {
                ovf_rmw.execute(1w0);
                ctr_oracle.count(C_TRACE_OVERFLOW);
            }

            drop_pkt();
        }
    }
}

/* ============================ ingress deparser ==========================
 * hdr.pgen is EXTRACTED but never EMITTED, which is how the 6-byte packet
 * generator header is stripped — the same behaviour the SDE's own tna_pktgen
 * example relies on ("the internal Packet Generator header is removed at the
 * ingress deparser"). What is emitted is Ethernet + the oracle header, followed
 * by the never-extracted residual of the template, verbatim. The only bytes
 * this program changes on the wire are oracle.role and oracle.pkt_id. */
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
 * Unreachable by construction, and deliberately empty. Parked frames carry
 * bypass_egress = 1 so they skip egress entirely; returning frames are dropped
 * in ingress. No egress state of any kind exists, so nothing in egress can
 * perturb the ordering being measured. */
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
