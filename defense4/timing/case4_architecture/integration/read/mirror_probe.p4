// F1 (Stream 1c) isolation probe: the ingress-deparser Mirror() clone that read_queue_timing.p4
// relies on, compiled and run ALONE so a Mirror-specific compiler complaint cannot hide behind that
// file's known PHV-allocation crash. Header layouts, the clone/parse_clone path, the IngressDeparser
// and the empty egress trio (probe_shell.p4, included unchanged) are the same as read_queue_timing.p4.
// The ingress is a stub: a T_IN pass is rewritten the way hold_operate() rewrites it (tev and eth
// invalidated, ladder made valid) and requests the clone; a clone that comes back on PKTGEN_RETURN is
// latched into registers (so the model run can read what the parser saw) and dropped.
// Port 9 is accepted as an injection alias of T_IN (front port, always injectable on the model).
#include <core.p4>
#include <tna.p4>
#include "ports.p4"   /* PKTGEN_RETURN now comes from ports.p4 (two-pipe layout, 196); was a local 9w324 */
const PortId_t PROBE_IN = 9w9;
const PortId_t PROBE_OUT = 9w1;
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_CLONE = 1;
const MirrorId_t CLONE_SESSION_ID = 10w7;

header tev_t { bit<32> epoch; bit<32> wgen; bit<32> t0q; bit<8> kind; bit<8> stage; bit<16> reserved; }
header ladder_t { bit<8> role; bit<8> child; bit<16> generation; bit<32> budget; }
header clone_hdr_t { bit<32> tag; }
header ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }
struct header_t { pktgen_timer_header_t timer; clone_hdr_t clone; tev_t tev; ladder_t ladder; ethernet_t eth; }
struct metadata_t { bit<32> clone_tag; MirrorId_t clone_ses; }

parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) {
            T_IN : parse_tev;
            PROBE_IN : parse_tev;
            PKTGEN_RETURN : parse_clone;
            default : accept;
        }
    }
    state parse_tev { pkt.extract(hdr.tev); transition opaque_ethernet; }
    state parse_clone { pkt.extract(hdr.clone); pkt.extract(hdr.tev); transition opaque_ethernet; }
    state opaque_ethernet { pkt.extract(hdr.eth); transition accept; }
}

control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    Register<bit<32>, bit<1>>(1, 0) clone_arrivals;
    RegisterAction<bit<32>, bit<1>, bit<32>>(clone_arrivals) bump_arrivals = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    Register<bit<32>, bit<1>>(1, 0) seen_tag;
    RegisterAction<bit<32>, bit<1>, bit<32>>(seen_tag) latch_tag = {
        void apply(inout bit<32> value) { value = hdr.clone.tag; }
    };
    Register<bit<32>, bit<1>>(1, 0) seen_epoch;
    RegisterAction<bit<32>, bit<1>, bit<32>>(seen_epoch) latch_epoch = {
        void apply(inout bit<32> value) { value = hdr.tev.epoch; }
    };
    Register<bit<32>, bit<1>>(1, 0) seen_kind;
    RegisterAction<bit<32>, bit<1>, bit<32>>(seen_kind) latch_kind = {
        void apply(inout bit<32> value) { value = (bit<32>)hdr.tev.kind; }
    };
    Register<bit<32>, bit<1>>(1, 0) seen_eth_type;
    RegisterAction<bit<32>, bit<1>, bit<32>>(seen_eth_type) latch_eth_type = {
        void apply(inout bit<32> value) { value = (bit<32>)hdr.eth.type; }
    };

    // Same shape as read_queue_timing.p4's hold_operate(): rewrite the original into a ladder blocker
    // and request the clone (mirror_type, clone_tag and clone_ses are three independent writes).
    action hold_like_operate() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE; md.clone_tag = hdr.tev.epoch + 32w0x10000;
        md.clone_ses = CLONE_SESSION_ID;
        hdr.tev.setInvalid(); hdr.eth.setInvalid();
        hdr.ladder.setValid();
        hdr.ladder.role = 13; hdr.ladder.child = 0;
        hdr.ladder.generation = 16w0x0102; hdr.ladder.budget = 32w0x0a0b0c0d;
        ig_tm_md.ucast_egress_port = PROBE_OUT;
    }

    apply {
        if (ig_intr_md.ingress_port == PKTGEN_RETURN) {
            bump_arrivals.execute(0); latch_tag.execute(0); latch_epoch.execute(0);
            latch_kind.execute(0); latch_eth_type.execute(0);
            ig_dprsr_md.drop_ctl = 1;
        } else if (hdr.tev.isValid()) {
            hold_like_operate();
        } else {
            ig_dprsr_md.drop_ctl = 1;
        }
    }
}

control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    // No-arg Mirror(): the typed Mirror(mirror_type) constructor errors "Inconsistent mirror
    // selectors" on Tofino-1 (defense4_rrc_bor_unified12.p4, IgDeparser).
    Mirror() clone_mirror;
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) {
            clone_mirror.emit<clone_hdr_t>(md.clone_ses, { md.clone_tag });
        }
        pkt.emit(hdr);
    }
}
#include "probe_shell.p4"

Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
