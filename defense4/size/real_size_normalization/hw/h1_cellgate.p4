/*
 * Gate S6 / H1 — cell-gate for the real S4 cell EtherType 0x88B5 (dp9 <-> CPU).
 *
 * Purpose: prove the dp9 <-> PCIe-CPU(bf_kpkt/ens1) <-> data-plane path is
 * endpoint-transparent and bounded, WITHOUT the cell layer. It only moves a
 * marked test EtherType between the Vision port and the CPU port.
 *
 * Authoritative device facts (read from bfrt device_configuration on the live
 * switch, BFN-T10-032D, 2 pipes, SDE 9.13.2):
 *   pcie_cpu_port = 192  (bf_kpkt / ens1)   <- CPU port; NOT 64 (that is the relay dp64)
 *   dp9  = 0x09 = Vision master (15/1)
 *   dp64 = 0x40 = relay leg (33/0)          (untouched here; H0 is isolated)
 *
 * Path proven:
 *   Vision --(TEST_ETYPE on dp9)--> punt to 192 --> ens1 (CPU echo shim)
 *          <--(reinject from 192)-- send to dp9 <-- ens1
 *
 * Deliberately simple: port compares (bit<9>) and one EtherType compare
 * (bit<16>) only -- no SALU, no hash, no 32-bit gateway compare, so none of the
 * bf-p4c constraint classes apply.
 */
#include <core.p4>
#include <tna.p4>

const bit<9> CPU_PORT    = 192;   // pcie_cpu_port (bf_kpkt / ens1)
const bit<9> VISION_PORT = 9;     // dp9 -> Vision master
const bit<16> TEST_ETYPE = 0x88B5;

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

struct headers_t { ethernet_h ethernet; }
struct metadata_t { }

/* ---------------- Ingress ---------------- */
parser IngressParser(packet_in pkt,
                     out headers_t hdr,
                     out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control Ingress(inout headers_t hdr,
                inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action send_to(bit<9> port) { ig_tm_md.ucast_egress_port = port; }
    action drop() { ig_dprsr_md.drop_ctl = 1; }

    apply {
        if (ig_intr_md.ingress_port == CPU_PORT) {
            send_to(VISION_PORT);                 // reinject: CPU -> Vision
        } else if (ig_intr_md.ingress_port == VISION_PORT &&
                   hdr.ethernet.ether_type == TEST_ETYPE) {
            send_to(CPU_PORT);                    // punt: Vision -> CPU
        } else {
            drop();                               // isolate the H0 test
        }
    }
}

control IngressDeparser(packet_out pkt,
                        inout headers_t hdr,
                        in metadata_t md,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr.ethernet); }
}

/* ---------------- Egress (empty) ---------------- */
parser EgressParser(packet_in pkt,
                    out headers_t hdr,
                    out metadata_t md,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); transition accept; }
}

control Egress(inout headers_t hdr,
               inout metadata_t md,
               in egress_intrinsic_metadata_t eg_intr_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}

control EgressDeparser(packet_out pkt,
                       inout headers_t hdr,
                       in metadata_t md,
                       in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { }
}

Pipeline(IngressParser(), Ingress(), IngressDeparser(),
         EgressParser(), Egress(), EgressDeparser()) pipe;

Switch(pipe) main;
