#include <core.p4>
#include <tna.p4>
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header work_ref_t { bit<32> epoch; bit<32> generation; }
header producer_t { bit<32> epoch; bit<32> cookie; bit<32> payload; bit<8> event; bit<24> reserved; }
header report_t { bit<32> old_phase; bit<32> payload; bit<32> published; bit<32> generation; }
struct work_cell_t { bit<32> generation; bit<32> phase; }
struct header_t { ethernet_t ethernet; producer_t producer; report_t report; }
struct metadata_t {
    work_ref_t ref;
    bit<32> epoch; bit<32> epoch_difference; bit<32> counter;
    bit<32> phase; bit<32> payload; bit<32> publication;
    bit<8> admitted;
}
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) { 0 : port_md; 1 : work_ref; }
    }
    state port_md { pkt.advance(PORT_METADATA_SIZE); transition ethernet; }
    state work_ref { pkt.extract(md.ref); transition ethernet; }
    state ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) { 0x88d4 : producer; default : reject; }
    }
    state producer { pkt.extract(hdr.producer); transition accept; }
}
control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    Register<bit<32>, bit<1>>(1, 1) connection_epoch;
    RegisterAction<bit<32>, bit<1>, bit<32>>(connection_epoch) read_epoch = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) work_counter;
    RegisterAction<bit<32>, bit<1>, bit<32>>(work_counter) allocate_generation = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value; if (value < 32w0xffffffff) { value = value + 1; }
        }
    };
    Register<work_cell_t, bit<1>>(1, {0, 4}) work;
    RegisterAction<work_cell_t, bit<1>, bit<32>>(work) claim = {
        void apply(inout work_cell_t value, out bit<32> old_phase) {
            old_phase = value.phase;
            if (value.phase == 4) { value.generation = md.ref.generation; value.phase = 1; }
        }
    };
    RegisterAction<work_cell_t, bit<1>, bit<32>>(work) advance = {
        void apply(inout work_cell_t value, out bit<32> old_phase) {
            old_phase = 0;
            if (value.generation == md.ref.generation && value.phase < 4) {
                old_phase = value.phase; value.phase = value.phase + 1;
            }
        }
    };
    RegisterAction<work_cell_t, bit<1>, bit<32>>(work) close = {
        void apply(inout work_cell_t value, out bit<32> old_phase) {
            old_phase = value.phase;
            if (value.phase == 1 || value.phase == 2) { value.phase = 3; }
        }
    };
    RegisterAction<work_cell_t, bit<1>, bit<32>>(work) read = {
        void apply(inout work_cell_t value, out bit<32> old_phase) { old_phase = value.phase; }
    };
    Register<bit<32>, bit<1>>(1, 0) payload;
    RegisterAction<bit<32>, bit<1>, bit<32>>(payload) write_payload = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = hdr.producer.payload; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(payload) read_payload = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) publication;
    RegisterAction<bit<32>, bit<1>, bit<32>>(publication) write_publication = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.ref.generation; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(publication) read_publication = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    action difference_first() { md.epoch_difference = hdr.producer.epoch ^ md.epoch; }
    action difference_return() { md.epoch_difference = md.ref.epoch ^ md.epoch; }
    action accept() { md.admitted = 1; }
    action refuse() { md.admitted = 0; }
    table first_difference { actions = { difference_first; } const default_action = difference_first(); size = 1; }
    table return_difference { actions = { difference_return; } const default_action = difference_return(); size = 1; }
    table authority {
        key = { md.epoch_difference : exact; }
        actions = { accept; refuse; }
        const entries = { 0 : accept(); } const default_action = refuse(); size = 1;
    }
    table generation_available {
        key = { md.counter : exact; }
        actions = { accept; refuse; }
        const entries = { 0xffffffff : refuse(); } const default_action = accept(); size = 1;
    }
    action form_reference() { md.ref.epoch = md.epoch; md.ref.generation = md.counter + 1; }
    table reference { actions = { form_reference; } const default_action = form_reference(); size = 1; }
    apply {
        md.phase = 0; md.payload = 0; md.publication = 0;
        md.epoch = read_epoch.execute(0);
        if (ig_intr_md.resubmit_flag == 0) { first_difference.apply(); } else { return_difference.apply(); }
        authority.apply();
        if (md.admitted == 1) {
            if (ig_intr_md.resubmit_flag == 0) {
                if (hdr.producer.event == 1) {
                    md.counter = allocate_generation.execute(0);
                    generation_available.apply();
                    if (md.admitted == 1) {
                        reference.apply();
                        md.phase = claim.execute(0);
                        if (md.phase == 4) { ig_dprsr_md.resubmit_type = 1; }
                    }
                } else if (hdr.producer.event == 255) { md.phase = close.execute(0); }
                else { md.phase = read.execute(0); }
            } else {
                md.phase = advance.execute(0);
                if (md.phase == 1) {
                    md.payload = write_payload.execute(0);
                    ig_dprsr_md.resubmit_type = 1;
                } else if (md.phase == 2) {
                    md.publication = write_publication.execute(0);
                    ig_dprsr_md.resubmit_type = 1;
                } else if (md.phase == 3) {
                    md.payload = read_payload.execute(0);
                    md.publication = read_publication.execute(0);
                }
            }
        }
        hdr.report.setValid();
        hdr.report.old_phase = md.phase;
        hdr.report.payload = md.payload;
        hdr.report.published = md.publication;
        hdr.report.generation = md.ref.generation;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        ig_tm_md.bypass_egress = 1;
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Resubmit() resubmit;
    apply {
        if (ig_dprsr_md.resubmit_type == 1) { resubmit.emit(md.ref); }
        pkt.emit(hdr);
    }
}
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
