#include <core.p4>
#include <tna.p4>
// Independent pktgen service compile probe. Initialization and ACK commit are
// diagnostic setup events, not the final authority or a CPU service path.
// Full integration must source those events from the atomic owner transition.
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header command_t { bit<8> event; bit<8> profile; bit<16> reserved; }
header report_t {
    bit<32> now; bit<32> operate_deadline; bit<32> readiness_deadline;
    bit<32> response_deadline; bit<8> operate_due; bit<8> readiness_due;
    bit<8> response_due; bit<8> reserved;
}
struct header_t { pktgen_timer_header_t timer; ethernet_t ethernet; command_t command; report_t report; }
struct metadata_t {
    bit<32> now; bit<32> operate; bit<32> readiness; bit<32> response;
    bit<32> operate_delta; bit<32> readiness_delta; bit<32> response_delta;
    bit<8> operate_due; bit<8> readiness_due; bit<8> response_due;
    bit<8> event;
}
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) { 68 : timer; 69 : ethernet; default : reject; }
    }
    state timer {
        pkt.extract(hdr.timer);
        transition select(hdr.timer.app_id) { 0 : ethernet; default : reject; }
    }
    state ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) { 0x88d4 : command; default : reject; }
    }
    state command { pkt.extract(hdr.command); transition accept; }
}
control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    Register<bit<32>, bit<1>>(1, 0) operate_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(operate_deadline) operate_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(operate_deadline) operate_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.operate; }
    };
    Register<bit<32>, bit<1>>(1, 0) readiness_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(readiness_deadline) readiness_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(readiness_deadline) readiness_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.readiness; }
    };
    Register<bit<32>, bit<1>>(1, 0) response_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(response_deadline) response_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(response_deadline) response_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.response; }
    };
    action clock_sample() { md.now = ((bit<32>)ig_prsr_md.global_tstamp) & 32w0xffffff00; }
    table clock { actions = { clock_sample; } const default_action = clock_sample(); size = 1; }
    action profile_5() { md.operate = md.now + 32w4999936; }
    action profile_10() { md.operate = md.now + 32w9999872; }
    action profile_15() { md.operate = md.now + 32w14999808; }
    action profile_20() { md.operate = md.now + 32w20000000; }
    table profile {
        key = { hdr.command.profile : exact; }
        actions = { profile_5; profile_10; profile_15; profile_20; }
        const entries = { 10 : profile_10(); 15 : profile_15(); 20 : profile_20(); }
        const default_action = profile_5(); size = 3;
    }
    action anchor_readiness() { md.readiness = md.now + 32w29999872; }
    action anchor_response() { md.response = md.now + 32w999936; }
    table readiness_anchor { actions = { anchor_readiness; } const default_action = anchor_readiness(); size = 1; }
    table response_anchor { actions = { anchor_response; } const default_action = anchor_response(); size = 1; }
    action compute_delta() {
        md.operate_delta = md.now - md.operate;
        md.readiness_delta = md.now - md.readiness;
        md.response_delta = md.now - md.response;
    }
    table deltas { actions = { compute_delta; } const default_action = compute_delta(); size = 1; }
    apply {
        clock.apply();
        md.event = hdr.command.event;
        if (ig_intr_md.ingress_port == 68) { md.event = 0; }
        if (md.event == 1) {
            profile.apply(); readiness_anchor.apply();
            operate_write.execute(0); readiness_write.execute(0);
        } else {
            md.operate = operate_read.execute(0);
            md.readiness = readiness_read.execute(0);
        }
        if (md.event == 2) {
            response_anchor.apply(); response_write.execute(0);
        } else { md.response = response_read.execute(0); }
        deltas.apply();
        md.operate_due = 0; md.readiness_due = 0; md.response_due = 0;
        if (md.operate_delta[31:31] == 0) { md.operate_due = 1; }
        if (md.readiness_delta[31:31] == 0) { md.readiness_due = 1; }
        if (md.response_delta[31:31] == 0) { md.response_due = 1; }
        hdr.report.setValid();
        hdr.report.now = md.now;
        hdr.report.operate_deadline = md.operate;
        hdr.report.readiness_deadline = md.readiness;
        hdr.report.response_deadline = md.response;
        hdr.report.operate_due = md.operate_due;
        hdr.report.readiness_due = md.readiness_due;
        hdr.report.response_due = md.response_due; hdr.report.reserved = 0;
        ig_tm_md.ucast_egress_port = 69; ig_tm_md.bypass_egress = 1;
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr); }
}
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
