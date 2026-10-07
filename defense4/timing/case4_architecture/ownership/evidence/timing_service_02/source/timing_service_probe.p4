#include <core.p4>
#include <tna.p4>
// Independent pktgen timing service compile probe. Initialization and ACK commit are
// diagnostic setup events, not the final authority or a CPU service path.
// Full integration must source those events from the atomic owner transition.
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header command_t { bit<32> epoch; bit<32> cookie; bit<8> event; bit<8> profile; bit<16> reserved; }
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
    bit<8> event; bit<32> blockers; bit<32> seen_mask;
    bit<32> ack_phase; bit<32> op_pending; bit<32> response_pending;
    bit<8> ack_eligible; bit<8> ack_committed; bit<8> response_operation;
    bit<8> operate_committed; bit<8> response_committed;
    bit<32> source_epoch; bit<32> epoch_difference; bit<8> authorized;
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
    Register<bit<32>, bit<1>>(1, 1) epoch;
    RegisterAction<bit<32>, bit<1>, bit<32>>(epoch) read_epoch = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) blockers;
    RegisterAction<bit<32>, bit<1>, bit<32>>(blockers) blockers_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(blockers) blockers_clear = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = 0; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(blockers) blockers_seen = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = value | md.seen_mask; }
    };
    action read_blockers() { md.blockers = blockers_read.execute(0); }
    action clear_blockers() { md.blockers = blockers_clear.execute(0); }
    action observe_blockers() { md.blockers = blockers_seen.execute(0); }
    table blocker_event {
        key = { md.event : exact; }
        actions = { read_blockers; clear_blockers; observe_blockers; }
        const entries = { 1 : clear_blockers(); 3 : observe_blockers(); 4 : observe_blockers(); }
        const default_action = read_blockers(); size = 3;
    }
    Register<bit<32>, bit<1>>(1, 0) operate_pending;
    RegisterAction<bit<32>, bit<1>, bit<8>>(operate_pending) op_read = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(operate_pending) op_arm = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; value = 1; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(operate_pending) op_abort = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; value = 0; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(operate_pending) op_service = {
        void apply(inout bit<32> value, out bit<8> old) {
            old = 0; if (value == 1 && md.operate_delta[31:31] == 0) { value = 0; old = 1; }
        }
    };
    action read_operate() { md.operate_committed = op_read.execute(0); }
    action arm_operate() { md.operate_committed = op_arm.execute(0); }
    action abort_operate() { md.operate_committed = op_abort.execute(0); }
    action service_operate() { md.operate_committed = op_service.execute(0); }
    table operate_event {
        key = { md.event : exact; }
        actions = { read_operate; arm_operate; abort_operate; service_operate; }
        const entries = { 0 : service_operate(); 1 : arm_operate(); 255 : abort_operate(); }
        const default_action = read_operate(); size = 3;
    }
    Register<bit<32>, bit<1>>(1, 0) ack_phase;
    RegisterAction<bit<32>, bit<1>, bit<8>>(ack_phase) ack_read = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(ack_phase) ack_arm = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; value = 1; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(ack_phase) ack_service = {
        void apply(inout bit<32> value, out bit<8> old) {
            old = 0; if (value == 1 && md.ack_eligible == 1) { value = 2; old = 1; }
        }
    };
    action read_ack() { md.ack_committed = ack_read.execute(0); }
    action arm_ack() { md.ack_committed = ack_arm.execute(0); }
    action service_ack() { md.ack_committed = ack_service.execute(0); }
    table ack_event {
        key = { md.event : exact; }
        actions = { read_ack; arm_ack; service_ack; }
        const entries = { 0 : service_ack(); 1 : arm_ack(); }
        const default_action = read_ack(); size = 2;
    }
    Register<bit<32>, bit<1>>(1, 0) response_pending;
    RegisterAction<bit<32>, bit<1>, bit<8>>(response_pending) reply_read = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(response_pending) reply_arm = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; value = 1; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(response_pending) reply_clear = {
        void apply(inout bit<32> value, out bit<8> old) { old = 0; value = 0; }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(response_pending) reply_service = {
        void apply(inout bit<32> value, out bit<8> old) {
            old = 0; if (value == 1 && md.response_delta[31:31] == 0) { value = 0; old = 1; }
        }
    };
    action read_reply() { md.response_committed = reply_read.execute(0); }
    action arm_reply() { md.response_committed = reply_arm.execute(0); }
    action clear_reply() { md.response_committed = reply_clear.execute(0); }
    action service_reply() { md.response_committed = reply_service.execute(0); }
    table response_event {
        key = { md.response_operation : exact; }
        actions = { read_reply; arm_reply; clear_reply; service_reply; }
        const entries = { 1 : arm_reply(); 2 : clear_reply(); 3 : service_reply(); }
        const default_action = read_reply(); size = 3;
    }
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
    }
    table deltas { actions = { compute_delta; } const default_action = compute_delta(); size = 1; }
    action allow() { md.authorized = 1; }
    action deny() { md.authorized = 0; }
    action source_difference() { md.epoch_difference = hdr.command.epoch ^ md.source_epoch; }
    table source_diff { actions = { source_difference; } const default_action = source_difference(); size = 1; }
    table source_authority {
        key = { md.epoch_difference : exact; }
        actions = { allow; deny; }
        const entries = { 0 : allow(); } const default_action = deny(); size = 1;
    }
    action observe_ack_mask() { md.seen_mask = 1; }
    action observe_response_mask() { md.seen_mask = 2; }
    action no_seen_mask() { md.seen_mask = 0; }
    table seen_mask {
        key = { md.event : exact; }
        actions = { observe_ack_mask; observe_response_mask; no_seen_mask; }
        const entries = { 3 : observe_ack_mask(); 4 : observe_response_mask(); }
        const default_action = no_seen_mask(); size = 2;
    }
    action eligible() { md.ack_eligible = 1; }
    action ineligible() { md.ack_eligible = 0; }
    table ack_eligibility {
        key = { md.blockers : ternary; md.operate_delta : ternary; md.readiness_delta : ternary; }
        actions = { eligible; ineligible; }
        const entries = {
            (3, 0 &&& 0x80000000, _) : eligible();
            (_, _, 0 &&& 0x80000000) : eligible();
        }
        const default_action = ineligible(); size = 2;
    }
    action read_response_clock() { md.response = response_read.execute(0); }
    action write_response_clock() { response_write.execute(0); }
    table response_clock {
        key = { md.ack_committed : exact; }
        actions = { read_response_clock; write_response_clock; }
        const entries = { 1 : write_response_clock(); }
        const default_action = read_response_clock(); size = 1;
    }
    action response_delta() { md.response_delta = md.now - md.response; }
    table reply_delta { actions = { response_delta; } const default_action = response_delta(); size = 1; }
    action select_reply_service() { md.response_operation = 3; }
    action select_reply_arm() { md.response_operation = 1; }
    action select_reply_clear() { md.response_operation = 2; }
    action select_reply_read() { md.response_operation = 0; }
    table reply_operation {
        key = { md.ack_committed : exact; md.event : exact; }
        actions = { select_reply_service; select_reply_arm; select_reply_clear; select_reply_read; }
        const entries = { (1, 0) : select_reply_arm(); (0, 1) : select_reply_clear(); (0, 0) : select_reply_service(); }
        const default_action = select_reply_read(); size = 3;
    }
    apply {
        md.source_epoch = read_epoch.execute(0);
        source_diff.apply(); source_authority.apply();
        clock.apply();
        profile.apply(); readiness_anchor.apply(); response_anchor.apply();
        md.event = hdr.command.event;
        if (ig_intr_md.ingress_port == 68) { md.event = 0; md.authorized = 1; }
        md.operate_due = 0; md.readiness_due = 0; md.response_due = 0;
        if (md.authorized == 1) {
            seen_mask.apply(); blocker_event.apply();
            if (md.event == 1) {
                operate_write.execute(0); readiness_write.execute(0);
            } else {
                md.operate = operate_read.execute(0);
                md.readiness = readiness_read.execute(0);
            }
            deltas.apply();
            if (md.operate_delta[31:31] == 0) { md.operate_due = 1; }
            if (md.readiness_delta[31:31] == 0) { md.readiness_due = 1; }
            operate_event.apply();
            ack_eligibility.apply(); ack_event.apply();
            response_clock.apply();
            reply_delta.apply();
            if (md.response_delta[31:31] == 0) { md.response_due = 1; }
            reply_operation.apply(); response_event.apply();
        }
        hdr.report.setValid();
        hdr.report.now = md.now;
        hdr.report.operate_deadline = md.operate;
        hdr.report.readiness_deadline = md.readiness;
        hdr.report.response_deadline = md.response;
        // These three bytes are actual atomic OP/ACK/response commitment flags.
        // Readiness is ignored after the ACK phase becomes2.
        hdr.report.operate_due = md.operate_committed;
        hdr.report.readiness_due = md.ack_committed;
        hdr.report.response_due = md.response_committed; hdr.report.reserved = 0;
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
