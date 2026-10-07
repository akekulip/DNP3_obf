#include <core.p4>
#include <tna.p4>
#include "work_record.p4"
#include "original_credit.p4"
// Actual packet holder primitive, NOT native READ/SELECT/OPERATE admission.
// Port69 admits checksum-valid pure ACK fixtures; port70 is a typed INTERNAL
// validated-producer seam for response/unsent OP. No port is configured here.
// Port71 is a private actual recirculation return. Port68 remains available
// for the independent pktgen role in a later composition.
// No packet spacing is assumed. WorkRecord protects all producer passes;
// issued-once bits prevent same-cookie original-slot reuse after terminal.
// The test association is epoch1/cookie1. Native owner installation and
// bounded 40ms recovery after physical packet loss remain composition gates.
const PortId_t ACK_INPUT = 9w69;
const PortId_t TYPED_INPUT = 9w70;
const PortId_t HELD_RETURN = 9w71;
const PortId_t FORWARD_PORT = 9w72;
header envelope_t {
    bit<32> epoch; bit<32> generation; bit<32> cookie; bit<32> expected_credit;
    bit<8> kind; bit<8> stage; bit<16> reserved;
}
header ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }
header ip_t {
    bit<4> version; bit<4> ihl; bit<8> tos; bit<16> len; bit<16> id;
    bit<3> flags; bit<13> frag; bit<8> ttl; bit<8> proto;
    bit<16> checksum; bit<32> src; bit<32> dst;
}
header tcp_t {
    bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack;
    bit<4> offset; bit<4> reserved; bit<8> flags; bit<16> window;
    bit<16> checksum; bit<16> urgent;
}
struct header_t { envelope_t envelope; ethernet_t eth; ip_t ip; tcp_t tcp; }
struct metadata_t {
    bool ip_error; bit<16> tcp_sum; bit<8> parsed; bit<8> source_valid;
    bit<8> kind; bit<8> work_op; bit<8> credit_op; bit<8> role;
    bit<8> cookie_valid; bit<8> state_valid;
    bit<32> generation; bit<32> work_phase; bit<32> epoch;
    bit<32> policy; bit<32> result; bit<32> desired;
    bit<32> expected_cookie; bit<32> cookie_difference;
}
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    Checksum() ipv4_checksum; Checksum() tcp_checksum;
    state start {
        pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        md.parsed = 0; md.source_valid = 0; md.kind = 0;
        transition select(ig_intr_md.ingress_port) {
            ACK_INPUT : native_ethernet;
            TYPED_INPUT : typed_envelope;
            HELD_RETURN : return_envelope;
            default : reject;
        }
    }
    state typed_envelope {
        pkt.extract(hdr.envelope);
        transition select(hdr.envelope.kind, hdr.envelope.stage, hdr.envelope.reserved) {
            (2, 0, 0) : opaque_ethernet;
            (3, 0, 0) : opaque_ethernet;
            default : reject;
        }
    }
    state return_envelope {
        pkt.extract(hdr.envelope);
        transition select(hdr.envelope.reserved) { 0 : opaque_ethernet; default : reject; }
    }
    // Original IP/TCP/application bytes remain opaque on real returns. They
    // are emitted unchanged after the prefix/ethernet and never reassembled.
    state opaque_ethernet { pkt.extract(hdr.eth); md.parsed = 1; transition accept; }
    state native_ethernet {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.type) { 0x0800 : ipv4; default : reject; }
    }
    state ipv4 {
        pkt.extract(hdr.ip); ipv4_checksum.add(hdr.ip);
        md.ip_error = ipv4_checksum.verify();
        tcp_checksum.subtract({hdr.ip.src, hdr.ip.dst, 8w0, hdr.ip.proto, hdr.ip.len});
        transition select(hdr.ip.version, hdr.ip.ihl, hdr.ip.proto, hdr.ip.len) {
            (4, 5, 6, 40) : fragment; default : reject;
        }
    }
    state fragment {
        transition select(hdr.ip.flags, hdr.ip.frag) {
            (0, 0) : tcp; (2, 0) : tcp; default : reject;
        }
    }
    state tcp {
        pkt.extract(hdr.tcp); tcp_checksum.subtract(hdr.tcp);
        md.tcp_sum = tcp_checksum.get();
        transition select(hdr.tcp.offset, hdr.tcp.reserved, hdr.tcp.flags, hdr.tcp.urgent) {
            (5, 0, 16, 0) : valid_ack; default : reject;
        }
    }
    state valid_ack { md.parsed = 1; md.kind = 1; transition accept; }
}
control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    WorkRecord() work; OriginalCredit() credits;
    Register<bit<32>, bit<1>>(1, 1) connection_epoch;
    RegisterAction<bit<32>, bit<1>, bit<32>>(connection_epoch) current_epoch = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) source_counter;
    RegisterAction<bit<32>, bit<1>, bit<32>>(source_counter) allocate = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = 0;
            if ((int<32>)value != -1) { value = value + 1; out_value = value; }
        }
    };
    // Configuration state, not a packet-service callback. Returns reread this
    // actual register; disabling it does not suppress terminal credit debit.
    Register<bit<32>, bit<1>>(1, 1) holding_policy;
    RegisterAction<bit<32>, bit<1>, bit<32>>(holding_policy) policy = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    action source_accept() { md.source_valid = 1; }
    table ack_guard {
        key = { md.parsed : exact; md.ip_error : exact; md.tcp_sum : exact; hdr.ip.ttl : range; }
        actions = { source_accept; NoAction; }
        const entries = { (1, false, 0xffeb, 1..255) : source_accept(); }
        const default_action = NoAction(); size = 1;
    }
    action typed_source() { md.source_valid = 1; md.kind = hdr.envelope.kind; }
    table typed_guard { actions = { typed_source; } const default_action = typed_source(); size = 1; }
    action allocate_source() { md.generation = allocate.execute(0); md.work_op = 1; }
    table mint { actions = { allocate_source; } const default_action = allocate_source(); size = 1; }
    action capture_return() { md.generation = hdr.envelope.generation; md.epoch = hdr.envelope.epoch; md.kind = hdr.envelope.kind; }
    table returning { actions = { capture_return; } const default_action = capture_return(); size = 1; }
    action cookie_extract() { md.expected_cookie = hdr.envelope.expected_credit >> 16; }
    table cookie_word { actions = { cookie_extract; } const default_action = cookie_extract(); size = 1; }
    action cookie_compare() { md.cookie_difference = hdr.envelope.cookie ^ md.expected_cookie; }
    table cookie_delta { actions = { cookie_compare; } const default_action = cookie_compare(); size = 1; }
    action cookie_accept() { md.cookie_valid = 1; }
    table cookie_guard {
        key = { md.cookie_difference : exact; hdr.envelope.cookie : ternary; }
        actions = { cookie_accept; NoAction; }
        const entries = { (0, 0 &&& 0xffff0000) : cookie_accept(); }
        const default_action = NoAction(); size = 1;
    }
    action admit_ack() { md.desired = hdr.envelope.expected_credit | 32w0x101; md.credit_op = 1; md.state_valid = 1; }
    action admit_response() { md.desired = hdr.envelope.expected_credit | 32w0x202; md.credit_op = 1; md.state_valid = 1; }
    action admit_operate() { md.desired = hdr.envelope.expected_credit | 32w0x404; md.credit_op = 1; md.state_valid = 1; }
    table admission {
        key = { md.kind : exact; hdr.envelope.expected_credit : ternary; }
        actions = { admit_ack; admit_response; admit_operate; NoAction; }
        const entries = {
            (1, 0 &&& 0x101) : admit_ack();
            (2, 0 &&& 0x202) : admit_response();
            (3, 0 &&& 0x404) : admit_operate();
        }
        const default_action = NoAction(); size = 3;
    }
    action debit_ack() { md.desired = hdr.envelope.expected_credit & 32w0xfffffffe; md.credit_op = 1; md.state_valid = 1; }
    action debit_response() { md.desired = hdr.envelope.expected_credit & 32w0xfffffffd; md.credit_op = 1; md.state_valid = 1; }
    action debit_operate() { md.desired = hdr.envelope.expected_credit & 32w0xfffffffb; md.credit_op = 1; md.state_valid = 1; }
    table terminal {
        key = { md.kind : exact; hdr.envelope.expected_credit : ternary; }
        actions = { debit_ack; debit_response; debit_operate; NoAction; }
        const entries = {
            (1, 1 &&& 1) : debit_ack();
            (2, 2 &&& 2) : debit_response();
            (3, 4 &&& 4) : debit_operate();
        }
        const default_action = NoAction(); size = 3;
    }
    action producer_snapshot() {
        hdr.envelope.setValid(); hdr.envelope.epoch = md.epoch;
        hdr.envelope.generation = md.generation;
        hdr.envelope.cookie = md.result >> 16;
        hdr.envelope.expected_credit = md.result;
        hdr.envelope.kind = md.kind; hdr.envelope.stage = 1; hdr.envelope.reserved = 0;
    }
    table snapshot { actions = { producer_snapshot; } const default_action = producer_snapshot(); size = 1; }
    action loop_original() { ig_tm_md.ucast_egress_port = HELD_RETURN; }
    table loop { actions = { loop_original; } const default_action = loop_original(); size = 1; }
    action forward_original() { hdr.envelope.setInvalid(); ig_tm_md.ucast_egress_port = FORWARD_PORT; }
    action abort_unsent_operate() { ig_dprsr_md.drop_ctl = 1; }
    table off_outcome {
        key = { md.kind : exact; }
        actions = { forward_original; abort_unsent_operate; }
        const entries = { 3 : abort_unsent_operate(); }
        const default_action = forward_original(); size = 1;
    }
    action refresh_credit() { hdr.envelope.expected_credit = md.result; hdr.envelope.stage = 4; }
    table refresh { actions = { refresh_credit; } const default_action = refresh_credit(); size = 1; }
    apply {
        md.work_op = 0; md.credit_op = 0; md.role = 0; md.state_valid = 0; md.cookie_valid = 0;
        md.generation = 0; md.result = 0; md.desired = 0;
        md.epoch = current_epoch.execute(0); md.policy = policy.execute(0);
        ig_tm_md.bypass_egress = 1;
        if (ig_intr_md.ingress_port == HELD_RETURN) {
            returning.apply(); cookie_word.apply(); cookie_delta.apply(); cookie_guard.apply();
            if (hdr.envelope.stage < 4) { md.work_op = 2; }
        } else {
            if (ig_intr_md.ingress_port == ACK_INPUT) { ack_guard.apply(); }
            else { typed_guard.apply(); }
            if (md.source_valid == 1) { mint.apply(); }
        }
        work.apply(md.work_op, md.generation, md.work_phase);
        if (md.work_op == 1 && md.work_phase == 4) { md.role = 1; }
        else if (md.work_op == 2) {
            if (md.work_phase == 1 && md.cookie_valid == 1) { admission.apply(); md.role = 2; }
            else if (md.work_phase == 2) { md.role = 3; }
            else if (md.work_phase == 3) { md.role = 4; }
        } else if (ig_intr_md.ingress_port == HELD_RETURN) {
            if (hdr.envelope.stage == 5) { md.role = 6; }
            else if (hdr.envelope.stage == 4 && md.policy == 0 && md.cookie_valid == 1) {
                terminal.apply(); md.role = 5;
            } else if (hdr.envelope.stage == 4) { md.role = 7; }
        }
        credits.apply(md.credit_op, md.epoch, hdr.envelope.expected_credit, md.desired, md.result);
        if (md.role == 1) { snapshot.apply(); loop.apply(); }
        else if (md.role == 2) {
            if (md.credit_op == 1 && md.result == 1) {
                hdr.envelope.expected_credit = md.desired; hdr.envelope.stage = 2;
            } else { hdr.envelope.stage = 2; hdr.envelope.kind = 0; }
            loop.apply();
        } else if (md.role == 3) { hdr.envelope.stage = 3; loop.apply(); }
        else if (md.role == 4) {
            if (hdr.envelope.kind == 0) { forward_original(); }
            else { hdr.envelope.stage = 4; loop.apply(); }
        } else if (md.role == 5) {
            if (md.credit_op == 1 && md.result == 1) { off_outcome.apply(); }
            else { hdr.envelope.stage = 5; loop.apply(); }
        } else if (md.role == 6) { refresh.apply(); loop.apply(); }
        else if (md.role == 7) { loop.apply(); }
        else {
            // Refused front producer forwards unchanged and never owns credit.
            // Invalid/stale private returns are duplicate suppression only.
            if (ig_intr_md.ingress_port == HELD_RETURN) { ig_dprsr_md.drop_ctl = 1; }
            else { forward_original(); }
        }
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) { apply { pkt.emit(hdr); } }
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
