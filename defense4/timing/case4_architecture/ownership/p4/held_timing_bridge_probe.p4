#include <core.p4>
#include <tna.p4>
#include "work_record.p4"
#include "original_credit.p4"
// Actual holder-to-timing bridge; NOT native READ/SELECT/OPERATE admission.
// Timer anchor is first protected successful original-admission relay, a
// structural fixture rather than the unavailable native READ request anchor.
// Observations derive only from real receipt CAS success carried by a genuine
// WorkRecord return. No externally asserted seen/proof or CPU packet service.
// Port69 admits checksum-valid pure ACK fixtures; port70 is a typed INTERNAL
// validated-producer seam for response/unsent OP. No port is configured here.
// Port71 is a private actual recirculation return. Port68 remains available
// for the independent pktgen role in a later composition.
// No packet spacing is assumed. WorkRecord protects all producer passes;
// Three indexed receipts prevent same-cookie original-slot reuse after terminal.
// The test association is epoch1/cookie1. Native owner installation and
// bounded 40ms recovery after physical packet loss remain composition gates.
const PortId_t ACK_INPUT = 9w69;
const PortId_t TYPED_INPUT = 9w70;
const PortId_t HELD_RETURN = 9w71;
const PortId_t FORWARD_PORT = 9w72;
struct timing_binding_t { bit<32> epoch; bit<32> cookie; }
header heartbeat_report_t { bit<32> anchor; bit<32> release; bit<32> response_ready; bit<32> now; }
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
struct header_t { pktgen_timer_header_t timer; envelope_t envelope; ethernet_t eth; ip_t ip; tcp_t tcp; heartbeat_report_t heartbeat_report; }
struct metadata_t {
    bool ip_error; bit<16> tcp_sum; bit<8> parsed; bit<8> source_valid;
    bit<8> kind; bit<8> work_op; bit<8> credit_op; bit<8> role;
    bit<8> cookie_valid; bit<8> state_valid;
    bit<2> original_index;
    bit<8> timing_event; bit<8> timing_authorized; bit<8> anchor_operation;
    bit<8> seen_operation; bit<8> response_operation; bit<8> reply_operation;
    bit<8> response_eligible; bit<8> release_reason;
    bit<32> now; bit<32> anchor; bit<32> t0; bit<32> seen; bit<32> seen_mask;
    bit<32> normal_deadline; bit<32> readiness_deadline;
    bit<32> normal_delta; bit<32> readiness_delta;
    bit<32> eligible_mask; bit<32> old_release; bit<32> current_release;
    bit<32> response_anchor; bit<32> response_deadline; bit<32> response_delta;
    bit<32> response_ready;
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
            68 : heartbeat_timer;
            ACK_INPUT : native_ethernet;
            TYPED_INPUT : typed_envelope;
            HELD_RETURN : return_envelope;
            default : reject;
        }
    }
    state heartbeat_timer {
        pkt.extract(hdr.timer);
        transition select(hdr.timer.app_id) { 0 : opaque_ethernet; default : reject; }
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
    Register<timing_binding_t, bit<1>>(1, {1, 1}) timing_binding;
    RegisterAction<timing_binding_t, bit<1>, bit<8>>(timing_binding) timing_check = {
        void apply(inout timing_binding_t value, out bit<8> accepted) {
            accepted = 0;
            if (value.epoch == hdr.envelope.epoch && value.cookie == hdr.envelope.cookie) { accepted = 1; }
        }
    };
    // Quantized timestamp leaves eight zero low bits. Bit0 marks actual first
    // admission; it prevents a heartbeat mixing a new observation with an old
    // unarmed timestamp when packets are adjacent in the pipeline.
    Register<bit<32>, bit<1>>(1, 0) admission_anchor;
    RegisterAction<bit<32>, bit<1>, bit<32>>(admission_anchor) anchor_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(admission_anchor) anchor_arm = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (value == 0) { value = md.now | 32w1; }
            out_value = value;
        }
    };
    action load_anchor() { md.anchor = anchor_read.execute(0); }
    action establish_anchor() { md.anchor = anchor_arm.execute(0); }
    table anchor_event {
        key = { md.anchor_operation : exact; }
        actions = { load_anchor; establish_anchor; }
        const entries = { 1 : establish_anchor(); }
        const default_action = load_anchor(); size = 1;
    }
    Register<bit<32>, bit<1>>(1, 0) observations;
    RegisterAction<bit<32>, bit<1>, bit<32>>(observations) observation_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(observations) observation_record = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            value = value | md.seen_mask; out_value = value;
        }
    };
    action load_observations() { md.seen = observation_read.execute(0); }
    action record_observation() { md.seen = observation_record.execute(0); }
    table observation_event {
        key = { md.seen_operation : exact; }
        actions = { load_observations; record_observation; }
        const entries = { 1 : record_observation(); }
        const default_action = load_observations(); size = 1;
    }
    Register<bit<32>, bit<1>>(1, 0) releases;
    RegisterAction<bit<32>, bit<1>, bit<32>>(releases) release_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(releases) release_service = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value; value = value | md.eligible_mask;
        }
    };
    action load_releases() { md.old_release = release_read.execute(0); }
    action service_releases() { md.old_release = release_service.execute(0); }
    table release_event {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { load_releases; service_releases; }
        const entries = { 68 : service_releases(); }
        const default_action = load_releases(); size = 1;
    }
    Register<bit<32>, bit<1>>(1, 0) committed_response_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(committed_response_deadline) deadline_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(committed_response_deadline) deadline_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.response_anchor; out_value = value; }
    };
    action load_response_deadline() { md.response_deadline = deadline_read.execute(0); }
    action commit_response_deadline() { md.response_deadline = deadline_write.execute(0); }
    table response_clock {
        key = { md.response_operation : exact; }
        actions = { load_response_deadline; commit_response_deadline; }
        const entries = { 1 : commit_response_deadline(); }
        const default_action = load_response_deadline(); size = 1;
    }
    Register<bit<32>, bit<1>>(1, 0) ready_response;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ready_response) ready_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ready_response) ready_service = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (md.response_eligible == 1) { value = 1; }
            out_value = value;
        }
    };
    action load_ready_response() { md.response_ready = ready_read.execute(0); }
    action service_ready_response() { md.response_ready = ready_service.execute(0); }
    table ready_event {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { load_ready_response; service_ready_response; }
        const entries = { 68 : service_ready_response(); }
        const default_action = load_ready_response(); size = 1;
    }
    action clock_sample() { md.now = ((bit<32>)ig_prsr_md.global_tstamp) & 32w0xffffff00; }
    table clock { actions = { clock_sample; } const default_action = clock_sample(); size = 1; }
    action relay_ack() { md.timing_event = 1; md.seen_mask = 1; }
    action relay_response() { md.timing_event = 1; md.seen_mask = 2; }
    action relay_operate() { md.timing_event = 1; md.seen_mask = 0; }
    table successful_admission {
        key = { md.role : exact; hdr.envelope.stage : exact; md.kind : exact; }
        actions = { relay_ack; relay_response; relay_operate; NoAction; }
        const entries = { (3, 2, 1) : relay_ack(); (3, 2, 2) : relay_response(); (3, 2, 3) : relay_operate(); }
        const default_action = NoAction(); size = 3;
    }
    action prepare_anchor() { md.t0 = md.anchor & 32w0xffffff00; }
    table anchor_timestamp { actions = { prepare_anchor; } const default_action = prepare_anchor(); size = 1; }
    action prepare_deadlines() {
        md.normal_deadline = md.t0 + 32w4999936;
        md.readiness_deadline = md.t0 + 32w29999872;
        md.response_anchor = md.now + 32w999936;
    }
    table deadline_offsets { actions = { prepare_deadlines; } const default_action = prepare_deadlines(); size = 1; }
    action prepare_deltas() {
        md.normal_delta = md.now - md.normal_deadline;
        md.readiness_delta = md.now - md.readiness_deadline;
    }
    table deadline_deltas { actions = { prepare_deltas; } const default_action = prepare_deltas(); size = 1; }
    action eligible_ack_operate() { md.eligible_mask = 3; }
    action eligible_operate() { md.eligible_mask = 1; }
    table heartbeat_eligibility {
        key = { md.anchor : ternary; md.normal_delta : ternary; md.readiness_delta : ternary; md.seen : ternary; }
        actions = { eligible_ack_operate; eligible_operate; NoAction; }
        const entries = {
            (1 &&& 1, 0 &&& 0x80000000, _, 3) : eligible_ack_operate();
            (1 &&& 1, _, 0 &&& 0x80000000, _) : eligible_ack_operate();
            (1 &&& 1, 0 &&& 0x80000000, _, _) : eligible_operate();
        }
        const default_action = NoAction(); size = 3;
    }
    action current_releases() { md.current_release = md.old_release | md.eligible_mask; }
    table release_snapshot { actions = { current_releases; } const default_action = current_releases(); size = 1; }
    action new_ack_commit() { md.response_operation = 1; }
    table ack_commit {
        key = { md.old_release : ternary; md.eligible_mask : ternary; }
        actions = { new_ack_commit; NoAction; }
        const entries = { (0 &&& 2, 2 &&& 2) : new_ack_commit(); }
        const default_action = NoAction(); size = 1;
    }
    action reply_delta() { md.response_delta = md.now - md.response_deadline; }
    table response_age { actions = { reply_delta; } const default_action = reply_delta(); size = 1; }
    action reply_eligible() { md.response_eligible = 1; }
    table response_eligibility {
        key = { md.current_release : ternary; md.response_delta : ternary; }
        actions = { reply_eligible; NoAction; }
        const entries = { (2 &&& 2, 0 &&& 0x80000000) : reply_eligible(); }
        const default_action = NoAction(); size = 1;
    }
    action timing_terminal() { md.role = 5; md.release_reason = 2; }
    table original_eligibility {
        key = { hdr.envelope.stage : exact; md.cookie_valid : exact; md.kind : exact; md.current_release : ternary; md.response_ready : ternary; }
        actions = { timing_terminal; NoAction; }
        const entries = {
            (4, 1, 1, 2 &&& 2, _) : timing_terminal();
            (4, 1, 2, _, 1) : timing_terminal();
            (4, 1, 3, 1 &&& 1, _) : timing_terminal();
        }
        const default_action = NoAction(); size = 3;
    }

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
    action index_ack() { md.original_index = 0; }
    action index_response() { md.original_index = 1; }
    action index_operate() { md.original_index = 2; }
    table original_slot {
        key = { md.kind : exact; }
        actions = { index_ack; index_response; index_operate; }
        const entries = { 2 : index_response(); 3 : index_operate(); }
        const default_action = index_ack(); size = 2;
    }
    action admit_original() { md.desired = hdr.envelope.expected_credit | 32w0x101; md.credit_op = 1; md.state_valid = 1; }
    table admission {
        key = { md.kind : exact; hdr.envelope.expected_credit : ternary; }
        actions = { admit_original; NoAction; }
        const entries = {
            (1, 0 &&& 0x101) : admit_original();
            (2, 0 &&& 0x101) : admit_original();
            (3, 0 &&& 0x101) : admit_original();
        }
        const default_action = NoAction(); size = 3;
    }
    action debit_original() { md.desired = hdr.envelope.expected_credit & 32w0xfffffffe; md.credit_op = 2; md.state_valid = 1; }
    action check_duplicate() { md.credit_op = 3; }
    table terminal {
        key = { md.kind : exact; hdr.envelope.expected_credit : ternary; }
        actions = { debit_original; check_duplicate; }
        const entries = {
            (1, 0x101 &&& 0x101) : debit_original();
            (2, 0x101 &&& 0x101) : debit_original();
            (3, 0x101 &&& 0x101) : debit_original();
        }
        const default_action = check_duplicate(); size = 3;
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
    action off_terminal() { md.role = 5; md.release_reason = 1; }
    action refresh_return() { md.role = 6; }
    action held_return() { md.role = 7; }
    table held_dispatch {
        key = { hdr.envelope.stage : exact; md.policy : ternary; md.cookie_valid : exact; }
        actions = { off_terminal; refresh_return; held_return; NoAction; }
        const entries = {
            (4, 0, 1) : off_terminal();
            (4, _, 1) : held_return();
            (5, _, 1) : refresh_return();
        }
        const default_action = NoAction(); size = 3;
    }
    apply {
        md.work_op = 0; md.credit_op = 0; md.role = 0; md.state_valid = 0; md.cookie_valid = 0;
        md.generation = 0; md.result = 0; md.desired = 0;
        md.timing_event = 0; md.timing_authorized = 0; md.anchor_operation = 0;
        md.seen_operation = 0; md.seen_mask = 0; md.eligible_mask = 0;
        md.response_operation = 0; md.response_eligible = 0; md.release_reason = 0;
        clock.apply();
        md.epoch = current_epoch.execute(0); md.policy = policy.execute(0);
        ig_tm_md.bypass_egress = 1;
        if (ig_intr_md.ingress_port == HELD_RETURN) {
            returning.apply(); cookie_word.apply(); cookie_delta.apply(); cookie_guard.apply();
            if (hdr.envelope.stage == 1 || hdr.envelope.stage == 2 ||
                hdr.envelope.stage == 3 || hdr.envelope.stage == 12 ||
                hdr.envelope.stage == 13) { md.work_op = 2; }
        } else if (ig_intr_md.ingress_port != 68) {
            if (ig_intr_md.ingress_port == ACK_INPUT) { ack_guard.apply(); }
            else { typed_guard.apply(); }
            if (md.source_valid == 1 && md.policy != 0) { mint.apply(); }
        }
        original_slot.apply();
        work.apply(md.work_op, md.generation, md.work_phase);
        if (md.work_op == 1 && md.work_phase == 4) { md.role = 1; }
        else if (md.work_op == 2) {
            if (md.work_phase == 1 && md.cookie_valid == 1) { admission.apply(); md.role = 2; }
            else if (md.work_phase == 2) { md.role = 3; }
            else if (md.work_phase == 3) { md.role = 4; }
        } else if (ig_intr_md.ingress_port == HELD_RETURN) {
            held_dispatch.apply();
        }
        successful_admission.apply();
        if (md.timing_event == 1) { md.timing_authorized = timing_check.execute(0); }
        if (md.timing_authorized == 1) { md.anchor_operation = 1; md.seen_operation = 1; }
        anchor_event.apply(); observation_event.apply();
        anchor_timestamp.apply(); deadline_offsets.apply(); deadline_deltas.apply();
        if (ig_intr_md.ingress_port == 68) { heartbeat_eligibility.apply(); }
        release_event.apply(); release_snapshot.apply(); ack_commit.apply();
        response_clock.apply(); response_age.apply(); response_eligibility.apply(); ready_event.apply();
        if (md.role == 7) { original_eligibility.apply(); }
        if (md.role == 5) { terminal.apply(); }
        credits.apply(md.credit_op, md.original_index, md.epoch, hdr.envelope.expected_credit, md.result);
        if (ig_intr_md.ingress_port == 68) {
            hdr.heartbeat_report.setValid(); hdr.heartbeat_report.anchor = md.anchor;
            hdr.heartbeat_report.release = md.current_release;
            hdr.heartbeat_report.response_ready = md.response_ready; hdr.heartbeat_report.now = md.now;
            ig_tm_md.ucast_egress_port = FORWARD_PORT;
        } else if (md.role == 1) { snapshot.apply(); loop.apply(); }
        else if (md.role == 2) {
            if (md.credit_op == 1 && md.result == 1) {
                hdr.envelope.expected_credit = md.desired; hdr.envelope.stage = 2;
            } else { hdr.envelope.stage = 12; }
            loop.apply();
        } else if (md.role == 3) {
            if (hdr.envelope.stage == 12) { hdr.envelope.stage = 13; }
            else { hdr.envelope.stage = 3; }
            loop.apply();
        }
        else if (md.role == 4) {
            if (hdr.envelope.stage == 1 || hdr.envelope.stage == 12 || hdr.envelope.stage == 13) { off_outcome.apply(); }
            else { hdr.envelope.stage = 4; loop.apply(); }
        } else if (md.role == 5) {
            if (md.credit_op == 2 && md.result == 1) {
                if (md.release_reason == 2) { forward_original(); }
                else { off_outcome.apply(); }
            }
            else if (md.credit_op == 3 && md.result == 1) { ig_dprsr_md.drop_ctl = 1; }
            else { hdr.envelope.stage = 5; loop.apply(); }
        } else if (md.role == 6) { refresh.apply(); loop.apply(); }
        else if (md.role == 7) { loop.apply(); }
        else {
            // Refused front producer forwards unchanged and never owns credit.
            // Invalid/stale private returns are duplicate suppression only.
            if (ig_intr_md.ingress_port == HELD_RETURN) { ig_dprsr_md.drop_ctl = 1; }
            else { off_outcome.apply(); }
        }
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) { apply { pkt.emit(hdr); } }
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
