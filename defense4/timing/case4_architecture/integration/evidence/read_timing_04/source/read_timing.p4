// READ timing role T, copy-evolved from ownership/p4/held_timing_expected_probe.p4 (the probe is
// untouched; see STEP2_DESIGN.md section 2.3 and tickets T6/T7). Phase-qualified held-original
// timing: actual emitted private stages feed expected-phase SALU equality with immutable
// generation; four heartbeat passes use a 28-byte snapshot independent of original circulation.
// T6: D_A, readiness, response gap and the 40 ms cap are action data of deadline_offsets
// (default action = the 5 ms values, replaceable at run time), not constants. The cap and the
// no-ACK response fallback are table rows. Every private port comes from ports.p4.
// T7: anchor, observations, releases, response deadline and ready bit are cookie-tagged 64-bit
// cells {cookie, word}. Reads return the word only when the cell cookie equals md.timing_cookie
// (the active association cookie on a heartbeat snapshot pass, the packet's own cookie on every
// other pass); a writer with a higher cookie lazily re-arms the cell, an equal cookie
// accumulates, a lower (stale) cookie is ignored. No cell is ever cleared. The heartbeat service path holds no pinned work
// record (heartbeat_work removed): each service pass is derived from the packet alone, so a lost
// pass cannot wedge later ticks. Cookies are minted non-wrapping, so the ordered compare is safe.
// T8-T11: READ association lifecycle. N hands typed events (tev_h: epoch, t0q, kind) to T_IN:
// 9 request, 10 ACK, 11 response, 12 unsent OPERATE (kept from the probe), 4 reset. A request
// runs four pinned passes: P0 claim, P1 debt peek (written straight into the packet), P2 mint
// cookie and install the ACK receipt, P3 install the response receipt, commit the association
// (binding + request-anchored t0q) and forward the request to RELAY_PORT. Debt or exhaustion or
// policy-off or quarantine forwards the request unchanged and is counted. Originals no longer
// arm the anchor. Not target evidence; N-to-T transport and cross-pipe behaviour are untested.
#include <core.p4>
#include <tna.p4>
#include "expected_work_record.p4"
#include "read_credit.p4"
#include "ports.p4"
// Observations derive only from real receipt CAS success carried by a genuine WorkRecord
// return. No externally asserted seen/proof or CPU packet service. No packet spacing is assumed.
// WorkRecord protects all producer passes; three indexed receipts prevent same-cookie
// original-slot reuse after terminal.
struct timing_binding_t { bit<32> epoch; bit<32> cookie; }
struct timing_cell_t { bit<32> cookie; bit<32> word; }
header heartbeat_service_t {
    bit<32> epoch; bit<32> generation; bit<32> cookie; bit<8> stage; bit<24> reserved;
    bit<32> anchor; bit<32> seen; bit<32> response_deadline;
}
header tev_t {
    bit<32> epoch; bit<32> wgen; bit<32> t0q; bit<8> kind; bit<8> stage; bit<16> reserved;
}
header heartbeat_report_t { bit<32> anchor; bit<32> release; bit<32> response_ready; bit<32> now; }
header envelope_t {
    bit<32> epoch; bit<32> generation; bit<32> cookie; bit<32> expected_credit;
    bit<8> kind; bit<8> stage; bit<16> reserved;
}
header ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }
struct header_t { pktgen_timer_header_t timer; heartbeat_service_t service; envelope_t envelope; tev_t tev; ethernet_t eth; heartbeat_report_t heartbeat_report; }
struct metadata_t {
    bit<8> kind; bit<8> work_op; bit<8> credit_op; bit<8> role;
    bit<8> cookie_valid; bit<8> state_valid;
    bit<2> original_index;
    bit<8> allocator_role; bit<8> service_operation; bit<8> service_role;
    bit<32> service_phase; bit<32> work_expected; bit<32> timing_epoch; bit<32> timing_cookie;
    bit<32> response_snapshot;
    bit<8> timing_event; bit<8> timing_authorized; bit<8> anchor_operation;
    bit<8> seen_operation; bit<8> response_operation; bit<8> reply_operation;
    bit<8> response_eligible; bit<32> ready_set; bit<8> release_reason;
    bit<32> now; bit<32> anchor; bit<32> t0; bit<32> seen; bit<32> seen_mask;
    bit<32> normal_deadline; bit<32> readiness_deadline;
    bit<32> cap_deadline; bit<32> normal_delta; bit<32> readiness_delta; bit<32> cap_delta;
    bit<32> eligible_mask; bit<32> old_release; bit<32> current_release;
    bit<32> response_anchor; bit<32> response_deadline; bit<32> response_delta;
    bit<32> response_ready;
    bit<32> generation; bit<32> work_phase; bit<32> epoch;
    bit<32> policy; bit<32> result; bit<32> desired;
    bit<32> expected_cookie; bit<32> cookie_difference;
    bit<32> credit_word; bit<32> anchor_time; bit<32> quarantined; bit<32> debt; bit<32> bumped;
    bit<8> debt_peek;
}
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        md.kind = 0; md.work_expected = 0; md.service_phase = 0; md.timing_cookie = 0; md.epoch = 0;
        transition select(ig_intr_md.ingress_port) {
            HB_PKTGEN : heartbeat_timer;
            HB_RETURN : heartbeat_return;
            T_IN : typed_event;
            HELD_RETURN : return_envelope;
            default : reject;
        }
    }
    state heartbeat_return {
        pkt.extract(hdr.service);
        md.timing_epoch = hdr.service.epoch; md.timing_cookie = hdr.service.cookie;
        transition select(hdr.service.reserved, hdr.service.stage) {
            (0, 1) : opaque_ethernet;
            (0, 2) : opaque_ethernet;
            (0, 3) : opaque_ethernet;
            default : reject;
        }
    }
    state heartbeat_timer {
        pkt.extract(hdr.timer);
        transition select(hdr.timer.app_id) { 0 : opaque_ethernet; default : reject; }
    }
    // N's typed event; epoch is N's verified connection epoch. The original frame follows opaque.
    state typed_event {
        pkt.extract(hdr.tev);
        md.epoch = hdr.tev.epoch;
        transition select(hdr.tev.kind, hdr.tev.stage, hdr.tev.reserved) {
            (9, 0, 0) : event_request;
            (10, 0, 0) : event_ack;
            (11, 0, 0) : event_response;
            (12, 0, 0) : event_operate;
            (4, 0, 0) : event_reset;
            default : reject;
        }
    }
    state event_request { md.kind = 9; transition opaque_ethernet; }
    state event_ack { md.kind = 1; transition opaque_ethernet; }
    state event_response { md.kind = 2; transition opaque_ethernet; }
    state event_operate { md.kind = 3; transition opaque_ethernet; }
    state event_reset { md.kind = 4; transition opaque_ethernet; }
    state return_envelope {
        pkt.extract(hdr.envelope);
        md.epoch = hdr.envelope.epoch;
        transition select(hdr.envelope.reserved, hdr.envelope.stage) {
            (0, 1) : return_phase1;
            (0, 2) : return_phase2;
            (0, 12) : return_phase2;
            (0, 3) : return_phase3;
            (0, 13) : return_phase3;
            (0, 4) : return_tail;
            (0, 5) : return_tail;
            default : reject;
        }
    }
    state return_phase1 { md.work_expected = 1; transition return_tail; }
    state return_phase2 { md.work_expected = 2; transition return_tail; }
    state return_phase3 { md.work_expected = 3; transition return_tail; }
    // A request in its pinned passes keeps N's typed event (t0q) after the private envelope.
    state return_tail {
        transition select(hdr.envelope.kind) { 9 : return_request; default : opaque_ethernet; }
    }
    state return_request { pkt.extract(hdr.tev); transition opaque_ethernet; }
    // Original bytes remain opaque on real returns. They are emitted unchanged after the
    // prefix/ethernet and never reassembled.
    state opaque_ethernet { pkt.extract(hdr.eth); transition accept; }
}
control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    ExpectedWorkRecord() work; OriginalCredit() credits;
    // Association binding {epoch, cookie}: written once per READ at ADMIT P3, checked by original
    // admissions, read (cookie) on a heartbeat snapshot pass. One register, one table.
    Register<timing_binding_t, bit<1>>(1, {0, 0}) timing_binding;
    RegisterAction<timing_binding_t, bit<1>, bit<8>>(timing_binding) timing_check = {
        void apply(inout timing_binding_t value, out bit<8> accepted) {
            accepted = 0;
            if (value.epoch == md.timing_epoch && value.cookie == md.timing_cookie) { accepted = 1; }
        }
    };
    RegisterAction<timing_binding_t, bit<1>, bit<8>>(timing_binding) timing_install = {
        void apply(inout timing_binding_t value, out bit<8> accepted) {
            accepted = 0; value.epoch = md.timing_epoch; value.cookie = md.timing_cookie;
        }
    };
    RegisterAction<timing_binding_t, bit<1>, bit<32>>(timing_binding) timing_current = {
        void apply(inout timing_binding_t value, out bit<32> out_value) { out_value = value.cookie; }
    };
    // Quantized timestamp leaves eight zero low bits. Bit0 marks actual first
    // admission; it prevents a heartbeat mixing a new observation with an old
    // unarmed timestamp when packets are adjacent in the pipeline.
    Register<timing_cell_t, bit<1>>(1, {0, 0}) admission_anchor;
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(admission_anchor) anchor_read = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie == md.timing_cookie) { out_value = value.word; }
        }
    };
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(admission_anchor) anchor_arm = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie < md.timing_cookie) {
                value.cookie = md.timing_cookie; value.word = md.anchor_time | 32w1; out_value = value.word;
            } else if (value.cookie == md.timing_cookie) { out_value = value.word; }
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
    Register<timing_cell_t, bit<1>>(1, {0, 0}) observations;
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(observations) observation_read = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie == md.timing_cookie) { out_value = value.word; }
        }
    };
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(observations) observation_record = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie < md.timing_cookie) {
                value.cookie = md.timing_cookie; value.word = md.seen_mask; out_value = value.word;
            } else if (value.cookie == md.timing_cookie) {
                value.word = value.word | md.seen_mask; out_value = value.word;
            }
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
    Register<timing_cell_t, bit<1>>(1, {0, 0}) releases;
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(releases) release_read = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie == md.timing_cookie) { out_value = value.word; }
        }
    };
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(releases) release_service = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie < md.timing_cookie) {
                value.cookie = md.timing_cookie; value.word = md.eligible_mask; out_value = value.word;
            } else if (value.cookie == md.timing_cookie) {
                value.word = value.word | md.eligible_mask; out_value = value.word;
            }
        }
    };
    action load_releases() { md.current_release = release_read.execute(0); }
    action service_releases() { md.current_release = release_service.execute(0); }
    table release_event {
        key = { ig_intr_md.ingress_port : exact; md.service_phase : exact; md.timing_authorized : exact; }
        actions = { load_releases; service_releases; }
        const entries = { (HB_RETURN, 1, 1) : service_releases(); }
        const default_action = load_releases(); size = 1;
    }
    Register<timing_cell_t, bit<1>>(1, {0, 0}) committed_response_deadline;
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(committed_response_deadline) deadline_read = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie == md.timing_cookie) { out_value = value.word; }
        }
    };
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(committed_response_deadline) deadline_write = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie > md.timing_cookie) { out_value = 0; }
            else {
                value.cookie = md.timing_cookie; value.word = md.response_anchor | 32w1;
                out_value = value.word;
            }
        }
    };
    action load_response_deadline() { hdr.service.response_deadline = deadline_read.execute(0); }
    action commit_response_deadline() { md.response_deadline = deadline_write.execute(0); }
    table response_clock {
        key = { md.role : ternary; md.kind : ternary; md.release_reason : ternary;
                md.credit_op : ternary; md.result : ternary; md.service_role : ternary; }
        actions = { load_response_deadline; commit_response_deadline; NoAction; }
        const entries = {
            (5, 1, 2, 2, 1, _) : commit_response_deadline();
            (_, _, _, _, _, 1) : load_response_deadline();
        }
        const default_action = NoAction(); size = 2;
    }
    Register<timing_cell_t, bit<1>>(1, {0, 0}) ready_response;
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(ready_response) ready_read = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie == md.timing_cookie) { out_value = value.word; }
        }
    };
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(ready_response) ready_service = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.cookie < md.timing_cookie) {
                value.cookie = md.timing_cookie; value.word = md.ready_set; out_value = value.word;
            } else if (value.cookie == md.timing_cookie) {
                value.word = value.word | md.ready_set; out_value = value.word;
            }
        }
    };
    action load_ready_response() { md.response_ready = ready_read.execute(0); }
    action service_ready_response() { md.response_ready = ready_service.execute(0); }
    table ready_event {
        key = { ig_intr_md.ingress_port : exact; md.service_phase : exact; md.timing_authorized : exact; }
        actions = { load_ready_response; service_ready_response; }
        const entries = { (HB_RETURN, 1, 1) : service_ready_response(); }
        const default_action = load_ready_response(); size = 1;
    }
    action clock_sample() { md.now = ((bit<32>)ig_prsr_md.global_tstamp) & 32w0xffffff00; }
    table clock { actions = { clock_sample; } const default_action = clock_sample(); size = 1; }
    action relay_ack() { md.timing_epoch = hdr.envelope.epoch; md.timing_cookie = hdr.envelope.cookie; md.timing_event = 1; md.seen_mask = 1; }
    action relay_response() { md.timing_epoch = hdr.envelope.epoch; md.timing_cookie = hdr.envelope.cookie; md.timing_event = 1; md.seen_mask = 2; }
    action relay_operate() { md.timing_epoch = hdr.envelope.epoch; md.timing_cookie = hdr.envelope.cookie; md.timing_event = 1; md.seen_mask = 0; }
    // READ request admission (ticket T8). P2 (role 3, stage 2): the mint put a cookie word in
    // credit_word and the ACK receipt is installed; if the debt peek was nonzero credit_word is that
    // debt (1..3) and an exhausted mint leaves 0, so low16 != 0 or the word is 0 and nothing installs.
    // P3 (role 4, stage 3): install the response receipt, commit the association, forward.
    action install_ack_receipt() { md.credit_op = 3; }
    action commit_association() {
        md.credit_op = 3; md.timing_event = 2; md.anchor_operation = 1;
        md.timing_epoch = hdr.envelope.epoch; md.timing_cookie = hdr.envelope.cookie;
        md.anchor_time = hdr.tev.t0q;
    }
    table successful_admission {
        key = { md.role : exact; hdr.envelope.stage : exact; md.kind : exact; md.credit_word : ternary; }
        actions = { relay_ack; relay_response; relay_operate; install_ack_receipt; commit_association; NoAction; }
        const entries = {
            (3, 2, 1, _) : relay_ack(); (3, 2, 2, _) : relay_response(); (3, 2, 3, _) : relay_operate();
            (3, 2, 9, 0 &&& 0xffffffff) : NoAction();
            (3, 2, 9, 0 &&& 0xffff) : install_ack_receipt();
            (4, 3, 9, _) : commit_association();
        }
        const default_action = NoAction(); size = 6;
    }
    action prepare_anchor() { md.t0 = hdr.service.anchor & 32w0xffffff00; }
    table anchor_timestamp { actions = { prepare_anchor; } const default_action = prepare_anchor(); size = 1; }
    // Offsets are multiples of 256 ns (clock grid). Defaults are the 5 ms case; the control
    // plane replaces the default action to install D_A = 10, 15 or 20 ms, readiness, gap, cap.
    action prepare_deadlines(bit<32> normal_offset, bit<32> readiness_offset,
                             bit<32> gap_offset, bit<32> cap_offset) {
        md.normal_deadline = md.t0 + normal_offset;
        md.readiness_deadline = md.t0 + readiness_offset;
        md.cap_deadline = md.t0 + cap_offset;
        md.response_anchor = md.now + gap_offset;
    }
    table deadline_offsets {
        actions = { prepare_deadlines; }
        default_action = prepare_deadlines(4999936, 29999872, 999936, 40000000); size = 1;
    }
    action prepare_deltas() {
        md.normal_delta = md.now - md.normal_deadline;
        md.readiness_delta = md.now - md.readiness_deadline;
        md.cap_delta = md.now - md.cap_deadline;
    }
    table deadline_deltas { actions = { prepare_deltas; } const default_action = prepare_deltas(); size = 1; }
    action eligible_ack_operate() { md.eligible_mask = 3; }
    action eligible_operate() { md.eligible_mask = 1; }
    table heartbeat_eligibility {
        key = { hdr.service.anchor : ternary; md.normal_delta : ternary; md.readiness_delta : ternary;
                md.cap_delta : ternary; hdr.service.seen : ternary; }
        actions = { eligible_ack_operate; eligible_operate; NoAction; }
        const entries = {
            (1 &&& 1, 0 &&& 0x80000000, _, _, 3) : eligible_ack_operate();
            (1 &&& 1, _, 0 &&& 0x80000000, _, _) : eligible_ack_operate();
            (1 &&& 1, _, _, 0 &&& 0x80000000, _) : eligible_ack_operate();
            (1 &&& 1, 0 &&& 0x80000000, _, _, _) : eligible_operate();
        }
        const default_action = NoAction(); size = 4;
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
    action snapshot_response() { md.response_snapshot = hdr.service.response_deadline & 32w0xffffff00; }
    table response_snapshot { actions = { snapshot_response; } const default_action = snapshot_response(); size = 1; }
    action reply_delta() { md.response_delta = md.now - md.response_snapshot; }
    table response_age { actions = { reply_delta; } const default_action = reply_delta(); size = 1; }
    action reply_eligible() { md.response_eligible = 1; md.ready_set = 32w1; }
    table response_eligibility {
        key = { hdr.service.anchor : ternary; hdr.service.response_deadline : ternary; hdr.service.seen : ternary;
                md.response_delta : ternary; md.readiness_delta : ternary; md.cap_delta : ternary; }
        actions = { reply_eligible; NoAction; }
        const entries = {
            // armed response deadline has elapsed
            (1 &&& 1, 1 &&& 1, _, 0 &&& 0x80000000, _, _) : reply_eligible();
            // FALLBACK_NO_ACK: response observed, no ACK committed (deadline unarmed), readiness elapsed
            // (a response not yet seen must not pre-set the sticky ready bit: it would skip the gap)
            (1 &&& 1, 0 &&& 1, 2 &&& 2, _, 0 &&& 0x80000000, _) : reply_eligible();
            // hard cap
            (1 &&& 1, _, _, _, _, 0 &&& 0x80000000) : reply_eligible();
        }
        const default_action = NoAction(); size = 3;
    }
    action timing_debit() {
        md.role = 5; md.release_reason = 2; md.credit_op = 2;
        md.desired = hdr.envelope.expected_credit & 32w0xfffffffe; md.state_valid = 1;
    }
    action timing_duplicate() { md.role = 5; md.release_reason = 2; md.credit_op = 0; }
    table original_eligibility {
        key = { hdr.envelope.stage : exact; md.cookie_valid : exact; md.kind : exact;
                md.current_release : ternary; md.response_ready : ternary;
                hdr.envelope.expected_credit : ternary; }
        actions = { timing_debit; timing_duplicate; NoAction; }
        const entries = {
            (4, 1, 1, 2 &&& 2, _, 0x101 &&& 0x101) : timing_debit();
            (4, 1, 2, _, 1, 0x101 &&& 0x101) : timing_debit();
            (4, 1, 3, 1 &&& 1, _, 0x101 &&& 0x101) : timing_debit();
            (4, 1, 1, 2 &&& 2, _, _) : timing_duplicate();
            (4, 1, 2, _, 1, _) : timing_duplicate();
            (4, 1, 3, 1 &&& 1, _, _) : timing_duplicate();
        }
        const default_action = NoAction(); size = 6;
    }

    // Cookie mint: {count, word}. Cookies 1..65535 are minted as word = cookie16<<16; the 65536th
    // call wraps the word to 0 and every later call returns 0: refusal, cookie exhausted.
    Register<timing_cell_t, bit<1>>(1, {0, 0}) cookie_counter;
    RegisterAction<timing_cell_t, bit<1>, bit<32>>(cookie_counter) mint_cookie_word = {
        void apply(inout timing_cell_t value, out bit<32> out_value) {
            if (value.cookie < 32w65536) { value.cookie = value.cookie + 1; value.word = value.word + 32w0x10000; }
            out_value = value.word;
        }
    };
    // Aggregate owned originals of the current association (OriginalDebt semantics): +1 on a real
    // admit success, -1 on a real terminal success, saturating 0..3. Peek writes the packet.
    Register<bit<32>, bit<1>>(1, 0) debt_cell;
    RegisterAction<bit<32>, bit<1>, bit<32>>(debt_cell) debt_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(debt_cell) debt_increment = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (value < 3) { value = value + 1; }
            out_value = value;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(debt_cell) debt_decrement = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (value > 0) { value = value - 1; }
            out_value = value;
        }
    };
    // Epoch of the last reset connection. A pass whose epoch equals it is quarantined:
    // held originals flush as policy-off, no new request is admitted.
    Register<bit<32>, bit<1>>(1, 0) quarantined_epoch;
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantined_epoch) quarantine_check = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = 0;
            if (value == md.epoch) { out_value = 1; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantined_epoch) quarantine_set = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.epoch; out_value = 1; }
    };
    action load_quarantine() { md.quarantined = quarantine_check.execute(0); }
    action set_quarantine() { md.quarantined = quarantine_set.execute(0); }
    table quarantine_event {
        key = { md.kind : exact; }
        actions = { load_quarantine; set_quarantine; }
        const entries = { 4 : set_quarantine(); }
        const default_action = load_quarantine(); size = 1;
    }
    // Bypass counters: 0 busy request, 1 cookie exhausted, 2 policy-off or quarantined request,
    // 3 original forwarded unheld (front refusal or refused admission).
    Register<bit<32>, bit<3>>(4, 0) bypass_counters;
    RegisterAction<bit<32>, bit<3>, bit<32>>(bypass_counters) bypass_bump = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = value + 1; out_value = value; }
    };
    action count_busy() { md.bumped = bypass_bump.execute(0); }
    action count_exhausted() { md.bumped = bypass_bump.execute(1); }
    action count_policy() { md.bumped = bypass_bump.execute(2); }
    action count_unheld() { md.bumped = bypass_bump.execute(3); }
    table bypass_count {
        key = { md.role : exact; md.work_op : ternary; md.kind : exact; md.credit_word : ternary;
                hdr.envelope.stage : ternary; ig_intr_md.ingress_port : ternary; }
        actions = { count_busy; count_exhausted; count_policy; count_unheld; NoAction; }
        const entries = {
            (0, 0, 9, _, _, T_IN) : count_policy();
            (0, 1, 9, _, _, T_IN) : count_busy();
            (0, _, 1, _, _, T_IN) : count_unheld();
            (0, _, 2, _, _, T_IN) : count_unheld();
            (0, _, 3, _, _, T_IN) : count_unheld();
            (4, _, 1, _, 12 &&& 0xfe, _) : count_unheld();
            (4, _, 2, _, 12 &&& 0xfe, _) : count_unheld();
            (4, _, 3, _, 12 &&& 0xfe, _) : count_unheld();
            (3, _, 9, 0, 2, _) : count_exhausted();
            (3, _, 9, 0 &&& 0xfffffffc, 2, _) : count_busy();
        }
        const default_action = NoAction(); size = 11;
    }
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
    action allocate_source() { md.generation = allocate.execute(0); md.work_op = 1; }
    action allocate_heartbeat() { md.generation = allocate.execute(0); md.service_operation = 1; }
    table mint {
        key = { md.allocator_role : exact; }
        actions = { allocate_source; allocate_heartbeat; NoAction; }
        const entries = { 1 : allocate_source(); 2 : allocate_heartbeat(); }
        const default_action = NoAction(); size = 2;
    }
    // ---- READ request admission (ticket T8) -------------------------------------------------
    // P1 (role 2): the debt cell is read straight into the packet (written by debt_event below).
    // P2 (role 3): with debt 0, mint a cookie word and install the ACK receipt; otherwise refuse.
    // P3 (role 4): install the response receipt, commit the association, forward the request.
    action mint_cookie() { md.credit_word = mint_cookie_word.execute(0); }
    // Early keys only (parser-known): the packet is a request P2 pass and the debt peek is zero.
    // A nonzero debt peek (1..3) becomes the credit word: low16 != 0, so nothing installs, and the
    // bypass counter reads it as busy; an exhausted mint leaves 0.
    action carry_debt() { md.credit_word = hdr.tev.wgen; }
    table request_mint {
        key = { md.kind : exact; hdr.envelope.stage : exact; hdr.tev.wgen : ternary; }
        actions = { mint_cookie; carry_debt; NoAction; }
        const entries = { (9, 2, 0 &&& 0xffffffff) : mint_cookie(); (9, 2, _) : carry_debt(); }
        const default_action = NoAction(); size = 2;
    }
    action peek_debt() { hdr.tev.wgen = debt_read.execute(0); }
    action own_debt() { md.debt = debt_increment.execute(0); }
    action settle_debt() { md.debt = debt_decrement.execute(0); }
    table debt_event {
        key = { md.debt_peek : exact; md.credit_op : exact; md.result : exact; }
        actions = { peek_debt; own_debt; settle_debt; NoAction; }
        const entries = {
            (1, 5, 0) : peek_debt();
            (0, 1, 1) : own_debt();
            (0, 2, 1) : settle_debt();
        }
        const default_action = NoAction(); size = 3;
    }
    action capture_return() {
        md.generation = hdr.envelope.generation; md.epoch = hdr.envelope.epoch; md.kind = hdr.envelope.kind;
        md.timing_cookie = hdr.envelope.cookie; md.credit_word = hdr.envelope.expected_credit;
    }
    table returning { actions = { capture_return; } const default_action = capture_return(); size = 1; }
    action cookie_extract() { md.expected_cookie = hdr.envelope.expected_credit >> 16; }
    table cookie_word { actions = { cookie_extract; } const default_action = cookie_extract(); size = 1; }
    action cookie_compare() { md.cookie_difference = hdr.envelope.cookie ^ md.expected_cookie; }
    table cookie_delta { actions = { cookie_compare; } const default_action = cookie_compare(); size = 1; }
    action cookie_accept() { md.cookie_valid = 1; }
    table cookie_guard {
        key = { md.cookie_difference : exact; hdr.envelope.cookie : ternary; }
        actions = { cookie_accept; NoAction; }
        const entries = { (0, 0 &&& 0xffffffff) : NoAction(); (0, 0 &&& 0xffff0000) : cookie_accept(); }
        const default_action = NoAction(); size = 2;
    }
    action index_ack() { md.original_index = 0; }
    action index_response() { md.original_index = 1; }
    action index_operate() { md.original_index = 2; }
    table original_slot {
        key = { md.kind : exact; hdr.envelope.stage : ternary; }
        actions = { index_ack; index_response; index_operate; }
        const entries = { (2, _) : index_response(); (3, _) : index_operate(); (9, 3) : index_response(); }
        const default_action = index_ack(); size = 3;
    }
    action admit_original() { md.desired = hdr.envelope.expected_credit | 32w0x101; md.credit_op = 1; md.state_valid = 1; }
    // A request's P1 is not an admission: credit op 5 (no operation) keeps the credit result 0 so the
    // debt cell is peeked by debt_event with an exact key.
    action request_peek() { md.credit_op = 5; md.debt_peek = 1; }
    table admission {
        key = { md.kind : exact; md.cookie_valid : ternary; hdr.envelope.expected_credit : ternary; }
        actions = { admit_original; request_peek; NoAction; }
        const entries = {
            (1, 1, 0 &&& 0x101) : admit_original();
            (2, 1, 0 &&& 0x101) : admit_original();
            (3, 1, 0 &&& 0x101) : admit_original();
            (9, _, _) : request_peek();
        }
        const default_action = NoAction(); size = 4;
    }
    action debit_original() { md.desired = hdr.envelope.expected_credit & 32w0xfffffffe; md.credit_op = 2; md.state_valid = 1; }
    action check_duplicate() { md.credit_op = 0; }
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
    // N's typed event is stripped everywhere except while a request is in its pinned passes
    // (one table owns the validity bit, so no other table serializes against it).
    action strip_event() { hdr.tev.setInvalid(); }
    table strip_tev {
        key = { md.kind : exact; md.role : exact; }
        actions = { strip_event; NoAction; }
        const entries = { (9, 1) : NoAction(); (9, 2) : NoAction(); (9, 3) : NoAction(); }
        const default_action = strip_event(); size = 3;
    }
    action off_terminal() { md.role = 5; md.release_reason = 1; }
    action refresh_return() { md.role = 6; }
    action held_return() { md.role = 7; }
    table held_dispatch {
        key = { hdr.envelope.stage : exact; md.policy : ternary; md.cookie_valid : exact; md.quarantined : ternary; }
        actions = { off_terminal; refresh_return; held_return; NoAction; }
        const entries = {
            (4, 0, 1, _) : off_terminal();
            (4, _, 1, 1) : off_terminal();
            (4, _, 1, _) : held_return();
            (5, _, 1, _) : refresh_return();
        }
        const default_action = NoAction(); size = 4;
    }
    action check_timing_key() { md.timing_authorized = timing_check.execute(0); }
    action install_timing_key() { md.timing_authorized = timing_install.execute(0); }
    action read_timing_key() { md.timing_cookie = timing_current.execute(0); }
    // Service passes are qualified by the cookie-ordered cells themselves; no epoch is carried.
    action authorize_service() { md.timing_authorized = 1; }
    table timing_authority {
        key = { md.timing_event : ternary; ig_intr_md.ingress_port : ternary; md.service_phase : ternary; }
        actions = { check_timing_key; install_timing_key; read_timing_key; authorize_service; NoAction; }
        const entries = {
            (1, _, _) : check_timing_key();
            (2, _, _) : install_timing_key();
            (3, _, _) : read_timing_key();
            (_, HB_RETURN, 1) : authorize_service();
        }
        const default_action = NoAction(); size = 4;
    }
    action admit_timing_event() { md.seen_operation = 1; }
    table timing_admission {
        key = { md.timing_event : exact; md.timing_authorized : exact; }
        actions = { admit_timing_event; NoAction; }
        const entries = { (1, 1) : admit_timing_event(); }
        const default_action = NoAction(); size = 1;
    }
    // One table owns every packet-byte and port outcome (logical-table budget of the last stage).
    action t_drop() { ig_dprsr_md.drop_ctl = 1; }
    action t_hb_snapshot() {
        hdr.service.setValid(); hdr.service.epoch = md.epoch;
        hdr.service.generation = md.generation; hdr.service.cookie = md.result >> 16;
        hdr.service.anchor = md.anchor; hdr.service.seen = md.seen;
        hdr.service.stage = 1; hdr.service.reserved = 0; hdr.timer.setInvalid();
        ig_tm_md.ucast_egress_port = HB_RETURN;
    }
    action t_hb_next() { hdr.service.stage = hdr.service.stage + 1; ig_tm_md.ucast_egress_port = HB_RETURN; }
    action t_hb_report() {
        hdr.service.setInvalid();
        hdr.heartbeat_report.setValid(); hdr.heartbeat_report.anchor = md.anchor;
        hdr.heartbeat_report.release = md.current_release;
        hdr.heartbeat_report.response_ready = md.response_ready; hdr.heartbeat_report.now = md.now;
        ig_tm_md.ucast_egress_port = FORWARD_PORT;
    }
    action t_start() { producer_snapshot(); ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_request_p1() { hdr.envelope.stage = 2; ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_admit_ok() {
        hdr.envelope.expected_credit = md.desired; hdr.envelope.stage = 2; ig_tm_md.ucast_egress_port = HELD_RETURN;
    }
    action t_stage12() { hdr.envelope.stage = 12; ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_request_p2_ok() {
        hdr.envelope.expected_credit = md.credit_word; hdr.envelope.cookie = md.credit_word >> 16;
        hdr.envelope.stage = 3; ig_tm_md.ucast_egress_port = HELD_RETURN;
    }
    action t_stage13() { hdr.envelope.stage = 13; ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_stage3() { hdr.envelope.stage = 3; ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_stage4() { hdr.envelope.stage = 4; ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_stage5() { hdr.envelope.stage = 5; ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_loop() { ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_refresh() { hdr.envelope.expected_credit = md.result; hdr.envelope.stage = 4; ig_tm_md.ucast_egress_port = HELD_RETURN; }
    action t_forward() { hdr.envelope.setInvalid(); ig_tm_md.ucast_egress_port = FORWARD_PORT; }
    action t_forward_request() { hdr.envelope.setInvalid(); ig_tm_md.ucast_egress_port = RELAY_PORT; }
    table tail {
        key = { md.service_role : ternary; ig_intr_md.ingress_port : ternary; md.role : ternary; md.kind : ternary;
                hdr.envelope.stage : ternary; md.credit_op : ternary; md.result : ternary; md.release_reason : ternary; }
        actions = { t_drop; t_hb_snapshot; t_hb_next; t_hb_report; t_start; t_request_p1; t_admit_ok; t_stage12;
                    t_request_p2_ok; t_stage13; t_stage3; t_stage4; t_stage5; t_loop; t_refresh; t_forward;
                    t_forward_request; NoAction; }
        const entries = {
            // heartbeat service passes, then pktgen/return passes that are not service roles
            (1, _, _, _, _, _, _, _) : t_hb_snapshot();
            (2, _, _, _, _, _, _, _) : t_hb_next();
            (3, _, _, _, _, _, _, _) : t_hb_report();
            (_, HB_PKTGEN, _, _, _, _, _, _) : t_drop();
            (_, HB_RETURN, _, _, _, _, _, _) : t_drop();
            // role 1: first pass of a producer
            (_, _, 1, _, _, _, _, _) : t_start();
            // role 2: request P1, admitted original, refused original
            (_, _, 2, 9, _, _, _, _) : t_request_p1();
            (_, _, 2, _, _, 1, 1, _) : t_admit_ok();
            (_, _, 2, _, _, _, _, _) : t_stage12();
            // role 3: request P2, refused marker, ordinary
            (_, _, 3, 9, _, 3, _, _) : t_request_p2_ok();
            (_, _, 3, 9, _, _, _, _) : t_stage13();
            (_, _, 3, _, 12, _, _, _) : t_stage13();
            (_, _, 3, _, _, _, _, _) : t_stage3();
            // role 4: request forward; refused original outcome; held original
            (_, _, 4, 9, _, _, _, _) : t_forward_request();
            (_, _, 4, 3, 1, _, _, _) : t_drop();
            (_, _, 4, 3, 12, _, _, _) : t_drop();
            (_, _, 4, 3, 13, _, _, _) : t_drop();
            (_, _, 4, _, 1, _, _, _) : t_forward();
            (_, _, 4, _, 12, _, _, _) : t_forward();
            (_, _, 4, _, 13, _, _, _) : t_forward();
            (_, _, 4, _, _, _, _, _) : t_stage4();
            // role 5: timing release, policy-off terminal, otherwise retry
            (_, _, 5, 3, _, 2, 1, 1) : t_drop();
            (_, _, 5, _, _, 2, 1, _) : t_forward();
            (_, _, 5, _, _, 0, _, _) : t_drop();
            (_, _, 5, _, _, _, _, _) : t_stage5();
            (_, _, 6, _, _, _, _, _) : t_refresh();
            (_, _, 7, _, _, _, _, _) : t_loop();
            // role 0: stale private return, refused front producer
            (_, HELD_RETURN, 0, _, _, _, _, _) : t_drop();
            (_, _, 0, 3, _, _, _, _) : t_drop();
            (_, _, 0, 4, _, _, _, _) : t_drop();
            (_, _, 0, 9, _, _, _, _) : t_forward_request();
            (_, _, 0, _, _, _, _, _) : t_forward();
        }
        const default_action = NoAction(); size = 35;
    }
    apply {
        md.work_op = 0; md.credit_op = 0; md.role = 0; md.state_valid = 0; md.cookie_valid = 0;
        md.generation = 0; md.result = 0; md.desired = 0;
        md.timing_event = 0; md.timing_authorized = 0; md.anchor_operation = 0;
        md.seen_operation = 0; md.seen_mask = 0; md.eligible_mask = 0;
        md.response_operation = 0; md.response_eligible = 0; md.ready_set = 0; md.release_reason = 0;
        md.allocator_role = 0; md.service_operation = 0; md.service_role = 0; md.debt_peek = 0;
        md.credit_word = 0; md.quarantined = 0; md.anchor_time = 0;
        clock.apply(); anchor_timestamp.apply(); deadline_offsets.apply(); deadline_deltas.apply();
        heartbeat_eligibility.apply(); response_snapshot.apply(); response_age.apply(); response_eligibility.apply();
        md.policy = policy.execute(0);
        quarantine_event.apply();
        ig_tm_md.bypass_egress = 1;
        // A snapshot pass carries no cookie; it reads under the binding's cookie (timing_event 3).
        if (ig_intr_md.ingress_port == HB_PKTGEN) { md.allocator_role = 2; md.timing_event = 3; }
        else if (ig_intr_md.ingress_port == HB_RETURN) {
            // The stage is widened in the control: the compiled parser (model run 04) produced 0x101 for a
            // parser-time (bit<32>) cast of this field.
            md.generation = hdr.service.generation; md.service_operation = 2;
            md.service_phase = (bit<32>)hdr.service.stage;
        }
        else if (ig_intr_md.ingress_port == HELD_RETURN) {
            returning.apply(); cookie_word.apply(); cookie_delta.apply(); cookie_guard.apply();
            if (hdr.envelope.stage == 1 || hdr.envelope.stage == 2 ||
                hdr.envelope.stage == 3 || hdr.envelope.stage == 12 ||
                hdr.envelope.stage == 13) { md.work_op = 2; }
        } else {
            if (md.kind != 4 && md.policy != 0 && md.quarantined == 0) { md.allocator_role = 1; }
        }
        mint.apply(); original_slot.apply(); request_mint.apply();
        if (md.service_operation == 1) { md.service_role = 1; }
        else if (md.service_operation == 2) {
            if (md.service_phase == 1 || md.service_phase == 2) { md.service_role = 2; }
            else if (md.service_phase == 3) { md.service_role = 3; }
        }
        work.apply(md.work_op, md.generation, md.work_expected, md.work_phase);
        if (md.work_op == 1 && md.work_phase == 4) { md.role = 1; }
        else if (md.work_op == 2) {
            if (md.work_phase == 1) { admission.apply(); md.role = 2; }
            else if (md.work_phase == 2) { md.role = 3; }
            else if (md.work_phase == 3) { md.role = 4; }
        } else if (ig_intr_md.ingress_port == HELD_RETURN) {
            held_dispatch.apply();
        }
        // Policy-off is selected before timing. Timing eligibility itself selects
        // the qualified terminal opcode, avoiding a second serial selector.
        if (md.role == 5) { terminal.apply(); }
        successful_admission.apply(); timing_authority.apply(); timing_admission.apply();
        anchor_event.apply(); observation_event.apply(); release_event.apply(); ready_event.apply();
        if (md.role == 7) { original_eligibility.apply(); }
        credits.apply(md.credit_op, md.original_index, md.epoch, md.credit_word, md.result);
        strip_tev.apply(); debt_event.apply(); bypass_count.apply();
        response_clock.apply();
        tail.apply();
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) { apply { pkt.emit(hdr); } }
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
