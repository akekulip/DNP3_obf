#include <core.p4>
#include <tna.p4>
#include "owner_protected_cell.p4"
// Four-pass structural experiment. This is not a full DNP3 policy.
// First pass claims a record before any record writes. Pass two atomically
// claims the current owner cell before payload writes. Pass three checks the
// owner again and publishes a generation. Pass four is the actual terminal.
// The slot issues once per association, so old work cannot alias same-cookie
// reuse. Integration must check this slot before timing/connection rearm.
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header work_ref_t { bit<32> epoch; bit<32> generation; }
header producer_t {
    bit<32> epoch; bit<32> cookie; bit<32> payload;
    bit<8> event; bit<24> reserved; // 0 arm, 1 producer, 255 quarantine
}
header report_t { bit<32> owner; bit<32> work_state; bit<32> published; bit<32> payload; }
struct header_t { ethernet_t ethernet; producer_t producer; report_t report; }
struct metadata_t {
    work_ref_t ref;
    owner_command_t command;
    owner_result_t owner;
    bit<32> epoch;
    bit<32> epoch_difference;
    bit<32> work_state;
    bit<32> work_expected;
    bit<32> work_desired;
    bit<32> claimed;
    bit<32> writing;
    bit<32> closed;
    bit<32> difference;
    bit<32> generation;
    bit<32> counter;
    bit<32> snapshot;
    bit<32> desired;
    bit<32> payload;
    bit<32> ready;
    bit<32> terminal;
    bit<32> publication;
    bit<32> generation_difference;
    bit<8> admitted;
    bit<8> role; // 0 refusal, 1 claim, 2 write, 3 publish, 4 terminal, 5 abort
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
    OwnerProtectedCell() owner;
    Register<bit<32>, bit<1>>(1, 1) connection_epoch;
    RegisterAction<bit<32>, bit<1>, bit<32>>(connection_epoch) epoch_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) work_state;
    RegisterAction<bit<32>, bit<1>, bit<32>>(work_state) work_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(work_state) work_claim = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value;
            if (value < 32w65536 && value != md.work_expected) { value = md.work_desired; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(work_state) work_cas = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value;
            if (value == md.work_expected) { value = md.work_desired; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(work_state) work_close = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value;
            if (value >= 32w65536) { value = (value & 32w65535) | 32w0x30000; }
        }
    };
    Register<bit<32>, bit<1>>(1, 0) record_counter;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_counter) counter_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_counter) counter_increment = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value; if (value < 32w0xffffffff) { value = value + 1; }
        }
    };
    Register<bit<32>, bit<1>>(1, 0) record_generation;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_generation) generation_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_generation) generation_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.generation; }
    };
    Register<bit<32>, bit<1>>(1, 0) record_snapshot;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_snapshot) snapshot_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_snapshot) snapshot_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.snapshot; }
    };
    Register<bit<32>, bit<1>>(1, 0) record_desired;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_desired) desired_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_desired) desired_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.desired; }
    };
    Register<bit<32>, bit<1>>(1, 0) record_payload;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_payload) payload_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_payload) payload_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.payload; }
    };
    Register<bit<32>, bit<1>>(1, 0) record_ready;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_ready) ready_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_ready) ready_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.ready; }
    };
    Register<bit<32>, bit<1>>(1, 0) record_terminal;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_terminal) terminal_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_terminal) terminal_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.terminal; }
    };
    Register<bit<32>, bit<1>>(1, 0) record_publication;
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_publication) publication_read = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(record_publication) publication_write = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; value = md.publication; }
    };
    action authorize() { md.admitted = 1; }
    action refuse() { md.admitted = 0; }
    action diff_epoch() {
        md.epoch_difference = hdr.producer.epoch ^ md.epoch;
        md.generation_difference = md.ref.epoch ^ md.epoch;
        md.claimed = hdr.producer.cookie | 32w0x10000;
        md.writing = hdr.producer.cookie | 32w0x20000;
        md.closed = hdr.producer.cookie | 32w0x30000;
        md.work_expected = hdr.producer.cookie;
        md.work_desired = hdr.producer.cookie | 32w0x10000;
    }
    table epoch_difference { actions = { diff_epoch; } const default_action = diff_epoch(); size = 1; }
    table first_authority {
        key = { md.epoch_difference : exact; hdr.producer.cookie : ternary; md.counter : ternary; }
        actions = { authorize; refuse; }
        const entries = {
            (0, _, 0xffffffff) : refuse();
            (0, 0 &&& 0xffff0000, _) : authorize();
        }
        const default_action = refuse(); size = 2;
    }
    table return_authority {
        key = { md.generation_difference : exact; md.difference : exact; }
        actions = { authorize; refuse; }
        const entries = { (0, 0) : authorize(); }
        const default_action = refuse(); size = 1;
    }
    action form_record_difference() { md.difference = md.generation ^ md.ref.generation; }
    table record_difference {
        actions = { form_record_difference; } const default_action = form_record_difference(); size = 1;
    }
    action claimed_role() { md.role = 1; }
    action write_role() { md.role = 2; }
    action publish_role() { md.role = 3; }
    action abort_role() { md.role = 5; }
    action no_role() { md.role = 0; }
    action difference_claim() { md.difference = md.work_state ^ hdr.producer.cookie; }
    table claim_difference {
        actions = { difference_claim; } const default_action = difference_claim(); size = 1;
    }
    table claim_result {
        key = { md.work_state : ternary; md.difference : ternary; }
        actions = { claimed_role; no_role; }
        const entries = { (_, 0) : no_role(); (0 &&& 0xffff0000, _) : claimed_role(); }
        const default_action = no_role(); size = 2;
    }
    action prepare_return() {
        md.work_expected = md.claimed;
        md.work_desired = md.writing;
        md.difference = md.ready ^ md.ref.generation;
    }
    table returning { actions = { prepare_return; } const default_action = prepare_return(); size = 1; }
    action prepare_terminal() {
        md.work_expected = md.terminal;
        md.work_desired = hdr.producer.cookie;
        md.role = 4;
    }
    action prepare_producer_return() { md.role = 0; }
    table ready {
        key = { md.difference : exact; }
        actions = { prepare_terminal; prepare_producer_return; }
        const entries = { 0 : prepare_terminal(); }
        const default_action = prepare_producer_return(); size = 1;
    }
    action form_return_difference() { md.difference = md.work_state ^ md.claimed; }
    table return_difference {
        actions = { form_return_difference; } const default_action = form_return_difference(); size = 1;
    }
    table return_result {
        key = { md.work_state : ternary; md.difference : ternary; }
        actions = { write_role; publish_role; abort_role; no_role; }
        const entries = {
            (_, 0) : write_role();
            (0x20000 &&& 0xffff0000, _) : publish_role();
            (0x30000 &&& 0xffff0000, _) : abort_role();
        }
        const default_action = no_role(); size = 3;
    }
    action form_owner_read() {
        md.command.epoch = md.epoch; md.command.cookie = hdr.producer.cookie;
        md.command.operation = 0; md.command.reserved = 0;
        md.command.expected = 0; md.command.desired = 0;
    }
    table owner_read_command {
        actions = { form_owner_read; } const default_action = form_owner_read(); size = 1;
    }
    action derive_producer() {
        md.snapshot = md.owner.observed;
        md.desired = md.owner.observed | 32w0x00800000;
        md.generation = md.counter + 1;
        md.ref.epoch = md.epoch;
        md.ref.generation = md.counter + 1;
        md.ready = 0;
        md.terminal = 0;
        md.publication = 0;
    }
    table owner_event {
        actions = { derive_producer; } const default_action = derive_producer(); size = 1;
    }
    action form_owner_claim() {
        md.command.epoch = md.epoch; md.command.cookie = hdr.producer.cookie;
        md.command.operation = 2; md.command.reserved = 0;
        md.command.expected = md.snapshot; md.command.desired = md.desired;
    }
    table owner_claim_command {
        actions = { form_owner_claim; } const default_action = form_owner_claim(); size = 1;
    }
    action form_owner_arm() { md.command.operation = 1; }
    action form_owner_close() { md.command.operation = 3; md.command.expected = hdr.producer.cookie; }
    table owner_arm_command { actions = { form_owner_arm; } const default_action = form_owner_arm(); size = 1; }
    table owner_close_command { actions = { form_owner_close; } const default_action = form_owner_close(); size = 1; }
    action form_publication_difference() { md.difference = md.owner.observed ^ md.desired; }
    table publication_difference {
        actions = { form_publication_difference; } const default_action = form_publication_difference(); size = 1;
    }
    action publish() { md.publication = md.ref.generation; }
    action invalidate() { md.publication = 0; }
    table publication {
        key = { md.difference : exact; md.owner.observed : ternary; }
        actions = { publish; invalidate; }
        const entries = { (0, 0x10000 &&& 0x30000) : publish(); }
        const default_action = invalidate(); size = 1;
    }
    apply {
        md.role = 0;
        md.epoch = epoch_read.execute(0);
        epoch_difference.apply();
        owner_read_command.apply();
        if (ig_intr_md.resubmit_flag == 0) {
            md.counter = counter_read.execute(0);
            first_authority.apply();
            if (md.admitted == 1) {
                if (hdr.producer.event == 0) {
                    md.work_state = work_read.execute(0);
                    if (md.work_state < 32w65536) {
                        owner_arm_command.apply();
                        owner.apply(md.command, md.owner);
                    }
                } else if (hdr.producer.event == 255) {
                    md.work_state = work_close.execute(0);
                    owner_close_command.apply();
                    owner.apply(md.command, md.owner);
                } else if (hdr.producer.event == 1) {
                    md.work_state = work_claim.execute(0);
                    claim_difference.apply();
                    claim_result.apply();
                    if (md.role == 1) {
                        // No protected bank write before claim accepted.
                        owner.apply(md.command, md.owner);
                        md.counter = counter_increment.execute(0);
                        owner_event.apply();
                        generation_write.execute(0);
                        snapshot_write.execute(0);
                        desired_write.execute(0);
                        ready_write.execute(0);
                        terminal_write.execute(0);
                        publication_write.execute(0);
                        ig_dprsr_md.resubmit_type = 1;
                    }
                }
            }
        } else {
            md.generation = generation_read.execute(0);
            record_difference.apply();
            return_authority.apply();
            if (md.admitted == 1) {
                md.ready = ready_read.execute(0);
                md.terminal = terminal_read.execute(0);
                returning.apply();
                ready.apply();
                md.work_state = work_cas.execute(0);
                if (md.role != 4) {
                    return_difference.apply();
                    return_result.apply();
                    if (md.role == 2) {
                        md.snapshot = snapshot_read.execute(0);
                        md.desired = desired_read.execute(0);
                        owner_claim_command.apply();
                        owner.apply(md.command, md.owner);
                        if (md.owner.accepted == 1) {
                            md.payload = hdr.producer.payload;
                            payload_write.execute(0);
                        }
                        ig_dprsr_md.resubmit_type = 1;
                    } else if (md.role == 3) {
                        md.desired = desired_read.execute(0);
                        md.payload = payload_read.execute(0);
                        owner.apply(md.command, md.owner);
                        publication_difference.apply();
                        publication.apply();
                        publication_write.execute(0);
                        md.ready = md.ref.generation;
                        md.terminal = md.writing;
                        ready_write.execute(0);
                        terminal_write.execute(0);
                        ig_dprsr_md.resubmit_type = 1;
                    } else if (md.role == 5) {
                        md.ready = md.ref.generation;
                        md.terminal = md.closed;
                        ready_write.execute(0);
                        terminal_write.execute(0);
                        ig_dprsr_md.resubmit_type = 1;
                    }
                }
            }
        }
        hdr.report.setValid();
        hdr.report.owner = md.owner.observed;
        hdr.report.work_state = md.work_state;
        hdr.report.published = md.publication;
        hdr.report.payload = md.payload;
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
