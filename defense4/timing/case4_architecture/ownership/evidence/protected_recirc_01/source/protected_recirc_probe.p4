#include <core.p4>
#include <tna.p4>
#include "owner_protected_cell.p4"
// Actual emitted-byte recirculation alternative: no snapshot bank cycle.
// Ports are compile-time laboratory roles, NOT configured by this program.
const PortId_t INPUT_PORT = 9w69;
const PortId_t RETURN_PORT = 9w68;
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header work_ref_t { bit<32> epoch; bit<32> generation; }
header envelope_t {
    bit<32> epoch; bit<32> generation; bit<32> expected_cell;
    bit<16> event; bit<16> reserved;
}
header producer_t { bit<32> epoch; bit<32> cookie; bit<32> payload; bit<8> event; bit<24> reserved; }
header report_t { bit<32> old_phase; bit<32> payload; bit<32> published; bit<32> generation; }
struct work_cell_t { bit<32> generation; bit<32> phase; }
struct header_t {
    envelope_t envelope; ethernet_t ethernet; producer_t producer; report_t report;
}
struct metadata_t {
    work_ref_t ref;
    owner_command_t command; owner_result_t owner;
    bit<32> epoch; bit<32> epoch_difference; bit<32> counter;
    bit<32> phase; bit<32> payload; bit<32> publication; bit<32> difference;
    bit<8> admitted; bit<8> role;
}
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) {
            INPUT_PORT : ethernet; RETURN_PORT : envelope; default : reject;
        }
    }
    state envelope {
        pkt.extract(hdr.envelope);
        md.ref.epoch = hdr.envelope.epoch;
        md.ref.generation = hdr.envelope.generation;
        transition ethernet;
    }
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
    RegisterAction<bit<32>, bit<1>, bit<32>>(connection_epoch) read_epoch = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) work_counter;
    RegisterAction<bit<32>, bit<1>, bit<32>>(work_counter) allocate_generation = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value; if ((int<32>)value != -1) { value = value + 1; }
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
    action accept_event() { md.admitted = 1; }
    action refuse_event() { md.admitted = 0; }
    table first_difference { actions = { difference_first; } const default_action = difference_first(); size = 1; }
    table return_difference { actions = { difference_return; } const default_action = difference_return(); size = 1; }
    table authority {
        key = { md.epoch_difference : exact; }
        actions = { accept_event; refuse_event; }
        const entries = { 0 : accept_event(); } const default_action = refuse_event(); size = 1;
    }
    table generation_available {
        key = { md.counter : exact; }
        actions = { accept_event; refuse_event; }
        const entries = { 0xffffffff : refuse_event(); } const default_action = accept_event(); size = 1;
    }
    action form_reference() { md.ref.epoch = md.epoch; md.ref.generation = md.counter + 1; }
    table reference { actions = { form_reference; } const default_action = form_reference(); size = 1; }
    action owner_read() {
        md.command.epoch = md.epoch; md.command.cookie = hdr.producer.cookie;
        md.command.expected = 0; md.command.desired = 0;
        md.command.operation = 0; md.command.reserved = 0;
    }
    action owner_arm() { md.command.operation = 1; }
    action owner_close() { md.command.operation = 3; md.command.expected = hdr.producer.cookie; }
    action owner_claim() {
        md.command.operation = 2;
        md.command.expected = hdr.envelope.expected_cell;
        md.command.desired = hdr.envelope.expected_cell | 32w0x00800000;
    }
    table read_command { actions = { owner_read; } const default_action = owner_read(); size = 1; }
    table arm_command { actions = { owner_arm; } const default_action = owner_arm(); size = 1; }
    table close_command { actions = { owner_close; } const default_action = owner_close(); size = 1; }
    table claim_command { actions = { owner_claim; } const default_action = owner_claim(); size = 1; }
    action form_publication_difference() { md.difference = md.owner.observed ^ hdr.envelope.expected_cell; }
    table publication_difference {
        actions = { form_publication_difference; } const default_action = form_publication_difference(); size = 1;
    }
    action publish_event() { md.admitted = 1; }
    action suppress_event() { md.admitted = 0; }
    table publication_guard {
        key = { md.difference : exact; md.owner.observed : ternary; hdr.envelope.event : exact; }
        actions = { publish_event; suppress_event; }
        const entries = { (0, 0x10000 &&& 0x30000, 1) : publish_event(); }
        const default_action = suppress_event(); size = 1;
    }
    action emit_snapshot() {
        hdr.envelope.setValid();
        hdr.envelope.epoch = md.ref.epoch;
        hdr.envelope.generation = md.ref.generation;
        hdr.envelope.expected_cell = md.owner.observed;
        hdr.envelope.event = 1; hdr.envelope.reserved = 0;
    }
    table snapshot_bytes { actions = { emit_snapshot; } const default_action = emit_snapshot(); size = 1; }
    action owner_snapshot_difference() {
        md.difference = (md.owner.observed & 32w0x3ffff) ^ (hdr.producer.cookie | 32w0x10000);
    }
    table snapshot_difference {
        actions = { owner_snapshot_difference; } const default_action = owner_snapshot_difference(); size = 1;
    }
    table snapshot_guard {
        key = { md.difference : exact; hdr.producer.cookie : ternary; }
        actions = { publish_event; suppress_event; }
        const entries = { (0, 0 &&& 0xffff0000) : publish_event(); }
        const default_action = suppress_event(); size = 1;
    }
    apply {
        md.phase = 0; md.role = 0; md.payload = 0; md.publication = 0;
        md.epoch = read_epoch.execute(0);
        read_command.apply();
        if (ig_intr_md.ingress_port == INPUT_PORT) { first_difference.apply(); }
        else { return_difference.apply(); }
        authority.apply();
        if (md.admitted == 1) {
            if (ig_intr_md.ingress_port == INPUT_PORT) {
                if (hdr.producer.event == 1) {
                    md.counter = allocate_generation.execute(0);
                    generation_available.apply();
                    if (md.admitted == 1) {
                        reference.apply();
                        md.phase = claim.execute(0);
                        if (md.phase == 4) { md.role = 1; }
                    }
                } else if (hdr.producer.event == 255) {
                    md.phase = close.execute(0); close_command.apply(); md.role = 7;
                } else if (hdr.producer.event == 0) {
                    md.phase = read.execute(0);
                    if (md.phase == 4) { arm_command.apply(); md.role = 6; }
                }
            } else {
                md.phase = advance.execute(0);
                if (md.phase == 1) { claim_command.apply(); md.role = 2; }
                else if (md.phase == 2) { md.role = 3; }
                else if (md.phase == 3) { md.role = 4; }
            }
        }
        // Exactly one textual owner application prevents multi-apply next-table
        // ambiguity. Each returning pass has the snapshot from parser stage0.
        if (md.role == 1 || md.role == 2 || md.role == 3 || md.role == 6 || md.role == 7) {
            owner.apply(md.command, md.owner);
        }
        if (md.role == 1) {
            snapshot_difference.apply();
            snapshot_guard.apply();
            snapshot_bytes.apply();
            if (md.admitted == 0) { hdr.envelope.event = 0; }
            ig_tm_md.ucast_egress_port = RETURN_PORT;
        } else if (md.role == 2) {
            if (md.owner.accepted == 1 && hdr.envelope.event == 1) {
                md.payload = write_payload.execute(0);
                hdr.envelope.expected_cell = md.command.desired;
            } else { hdr.envelope.event = 0; }
            ig_tm_md.ucast_egress_port = RETURN_PORT;
        } else if (md.role == 3) {
            publication_difference.apply();
            publication_guard.apply();
            if (md.admitted == 1) { md.publication = write_publication.execute(0); }
            ig_tm_md.ucast_egress_port = RETURN_PORT;
        } else {
            if (md.role == 4) {
                md.payload = read_payload.execute(0);
                md.publication = read_publication.execute(0);
            }
            hdr.envelope.setInvalid();
            hdr.report.setValid();
            hdr.report.old_phase = md.phase;
            hdr.report.payload = md.payload;
            hdr.report.published = md.publication;
            hdr.report.generation = md.ref.generation;
            ig_tm_md.ucast_egress_port = INPUT_PORT;
        }
        ig_tm_md.bypass_egress = 1;
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
