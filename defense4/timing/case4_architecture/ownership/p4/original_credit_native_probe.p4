#include <core.p4>
#include <tna.p4>
#include "original_credit_native.p4"
#include "original_debt.p4"
// Isolated SALU compile/setup probe. Commands are diagnostic only; final
// native caller must derive op3 under the documented WorkRecord/zero barrier.
header ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }
header command_t { bit<32> epoch; bit<32> word; bit<8> operation; bit<8> kind; bit<16> reserved; }
header report_t { bit<32> result; bit<32> debt; }
struct header_t { ethernet_t eth; command_t command; report_t report; }
struct metadata_t { bit<2> index; bit<32> result; bit<8> debt_operation; bit<32> debt; }
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start { pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE); transition ethernet; }
    state ethernet { pkt.extract(hdr.eth); transition select(hdr.eth.type) { 0x88d4 : command; default : reject; } }
    state command { pkt.extract(hdr.command); transition accept; }
}
control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    NativeOriginalCredit() credits;
    OriginalDebt() originals;
    action ack() { md.index = 0; }
    action response() { md.index = 1; }
    action operate() { md.index = 2; }
    table kind { key = { hdr.command.kind : exact; } actions = { ack; response; operate; }
        const entries = { 2 : response(); 3 : operate(); } const default_action = ack(); size = 2; }
    action original_admitted() { md.debt_operation = 1; }
    action original_terminal() { md.debt_operation = 2; }
    table actual_outcome {
        key = { hdr.command.operation : exact; md.result : exact; }
        actions = { original_admitted; original_terminal; NoAction; }
        const entries = { (1, 1) : original_admitted(); (2, 1) : original_terminal(); }
        const default_action = NoAction(); size = 2;
    }
    apply {
        md.debt_operation = 0;
        kind.apply();
        credits.apply(hdr.command.operation, md.index, hdr.command.epoch, hdr.command.word, md.result);
        actual_outcome.apply(); originals.apply(md.debt_operation, md.debt);
        hdr.report.setValid(); hdr.report.result = md.result; hdr.report.debt = md.debt;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port; ig_tm_md.bypass_egress = 1;
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) { apply { pkt.emit(hdr); } }
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
