#ifndef CASE4_NATIVE_ORIGINAL_CREDIT_P4
#define CASE4_NATIVE_ORIGINAL_CREDIT_P4
struct original_credit_cell_t { bit<32> epoch; bit<32> credit; }
// Three bounded original receipts: index0 ACK, index1 response, index2 OP.
// Each has cookie16 in [31:16], owned bit0 and issued-once bit8. An issued
// bit survives debit. Kind is register index, not a third SALU PHV input.
// Canonical cookie32 remains a separate immutable field in the carried packet.
// Constant admit/debit mutations come from actual events. The two SALU PHV
// inputs are epoch32 and full expectedCredit32. No asserted desired is accepted.
// INSTALL requires a native protected producer plus zero owned bits.
// Complete native caller/retirement publication is a separate composition gate.
control NativeOriginalCredit(in bit<8> operation, in bit<2> index, in bit<32> epoch,
                       in bit<32> expected,
                       inout bit<32> result) {
    Register<original_credit_cell_t, bit<2>>(3, {0, 0}) cell;
    RegisterAction<original_credit_cell_t, bit<2>, bit<32>>(cell) read = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            out_value = value.credit;
        }
    };
    RegisterAction<original_credit_cell_t, bit<2>, bit<32>>(cell) admit = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.epoch == epoch && value.credit == expected) {
                value.credit = value.credit | 32w0x101; out_value = 1;
            }
        }
    };
    RegisterAction<original_credit_cell_t, bit<2>, bit<32>>(cell) terminal = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.epoch == epoch && value.credit == expected) {
                value.credit = value.credit & 32w0xfffffffe; out_value = 1;
            }
        }
    };
    // Operation3 is native producer installation only. Caller must hold the
    // actual WorkRecord pin and establish all three receipts and every old
    // writer terminal. Source epoch/cookie are derived by that native producer.
    // A nonzero original blocks replacement inside the atomic SALU itself.
    // expected is NEW cookie16<<16 for install, not the old compare word.
    RegisterAction<original_credit_cell_t, bit<2>, bit<32>>(cell) install = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if ((value.credit & 32w1) == 0) {
                value.epoch = epoch; value.credit = expected; out_value = 1;
            }
        }
    };
    action read_credit() { result = read.execute(index); }
    action admit_credit() { result = admit.execute(index); }
    action terminal_credit() { result = terminal.execute(index); }
    action install_credit() { result = install.execute(index); }
    table event {
        key = { operation : exact; }
        actions = { read_credit; admit_credit; terminal_credit; install_credit; NoAction; }
        const entries = { 0 : read_credit(); 1 : admit_credit(); 2 : terminal_credit(); 3 : install_credit(); }
        const default_action = NoAction(); size = 4;
    }
    apply { event.apply(); }
}
#endif
