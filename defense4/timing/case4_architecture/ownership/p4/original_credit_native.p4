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
    // Local9.13.1 rejects sliced/masked SALU owned-bit conditions. Therefore
    // the actual native caller MUST read all three owned bits after acquiring
    // its genuine producer pin, reject nonzero debt, and prevent old writers
    // through final-generation publication/terminal. No wire proof flag may
    // substitute for that barrier. This helper cannot establish it alone.
    // expected is NEW cookie16<<16 for install, not the old compare word.
    RegisterAction<original_credit_cell_t, bit<2>, bit<32>>(cell) install = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            value.epoch = epoch; value.credit = expected; out_value = 1;
        }
    };
    action read_credit() { result = read.execute(index); }
    action admit_credit() { result = admit.execute(index); }
    action terminal_credit() { result = terminal.execute(index); }
    action install_credit() { result = install.execute(index); }
    table event {
        key = { operation : exact; epoch : ternary; expected : ternary; }
        actions = { read_credit; admit_credit; terminal_credit; install_credit; NoAction; }
        const entries = {
            (0, _, _) : read_credit();
            (1, 0, _) : NoAction();
            (1, _, 0 &&& 0xffff0000) : NoAction();
            (1, _, 0 &&& 0xffff) : admit_credit();
            (2, 0, _) : NoAction();
            (2, _, 0 &&& 0xffff0000) : NoAction();
            (2, _, 0x101 &&& 0xffff) : terminal_credit();
            (3, 0, _) : NoAction();
            (3, _, 0 &&& 0xffff) : install_credit();
        }
        const default_action = NoAction(); size = 9;
    }
    apply { result = 0; event.apply(); }
}
#endif
