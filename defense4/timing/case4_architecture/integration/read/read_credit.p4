#ifndef CASE4_READ_CREDIT_P4
#define CASE4_READ_CREDIT_P4
struct original_credit_cell_t { bit<32> epoch; bit<32> credit; }
// READ copy of original_credit.p4: op3 (current) is replaced by op3 install. A held original whose word
// lacks the owned bit has already been debited by another copy: the caller drops it. Four RegisterActions is the limit. Three bounded original receipts: index0 ACK, index1 response, index2 OP.
// Each has cookie16 in [31:16], owned bit0 and issued-once bit8. An issued
// bit survives debit. Kind is register index, not a third SALU PHV input.
// Canonical cookie32 remains a separate immutable field in the carried packet.
// Constant admit/debit mutations come from actual events. The two SALU PHV
// inputs are epoch32 and full expectedCredit32. No asserted desired is accepted.
// Association replacement requires a protected producer pin plus zero owned
// bits; the complete native replacement adapter is outside this primitive.
control OriginalCredit(in bit<8> operation, in bit<2> index, in bit<32> epoch,
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
    // Op3 installs a freshly minted association (READ admission). The caller holds the producer pin
    // and has checked the old association owns no credit; `expected` is the new cookie16<<16.
    RegisterAction<original_credit_cell_t, bit<2>, bit<32>>(cell) install = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            value.epoch = epoch; value.credit = expected; out_value = 1;
        }
    };
    action install_credit() { result = install.execute(index); }
    action read_credit() { result = read.execute(index); }
    action admit_credit() { result = admit.execute(index); }
    action terminal_credit() { result = terminal.execute(index); }
    table event {
        key = { operation : exact; epoch : ternary; expected : ternary; }
        actions = { read_credit; admit_credit; terminal_credit; install_credit; NoAction; }
        const entries = {
            (0, _, _) : read_credit();
            (1, _, _) : admit_credit();
            (2, _, _) : terminal_credit();
            (3, 0, _) : NoAction();
            (3, _, 0 &&& 0xffff) : install_credit();
        }
        const default_action = NoAction(); size = 5;
    }
    apply { event.apply(); }
}
#endif
