#ifndef CASE4_ORIGINAL_CREDIT_P4
#define CASE4_ORIGINAL_CREDIT_P4
struct original_credit_cell_t { bit<32> epoch; bit<32> credit; }
// A single bounded association: cookie16 in [31:16], ACK/response/OP owned
// bits in [2:0], and issued-once bits in [10:8]. Issued bits survive debit.
// Canonical cookie32 remains a separate immutable field in the carried packet.
// The caller derives desired from actual admit/terminal events, never from an
// external expected/desired request. Full-cell CAS is atomic in one SALU.
// Association replacement requires a protected producer pin plus zero owned
// bits; the complete native replacement adapter is outside this primitive.
control OriginalCredit(in bit<8> operation, in bit<32> epoch,
                       in bit<32> expected, in bit<32> desired,
                       inout bit<32> result) {
    Register<original_credit_cell_t, bit<1>>(1, {1, 0x10000}) cell;
    RegisterAction<original_credit_cell_t, bit<1>, bit<32>>(cell) read = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            out_value = value.credit;
        }
    };
    RegisterAction<original_credit_cell_t, bit<1>, bit<32>>(cell) compare = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.epoch == epoch && value.credit == expected) {
                value.credit = desired; out_value = 1;
            }
        }
    };
    RegisterAction<original_credit_cell_t, bit<1>, bit<32>>(cell) current = {
        void apply(inout original_credit_cell_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.epoch == epoch && value.credit == expected) { out_value = 1; }
        }
    };
    action read_credit() { result = read.execute(0); }
    action change_credit() { result = compare.execute(0); }
    action check_credit() { result = current.execute(0); }
    table event {
        key = { operation : exact; }
        actions = { read_credit; change_credit; check_credit; }
        const entries = { 1 : change_credit(); 2 : check_credit(); }
        const default_action = read_credit(); size = 2;
    }
    apply { event.apply(); }
}
#endif
