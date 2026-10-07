#ifndef CASE4_ORIGINAL_DEBT_P4
#define CASE4_ORIGINAL_DEBT_P4
// One current-association total over three indexed original receipts.
// INCREMENT/DECREMENT must derive solely from a real receipt operation whose
// full-key SALU returned1. Duplicate/stale/invalid operations leave debt alone.
// Producer pins last through the increment bank write and genuine terminal.
// Receipt terminals and any downstream timing/cache writes require corresponding
// writer pins through their genuine returns. Native rekey first acquires its
// own genuine pin, reads this actual debt, and rejects nonzero before any write.
// INSTALL does not reset debt. No heartbeat synthesizes decrement after loss.
control OriginalDebt(in bit<8> operation, inout bit<32> result) {
    Register<bit<32>, bit<1>>(1, 0) debt;
    RegisterAction<bit<32>, bit<1>, bit<32>>(debt) read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(debt) increment = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (value < 3) { value = value + 1; }
            out_value = value;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(debt) decrement = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (value > 0) { value = value - 1; }
            out_value = value;
        }
    };
    action load_debt() { result = read.execute(0); }
    action own_original() { result = increment.execute(0); }
    action settle_original() { result = decrement.execute(0); }
    table event {
        key = { operation : exact; }
        actions = { load_debt; own_original; settle_original; }
        const entries = { 1 : own_original(); 2 : settle_original(); }
        const default_action = load_debt(); size = 2;
    }
    apply { event.apply(); }
}
#endif
