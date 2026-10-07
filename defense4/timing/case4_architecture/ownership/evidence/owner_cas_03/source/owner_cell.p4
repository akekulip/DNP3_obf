#ifndef CASE4_OWNER_CELL_P4
#define CASE4_OWNER_CELL_P4
// The canonical cookie is never sliced or reassigned by the parser/control.
// expected/desired are a diagnostic CAS interface, not external lifecycle proof.
header owner_command_t {
    bit<32> epoch;
    bit<32> cookie;
    bit<32> expected;
    bit<32> desired;
    bit<8> operation; // 0 read, 1 arm idle, 2 full-cell compare-and-swap
    bit<8> reserved;
}
struct owner_result_t {
    bit<32> observed;
    bit<8> accepted;
}
control OwnerCell(in owner_command_t command, inout owner_result_t result) {
    Register<bit<32>, bit<1>>(1, 0) lifecycle;
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) read_cell = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) arm_cell = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value;
            if (value < 32w65535) { value = (value + 1) | 32w0x00010000; }
        }
    };
    // Two PHV operands. The comparison includes generation, phase, credits and
    // issued flags: an old readiness snapshot cannot retire ACK_COMMITTED.
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) compare_swap_cell = {
        void apply(inout bit<32> value, out bit<32> old) {
            old = value;
            if (value == command.expected) { value = command.desired; }
        }
    };
    action read_owner() { result.observed = read_cell.execute(0); }
    action arm_owner() { result.observed = arm_cell.execute(0); }
    action compare_swap_owner() { result.observed = compare_swap_cell.execute(0); }
    table event {
        key = { command.operation : exact; }
        actions = { read_owner; arm_owner; compare_swap_owner; }
        const entries = { 1 : arm_owner(); 2 : compare_swap_owner(); }
        const default_action = read_owner();
        size = 2;
    }
    apply {
        event.apply();
        result.accepted = 0;
        if (command.operation == 1) {
            if (result.observed < 32w65535) { result.accepted = 1; }
        } else if (command.operation == 2) {
            if (result.observed == command.expected) { result.accepted = 1; }
        }
    }
}
#endif
