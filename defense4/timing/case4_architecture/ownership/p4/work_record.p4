#ifndef CASE4_WORK_RECORD_P4
#define CASE4_WORK_RECORD_P4
struct work_cell_t { bit<32> generation; bit<32> phase; }
// 4 is free only after a genuine terminal return. 1/2/3 stay pinned.
// The full immutable work generation is compared within the same atomic SALU
// that advances phase. A stale separate bank lookup is not authorization.
// A globally nonwrapping allocator and independent epoch authority are required.
control WorkRecord(in bit<8> operation, in bit<32> work_generation,
                   inout bit<32> observed_phase) {
    Register<work_cell_t, bit<1>>(1, {0, 4}) work;
    RegisterAction<work_cell_t, bit<1>, bit<32>>(work) claim = {
        void apply(inout work_cell_t value, out bit<32> old_phase) {
            old_phase = value.phase;
            if (value.phase == 4) { value.generation = work_generation; value.phase = 1; }
        }
    };
    RegisterAction<work_cell_t, bit<1>, bit<32>>(work) advance = {
        void apply(inout work_cell_t value, out bit<32> old_phase) {
            old_phase = 0;
            if (value.generation == work_generation && value.phase < 4) {
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
    action claim_work() { observed_phase = claim.execute(0); }
    action return_work() { observed_phase = advance.execute(0); }
    action close_work() { observed_phase = close.execute(0); }
    action read_work() { observed_phase = read.execute(0); }
    action unavailable_work() { observed_phase = 0; }
    table dispatch {
        key = { operation : exact; work_generation : ternary; }
        actions = { claim_work; return_work; close_work; read_work; unavailable_work; }
        const entries = {
            (1, 0) : unavailable_work();
            (1, _) : claim_work();
            (2, _) : return_work();
            (3, _) : close_work();
        }
        const default_action = read_work(); size = 4;
    }
    apply { dispatch.apply(); }
}
#endif
