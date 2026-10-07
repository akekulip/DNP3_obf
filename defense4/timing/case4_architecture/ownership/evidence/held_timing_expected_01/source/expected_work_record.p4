#ifndef CASE4_EXPECTED_WORK_RECORD_P4
#define CASE4_EXPECTED_WORK_RECORD_P4
struct expected_work_cell_t { bit<32> generation; bit<32> phase; }
// A genuine producer emits expected phase1/2/3 in its private return packet.
// Full generation and full expected phase are compared in one atomic SALU.
// The caller must quarantine lifecycle ownership separately on raw close;
// operation3 observes the pin and never accelerates or fabricates terminal.
// Free4 is published only by an actual expected-phase3 return. Global full32
// generations must not wrap; epoch and final dirty-write lifetime are caller
// authority. No shared bank write may follow a terminal that permits reuse.
control ExpectedWorkRecord(in bit<8> operation, in bit<32> generation,
                           in bit<32> expected_phase,
                           inout bit<32> observed_phase) {
    Register<expected_work_cell_t, bit<1>>(1, {0, 4}) work;
    RegisterAction<expected_work_cell_t, bit<1>, bit<32>>(work) claim = {
        void apply(inout expected_work_cell_t value, out bit<32> old_phase) {
            old_phase = value.phase;
            if (value.phase == 4) { value.generation = generation; value.phase = 1; }
        }
    };
    RegisterAction<expected_work_cell_t, bit<1>, bit<32>>(work) advance = {
        void apply(inout expected_work_cell_t value, out bit<32> old_phase) {
            old_phase = 0;
            if (value.generation == generation && value.phase == expected_phase) {
                old_phase = value.phase; value.phase = value.phase + 1;
            }
        }
    };
    RegisterAction<expected_work_cell_t, bit<1>, bit<32>>(work) read = {
        void apply(inout expected_work_cell_t value, out bit<32> old_phase) { old_phase = value.phase; }
    };
    action claim_work() { observed_phase = claim.execute(0); }
    action return_work() { observed_phase = advance.execute(0); }
    action read_work() { observed_phase = read.execute(0); }
    action unavailable_work() { observed_phase = 0; }
    table dispatch {
        key = { operation : exact; generation : ternary; expected_phase : ternary; }
        actions = { claim_work; return_work; read_work; unavailable_work; }
        const entries = {
            (1, 0, _) : unavailable_work();
            (1, _, _) : claim_work();
            (2, _, 1) : return_work();
            (2, _, 2) : return_work();
            (2, _, 3) : return_work();
            (2, _, _) : unavailable_work();
        }
        const default_action = read_work(); size = 6;
    }
    apply { dispatch.apply(); }
}
#endif
