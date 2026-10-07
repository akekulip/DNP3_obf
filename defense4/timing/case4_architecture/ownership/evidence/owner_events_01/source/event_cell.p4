#ifndef CASE4_EVENT_CELL_P4
#define CASE4_EVENT_CELL_P4
// Single owner, two one-shot producer roles per timing association.
// For integration terminal events must be produced only after every write and
// authenticated against the protected epoch32/work-generation32 record.
// This scalar event probe deliberately does not assert that record validation.
header event_command_t { bit<32> epoch; bit<32> cookie; bit<8> operation; bit<24> reserved; }
struct event_result_t {
    bit<32> old;
    bit<32> active_cookie;
    bit<32> request_cookie;
    bit<32> response_cookie;
    bit<32> ack_cookie;
    bit<32> response_original_cookie;
    bit<32> operate_cookie;
    bit<32> ready_cookie;
}
control EventCell(in event_command_t command, inout event_result_t md) {
    Register<bit<32>, bit<1>>(1, 0) lifecycle;
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) read_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) arm_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if (value < 32w65535) { value = (value + 1) | 32w0x00010000; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) request_acquire_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0083ffff) == md.active_cookie) { value = value | 32w0x00a00000; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) response_acquire_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0103ffff) == md.active_cookie) { value = value | 32w0x01400000; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) request_terminal_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0020ffff) == md.request_cookie) { value = value & 32w0xffdfffff; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) response_terminal_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0040ffff) == md.response_cookie) { value = value & 32w0xffbfffff; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) reset_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0000ffff) == command.cookie) { value = (value & 32w0xfffcffff) | 32w0x00030000; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) finish_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x007f0000) == 32w0x00030000) { value = value & 32w65535; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) ack_hold_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0003ffff) == md.active_cookie) { value = value | 32w0x00040000; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) response_hold_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0003ffff) == md.active_cookie) { value = value | 32w0x00080000; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) operate_hold_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0003ffff) == md.active_cookie) { value = value | 32w0x00100000; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) ack_terminal_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0004ffff) == md.ack_cookie) { value = value & 32w0xfffbffff; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) response_original_terminal_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0008ffff) == md.response_original_cookie) { value = value & 32w0xfff7ffff; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) operate_terminal_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x0010ffff) == md.operate_cookie) { value = value & 32w0xffefffff; } }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(lifecycle) ack_commit_ra = {
        void apply(inout bit<32> value, out bit<32> old) { old = value; if ((value & 32w0x000fffff) == md.ready_cookie) { value = (value & 32w0xfff8ffff) | 32w0x00020000; } }
    };
    action form_guards() {
        md.active_cookie = command.cookie | 32w0x00010000;
        md.request_cookie = command.cookie | 32w0x00200000;
        md.response_cookie = command.cookie | 32w0x00400000;
        md.ack_cookie = command.cookie | 32w0x00040000;
        md.response_original_cookie = command.cookie | 32w0x00080000;
        md.operate_cookie = command.cookie | 32w0x00100000;
        md.ready_cookie = command.cookie | 32w0x000d0000;
    }
    table guards { actions = { form_guards; } const default_action = form_guards(); size = 1; }
    action read() { md.old = read_ra.execute(0); }
    action arm() { md.old = arm_ra.execute(0); }
    action request_acquire() { md.old = request_acquire_ra.execute(0); }
    action response_acquire() { md.old = response_acquire_ra.execute(0); }
    action request_terminal() { md.old = request_terminal_ra.execute(0); }
    action response_terminal() { md.old = response_terminal_ra.execute(0); }
    action reset() { md.old = reset_ra.execute(0); }
    action finish() { md.old = finish_ra.execute(0); }
    action ack_hold() { md.old = ack_hold_ra.execute(0); }
    action response_hold() { md.old = response_hold_ra.execute(0); }
    action operate_hold() { md.old = operate_hold_ra.execute(0); }
    action ack_terminal() { md.old = ack_terminal_ra.execute(0); }
    action response_original_terminal() { md.old = response_original_terminal_ra.execute(0); }
    action operate_terminal() { md.old = operate_terminal_ra.execute(0); }
    action ack_commit() { md.old = ack_commit_ra.execute(0); }
    table events {
        key = { command.operation : exact; }
        actions = { read; arm; request_acquire; response_acquire; request_terminal; response_terminal; reset; finish; ack_hold; response_hold; operate_hold; ack_terminal; response_original_terminal; operate_terminal; ack_commit; }
        const entries = {
            1 : arm();
            2 : request_acquire();
            3 : response_acquire();
            4 : request_terminal();
            5 : response_terminal();
            6 : reset();
            7 : finish();
            8 : ack_hold();
            9 : response_hold();
            10 : operate_hold();
            11 : ack_terminal();
            12 : response_original_terminal();
            13 : operate_terminal();
            14 : ack_commit();
        }
        const default_action = read();
        size = 14;
    }
    apply { guards.apply(); events.apply(); }
}
#endif
