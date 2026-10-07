#ifndef CASE4_ASSOCIATION_BINDING_P4
#define CASE4_ASSOCIATION_BINDING_P4
struct association_key_t { bit<32> epoch; bit<32> cookie; }
struct binding_result_t { bit<32> value; bit<8> authorized; }
// Canonical timing cookie stays zero-extended32 on every interface. The minted
// source is nonwrapping16. Both full32 key fields are checked atomically.
// INSTALL is not wire authority: the caller must hold an actual WorkRecord pin,
// verify current connection epoch, and establish original-credit quiescence
// before replacing this key. Keep that pin through the last bank write/return.
// Stale scans use full owner-cell CAS; this read check alone is no reuse barrier.
control AssociationBinding(in bit<8> operation, in bit<32> epoch,
                           in bit<32> cookie, inout binding_result_t result) {
    Register<association_key_t, bit<1>>(1, {0, 0}) key;
    RegisterAction<association_key_t, bit<1>, bit<32>>(key) install = {
        void apply(inout association_key_t value, out bit<32> out_value) {
            out_value = 0; value.epoch = epoch; value.cookie = cookie;
        }
    };
    RegisterAction<association_key_t, bit<1>, bit<32>>(key) authorize = {
        void apply(inout association_key_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.epoch == epoch && value.cookie == cookie) { out_value = 1; }
        }
    };
    RegisterAction<association_key_t, bit<1>, bit<32>>(key) read_cookie = {
        void apply(inout association_key_t value, out bit<32> out_value) { out_value = value.cookie; }
    };
    RegisterAction<association_key_t, bit<1>, bit<32>>(key) read_epoch = {
        void apply(inout association_key_t value, out bit<32> out_value) { out_value = value.epoch; }
    };
    action install_key() { result.value = install.execute(0); }
    action check_key() { result.value = authorize.execute(0); }
    action current_cookie() { result.value = read_cookie.execute(0); }
    action current_epoch() { result.value = read_epoch.execute(0); }
    table event {
        key = { operation : exact; }
        actions = { install_key; check_key; current_cookie; current_epoch; }
        const entries = { 1 : install_key(); 2 : check_key(); 3 : current_epoch(); }
        const default_action = current_cookie(); size = 3;
    }
    apply {
        event.apply();
        result.authorized = 0;
        if (operation == 2 && result.value == 1) { result.authorized = 1; }
    }
}
// Call this only with the function byte extracted from a fully validated native
// DNP3 frame. The classifier does not validate TCP/DNP3 CRC/profile by itself.
// READ opens a timing association without control padding; SELECT opens control;
// OPERATE joins current control and cannot allocate a fresh timing cookie.
control AssociationKind(in bit<8> native_function, inout bit<8> kind) {
    action read_request() { kind = 1; }
    action select_request() { kind = 2; }
    action operate_request() { kind = 3; }
    action unsupported() { kind = 0; }
    table function {
        key = { native_function : exact; }
        actions = { read_request; select_request; operate_request; unsupported; }
        const entries = { 1 : read_request(); 3 : select_request(); 4 : operate_request(); }
        const default_action = unsupported(); size = 3;
    }
    apply { function.apply(); }
}
#endif
