#!/usr/bin/env python3
"""N register-layout variants.  usage: mkn.py BASE(all|h1c2) OUT EDIT [EDIT...]  -> /scratch_p4/OUT.p4"""
import sys
from pathlib import Path
D = Path('/home/philip/Projects/DNP3/.scratch_p4')

def once(src, old, new):
    n = src.count(old)
    assert n == 1, (n, old[:140])
    return src.replace(old, new)

APP_OLD = ("Register<bit<32>,bit<1>>(1,0) application;\n"
 "RegisterAction<bit<32>,bit<1>,bit<32>>(application) write_application={void apply(inout bit<32> v,out bit<32> r){v=m.compare_application;r=v;}};\n"
 "RegisterAction<bit<32>,bit<1>,bit<32>>(application) read_op_application={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_application;}};RegisterAction<bit<32>,bit<1>,bit<32>>(application) read_rsp_application={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_application;}};\n"
 "action compare_rsp_application(){m.diff_application=read_rsp_application.execute(1w0);}\n"
 "action compare_application(){m.diff_application=read_op_application.execute(1w0);}\n"
 "action store_application(){write_application.execute(1w0);}\n"
 "table application_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_application;compare_application;compare_rsp_application;NoAction;}size=4;const entries={(2w1,8w5,32w1,32w0):store_application();(2w1,8w7,32w1,32w0):store_application();(2w0,8w7,32w4,_):compare_application();(2w0,8w6,32w4,_):compare_rsp_application();}const default_action=NoAction();}\n")
OFF_OLD = ("Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_off_native_start;\n"
 "RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_native_start) write_real_off={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_real_off;v.second=m.compare_native_start;r=32w0;}};\n"
 "RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_native_start) read_real_off={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_real_off||v.second!=m.compare_native_start){r=32w1;}else{r=32w0;}}};\n"
 "action store_real_off(){write_real_off.execute(1w0);}\n"
 "action compare_real_off(){m.diff_real_off=read_real_off.execute(1w0);}\n")
# A: application (8 significant bits) takes native_start's half. native_start == native_end - 35 in every
# compare_*_inputs action, so its compare is implied by native_end's (pair_native_end_server_start).
# One SALU returns the application difference, or 0x10000 (outside [-255,255] mod 2^32) if off differs.
# Initial second half 0x10000: a never-stored cell can never yield 0, -1 or 15 (as before: never-stored never matched).
OFF_NEW_A = ("Register<n_object_pair_t,bit<1>>(1,{0,32w0x10000}) pair_real_off_application;\n"
 "RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_application) write_real_off={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_real_off;v.second=m.compare_application;r=32w0;}};\n"
 "RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_application) read_real_off={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_real_off){r=32w0x10000;}else{r=v.second-m.compare_application;}}};\n"
 "action store_real_off(){write_real_off.execute(1w0);}\n"
 "action compare_real_off(){m.diff_application=read_real_off.execute(1w0);}\n")
APPLY_OLD = "real_links_t.apply();real_tcp_dst_t.apply();real_object_t.apply();real_off_t.apply();native_end_t.apply();application_t.apply();"
APPLY_NEW = "real_links_t.apply();real_tcp_dst_t.apply();real_object_t.apply();real_off_t.apply();native_end_t.apply();"
OM_OLD = ("table object_match{key={m.response:exact;m.diff_real_links:exact;m.diff_real_tcp_dst:exact;m.diff_real_object:exact;m.diff_real_off:exact;m.diff_native_end:exact;m.diff_application:exact;}actions={matched;NoAction;}size=3;const default_action=NoAction();const entries={(1w1,32w0,32w0,32w0,32w0,32w0,32w0):matched();(1w0,32w0,32w0,32w0,32w0,32w0,32w4294967295):matched();(1w0,32w0,32w0,32w0,32w0,32w0,32w15):matched();}}")
OM_NEW = ("table object_match{key={m.response:exact;m.diff_real_links:exact;m.diff_real_tcp_dst:exact;m.diff_real_object:exact;m.diff_native_end:exact;m.diff_application:exact;}actions={matched;NoAction;}size=3;const default_action=NoAction();const entries={(1w1,32w0,32w0,32w0,32w0,32w0):matched();(1w0,32w0,32w0,32w0,32w0,32w4294967295):matched();(1w0,32w0,32w0,32w0,32w0,32w15):matched();}}")
# A2: dual-field SALUs cannot output a subtraction (bf-p4c); the SALU returns the stored application byte (or
# 0x10000 if off differs) and one stateless table forms diff_application = stored - compare, as before.
OFF_NEW_A2 = ("Register<n_object_pair_t,bit<1>>(1,{0,32w0x10000}) pair_real_off_application;\n"
 "RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_application) write_real_off={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_real_off;v.second=m.compare_application;r=32w0;}};\n"
 "RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_application) read_real_off={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_real_off){r=32w0x10000;}else{r=v.second;}}};\n"
 "action store_real_off(){write_real_off.execute(1w0);}\n"
 "action compare_real_off(){m.app_stored=read_real_off.execute(1w0);}\n"
 "action app_diff(){m.diff_application=m.app_stored-m.compare_application;}\n"
 "table app_diff_t{actions={app_diff;}size=1;const default_action=app_diff();}\n")
META_OLD = "struct n_meta_t{"
META_NEW = "struct n_meta_t{bit<32> app_stored;"
OM_APPLY_OLD = "if(m.packet_kind==8w6||m.packet_kind==8w7){object_match.apply();}"
OM_APPLY_NEW = "if(m.packet_kind==8w6||m.packet_kind==8w7){app_diff_t.apply();object_match.apply();}"
# A3: as A2, but the off-mismatch output is an ALU result (stored | 0x10000), not a constant (A2: "Incompatible
# outputs in RegisterAction: predicate and mem_hi").
OFF_NEW_A3 = OFF_NEW_A2.replace("{r=32w0x10000;}else{r=v.second;}", "{r=v.second|32w0x10000;}else{r=v.second;}")
# P1: placement only -- application_t (stage 7) pinned to stage 9, beside owner/read_app; object_match already sits at 10.
P1 = [("table application_t{", "@stage(9) table application_t{")]
P1W = [("    table img_wend_t {", "    @stage(8) table img_wend_t {")]
R9 = [("table read_app_t{", "@stage(9) table read_app_t{")]
G2 = [(" table retry_valid_t{", " @stage(2) table retry_valid_t{"), ("table rd_request_two_crc_t{", "@stage(2) table rd_request_two_crc_t{")]
EDITS = {'G2': G2, 'P1': P1, 'R9': R9, 'P1W': P1W,
         'A3': [(APP_OLD, ''), (OFF_OLD, OFF_NEW_A3), (APPLY_OLD, APPLY_NEW), (OM_OLD, OM_NEW), (META_OLD, META_NEW), (OM_APPLY_OLD, OM_APPLY_NEW)],
         'A2': [(APP_OLD, ''), (OFF_OLD, OFF_NEW_A2), (APPLY_OLD, APPLY_NEW), (OM_OLD, OM_NEW), (META_OLD, META_NEW), (OM_APPLY_OLD, OM_APPLY_NEW)],
         'A': [(APP_OLD, ''), (OFF_OLD, OFF_NEW_A), (APPLY_OLD, APPLY_NEW), (OM_OLD, OM_NEW)]}

if __name__ == '__main__':
    base, out, *names = sys.argv[1:]
    src = (D / (base + '.p4')).read_text()
    for nm in names:
        for old, new in EDITS[nm]:
            src = once(src, old, new)
    (D / (out + '.p4')).write_text(src)
    print('wrote', out)
