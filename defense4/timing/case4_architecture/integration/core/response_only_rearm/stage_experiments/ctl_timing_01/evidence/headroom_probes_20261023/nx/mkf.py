#!/usr/bin/env python3
"""Front-of-pipe-0 variants (round 3).  usage: mkf.py BASE OUT EDIT...  (BASE/OUT are .scratch_p4/<name>.p4)"""
import sys
from pathlib import Path
D = Path('/home/philip/Projects/DNP3/.scratch_p4')
def once(src, old, new):
    n = src.count(old); assert n == 1, (n, old[:140]); return src.replace(old, new)
E = {}
# F1a/F1b: E stage-0 identity hashes of the same width -> plain move / OR (each frees 2 hash-distribution units)
E['F1a'] = [("    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) original_wire_ack;\n    action capture_normalization_ack() { hdr.prov.wgen = original_wire_ack.get({hdr.tcp.ack}); }",
             "    action capture_normalization_ack() { hdr.prov.wgen = hdr.tcp.ack; }")]
E['F1b'] = [("    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) open_epoch_bound;\n    action prepare_open() { m.open_bound = open_epoch_bound.get({1w1, hdr.prov.epoch[30:0]}); }",
             "    action prepare_open() { m.open_bound = hdr.prov.epoch | 32w0x80000000; }")]
# F1c: 16->32 identity widen -> zero-extending cast (PHV risk: cast-add)
E['F1c'] = [("    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) widen_len;\n    action leff_off(bit<32> off) { m.leff = widen_len.get({hdr.ip.len}) + off; }",
             "    action leff_off(bit<32> off) { m.leff = (bit<32>)hdr.ip.len + off; }")]
# F2b: N tail/second CRCs (no earlier writer of tcrc/crc1) pinned to stage 1; rd_request_two_crc_t to stage 2
E['F2b'] = [("@stage(2) table input_tail_t{", "@stage(1) table input_tail_t{"), ("@stage(2) table response_crct_t{", "@stage(1) table response_crct_t{"),
            ("@stage(2) table rd_second_crc_t{", "@stage(1) table rd_second_crc_t{"), ("@stage(2) table rd_tail_crc_t{", "@stage(1) table rd_tail_crc_t{"),
            ("table rd_request_two_crc_t{", "@stage(2) table rd_request_two_crc_t{")]
# F2a: drop the five N CRC stage pins, let the compiler place
E['F2a'] = [("@stage(2) table input_tail_t{", "table input_tail_t{"), ("@stage(2) table response_crct_t{", "table response_crct_t{"),
            ("@stage(2) table rd_second_crc_t{", "table rd_second_crc_t{"), ("@stage(2) table rd_tail_crc_t{", "table rd_tail_crc_t{"),
            ("@stage(2) table rd_request_crc_t{", "table rd_request_crc_t{")]
# P8: the round-2 pins (@stage(9) application_t/read_app_t) go stale once the front shifts by one -> stage 8
E['P8'] = [("@stage(9) table application_t{", "@stage(8) table application_t{"), ("@stage(9) table read_app_t{", "@stage(8) table read_app_t{")]
E['P0'] = [("@stage(9) table application_t{", "table application_t{"), ("@stage(9) table read_app_t{", "table read_app_t{")]
# F2c: only the pins that land: input_tail_t/response_crct_t -> stage 1 (they write tcrc, no stage-1 writer); rd_request_two_crc_t -> 2
E['F2c'] = [("@stage(2) table input_tail_t{", "@stage(1) table input_tail_t{"), ("@stage(2) table response_crct_t{", "@stage(1) table response_crct_t{"),
            ("table rd_request_two_crc_t{", "@stage(2) table rd_request_two_crc_t{")]
# F2d: minimal -- response_crct_t -> stage 1, rd_request_two_crc_t -> stage 2 (every other pin unchanged)
E['F2d'] = [("@stage(2) table response_crct_t{", "@stage(1) table response_crct_t{"), ("table rd_request_two_crc_t{", "@stage(2) table rd_request_two_crc_t{")]
if __name__ == '__main__':
    base, out, *names = sys.argv[1:]
    src = (D / (base + '.p4')).read_text()
    for nm in names:
        for old, new in E[nm]: src = once(src, old, new)
    (D / (out + '.p4')).write_text(src); print('wrote', out)
