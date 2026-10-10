#!/usr/bin/env python3
"""Derive role E (pipe 0 egress) for the response-only target from protocol/case4_response_path.p4.

The committed file is left untouched. Four asserted edit groups.

1. Per the execution document ("Preferred initial ACK placement"): the egress parser dispatches early on
the egress intrinsic egress_port and parses the mapper's headers only for

  * MASTER_PORT (9):    final departure to the master -> forward mapper and padding (and SYN-ACK arming),
  * N_ACK_RETURN (70):  N's normalization pass        -> reverse ACK/window mapper, once.

Every other egress port leaves the parser at `accept` with no header extracted: no connection lookup, no
mapper state touched, bytes unchanged. That covers the native request leaving for the outstation (64),
whose ACK was already normalized on the N_ACK_RETURN pass (reverse-mapping it again would translate twice),
and any other pipe-0 departure. N's own recirculation (68) already bypasses egress. No stage is added.

2. Port provenance for direction (review finding C3). conn gains eg.egress_port as its last key, so a
fwd_conn row (outstation -> master 4-tuple) is installed only at MASTER_PORT and a rev_conn row only at
N_ACK_RETURN (core/response_only/cp.py). A packet injected on the master link with the outstation's
4-tuple reaches egress 70, misses conn, and touches no mapper state; it can no longer run the forward
mapper on the normalization pass and again on its final departure.

3. Make E's checksum invariant hold without trusting the compiler's pins. E's incremental TCP checksum
sums the containers of every padding header (rtp, ctp1, ctp2) whether or not it is present, so those
containers must hold zero when the header is absent; E relied on @pa_no_overlay / @pa_solitary pins for
that. Under pipe 0's full PHV (N's ingress beside E) bf-p4c 9.13 ignored them silently: the final allocation
(pa.results.log) put live metadata in seven of those containers, m.ina with hdr.ctp2.filler_b[31:0] (W26)
and m.in_cb0 / m.in_rb0 / m.in_rb1 / m.in_rt with rtp/ctp1 fields, and even E's own @pa_solitary bits
share a container (route_ab_01/response_only_07, _08 and pin_probe/: adding metadata-side pins, pipe-
qualified or as @pa_solitary, changed nothing). On the model every reverse-translated ACK then left with
its TCP checksum short by the ACK value (m.ina = ack): model_03, master_handshake_ACK, c111 instead of
c496. Zeroing the absent headers late cost a 13th stage on both gresses (response_only_09). The fix
instead splits the deparser update into three mutually exclusive cases -- no padding, READ padding (rtp),
control padding (ctp1+ctp2) -- each summing only the padding header that is present, so an absent one's
containers are never read. Each padding header is an even number of bytes: later fields keep their parity.
4. Outgoing CRCs without the post-padding hash/render chain. Padding is granted only on a commit/replay
verdict that already required every native link CRC to be valid, so:
  * link header: only the length byte changes (READ 0x26 -> 0x2f, CONTROL 0x1c -> 0x2f) and the CRC is affine,
    so the new wire-order CRC is the native one XOR 0x3b2f / 0x131a (efficiency_01/verify_dl_xor.py: 0
    mismatches in 200,000 random headers each, against both repository CRC codecs). hash_dl, crc_dl_t and
    render_dl_crc_t are gone.
  * tails: the padded tail CRC depends only on native fields and the fixed filler, so it is hashed early from
    hdr.rtn / hdr.ctn and the pad action writes it; render_read_crc_t and render_ctl_crc_t are gone. Each 72-bit
    filler is written 8w ++ 64w: bf-p4c 9.13.1 rejects a hash-input constant wider than 64 bits.
  Both padding headers are still fully written by their pad action, so the PIN_NOTE invariant below holds.
  evidence/route_ab_01/response_only_19 (vs _18, both SDKs): stages unchanged (p0 12/11, critical path 11);
  PHV 196 -> 193 containers (8b 59 -> 55, 16b 73 -> 74, 32b 64 -> 64); E tables 35 -> 31; hash-dist units
  27 -> 26. Model 70/70 with every emitted frame byte-identical to _17/model_03, and efficiency_01/verify_wire.py
  recomputes valid IPv4/TCP/DNP3 checksums from the emitted bytes in all three deparser cases.
  python3 make_e.py [out.p4]     (default: e_response_only.p4 next to this script)
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent.parent.parent / 'protocol' / 'case4_response_path.p4'
MASTER_PORT, N_ACK_RETURN = 9, 70   # keep N_ACK_RETURN equal to make_n.py's constant

OLD = """        m.badh = 0; m.rbad0 = 0; m.rbad1 = 0; m.rbadt = 0; m.cbad0 = 0; m.cbadt = 0;
        transition eth;
    }"""
NEW = """        m.badh = 0; m.rbad0 = 0; m.rbad1 = 0; m.rbadt = 0; m.cbad0 = 0; m.cbadt = 0;
        /* response-only target: mapper headers only on final master departure and N's normalization pass */
        transition select(eg.egress_port) { 9w%d: eth; 9w%d: eth; default: accept; }
    }""" % (MASTER_PORT, N_ACK_RETURN)


CONN_OLD = "key = { hdr.ip.src : exact; hdr.ip.dst : exact; hdr.tcp.sport : exact; hdr.tcp.dport : exact; }\n        actions = { fwd_conn; rev_conn; NoAction; }"
CONN_NEW = "key = { hdr.ip.src : exact; hdr.ip.dst : exact; hdr.tcp.sport : exact; hdr.tcp.dport : exact; eg.egress_port : exact; }\n        actions = { fwd_conn; rev_conn; NoAction; }"


RTP = "                hdr.rtp.data_last, hdr.rtp.filler, hdr.rtp.crc2,\n"
CTP = ("                hdr.ctp1.on_lo, hdr.ctp1.off, hdr.ctp1.status, hdr.ctp1.filler_a, hdr.ctp1.crc1,\n"
       "                hdr.ctp2.filler_b, hdr.ctp2.crc2,\n")
CSUM_HEAD = "        if (m.changed == 1w1) {\n"
PAD_ACTIONS = (("m.result = OUT_COMMIT;    m.pad = 1; m.changed = 1; }", "m.result = OUT_COMMIT;    m.pad = 1; }"),
               ("m.result = OUT_REPLAY;    m.pad = 1; m.changed = 1; }", "m.result = OUT_REPLAY;    m.pad = 1; }"))
CSUM_UPDATE = "            hdr.tcp.checksum = tcp_new.update({"


def split_checksum(text):
    """Edit group 3: one conditional TCP update per padding case, each summing only the padding header
    that is present (rtp, ctp1+ctp2, or none). Every padding header is an even number of bytes, so
    dropping one keeps each later field's byte parity."""
    start = text.index(CSUM_HEAD)
    end = text.index("        }\n", text.index("m.residual});", start)) + len("        }\n")
    block = text[start:end]
    assert text.count(CSUM_HEAD) == 1 and block.count(RTP) == 1 and block.count(CTP) == 1
    body = block[len(CSUM_HEAD):-len("        }\n")]
    # bf-p4c accepts only single-term deparser conditions ("&&" -> "Destination m.changed must be intrinsic
    # metadata", response_only_10). m.pad = 1 (commit/replay) always validates exactly one of rtp / ctp1
    # (Egress apply: read_pad_t or ctl_pad_t), so commit/replay stop setting m.changed (PAD_ACTIONS below)
    # and m.changed alone then means "changed, not padded": the three conditions are mutually exclusive.
    cases = (("m.changed == 1w1", "tcp_plain", body.replace(RTP, "").replace(CTP, "")),
             ("hdr.rtp.isValid()", "tcp_read", body.replace(CTP, "")),
             ("hdr.ctp1.isValid()", "tcp_ctl", body.replace(RTP, "")))
    new = ("        /* response-only (make_e.py edit 3): an absent padding header's containers may hold live metadata\n"
           "           under pipe-0 PHV pressure, so each case sums only the padding header that is present. */\n")
    for cond, unit, b in cases:
        assert b.count(CSUM_UPDATE) == 1
        new += "        if (%s) {\n%s        }\n" % (cond, b.replace(CSUM_UPDATE, "            hdr.tcp.checksum = %s.update({" % unit))
    text = text[:start] + new + text[end:]
    for old_a, new_a in PAD_ACTIONS:     # after the slice: the indices above refer to the unedited text
        assert text.count(old_a) == 1, old_a
        text = text.replace(old_a, new_a)
    old_decl = "Checksum() ip_new; Checksum() tcp_new;"
    assert text.count(old_decl) == 1
    return text.replace(old_decl, "Checksum() ip_new; Checksum() tcp_plain; Checksum() tcp_read; Checksum() tcp_ctl;")

PIN_NOTE_OLD = "     shares their containers, hence the @pa_no_overlay pins below (TRANSPORT_MAPPER_SPEC.md section 10).\n"
PIN_NOTE_NEW = ("     shares their containers, hence the @pa_no_overlay pins below (TRANSPORT_MAPPER_SPEC.md section 10).\n"
                "     RESPONSE-ONLY BUILD (make_e.py): bf-p4c 9.13 does NOT honor these pins (or @pa_solitary) in this\n"
                "     composite; pa.results.log shows live metadata in pinned padding-header containers. This build is\n"
                "     safe only because edit 3 sums each padding header solely when it is present, and every container a\n"
                "     present padding header shares is fully overwritten by that header before the deparser runs.\n")


CRC_EDITS = (
    # link header: XOR the validated native CRC with the length-byte delta, inside the pad actions
    ("hdr.dl.len=8w0x2f;hdr.ip.len=hdr.ip.len+16w9;m.len_delta=16w9;}",
     "hdr.dl.len=8w0x2f;hdr.dl.crc=hdr.dl.crc^16w0x3b2f;hdr.ip.len=hdr.ip.len+16w9;m.len_delta=16w9;}"),
    ("hdr.dl.len=8w0x2f;hdr.ip.len=hdr.ip.len+16w21;m.len_delta=16w21;}",
     "hdr.dl.len=8w0x2f;hdr.dl.crc=hdr.dl.crc^16w0x131a;hdr.ip.len=hdr.ip.len+16w21;m.len_delta=16w21;}"),
    ("    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_dl;\n"
     "    action crc_dl(){m.dlcrc=hash_dl.get({hdr.dl.start,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}\n"
     "    table crc_dl_t{actions={crc_dl;}size=1;const default_action=crc_dl();}\n", ""),
    ("    action render_dl_crc(){hdr.dl.crc=m.dlcrc[7:0]++m.dlcrc[15:8];}\n"
     "    table render_dl_crc_t{actions={render_dl_crc;}size=1;const default_action=render_dl_crc();}\n", ""),
    ("            crc_dl_t.apply(); render_dl_crc_t.apply();\n", ""),
    ("bit<16> dlcrc; bit<16> rtcrc;", "bit<16> rtcrc;"),
    # tails: hash native fields + the fixed filler early; the pad action renders the byte-swapped result
    ("    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.rtp.data_last,hdr.rtp.filler});}",
     "    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.rtn.data_last,8w0x29,64w0x0106290206290306});}"),
    ("    action crc_ctl_tail1(){m.ctcrc1=hash_ctl_tail1.get({hdr.ctp1.on_lo,hdr.ctp1.off,hdr.ctp1.status,hdr.ctp1.filler_a});}",
     "    action crc_ctl_tail1(){m.ctcrc1=hash_ctl_tail1.get({hdr.ctn.on_lo,hdr.ctn.off,hdr.ctn.status,8w0x29,64w0x032802002d010000});}"),
    ("    action render_read_crc(){hdr.rtp.crc2=m.rtcrc[7:0]++m.rtcrc[15:8];}\n"
     "    table render_read_crc_t{actions={render_read_crc;}size=1;const default_action=render_read_crc();}\n", ""),
    ("    action render_ctl_crc(){hdr.ctp1.crc1=m.ctcrc1[7:0]++m.ctcrc1[15:8];}\n"
     "    table render_ctl_crc_t{actions={render_ctl_crc;}size=1;const default_action=render_ctl_crc();}\n", ""),
    ("hdr.rtp.filler=72w0x290106290206290306;",
     "hdr.rtp.filler=72w0x290106290206290306;hdr.rtp.crc2=m.rtcrc[7:0]++m.rtcrc[15:8];"),
    ("hdr.ctp1.filler_a=72w0x29032802002d010000;",
     "hdr.ctp1.filler_a=72w0x29032802002d010000;hdr.ctp1.crc1=m.ctcrc1[7:0]++m.ctcrc1[15:8];"),
    ("            if (hdr.rtp.isValid()) { crc_read_tail_t.apply(); render_read_crc_t.apply(); }\n"
     "            if (hdr.ctp1.isValid()) { crc_ctl_tail1_t.apply(); render_ctl_crc_t.apply(); }\n", ""),
    ("in_rb1_t.apply(); in_rt_t.apply(); }", "in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); }"),
    ("in_cb0_t.apply(); in_ct_t.apply(); }", "in_cb0_t.apply(); in_ct_t.apply(); crc_ctl_tail1_t.apply(); }"),
)


def generate():
    text = SOURCE.read_text()
    for old, new in ((OLD, NEW), (CONN_OLD, CONN_NEW), (PIN_NOTE_OLD, PIN_NOTE_NEW)) + CRC_EDITS:
        assert text.count(old) == 1, ('edit target not found exactly once', old[:60])
        text = text.replace(old, new)
    text = split_checksum(text)
    return ('/* GENERATED by core/response_only/make_e.py from protocol/case4_response_path.p4 (sha256 %s).\n'
            '   Role E for the response-only target. Do not edit. */\n'
            % hashlib.sha256(SOURCE.read_bytes()).hexdigest()) + text


if __name__ == '__main__':
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'e_response_only.p4'
    out.write_text(generate())
    print('wrote', out)
