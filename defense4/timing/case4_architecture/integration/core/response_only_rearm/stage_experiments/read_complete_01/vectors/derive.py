"""Derive the switch's per-shape READ prefix constants from the reference encoder (Python >= 3.10).

For each hardware READ shape of the frozen policy (policy/policy.json) this computes the constants the P4
prefix padder needs, then PROVES on many varied native responses (every transport sequence, varied app
sequence, IIN, point values and link addresses) that the constant-based construction equals
general_read_padding.pad_read byte for byte. Output: constants.json, consumed by make_m12.py (P4 constants)
and by the Python-3.8 model drivers (expected bytes). Nothing here is capture-specific: only the frame
structure (link LEN of the native first frame, application/object layout) selects a shape.

  python3 derive.py            # writes constants.json next to this file

Shapes
------
range_g10v2_23   single native link frame (49 B), padded to 141 by one prefix frame. This is the frozen
                 policy's hardware READ and feeds make_m12 --policy. Its constants are unchanged here.
segmented_integrity_377
                 the two-frame large-DB integrity/class0 native [292, 85] = 377 B, padded to 401 by one
                 24-B prefix frame plus a block-0 rewrite of BOTH original frames (the 377 -> 401 workload
                 shape named in policy.json). It feeds make_m12 --segmented only; it does not change the
                 range shape, the produced response_only.p4 for --policy/--full/default, or any committed
                 build. Because 401 - 377 = 24 is reachable by the prefix construction (padding object
                 g1v2 q01 [1024..1027], obj_len 11, prefix_size 24), pad_read selects construction='prefix'
                 here, NOT the resegment fallback; the fallback was needed only for the rejected greedy +1
                 target (see policy.json 'rule').

What is a compile constant and what is derived on chip
------------------------------------------------------
The only per-shape compile constants are the padding object's own content (padobj_head) and the fixed
link LEN / CTRL / start octets of the synthetic prefix frame. Everything that depends on the live
response -- the moved application header (app ctrl, function, IIN), the link addresses copied into the
prefix, every link-block CRC, and the IP/TCP checksums -- is derived in the switch from live fields. For
the segmented shape this module measures, across >=256 varied samples, exactly which per-segment
block-0 CRC and IP/TCP checksum quantities are invariant (hence a constant the deparser may add) and
which vary (hence must be computed from live bytes). It does not assume a single constant checksum delta.
"""
import hashlib
import json
import pathlib
import random
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'software/source/full_read_01'))
import general_read_padding as gp  # noqa: E402

std = gp.std
POLICY = json.loads((ROOT / 'policy/policy.json').read_text())
TARGETS = POLICY['selected']['targets']
PAD_START, PAD_STOP = POLICY['profile']['reserved_padding_range']


def crc_be(frame, offset):
    """P4-space value of a wire CRC (P4 reads the little-endian wire octets as a big-endian bit<16>)."""
    return int.from_bytes(frame[offset:offset + 2], 'big')


def construct(native, c):
    """The switch construction from constants only (mirrors the P4 action). native = first link frame
    (+ any further frames, passed through except for the transport octet renumber, which the P4 handles
    per continuation shape)."""
    frames = gp.split_frames(native)
    first = frames[0]
    hdr, user = std.deframe(first)
    tp = user[0]
    seq = tp & 63
    prefix_user = bytes([0x40 | seq]) + user[1:5] + bytes.fromhex(c['padobj_head'])
    prefix = std.frame(hdr[:2] + bytes([c['prefix_link_len']]) + hdr[3:], prefix_user)
    out = [prefix]
    for i, f in enumerate(frames):
        h, u = std.deframe(f)
        th = (u[0] & std.FIN) | (((u[0] & 63) + 1) & 63)
        body = bytes(4) + u[5:] if i == 0 else u[1:]
        out.append(std.frame(h, bytes([th]) + body))
    return b''.join(out)


def derive(shape, sample):
    req, native = sample()
    r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
    assert r.status == 'padded' and r.construction == 'prefix' and r.prefix_frames == 1, r
    out = gp.split_frames(r.output)
    prefix, cont = out[0], out[1]
    _, pu = std.deframe(prefix)
    c = dict(shape=shape['name'], native_first_link_len=native[2], native_total=len(native), target=r.target,
             added=len(r.output) - len(native), padding_points=r.padding_points,
             prefix_link_len=prefix[2], prefix_frame_len=len(prefix), padobj_head=pu[5:].hex(),
             block0_tail=pu[5:16].hex(),                      # bytes 6..16 of the prefix block 0 (after tp+app)
             rest=prefix[28:].hex(),                          # constant data blocks + their CRCs after block 0
             link_crc_delta=crc_be(prefix, 8) ^ crc_be(native, 8),
             reserved_first_index=PAD_START, frames_out=[len(f) for f in out])
    return c


def range_sample(rng):
    def make():
        seq = rng.randrange(64); appseq = rng.randrange(16)
        iin = bytes([rng.randrange(256) & 0xfe, rng.randrange(256) & 0x3f])
        dst, src = rng.randrange(1, 0xfff0), rng.randrange(1, 0xfff0)
        statuses = bytes(rng.randrange(256) for _ in range(23))
        user = bytes([0xc0 | seq, 0xc0 | appseq, 0x81]) + iin + bytes.fromhex('0a02000016') + statuses
        native = std.frame(bytes([0x05, 0x64, 5 + len(user), 0x44]) + dst.to_bytes(2, 'little') + src.to_bytes(2, 'little'), user)
        req_user = bytes([0xc0 | ((seq - 1) & 63), 0xc0 | appseq, 0x01]) + bytes.fromhex('0a02000016')
        req = std.frame(bytes([0x05, 0x64, 5 + len(req_user), 0xc4]) + src.to_bytes(2, 'little') + dst.to_bytes(2, 'little'), req_user)
        return req, native
    return make


# --------------------------------------------------------------------------------------------------------
# Segmented (two-frame 377 -> 401) shape
# --------------------------------------------------------------------------------------------------------
# Object layout of the large-DB integrity/class0 native, taken from the reference capture
# (handoff/.../native_integrity_large/capture.pcap): g1v2[0..15], g30v1[0..41], g20v1[0..7], g10v2[0..22].
# 4-octet app header + 309 object octets = 313 application octets, segmented native-side into
# transport seg0 = app[0:249] (frame0, link LEN 255, 292 B) and seg1 = app[249:313] (frame1, link LEN 70,
# 85 B). Point VALUES, transport/app sequence, IIN and link addresses vary; the 377 length does not.
SEG_OBJECTS = [(1, 2, 0, 15, 1), (30, 1, 0, 41, 5), (20, 1, 0, 7, 5), (10, 2, 0, 22, 1)]
SEG_REQ_OBJS = bytes.fromhex('3c02063c03063c04063c0106')   # g60 v2/v3/v4/v1 q06 class integrity READ


def segmented_sample(rng):
    def make():
        seq = rng.randrange(64); appseq = rng.randrange(16)
        iin = bytes([rng.randrange(256), rng.randrange(256)])
        dst, src = rng.randrange(1, 0xfff0), rng.randrange(1, 0xfff0)
        objects = b''
        for g, v, lo, hi, osz in SEG_OBJECTS:
            n = hi - lo + 1
            objects += bytes([g, v, 0x00, lo, hi]) + bytes(rng.randrange(256) for _ in range(n * osz))
        app = bytes([0xc0 | appseq, 0x81]) + iin + objects
        assert len(app) == 313, len(app)
        seg0, seg1 = app[:249], app[249:]
        f0 = std.frame(bytes([0x05, 0x64, 5 + 1 + len(seg0), 0x44]) + dst.to_bytes(2, 'little') + src.to_bytes(2, 'little'),
                       bytes([std.FIR | seq]) + seg0)
        f1 = std.frame(bytes([0x05, 0x64, 5 + 1 + len(seg1), 0x44]) + dst.to_bytes(2, 'little') + src.to_bytes(2, 'little'),
                       bytes([std.FIN | ((seq + 1) & 63)]) + seg1)
        native = f0 + f1
        req_user = bytes([0xc0 | ((seq - 1) & 63), 0xc0 | appseq, 0x01]) + SEG_REQ_OBJS
        req = std.frame(bytes([0x05, 0x64, 5 + len(req_user), 0xc4]) + src.to_bytes(2, 'little') + dst.to_bytes(2, 'little'), req_user)
        return req, native
    return make


# ---- IP/TCP packet model (only for measuring which per-segment checksum deltas are invariant) ----------
def _ones_sum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) | data[i + 1]
    if len(data) & 1:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def _cksum16(data):
    return (~_ones_sum(data)) & 0xffff


def _seg_packets(native_frames, out_frames):
    """Return, for each native link frame and its transformed image, the TCP payload pair and the
    before/after IP and TCP checksums under a fixed 5-tuple. out_frames excludes the prefix; the prefix
    is prepended to segment 0's payload (the wire packetization is one link frame per TCP segment)."""
    SRCIP, DSTIP = bytes([192, 168, 10, 1]), bytes([192, 168, 10, 7])
    SPORT, DPORT = 20000, 56857
    SEQ0, ACK0 = 0x11111111, 0x22222222
    prefix = out_frames[0]
    mapped = out_frames[1:]
    results = []
    stream_shift = 0           # bytes already inserted earlier in the stream (prefix) shift later seqs
    for i, (nf, mf) in enumerate(zip(native_frames, mapped)):
        old_pl = nf
        new_pl = (prefix + mf) if i == 0 else mf
        seq = (SEQ0 + sum(len(x) for x in native_frames[:i])) & 0xffffffff
        new_seq = (seq + stream_shift) & 0xffffffff
        def build(payload, tcpseq):
            ip_len = 20 + 20 + len(payload)
            ip = bytearray([0x45, 0x00, (ip_len >> 8) & 0xff, ip_len & 0xff, 0x00, 0x00, 0x00, 0x00,
                            0x40, 0x06, 0x00, 0x00]) + SRCIP + DSTIP
            ipck = _cksum16(bytes(ip))
            ip[10], ip[11] = (ipck >> 8) & 0xff, ipck & 0xff
            tcp = bytearray([(SPORT >> 8) & 0xff, SPORT & 0xff, (DPORT >> 8) & 0xff, DPORT & 0xff,
                             (tcpseq >> 24) & 0xff, (tcpseq >> 16) & 0xff, (tcpseq >> 8) & 0xff, tcpseq & 0xff,
                             (ACK0 >> 24) & 0xff, (ACK0 >> 16) & 0xff, (ACK0 >> 8) & 0xff, ACK0 & 0xff,
                             0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00])
            pseudo = SRCIP + DSTIP + bytes([0x00, 0x06, (len(tcp) + len(payload)) >> 8, (len(tcp) + len(payload)) & 0xff])
            tck = _cksum16(bytes(pseudo) + bytes(tcp) + payload)
            tcp[16], tcp[17] = (tck >> 8) & 0xff, tck & 0xff
            return ipck, tck
        old_ip, old_tcp = build(old_pl, seq)
        new_ip, new_tcp = build(new_pl, new_seq)
        results.append(dict(seg=i, old_len=len(old_pl), new_len=len(new_pl),
                            ip_before=old_ip, ip_after=new_ip, tcp_before=old_tcp, tcp_after=new_tcp,
                            tcp_seq_shift=stream_shift))
        stream_shift += len(new_pl) - len(old_pl)
    return results


def derive_segmented(shape, sample):
    """Full constant set + per-segment change characterisation for the two-frame 377 -> 401 shape."""
    req, native = sample()
    r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
    assert r.status == 'padded' and r.construction == 'prefix' and r.prefix_frames == 1, r
    out = gp.split_frames(r.output)
    prefix = out[0]
    nf = gp.split_frames(native)
    _, pu = std.deframe(prefix)
    hdr0, _ = std.deframe(nf[0])
    # per-frame rewritten byte positions. rewritten_positions is structural (the P4 always writes these
    # offsets); observed_changed is value-dependent (a moved IIN octet already 0 does not differ) so it is
    # recorded but never asserted on.
    per_frame = []
    for i, (a, b) in enumerate(zip(nf, out[1:])):
        h, u = std.deframe(a)
        crc_off = 10 + min(16, len(u))
        rewritten = [10] + ([11, 12, 13, 14] if i == 0 else []) + [crc_off, crc_off + 1]
        changed = [j for j in range(len(a)) if a[j] != b[j]]
        per_frame.append(dict(index=i, link_len=a[2], frame_len=len(a),
                              transport_old=u[0], transport_new=(u[0] & std.FIN) | (((u[0] & 63) + 1) & 63),
                              rewritten_positions=rewritten, observed_changed_positions=changed,
                              block0_crc_off=crc_off,
                              block0_crc_old=crc_be(a, crc_off),
                              block0_crc_new=crc_be(b, crc_off)))
    pkt = _seg_packets(nf, out)
    c = dict(shape=shape['name'], construction='prefix', native_total=len(native), target=r.target,
             added=len(r.output) - len(native), padding_points=r.padding_points,
             frames_out=[len(f) for f in out], native_frames=[len(f) for f in nf],
             tcp_packetization=[len(f) for f in nf],                 # one link frame per TCP segment (from captures)
             prefix_frame=prefix.hex(), prefix_frame_len=len(prefix), prefix_link_len=prefix[2],
             prefix_link_ctrl=hdr0[3],                               # copied from the native response (0x44)
             prefix_user_len=len(pu), padobj_head=pu[5:].hex(),      # the ONLY payload-content compile constant
             padobj_group_var_qual=pu[5:8].hex(), padobj_range=pu[8:12].hex(),
             prefix_link_crc_delta=crc_be(prefix, 8) ^ crc_be(nf[0], 8),  # pll.crc = native frame0 link crc ^ this (invariant)
             reserved_first_index=PAD_START, reserved_last_index=PAD_START + r.padding_points - 1,
             moved_app_header_src='native frame0 user[1:5] (app ctrl, function, IIN) -> prefix user[1:5]',
             per_frame=per_frame)
    return c, pkt


def _invariance(samples, pick):
    """Return (constant_value | None, n_distinct) for pick(sample) across samples."""
    vals = {pick(s) for s in samples}
    return (next(iter(vals)) if len(vals) == 1 else None), len(vals)


def main():
    rng = random.Random(20261020)
    result = dict(policy_targets=TARGETS, reserved_range=[PAD_START, PAD_STOP],
                  encoder_sha256=hashlib.sha256((ROOT / 'software/source/full_read_01/general_read_padding.py').read_bytes()).hexdigest(),
                  policy_sha256=hashlib.sha256((ROOT / 'policy/policy.json').read_bytes()).hexdigest(), shapes={})

    # ---- range_g10v2_23 : unchanged behaviour ----
    for shape in [dict(name='range_g10v2_23', native=49, sampler=range_sample)]:
        sample = shape['sampler'](rng)
        c = derive(shape, sample)
        checked = 0
        for _ in range(512):
            req, native = sample()
            r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
            assert construct(native, c) == r.output, 'constant construction differs from pad_read'
            again = derive(shape, lambda: (req, native))
            for k in ('prefix_link_len', 'padobj_head', 'rest', 'link_crc_delta', 'block0_tail'):
                assert again[k] == c[k], ('constant depends on live bytes', k)
            checked += 1
        c['verified_samples'] = checked
        result['shapes'][shape['name']] = c

    # ---- segmented_integrity_377 : two-frame 377 -> 401 ----
    shape = dict(name='segmented_integrity_377')
    sample = segmented_sample(rng)
    c0, _ = derive_segmented(shape, sample)
    samples = []
    checked = 0
    N = 512
    for _ in range(N):
        req, native = sample()
        r = gp.pad_read(req, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
        assert r.construction == 'prefix', ('expected prefix construction', r.construction)
        assert construct(native, c0) == r.output, 'segmented constant construction differs from pad_read'
        ci, pkt = derive_segmented(shape, lambda: (req, native))
        # the declared compile constants must not depend on live bytes
        for k in ('prefix_link_len', 'prefix_link_ctrl', 'padobj_head', 'padobj_group_var_qual',
                  'padobj_range', 'target', 'added', 'padding_points', 'frames_out', 'tcp_packetization',
                  'prefix_link_crc_delta'):
            assert ci[k] == c0[k], ('segmented constant depends on live bytes', k, ci[k], c0[k])
        # the rewritten byte offsets are structural and must be identical for every sample
        for a, b in zip(ci['per_frame'], c0['per_frame']):
            assert a['rewritten_positions'] == b['rewritten_positions'], ('rewritten positions vary', a, b)
        samples.append(dict(ci=ci, pkt=pkt))
        checked += 1

    # characterise what is constant vs derived-on-chip across all samples
    f0 = [s['pkt'][0] for s in samples]
    f1 = [s['pkt'][1] for s in samples]
    pf0 = [s['ci']['per_frame'][0] for s in samples]
    pf1 = [s['ci']['per_frame'][1] for s in samples]

    def inv(seq, key):
        v, n = _invariance(seq, lambda s: s[key])
        return dict(constant=v, distinct=n, invariant=(n == 1))

    c0['verified_samples'] = checked
    c0['prefix_frame_note'] = ('prefix_frame is one sample only; across samples only link start octets, '
                               'link LEN, link CTRL and padobj_head are invariant -- addresses, moved app '
                               'header and both CRCs vary and are derived on chip')
    # the constant bytes the deparser may add to the TCP checksum (link start+LEN+CTRL, padobj_head),
    # plus the pseudo-header length growth; everything else is derived from live fields
    const_prefix_bytes = bytes([0x05, 0x64, c0['prefix_link_len'], c0['prefix_link_ctrl']]) + bytes.fromhex(c0['padobj_head'])
    c0['checksum_model'] = dict(
        seg0_tcp_pseudo_len_growth=24, seg1_tcp_pseudo_len_growth=0,
        constant_added_bytes_ones_sum=_ones_sum(const_prefix_bytes),
        constant_added_bytes=const_prefix_bytes.hex(),
        seg0=dict(ip_before=inv(f0, 'ip_before'), ip_after=inv(f0, 'ip_after'),
                  tcp_before=inv(f0, 'tcp_before'), tcp_after=inv(f0, 'tcp_after')),
        seg1=dict(ip_before=inv(f1, 'ip_before'), ip_after=inv(f1, 'ip_after'),
                  tcp_before=inv(f1, 'tcp_before'), tcp_after=inv(f1, 'tcp_after')),
        note=('IP/TCP checksums vary across samples (addresses, moved IIN, varied points, transport '
              'renumber, +24 stream shift on seg1 seq); none is a compile constant. The deparser adds '
              'the constant_added_bytes one\'s-complement sum and the pseudo-header length growth; the '
              'remainder is derived from live fields exactly as the range padder does.'))
    c0['block0_crc'] = dict(
        frame0=dict(off=pf0[0]['block0_crc_off'], old_invariant=inv(pf0, 'block0_crc_old'),
                    new_invariant=inv(pf0, 'block0_crc_new')),
        frame1=dict(off=pf1[0]['block0_crc_off'], old_invariant=inv(pf1, 'block0_crc_old'),
                    new_invariant=inv(pf1, 'block0_crc_new')),
        note='block-0 CRCs (old and new) vary with live data; recomputed on chip, not a constant.')
    c0['transport_renumber'] = dict(
        frame0='FIR|seq -> seq+1 (FIR cleared, becomes a middle segment); prefix carries the new FIR',
        frame1='FIN|seq -> FIN|seq+1', table='(0xC0|s)->set per-s like the range padder tp table')
    # The segmented shape is an INVESTIGATION artifact: the frozen policy build (make_m12 --policy) and the
    # committed m12p_c12 candidate use only range_g10v2_23, and their inputs.json bind constants.json by sha256.
    # So constants.json keeps ONLY the range shape (byte-stable, that bound hash), and the segmented shape goes to
    # its own file constants_segmented.json, consumed by make_m12 --segmented and the segmented model drivers.
    seg = dict(policy_targets=TARGETS, reserved_range=[PAD_START, PAD_STOP], encoder_sha256=result['encoder_sha256'],
               policy_sha256=result['policy_sha256'], shapes={'segmented_integrity_377': c0})
    # c0 is intentionally NOT added to result['shapes']: constants.json stays the range-only, byte-stable file.

    (HERE / 'constants.json').write_text(json.dumps(result, indent=1) + '\n')
    (HERE / 'constants_segmented.json').write_text(json.dumps(seg, indent=1) + '\n')
    print(json.dumps(seg['shapes']['segmented_integrity_377'], indent=1))
    print('range verified_samples:', result['shapes']['range_g10v2_23']['verified_samples'])
    print('segmented verified_samples:', checked)


if __name__ == '__main__':
    main()
