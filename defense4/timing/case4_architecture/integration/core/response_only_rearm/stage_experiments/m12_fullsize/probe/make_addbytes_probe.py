"""Probe: can E add ~N constant bytes to the READ response in one egress pass?

The software append-padder reaches a shared target >=266 B by adding ~220 B to a 49-B READ (or ~232 B
of framing to a 37-B SBO). The existing E adds only ~12-24 B via small PHV headers and uses no
recirculation. This probe adds `--bytes` of constant headers to the read_eligible path and emits them,
then compiles, to learn whether bf-p4c can materialize that many added egress bytes in one pass
(placement only; checksum correctness is irrelevant to this feasibility question).

Usage: python3 make_addbytes_probe.py OUT_P4 --bytes 220
"""
import argparse
import hashlib
from pathlib import Path

M11_09 = (Path(__file__).resolve().parents[2]
          / 'ctl_timing_01/evidence/m11_09/response_only.p4')
M11_09_SHA = 'f1de2b30e9f00fb93b20df51c3ddfafd3fcfd18e9b6dfcaadd62146dddbe5af8'
CHUNK = 40  # bytes per added header (bit<320>)


def build(nbytes):
    src = M11_09.read_text()
    if hashlib.sha256(src.encode()).hexdigest() != M11_09_SHA:
        raise SystemExit('m11_09 source changed')
    nchunks = (nbytes + CHUNK - 1) // CHUNK
    # 1) declare the pad headers
    decls = ''.join('header r_pad%d_h{bit<%d> v;}\n' % (i, CHUNK * 8) for i in range(nchunks))
    src = src.replace('header r_read_d8_h{bit<8> d;}', decls + 'header r_read_d8_h{bit<8> d;}', 1)
    # 2) add them to the header struct (after cs3, the last emitted member)
    fields = ' '.join('r_pad%d_h pad%d;' % (i, i) for i in range(nchunks))
    src = src.replace('r_ctl_dl_h cd3; r_ctl_seg3_h cs3; }',
                      'r_ctl_dl_h cd3; r_ctl_seg3_h cs3; ' + fields + ' }', 1)
    # 3) set them valid with a constant in read_eligible, bump ip.len by nbytes
    setvalid = ''.join('hdr.pad%d.setValid();hdr.pad%d.v=%d;' % (i, i, CHUNK * 8 // 4 * 0) for i in range(nchunks))
    anchor = 'hdr.ip.len=hdr.ip.len+16w12;m.len_delta=16w12;}'
    newact = setvalid + ('hdr.ip.len=hdr.ip.len+16w%d;m.len_delta=16w%d;}' % (nbytes + 12, nbytes + 12))
    assert src.count(anchor) == 1
    src = src.replace(anchor, newact, 1)
    # 4) emit them in the deparser after cs3
    emit = ''.join('pkt.emit(hdr.pad%d);' % i for i in range(nchunks))
    src = src.replace('pkt.emit(hdr.cd3); pkt.emit(hdr.cs3);',
                      'pkt.emit(hdr.cd3); pkt.emit(hdr.cs3); ' + emit, 1)
    return src


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--bytes', type=int, default=220)
    a = ap.parse_args()
    out = Path(a.out)
    out.write_text(build(a.bytes))
    print('wrote %s (added %d bytes in %d chunks, sha=%s)'
          % (out, a.bytes, (a.bytes + CHUNK - 1) // CHUNK, hashlib.sha256(out.read_bytes()).hexdigest()[:12]))


if __name__ == '__main__':
    main()
