#!/usr/bin/env python3
"""SCRATCH. Checksum verification from the real bytes the Tofino model emitted (not the driver's verdict).
For every frame that left the switch in a model run's cases.json: recompute the IPv4 header checksum, the
TCP checksum over pseudo-header + segment, and every DNP3 link CRC (framework/size/rrc.py), and sort the
frame into the deparser's three exclusive cases:
  plain_changed  unpadded and rewritten by E (m.changed == 1: seq/ack/window differs from what was sent;
                 standalone runs only, which record 'sent')
  read_padded    DNP3 len 0x2f, READ object header 0a02000016           (hdr.rtp.isValid())
  ctl_padded     DNP3 len 0x2f, CROB object header 0c01280100           (hdr.ctp1.isValid())
plus untouched frames. Exit 1 if any frame fails any check, or a requested case has zero frames.
  python3 verify_wire.py <cases.json> [--require plain_changed,read_padded,ctl_padded]
"""
import json
import sys
from pathlib import Path

T = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(T / 'framework' / 'size'))
import rrc  # noqa: E402


def classify(rx, sent):
    p = rrc.parse(rx)
    if p is None:
        return 'non_tcp', True, ''
    ok = rrc.ip_ok(p) and rrc.tcp_ok(p)
    why = '' if ok else 'ip_ok=%s tcp_ok=%s' % (rrc.ip_ok(p), rrc.tcp_ok(p))
    pl = p.payload
    if pl[:2] == b'\x05\x64':
        fo = rrc.dnp3_frame_ok(bytes(pl))
        # a frame sent with a deliberately broken DNP3 CRC must leave with it still broken (never repaired/padded)
        s = rrc.parse(sent) if sent is not None else None
        want = rrc.dnp3_frame_ok(bytes(s.payload)) if s is not None and s.payload[:2] == b'\x05\x64' else True
        ok &= fo == want
        why += '' if fo == want else ' dnp3_crc_valid=%s expected=%s' % (fo, want)
        if pl[2] == 0x2f and len(pl) == 58:
            if pl[15:20] == bytes.fromhex('0a02000016'):
                return 'read_padded', ok, why
            if pl[15:20] == bytes.fromhex('0c01280100'):
                return 'ctl_padded', ok, why
            return 'padded_unknown', ok, why
    if sent is not None:
        s = rrc.parse(sent)
        if s is not None and (s.seq, s.ack, s.raw[14 + s.ihl + 14:14 + s.ihl + 16]) != \
                (p.seq, p.ack, p.raw[14 + p.ihl + 14:14 + p.ihl + 16]):
            return 'plain_changed', ok, why
    return 'untouched_or_unclassified', ok, why


def main():
    path = Path(sys.argv[1])
    req = sys.argv[3].split(',') if len(sys.argv) > 3 and sys.argv[2] == '--require' else []
    d = json.loads(path.read_text())
    counts, bad = {}, []
    # composite runs record no 'sent'; E's own outcome counter says which path ran: codes 2/3/5 (translate, zero,
    # stale) and 9/10 (reverse translate / withhold) set m.changed without padding
    changed_cases = {c['name'][:-len('_E_outcomes')] for c in d['cases'] if c['name'].endswith('_E_outcomes')
                     and isinstance(c.get('observed'), dict)
                     and any(str(k) in ('2', '3', '5', '9', '10') for k in c['observed'])}
    for c in d['cases']:
        rec = c.get('received')
        if rec is None:
            continue
        frames = [f for fl in rec.values() for f in fl] if isinstance(rec, dict) else rec
        sent = bytes.fromhex(c['sent']) if 'sent' in c else None
        for h in frames:
            kind, ok, why = classify(bytes.fromhex(h), sent)
            if kind == 'untouched_or_unclassified' and c['name'] in changed_cases:
                kind = 'plain_changed'
            counts.setdefault(kind, [0, 0])
            counts[kind][0] += 1
            counts[kind][1] += ok
            if not ok:
                bad.append((c['name'], kind, why))
    print(path)
    for k, (n, good) in sorted(counts.items()):
        print('  %-26s frames %3d  checksums+CRCs valid %3d' % (k, n, good))
    for b in bad:
        print('  BAD', b)
    missing = [r for r in req if counts.get(r, [0])[0] == 0]
    if missing:
        print('  MISSING required case(s):', missing)
    return 1 if bad or missing else 0


if __name__ == '__main__':
    sys.exit(main())
