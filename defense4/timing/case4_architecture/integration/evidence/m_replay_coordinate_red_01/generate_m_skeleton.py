#!/usr/bin/env python3
"""Emit m_skeleton.p4: the S3-3 resource canary of role M (pipe 1 ingress).

Mapping entry lists come from frozen payload_mapping/forward.p4 and reverse.p4.
The window guard retains its full-width deny entries; every success action commits
the computed inverse ACK/window in that same table. Producer/replay scratch stays
separate from mapper scratch. This remains a canary, not a composed target.
Usage: generate_m_skeleton.py > m_skeleton.p4
"""
import sys
from pathlib import Path

MAP = Path(__file__).resolve().parents[3] / 'protocol/payload_mapping'


def cut(text, start, end):
    a = text.index(start)
    return text[a:text.index(end, a)]


def tables():
    fwd = (MAP / 'forward.p4').read_text()
    rev = (MAP / 'reverse.p4').read_text()
    return (cut(fwd, 'action seq1_shift', 'action left1_shift'),
            cut(rev, 'action left1_shift', 'action difference'),
            cut(rev, 'table window_guard', 'action window_narrow'))


def main():
    seq, edges, guard = tables()
    template = Path(__file__).with_name('m_skeleton.p4.in').read_text()
    # original_ack was a copy of hdr.tcp.ack taken in edges(); read the header directly (PHV saving)
    # seq_result removed (PHV): the shifts accumulate in place, seq2 adds its own +20 on top of seq1's +20
    seq = (seq.replace('m.seq_result=m.original_seq+32w20;', 'hdr.tcp.seq=hdr.tcp.seq+32w20;')
              .replace('m.seq_result=m.original_seq+32w40;', 'hdr.tcp.seq=hdr.tcp.seq+32w20;'))
    # Fuse every success entry/default with header commit; deny masks are unchanged.
    guard = guard.replace("NoAction", "complete_reverse")
    edges = edges.replace('m.original_ack', 'hdr.tcp.ack').replace('m.original_seq=hdr.tcp.seq;', '').replace('m.m.seq_result', 'm.seq_result')
    sys.stdout.write(template.replace('@SEQ_TABLES@', seq).replace('@EDGE_TABLES@', edges)
                     .replace('@WINDOW_GUARD@', guard))


if __name__ == '__main__':
    main()
