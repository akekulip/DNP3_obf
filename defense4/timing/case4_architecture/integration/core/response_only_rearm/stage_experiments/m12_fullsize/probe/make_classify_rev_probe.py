"""Probe: regenerate classify_rev for a larger image and compile the otherwise-unchanged m11_09.

This isolates the single gating resource question for the integrated READ+SBO size candidate: the
reverse-ACK withhold window `classify_rev` (m.r ternary x tcp.window range) carries two const entries
per image byte (124 for the 61-byte image). A shared target that accommodates the 247-byte full READ
needs an image near ~282, i.e. ~566 entries. If that table does not place, the per-byte construction is
the blocker and a 2-D (offset vs window) match primitive or a smaller max image is required.

Usage: python3 make_classify_rev_probe.py OUT_P4 --image 282
"""
import argparse
import hashlib
from pathlib import Path

M11_09 = (Path(__file__).resolve().parents[2]
          / 'ctl_timing_01/evidence/m11_09/response_only.p4')
M11_09_SHA = 'f1de2b30e9f00fb93b20df51c3ddfafd3fcfd18e9b6dfcaadd62146dddbe5af8'


def rev_entries(image):
    lines = ['            (32w0 &&& 32w0x80000000, _) : rev_translate();']
    for d in range(1, image + 1):
        r = (0x100000000 - d) & 0xFFFFFFFF
        lines.append('            (32w0x%08x, 16w0 .. 16w%d) : rev_withhold_zero();' % (r, d - 1))
        lines.append('            (32w0x%08x, 16w%d .. 16w65535) : rev_withhold_open();' % (r, d))
    return '\n'.join(lines)


def build(image):
    src = M11_09.read_text()
    if hashlib.sha256(src.encode()).hexdigest() != M11_09_SHA:
        raise SystemExit('m11_09 source changed')
    start = src.index('    table classify_rev {')
    body_start = src.index('const entries = {', start) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    old_size = src.index('size = 124;', start)
    src = src[:old_size] + ('size = %d;' % (2 * image + 2)) + src[old_size + len('size = 124;'):]
    # indices shifted by the size edit; recompute the entries region
    body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    return src[:body_start] + '\n' + rev_entries(image) + '\n        ' + src[body_end:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--image', type=int, default=282)
    a = ap.parse_args()
    out = Path(a.out)
    out.write_text(build(a.image))
    print('wrote %s (image=%d, classify_rev size=%d, sha=%s)'
          % (out, a.image, 2 * a.image + 2, hashlib.sha256(out.read_bytes()).hexdigest()[:12]))


if __name__ == '__main__':
    main()
