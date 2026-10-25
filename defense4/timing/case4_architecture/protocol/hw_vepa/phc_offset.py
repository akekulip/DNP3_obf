#!/usr/bin/env python3
"""Sample a NIC's PTP hardware clock (PHC) against CLOCK_REALTIME, with a per-sample uncertainty bound.

  sudo python3 phc_offset.py IFACE [IFACE ...] [--samples 25] [--json OUT]

Used before and after every relay-leg capture block (c52 timing diagnosis, plan Step 3): with hardware RX timestamps
(`tcpdump -j adapter_unsynced`) each capture is stamped by its NIC's PHC, so relating two captures needs each PHC's
offset to the system clock and its drift over the block. No package is installed (no linuxptp): this calls the
kernel's PTP_SYS_OFFSET_EXTENDED ioctl directly (linux/ptp_clock.h), which returns [system, phc, system] triples.

Per sample: offset = phc - (sys_before + sys_after) / 2, bound = (sys_after - sys_before) / 2, so the true offset
lies within offset +- bound (plus the PHC read's own asymmetry, which the kernel window does not remove). The
reported estimate is the sample with the narrowest window; all samples are kept.
"""
import argparse
import fcntl
import json
import os
import struct
import sys
import time
from pathlib import Path

PTP_MAX_SAMPLES = 25
TIME = struct.Struct('<qIi')                 # struct ptp_clock_time { __s64 sec; __u32 nsec; __u32 reserved; }
HEADER = struct.Struct('<I3I')               # n_samples, rsv[3]
SIZE = HEADER.size + PTP_MAX_SAMPLES * 3 * TIME.size


def iowr(magic, nr, size):
    return (3 << 30) | (size << 16) | (ord(magic) << 8) | nr


PTP_SYS_OFFSET_EXTENDED = iowr('=', 9, SIZE)


def ptp_device(iface, sysfs=Path('/sys/class/net')):
    """/dev/ptpN for an interface, from sysfs; raises if the NIC exposes no PHC."""
    entries = sorted((sysfs / iface / 'device' / 'ptp').glob('ptp*'))
    if len(entries) != 1:
        raise ValueError('%s exposes %d PHCs (need exactly one)' % (iface, len(entries)))
    return Path('/dev') / entries[0].name


def parse(raw, n):
    """Pure: decode n [system, phc, system] triples into per-sample offset and bound (ns)."""
    if not 1 <= n <= PTP_MAX_SAMPLES or len(raw) < HEADER.size + n * 3 * TIME.size:
        raise ValueError('bad sample count or short buffer')
    samples = []
    for i in range(n):
        base = HEADER.size + i * 3 * TIME.size
        sec_ns = [TIME.unpack_from(raw, base + k * TIME.size) for k in range(3)]
        before, phc, after = [s * 1000000000 + ns for s, ns, _ in sec_ns]
        if after < before:
            raise ValueError('system clock went backwards inside sample %d' % i)
        samples.append(dict(sys_before_ns=before, phc_ns=phc, sys_after_ns=after,
                            # integers first: at epoch-ns magnitude (~1.7e18) a float sum loses ~100 ns
                            offset_ns=(2 * phc - before - after) / 2.0, bound_ns=(after - before) / 2.0))
    best = min(samples, key=lambda s: s['bound_ns'])
    # A preempted read widens its window (measured on Vision's i40e: up to 2 ms) and its midpoint offset is then
    # meaningless; the agreement among narrow-window samples (<= 2x the narrowest) is the consistency check.
    narrow = [s['offset_ns'] for s in samples if s['bound_ns'] <= 2 * best['bound_ns']]
    return dict(samples=samples, offset_ns=best['offset_ns'], bound_ns=best['bound_ns'],
                spread_ns=max(s['offset_ns'] for s in samples) - min(s['offset_ns'] for s in samples),
                narrow_count=len(narrow), narrow_spread_ns=max(narrow) - min(narrow))


def sample(device, n=PTP_MAX_SAMPLES, ioctl=fcntl.ioctl):
    buf = bytearray(SIZE)
    HEADER.pack_into(buf, 0, n, 0, 0, 0)
    fd = os.open(str(device), os.O_RDWR)
    try:
        ioctl(fd, PTP_SYS_OFFSET_EXTENDED, buf)
    finally:
        os.close(fd)
    return parse(bytes(buf), n)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('iface', nargs='+')
    ap.add_argument('--samples', type=int, default=PTP_MAX_SAMPLES)
    ap.add_argument('--json')
    a = ap.parse_args(argv)
    out = dict(at_realtime_ns=time.time_ns(), clock='CLOCK_REALTIME', ioctl='PTP_SYS_OFFSET_EXTENDED', nics={})
    for iface in a.iface:
        device = ptp_device(iface)
        out['nics'][iface] = dict(device=str(device), **sample(device, a.samples))
    text = json.dumps(out, indent=1)
    if a.json:
        Path(a.json).write_text(text + '\n')
    for iface, r in out['nics'].items():
        print('%s %s offset %.0f ns +- %.0f ns; narrow-window spread %.0f ns over %d of %d samples (all: %.0f ns)'
              % (iface, r['device'], r['offset_ns'], r['bound_ns'], r['narrow_spread_ns'], r['narrow_count'],
                 len(r['samples']), r['spread_ns']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
