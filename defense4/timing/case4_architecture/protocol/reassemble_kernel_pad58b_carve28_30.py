"""Feed the EXACT segments the Tofino-1 model emitted for case4_pad58b_carve28_30.p4 to a real Linux TCP receiver.

  unshare -Urn python3 protocol/reassemble_kernel_pad58b_carve28_30.py \
      protocol/evidence/pad58b_carve28_30_01/model_01/cases.json protocol/evidence/pad58b_carve28_30_01/kernel_01

Runs in a private user+network namespace (no root, no host traffic). The receiving socket is the kernel's
own TCP (10.0.0.2:40000) put directly into ESTABLISHED with TCP_REPAIR so its rcv_nxt equals the captured
prefix's sequence number and its snd_nxt equals the captured ack (0x22222222); repair mode is then turned
off, so everything after that is ordinary kernel receive processing: checksum validation, out-of-order
queueing and in-order delivery to read(). Captured frames are written to the peer veth unmodified.

Per split case it checks:
  arrival_order   - segments injected in the order the model put them on the wire;
  reversed_order  - the opposite order;
  suffix_only     - control: the suffix alone must deliver nothing (the stream has a 28-byte hole);
  bad_tcp_csum    - control: prefix with its TCP checksum flipped, then the suffix -> nothing delivered
                    (shows the kernel really validates the checksums the deparser wrote).
A delivered stream must equal the oracle's padded 58-byte image exactly and parse as one valid DNP3 frame.
"""
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'framework' / 'size'))
import rrc  # noqa: E402

TCP_REPAIR, TCP_REPAIR_QUEUE, TCP_QUEUE_SEQ = 19, 20, 21
TCP_RECV_QUEUE, TCP_SEND_QUEUE = 1, 2


def setup():
    subprocess.run('ip link set lo up; ip link add va type veth peer name vb; '
                   'ip link set va address 0a:00:00:00:00:02; ip link set vb address 0a:00:00:00:00:01; '
                   'ip addr add 10.0.0.2/24 dev va; ip link set va up; ip link set vb up; '
                   'ip neigh replace 10.0.0.1 lladdr 0a:00:00:00:00:01 dev va nud permanent',
                   shell=True, check=True)
    time.sleep(0.5)
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    tx.bind(('vb', 0))
    return tx


def receiver(rcv_nxt, snd_nxt):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 1)
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
    s.setsockopt(socket.IPPROTO_TCP, TCP_QUEUE_SEQ, struct.pack('=I', snd_nxt))  # u32: seq may exceed 2^31
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE)
    s.setsockopt(socket.IPPROTO_TCP, TCP_QUEUE_SEQ, struct.pack('=I', rcv_nxt))
    s.bind(('10.0.0.2', 40000))
    s.connect(('10.0.0.1', 20000))
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 0)
    s.setblocking(False)
    return s


def discard(s):
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 1)   # close without emitting FIN/RST
    s.close()


def deliver(tx, frames, rcv_nxt, snd_nxt, wait=0.5):
    s = receiver(rcv_nxt, snd_nxt)
    for f in frames:
        tx.send(f)
        time.sleep(0.05)
    got, end = b'', time.time() + wait
    while time.time() < end:
        r, _, _ = select.select([s], [], [], 0.05)
        if r:
            try:
                chunk = s.recv(4096)
            except BlockingIOError:
                continue
            if not chunk:
                break
            got += chunk
    discard(s)
    return got


def main(cases_path, out_dir):
    cases = {c['name']: c for c in json.load(open(cases_path))['cases']}
    tx = setup()
    results, ok_all = [], True
    names = sorted(n[:-len('_two_frames')] for n in cases if n.endswith('_two_frames'))
    for name in names:
        c = cases[name + '_two_frames']
        frames = [bytes.fromhex(x) for x in c['received']]
        padded = rrc.parse(bytes.fromhex(c['padded']))
        image, seq, ack = padded.payload, padded.seq, padded.ack
        pre = next(f for f in frames if rrc.parse(f).seq == seq)
        suf = next(f for f in frames if rrc.parse(f).seq != seq)
        bad = bytearray(pre)
        bad[14 + 20 + 16] ^= 0x01                        # flip one TCP checksum bit
        runs = {'arrival_order': (frames, image), 'reversed_order': (frames[::-1], image),
                'suffix_only': ([suf], b''), 'bad_tcp_csum': ([bytes(bad), suf], b'')}
        row = dict(case=name, seq=seq, arrival=c['arrival'], padded_image=image.hex())
        for run, (inject, want) in runs.items():
            got = deliver(tx, inject, seq, ack)
            passed = got == want and (not want or rrc.dnp3_frame_ok(got))
            row[run] = dict(delivered=got.hex(), delivered_len=len(got), expected_len=len(want), ok=passed)
            ok_all &= passed
            print('%-4s %-38s %-15s delivered=%d expected=%d' % ('PASS' if passed else 'FAIL', name, run, len(got), len(want)))
        results.append(row)
    os.makedirs(out_dir, exist_ok=True)
    summary = dict(cases=len(results), runs=4 * len(results),
                   passed=sum(r[k]['ok'] for r in results for k in ('arrival_order', 'reversed_order', 'suffix_only', 'bad_tcp_csum')),
                   kernel=os.uname().release)
    json.dump(dict(summary=summary, results=results), open(os.path.join(out_dir, 'reassembly.json'), 'w'), indent=1)
    print('SUMMARY', summary)
    return ok_all


if __name__ == '__main__':
    sys.exit(0 if main(sys.argv[1], sys.argv[2]) else 1)
