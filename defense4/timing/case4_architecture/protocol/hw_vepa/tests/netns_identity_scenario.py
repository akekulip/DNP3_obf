"""Kernel scenario for identity-targeted loss, run INSIDE a private network+mount namespace in which this process
holds CAP_NET_ADMIN (launched by test_loss_identity_netns.py through `sudo -n unshare -nm` or `unshare -Urnm`).

    python3 netns_identity_scenario.py MODE        MODE = request | response | response_ack

Topology: this (outer) namespace is the master, 192.168.10.1:59970; a nested namespace is the relay,
192.168.10.7:20000; a veth pair joins them. The master sends three 27-byte requests (IP length 79 with TCP
timestamps, the request_full shape), waits for a 158-byte answer to each, then pauses PAUSE_S so its delayed
pure ACK of that answer leaves before the next request. relay_loss.RelayLoss takes the ISNs from the master's
receive capture (SYN-ACK) and arms its u32 rule immediately before the target request is sent:

  request       request_full:3:identity            OUTPUT, SEQ @4  -- request 3. Before it, a forcing rule that
                matches request 1's OWN SEQ (u32) drops request 1's first copy, so request 1 is retransmitted (the
                occurrence shift of rc01_hw_c52_20261024_26_loss_full_950 t0). The forcing rule is read and DELETED
                once request 1 is answered, before request 3 is armed, so nothing rewrites the table between the
                identity drop and request 3's retransmission (see LOSS_TARGETING.md, one-shot precondition).
  response      read_resp_padded:2:identity        INPUT,  SEQ @4  -- the relay's response 2, SEQ computed from
                the relay ISN + tcpi_bytes_received; the relay retransmits it.
  response_ack  master_ack_of_padded_data:2:identity OUTPUT, ACK @8 -- the master's pure ACK of response 2.

Captures use the in-file Sniffer (AF_PACKET) rather than tcpdump, so the same script also runs unprivileged:
'out' is what left after netfilter OUTPUT, 'in' is what arrived before netfilter INPUT. Prints one JSON object
with the loss report, round trips, both captures' TCP segments and the forcing rule's counters. All rules and
processes are removed in finally blocks; the namespaces die with this process."""
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import relay_loss  # noqa: E402
import wire_check  # noqa: E402

MASTER, RELAY, MPORT, RPORT = '192.168.10.1', '192.168.10.7', 59970, 20000
REQ, RESP = 27, 158
PAUSE_S = 0.1                      # > the 40 ms delayed-ACK floor, < the 200 ms minimum RTO
MODES = {'request': 'request_full:3:identity', 'response': 'read_resp_padded:2:identity',
         'response_ack': 'master_ack_of_padded_data:2:identity'}


def force_rule(seq):
    """Drop the first copy of the master segment whose SEQ is `seq` (request 1): u32-selected, so it can never
    match any other segment; limit 1/minute so it is distinct from the owned rules."""
    return ['-p', 'tcp', '-s', MASTER, '-d', RELAY, '--sport', str(MPORT), '--dport', str(RPORT), '-m', 'length',
            '--length', str(40 + 12 + REQ), '--tcp-flags', 'SYN,RST,ACK,FIN,PSH', 'ACK,PSH',
            '-m', 'u32', '--u32', relay_loss.u32_expression('SEQ', seq),
            '-m', 'limit', '--limit', '1/minute', '--limit-burst', '1', '-j', 'DROP']


SERVER = r'''
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("%s", %d)); s.listen(1); print("ready", flush=True)
c, _ = s.accept(); c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
buf = b""
while True:
    d = c.recv(4096)
    if not d: break
    buf += d
    while len(buf) >= %d:
        buf = buf[%d:]; c.sendall(b"r" * %d)
c.close()
''' % (RELAY, RPORT, REQ, REQ, RESP)


class Sniffer(threading.Thread):
    """Minimal AF_PACKET capture to a classic Ethernet pcap, flushed per packet like `tcpdump -U`. Used instead of
    tcpdump because tcpdump cannot drop privileges (setgroups/chown) inside an unprivileged user namespace.
    direction 'out' keeps PACKET_OUTGOING frames (what left after netfilter OUTPUT), 'in' everything else."""
    def __init__(self, ifname, direction, path):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.sock.bind((ifname, 0))
        self.sock.settimeout(0.1)
        self.outgoing, self.stream, self.stop = direction == 'out', open(path, 'wb'), threading.Event()
        self.stream.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.stream.flush()
        self.start()

    def run(self):
        while not self.stop.is_set():
            try:
                frame, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if (addr[2] == socket.PACKET_OUTGOING) != self.outgoing:
                continue
            t = time.time()
            self.stream.write(struct.pack('<IIII', int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame)
            self.stream.flush()

    def poll(self):
        return None if self.is_alive() else 0

    def kill(self):
        self.stop.set()

    def wait(self, timeout=None):
        self.join(5)
        self.stream.close()
        self.sock.close()


def sh(*argv, check=True):
    r = subprocess.run(list(argv), capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError('%s failed: %s' % (' '.join(argv), r.stderr.strip()))
    return r


def counters(chain='OUTPUT'):
    out = sh('iptables', '-w', '-L', chain, '-v', '-n', '-x').stdout
    return [line.split() for line in out.splitlines()[2:] if line.strip()]


def segments(path):
    segs, _ = wire_check.parse(path)
    return [dict(src=x['src'], seq=x['seq'], ack=x['ack'], flags=x['flags'], len=x['len'], ip_len=x['ip_len'],
                 t_us=x['t_us']) for x in segs]


def main():
    mode = sys.argv[1]
    work = Path(tempfile.mkdtemp(prefix='identity_netns_'))
    sh('mount', '-t', 'tmpfs', 'none', '/run')           # private /run: xtables.lock inside this mount namespace
    procs, force = [], None
    result = dict(mode=mode)
    try:
        sh('ip', 'link', 'set', 'lo', 'up')
        holder = subprocess.Popen(['unshare', '-n', 'sleep', '120'])
        procs.append(holder)
        time.sleep(0.2)
        nsx = ['nsenter', '-t', str(holder.pid), '-n']
        sh('ip', 'link', 'add', 'va', 'type', 'veth', 'peer', 'name', 'vb')
        sh('ip', 'link', 'set', 'vb', 'netns', str(holder.pid))
        sh('ip', 'addr', 'add', MASTER + '/24', 'dev', 'va')
        sh('ip', 'link', 'set', 'va', 'up')
        for cmd in (['ip', 'link', 'set', 'lo', 'up'], ['ip', 'addr', 'add', RELAY + '/24', 'dev', 'vb'],
                    ['ip', 'link', 'set', 'vb', 'up']):
            sh(*(nsx + cmd))
        server = subprocess.Popen(nsx + [sys.executable, '-c', SERVER], stdout=subprocess.PIPE, text=True)
        procs.append(server)
        assert server.stdout.readline().strip() == 'ready'
        caps = {}
        for direction in ('in', 'out'):
            caps[direction] = Sniffer('va', direction, work / (direction + '.pcap'))
            procs.append(caps[direction])
        time.sleep(0.5)
        spec = relay_loss.parse_drop(MODES[mode], 'full', 1)
        owner = relay_loss.RelayLoss(spec, MPORT, 'netns_identity', work / 'relay_loss_state.json',
                                     capture=str(work / 'in.pcap'))
        owner.install()
        rtt_ms, error, force_counters = [], None, None
        try:
            s = socket.socket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.bind((MASTER, MPORT))
            s.settimeout(10)
            s.connect((RELAY, RPORT))
            owner.on_connect(timeout_s=3)
            if mode == 'request':
                force = force_rule((owner.target.master_isn + 1) & 0xFFFFFFFF)
                sh('iptables', '-w', '-I', 'OUTPUT', '1', *force)
            for k in range(3):
                frame = bytes([0x30 + k]) * REQ
                owner.before_send('READ', frame, s)
                t = time.monotonic()
                s.sendall(frame)
                got = b''
                while len(got) < RESP:
                    got += s.recv(RESP - len(got))
                rtt_ms.append(round((time.monotonic() - t) * 1e3, 3))
                if force is not None:              # request 1 answered: read and remove the forcing rule now,
                    force_counters = counters()    # before request 3 is armed
                    sh('iptables', '-w', '-D', 'OUTPUT', *force)
                    force = None
                time.sleep(PAUSE_S)
            s.close()
            time.sleep(0.5)
        except Exception as exc:                          # recorded, then the owner still finishes and restores
            error = repr(exc)
        if force is not None:
            sh('iptables', '-w', '-D', 'OUTPUT', *force, check=False)
            force = None
        report = owner.finish()
        for p in caps.values():
            p.kill()
            p.wait()
        result.update(error=error, rtt_ms=rtt_ms, report=report, force_counters=force_counters,
                      isns=list(relay_loss.syn_ack_isns(str(work / 'in.pcap'), MPORT)),
                      out=segments(str(work / 'out.pcap')), into=segments(str(work / 'in.pcap')))
    finally:
        if force is not None:
            sh('iptables', '-w', '-D', 'OUTPUT', *force, check=False)
        for p in procs:
            if p.poll() is None:
                p.kill()
                p.wait()
    print(json.dumps(result, default=str))


if __name__ == '__main__':
    main()
