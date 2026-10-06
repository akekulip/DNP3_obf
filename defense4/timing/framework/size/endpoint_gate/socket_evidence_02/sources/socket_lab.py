"""One production OpenDNP3 pair, private software topology and Linux tail repair.

The bridge calls the existing software image oracle. It truncates the first wire
image of each phase once, then only reacts to real kernel packets. It never
creates ACKs, sends autonomously, retries application commands or touches host
interfaces. This is not BMv2/Tofino evidence or a physical retention measurement.
"""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
FRAMEWORK = HERE.parents[1]
sys.path.insert(0, str(FRAMEWORK))
sys.path.insert(0, str(HERE.parent))
from runner.evidence import claim_run, sha256


def accept(data):
    failures = []
    master, station, phases = data.get('master', {}), data.get('outstation', {}), data.get('phases', [])
    if master.get('success') is not True: failures.append('master command status')
    if master.get('application_calls') != 1: failures.append('application resend')
    if master.get('opens') != 1 or station.get('opens') != 1: failures.append('connection count')
    for key in ('select_real', 'select_decoy', 'operate_real', 'operate_decoy'):
        if station.get(key) != 1: failures.append('endpoint callback ' + key)
    if not 0 <= station.get('retention_ns', -1) <= 500000000: failures.append('endpoint selection retention')
    if len(phases) != 2: failures.append('exactly two phases required')
    for index, phase in enumerate(phases):
        expected = dict(native_size=35, wire_size=55, prefix_ack=34 + index * 35,
                        complete_ack=35 + index * 35, kernel_retransmission_size=1,
                        replay_size=21, response_size=57)
        for key, value in expected.items():
            if phase.get(key) != value: failures.append('phase %d %s' % (index, key))
    return dict(passed=not failures, failures=failures, **data)


def launch(run, manifest):
    for source in sorted((FRAMEWORK / 'bmv2/lab').glob('*.py')):
        run.snapshot(source, 'lab/' + source.name)
    run.record('socket_namespace_launch', binary_sha256=manifest['binary_sha256'])
    env = dict(os.environ, CASE4_RUN_TOKEN=run.token, CASE4_PARENT_NETNS=os.readlink('/proc/self/ns/net'),
               CASE4_PRIVATE_SOCKET_GATE='1')
    command = ['unshare', '-Urnm', sys.executable, '-B', str(HERE / 'socket_lab.py'), '--inner', str(run.path)]
    run.write_json('socket_command.json', command)
    with (run.path / 'socket_namespace.log').open('x') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    path = run.path / 'socket_result.json'
    if not path.exists(): return {'passed': False, 'failures': ['private socket acquisition did not complete'], 'exit_code': result}
    data = json.loads(path.read_text()); data['exit_code'] = result
    if result: data['passed'] = False
    return data


class Bridge:
    def __init__(self, work):
        import rrc
        from case4_padding import Decoy
        self.rrc = rrc
        self.decoy = Decoy(201, bytes.fromhex('0101640000006400000000'))
        self.connection = None
        self.work = work
        self.stop = threading.Event()
        self.error = None
        self.base = None
        self.phases = []
        self.tuple = None
        self.sockets = []

    def open(self):
        # Create and bind each socket synchronously before launching a TCP
        # client. Unbound ETH_P_ALL sockets receive packets from every port;
        # asynchronous binding can misroute a queued SYN and lose its RTT.
        try:
            for iface in ('s0', 's1'):
                stream = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                self.sockets.append(stream)
                stream.bind((iface, 0))
        except BaseException:
            for stream in self.sockets: stream.close()
            raise

    def run(self):
        from case4_transport import ControlConnection
        sockets = self.sockets
        if len(sockets) != 2: raise RuntimeError('bridge must bind before endpoint launch')
        try:
            with (self.work / 'bridge_events.jsonl').open('x') as log:
                while not self.stop.is_set():
                    ready, _, _ = select.select(sockets, [], [], .02)
                    for stream in ready:
                        raw, address = stream.recvfrom(65535)
                        if address[2] == socket.PACKET_OUTGOING: continue
                        direction = sockets.index(stream)
                        packet = self.rrc.parse(raw)
                        if packet is None: continue
                        if not self.rrc.ip_ok(packet) or not self.rrc.tcp_ok(packet):
                            raise RuntimeError('captured input network checksum invalid')
                        if direction == 0 and packet.flags & 2 and not packet.flags & 16:
                            self.tuple = dict(source='10.0.0.1', source_port=packet.sport, destination='10.0.0.2', destination_port=packet.dport)
                        event = dict(time_ns=time.monotonic_ns(), direction=direction, seq=packet.seq, ack=packet.ack,
                                     payload_hex=packet.payload.hex(), flags=packet.flags)
                        outputs = [raw]
                        if direction == 0 and packet.payload:
                            if self.connection is None and len(packet.payload) == 35:
                                self.base = packet.seq
                                self.connection = ControlConnection(self.base, self.decoy)
                            if self.connection:
                                translated = self.connection.forward(packet.seq, packet.payload)
                                if translated.inserted:
                                    phase = dict(native_size=len(packet.payload), wire_size=len(translated.payload),
                                                 native_start=(packet.seq-self.base)&0xffffffff,
                                                 wire_start=(translated.seq-self.base)&0xffffffff,
                                                 prefix_ack=None, complete_ack=None, kernel_retransmission_size=None,
                                                 replay_size=None, response_size=None)
                                    self.phases.append(phase)
                                    # Drop exactly the inserted tail on the first transmission.
                                    payload = translated.payload[:35]
                                    event['fault'] = 'truncated inserted tail once'
                                    event['full_image_hex'] = translated.payload.hex()
                                else:
                                    payload = translated.payload
                                    for phase in self.phases:
                                        if ((packet.seq-self.base)&0xffffffff) == phase['native_start']+34 and len(packet.payload)==1:
                                            phase['kernel_retransmission_size']=len(packet.payload)
                                            phase['replay_size']=len(payload)
                                            event['kernel_tail_replay']=len(self.phases)
                                outputs = [self.rrc._build(packet, payload, translated.seq, packet.flags)]
                        elif direction == 1 and self.connection and packet.flags & 16:
                            window = struct.unpack_from('>H', raw, packet.tcp_off+14)[0]
                            ack, window = self.connection.ledger.reverse(packet.ack, window)
                            wire_ack = (packet.ack-self.base)&0xffffffff
                            for phase in self.phases:
                                if wire_ack == phase['wire_start']+35: phase['prefix_ack']=(ack-self.base)&0xffffffff
                                if wire_ack == phase['wire_start']+55: phase['complete_ack']=(ack-self.base)&0xffffffff
                            adjusted = bytearray(raw)
                            struct.pack_into('>I', adjusted, packet.tcp_off+8, ack)
                            struct.pack_into('>H', adjusted, packet.tcp_off+14, window)
                            outputs = [self.rrc._build(self.rrc.parse(bytes(adjusted)), packet.payload, packet.seq, packet.flags)]
                            if packet.payload and self.rrc.dnp3_frame_ok(packet.payload):
                                from case4_padding import decode_frame
                                _, user = decode_frame(packet.payload)
                                if len(user) >= 3 and user[2] == 129:
                                    phase_index = len(self.phases)-1
                                    if phase_index >= 0: self.phases[phase_index]['response_size']=len(packet.payload)
                            event['translated_ack']=ack
                            event['translated_window']=window
                        event['outputs']=[image.hex() for image in outputs]
                        log.write(json.dumps(event)+'\n'); log.flush()
                        for image in outputs: sockets[1-direction].send(image)
        except BaseException as error:
            self.error = error
        finally:
            for stream in sockets: stream.close()


def last_json(path):
    rows = [line for line in path.read_text().splitlines() if line.startswith('{')]
    return json.loads(rows[-1]) if rows else {}


def acquire(work):
    run = claim_run(work, os.environ.get('CASE4_RUN_TOKEN', ''))
    if os.readlink('/proc/self/ns/net') == os.environ.get('CASE4_PARENT_NETNS'):
        raise RuntimeError('private network namespace required')
    # Every executed Python input must still match its reserved snapshot.
    for source in ('socket_lab.py',):
        if sha256(HERE/source) != sha256(work/'sources'/source): raise RuntimeError('socket source changed after reservation')
    for source in ('case4_padding.py', 'case4_transport.py', 'rrc.py'):
        if sha256(HERE.parent/source) != sha256(work/'sources'/source): raise RuntimeError('software oracle changed after reservation')
    lab_path = FRAMEWORK / 'bmv2/lab'
    for source in lab_path.glob('*.py'):
        if sha256(source) != sha256(work/'sources/lab'/source.name): raise RuntimeError('lab source changed after reservation')
    sys.path.insert(0,str(lab_path)); from lab import Lab
    manifest=json.loads((work/'manifest.json').read_text()); binary=Path(manifest['binary_path'])
    if sha256(binary)!=manifest['binary_sha256']: raise RuntimeError('built endpoint binary changed')
    lab=Lab(work); bridge=Bridge(work); worker=threading.Thread(target=bridge.run)
    master_result={}; station_result={}; master_rc=None
    try:
        lab.up()
        for ns in ('m','o'):
            lab.sh('sysctl','-qw','net.ipv4.tcp_timestamps=0','net.ipv4.tcp_sack=0','net.ipv4.tcp_window_scaling=0',ns=ns)
        cap_m=lab.capture('s0','master_side.pcap'); cap_o=lab.capture('s1','outstation_side.pcap')
        bridge.open()
        worker.start()
        stop=work/'endpoint_stop'
        with (work/'outstation.log').open('x') as station_log:
            station=subprocess.Popen(['ip','netns','exec','o',str(binary),'outstation',str(stop)],stdout=station_log,stderr=subprocess.STDOUT)
            lab.procs.append(station)
            deadline=time.monotonic()+2
            while time.monotonic()<deadline and 'READY' not in (work/'outstation.log').read_text():
                if station.poll() is not None: raise RuntimeError('production outstation exited before readiness')
                time.sleep(.01)
            if 'READY' not in (work/'outstation.log').read_text(): raise RuntimeError('production outstation not ready')
            with (work/'master.log').open('x') as master_log:
                master=subprocess.Popen(['ip','netns','exec','m',str(binary),'master',str(stop)],stdout=master_log,stderr=subprocess.STDOUT)
                lab.procs.append(master)
                deadline=time.monotonic()+7
                with (work/'tcp_info.jsonl').open('x') as samples:
                    while master.poll() is None and time.monotonic()<deadline:
                        observed=time.monotonic_ns()
                        info=lab.sh('ss','-tin',ns='m')
                        samples.write(json.dumps(dict(time_ns=observed,source='ss -tin private master namespace',
                                                      stdout=info.stdout,stderr=info.stderr,exit_code=info.returncode))+'\n')
                        samples.flush(); time.sleep(.025)
                master_rc=master.wait(timeout=1)
            stop.touch(exist_ok=False)
            station.wait(timeout=2)
        time.sleep(.1)
        master_result=last_json(work/'master.log'); station_result=last_json(work/'outstation.log')
    finally:
        bridge.stop.set()
        if worker.ident: worker.join(timeout=2)
        lab.down()
    data=dict(master=master_result,outstation=station_result,phases=bridge.phases,
              scope='production OpenDNP3 TCP sockets + Linux kernels + software image oracle; no P4 or physical endpoint',
              connection_id=run.token+':'+json.dumps(bridge.tuple,sort_keys=True), connection=bridge.tuple,
              endpoint_binary_sha256=manifest['binary_sha256'], opendnp3_commit=manifest['opendnp3_commit'],
              profile_sha256=manifest['wire_transform_sha256'], transport_sha256=manifest['transport_sha256'],
              netns=os.readlink('/proc/self/ns/net'), kernel=os.uname().release, master_exit_code=master_rc)
    result=accept(data)
    if bridge.error: result['passed']=False; result['failures'].append('bridge error: '+str(bridge.error))
    run.write_json('socket_result.json',result)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    if len(sys.argv)!=3 or sys.argv[1]!='--inner': raise SystemExit('use run.py --sockets with a fresh output')
    raise SystemExit(acquire(Path(sys.argv[2])))
