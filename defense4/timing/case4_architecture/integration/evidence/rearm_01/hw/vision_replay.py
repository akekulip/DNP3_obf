#!/usr/bin/env python3
"""Three fixed59400 RST connections with externally observed old-packet replay.

Default is an offline plan. --apply requires DEFENSE4_HW_AUTHORIZED=1 and an
already installed software tuple. The hardware owner writes c2/replay_graceful.json
and c2/replay_rst.json using replay_old_packets.py during c2's10000ms pre-READ pause.
No setup, switch access, packet sending, or checksum repair occurs here.

Raw captures remain intact. Only exact manifest-declared OUT frame counts are
removed in c2/current/out.pcap; the entire IN capture is copied unchanged. The
existing application/wire/controls/RST gate then evaluates current evidence.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vision_isolation as vi
import replay_old_packets as rp

vc, PORT = vi.vc, 59400
MANIFESTS = ('replay_graceful.json', 'replay_rst.json')
COPIES = ('in.pcap', 'master.json', 'outstation.json', 'result.json', 'state.txt', 'pre_read_ready.json')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def coordinates(value):
    if not isinstance(value, dict) or set(value) != {'client', 'server'} or any(
            type(number) is not int or not 0 <= number <= rp.MASK for number in value.values()):
        raise ValueError('missing or malformed connection ISNs')
    return value


def pcap_records(path):
    raw = Path(path).read_bytes()
    rp.records(path)  # complete classic Ethernet pcap; no truncated frames permitted
    little = raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1')
    endian = '<' if little else '>'
    scale = 1 if raw[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1000
    records, offset = [], 24
    while offset < len(raw):
        seconds, fraction, length, _ = struct.unpack(endian + 'IIII', raw[offset:offset + 16])
        if fraction * scale >= 1_000_000_000:
            raise ValueError('malformed pcap timestamp')
        record = raw[offset:offset + 16 + length]
        records.append(dict(raw=record, frame=record[16:], ns=seconds * 1_000_000_000 + fraction * scale))
        offset += 16 + length
    return raw[:24], records


def load_manifests(dest):
    manifests, wanted, descriptors = [], Counter(), {}
    for name in MANIFESTS:
        value = json.loads((dest / name).read_text())
        if not isinstance(value, dict) or value.get('applied') is not True or value.get('interface') != vc.NIC or \
                value.get('tuple') != [vc.MASTER, PORT, vc.OUTSTATION, 20000]:
            raise ValueError(name + ': replay was not applied on the fixed software tuple/NIC')
        coordinates(value.get('isns')); coordinates(value.get('new_isns'))
        packets = value.get('packets')
        if not isinstance(packets, list) or not packets or type(value.get('sent')) is not int or value['sent'] != len(packets):
            raise ValueError(name + ': sent count does not equal complete packet list')
        counts, local = Counter(), Counter()
        for packet in packets:
            if not isinstance(packet, dict) or not isinstance(packet.get('sha256'), str) or \
                    not re.fullmatch('[0-9a-f]{64}', packet['sha256']) or packet.get('class') not in rp.CLASSES or \
                    type(packet.get('payload_bytes')) is not int or packet['payload_bytes'] < 0:
                raise ValueError(name + ': malformed replay packet declaration')
            digest = packet['sha256']
            if digest in wanted:
                raise ValueError('replay archives share ambiguous frame hashes')
            if digest in descriptors and any(descriptors[digest][key] != packet[key] for key in ('class', 'payload_bytes')):
                raise ValueError('duplicate hash has inconsistent packet declaration')
            descriptors[digest] = packet
            local[digest] += 1; counts[packet['class']] += 1
            if packet['class'] == 'READ_RESPONSE' and packet['payload_bytes'] != 49:
                raise ValueError(name + ': old READ response is not native49')
        if value.get('counts') != {kind: counts[kind] for kind in rp.CLASSES} or \
                any(not counts[kind] for kind in ('SYN', 'SYN_ACK', 'PURE_ACK', 'READ_REQUEST', 'READ_RESPONSE')):
            raise ValueError(name + ': missing classes or inconsistent class counts')
        if (name == MANIFESTS[0] and (not counts['FIN'] or counts['RST'])) or (name == MANIFESTS[1] and not counts['RST']):
            raise ValueError(name + ': captured graceful FIN or actual RST proof missing')
        manifests.append(value); wanted.update(local)
    if manifests[0]['new_isns'] != manifests[1]['new_isns'] or any(
            manifests[0]['isns'][key] == manifests[1]['isns'][key] for key in ('client', 'server')):
        raise ValueError('archives must have distinct old ISNs and agree on current ISNs')
    return manifests, wanted, descriptors


def fresh_handshake(dest, wanted, new):
    sent = [seg for seg in vc.wc.parse(dest / 'out.pcap')[0] if hashlib.sha256(seg['frame']).hexdigest() not in wanted]
    clients = {seg['seq'] for seg in sent if vc.exact(seg, PORT) and seg['flags'] == vc.wc.SYN and not seg['len']}
    servers = {seg['seq'] for seg in sent if vc.exact(seg, PORT, True) and seg['flags'] == vc.wc.SYN | vc.wc.ACK and not seg['len']}
    if clients != {new['client']} or servers != {new['server']}:
        raise ValueError('declared current ISNs differ from captured current handshake')
    ack = [seg for seg in sent if vc.exact(seg, PORT) and seg['flags'] == vc.wc.ACK and not seg['len'] and
           seg['seq'] == (new['client'] + 1) & rp.MASK and seg['ack'] == (new['server'] + 1) & rp.MASK]
    reads = [seg for seg in sent if vc.exact(seg, PORT) and seg['payload'][12:18] == b'\x01\x0a\x02\x00\x00\x16']
    returned = [seg for seg in vc.wc.parse(dest / 'in.pcap')[0] if all(vc.wc.ip_tcp_checksum(seg)[:2])]
    if not ack or not reads or not any(vc.exact(seg, PORT) and seg['flags'] == vc.wc.SYN and seg['seq'] == new['client'] for seg in returned) or \
            not any(vc.exact(seg, PORT, True) and seg['flags'] == vc.wc.SYN | vc.wc.ACK and seg['seq'] == new['server'] and
                    seg['ack'] == (new['client'] + 1) & rp.MASK for seg in returned):
        raise ValueError('missing checksum-valid current handshake or first READ')
    return min(seg['index'] for seg in ack), min(seg['index'] for seg in reads)


def derive_current(dest):
    dest = Path(dest)
    manifests, wanted, descriptors = load_manifests(dest)
    header, records = pcap_records(dest / 'out.pcap')
    actual, frames = Counter(), {}
    removed, retained = [], []
    for index, record in enumerate(records):
        digest = hashlib.sha256(record['frame']).hexdigest()
        if digest not in wanted:
            retained.append(record['raw']); continue
        facts = rp.segment(record['frame'], PORT)  # verifies checksums/CRC and rejects private headers/other flows
        declared = descriptors[digest]
        if any(declared.get(key) != facts[key] for key in ('class', 'payload_bytes')) or any(
                key in declared and declared[key] != value for key, value in facts.items()):
            raise ValueError('replay declaration differs from actual captured bytes')
        actual[digest] += 1; frames[digest] = facts
        removed.append(index)
    if actual != wanted:
        raise ValueError('captured replay SHA counts do not equal declared sent counts')
    new = manifests[0]['new_isns']
    for manifest in manifests:
        packets = [frames[packet['sha256']] for packet in manifest['packets']]
        if rp.handshake(packets) != manifest['isns']:
            raise ValueError('declared old ISNs differ from replayed old handshake')
        for direction, key in (('M->O', 'client'), ('O->M', 'server')):
            isn = manifest['isns'][key]
            spans = [((packet['seq'] - isn) & rp.MASK) + packet['payload_bytes'] + bool(packet['flags'] & (vc.wc.SYN | vc.wc.FIN))
                     for packet in packets if packet['direction'] == direction]
            if max(spans) >= 0x80000000 or not 2 <= ((new[key] + 1 - isn - max(spans)) & rp.MASK) <= 0x7fffffff:
                raise ValueError('ambiguous or overlapping old/current sequence range')
    ack, read = fresh_handshake(dest, wanted, new)
    if any(not ack < index < read or not records[ack]['ns'] <= records[index]['ns'] <= records[read]['ns'] for index in removed):
        raise ValueError('intentional replays occurred outside current handshake/first READ pause')
    for name in COPIES:
        if not (dest / name).is_file() or not (dest / name).stat().st_size:
            raise ValueError('missing raw evidence: ' + name)
    pcap_records(dest / 'in.pcap')
    current = dest / 'current'; current.mkdir()  # never reuse derived evidence
    (current / 'out.pcap').write_bytes(header + b''.join(retained))
    for name in COPIES:
        shutil.copyfile(dest / name, current / name)
    result = dict(evidence_dir=str(current), removed=len(removed), removed_sha_counts=dict(actual),
                  classes=dict(sum((Counter(value['counts']) for value in manifests), Counter())), new_isns=new,
                  old_isns=[value['isns'] for value in manifests],
                  interval=dict(handshake_ack_ns=records[ack]['ns'], first_read_ns=records[read]['ns'],
                                first_replay_ns=min(records[index]['ns'] for index in removed),
                                last_replay_ns=max(records[index]['ns'] for index in removed)),
                  manifest_hashes={name: sha(dest / name) for name in MANIFESTS},
                  raw_hashes={name: sha(dest / name) for name in ('out.pcap',) + COPIES},
                  derived_hashes={name: sha(current / name) for name in ('out.pcap',) + COPIES})
    vc.write_json(current / 'filter.json', result)
    return result


def scenario(label, port=PORT, padding=1, apply=False):
    vc.guard(port, apply)
    if port != PORT:
        raise ValueError('external replay requires fixed master source port59400')
    if not re.fullmatch('[A-Za-z0-9_]+', label) or type(padding) is not int or padding not in (0, 1):
        raise ValueError('invalid label or padding')
    record = vi.scenario(label, port, padding)  # pure offline plan; its controls are the shared fixed sequence
    record.update(scenario='candidate_same_tuple_replay', applied=apply, ok=False)
    if not apply:
        record['ok'] = True; return record
    parent = Path(vc.vr.RUNS) / label; parent.mkdir(parents=True)
    try:
        record['preflight'] = vc.preflight('rst')
        for leg in record['plan']:
            dest = parent / leg['name']
            done, observer = threading.Event(), {}
            connection = dict(leg, ok=False, failures=[])
            record['connections'].append(connection)

            def watch():
                try: observer.update(vc.observe(dest, PORT, done))
                except Exception as error: observer.update(ok=False, error=str(error))

            worker = threading.Thread(target=watch, daemon=True); worker.start()
            try:
                with vc.pre_read_controls(dest, leg['pre_read_grace_ms']):
                    result = vc.vr.run_connection(str(dest), label + '_' + dest.name, PORT, 1, 8, 0, 0,
                        leg['start_seed'], read_pause_ms=25, run_sbo=True, close_grace_ms=1000, capture_immediate=True)
                connection['result'] = result
            except Exception as error:
                result = {}; connection['failures'].append(str(error))
            finally:
                done.set(); dest.mkdir(exist_ok=True); worker.join(timeout=5)
                if worker.is_alive(): connection['failures'].append('observer did not stop within5seconds')
                connection['observer'] = dict(observer); vc.write_json(dest / 'observer.json', observer)
                if observer.get('ok') is not True: connection['failures'].append('kernel RST observer failed')
            try:
                evidence = dest
                if leg['name'] == 'c2':
                    connection['replay_filter'] = derive_current(dest)
                    evidence = Path(connection['replay_filter']['evidence_dir'])
                connection['evidence_dir'] = str(evidence)
                connection['failures'] += vc.evaluate(evidence, PORT, 'rst', padding, result,
                    rst_grace_ms=1000, reads=1, pre_read_grace_ms=leg['pre_read_grace_ms'])
            except Exception as error:
                connection['failures'].append('replay evidence failed: ' + str(error))
            connection['pre_read_hook'] = vc.pre_read_evidence(dest, leg['pre_read_grace_ms'])[1]
            connection['ok'] = not connection['failures']; vc.write_json(dest / 'verdict.json', connection)
            if not connection['ok']: break
        record['ok'] = len(record['connections']) == 3 and all(connection['ok'] for connection in record['connections'])
    except Exception as error:
        record['error'] = str(error)
    finally:
        record['source_sha256'] = {str(path): sha(path) for path in
            (Path(__file__), Path(vi.__file__), Path(vc.__file__), Path(rp.__file__), Path(vc.vr.__file__),
             Path(vc.wc.__file__), Path(vc.clrt.__file__), Path(vc.checks.__file__),
             HERE / 'token_window.py', HERE / 'snapshot_lifecycle.py')}
        record['hashes'] = {str(path.relative_to(parent)): sha(path) for path in parent.rglob('*') if path.is_file()}
        vc.write_json(parent / 'scenario.json', record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label'); parser.add_argument('--master-port', type=int, default=PORT)
    parser.add_argument('--padding', type=int, choices=(0, 1), default=1)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    record = scenario(args.label, args.master_port, args.padding, args.apply)
    print(json.dumps(record, indent=2)); return 0 if record['ok'] else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except (ValueError, OSError) as error:
        sys.stderr.write('Vision replay refused: %s\n' % error); sys.exit(2)
