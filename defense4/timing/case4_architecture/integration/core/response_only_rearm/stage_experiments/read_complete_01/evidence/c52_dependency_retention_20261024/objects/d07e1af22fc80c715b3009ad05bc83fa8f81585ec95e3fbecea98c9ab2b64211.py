#!/usr/bin/env python3
"""Independent source-fragment counterexamples; no parser/model/device execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
ARCH = ROOT.parents[1]
SNAPSHOT = ROOT / 'source_01'
sys.path.insert(0, str(ARCH / 'protocol'))
sys.path.insert(0, str(ARCH.parent / 'framework/size'))
sys.path.insert(0, str(ARCH.parent / 'framework/control'))
from source_eval import Source, block


def checksum(data):
    data += b'\0' if len(data) % 2 else b''
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(flags, seq, ack, reverse=False, mss=None):
    src, dst, sport, dport = (0x0a000001, 0x0a000002, 30001, 20000)
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    option = b'' if mss is None else struct.pack('!BBH', 2, 4, mss)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, ((20 + len(option)) // 4) << 4,
                      flags, 4096, 0, 0) + option
    pseudo = struct.pack('!IIBBH', src, dst, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def normalized(text):
    text = re.sub(r'\br\b', 'rv', text)
    text = text.replace('RETURN_PORT', '9w68').replace(',_):', ',8w0&&&8w0):')
    return re.sub(r'(8w\d+):(\w+\(\);)', r'(\1):\2', text)


def forwarding_counterexamples():
    source_path = SNAPSHOT / 'integration/connection/binding/native_binding.p4'
    original = source_path.read_text()
    text = normalized(original)
    parser = load('review_connection_reference', SNAPSHOT / 'integration/connection/reference.py')
    # These are complete valid bytes accepted by the isolated supported network
    # shape. Source-fragment evaluation starts after real port/flow admission;
    # it deliberately does not assert that the entire target parser has run.
    rows = (
        ('lost_SYN_native_retry', 1, 2, 100, 0, False, 1500, 0x20001),
        ('lost_SYNACK_native_retry', 2, 18, 900, 101, True, 1500, 0x40001),
        ('lost_final_ACK_native_retry', 3, 16, 101, 901, False, None, 0x50001),
        ('established_client_ACK', 3, 16, 136, 958, False, None, 0x90001),
    )
    results = []
    for label, kind, flags, seq, ack, reverse, mss, owner in rows:
        raw = frame(flags, seq, ack, reverse, mss)
        packet = parser.parse_packet(raw)
        assert (packet.flags, packet.seq, packet.ack) == (flags, seq, ack)
        s = Source(text, {'m.kind': kind, 'm.sequence_valid': 1, 'm.matched': 0,
                        'm.observed': owner, 'm.generation': 29, 'm.epoch': 17})
        s.table('snapshot_t')
        s.table('first_event')
        emitted = s.env['hdr.event.event']
        assert emitted == 0x1ff, (label, emitted)
        # Follow the exact terminal branch with the abort kind the program
        # itself emitted. ExpectedWorkRecord still retains genuine returns;
        # the problem is the resulting original-packet outcome.
        s.env.update({'m.work_phase': 3, 'm.kind': emitted & 255})
        terminal = block(text, 'else if(m.work_phase==32w3)')
        s.run(terminal)
        assert s.env['md.drop_ctl'] == 1
        assert all(not s.valid[name] for name in ('envelope', 'work_generation', 'expected_cell', 'event'))
        results.append({'case': label, 'original_hex': raw.hex(), 'network_checksum_valid': True,
                        'owner_before': owner, 'source_emitted_event': emitted,
                        'actual_terminal_drop_ctl': s.env['md.drop_ctl'],
                        'source_fragment_only': True})
    return results


def rollback_counterexample():
    # Replay the frozen controller source. Its schema types come from the
    # existing local framework; this pure function never calls the SDK builder.
    path = SNAPSHOT / 'integration/controller/preparation.py'
    api = load('review_preparation', path)
    with tempfile.TemporaryDirectory() as directory:
        schema = Path(directory) / 'bfrt.json'
        schema.write_text(json.dumps({'tables': [
            {'name': 'pipe.Ingress.' + name, 'key': [], 'action_specs': [
                {'name': 'Ingress.set_' + name, 'data': [
                    {'name': 'value', 'type': {'type': 'uint32', 'width': 32}}]}]}
            for name in ('holding', 'pgen', 'owner')]}))
        def op(table, value, phase, role):
            return {'table': 'pipe.Ingress.' + table, 'fields': {'action_name': 'Ingress.set_' + table, 'value': value},
                    'key': None, 'kind': 'default', 'phase': phase, 'role': role,
                    'lifetime': 'configuration'}
        # Both supplied inventory and snapshot relabel the actual timing owner.
        # The schema checks byte widths, not authoritative semantic lifetimes.
        inventory = [op('holding', 0, 'disable', 'holding_gate'),
                     op('pgen', 0, 'disable', 'packet_generator'),
                     op('owner', 0, 'configure', 'timing_owner'),
                     op('holding', 1, 'enable', 'holding_gate'),
                     op('pgen', 1, 'enable', 'packet_generator')]
        identity = {'source_sha256': 'a' * 64, 'binary_sha256': 'b' * 64,
                    'manifest_sha256': 'c' * 64, 'schema_sha256': hashlib.sha256(schema.read_bytes()).hexdigest(),
                    'inventory_sha256': api.digest(inventory)}
        entries = [dict(inventory[n], fields=dict(inventory[n]['fields'], value=value))
                   for n, value in ((0, 0), (1, 0), (2, 0x80000001))]
        result = api.configuration_rollback({'identity': identity, 'entries': entries}, schema,
                                            expected_identity=identity, inventory=inventory)
        owner_writes = [row for row in result['actions'] if row['table'] == 'pipe.Ingress.owner']
        assert len(owner_writes) == 1 and owner_writes[0]['fields']['value'] == 0x80000001
        assert result['runtime_state_restored'] is False
        return {'mock_schema_only': True, 'owner_restore_value': owner_writes[0]['fields']['value'],
                'reported_runtime_state_restored': result['runtime_state_restored'],
                'qualification_registry_consulted': False, 'hardware_contact': False}


def main():
    report = {'source_inventory': json.loads((SNAPSHOT / 'inventory.json').read_text()),
              'forwarding': forwarding_counterexamples(), 'rollback': rollback_counterexample(),
              'target_model_run': False, 'hardware_contact': False}
    (ROOT / 'counterexamples.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
