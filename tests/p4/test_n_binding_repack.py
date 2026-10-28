"""Current single-master policy proof and SELECT-bound DL/native-start state parity.

The previous binding stored (DNP links32, masterIP32) plus native_start32. The
current pair stores (DNP links32, native_start32). State parity below is conditional
on a SELECT-established binding; the full model gate checks pre-SELECT/abort paths.
"""
import importlib.util
import itertools
from functools import lru_cache
from pathlib import Path
import random
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'p4/response_only.p4').read_text()
N = SOURCE.split('control n_Ingress(')[1].split('control n_IgDeparser(')[0]
EDGES = (0, 1, 45, 49, 0x7fffffff, 0x80000000, 0xffffffd3, 0xffffffff)


@lru_cache(maxsize=64)
def block(text, pattern):
    match = re.search(pattern, text)
    assert match, pattern
    start = text.index('{', match.start())
    end, depth = start, 1
    while depth:
        end += 1
        depth += (text[end] == '{') - (text[end] == '}')
    return text[start + 1:end]


def table_rows(name):
    entries = block(block(N, r'\btable\s+' + name + r'\b'), r'\bconst\s+entries\s*=')
    entries = re.sub(r'\(bit<\d+>\)', '', entries)
    return [(tuple(part.strip() for part in key.split(',')), action)
            for key, action in re.findall(r'\(([^()]*)\)\s*:\s*(\w+)\([^()]*\);', entries)]


def number(token):
    if re.fullmatch(r'(?:\d+w)?(?:0x[0-9a-fA-F]+|\d+)', token):
        return int(token.split('w')[-1], 0)
    match = re.search(r'\b' + re.escape(token) + r'\s*=\s*(\d+w(?:0x[0-9a-fA-F]+|\d+))', SOURCE)
    assert match, token
    return number(match.group(1))


def lookup(rows, values):
    for key, action in rows:
        assert len(key) == len(values)
        for token, value in zip(key, values):
            if token == '_':
                continue
            parts = token.split('&&&')
            if len(parts) == 1:
                matches = value == number(parts[0].strip())
            else:
                expected, mask = (number(part.strip()) for part in parts)
                matches = value & mask == expected & mask
            if not matches:
                break
        else:
            return action
    return 'NoAction'


def policy(master_ip='192.168.10.1', relay_ip='192.168.10.7'):
    spec = importlib.util.spec_from_file_location('binding_repack_rows', ROOT / 'scripts/hardware/rows.py')
    rows = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rows)
    master, relay = rows.endpoints(master_ip, 54321, 9, relay_ip, 20000, 64)
    ports = {'n_ack_return': number('n_N_ACK_RETURN'), 'return_port': number('n_RETURN_PORT')}
    return rows.build(master, relay, rows.VECTOR_DECOY, ports), master, relay


def test_current_control_policy_is_one_reciprocal_endpoint_tuple():
    rows, master, relay = policy()
    data = [row for row in rows if row['table'] == 'p0.n_Ingress.data_connection']
    assert len(data) == 2
    key = lambda row: {name: value for name, value, mask in row['key'] if mask is None}
    request = {'hdr.ip.src': master.ip_int, 'hdr.ip.dst': relay.ip_int,
               'hdr.tcp.sport': master.port, 'hdr.tcp.dport': relay.port}
    response = {'hdr.ip.src': relay.ip_int, 'hdr.ip.dst': master.ip_int,
                'hdr.tcp.sport': relay.port, 'hdr.tcp.dport': master.port}
    assert sorted(tuple(sorted(key(row).items())) for row in data) == sorted((
        tuple(sorted(request.items())), tuple(sorted(response.items()))))
    assert all(row['action'] == 'n_Ingress.configure' for row in data)
    connections = [row for row in rows if row['table'] == 'p0.n_Ingress.connection']
    assert len(connections) == 4
    for row in connections:
        assert row['action'] in ('n_Ingress.forward_flow', 'n_Ingress.reverse_flow')
        four = {name: value for name, value, _ in row['key'] if name != 'ig.ingress_port'}
        assert four == (request if row['action'] == 'n_Ingress.forward_flow' else response)
    table = block(N, r'\btable\s+data_connection\b')
    assert 'default_action=NoAction()' in re.sub(r'\s+', '', table)
    assert set(re.findall(r'(hdr\.[\w.]+)\s*:\s*exact', table)) == set(request)


@pytest.mark.parametrize('master_ip,relay_ip', [
    ('192.168.10.2', '192.168.10.7'), ('192.168.10.1', '192.168.10.8'),
    ('192.168.10.61', '192.168.10.62'),
])
def test_current_installer_rejects_endpoint_policy_outside_the_fixed_pair(master_ip, relay_ip):
    with pytest.raises(ValueError, match='fixed reciprocal SEL-751 IP pair'):
        policy(master_ip, relay_ip)


def test_foreign_master_ip_cannot_qualify_control_object_actions():
    parser = SOURCE.split('parser n_IgParser(')[1].split('control n_Ingress(')[0]
    assert 'm.enabled=(bit<1>)(8w0);' in re.sub(r'\s+', '', parser)
    control_dispatch = block(N, r'if\(m.packet_kind==8w5\|\|m.packet_kind==8w6\|\|m.packet_kind==8w7\)')
    assert 'data_connection.apply();' in control_dispatch
    assert 'read_connection.apply();' not in control_dispatch
    rows, master, _ = policy()
    data = [row for row in rows if row['table'] == 'p0.n_Ingress.data_connection']
    for row in data:
        values = {name: value for name, value, _ in row['key']}
        foreign = values.copy()
        foreign['hdr.ip.src' if values['hdr.ip.src'] == master.ip_int else 'hdr.ip.dst'] ^= 1
        assert all(foreign != {name: value for name, value, _ in other['key']} for other in data)
    # Try otherwise-valid native and recirculated control shapes with no direction/data hit.
    guard = table_rows('guard')
    for stage, packet_kind, kind in itertools.product(range(4), (5, 6, 7), (0, 5, 6, 7, 8, 24, 25, 255)):
        inputs = (stage, packet_kind, kind, 0, 1, 0, 1, 0,
                  0x993a, 0x993a, 0x993a, 0x993a, 64, 0)
        action = lookup(guard, inputs)
        assert action in ('NoAction', 'go_ret_abort', 'go_ret_work')
        if action == 'go_ret_work':
            assert kind == 255  # Generic aborted return never matches an object action.
        effective_kind = 255 if action == 'go_ret_abort' else kind
        if action != 'NoAction':
            assert lookup(table_rows('real_links_t'), (stage, effective_kind, 4 if stage == 0 else 1, 0)) == 'NoAction'


def update(action, pair, links, native):
    body = block(block(N, r'\b' + action + r'\s*=\s*\{'), r'\bvoid\s+apply\(')
    values = {'compare_real_links': links, 'compare_native_start': native}
    result = list(pair)
    writes = re.findall(r'v\.(first|second)\s*=\s*m\.(\w+)\s*;', body)
    for lane, value in writes:
        result[lane == 'second'] = values[value]
    assert writes
    return tuple(result)


def test_select_and_operate_updates_preserve_binding_state_and_mismatch():
    table = table_rows('real_links_t')
    assert lookup(table, (1, 5, 1, 0)) == 'store_real_links'
    assert lookup(table, (1, 7, 1, 0)) == 'store_native_start'
    assert lookup(table, (1, 5, 1, 1)) == 'NoAction'
    read = block(block(N, r'\bread_real_links\s*=\s*\{'), r'\bvoid\s+apply\(')
    assert 'if(v.first!=m.compare_real_links||v.second!=m.compare_native_start)' in re.sub(r'\s+', '', read)
    assert 'r=8w1;' in read and 'r=8w0;' in read
    rng = random.Random(0x751)
    samples = list(itertools.product(EDGES, repeat=3))
    samples += [tuple(rng.getrandbits(32) for _ in range(3)) for _ in range(4096)]
    master_ip = 0xc0a80a01
    for links, selected_native, operated_native in samples:
        pair = update('write_real_links', (rng.getrandbits(32), rng.getrandbits(32)), links, selected_native)
        assert pair == (links, selected_native)
        pair = update('write_native_start', pair, links ^ 1, operated_native)
        assert pair == (links, operated_native)  # OPERATE must preserve SELECT's links.
        old_links, old_master, old_native = links, master_ip, operated_native
        for query_links, query_native in ((links, operated_native), (links ^ 1, operated_native),
                                          (links, operated_native ^ 1), (links ^ 1, operated_native ^ 1)):
            old_mismatch = old_links != query_links or old_master != master_ip or old_native != query_native
            new_mismatch = pair[0] != query_links or pair[1] != query_native
            assert new_mismatch == old_mismatch
            for kind in (6, 7):
                assert lookup(table, (0, kind, 4, 0)) == 'compare_real_links'


def test_binding_register_declarations_remove_exactly_32_persistent_bits():
    assert 'pair_real_links_real_tcp_src' not in N
    assert 'pair_real_off_native_start' not in N
    declaration = re.search(r'Register<\s*n_object_pair_t\s*,\s*bit<1>>\s*\(1,\{0,0\}\)\s+pair_real_links_native_start;', N)
    assert declaration
    cell = block(SOURCE, r'\bstruct\s+n_object_pair_t\b')
    current_bits = sum(int(width) for width in re.findall(r'bit<(\d+)>', cell))
    previous_bits = 64 + 32  # Independent previous DL/master pair plus native-start cell.
    assert current_bits == 64
    assert previous_bits - current_bits == 32
