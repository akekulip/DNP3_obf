"""Explicit physical relay binding; software fixture remains the legacy default."""
import re
import hashlib
import json
from pathlib import Path
MASTER_IP, RELAY_IP, RELAY_PORT = '192.168.10.1', '192.168.10.7', 20000
COMMAND = dict(master='active_harness', points=[1, 3], code=1, count=1, on_ms=200, off_ms=0)


def is_relay(cfg):
    return cfg.get('endpoint_profile') == 'sel751'


def validate(cfg):
    profile = cfg.get('endpoint_profile', 'software')
    if profile not in ('software', 'sel751'):
        raise ValueError('unsupported endpoint_profile: %r' % profile)
    if profile == 'software':
        return
    wanted = dict(master_ip=MASTER_IP, outstation_ip=RELAY_IP, outstation_port=RELAY_PORT,
                  read_src=1, read_dst=0)
    if any(type(cfg.get('endpoints', {}).get(k)) is not type(v) or cfg.get('endpoints', {}).get(k) != v
           for k, v in wanted.items()):
        raise ValueError('sel751 requires master .1/address1 -> relay .7:20000/address0')
    if any(cfg.get('ports_map', {}).get(k) != v for k, v in dict(master_dev=9, relay_dev=64).items()):
        raise ValueError('sel751 requires master dev9 and relay dev64')
    if any(type(cfg.get('endpoint', {}).get(k)) is not type(v) or cfg.get('endpoint', {}).get(k) != v
           for k, v in COMMAND.items()):
        raise ValueError('sel751 requires active_harness guarded {1,3}, code1/count1/on200/off0')
    if any(k in cfg.get('endpoint', {}) for k in ('binary', 'binary_sha256', 'lib_sha256', 'opendnp3_commit')):
        raise ValueError('sel751 may not declare a software outstation binary/library')


def validate_baseline(cfg):
    validate(cfg)
    if not is_relay(cfg) or cfg.get('purpose') != 'relay-native-baseline' or cfg.get('builds') != {} or cfg.get('arms') != []:
        raise ValueError('production baseline requires sel751, no candidate builds/arms, relay-native-baseline purpose')
    prod = cfg.get('production') or {}
    if prod.get('program') != 'case4_response_path' or not prod.get('relay_slot'):
        raise ValueError('native baseline requires case4_response_path production with relay restoration')
    for key in ('launch_sha256', 'conf_sha256'):
        if not isinstance(prod.get(key), str) or not re.fullmatch('[a-f0-9]{64}', prod[key]):
            raise ValueError('production baseline requires ' + key)
    if not prod.get('launch_script', '').startswith('/') or not prod.get('conf', '').startswith('/'):
        raise ValueError('production baseline requires absolute launch/conf identities')
    artifacts = prod.get('artifact_sha256')
    if not isinstance(artifacts, dict) or not artifacts or any(not path.startswith('/') or
            not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest)
            for path, digest in artifacts.items()):
        raise ValueError('production baseline requires loaded artifact identities')


def native_observation_files(cfg):
    """Local source closure for the fresh physical packet profile, required before candidate loading."""
    wire = cfg.get('wire_profile') or {}
    if wire.get('tcp_profile') != 'sel751_ts' or wire.get('ipv4_header_octets') != 20 or wire.get('tcp_header_octets') != 32:
        raise ValueError('physical candidate requires the observed IPv4/TCP timestamp profile')
    path = Path(wire.get('native_observation', ''))
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != wire.get('native_observation_sha256'):
        raise ValueError('fresh native observation identity missing or changed')
    report = json.loads(path.read_text())
    validate_tcp_observation(report)
    artifacts = report.get('artifacts') or {}
    if report.get('ok') is not True or set(artifacts) != {'out.pcap', 'in.pcap', 'master.json', 'result.json'}:
        raise ValueError('fresh native observation failed or has incomplete raw artifact identities')
    files = [path]
    for name, digest in artifacts.items():
        raw = path.parent / name
        if not raw.is_file() or hashlib.sha256(raw.read_bytes()).hexdigest() != digest:
            raise ValueError('fresh native observation raw artifact changed: ' + name)
        files.append(raw)
    return files


def validate_tcp_observation(report):
    """The fixed sel751_ts parser contract, including negotiated window units."""
    if not isinstance(report, dict) or not isinstance(report.get('packets'), dict):
        raise ValueError('physical TCP observation is missing')
    outgoing, incoming = report['packets'].get('out') or [], report['packets'].get('in') or []
    syns = [p for p in outgoing if p.get('flags') == 2]
    synacks = [p for p in incoming if p.get('flags') == 18]
    if not syns or not synacks:
        raise ValueError('physical TCP profile requires captured SYN and SYNACK')
    client_timestamps = set()
    for packet in syns:
        options = bytes.fromhex(packet.get('tcp_options_hex', ''))
        if packet.get('tcp_header_bytes') != 40 or packet.get('ipv4_header_bytes') != 20 or len(options) != 20 or \
                options[:8] != bytes.fromhex('020405b40402080a') or options[12:16] != bytes(4) or \
                options[16:] != bytes.fromhex('01030307'):
            raise ValueError('unsupported master SYN layout/MSS1460/window-scale7')
        client_timestamps.add(options[8:12])
    for packet in synacks:
        options = bytes.fromhex(packet.get('tcp_options_hex', ''))
        if packet.get('tcp_header_bytes') != 44 or packet.get('ipv4_header_bytes') != 20 or len(options) != 24 or \
                options[:16] != bytes.fromhex('020405b401030300010104020101080a') or options[20:24] not in client_timestamps:
            raise ValueError('unsupported relay SYNACK layout/MSS1460/window-scale0/timestamp echo')
    data = [p for p in outgoing + incoming if p.get('payload_len')]
    if not data or any(p.get('tcp_header_bytes') != 32 or p.get('ipv4_header_bytes') != 20 or
                       not p.get('tcp_options_hex', '').startswith('0101080a') for p in data):
        raise ValueError('unsupported physical TCP data timestamp layout')
