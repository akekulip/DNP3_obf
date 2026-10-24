"""Explicit physical relay binding; software fixture remains the legacy default."""
import re
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
