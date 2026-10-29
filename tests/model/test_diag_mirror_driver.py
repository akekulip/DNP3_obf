"""c72_diag_mirror model-driver helpers: log parsing, probe frames, copy matching and the on/off comparison."""
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / 'scripts/model'


def load(name, path):
    sys.path[:0] = [str(MODEL), str(MODEL.parent / 'checks'), str(MODEL.parent / 'hardware')]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def driver():
    return load('diag_driver', MODEL / 'model_diag_mirror.py')


@pytest.fixture(scope='module')
def companion():
    return load('diag_companion', MODEL / 'model_diag_mirror_companion.py')


@pytest.fixture(scope='module')
def runner():
    return load('diag_runner', MODEL / 'run_diag_mirror.py')


LOG = """\
:10-28 15:03:31.6:    :0x1:-:<0,0,0>:========== Ingress Pkt from port 64 (102 bytes)  ==========
:10-28 15:03:31.6:    :0x1:-:<0,0,->:---- Mirroring session 101 : ingress  ----
:10-28 15:03:31.7:    :-:0x2:<0,0,0>:========== Packet to egress parser: to port 10 (102 bytes)  ==========
:10-28 15:03:31.7:    :-:0x2:<0,0,0>:========== Tx Pkt to port 10 (102 bytes) ==========
:10-28 15:03:31.7:    :-:0x2:<0,0,->:---- Mirroring session 0 : egress  ----
:10-28 15:03:31.7:        :-:0x2:<0,0,->:Mirroring session 0 is not enabled
:10-28 15:03:31.8:    :-:0x3:<0,0,0>:========== Tx Pkt to port 68 recirculated ==========
:10-28 15:03:31.8:    :-:0x4:<0,0,0>:========== Tx Pkt to port 68 (Bypass Egress) (94 bytes) ==========
:10-28 15:03:31.9:    :-:0x5:<0,0,0>:========== Packet to egress parser: to port 64 (90 bytes)  ==========
:10-28 15:03:31.9:        :-:0x5:<0,0,9>:Execute Action: r_Egress.drop_lifetime
"""


def test_log_counts(driver):
    c = driver.log_counts(LOG)
    assert c['ingress_from'] == {'64': 1} and c['tx_to'] == {'10': 1}
    assert c['recirculated'] == {'68': 1} and c['bypass_egress_tx'] == {'68': 1}
    assert c['egress_parser_to'] == {'10': 1, '64': 1}
    assert c['mirror_requests'] == {'101:ingress': 1, '0:egress': 1} and c['mirror_not_enabled'] == {'0': 1}


def test_egress_drops_are_attributed_to_their_port(companion, tmp_path):
    path = tmp_path / 'model_x.log'
    path.write_text(LOG)
    assert companion.egress_drops_by_port(path) == {'r_Egress.drop_lifetime@64': 1}


def csum(data):
    data += b'\x00' * (len(data) % 2)
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def segment(options=b'\x01\x01\x08\x0a' + bytes(8)):
    payload = b'\x05\x64'
    tcp = struct.pack('!HHIIBBHHH', 20000, 1234, 7, 9, (5 + len(options) // 4) << 4, 0x18, 512, 0, 0) + options
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000, 64, 6, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack('!H', ~csum(ip) & 0xffff) + ip[12:]
    pseudo = ip[12:20] + b'\x00\x06' + struct.pack('!H', len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', ~csum(pseudo + tcp + payload) & 0xffff) + tcp[18:]
    return bytes(14) + ip + tcp + payload


def test_without_tcp_options_keeps_valid_checksums(driver):
    frame = driver.without_tcp_options(segment())
    ip, tcp = frame[14:34], frame[34:54]
    assert frame[46] >> 4 == 5 and len(frame) == 14 + 20 + 20 + 2
    assert csum(ip) == 0xffff
    assert csum(ip[12:20] + b'\x00\x06' + struct.pack('!H', 22) + tcp + frame[54:]) == 0xffff
    assert frame[54:] == b'\x05\x64'


def test_odd_ip_request_has_valid_header_checksum(driver):
    class V:
        @staticmethod
        def packet(flags, seq, ack):
            return segment()
    frame = driver.odd_ip_request(V, 1, 2)
    assert frame[14] == 0x46 and csum(frame[14:38]) == 0xffff


def test_match_copies(companion):
    a, b, c = bytes(range(70)), bytes(range(1, 71)), b'\x01' * 54
    unmatched, uncopied, kinds = companion.match_copies([a, b, c + bytes(6)], injected=[b, c], emitted=[a])
    assert (unmatched, uncopied) == ([], []) and kinds == dict(emitted_exact=1, injected_exact=1, injected_min_padding=1)
    unmatched, uncopied, _ = companion.match_copies([a, a], injected=[], emitted=[a])
    assert len(unmatched) == 1 and uncopied == []                 # a second copy of one frame is caught
    unmatched, uncopied, _ = companion.match_copies([], injected=[b], emitted=[])
    assert unmatched == [] and uncopied == [b.hex()]               # a missing copy is caught
    unmatched, _u, _k = companion.match_copies([a[:-1] + b'\xff'], injected=[], emitted=[a])
    assert len(unmatched) == 1                                     # one changed byte is caught


def run_rows(copy_frames, fwd='aa', tx_extra=None):
    log = dict(ingress_from={'9': 1}, recirculated={}, bypass_egress_tx={}, tx_to=dict({'64': 1}, **(tx_extra or {})),
               egress_parser_to=dict({'64': 1}, **(tx_extra or {})))
    step = dict(name='S', outputs={'9': [], '64': [fwd], '10': copy_frames}, log=log)
    return [step], dict(summary=dict(failed=[]), meta=dict(reflections={'48': dict(frames=3)},
                                                           reflections_before_steps={'48': 1}))


def test_compare_passes_and_fails(runner):
    good = dict(on=run_rows(['aa'], tx_extra={'10': 1}), off=run_rows([]), absent=run_rows([]))
    assert not any(runner.compare(good, 10, 64, 9).values())
    bad = dict(good, off=run_rows([], fwd='ab'))
    assert runner.compare(bad, 10, 64, 9)['forwarding_identical']
    leak = dict(good, absent=run_rows(['aa'], tx_extra={'10': 1}))
    assert runner.compare(leak, 10, 64, 9)['copies_only_when_on']
    extra = dict(good, on=run_rows(['aa'], tx_extra={'10': 1, '48': 1}))
    assert runner.compare(extra, 10, 64, 9)['extra_passes_only_copies']
