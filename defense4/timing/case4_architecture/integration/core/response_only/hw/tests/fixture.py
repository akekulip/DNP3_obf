"""Pure-source fixture for the test_src_* suite: a synthetic build directory, made in a temporary directory, that
needs no compiled evidence tree and no SDE.

The installer reads three things from a build: the sha256 of bfrt.json and the two tofino.bin files (identity),
the port constants in out/response_only.p4pp (build_ports), and bfrt.json plus the SDE shared schemas (the
offline name check). This fixture provides the first two with placeholder binaries and a p4pp that holds only
the port constants, taken from pinned_build.json's port map so it mirrors the production layout. It does NOT
provide a real bfrt.json or schemas: tests that drive bringup_composite.main() replace the name check with
no_name_check(), and the name check itself is covered by test_build_validation.py against the real build.
"""
import contextlib
import hashlib
import json
import re  # noqa: F401  (re-exported for tests that rewrite the fixture p4pp)
import shutil  # noqa: F401
import sys
import tempfile
from pathlib import Path

HW = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HW))
import bringup_composite as bc  # noqa: E402
import build_ports  # noqa: E402

PIN = json.loads((Path(__file__).resolve().parent / 'pinned_build.json').read_text())
P = PIN['ports']

P4PP = '\n'.join([
    'const PortId_t n_RETURN_PORT=9w%d;' % P['return_port'],
    'const PortId_t n_N_ACK_RETURN=9w%d;' % P['n_ack_return'],
    'const PortId_t n_READ_HANDOFF_PORT=9w%d;' % P['n_handoff'],
    'const PortId_t t_PKTGEN_RETURN = 9w%d;' % P['pktgen_return'],
    'const PortId_t t_T_IN = 9w%d;' % P['t_in'],
    'const PortId_t t_HB_RETURN = 9w%d;' % P['hb_return'],
    'const PortId_t t_HELD_RETURN = 9w%d;' % P['held_return'],
    'const PortId_t t_FORWARD_PORT = 9w%d;' % P['forward'],
    'const PortId_t t_RELAY_PORT = 9w%d;' % P['relay'],
    'const PortId_t t_N_RETURN = 9w%d;' % P['t_n_return'],
    'const MirrorId_t t_CLONE_SESSION_ID = 10w%d;' % P['clone_session'],
    'state eth_dispatch { transition select(eg.egress_port) { 9w%d: eth; 9w%d: eth; default: accept; } }'
    % (P['forward'], P['n_ack_return']),
]) + '\n'

_TMP = tempfile.TemporaryDirectory(prefix='hw_fixture_')     # removed when the test process exits
BUILD = Path(_TMP.name)
# Deliberately NOT named `out`: the deploy layout is <aux>/out_<buildname>, and nothing in the installer may
# assume the compiled directory's name (the first campaign run hit exactly that in the mirror guard).
OUT = BUILD / 'out_fixture_build'
_out = OUT
(_out / 'p0').mkdir(parents=True)
(_out / 'p1').mkdir()
(_out / 'response_only.p4pp').write_text(P4PP)
for rel, body in (('bfrt.json', b'{"tables": []}\n'), ('p0/tofino.bin', b'fixture p0\n'), ('p1/tofino.bin', b'fixture p1\n')):
    (_out / rel).write_bytes(body)
# Minimal pipe-1 assembly in the layout check_mirror_select parses: a live-range listing, then the ingress
# deparser's mirror block. BFA_PASS: the non-clone entry's session container holds only that temporary, so it
# can never carry another field's value. BFA_FAIL: that container also holds md.cur_gen, the token_stale_01
# defect, so a non-clone pass could be mirrored to session cur_gen[9:0].
_BFA = """  live:
    W0:
    - { name : md.clone_ses, x }
    W1:
    - { name : $tmp1, x }%s
    B0:
    - { name : ig_intr_md_for_dprsr.mirror_type, x }
deparser ingress:
  mirror:
    select: B0(0..3)
    0:
      - W1  # ingress::$tmp1
    1:
      - W0  # ingress::md.clone_ses
"""
BFA_PASS = _BFA % ''
BFA_FAIL = _BFA % '\n    - { name : md.cur_gen, x }'
(_out / 'p1' / 'response_only.bfa').write_text(BFA_PASS)
SHA = {rel: hashlib.sha256((_out / rel).read_bytes()).hexdigest() for rel in bc.REQUIRED_EXPECT}
(BUILD / 'manifest.json').write_text(json.dumps({'artifact_sha256': SHA}) + '\n')
FIXED = str(BUILD / 'no_schemas')        # never read: the name check is replaced (see no_name_check)

PORTS, _errs = build_ports.read(_out)
assert not _errs, _errs
assert {k: PORTS[k] for k in P} == P, 'fixture p4pp does not reproduce the pinned port map'

ENDPOINTS = ['--master-port', '54321', '--master-dev', str(PORTS['forward']), '--relay-dev', str(PORTS['relay'])]
if PORTS['forward'] == PORTS['relay']:
    ENDPOINTS += ['--master-ip', '192.168.10.61', '--relay-ip', '192.168.10.62']


def args(*extra, sha=None):
    sha = sha or SHA
    base = ['--build-out', str(OUT), '--fixed-schema-dir', FIXED] + ENDPOINTS
    for rel in bc.REQUIRED_EXPECT:
        base += ['--expect', '%s=%s' % (rel, sha[rel])]
    return bc.parse(base + list(extra))


def plan(a):
    return bc.plan(a, PORTS)


@contextlib.contextmanager
def no_name_check():
    """The fixture has no real bfrt.json or SDE schemas, so bringup_composite.offline() is replaced for the
    duration. The name check is tested against the real build in test_build_validation.py."""
    saved = bc.offline
    bc.offline = lambda ops, a, ports: []
    try:
        yield
    finally:
        bc.offline = saved
