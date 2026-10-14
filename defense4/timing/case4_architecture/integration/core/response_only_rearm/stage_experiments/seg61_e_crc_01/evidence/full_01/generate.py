"""Generate the E control-tail CRC experiment from the qualified candidate61 source (f0baa724a audit, Gate 4).

Input: seg61_02/evidence/full_04/response_only.p4 (SHA256 1b2d62d1...65aa). N and T are preserved byte for byte;
only E changes, and only its control-tail CRC dependency (crc_probe.py proves the algebra):

  before  ctl_sequences_t (TH2, TH3) -> crc_ctl_tail2_t hash(TH2, on_lo, off) and crc_ctl_tail3_t hash(TH3, status)
  after   crc_ctl_base_t hash(0x00, on_lo, off) has no input from the sequence lookup; ctl_sequences_t returns
          TH2, TH3, delta[s] and CRC3[s] (both already in wire byte order); ctl_eligible emits
          cs2.crc = swap(base) ^ delta_le[s] and cs3.crc = crc3_le[s]

CRC3 is a constant only because ctl_profile admits status 0 alone (unchanged). The native-tail CRC check (in_ct),
the checksum update list, the transport-sequence table keys and every other E table are unchanged. The generator
asserts N/T identity, replace-back equality, and that every table entry's constants match crc_probe.py.
"""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'seg61_02/evidence/full_04/response_only.p4'
SOURCE_SHA256 = '1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa'

spec = importlib.util.spec_from_file_location('seg61_e_crc_combined', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)
spec = importlib.util.spec_from_file_location('seg61_e_crc_probe', HERE / 'crc_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def frozen():
    raw = SOURCE.read_bytes()
    assert digest(raw) == SOURCE_SHA256, 'qualified candidate61 input changed'
    return raw.decode()


def once(text, old, new):
    count = text.count(old)
    assert count == 1, ('anchor not found exactly once', count, old[:120])
    return text.replace(old, new, 1)


def le(value):
    """The 16-bit value whose big-endian field bytes are value's little-endian wire bytes."""
    return struct.unpack('>H', struct.pack('<H', value))[0]


def sequence_entries():
    zero7 = probe.crc(bytes(7))
    rows = []
    for s, (th2, th3) in sorted(probe.sequence_table().items()):
        delta = probe.crc(bytes([th2]) + bytes(6)) ^ zero7
        crc3 = probe.crc(bytes([th3, 0]))
        rows.append('        8w%d:ctl_sequences(8w%d,8w%d,16w0x%04x,16w0x%04x);' % (192 + s, th2, th3, le(delta), le(crc3)))
    return rows


def transform_e(e):
    old_rows = ['        8w%d:ctl_sequences(8w%d,8w%d);' % (192 + s, th2, th3)
                for s, (th2, th3) in sorted(probe.sequence_table().items())]
    e = once(e, '\n'.join(old_rows), '\n'.join(sequence_entries()))
    e = once(e, 'action ctl_sequences(bit<8> second, bit<8> third){hdr.cs2.tpctrl=second;hdr.cs3.tpctrl=third;}',
             'action ctl_sequences(bit<8> second, bit<8> third, bit<16> delta_le, bit<16> crc3_le)'
             '{hdr.cs2.tpctrl=second;hdr.cs3.tpctrl=third;m.ctdelta=delta_le;m.ctcrc3=crc3_le;}')
    e = once(e, """    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail2;
    action crc_ctl_tail2(){m.ctcrc2=hash_ctl_tail2.get({hdr.cs2.tpctrl,hdr.ctn.on_lo,hdr.ctn.off});}
    table crc_ctl_tail2_t{actions={crc_ctl_tail2;}size=1;const default_action=crc_ctl_tail2();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail3;
    action crc_ctl_tail3(){m.ctcrc3=hash_ctl_tail3.get({hdr.cs3.tpctrl,hdr.ctn.status});}
    table crc_ctl_tail3_t{actions={crc_ctl_tail3;}size=1;const default_action=crc_ctl_tail3();}""",
             """    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_base;
    action crc_ctl_base(){m.ctcrc2=hash_ctl_base.get({8w0,hdr.ctn.on_lo,hdr.ctn.off});}
    table crc_ctl_base_t{actions={crc_ctl_base;}size=1;const default_action=crc_ctl_base();}""")
    e = once(e, 'hdr.cs2.crc=m.ctcrc2[7:0]++m.ctcrc2[15:8];', 'hdr.cs2.crc=(m.ctcrc2[7:0]++m.ctcrc2[15:8])^m.ctdelta;')
    e = once(e, 'hdr.cs3.crc=m.ctcrc3[7:0]++m.ctcrc3[15:8];', 'hdr.cs3.crc=m.ctcrc3;')
    e = once(e, 'ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); crc_ctl_tail3_t.apply();',
             'crc_ctl_base_t.apply(); ctl_sequences_t.apply();')
    e = once(e, 'bit<16> ctcrc2; bit<16> ctcrc3;', 'bit<16> ctcrc2; bit<16> ctcrc3; bit<16> ctdelta;')
    return e


def full_source():
    base = frozen()
    old_e = combined.segment(base, 'E')
    new_e = transform_e(old_e)
    text = base.replace(old_e, new_e, 1)
    assert combined.segment(text, 'N') == combined.segment(base, 'N')
    assert combined.segment(text, 'T') == combined.segment(base, 'T')
    assert text.replace(new_e, old_e, 1) == base
    for gone in ('hash_ctl_tail2', 'hash_ctl_tail3', 'crc_ctl_tail2_t', 'crc_ctl_tail3_t'):
        assert gone not in text, gone
    return text


def write(directory):
    directory = Path(directory)
    text = full_source()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    (directory / 'generate.py').write_bytes(Path(__file__).read_bytes())
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='seg61_e_crc_01',
                    source_sha256=digest(text.encode()),
                    candidate61_source={'path': str(SOURCE), 'sha256': SOURCE_SHA256},
                    generator_sha256=digest(Path(__file__).read_bytes()),
                    probe_sha256=digest((HERE / 'crc_probe.py').read_bytes()),
                    changed_role='E',
                    change='control-tail CRC: base hash before the sequence lookup; per-sequence delta and CRC3',
                    segment_sha256={name: digest(combined.segment(text, name).encode()) for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps({'source_sha256': metadata['source_sha256'], 'segments': metadata['segment_sha256']}, indent=1))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: generate.py OUT_DIR')
    write(sys.argv[1])
