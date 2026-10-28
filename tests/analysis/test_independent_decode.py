"""Independent decode: tshark's DNP3 dissector against the repository codec on the same retained bytes."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import independent_decode as idec  # noqa: E402

CODEC = dict(function=129, iin=0x8000, app_seq=3, objects=[(1, 2, 0x01), (30, 1, 0x00)], indices=[1024, 0, 1],
             analog=[5, 60], crob_status=[], crob_index=[])
TSHARK = dict(function=129, iin=0x8000, app_seq=3, objects=[(1, 2, 0x01), (30, 1, 0x00)], indices=[1024, 0, 1],
              analog=[5, 60], crob_status=[], crob_index=[], expert=[])


def test_identical_views_have_no_differences():
    assert idec.differences(CODEC, TSHARK) == []


def test_each_field_disagreement_is_named():
    for field, value in (('function', 130), ('iin', 0x8100), ('app_seq', 4), ('objects', [(1, 2, 0x00)]),
                         ('indices', [1024, 0, 2]), ('analog', [5, 61]), ('crob_status', [1])):
        assert [d['field'] for d in idec.differences(CODEC, dict(TSHARK, **{field: value}))] == [field]


def test_codec_iin_bytes_are_normalised_to_iin1_iin2():
    assert idec.iin_word(0x0080) == 0x8000 and idec.iin_word(0x0280) == 0x8002


def test_tshark_row_is_parsed_into_the_shared_view():
    row = dict(func='129', iin='0x8000', seq='3', obj='0x0102|0x1e01', prefix='0|0', range='1|0',
               point_index='1024|0|1', index='', ana='5|60', ctrlstatus='', expert='')
    view = idec.tshark_view(row)
    assert view == dict(function=129, iin=0x8000, app_seq=3, objects=[(1, 2, 0x01), (30, 1, 0x00)],
                        indices=[1024, 0, 1], analog=[5, 60], crob_status=[], crob_index=[], expert=[])


def test_one_retained_connection_decodes_identically_in_both_parsers():
    trial = next((ROOT / 'results/hardware/blocks/rc01_hw_c72_eval_20261027_01_e01_d5_r01/physical_relay/combined'
                  ).glob('*_t0'))
    report = idec.compare_connection(trial)
    assert report['responses'] == 193 and report['matched'] == 193 and report['unmatched'] == []
    assert report['wrap_responses'] == 3 and report['matched_after_renumber'] == 3
    assert report['differences'] == [] and report['expert'] == {}


def test_wrap_control_renumbers_only_transport_sequences_and_keeps_valid_crcs():
    import json
    trial = next((ROOT / 'results/hardware/blocks/rc01_hw_c72_eval_20261027_01_e01_d5_r01/physical_relay/combined'
                  ).glob('*_t0'))
    wires = [bytes.fromhex(e['response']['wire_hex'])
             for e in json.loads((trial / 'relay_wire.json').read_text())['exchanges']]
    wrapped = [w for w in wires if idec.wraps(w)]
    assert len(wrapped) == 3
    for wire in wrapped:
        control = idec.renumber(wire)
        frames = idec.link_frames(control)
        assert [control[p + 10] & 0x3f for p, _ in frames] == list(range(len(frames)))
        assert [control[p + 10] & 0xc0 for p, _ in frames] == [wire[p + 10] & 0xc0 for p, _ in frames]
        for p, length in frames:
            frame, _ = idec.dnp3_codec.parse_frame(control[p:p + length], verify_crc=True)
            assert frame is not None
        assert len(control) == len(wire)
        allowed = set()
        for p, length in frames:                    # transport byte, then the first data block's two CRC octets
            block = min(16, length - 12)
            allowed |= {p + 10, p + 10 + block, p + 11 + block}
        assert {i for i, (a, b) in enumerate(zip(wire, control)) if a != b} <= allowed
