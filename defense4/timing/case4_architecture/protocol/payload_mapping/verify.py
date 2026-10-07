"""Seal supporting byte checks; this executes source fragments, never a target."""
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[1]
sys.path[:0] = [str(ARCH), str(ARCH.parent / 'framework'), str(HERE / 'tests')]
from build import verify_evidence
from runner.evidence import reserve_run, sha256
from generate import generate
import test_mapping as checks


def profiles():
    native = checks.fixtures.ExactImages().native(4)
    padded = checks.codec.expand_control(native, checks.codec.Decoy(
        201, bytes.fromhex('0101640000006400000000')))[0]
    read = bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
    read_response = checks.codec.build_frame(bytes.fromhex('0564004401000000'),
        bytes.fromhex('c0c08180000a02000016') + bytes(range(23)))
    result = [('native35', native), ('padded55', padded),
              ('response57', checks.response()), ('READ20', read),
              ('READresponse49', read_response), ('pureACK', b''),
              ('nativeTail1', native[-1:])]
    assert [len(payload) for _, payload in result] == [35, 55, 57, 20, 49, 0, 1]
    return result


def exact_vectors():
    result = []
    def add(label, direction, payload, seq, ack, window, base, valid=3):
        source, output, prefix, accepted = checks.run(
            direction, payload, seq, ack, window, base, valid)
        mapped_seq = checks.forward(seq, base, valid) if direction == 1 else seq
        mapped_ack = checks.inverse(ack, base, valid) if direction == 2 else ack
        mapped_window = ((checks.inverse((ack + window) & checks.MASK, base, valid)
                          - mapped_ack) & checks.MASK) if direction == 2 else window
        expected = prefix + checks.packet(payload, mapped_seq, mapped_ack, mapped_window)
        item = {'case': label, 'direction': direction, 'base': base, 'valid': valid,
                'payload_bytes': len(payload), 'input_packet':
                (prefix + checks.packet(payload, seq, ack, window)).hex(),
                'actual_packet': output.hex(), 'independent_expected_packet': expected.hex(),
                'parser_accepted': accepted, 'drop_ctl': source.env.get('md.drop_ctl', 0),
                'changed': source.env.get('m.changed', 0),
                'matches': output == expected and accepted and
                source.env.get('md.drop_ctl', 0) == 0}
        result.append(item)

    for base in (1000, 0xfffffff0):
        for direction in (1, 2):
            for name, payload in profiles():
                add(name, direction, payload, (base + 35) & checks.MASK,
                    (base + 110) & checks.MASK, 20, base)
        for position in (-1, 0, 34, 35, 36, 54, 55, 69, 89, 90, 91, 109, 110, 130):
            for window in (0, 1, 20, 65535):
                add('inverseACK%d_window%d' % (position, window), 2, bytes(range(57)),
                    700, (base + position) & checks.MASK, window, base)
        for valid in (0, 1, 3):
            for position in (-1, 0, 34, 35, 36, 69, 70, 71, 130):
                add('forwardSEQ%d' % position, 1, b'unchanged',
                    (base + position) & checks.MASK, 700, 20, base, valid)
            add('inverseValid%d' % valid, 2, b'unchanged', 700,
                (base + 54) & checks.MASK, 20, base, valid)
    for direction in (1, 2):
        seq, ack = (1035, 700) if direction == 1 else (700, 1110)
        new_seq, new_ack = (1055, 700) if direction == 1 else (700, 1070)
        for zero_after in (False, True):
            basis = checks.packet(b'\0\0', new_seq if zero_after else seq,
                                  new_ack if zero_after else ack)
            add('checksumZeroAfter' if zero_after else 'checksumZeroBefore',
                direction, basis[50:52], seq, ack, 20, 1000)
    return result


def verify(destination):
    with reserve_run(destination, {'scope': 'source parser/control/deparser fragments; '
                     'independent Scapy packet serialization; no model or physical traffic',
                     'full_target': False}) as run:
        inputs = list(HERE.glob('*.py')) + list((HERE / 'tests').glob('*.py'))
        inputs += [HERE / 'forward.p4', HERE / 'reverse.p4',
            ARCH / 'build.py', ARCH / 'tests/source_control.py',
            ARCH / 'protocol/source_eval.py', ARCH / 'protocol/egress/source_packets.py',
            ARCH / 'protocol/mapping_forward.p4', ARCH / 'protocol/mapping_reverse.p4',
            ARCH / 'protocol/tests/test_protocol.py', ARCH / 'protocol/tests/test_carving.py',
            ARCH / 'protocol/generate_padding.py', ARCH / 'protocol/generate_images.py',
            ARCH.parent / 'framework/size/case4_padding.py',
            ARCH.parent / 'framework/runner/evidence.py']
        identities = {}
        for path in inputs:
            relative = str(path.relative_to(ARCH.parent))
            identities[relative] = sha256(path)
            run.snapshot(path, relative)
        generated = all((HERE / (name + '.p4')).read_text() == generate(direction)
                        for direction, name in ((1, 'forward'), (2, 'reverse')))
        tests = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s',
                               str(HERE / 'tests'), '-v'], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        run.write_bytes('tests.log', tests.stdout)
        vectors = exact_vectors()
        run.write_json('exact_vectors.json', vectors)
        compiled = {name: verify_evidence(HERE / 'evidence' / build)
                    for name, build in (('forward', 'forward_03'), ('reverse', 'reverse_12'))}
        result = {'tests': 9, 'tests_exit_code': tests.returncode,
                  'generated_matches': generated, 'source_sha256': identities,
                  'exact_vectors': len(vectors), 'all_vectors_match': all(v['matches'] for v in vectors),
                  'compiled_primitives': compiled, 'full_target': False}
        run.write_json('manifest.json', result)
        passed = tests.returncode == 0 and generated and result['all_vectors_match'] and all(
            value['compiled_artifacts_verified'] for value in compiled.values())
        run.finish('passed' if passed else 'failed', result)
        return result


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1])), indent=2))
