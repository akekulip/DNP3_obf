"""Reference vectors for the hardware checkers' independent READ 49 -> 141 construction (Python >= 3.10).

Writes read141_vectors.json: 64 natives of the one hardware READ shape, G10V2 q0x00 0..22 (derive.range_sample,
its own seed; transport/app sequence, IIN, link addresses and point flags vary) and, for each, the
reference encoder's output, general_read_padding.pad_read under the frozen policy. The Python-3.8 harness tests
(protocol/hw_vepa/tests/test_read_policy_checkers.py) compare profile_check's own construction against them.

  python3 make_read141_vectors.py
"""
import json
import pathlib
import random

import derive

HERE = pathlib.Path(__file__).resolve().parent


def main():
    sample = derive.range_sample(random.Random(20261021))
    rows = []
    for _ in range(64):
        req, native = sample()
        r = derive.gp.pad_read(req, native, derive.TARGETS, pad_start=derive.PAD_START, pad_stop=derive.PAD_STOP)
        assert r.status == 'padded' and len(r.output) == 141, (r.status, len(r.output))
        rows.append(dict(native=native.hex(), expected=r.output.hex()))
    out = dict(policy_targets=derive.TARGETS, reserved_range=[derive.PAD_START, derive.PAD_STOP],
               encoder='general_read_padding.pad_read', vectors=rows)
    (HERE / 'read141_vectors.json').write_text(json.dumps(out, indent=1) + '\n')
    print('wrote %d vectors' % len(rows))


if __name__ == '__main__':
    main()
