"""Precompute deterministic segmented READ 377->401 model-injection vectors (run under the research Python).

The compiled-model driver (seg61_02/model_segmented.py) runs under the system Python 3.8 inside the model
namespace, which cannot import derive.py / general_read_padding.py (PEP 604 `int | None`). So the native samples
and their expected padded images are derived HERE, once, with the same functions derive.py proved byte-equal to
general_read_padding.pad_read, and written to segmented_vectors.json for the driver to read and inject.

Each sample is already re-addressed to the model connection's link addresses (response dst=master 0x0001,
src=outstation 0x0000, matching model_packets.read_frame; request the reverse), so N's link guard admits it.

  $RESEARCH_PYTHON make_segmented_vectors.py          # writes segmented_vectors.json; prints sha256
"""
import hashlib
import importlib.util
import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


derive = _load('_derive_for_vectors', HERE / 'derive.py')
gp = derive.gp
std = derive.std
SEG_C = json.loads((HERE / 'constants_segmented.json').read_text())['shapes']['segmented_integrity_377']

RESP_ADDR = bytes.fromhex('01000000')   # dst=master 0x0001, src=outstation 0x0000 (little-endian in the frame)
REQ_ADDR = bytes.fromhex('00000100')    # request direction (dst=outstation, src=master)
N_SAMPLES = 16
SEED = 0x5e6


def readdress(stream, addr4):
    out = []
    for f in gp.split_frames(stream):
        hdr, user = std.deframe(f)
        hdr = bytearray(hdr)
        hdr[4:8] = addr4
        out.append(std.frame(bytes(hdr), user))
    return b''.join(out)


def main():
    rng = random.Random(SEED)
    samples = []
    for _ in range(N_SAMPLES):
        req, native = derive.segmented_sample(rng)()
        req = readdress(req, REQ_ADDR)
        native = readdress(native, RESP_ADDR)
        expected = derive.construct(native, SEG_C)
        assert len(native) == SEG_C['native_total'] and len(expected) == SEG_C['target'], (len(native), len(expected))
        # cross-check against the reference padder, exactly as derive.py does
        pr = gp.pad_read(req, native, derive.TARGETS, pad_start=derive.PAD_START, pad_stop=derive.PAD_STOP)
        assert pr.output == expected, 'construct != pad_read for a generated sample'
        frames = [len(f) for f in gp.split_frames(native)]
        samples.append(dict(request=req.hex(), native=native.hex(), expected=expected.hex(), native_frames=frames))
    doc = dict(shape='segmented_integrity_377', seed=SEED, n=N_SAMPLES,
               native_total=SEG_C['native_total'], target=SEG_C['target'],
               prefix_frame_len=SEG_C['prefix_frame_len'], reserved_first_index=SEG_C['reserved_first_index'],
               padding_points=SEG_C['padding_points'], resp_addr=RESP_ADDR.hex(), req_addr=REQ_ADDR.hex(),
               samples=samples)
    text = json.dumps(doc, indent=1) + '\n'
    (HERE / 'segmented_vectors.json').write_text(text)
    print('segmented_vectors.json sha256', hashlib.sha256(text.encode()).hexdigest())
    print('samples', len(samples), 'native_total', doc['native_total'], 'target', doc['target'])


if __name__ == '__main__':
    main()
