"""Shared fixture for the per-class READ tests: real bytes from the READ-class schedule loopback captures
(fixtures/read_class_vectors.json, made by fixtures/make_read_class_vectors.py from the reference encoder) and a
synthetic two-capture run builder (out.pcap = what the endpoints sent, in.pcap = what the master received).

Every request and native response octet comes from the loopback capture; only the TCP/IP framing is synthetic
(pcaptk), on the Vision addresses the analyzers expect."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcaptk as tk  # noqa: E402

VECTORS = HERE / 'fixtures' / 'read_class_vectors.json'
M, O, MP, OP = '192.168.10.61', '192.168.10.62', 59460, 20000
ORDER = ('range', 'analog', 'class0', 'integrity')
NATIVE = {'base': {'range': 49, 'analog': 141, 'class0': 247, 'integrity': 247},
          'large': {'range': 49, 'analog': 141, 'class0': 377, 'integrity': 377}}
IMAGES = {'range': 141, 'analog': 141, 'class0': 247, 'integrity': 247}
IMAGES_BY_DB = {'large': {'class0': 401, 'integrity': 401}}


def vectors(db=None):
    rows = json.loads(VECTORS.read_text())['vectors']
    return [r for r in rows if db is None or r['db'] == db]


def by_class(db):
    out = {}
    for r in vectors(db):
        out.setdefault(r['class'], []).append(r)
    return out


def link_frames(data):
    out, p = [], 0
    while p < len(data):
        user = data[p + 2] - 5
        n = 10 + user + 2 * (-(-user // 16))
        out.append(data[p:p + n])
        p += n
    return out


def schedule(db, reads=8):
    """[(slot, class, vector)] in the endpoint's fixed order (at most three exchanges of a class per database)."""
    rows = by_class(db)
    return [(k, ORDER[k % 4], rows[ORDER[k % 4]][k // 4]) for k in range(reads)]


def expected_segments(vector):
    """The packet-level policy image: unchanged native segments when the class is at its target; otherwise the
    prefix frame travels with the native first frame and every later native frame keeps its own segment."""
    if vector['expected'] == vector['native']:
        return [bytes.fromhex(s) for s in vector['native_segments']]
    frames = link_frames(bytes.fromhex(vector['expected']))
    return [frames[0] + frames[1]] + frames[2:]


def config(db='base', padding=1, images=None, images_by_db=None, schedule_name='rotate4', reads=8, sbo=False,
           build_extra=None):
    build = {'profile': 'candidate61', 'image_len': 61,
             'read_images': dict(IMAGES if images is None else images),
             'read_images_by_db': json.loads(json.dumps(IMAGES_BY_DB if images_by_db is None else images_by_db))}
    build.update(build_extra or {})
    traffic = {'run_sbo': bool(sbo), 'db': db}
    if schedule_name:
        traffic['read_schedule'] = schedule_name
    if sbo:
        traffic['sbo_cycles'] = reads - 1
    cfg = {'builds': {'b': build}, 'traffic': traffic,
           'arms': [{'name': 'size_only', 'build': 'b', 'padding': padding, 'T': 0}]}
    return cfg, cfg['arms'][0], {'reads': reads, 'label': 't0'}


def build_run(tmp, db, transform=None, reads=8):
    """Write out.pcap/in.pcap for `reads` READs of the schedule. transform(slot, cls, vector) returns the in.pcap
    TCP payloads of that response (default: expected_segments). Returns the schedule."""
    sched = schedule(db, reads)
    transform = transform or (lambda k, c, v: expected_segments(v))
    for side in ('out', 'in'):
        c0, s0 = 1000, 5000
        recs = [(0, tk.frame(M, O, MP, OP, c0, 0, tk.SYN)),
                (50, tk.frame(O, M, OP, MP, s0, c0 + 1, tk.SYN | tk.ACK)),
                (90, tk.frame(M, O, MP, OP, c0 + 1, s0 + 1, tk.ACK))]
        sseq, rseq, t = c0 + 1, s0 + 1, 100
        for k, cls, v in sched:
            q = bytes.fromhex(v['request'])
            recs.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            sseq += len(q)
            recs.append((t + 20, tk.frame(O, M, OP, MP, rseq, sseq, tk.ACK)))      # the separate ACK
            segs = [bytes.fromhex(s) for s in v['native_segments']] if side == 'out' else transform(k, cls, v)
            for n, payload in enumerate(segs):
                recs.append((t + 200 + n, tk.frame(O, M, OP, MP, rseq, sseq, tk.PSH | tk.ACK, payload)))
                rseq += len(payload)
            t += 1000
        tk.write_pcap(str(Path(tmp) / ('%s.pcap' % side)), recs)
    return sched


def read_classes_expectation(db, padded=True):
    """The per-class mapping the checkers receive (what read_classes.expectations returns under 'classes')."""
    images = dict(IMAGES, **IMAGES_BY_DB.get(db, {}))
    out = {}
    for cls in ORDER:
        native = NATIVE[db][cls]
        segs = [len(bytes.fromhex(s)) for s in by_class(db)[cls][0]['native_segments']]
        out[cls] = {'native': native, 'image': images[cls] if padded else native, 'native_segments': segs}
    return out
