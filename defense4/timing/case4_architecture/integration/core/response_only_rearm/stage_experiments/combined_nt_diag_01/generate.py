"""Attribute raw timers while retaining the immutable combined N/E/T behavior."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parents[1]
SOURCE = HERE.parent / 'combined_nt_01/evidence/full_01/response_only.p4'
SOURCE_SHA256 = 'cad16b85f79d0609ad07e547a9551def720fdfa668c14000b7503a570cae7357'
spec = importlib.util.spec_from_file_location('diag_combined_generator', HERE.parent / 'combined_nt_01/generate.py')
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)


def frozen():
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'combined input changed'
    return raw.decode()


def edits(prefix='t_'):
    stale = prefix + 'OUT_TOKEN_STALE'
    old_verdict = '''    table token_verdict {
        key = { md.e_bad : ternary; hdr.timer.app_id : ternary; hdr.timer.packet_id : ternary; md.op_tok_diff : ternary;
                md.rd_tok_diff : ternary; hdr.timer.batch_id : ternary; }
        actions = { seed_op_blocker; seed_ack_blocker; seed_resp_blocker; drop_timer_stale; }
        const entries = {
            (_, _, _, _, _, 16w0xffff) : drop_timer_stale();
            (0, 1, _, 0, _, _) : seed_op_blocker();
            (0, 1, _, _, _, _) : drop_timer_stale();
            (0, _, 16w0 &&& 16w1, _, 0, _) : seed_ack_blocker();
            (0, _, 16w0 &&& 16w1, _, _, _) : drop_timer_stale();
            (0, _, _, _, 0, _) : seed_resp_blocker();
        }
        default_action = drop_timer_stale(); size = 6;
    }'''
    new_verdict = '''    table token_verdict {
        key = { md.e_bad : ternary; hdr.timer.app_id : ternary; hdr.timer.packet_id : ternary; md.op_tok_diff : ternary;
                md.rd_tok_diff : ternary; hdr.timer.batch_id : ternary; }
        actions = { seed_op_blocker; seed_ack_blocker; seed_resp_blocker; drop_timer_stale; }
        const entries = {
            (_, 1, _, _, _, 16w0xffff) : drop_timer_stale(5w23);
            (_, _, _, _, _, 16w0xffff) : drop_timer_stale(5w24);
            (0, 1, _, 0, _, _) : seed_op_blocker();
            (_, 1, _, _, _, _) : drop_timer_stale(5w23);
            (0, _, 16w0 &&& 16w1, _, 0, _) : seed_ack_blocker();
            (0, _, 16w0 &&& 16w1, _, _, _) : drop_timer_stale(5w24);
            (0, _, _, _, 0, _) : seed_resp_blocker();
        }
        default_action = drop_timer_stale(5w24); size = 7;
    }'''
    return [
        ('Register<bit<32>, bit<4>>(16, 0) outcomes;',
         'Register<bit<32>, bit<5>>(25, 0) outcomes;'),
        ('RegisterAction<bit<32>, bit<4>, bit<32>>(outcomes) bump_outcome',
         'RegisterAction<bit<32>, bit<5>, bit<32>>(outcomes) bump_outcome'),
        ('action bump(bit<4> idx)', 'action bump(bit<5> idx)'),
        ('13 : bump(13); 14 : bump(14); 15 : bump(15);',
         '13 : bump(13); 14 : bump(14); 15 : bump(15); 23 : bump(23); 24 : bump(24);'),
        ('default_action = NoAction(); size = 16;\n    }\n\n    // ---- request admission',
         'default_action = NoAction(); size = 25;\n    }\n\n    // ---- request admission'),
        ('action drop_timer_stale() { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; count(' + stale + '); }',
         'action drop_timer_stale(bit<5> index) { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; count((bit<32>)index); }'),
        (old_verdict, new_verdict),
    ]


def transform(text, prefix='t_'):
    original_text = text
    changes = edits(prefix)
    for old, new in changes:
        assert text.count(old) == 1, ('diagnostic anchor moved', old[:70])
        text = text.replace(old, new, 1)
    restored = text
    for old, new in reversed(changes):
        assert restored.count(new) == 1
        restored = restored.replace(new, old, 1)
    assert restored == original_text, 'diagnostic edits not exactly reversible'
    return text


def full_source():
    base = frozen()
    t = original.segment(base, 'T')
    changed = transform(t)
    source = base.replace(t, changed, 1)
    assert original.segment(source, 'N') == original.segment(base, 'N')
    assert original.segment(source, 'E') == original.segment(base, 'E')
    assert source.replace(changed, t, 1) == base
    return source


def source_role(name):
    frozen()  # Require the compiled input pin as well as the inherited inputs.
    source = original.source_role(name)
    return transform(source, prefix='') if name == 'T' else source


def write(directory):
    directory = Path(directory)
    text = full_source()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='combined_nt_diag_01', source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    t_lifetime_encoding='sealed_low31',
                    outcome_layout={'register_size': 25, 'blocker_stale': 6, 'raw_OP_stale': 23,
                                    'raw_READ_stale': 24, 'old_epoch': 14, 'generation_exhausted': 15,
                                    'legacy_stale_sum': [6, 23, 24], 'unused': list(range(16, 23))},
                    combined_source={'path': str(SOURCE), 'sha256': SOURCE_SHA256},
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    segment_sha256={name: hashlib.sha256(original.segment(text, name).encode()).hexdigest()
                                    for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1])
