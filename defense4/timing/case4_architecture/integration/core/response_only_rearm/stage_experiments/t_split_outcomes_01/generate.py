"""Split T outcome accounting into per-verdict register banks.

This is an isolated stage experiment from the frozen combined NT diagnostic
source. It intentionally changes only T outcome bookkeeping: each terminal
verdict table writes a stage-local 25-slot bank, and the control plane sums the
same index across banks to recover the original 25 outcome meanings.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'combined_nt_diag_01/evidence/full_01/response_only.p4'
SOURCE_SHA256 = '13b21e3c34072b9a113acaf5bda5a1210d9a70cbe787d30fb722ad3c3dcbf5bd'
BANKS = ('tin', 'token', 'held', 'hb')
OUTCOME_COUNT = 25

COUNTER_MEANINGS = {
    0: 't_OUT_UNMATCHED',
    1: 't_OUT_HELD_REWAIT',
    2: 't_OUT_ACK_COMMIT',
    3: 't_OUT_RESP_RELEASE',
    4: 't_OUT_RESP_DUP_DROP',
    5: 't_OUT_OP_RELEASE',
    6: 't_OUT_TOKEN_STALE',
    7: 't_OUT_HELD_STALE_FLUSH',
    8: 't_OUT_ACK_FALLBACK',
    9: 't_OUT_RESP_FALLBACK',
    10: 't_OUT_TOKEN_TMO',
    11: 't_OUT_HELD_OFF_FLUSH',
    12: 't_OUT_TOKEN_OFF',
    13: 't_OUT_REQ_BYPASS',
    14: 't_OUT_OLD_EPOCH_DROP',
    15: 't_OUT_GEN_EXHAUSTED',
    16: 'unused',
    17: 'unused',
    18: 'unused',
    19: 'unused',
    20: 'unused',
    21: 'unused',
    22: 'unused',
    23: 't_OUT_RAW_OP_STALE',
    24: 't_OUT_RAW_READ_STALE',
}

ACTION_BANK = {
    'bypass_request': 'tin',
    'drop_duplicate_response': 'tin',
    'tin_drop_old_epoch': 'tin',
    'tin_drop_exhausted': 'tin',
    'tin_unmatched': 'tin',
    'drop_timer_stale': 'token',
    'held_stop_blocking_stale': 'held',
    'held_stop_blocking_tmo': 'held',
    'held_stop_blocking_off': 'held',
    'rewait_ack': 'held',
    'flush_ack_stale': 'held',
    'flush_ack_off': 'held',
    'rewait_response': 'held',
    'flush_response_stale': 'held',
    'flush_response_off': 'held',
    'release_ack_commit': 'held',
    'release_ack_fallback': 'held',
    'release_response_counted': 'held',
    'release_response_fallback': 'held',
    'held_drop_old_epoch': 'held',
    'held_unmatched': 'held',
    'hb_stop_blocking_stale': 'hb',
    'hb_stop_blocking_tmo': 'hb',
    'hb_stop_blocking_off': 'hb',
    'rewait_operate': 'hb',
    'flush_operate_stale': 'hb',
    'flush_operate_off': 'hb',
    'release_operate_counted': 'hb',
    'hb_drop_old_epoch': 'hb',
    'hb_unmatched': 'hb',
}

TABLE_ACTIONS = {
    'tin_verdict': {
        'bypass_request', 'drop_duplicate_response', 'tin_drop_old_epoch', 'tin_drop_exhausted', 'tin_unmatched',
    },
    'token_verdict': {'drop_timer_stale'},
    'held_verdict': {
        'held_stop_blocking_stale', 'held_stop_blocking_tmo', 'held_stop_blocking_off', 'rewait_ack',
        'flush_ack_stale', 'flush_ack_off', 'rewait_response', 'flush_response_stale', 'flush_response_off',
        'release_ack_commit', 'release_ack_fallback', 'release_response_counted', 'release_response_fallback',
        'held_drop_old_epoch', 'held_unmatched',
    },
    'hb_verdict': {
        'hb_stop_blocking_stale', 'hb_stop_blocking_tmo', 'hb_stop_blocking_off', 'rewait_operate',
        'flush_operate_stale', 'flush_operate_off', 'release_operate_counted', 'hb_drop_old_epoch', 'hb_unmatched',
    },
}


def frozen() -> str:
    raw = SOURCE.read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    assert got == SOURCE_SHA256, f'frozen source changed: {got}'
    return raw.decode()


def one(text: str, old: str, new: str) -> str:
    count = text.count(old)
    assert count == 1, (count, old[:120])
    return text.replace(old, new, 1)


def split_outcome_block() -> str:
    regs = []
    for bank in BANKS:
        regs.append(f'    Register<bit<32>, bit<5>>({OUTCOME_COUNT}, 0) outcomes_{bank};')
        regs.append(f'    RegisterAction<bit<32>, bit<5>, bit<32>>(outcomes_{bank}) bump_outcome_{bank} = {{')
        regs.append('        void apply(inout bit<32> value, out bit<32> out_value) { value = value + 1; out_value = value; }')
        regs.append('    };')
        regs.append(f'    action count_{bank}(bit<5> idx) {{ bump_outcome_{bank}.execute(idx); }}')
    return '''    // ---- outcomes -----------------------------------------------------------------------------
%s
    // Split-counter experiment: each terminal T verdict table updates only its stage-local bank.
    // The control plane preserves the original 25 outcome meanings by summing the same index across
    // outcomes_tin, outcomes_token, outcomes_held, and outcomes_hb. One packet reaches at most one
    // verdict branch below, so this preserves one bump per packet while removing the late sink table.
''' % ('\n'.join(regs))


def replace_scoped(text: str, start: str, end: str, replacements: list[tuple[str, str]]) -> str:
    a = text.index(start)
    b = text.index(end, a)
    segment = text[a:b]
    for old, new in replacements:
        count = segment.count(old)
        assert count >= 1, (start, old)
        segment = segment.replace(old, new)
    return text[:a] + segment + text[b:]


def transform(text: str) -> str:
    original = text
    old_block = '''    // ---- outcomes -----------------------------------------------------------------------------
    Register<bit<32>, bit<5>>(25, 0) outcomes;
    RegisterAction<bit<32>, bit<5>, bit<32>>(outcomes) bump_outcome = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = value + 1; out_value = value; }
    };
    // Every t_path records at most one outcome. A Tofino register lives in one stage, and the ~dozen
    // tables that used to bump `outcomes` directly sat at different dependency depths, so they could
    // not share its stage (bf-p4c: "Table placement was not able to allocate ... in the same stage
    // along with Register t_Ingress.outcomes"). count() now only names the outcome; outcome_count, the
    // register's single call site, bumps it once at the end of the pass. Same index, same +1.
    action count(bit<32> code) { md.outcome_code = (bit<8>)code; }
    action bump(bit<5> idx) { bump_outcome.execute(idx); }
    table outcome_count {
        key = { md.outcome_code : exact; }
        actions = { bump; NoAction; }
        const entries = {
            0 : bump(0); 1 : bump(1); 2 : bump(2); 3 : bump(3); 4 : bump(4); 5 : bump(5); 6 : bump(6);
            7 : bump(7); 8 : bump(8); 9 : bump(9); 10 : bump(10); 11 : bump(11); 12 : bump(12); 13 : bump(13); 14 : bump(14); 15 : bump(15); 23 : bump(23); 24 : bump(24);
        }
        default_action = NoAction(); size = 25;
    }
'''
    text = one(text, old_block, split_outcome_block())
    text = one(text, '        md.outcome_code = t_OUT_NONE;\n', '')
    text = one(text, '        outcome_count.apply();\n', '')

    replacements = [
        ('count(t_OUT_REQ_BYPASS)', 'count_tin((bit<5>)t_OUT_REQ_BYPASS)'),
        ('count(t_OUT_RESP_DUP_DROP)', 'count_tin((bit<5>)t_OUT_RESP_DUP_DROP)'),
        ('count((bit<32>)index)', 'count_token(index)'),
        ('count(t_OUT_HELD_REWAIT)', 'count_held((bit<5>)t_OUT_HELD_REWAIT)'),
        ('count(t_OUT_HELD_STALE_FLUSH)', 'count_held((bit<5>)t_OUT_HELD_STALE_FLUSH)'),
        ('count(t_OUT_HELD_OFF_FLUSH)', 'count_held((bit<5>)t_OUT_HELD_OFF_FLUSH)'),
        ('count(t_OUT_ACK_COMMIT)', 'count_held((bit<5>)t_OUT_ACK_COMMIT)'),
        ('count(t_OUT_ACK_FALLBACK)', 'count_held((bit<5>)t_OUT_ACK_FALLBACK)'),
        ('count(t_OUT_RESP_RELEASE)', 'count_held((bit<5>)t_OUT_RESP_RELEASE)'),
        ('count(t_OUT_RESP_FALLBACK)', 'count_held((bit<5>)t_OUT_RESP_FALLBACK)'),
        ('count(t_OUT_OP_RELEASE)', 'count_hb((bit<5>)t_OUT_OP_RELEASE)'),
    ]
    for old, new in replacements:
        assert old in text, old
        text = text.replace(old, new)

    old_shared = '''    action stop_blocking_stale() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_TOKEN_STALE); }
    action stop_blocking_tmo() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_TOKEN_TMO); }
    action stop_blocking_off() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_TOKEN_OFF); }
'''
    new_shared = '''    action held_stop_blocking_stale() { ig_dprsr_md.drop_ctl = 1; count_held((bit<5>)t_OUT_TOKEN_STALE); }
    action held_stop_blocking_tmo() { ig_dprsr_md.drop_ctl = 1; count_held((bit<5>)t_OUT_TOKEN_TMO); }
    action held_stop_blocking_off() { ig_dprsr_md.drop_ctl = 1; count_held((bit<5>)t_OUT_TOKEN_OFF); }
    action hb_stop_blocking_stale() { ig_dprsr_md.drop_ctl = 1; count_hb((bit<5>)t_OUT_TOKEN_STALE); }
    action hb_stop_blocking_tmo() { ig_dprsr_md.drop_ctl = 1; count_hb((bit<5>)t_OUT_TOKEN_TMO); }
    action hb_stop_blocking_off() { ig_dprsr_md.drop_ctl = 1; count_hb((bit<5>)t_OUT_TOKEN_OFF); }
'''
    text = one(text, old_shared, new_shared)

    old_tail = '''    action drop_old_epoch() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_OLD_EPOCH_DROP); }
    // op_go: a held OPERATE may commit (live and its deadline passed); op_done_try writes only then.
'''
    new_tail = '''    action tin_drop_old_epoch() { ig_dprsr_md.drop_ctl = 1; count_tin((bit<5>)t_OUT_OLD_EPOCH_DROP); }
    action held_drop_old_epoch() { ig_dprsr_md.drop_ctl = 1; count_held((bit<5>)t_OUT_OLD_EPOCH_DROP); }
    action hb_drop_old_epoch() { ig_dprsr_md.drop_ctl = 1; count_hb((bit<5>)t_OUT_OLD_EPOCH_DROP); }
    // op_go: a held OPERATE may commit (live and its deadline passed); op_done_try writes only then.
'''
    text = one(text, old_tail, new_tail)
    text = text.replace('action rewait_operate() {\n        ig_tm_md.ucast_egress_port = t_HB_RETURN; ig_tm_md.qid = 2;\n        count_held((bit<5>)t_OUT_HELD_REWAIT);\n    }',
                        'action rewait_operate() {\n        ig_tm_md.ucast_egress_port = t_HB_RETURN; ig_tm_md.qid = 2;\n        count_hb((bit<5>)t_OUT_HELD_REWAIT);\n    }')
    text = text.replace('action flush_operate_stale() {\n        export_held(); ig_tm_md.ucast_egress_port = t_RELAY_PORT;\n        count_held((bit<5>)t_OUT_HELD_STALE_FLUSH);\n    }',
                        'action flush_operate_stale() {\n        export_held(); ig_tm_md.ucast_egress_port = t_RELAY_PORT;\n        count_hb((bit<5>)t_OUT_HELD_STALE_FLUSH);\n    }')
    text = text.replace('action flush_operate_off() {\n        export_held(); ig_tm_md.ucast_egress_port = t_RELAY_PORT;\n        count_held((bit<5>)t_OUT_HELD_OFF_FLUSH);\n    }',
                        'action flush_operate_off() {\n        export_held(); ig_tm_md.ucast_egress_port = t_RELAY_PORT;\n        count_hb((bit<5>)t_OUT_HELD_OFF_FLUSH);\n    }')
    text = one(text, '    action drop_exhausted() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_GEN_EXHAUSTED); }\n    action unmatched() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_UNMATCHED); }\n',
               '    action tin_drop_exhausted() { ig_dprsr_md.drop_ctl = 1; count_tin((bit<5>)t_OUT_GEN_EXHAUSTED); }\n'
               '    action tin_unmatched() { ig_dprsr_md.drop_ctl = 1; count_tin((bit<5>)t_OUT_UNMATCHED); }\n'
               '    action held_unmatched() { ig_dprsr_md.drop_ctl = 1; count_held((bit<5>)t_OUT_UNMATCHED); }\n'
               '    action hb_unmatched() { ig_dprsr_md.drop_ctl = 1; count_hb((bit<5>)t_OUT_UNMATCHED); }\n')

    text = replace_scoped(text, '    table tin_verdict {', '    table token_verdict {', [
        ('unmatched; drop_old_epoch; drop_exhausted;', 'tin_unmatched; tin_drop_old_epoch; tin_drop_exhausted;'),
        ('drop_exhausted();', 'tin_drop_exhausted();'),
        ('default_action = drop_old_epoch(); size = 19;', 'default_action = tin_drop_old_epoch(); size = 19;'),
    ])
    text = replace_scoped(text, '    table held_verdict {', '    table hb_verdict {', [
        ('stop_blocking; stop_blocking_stale; stop_blocking_tmo; stop_blocking_off; keep_blocking;',
         'stop_blocking; held_stop_blocking_stale; held_stop_blocking_tmo; held_stop_blocking_off; keep_blocking;'),
        ('flush_response_stale; flush_response_off; unmatched; drop_old_epoch;',
         'flush_response_stale; flush_response_off; held_unmatched; held_drop_old_epoch;'),
        ('stop_blocking_stale();', 'held_stop_blocking_stale();'),
        ('stop_blocking_tmo();', 'held_stop_blocking_tmo();'),
        ('stop_blocking_off();', 'held_stop_blocking_off();'),
        ('drop_old_epoch();', 'held_drop_old_epoch();'),
        ('default_action = unmatched(); size = 31;', 'default_action = held_unmatched(); size = 31;'),
    ])
    text = replace_scoped(text, '    table hb_verdict {', '    apply {', [
        ('stop_blocking; stop_blocking_stale; stop_blocking_tmo; stop_blocking_off; keep_blocking;\n                    release_operate_counted; rewait_operate; flush_operate_stale; flush_operate_off; unmatched; drop_old_epoch;',
         'stop_blocking; hb_stop_blocking_stale; hb_stop_blocking_tmo; hb_stop_blocking_off; keep_blocking;\n                    release_operate_counted; rewait_operate; flush_operate_stale; flush_operate_off; hb_unmatched; hb_drop_old_epoch;'),
        ('stop_blocking_stale();', 'hb_stop_blocking_stale();'),
        ('stop_blocking_tmo();', 'hb_stop_blocking_tmo();'),
        ('stop_blocking_off();', 'hb_stop_blocking_off();'),
        ('drop_old_epoch();', 'hb_drop_old_epoch();'),
        ('default_action = unmatched(); size = 12;', 'default_action = hb_unmatched(); size = 12;'),
    ])

    # The broad held replacements above should not leak into T-in/token declarations.
    assert 'table outcome_count' not in text
    assert 'outcome_count.apply()' not in text
    assert 'count(t_OUT_' not in text
    assert 'count((bit<32>)index)' not in text
    assert text != original
    return text


def bank_inverse() -> dict:
    inverse = {str(i): {bank: COUNTER_MEANINGS[i] for bank in BANKS} for i in range(OUTCOME_COUNT)}
    return inverse


def write(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    source = transform(frozen())
    out = directory / 'response_only.p4'
    out.write_text(source)
    proof = {
        'experiment': 't_split_outcomes_01',
        'source_input': {'path': str(SOURCE), 'sha256': SOURCE_SHA256},
        'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'banks': list(BANKS),
        'counter_count_per_bank': OUTCOME_COUNT,
        'control_plane_sum_rule': 'logical_outcome[i] = outcomes_tin[i] + outcomes_token[i] + outcomes_held[i] + outcomes_hb[i]',
        'counter_meanings': {str(k): v for k, v in COUNTER_MEANINGS.items()},
        'action_bank': ACTION_BANK,
        'table_actions': {k: sorted(v) for k, v in TABLE_ACTIONS.items()},
        'bank_inverse': bank_inverse(),
        'one_bump_per_packet_argument': [
            'T apply uses mutually exclusive branch chain: clone, T_IN, token, HELD_RETURN, HB_RETURN, else foreign.',
            'Only the T_IN/token/HELD_RETURN/HB_RETURN verdict tables call count_* actions.',
            'Each verdict table applies once and selects one action, so at most one split outcome bank increments per packet.',
            'drop_clone/drop_foreign preserve prior no-outcome behavior.',
        ],
    }
    (directory / 'counter_semantics.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'evidence/full_01'
    write(target)
