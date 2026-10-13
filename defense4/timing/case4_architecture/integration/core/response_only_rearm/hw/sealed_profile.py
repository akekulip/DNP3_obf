"""Pinned sealed-epoch profile; sparse counters retain the original stale sum."""
import hashlib
import json
from pathlib import Path

# Actual complete compiler artifacts, not a register-size heuristic.
PROFILES = {
    '4c1bfc92eb746d5df80cb6464e777c3b244fb7f792b17c76eb31bb461e1170da': {
        '6dab48d4ad2bdc9db993825fe57117e0fd27c57951e8c1b1578333ee37b256dc',
        '25244d805cfbc05c39c14a7f3f947ec049826a6108ea0737ed717df3e4634fb1',
    },
    # retx_passthrough_01 (candidate56 + retransmission pass-through): installed SDK 9.13.2, then local 9.13.1.
    'fbb1f2c0111342dd6808381e32a22df04e3ad2cfde3d7d340a113a2acc4e899e': {
        '62de2c19001b2fbb42742974b8a5e61813037be3a5efb06f0acc6dac5c37d6c6',
    },
    '21275f3befdf6260ad24253b5432b8005743e5cc78f0266d87251f80d2c959bf': {
        '095db5023e7a011de7a48994cabe1208bc441d352bc2d6a50334f2c3c4dde36a',
    },
    # rearm_57s (dup_hold_01 full_02_strict: conforming READ re-encoding, strict controls, duplicate-OPERATE
    # hold): installed SDK 9.13.2, then local 9.13.1.
    '22d666b23d2d63bf76d62b7d2b6643a5aac6e303abe9ac6b4f1392ed38f437f6': {
        '2052c564cc77938f3b13001ed94abe089b93e0cdb040c0b259161270dcf3c0d9',
    },
    '2a22b713f5f0e767d4f635aaf908fc4e9bf5ccb9a5aa247a39f49fe893f5f92a': {
        'e784485bfbde211d74929ea8e4d514bd219714798c55afaf6237b6cdb26d8480',
    },
}


def select(build_out):
    out = Path(build_out)
    raw = (out/'bfrt.json').read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest in PROFILES:
        if hashlib.sha256((out/'response_only.p4pp').read_bytes()).hexdigest() not in PROFILES[digest]:
            raise ValueError('sealed profile compiled source differs from its pinned artifact')
        return True
    tables = {item['name']: item for item in json.loads(raw)['tables']}
    if tables.get('p1.t_Ingress.outcomes', {}).get('size') == 16 and \
            'p1.t_Ingress.quarantine_reg' in tables:
        return False
    raise ValueError('unsupported candidate epoch/counter profile')


def read_diagnostics(read_outcome, outcomes, expected=False):
    blocker = outcomes.get('OUT_TOKEN_STALE')
    op, read = read_outcome(23), read_outcome(24)
    if any(type(value) is not int or value < 0 for value in (blocker, op, read)):
        raise ValueError('missing or malformed raw timer/blocker rejection counters')
    outcomes.update(STALE_BLOCKER=blocker, RAW_OPERATE_TIMER_STALE=op, RAW_READ_TIMER_STALE=read,
                    OUT_TOKEN_STALE=blocker+op+read)
    # dup_hold_01 builds count an early duplicate OPERATE dropped while its original is held at index 16
    # (t_OUT_OP_DUP_DROP). Recorded only; it is not stale and never enters stale_total. Older sealed builds
    # leave index 16 unused (0).
    dup = read_outcome(16)
    outcomes.update(OUT_OP_DUP_DROP=dup if type(dup) is int and dup >= 0 else None)
    # This is not make_diag_t's layout: index14/15 remain lifecycle/exhaustion,
    # and a readable unused index16 must not switch to legacy stale accounting.
    return dict(present=False, layout='split_raw_timer_23_24',
                rewait={'OPERATE': outcomes.get('OUT_HELD_REWAIT')}, blocker_laps={},
                stale={}, read_errors=[], stale_sources={'6': 'STALE_BLOCKER',
                '23': 'RAW_OPERATE_TIMER_STALE', '24': 'RAW_READ_TIMER_STALE'},
                stale_total=blocker+op+read)
