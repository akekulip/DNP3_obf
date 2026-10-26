"""Opt-in removal of write-only measurement state (Philip, 2026-10-25: out-of-scope measures go, c68).

Removes only state that no forwarding decision reads:
  N  count_first / count_busy / count_term registers and their bumps; retry_dup_t (count-only table).
     The first_event rows that only counted keep their match and do nothing, as before.
  E  outcome Counter and count_t.
  T  outcomes register, bump_outcome, outcome_count, md.outcome_code and every count(...) call.
  p1 egress  p1_outcome Counter.
Every edit is literal and fails closed (common.once) if the expected text is missing.
"""
import re

from .common import combined, once

T_COUNT = re.compile(r'\s*count\((?:t_OUT_[A-Z_]+|\(bit<32>\)index)\);')


def _remove(text, pattern, expected):
    """Delete every match of a regex; the match count must equal `expected`."""
    out, n = re.subn(pattern, '', text)
    if n != expected:
        raise ValueError('strip_telemetry: %r matched %d, expected %d' % (pattern, n, expected))
    return out


def transform(src):
    n_old = combined.segment(src, 'N')
    n = n_old
    n = once(n, 'Register<bit<32>,bit<4>>(4,0) count_first;\n'
                'RegisterAction<bit<32>,bit<4>,bit<32>>(count_first) count_first_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};\n'
                'Register<bit<32>,bit<4>>(8,0) count_busy;\n'
                'RegisterAction<bit<32>,bit<4>,bit<32>>(count_busy) count_busy_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};\n'
                'Register<bit<32>,bit<4>>(4,0) count_term;\n'
                'RegisterAction<bit<32>,bit<4>,bit<32>>(count_term) count_term_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};\n'
                'action count_retry_duplicate(){count_term_bump.execute(4w0);}\n', '')
    for index in range(3):
        n = once(n, 'count_first_bump.execute(4w%d);' % index, '')
    n = _remove(n, r'count_busy_bump\.execute\(4w\d\);', 11)
    start = n.index(' table retry_dup_t{')
    end = n.index('\n', start)
    n = n[:start] + n[end + 1:]
    n = once(n, 'retry_dup_t.apply();', '')
    src = once(src, n_old, n)

    e_old = combined.segment(src, 'E')
    e = e_old
    e = once(e, '''    /* ============ outcome bookkeeping ============
       count_t r_is observability only. settle_t r_is NOT: it drops untranslatable shapes on mapped connections
       (drop_odd) and gives m.result its value on paths no classifier writes. */
    Counter<bit<32>, bit<8>>(32, CounterType_t.PACKETS) outcome;
    action count() { outcome.count(m.result); }
    table count_t { actions = { count; } size = 1; const default_action = count(); }
''', '''    /* settle_t drops untranslatable shapes on mapped connections (drop_odd) and gives m.result its value on
       paths no classifier writes. */
''')
    e = once(e, '        count_t.apply();\n', '')
    src = once(src, e_old, e)

    t_old = combined.segment(src, 'T')
    t = t_old
    start = t.index('    // ---- outcomes ----')
    end = t.index('        } default_action = NoAction(); size = 19;\n    }\n', start)
    t = t[:start] + t[end + len('        } default_action = NoAction(); size = 19;\n    }\n'):]
    t = once(t, '    // The one outcome this pass records; bumped by the single outcome_count table at the end of apply.\n'
                '    bit<8> outcome_code;\n', '')
    t = once(t, '        md.outcome_code = t_OUT_NONE;\n', '')
    start = t.index('// Outcome counters (outcomes register index)')
    end = t.index('const bit<8> t_OUT_NONE = 0xff;\n', start)
    t = t[:start] + t[end + len('const bit<8> t_OUT_NONE = 0xff;\n'):]
    t = once(t, '        outcome_count.apply();\n', '')
    t = _remove(t, T_COUNT, 22)
    # drop_timer_stale's index only chose the outcome cell; two data-free actions keep the two cases apart by name.
    t = once(t, '    action drop_timer_stale(bit<5> index) { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; }',
             '    action drop_timer_stale_operate() { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; }\n'
             '    action drop_timer_stale_read() { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; }')
    t = once(t, 'seed_resp_blocker; drop_timer_stale; }', 'seed_resp_blocker; drop_timer_stale_operate; drop_timer_stale_read; }')
    t, n23 = re.subn(r'drop_timer_stale\(5w23\)', 'drop_timer_stale_operate()', t)
    t, n24 = re.subn(r'drop_timer_stale\(5w24\)', 'drop_timer_stale_read()', t)
    if (n23, n24) != (2, 3):
        raise ValueError('strip_telemetry: drop_timer_stale rows %d/%d, expected 2/3' % (n23, n24))
    src = once(src, t_old, t)

    src = once(src, '''    /* observability: one count per mixed/full READ frame seen: 1 padded, 2 declined (no size-enabled
       connection), 3 declined (block-0 CRC or profile); the sum of the three is the number seen */
    Counter<bit<32>, bit<2>>(4, CounterType_t.PACKETS) p1_outcome;
''', '')
    src = once(src, '            p1_outcome.count(m.p1_res);   // 1 padded (read_profile), 3 conn ok not padded (p1_conn), 2 no conn (parser)\n', '')
    for name in ('count_first', 'count_busy', 'count_term', 'retry_dup_t', 'outcome_count', 'outcome_code',
                 'bump_outcome', 'p1_outcome', 'count_t', 'outcome.count'):
        if name in src:
            raise ValueError('strip_telemetry: %s still present' % name)
    return src
