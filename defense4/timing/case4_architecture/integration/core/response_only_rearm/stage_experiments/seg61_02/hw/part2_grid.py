"""Part 2 timing grid on the frozen m10_03 build: the conditions, and the checks every grid config must pass.

  python3 part2_grid.py CONFIG [CONFIG ...]      # exit 1 if any config fails a check

Knob semantics (verified on m10_03's P4; ctl_timing_01/evidence/m10_03/PART2_DESIGN_20261018.md):
  da    minimum request->ACK: the ACK commits once t0 + da has passed AND a response child has been seen; so
        request->ACK = max(da, L) for an outstation response latency L;
  gap   D, the replacement CLRT: the response is released at a_commit + gap, a_commit being the ACK's own release;
  readiness   fallback for both, from t0; pb  piggybacked-response bound, from t0; op_j  J, the OPERATE hold.
The historical 5/10/15/20 ms were request->ACK deadlines (DA), so the comparable knob is da, not gap.

Checks (`check`):
  1. the validator's own rules (campaign.py, t_config.py): op_j < pb < readiness, da < readiness <= cap, each
     duration in (0, 1 s), each in T units < 2^31;
  2. the IMPLEMENTATION-required relation the validators do not check: readiness >= max(da, L + J) + gap + SLACK.
     The ACK commits only once a response child has been seen; for OPERATE the command is first held for J, so its
     ACK commits at max(da, J + L) after t0 (code review H1; m9 combined: OPERATE ACK median 7.9 ms against 5.5 ms
     for READ/SELECT). Below the relation the readiness fallback releases the response before a_commit + gap, so the
     condition would not measure D. L = the config's fixture delay (fixture.delay_ms), SLACK = 5 ms (lap and shaping
     granularity, a stated margin, not a measured bound). This is a new check, never a loosened one;
  3. the fixture delay is the grid's one L (5 ms) in every Part 2 config (code review C1: the rotation templates carry
     5/3/8 ms by block, which under leave-one-block-out hides even the undefended baseline's leak).
`normalizes` states, per condition, whether request->ACK is NOMINALLY normalized for each kind: READ/SELECT need
da > L, OPERATE needs da > L + J, strictly (equality is not enough: on m9 at L = 5 ms, READ/SELECT request->ACK had a
median of about 5.45 ms, above da = 5 ms; lap and shaping overhead are not modelled).
"""
import json
import sys

MS = 1_000_000
FIXTURE_L_NS = 5 * MS
SLACK_NS = 5 * MS
OP_J_NS = 2_400_000                       # J, fixed across the grid (the qualified value)
READINESS_NS = 40 * MS                    # fixed for every condition, the reference included
CAP_NS = 40 * MS

# (name, da, gap, readiness): pb = da + gap for each (piggyback request->response comparable to separate-ACK
# request->response)
CONDITIONS = (
    ('ref_r30', 2 * MS, 950_000, 30 * MS),        # the qualified setting, unchanged (readiness 30 ms)
    ('ref_r40', 2 * MS, 950_000, READINESS_NS),   # the same at the grid's readiness, to expose the readiness confound
    ('da05_g100', 5 * MS, 1 * MS, READINESS_NS),  # axis 1: request->ACK, D = 1 ms (the historical CLRT centre)
    ('da10_g100', 10 * MS, 1 * MS, READINESS_NS),
    ('da15_g100', 15 * MS, 1 * MS, READINESS_NS),
    ('da20_g100', 20 * MS, 1 * MS, READINESS_NS),
    ('da10_g095', 10 * MS, 950_000, READINESS_NS),  # axis 2: D configurable, at da = 10 ms
    ('da10_g200', 10 * MS, 2 * MS, READINESS_NS),
    ('da10_g400', 10 * MS, 4 * MS, READINESS_NS),
    ('da10_g800', 10 * MS, 8 * MS, READINESS_NS),
)


def params(da, gap, readiness):
    return dict(da=da, gap=gap, readiness=readiness, cap=max(CAP_NS, readiness), pb=da + gap, op_j=OP_J_NS)


def t_units(ns):
    """t_config's conversion for the 256 ns clock: ceil((ns + 512) / 256)."""
    return -(-(ns + 512) // 256)


def normalizes(da, op_j=OP_J_NS, fixture_l_ns=FIXTURE_L_NS):
    """Whether request->ACK is nominally set by da rather than by the outstation, per kind (strict inequality)."""
    return dict(READ=da > fixture_l_ns, SELECT=da > fixture_l_ns, OPERATE=da > fixture_l_ns + op_j)


def check_config(cfg, slack_ns=SLACK_NS):
    """check() on a whole config, with L read from its fixture, plus the fixed-L rule."""
    l_ns = int(round(cfg['fixture']['delay_ms'] * MS))
    out = check(cfg['timing_params_ns'], fixture_l_ns=l_ns, slack_ns=slack_ns)
    if l_ns != FIXTURE_L_NS:
        out.append('fixture delay %g ms is not the grid L (%g ms)' % (l_ns / MS, FIXTURE_L_NS / MS))
    return out


def check(timing, fixture_l_ns=FIXTURE_L_NS, slack_ns=SLACK_NS):
    """Problems with one timing_params_ns block ([] when it passes)."""
    p, out = timing, []
    for k in ('da', 'gap', 'readiness', 'cap', 'op_j', 'pb'):
        if k not in p:
            out.append('missing %s' % k)
    if out:
        return out
    if not p['op_j'] < p['pb'] < p['readiness']:
        out.append('validator: op_j < pb < readiness fails (%d, %d, %d)' % (p['op_j'], p['pb'], p['readiness']))
    if not p['da'] < p['readiness'] <= p['cap']:
        out.append('validator: da < readiness <= cap fails (%d, %d, %d)' % (p['da'], p['readiness'], p['cap']))
    for k in ('da', 'gap', 'readiness', 'cap', 'op_j'):
        if not 0 < p[k] < 1_000_000_000:
            out.append('validator: %s outside (0, 1 s)' % k)
    for k in ('da', 'gap', 'readiness', 'cap', 'op_j', 'pb'):
        if t_units(p[k]) >= 2 ** 31:
            out.append('%s exceeds the 31-bit T range' % k)
    need = max(p['da'], fixture_l_ns + p['op_j']) + p['gap'] + slack_ns
    if p['readiness'] < need:
        out.append('implementation: readiness %d < max(da, L + J) + gap + slack = %d; the fallback would pre-empt D'
                   % (p['readiness'], need))
    return out


def main(argv):
    bad = 0
    for path in argv[1:]:
        problems = check_config(json.load(open(path)))
        print('%s %s' % ('FAIL' if problems else 'ok  ', path), *problems, sep='\n    ' if problems else '')
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
