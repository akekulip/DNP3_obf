"""Generate an m12 READ+SBO timing-and-size candidate from the pinned m11_09 source.

Every candidate is m11_09 plus a fixed sequence of anchored text transforms (m12gen/), each a once()-style edit so a
missing or duplicated anchor fails loudly. Live builds:

  python3 make_m12.py OUT --policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry  # c27: c26 + F1
  python3 make_m12.py OUT ... --two-read --reduce --ack-retry --read-handshake                      # c28: c27 + READ completes handshake
  python3 make_m12.py OUT ... --read-handshake --headroom                                          # c29: c28 + pipe-0 headroom
  python3 make_m12.py OUT ... --read-handshake --headroom --relay                                  # c30: c29 with relay shapes (integrity 134->158)
  python3 make_m12.py OUT --policy --c3 cimg --shapes passthrough --two-read --reduce  # c26: c25, resource-reduced
  python3 make_m12.py OUT --policy --c3 cimg --shapes passthrough --two-read        # c25 (hardware campaign 02)
  python3 make_m12.py OUT --policy --c3 cimg --shapes passthrough                   # c12 (range READ 49 -> 141)
  python3 make_m12.py OUT --policy --c3 cimg --shapes passthrough --segmented-full  # c20 (377 -> 401, historical)
  python3 make_m12.py OUT --policy [--c3 cimg]                                      # b08 (ladder) / cimg policy

--only NAME stops after that transform (placement experiments; the build is then marked non-runnable). Builds that
were never used past 0c475ebc2 (no-policy range/full proofs, the --segmented/--seg-n/--seg-n2 probes) were removed
and are recoverable from that commit. check_generator_identity.py proves refactors leave every live output unchanged.
"""
import argparse
from pathlib import Path

from m12gen import read_policy, two_read
from m12gen.build import build, write_outputs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--only', default=None)
    ap.add_argument('--policy', action='store_true', required=True,
                    help='read_complete_01 policy build (required: every live build is a policy build)')
    ap.add_argument('--c3', choices=('ladder', 'cimg'), default='ladder',
                    help='reverse boundary: max-image ladder (m12p_b08) or per committed image (cimg)')
    ap.add_argument('--shapes', choices=('none', 'passthrough'), default='none',
                    help='also admit the pass-through READ classes (analog 141, class0/integrity 247) at native size')
    ap.add_argument('--segmented-pad', dest='segmented_pad', action='store_true',
                    help='faithful segmented 377->401 READ padder in pipe-1 egress (historical, m12p_c16+)')
    ap.add_argument('--segmented-full', dest='segmented_full', action='store_true',
                    help='full faithful segmented path: pipe-1 padder + N two-segment classifier + T second child (c20)')
    ap.add_argument('--two-read', dest='two_read', action='store_true',
                    help='two-READ-target profile (m12p_c21+): mixed READ 91->141 + full READ 247->271 replace the range '
                         'READ; SBO 37->61 unchanged (requires --c3 cimg --shapes passthrough)')
    ap.add_argument('--reduce', action='store_true',
                    help='m12p_c26: behavior-preserving resource reduction of the two-READ build (requires --two-read)')
    ap.add_argument('--ack-retry', dest='ack_retry', action='store_true',
                    help='m12p_c27: F1, busy pure ACKs retried instead of passed (requires --reduce)')
    ap.add_argument('--read-handshake', dest='read_handshake', action='store_true',
                    help='m12p_c28: a READ that overtakes the final handshake ACK completes it (requires --ack-retry)')
    ap.add_argument('--headroom', action='store_true',
                    help='m12p_c29: pipe-0 headroom, N and E highest occupied index 10 (requires --read-handshake)')
    ap.add_argument('--relay', action='store_true',
                    help='m12p_c30: relay (SEL-751) two-READ shapes -- integrity 134->158 instead of the software '
                         '247->271; requires --two-read (constants_two_read_relay.json)')
    ap.add_argument('--relay-sbo', dest='relay_sbo', action='store_true',
                    help='actual guarded two-CROB relay45/49 exchange, faithful49->60 (requires --relay --headroom)')
    ap.add_argument('--relay-ts', dest='relay_ts', action='store_true', help='observed SEL-751 TCP timestamp profile (requires --relay-sbo)')
    ap.add_argument('--response-ready-timing', action='store_true',
                    help='genuine ACK waits for whole response; release response D after commit; requires --relay-ts')
    ap.add_argument('--strip-telemetry', dest='strip_telemetry', action='store_true',
                    help='remove write-only measurement registers and counters (requires --response-ready-timing)')
    ap.add_argument('--strip-operate-hold', dest='strip_operate_hold', action='store_true',
                    help='remove fixed OPERATE-J hold; retain response-ready ACK/D timing (requires --strip-telemetry)')
    ap.add_argument('--strip-rbad', dest='strip_rbad', action='store_true',
                    help="c70 trial: remove E's always-zero rbad0/rbad1/rbadt predicates (requires --strip-operate-hold)")
    ap.add_argument('--diag-anchors', dest='diag_anchors', action='store_true',
                    help='diagnostic switch-clock transaction anchors in T (separate evidence tier; requires --relay-ts)')
    a = ap.parse_args()
    if a.strip_rbad and not a.strip_operate_hold:
        ap.error('--strip-rbad requires --strip-operate-hold')
    if a.strip_operate_hold and not a.strip_telemetry:
        ap.error('--strip-operate-hold requires --strip-telemetry')
    if a.response_ready_timing and not a.relay_ts:
        ap.error('--response-ready-timing requires --relay-ts')
    if a.strip_telemetry and not a.response_ready_timing:
        ap.error('--strip-telemetry requires --response-ready-timing')
    if a.response_ready_timing and a.diag_anchors:
        ap.error('--response-ready-timing excludes --diag-anchors')
    if a.diag_anchors and not a.relay_ts:
        ap.error('--diag-anchors requires --relay-ts')
    if a.relay_ts and not a.relay_sbo:
        ap.error('--relay-ts requires --relay-sbo')
    if a.relay_sbo and not (a.relay and a.headroom):
        ap.error('--relay-sbo requires --relay --headroom')
    if a.headroom and not a.read_handshake:
        ap.error('--headroom requires --read-handshake')
    if a.read_handshake and not a.ack_retry:
        ap.error('--read-handshake requires --ack-retry')
    if a.ack_retry and not a.reduce:
        ap.error('--ack-retry requires --reduce')
    if a.reduce and not a.two_read:
        ap.error('--reduce requires --two-read')
    if a.relay and not a.two_read:
        ap.error('--relay requires --two-read')
    if a.two_read and not (a.c3 == 'cimg' and a.shapes == 'passthrough'):
        ap.error('--two-read requires --policy --c3 cimg --shapes passthrough')
    if a.two_read and (a.segmented_pad or a.segmented_full):
        ap.error('--two-read excludes the segmented probes (the native 377 segment work is not in this profile)')
    if a.segmented_full and a.segmented_pad:
        ap.error('--segmented-full already includes the padder; do not combine with --segmented-pad')
    two_read.use_relay_shapes(a.relay)
    image = two_read.two_read_shapes()[0]['target'] if a.two_read else read_policy.policy_shape()['target']
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    src, applied = build(a.only, c3=a.c3, shapes=a.shapes, segmented_pad=a.segmented_pad,
                         segmented_full=a.segmented_full, two_read_build=a.two_read, reduce=a.reduce,
                         ack_retry=a.ack_retry, read_handshake=a.read_handshake,
                         headroom=a.headroom, relay=a.relay, relay_sbo=a.relay_sbo, relay_ts=a.relay_ts,
                         diag_anchors=a.diag_anchors, response_ready_timing=a.response_ready_timing,
                         strip_telemetry=a.strip_telemetry, strip_operate_hold=a.strip_operate_hold,
                         strip_rbad=a.strip_rbad)
    sha = write_outputs(out, a, src, applied)
    print('wrote %s (image=%d, transforms=%s, sha=%s)' % (out / 'response_only.p4', image, applied, sha[:12]))


if __name__ == '__main__':
    main()
